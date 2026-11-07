//! `litric` — Litric Defender command line client.
//!
//! Operational commands (`status`, `scan`, `analyze`, `quarantine`) go through
//! the running `litricd` daemon over its local API by default. That is the
//! supported path for daemon-backed work: one scanner, one threat database, one
//! quarantine, one audit trail — shared by the UI and the CLI.
//!
//! `guard` is the deliberate in-process exception: it scans, quarantines and
//! launches one child under one fail-closed policy, without a daemon handoff.
//!
//! `--local` is an explicit, clearly-labelled escape hatch that uses the embedded
//! engine for standalone scanning (forensics, CI, offline hosts). It never
//! triggers automatically: if the daemon is down, the client says so.
//!
//! Rule authoring and database publishing (`rules lint`, `db build`, `db verify`,
//! `bench`) are in-process by design; they operate on engine artifacts, not on
//! the running protection state.

use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, ExitStatus};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

use litric_cli::client::{self, Client};
use litric_core::engine::{Engine, EngineConfig};
use litric_core::guard::{decide, PreflightAction, PreflightPolicy};
use litric_core::hash::sha256_bytes;
use litric_core::quarantine::QuarantineVault;
use litric_core::rules::{parse_rule_file, Rule, RuleSet};
use litric_core::scan::{ScanLimits, ScanSummary, Scanner};
use litric_core::scan_quarantine::{
    quarantine_malicious as quarantine_malicious_detections, ScanQuarantineReport,
};
use litric_core::threatdb::{
    build_signed, dev_signing_key, DbPayload, DbTrust, HashEntry, RuleSource, ThreatDb,
    DB_FORMAT_VERSION,
};

#[derive(Parser)]
#[command(
    name = "litric",
    version = litric_core::ENGINE_VERSION,
    about = "Litric Defender client: drives the litricd daemon, or scans standalone with --local",
    long_about = "Litric Defender CLI.\n\n\
        Daemon-backed commands talk to the running litricd daemon \
        (127.0.0.1:8787) using its bearer token. If the daemon is not running or the \
        token is missing, the command fails with instructions instead of quietly \
        scanning in-process. `guard` is the exception: it scans and quarantines \
        in-process, then launches the child only if the verdict permits it.\n\n\
        Use --local for standalone scanning without a daemon (it does not affect \
        guard).\n\n\
        Exit codes: 0 success, 1 threat/guard refusal or failed job, 2 client/usage \
        error, 3 cancelled, 4 quarantine failure during a scan."
)]
struct Cli {
    /// Address of the running litricd daemon (default 127.0.0.1:8787).
    #[arg(long, global = true, value_name = "HOST:PORT")]
    addr: Option<String>,
    /// Path to the daemon API token file (default ./litric-data/api.token).
    #[arg(long, global = true, value_name = "PATH")]
    token_file: Option<PathBuf>,
    /// Bypass the daemon and use the embedded engine (standalone mode).
    #[arg(long, global = true)]
    local: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show daemon status, including whether real-time protection is actually on.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Scan a file or directory.
    Scan {
        path: PathBuf,
        /// Scan profile: quick, full, deep or custom.
        #[arg(long, default_value = "quick")]
        profile: String,
        /// Print the raw job JSON.
        #[arg(long)]
        json: bool,
        /// Queue the scan and return immediately.
        #[arg(long)]
        no_wait: bool,
        /// Exit with code 1 when anything malicious or suspicious is found.
        #[arg(long)]
        fail_on_threat: bool,
        /// Quarantine MALICIOUS files after scanning; Clean and Unknown files are untouched.
        #[arg(long)]
        quarantine_malicious: bool,
        /// Encrypted vault directory (used only with --local and --quarantine-malicious).
        #[arg(long)]
        vault_dir: Option<PathBuf>,
        /// Encrypted vault key file (used only with --local and --quarantine-malicious).
        #[arg(long)]
        vault_key: Option<PathBuf>,
        /// Maximum seconds to wait for completion (default 3600).
        #[arg(long)]
        timeout: Option<u64>,
        /// Rules directory (used only with --local).
        #[arg(long, default_value = "rules")]
        rules: PathBuf,
        /// Threat database directory (used only with --local).
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Cancel a running scan by job id.
    Cancel {
        id: String,
    },
    /// Analyse one file and show the evidence behind the verdict.
    Analyze {
        file: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value = "rules")]
        rules: PathBuf,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Scan a file, block malicious content, and launch it only if safe.
    ///
    /// This protects only launches made through this command. It is not a
    /// system-wide real-time scanner and cannot intercept Explorer double-clicks.
    Guard {
        file: PathBuf,
        /// Permit execution when the scan result is UNKNOWN (not recommended).
        #[arg(long)]
        allow_unknown: bool,
        /// Move a malicious file into the encrypted vault before blocking it.
        /// Off by default: blocking never touches the file.
        #[arg(long)]
        quarantine: bool,
        /// Deprecated no-op, kept so existing scripts keep parsing. Quarantine is
        /// opt-in, so this flag is already the default and never removes a file.
        #[arg(long, hide = true)]
        no_quarantine: bool,
        /// Rules directory.
        #[arg(long, default_value = "rules")]
        rules: PathBuf,
        /// Threat database directory.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Directory for the encrypted quarantine vault.
        #[arg(long)]
        vault_dir: Option<PathBuf>,
        /// Key file for the quarantine vault.
        #[arg(long)]
        vault_key: Option<PathBuf>,
        /// Arguments passed to the program after `--`.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Show the policy that gates every destructive operation, and verify the
    /// append-only audit chain that records them.
    Safety {
        #[arg(long)]
        json: bool,
        /// Vault directory (used only with --local).
        #[arg(long)]
        vault_dir: Option<PathBuf>,
        /// Vault key file (used only with --local).
        #[arg(long)]
        vault_key: Option<PathBuf>,
    },
    /// Quarantine operations.
    Quarantine {
        #[command(subcommand)]
        cmd: QuarantineCmd,
        /// Vault directory (used only with --local).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Vault key file (used only with --local).
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Rule authoring tools (in-process).
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    /// Threat database tools (in-process).
    Db {
        #[command(subcommand)]
        cmd: DbCmd,
    },
    /// SafeOS: risk assessment and isolation policy (daemon).
    Safeos {
        #[command(subcommand)]
        cmd: SafeosCmd,
    },
    /// Measure scan throughput (in-process).
    Bench {
        path: PathBuf,
        #[arg(long, default_value_t = 3)]
        runs: usize,
        #[arg(long, default_value = "rules")]
        rules: PathBuf,
    },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// List quarantined objects.
    List,
    /// Copy a file into the encrypted vault. The original is left in place
    /// unless --remove-original is passed.
    Add {
        file: PathBuf,
        #[arg(long, default_value = "User.Request")]
        threat: String,
        /// Remove the source after the encrypted copy is written and verified.
        /// Off by default: a quarantined original is never deleted by accident.
        #[arg(long)]
        remove_original: bool,
    },
    /// Restore a quarantined object by id.
    Restore {
        id: String,
        #[arg(long)]
        dest: Option<PathBuf>,
    },
    /// Verify every entry decrypts and matches its recorded hash.
    Verify,
    /// Permanently delete an entry (irreversible).
    Purge {
        id: String,
        /// Required acknowledgement.
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
enum SafeosCmd {
    /// Show isolation backends and why they are or are not available.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Classify an application and show the fail-closed execution decision.
    Assess {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Launch an application in a disposable, offline Windows Sandbox session.
    Launch {
        file: PathBuf,
        /// Wait for the sandbox process to exit before returning.
        #[arg(long)]
        wait: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// Validate every .lrs file in a directory.
    Lint {
        #[arg(default_value = "rules")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum DbCmd {
    /// Build and sign a threat database from rules (and an optional hash list).
    Build {
        #[arg(long, default_value = "rules")]
        rules: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        version: u64,
        #[arg(long)]
        hashes: Option<PathBuf>,
    },
    /// Verify a database directory against its signature.
    Verify {
        #[arg(long)]
        dir: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("litric: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let Cli {
        addr,
        token_file,
        local,
        command,
    } = cli;

    match command {
        Command::Status { json } => {
            let c = Client::discover(addr.as_deref(), token_file.as_deref())?;
            let v = c.status()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                print!("{}", client::render_status(&v));
                println!("daemon       : {}", c.addr());
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Scan {
            path,
            profile,
            json,
            no_wait,
            fail_on_threat,
            quarantine_malicious,
            vault_dir,
            vault_key,
            timeout,
            rules,
            db,
        } => {
            if local {
                let vault = if quarantine_malicious {
                    match open_local_vault(vault_dir, vault_key) {
                        Ok(v) => Some(v),
                        Err(e) => {
                            eprintln!(
                                "litric: cannot open the quarantine vault ({e}); refusing to run \
                                 --quarantine-malicious without a working vault"
                            );
                            return Ok(ExitCode::from(4));
                        }
                    }
                } else {
                    None
                };
                return local_scan(
                    &rules,
                    db.as_deref(),
                    &path,
                    json,
                    fail_on_threat,
                    vault.as_ref(),
                );
            }
            let c = Client::discover(addr.as_deref(), token_file.as_deref())?;
            let target = canonical(&path)?;
            let started = c.start_scan(
                &target.display().to_string(),
                &profile,
                quarantine_malicious,
            )?;
            let id = started["job_id"]
                .as_str()
                .ok_or("daemon accepted the scan but returned no job id")?
                .to_string();
            println!("scan queued  : {id}  ({} / {profile})", target.display());
            if no_wait {
                println!(
                    "not waiting  : job {id} is running in the daemon; re-run without \
                     --no-wait to watch it, or check `litric status`"
                );
                return Ok(ExitCode::SUCCESS);
            }

            let deadline = Instant::now() + Duration::from_secs(timeout.unwrap_or(3600));
            let mut last_reported: u64 = 0;
            loop {
                let job = c.scan_job(&id)?;
                let state = job["state"].as_str().unwrap_or("unknown");
                let files = job["files_scanned"].as_u64().unwrap_or(0);
                if files != last_reported {
                    println!("  … {files} file(s) inspected");
                    last_reported = files;
                }
                match state {
                    "completed" | "cancelled" | "failed" => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&job)?);
                        } else {
                            print!("{}", client::render_job(&job));
                        }
                        return Ok(match state {
                            "cancelled" => ExitCode::from(3),
                            "failed" => ExitCode::from(1),
                            _ => {
                                let hits = job["malicious"].as_u64().unwrap_or(0)
                                    + job["suspicious"].as_u64().unwrap_or(0);
                                let quarantine_failures =
                                    job["quarantine_failures"].as_u64().unwrap_or(0);
                                if quarantine_failures > 0 {
                                    ExitCode::from(4)
                                } else if (quarantine_malicious
                                    && job["malicious"].as_u64().unwrap_or(0) > 0)
                                    || (fail_on_threat && hits > 0)
                                {
                                    ExitCode::from(1)
                                } else {
                                    ExitCode::SUCCESS
                                }
                            }
                        });
                    }
                    _ => {}
                }
                if Instant::now() >= deadline {
                    let _ = c.cancel_scan(&id);
                    eprintln!(
                        "litric: scan {id} did not finish within the wait limit; cancellation requested.\n\
                         The scan may still be running in the daemon — check `litric status`."
                    );
                    return Ok(ExitCode::from(3));
                }
                std::thread::sleep(Duration::from_millis(150));
            }
        }

        Command::Cancel { id } => {
            let c = Client::discover(addr.as_deref(), token_file.as_deref())?;
            let v = c.cancel_scan(&id)?;
            println!(
                "cancellation requested: {id} ({})",
                v["state"].as_str().unwrap_or("cancelling")
            );
            Ok(ExitCode::SUCCESS)
        }

        Command::Analyze {
            file,
            json,
            rules,
            db,
        } => {
            if local {
                return local_analyze(&rules, db.as_deref(), &file);
            }
            let c = Client::discover(addr.as_deref(), token_file.as_deref())?;
            let target = canonical(&file)?;
            let v = c.analyze(&target.display().to_string())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                print!("{}", client::render_analysis(&v));
            }
            let verdict = v["verdict"].as_str().unwrap_or("unknown");
            Ok(if matches!(verdict, "malicious" | "suspicious") {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }

        Command::Guard {
            file,
            allow_unknown,
            quarantine,
            no_quarantine,
            rules,
            db,
            vault_dir,
            vault_key,
            args,
        } => local_guard(
            &rules,
            db.as_deref(),
            &file,
            GuardOptions {
                allow_unknown,
                // `--no-quarantine` always wins, so a script that relied on it
                // can never start deleting files after this change.
                quarantine: quarantine && !no_quarantine,
                vault_dir,
                vault_key,
                args,
            },
        ),

        Command::Safety {
            json,
            vault_dir,
            vault_key,
        } => {
            let status = if local {
                let v = open_local_vault(vault_dir, vault_key)?;
                v.safety().status_json()
            } else {
                Client::discover(addr.as_deref(), token_file.as_deref())?.safety()?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                print!("{}", client::render_safety(&status));
            }
            let trusted = status["policy_trusted"].as_bool() == Some(true);
            let chain_ok = status["audit"]["ok"].as_bool() == Some(true);
            Ok(if trusted && chain_ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }

        Command::Quarantine { cmd, dir, key } => {
            if local {
                return local_quarantine(cmd, dir, key);
            }
            let c = Client::discover(addr.as_deref(), token_file.as_deref())?;
            match cmd {
                QuarantineCmd::List => {
                    let v = c.quarantine_list()?;
                    print!("{}", client::render_quarantine(&v));
                    Ok(ExitCode::SUCCESS)
                }
                QuarantineCmd::Add {
                    file,
                    threat,
                    remove_original,
                } => {
                    let target = canonical(&file)?;
                    let v = c.quarantine_add(
                        &target.display().to_string(),
                        &threat,
                        remove_original,
                    )?;
                    println!("quarantined {} as {}", target.display(), v["id"].as_str().unwrap_or("?"));
                    println!("sha256      : {}", v["sha256"].as_str().unwrap_or("?"));
                    println!(
                        "original removed: {}",
                        v["original_removed"].as_bool().unwrap_or(false)
                    );
                    Ok(ExitCode::SUCCESS)
                }
                QuarantineCmd::Restore { id, dest } => {
                    let v = c.quarantine_restore(&id, dest.as_deref())?;
                    println!("restored to {}", v["restored_to"].as_str().unwrap_or("?"));
                    Ok(ExitCode::SUCCESS)
                }
                QuarantineCmd::Verify => {
                    let v = c.quarantine_verify()?;
                    let results = v["results"].as_array().cloned().unwrap_or_default();
                    let failed = results
                        .iter()
                        .filter(|r| r["ok"].as_bool() != Some(true))
                        .count();
                    for r in &results {
                        println!(
                            "{}  {}  {}",
                            r["id"].as_str().unwrap_or("?"),
                            if r["ok"].as_bool() == Some(true) { "ok  " } else { "FAIL" },
                            r["detail"].as_str().unwrap_or("")
                        );
                    }
                    println!("{} entry/entries, {failed} failed", results.len());
                    Ok(if failed > 0 {
                        ExitCode::from(1)
                    } else {
                        ExitCode::SUCCESS
                    })
                }
                QuarantineCmd::Purge { id, confirm } => {
                    if !confirm {
                        return Err(
                            "refusing to purge without --confirm: this permanently deletes the \
                             quarantined file"
                                .into(),
                        );
                    }
                    c.quarantine_purge(&id)?;
                    println!("purged {id}");
                    Ok(ExitCode::SUCCESS)
                }
            }
        }

        Command::Safeos { cmd } => {
            let c = Client::discover(addr.as_deref(), token_file.as_deref())?;
            match cmd {
                SafeosCmd::Status { json } => {
                    let v = c.safeos_status()?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        print!("{}", client::render_safeos_status(&v));
                    }
                    Ok(ExitCode::SUCCESS)
                }
                SafeosCmd::Launch { file, wait, json } => {
                    // Keep the raw path when it cannot be resolved here so the
                    // daemon can reject drive roots/profiles with its own rule.
                    let target = std::fs::canonicalize(&file)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| file.display().to_string());
                    let v = c.safeos_launch(&target, wait)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        print!("{}", client::render_safeos_launch(&v));
                    }
                    Ok(ExitCode::SUCCESS)
                }
                SafeosCmd::Assess { file, json } => {
                    let target = canonical(&file)?;
                    let v = c.safeos_assess(&target.display().to_string())?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        print!("{}", client::render_safeos_assessment(&v));
                    }
                    let action = v["action"].as_str().unwrap_or("deny");
                    Ok(if matches!(action, "deny" | "block_and_quarantine") {
                        ExitCode::from(1)
                    } else {
                        ExitCode::SUCCESS
                    })
                }
            }
        }

        Command::Rules { cmd: RulesCmd::Lint { dir } } => lint_rules(&dir),
        Command::Db {
            cmd: DbCmd::Build {
                rules,
                out,
                version,
                hashes,
            },
        } => build_db(&rules, &out, version, hashes.as_deref()),
        Command::Db { cmd: DbCmd::Verify { dir } } => verify_db(&dir),
        Command::Bench { path, runs, rules } => bench(&path, runs, &rules),
    }
}

fn canonical(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    std::fs::canonicalize(path).map_err(|e| {
        format!(
            "cannot access `{}`: {e}\nCheck the path, or run `litric status` to confirm the daemon is up.",
            path.display()
        )
        .into()
    })
}

// ---------------------------------------------------------------------------
// Explicit standalone mode
// ---------------------------------------------------------------------------

fn local_scan(
    rules: &Path,
    db: Option<&Path>,
    path: &Path,
    json: bool,
    fail_on_threat: bool,
    vault: Option<&QuarantineVault>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    eprintln!("litric: standalone mode (--local): no daemon involved, results are not shared with the service");
    let engine = build_engine(rules, db)?;
    let limits = ScanLimits {
        max_file_bytes: 128 * 1024 * 1024,
        ..Default::default()
    };
    let mut scanner = Scanner::new(&engine, limits);
    let summary = scanner.scan_path(path);
    let quarantine = vault.map(|v| quarantine_malicious_detections(&summary, v));

    if json {
        let mut out = serde_json::json!({
            "mode": "local",
            "files_scanned": summary.files_scanned,
            "clean": summary.clean,
            "unknown": summary.unknown,
            "suspicious": summary.suspicious,
            "malicious": summary.malicious,
            "unreadable": summary.unreadable,
            "skipped": summary.skipped,
            "duration_ms": summary.duration.as_millis(),
            "files_per_second": summary.files_per_second(),
            "mb_per_second": summary.mb_per_second(),
            "detections": summary.detections.iter().map(|d| serde_json::json!({
                "path": d.path.display().to_string(),
                "verdict": d.verdict.as_str(),
                "score": d.score,
                "threat": d.threat_name,
            })).collect::<Vec<_>>(),
        });
        if let Some(q) = &quarantine {
            out["quarantine"] = serde_json::to_value(q)?;
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_local_summary(&summary);
        if let Some(q) = &quarantine {
            print_quarantine_report(q);
        }
    }

    let quarantine_failed = quarantine
        .as_ref()
        .map(|q| q.failures > 0)
        .unwrap_or(false);
    let found_malicious = summary.malicious > 0;
    Ok(if quarantine_failed {
        ExitCode::from(4)
    } else if (quarantine.is_some() && found_malicious)
        || (fail_on_threat && (summary.malicious > 0 || summary.suspicious > 0))
    {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn print_local_summary(s: &ScanSummary) {
    println!("files scanned : {}", s.files_scanned);
    println!(
        "  clean {}  unknown {}  suspicious {}  malicious {}",
        s.clean, s.unknown, s.suspicious, s.malicious
    );
    println!(
        "skipped {}  unreadable {}  truncated {}",
        s.skipped, s.unreadable, s.truncated
    );
    println!("duration      : {:?}", s.duration);
    println!(
        "throughput    : {:.1} files/s, {:.2} MiB/s",
        s.files_per_second(),
        s.mb_per_second()
    );
    for d in &s.detections {
        println!(
            "  [{:>10}] {}  ({})",
            d.verdict.as_str().to_uppercase(),
            d.path.display(),
            d.threat_name.as_deref().unwrap_or("unclassified")
        );
    }
    if s.unknown > 0 {
        println!("note: {} file(s) are UNKNOWN, not clean", s.unknown);
    }
}

fn print_quarantine_report(q: &ScanQuarantineReport) {
    println!(
        "quarantine    : {} malicious, {} moved, {} failed",
        q.malicious_seen, q.quarantined, q.failures
    );
    for entry in &q.entries {
        println!(
            "  moved {}  {}  (original removed: {})",
            entry.id, entry.original_path, entry.original_removed
        );
    }
    for failure in &q.errors {
        println!("  FAILED {}  ({})", failure.path, failure.error);
    }
}

fn local_analyze(
    rules: &Path,
    db: Option<&Path>,
    file: &Path,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    eprintln!("litric: standalone mode (--local): no daemon involved");
    let engine = build_engine(rules, db)?;
    let scanner = Scanner::new(&engine, ScanLimits::default());
    let (r, truncated) = scanner.analyze_file(file)?;
    println!("file        : {}", r.name);
    println!("sha256      : {}", r.sha256);
    println!("size        : {} bytes", r.size);
    println!("content     : {} (extension .{})", r.format, r.ext);
    println!(
        "verdict     : {} (score {}/100, confidence {:.2})",
        r.verdict.as_str().to_uppercase(),
        r.score,
        r.confidence
    );
    if let Some(t) = &r.threat_name {
        println!("threat      : {t}");
    }
    for s in &r.signals {
        println!("  [{:>3}] {}: {}", s.weight, s.title, s.detail);
    }
    for m in &r.rules {
        println!("matched rule: {} [{}]", m.name, m.severity);
    }
    if truncated {
        println!("note        : file was sampled, not fully read");
    }
    Ok(if r.is_threat() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

struct GuardOptions {
    allow_unknown: bool,
    quarantine: bool,
    vault_dir: Option<PathBuf>,
    vault_key: Option<PathBuf>,
    args: Vec<String>,
}

fn local_guard(
    rules: &Path,
    db: Option<&Path>,
    file: &Path,
    options: GuardOptions,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let GuardOptions {
        allow_unknown,
        quarantine,
        vault_dir,
        vault_key,
        args,
    } = options;
    let target = std::fs::canonicalize(file).map_err(|e| {
        format!(
            "cannot access guard target `{}`: {e}\nThe guard must run on a regular file before it is launched.",
            file.display()
        )
    })?;
    let metadata = std::fs::metadata(&target)?;
    if !metadata.is_file() {
        return Err(format!(
            "guard target `{}` is not a regular file",
            target.display()
        )
        .into());
    }

    eprintln!(
        "litric: preflight guard (in-process); only launches through this command are protected"
    );
    let engine = build_engine(rules, db)?;
    let scanner = Scanner::new(&engine, ScanLimits::default());
    let scan_started = Instant::now();
    let (report, truncated) = scanner.analyze_file(&target)?;
    let scan_ms = scan_started.elapsed().as_millis();
    let policy = PreflightPolicy {
        allow_unknown,
        quarantine_malicious: quarantine,
    };
    let decision = decide(report.verdict, truncated, policy);

    println!("target      : {}", target.display());
    println!("sha256      : {}", report.sha256.to_hex());
    println!(
        "verdict     : {} (score {}/100, confidence {:.2})",
        report.verdict.as_str().to_uppercase(),
        report.score,
        report.confidence
    );
    if let Some(threat) = &report.threat_name {
        println!("threat      : {threat}");
    }
    println!(
        "scan        : {scan_ms} ms for {} bytes{}",
        report.size,
        if truncated { " (TRUNCATED)" } else { "" }
    );
    println!("action      : {}", decision.action.as_str());
    println!("reason      : {}", decision.reason);
    if let Some(warning) = decision.warning {
        eprintln!("guard: warning: {warning}");
    }

    match decision.action {
        PreflightAction::Allow => {
            if let Err(e) = verify_file_unchanged(
                &target,
                &report.sha256.to_hex(),
                report.size,
                ScanLimits::default().max_file_bytes,
            ) {
                eprintln!("guard: refusing to execute: {e}");
                return Ok(ExitCode::from(1));
            }
            let command_line = if args.is_empty() {
                target.display().to_string()
            } else {
                format!("{} {:?}", target.display(), args)
            };
            println!("exec        : {command_line}");
            let mut child = ProcessCommand::new(&target);
            child.args(&args);
            match child.status() {
                Ok(status) => Ok(exit_code_for(status)),
                Err(e) => {
                    eprintln!("guard: cannot execute `{}`: {e}", target.display());
                    Ok(ExitCode::from(1))
                }
            }
        }
        PreflightAction::Block => {
            eprintln!("guard: refusing to execute `{}`", target.display());
            Ok(ExitCode::from(1))
        }
        PreflightAction::Quarantine => {
            if let Err(e) = verify_file_unchanged(
                &target,
                &report.sha256.to_hex(),
                report.size,
                ScanLimits::default().max_file_bytes,
            ) {
                eprintln!("guard: refusing to quarantine or execute: {e}");
                return Ok(ExitCode::from(1));
            }
            let vault = open_local_vault(vault_dir, vault_key)?;
            let threat = report.threat_name.as_deref().unwrap_or("Malware.Preflight");
            match vault.quarantine_file(
                &target,
                threat,
                report.family.as_deref(),
                report.score,
                false,
            ) {
                Ok(meta) => {
                    println!(
                        "quarantine  : {} (original removed: {})",
                        meta.id, meta.original_removed
                    );
                    if meta.sha256 != report.sha256.to_hex() {
                        eprintln!(
                            "guard: warning: the file changed while it was being quarantined; \
                             the entry was preserved and execution is refused"
                        );
                    }
                    if !meta.original_removed {
                        eprintln!(
                            "guard: warning: the original file could not be removed; execution \
                             is still refused"
                        );
                    }
                }
                Err(e) => {
                    eprintln!("guard: quarantine FAILED: {e}");
                    eprintln!("guard: refusing to execute; the original was left in place");
                    return Ok(ExitCode::from(1));
                }
            }
            eprintln!("guard: refusing to execute `{}`", target.display());
            Ok(ExitCode::from(1))
        }
    }
}

fn open_local_vault(
    dir: Option<PathBuf>,
    key: Option<PathBuf>,
) -> Result<QuarantineVault, Box<dyn std::error::Error>> {
    let dir = dir.unwrap_or_else(|| PathBuf::from("litric-data/quarantine"));
    let key = key.unwrap_or_else(|| PathBuf::from("litric-data/vault.key"));
    // `QuarantineVault::open` enforces the protected DACL for every caller
    // (CLI, daemon, watcher) and fails closed on non-NTFS.
    Ok(QuarantineVault::open(&dir, &key)?)
}

/// Re-hashes the file immediately before launch so a replaced file cannot ride
/// on the earlier `Clean` verdict. This narrows the scan-to-exec race; it does
/// not eliminate it, because a path can still be swapped after this check.
fn verify_file_unchanged(
    path: &Path,
    expected_sha256: &str,
    expected_size: u64,
    max_file_bytes: u64,
) -> Result<(), String> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("cannot re-read `{}` before launch: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("`{}` is no longer a regular file", path.display()));
    }
    if metadata.len() != expected_size {
        return Err(format!(
            "file size changed after scan (expected {expected_size}, found {})",
            metadata.len()
        ));
    }
    if metadata.len() > max_file_bytes {
        return Err(format!(
            "file is larger than the {} byte scan cap",
            max_file_bytes
        ));
    }
    let data = std::fs::read(path)
        .map_err(|e| format!("cannot re-read `{}` before launch: {e}", path.display()))?;
    let actual = sha256_bytes(&data).to_hex();
    if actual != expected_sha256 {
        return Err(format!(
            "file content changed after scan (expected {expected_sha256}, found {actual})"
        ));
    }
    Ok(())
}

fn exit_code_for(status: ExitStatus) -> ExitCode {
    match status.code() {
        Some(0) => ExitCode::SUCCESS,
        Some(code) if (1..=255).contains(&code) => ExitCode::from(code as u8),
        Some(_) | None => ExitCode::from(1),
    }
}

fn local_quarantine(
    cmd: QuarantineCmd,
    dir: Option<PathBuf>,
    key: Option<PathBuf>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    // Goes through the same hardening path as scan/guard: quarantine commands
    // must never open a vault that other local users can read.
    let vault = open_local_vault(dir, key)?;
    match cmd {
        QuarantineCmd::List => {
            let entries = vault.list();
            if entries.is_empty() {
                println!("quarantine is empty");
            }
            for e in entries {
                println!(
                    "{}  {:<28} {}  ({} bytes)",
                    e.id, e.threat_name, e.original_path, e.size
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        QuarantineCmd::Add {
            file,
            threat,
            remove_original,
        } => {
            let meta = vault.quarantine_file(&file, &threat, None, 100, !remove_original)?;
            println!("quarantined as {}", meta.id);
            println!("original removed: {}", meta.original_removed);
            if let Some(reason) = &meta.source_retained_reason {
                println!("source retained: {reason}");
            }
            Ok(ExitCode::SUCCESS)
        }
        QuarantineCmd::Restore { id, dest } => {
            let path = vault.restore(&id, dest.as_deref())?;
            println!("restored to {}", path.display());
            Ok(ExitCode::SUCCESS)
        }
        QuarantineCmd::Verify => {
            let report = vault.verify_all();
            let bad = report.iter().filter(|(_, ok, _)| !ok).count();
            for (id, ok, msg) in &report {
                println!("{} {} {}", id, if *ok { "ok  " } else { "FAIL" }, msg);
            }
            println!("{} entry/entries, {bad} failed", report.len());
            Ok(if bad > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        QuarantineCmd::Purge { id, confirm } => {
            if !confirm {
                return Err("refusing to purge without --confirm".into());
            }
            vault.purge(&id)?;
            println!("purged {id}");
            Ok(ExitCode::SUCCESS)
        }
    }
}

// ---------------------------------------------------------------------------
// Engine tooling (in-process by design)
// ---------------------------------------------------------------------------

fn build_engine(
    rules_dir: &Path,
    db_dir: Option<&Path>,
) -> Result<Engine, Box<dyn std::error::Error>> {
    let db = match db_dir {
        Some(dir) => {
            let db = ThreatDb::load_for_runtime(dir, litric_core::ENGINE_VERSION)?;
            if db.trust == DbTrust::DevelopmentOnly {
                eprintln!(
                    "litric: warning: using a DEVELOPMENT-signed threat database; \
                     set LITRIC_DB_PUBKEY for production content"
                );
            }
            db
        }
        None => ThreatDb::empty(),
    };
    let mut rules: Vec<Rule> = Vec::new();
    if rules_dir.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(rules_dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("lrs"))
            .collect();
        entries.sort();
        for path in entries {
            let text = std::fs::read_to_string(&path)?;
            match parse_rule_file(&text, &path.display().to_string()) {
                Ok(mut r) => rules.append(&mut r),
                Err(e) => eprintln!("litric: rule error in {}: {e}", path.display()),
            }
        }
    }
    for r in &db.payload.rules {
        if let Ok(mut parsed) = parse_rule_file(&r.text, &format!("db:{}", r.name)) {
            rules.append(&mut parsed);
        }
    }
    Ok(Engine::new(
        RuleSet::compile(rules)?,
        db,
        EngineConfig::default(),
    ))
}

fn lint_rules(dir: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut total = 0usize;
    let mut failed = 0usize;
    let mut seen = std::collections::HashSet::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("lrs"))
        .collect();
    entries.sort();
    if entries.is_empty() {
        eprintln!("litric: no .lrs files in {}", dir.display());
        return Ok(ExitCode::from(1));
    }
    for path in entries {
        let text = std::fs::read_to_string(&path)?;
        match parse_rule_file(&text, &path.display().to_string()) {
            Ok(rules) => {
                for r in &rules {
                    total += 1;
                    if !seen.insert(r.name.clone()) {
                        eprintln!("{}: duplicate rule name `{}`", path.display(), r.name);
                        failed += 1;
                    }
                    if r.meta.description.is_empty() {
                        eprintln!("{}: rule `{}` has no description", path.display(), r.name);
                        failed += 1;
                    }
                }
                println!("{}: {} rule(s) ok", path.display(), rules.len());
            }
            Err(e) => {
                eprintln!("{}: {e}", path.display());
                failed += 1;
            }
        }
    }
    println!("{total} rule(s) parsed, {failed} problem(s)");
    Ok(if failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn build_db(
    rules_dir: &Path,
    out: &Path,
    version: u64,
    hashes: Option<&Path>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut rule_sources = Vec::new();
    if rules_dir.is_dir() {
        for entry in std::fs::read_dir(rules_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("lrs") {
                let text = std::fs::read_to_string(&path)?;
                parse_rule_file(&text, &path.display().to_string())?;
                rule_sources.push(RuleSource {
                    name: path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("rules")
                        .to_string(),
                    text,
                    license: Some("Litric Labs proprietary".into()),
                    author: Some("Litric Labs".into()),
                });
            }
        }
    }
    let mut hash_entries: Vec<HashEntry> = Vec::new();
    if let Some(h) = hashes {
        hash_entries = serde_json::from_str(&std::fs::read_to_string(h)?)?;
    }
    let payload = DbPayload {
        schema: DB_FORMAT_VERSION,
        db_version: version,
        min_engine: litric_core::ENGINE_VERSION.to_string(),
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        hashes: hash_entries,
        rules: rule_sources,
        revoked_rules: Vec::new(),
        revoked_hashes: Vec::new(),
        sources: vec!["Litric Labs core rules".into()],
    };
    let (payload_bytes, manifest_bytes) = build_signed(&payload, &dev_signing_key())?;
    let db = ThreatDb::install(
        out,
        &payload_bytes,
        &manifest_bytes,
        &[],
        true,
        litric_core::ENGINE_VERSION,
        false,
    )?;
    println!(
        "wrote threat database v{} to {} ({} rule file(s), {} hash entry/entries)",
        db.version(),
        out.display(),
        db.payload.rules.len(),
        db.payload.hashes.len()
    );
    println!(
        "WARNING: signed with the development key. Production builds must use the Litric \
         production signing key."
    );
    Ok(ExitCode::SUCCESS)
}

fn verify_db(dir: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    // Diagnostic path: accepts the fixture key so an operator can inspect test
    // content, and prints the resulting trust level. Runtime code must use
    // `ThreatDb::load_for_runtime`, never this call.
    match ThreatDb::open_dir(dir, &[], true, litric_core::ENGINE_VERSION) {
        Ok(db) => {
            println!("signature   : valid");
            println!("trust       : {:?}", db.trust);
            println!("db version  : {}", db.version());
            println!("min engine  : {}", db.payload.min_engine);
            println!("rules       : {}", db.payload.rules.len());
            println!("hash entries: {}", db.payload.hashes.len());
            println!(
                "revoked     : {} rule(s), {} hash(es)",
                db.payload.revoked_rules.len(),
                db.payload.revoked_hashes.len()
            );
            println!("warning     : development key — not production content");
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("litric: database verification failed: {e}");
            Ok(ExitCode::from(1))
        }
    }
}

fn bench(path: &Path, runs: usize, rules_dir: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let engine = build_engine(rules_dir, None)?;
    println!(
        "engine {} v{} with {} rules",
        litric_core::ENGINE_NAME,
        litric_core::ENGINE_VERSION,
        engine.rules().len()
    );
    let mut best = f64::MAX;
    for i in 0..runs.max(1) {
        let mut scanner = Scanner::new(&engine, ScanLimits::default());
        let start = Instant::now();
        let summary = scanner.scan_path(path);
        let secs = start.elapsed().as_secs_f64();
        let fps = summary.files_scanned as f64 / secs.max(1e-9);
        let mbps = (summary.bytes_scanned as f64 / (1024.0 * 1024.0)) / secs.max(1e-9);
        best = best.min(secs);
        println!(
            "run {}: {} files in {:.3}s = {:.0} files/s, {:.1} MB/s",
            i + 1,
            summary.files_scanned,
            secs,
            fps,
            mbps
        );
    }
    println!("best wall time: {best:.3}s");
    Ok(ExitCode::SUCCESS)
}
