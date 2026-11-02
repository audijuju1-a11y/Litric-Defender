//! `litric` — Litric Defender command line scanner and engine tooling.
//!
//! This is the reference front-end for the engine. It is a real scanner: the
//! same `litric-core` code that the Windows service uses. On Windows it can be
//! registered as a shell-context "Scan with Litric" handler.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};

use litric_core::engine::{Engine, EngineConfig, FileReport};
use litric_core::quarantine::QuarantineVault;
use litric_core::rules::{parse_rule_file, RuleSet};
use litric_core::scan::{ScanCache, ScanLimits, Scanner};
use litric_core::threatdb::{
    build_signed, dev_signing_key, DbPayload, DbTrust, HashEntry, RuleSource, ThreatDb,
    DB_FORMAT_VERSION,
};

#[derive(Parser)]
#[command(
    name = "litric",
    version = litric_core::ENGINE_VERSION,
    about = "Litric Defender engine: scanner, rule tooling and quarantine vault",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a file or directory tree.
    Scan {
        path: PathBuf,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
        /// Directory holding .lrs rules.
        #[arg(long, default_value = "rules")]
        rules: String,
        /// Directory holding a signed threat database.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Wall-clock budget in seconds.
        #[arg(long)]
        timeout: Option<u64>,
        /// Maximum bytes read per file.
        #[arg(long, default_value_t = 128 * 1024 * 1024)]
        max_file_bytes: u64,
        /// Cache results for unchanged files in this directory.
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Exit non-zero when anything is malicious or suspicious.
        #[arg(long)]
        fail_on_threat: bool,
    },
    /// Analyse one file and print the full evidence report.
    Analyze {
        file: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value = "rules")]
        rules: String,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Parse and validate rule files.
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    /// Threat database operations.
    Db {
        #[command(subcommand)]
        cmd: DbCmd,
    },
    /// Quarantine vault operations.
    Quarantine {
        #[command(subcommand)]
        cmd: QuarantineCmd,
    },
    /// Measure scan throughput on a directory.
    Bench {
        path: PathBuf,
        #[arg(long, default_value_t = 3)]
        runs: usize,
        #[arg(long, default_value = "rules")]
        rules: String,
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
        /// Directory holding .lrs rules.
        #[arg(long, default_value = "rules")]
        rules: PathBuf,
        /// Output directory.
        #[arg(long)]
        out: PathBuf,
        /// Database version (must increase for updates to be accepted).
        #[arg(long, default_value_t = 1)]
        version: u64,
        /// Optional JSON array of {sha256,name,kind} hash entries.
        #[arg(long)]
        hashes: Option<PathBuf>,
    },
    /// Verify a database directory against its signature.
    Verify {
        #[arg(long)]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// Quarantine a file: encrypt, verify, then remove the original.
    Add {
        file: PathBuf,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "User.Request")]
        threat: String,
    },
    /// List quarantined objects.
    List {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Restore one object by id.
    Restore {
        id: String,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Restore here instead of the original path.
        #[arg(long)]
        dest: Option<PathBuf>,
    },
    /// Verify every entry decrypts and matches its recorded hash.
    Verify {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("litric: error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Scan {
            path,
            json,
            rules,
            db,
            timeout,
            max_file_bytes,
            cache,
            fail_on_threat,
        } => {
            let engine = build_engine(Path::new(&rules), db.as_deref())?;
            let limits = ScanLimits {
                max_file_bytes,
                deadline: timeout.map(std::time::Duration::from_secs),
                ..Default::default()
            };
            let mut cache_store = cache.as_ref().map(|_| ScanCache::new());
            let summary = {
                let mut scanner = Scanner::new(&engine, limits);
                if let Some(c) = cache_store.as_mut() {
                    scanner = scanner.with_cache(c);
                }
                scanner.scan_path(&path)
            };

            if json {
                let detections: Vec<_> = summary
                    .detections
                    .iter()
                    .map(|d| {
                        serde_json::json!({
                            "path": d.path.display().to_string(),
                            "verdict": d.verdict.as_str(),
                            "score": d.score,
                            "threat": d.threat_name,
                            "sha256": d.sha256,
                            "truncated": d.truncated,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "engine": litric_core::ENGINE_NAME,
                        "engine_version": litric_core::ENGINE_VERSION,
                        "rules_loaded": engine.rules().len(),
                        "db_version": engine.db().version(),
                        "db_trust": format!("{:?}", engine.db().trust),
                        "files_scanned": summary.files_scanned,
                        "clean": summary.clean,
                        "unknown": summary.unknown,
                        "suspicious": summary.suspicious,
                        "malicious": summary.malicious,
                        "unreadable": summary.unreadable,
                        "skipped_too_large": summary.skipped_too_large,
                        "skipped_budget": summary.skipped_budget,
                        "truncated": summary.truncated,
                        "bytes_scanned": summary.bytes_scanned,
                        "duration_ms": summary.duration.as_millis(),
                        "files_per_second": summary.files_per_second(),
                        "detections": detections,
                        "errors": summary.errors.iter().map(|(p, e)| serde_json::json!({
                            "path": p.display().to_string(), "error": e
                        })).collect::<Vec<_>>(),
                    }))?
                );
            } else {
                print_summary(&summary, &engine);
            }

            if fail_on_threat && (summary.malicious > 0 || summary.suspicious > 0) {
                return Ok(ExitCode::from(1));
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Analyze {
            file,
            json,
            rules,
            db,
        } => {
            let engine = build_engine(Path::new(&rules), db.as_deref())?;
            let scanner = Scanner::new(&engine, ScanLimits::default());
            let (report, truncated) = scanner.analyze_file(&file)?;
            if json {
                println!("{}", report_json(&report, truncated));
            } else {
                print_report(&report, truncated);
            }
            Ok(if report.is_threat() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }

        Command::Rules {
            cmd: RulesCmd::Lint { dir },
        } => lint_rules(&dir),

        Command::Db {
            cmd: DbCmd::Build {
                rules,
                out,
                version,
                hashes,
            },
        } => build_db(&rules, &out, version, hashes.as_deref()),

        Command::Db {
            cmd: DbCmd::Verify { dir },
        } => verify_db(&dir),

        Command::Quarantine { cmd } => quarantine_cmd(cmd),

        Command::Bench { path, runs, rules } => bench(&path, runs, Path::new(&rules)),
    }
}

fn build_engine(rules_dir: &Path, db_dir: Option<&Path>) -> Result<Engine, Box<dyn std::error::Error>> {
    let mut sources = Vec::new();
    if rules_dir.is_dir() {
        for entry in std::fs::read_dir(rules_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("lrs") {
                let text = std::fs::read_to_string(&path)?;
                sources.push((path.display().to_string(), text));
            }
        }
    }
    // Rules shipped inside a signed database are added too.
    let db = match db_dir {
        Some(dir) => {
            let db = ThreatDb::open_dir(
                dir,
                // No production keys are pinned in this build, so a dev-signed
                // database is reported as DevelopmentOnly rather than trusted.
                &[],
                true,
                litric_core::ENGINE_VERSION,
            )?;
            if db.trust == DbTrust::DevelopmentOnly {
                eprintln!(
                    "litric: warning: threat database `{}` is signed with the DEVELOPMENT key; \
                     it must not be treated as production content",
                    dir.display()
                );
            }
            db
        }
        None => ThreatDb::empty(),
    };
    for (name, text) in db.payload.rules.iter().map(|r| (r.name.clone(), r.text.clone())) {
        sources.push((format!("db:{name}"), text));
    }

    let mut rules = Vec::new();
    for (source, text) in &sources {
        match parse_rule_file(text, source) {
            Ok(mut r) => rules.append(&mut r),
            Err(e) => eprintln!("litric: rule error in {source}: {e}"),
        }
    }
    let ruleset = RuleSet::compile(rules)?;
    Ok(Engine::new(ruleset, db, EngineConfig::default()))
}

fn print_summary(summary: &litric_core::scan::ScanSummary, engine: &Engine) {
    println!("Litric Defender {} ({})", litric_core::ENGINE_VERSION, litric_core::ENGINE_NAME);
    println!(
        "rules: {}   threat db: v{} ({:?})",
        engine.rules().len(),
        engine.db().version(),
        engine.db().trust
    );
    println!("---------------------------------------------------------------");
    println!("files scanned : {}", summary.files_scanned);
    println!("  clean       : {}", summary.clean);
    println!("  unknown     : {}", summary.unknown);
    println!("  suspicious  : {}", summary.suspicious);
    println!("  malicious   : {}", summary.malicious);
    println!(
        "skipped       : {} (too large {}, budget {}, links {}, duplicates {})",
        summary.skipped,
        summary.skipped_too_large,
        summary.skipped_budget,
        summary.skipped_links,
        summary.skipped_duplicates
    );
    println!("unreadable    : {}", summary.unreadable);
    println!("truncated     : {}", summary.truncated);
    println!(
        "throughput    : {:.0} files/s, {:.1} MB/s, {:?}",
        summary.files_per_second(),
        summary.mb_per_second(),
        summary.duration
    );
    if summary.cache_hits > 0 {
        println!("cache hits    : {}", summary.cache_hits);
    }
    if !summary.detections.is_empty() {
        println!("---------------------------------------------------------------");
        for d in &summary.detections {
            println!(
                "{:>10}  {:<10}  {}",
                d.verdict.as_str(),
                d.threat_name.as_deref().unwrap_or("-"),
                d.path.display()
            );
        }
    }
    if !summary.errors.is_empty() {
        println!("---------------------------------------------------------------");
        for (p, e) in &summary.errors {
            println!("error: {}: {e}", p.display());
        }
    }
    if summary.unknown > 0 {
        println!(
            "note: {} file(s) are UNKNOWN, not clean. Litric only reports `clean` for \
             positively trusted content.",
            summary.unknown
        );
    }
}

fn print_report(r: &FileReport, truncated: bool) {
    println!("file        : {}", r.name);
    println!("sha256      : {}", r.sha256);
    println!("size        : {} bytes", r.size);
    println!("content     : {} (extension: .{})", r.format, r.ext);
    println!("verdict     : {} (score {}/100, confidence {:.2})",
        r.verdict.as_str().to_uppercase(), r.score, r.confidence);
    if let Some(t) = &r.threat_name {
        println!("threat      : {t}");
    }
    if let Some(f) = &r.family {
        println!("family      : {f}");
    }
    if let Some(pe) = &r.pe {
        println!(
            "pe          : {} {}{}{} | {} sections, {} imports, entropy {:.2}",
            pe.machine,
            if pe.is_dll { "DLL" } else { "EXE" },
            if pe.is_driver { " (kernel driver)" } else { "" },
            if pe.is_dotnet { " (.NET)" } else { "" },
            pe.sections,
            pe.imports,
            pe.code_entropy
        );
        println!(
            "signature   : {}",
            if pe.signed {
                format!("present ({} subject(s))", pe.signers.len())
            } else {
                "absent".to_string()
            }
        );
        if !pe.signers.is_empty() {
            println!("signers     : {}", pe.signers.join(", "));
        }
        println!(
            "hardening   : ASLR {} | DEP {} | CFG {} | checksum {}",
            yes_no(pe.aslr),
            yes_no(pe.dep),
            yes_no(pe.cfg),
            if pe.checksum_valid { "ok" } else { "invalid/unset" }
        );
        if !pe.packer_hints.is_empty() {
            println!("packer      : {}", pe.packer_hints.join(", "));
        }
    }
    if !r.mitre.is_empty() {
        println!("mitre       : {}", r.mitre.join(", "));
    }
    if !r.signals.is_empty() {
        println!("---------------------------------------------------------------");
        println!("evidence:");
        for s in &r.signals {
            println!(
                "  [{:>3}] {} {}",
                s.weight,
                s.title,
                if s.mitre.is_empty() {
                    String::new()
                } else {
                    format!("({})", s.mitre.join(","))
                }
            );
            println!("        {}", s.detail);
        }
    }
    if !r.rules.is_empty() {
        println!("matched rules:");
        for m in &r.rules {
            println!("  {} [{}] {}", m.name, m.severity, m.description);
        }
    }
    for n in &r.notes {
        println!("note        : {n}");
    }
    if truncated {
        println!("note        : file was sampled, not fully read (size cap)");
    }
}

fn report_json(r: &FileReport, truncated: bool) -> String {
    serde_json::json!({
        "name": r.name,
        "sha256": r.sha256.to_hex(),
        "size": r.size,
        "format": r.format,
        "extension": r.ext,
        "verdict": r.verdict.as_str(),
        "score": r.score,
        "confidence": r.confidence,
        "threat": r.threat_name,
        "family": r.family,
        "mitre": r.mitre,
        "signals": r.signals.iter().map(|s| serde_json::json!({
            "id": s.id,
            "weight": s.weight,
            "confidence": s.confidence.as_str(),
            "title": s.title,
            "detail": s.detail,
            "mitre": s.mitre,
        })).collect::<Vec<_>>(),
        "rules": r.rules.iter().map(|m| serde_json::json!({
            "name": m.name,
            "severity": m.severity.as_str(),
            "description": m.description,
            "matched_strings": m.matched_strings,
        })).collect::<Vec<_>>(),
        "notes": r.notes,
        "truncated": truncated,
        "engine": r.engine,
        "engine_version": r.engine_version,
    })
    .to_string()
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn lint_rules(dir: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut total = 0usize;
    let mut failed = 0usize;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
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
                    if r.strings.is_empty() && !matches!(r.condition, litric_core::rules::Cond::Literal(_)) {
                        // only a literal condition can be stringless
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
    Ok(if failed > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS })
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
                // Validate before publishing: a database with a broken rule is
                // worse than no update.
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
        let raw = std::fs::read_to_string(h)?;
        hash_entries = serde_json::from_str(&raw)?;
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
    );
    match db {
        Ok(d) => {
            println!(
                "wrote threat database v{} to {} ({} rule file(s), {} hash entry/entries)",
                d.version(),
                out.display(),
                d.payload.rules.len(),
                d.payload.hashes.len()
            );
            println!(
                "WARNING: signed with the development key. Production builds must use the \
                 Litric production signing key."
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => Err(e.into()),
    }
}

fn verify_db(dir: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match ThreatDb::open_dir(dir, &[], true, litric_core::ENGINE_VERSION) {
        Ok(db) => {
            println!("signature   : valid");
            println!("trust       : {:?}", db.trust);
            println!("db version  : {}", db.version());
            println!("min engine  : {}", db.payload.min_engine);
            println!("rules       : {}", db.payload.rules.len());
            println!("hash entries: {}", db.payload.hashes.len());
            println!("revoked     : {} rule(s), {} hash(es)",
                db.payload.revoked_rules.len(), db.payload.revoked_hashes.len());
            if db.trust == DbTrust::DevelopmentOnly {
                println!("warning     : development key — not production content");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("litric: database verification failed: {e}");
            Ok(ExitCode::from(1))
        }
    }
}

fn quarantine_cmd(cmd: QuarantineCmd) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cmd {
        QuarantineCmd::Add {
            file,
            dir,
            key,
            threat,
        } => {
            let v = QuarantineVault::open(&dir, &key)?;
            let meta = v.quarantine_file(&file, &threat, None, 100, false)?;
            println!("quarantined {} as {}", file.display(), meta.id);
            println!("sha256      : {}", meta.sha256);
            println!("original removed: {}", meta.original_removed);
            Ok(ExitCode::SUCCESS)
        }
        QuarantineCmd::List { dir, key } => {
            let v = QuarantineVault::open(&dir, &key)?;
            let entries = v.list();
            if entries.is_empty() {
                println!("quarantine is empty");
            }
            for e in entries {
                println!(
                    "{}  {}  {:>10}  {}  ({})",
                    e.id,
                    e.threat_name,
                    format_size(e.size),
                    e.original_path,
                    e.sha256
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        QuarantineCmd::Restore {
            id,
            dir,
            key,
            dest,
        } => {
            let v = QuarantineVault::open(&dir, &key)?;
            let target = v.restore(&id, dest.as_deref())?;
            println!("restored to {}", target.display());
            Ok(ExitCode::SUCCESS)
        }
        QuarantineCmd::Verify { dir, key } => {
            let v = QuarantineVault::open(&dir, &key)?;
            let report = v.verify_all();
            let bad = report.iter().filter(|(_, ok, _)| !ok).count();
            for (id, ok, msg) in &report {
                println!("{} {} {}", id, if *ok { "ok  " } else { "FAIL" }, msg);
            }
            println!("{} entry/entries, {bad} failed", report.len());
            Ok(if bad > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS })
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

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[allow(dead_code)]
fn format_note() {}
