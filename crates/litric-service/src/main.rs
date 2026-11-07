//! `litricd` — the Litric Defender background service backend.
//!
//! Runs a loopback HTTP/JSON API over the detection engine. Designed to be the
//! single source of truth for the Windows UI: no UI process scans files itself.
//!
//! Two ways to run it:
//!
//! * `litricd serve` — foreground process for development and CLI clients.
//! * `litricd service install` + SCM start — the real Windows service. The SCM
//!   starts `litricd run-service`, which calls `StartServiceCtrlDispatcherW`
//!   before doing any other work.
//!
//! The service mode never prints the bearer token (stdout is not connected when
//! the SCM starts a service) and writes its diagnostics to `service.log` in the
//! data directory.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};

use litric_core::engine::{Engine, EngineConfig};
use litric_core::quarantine::QuarantineVault;
use litric_core::rules::{parse_rule_file, Rule, RuleSet};
use litric_core::threatdb::{DbTrust, ThreatDb};
use litric_service::{load_or_create_token, server, AppState};
use processgate::{GateConfig, GateMode};

#[cfg(windows)]
use litric_service::winsvc;

/// CLI spelling of the process-gate mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum GateArg {
    Off,
    Monitor,
    Enforce,
}

impl GateArg {
    fn as_str(self) -> &'static str {
        match self {
            GateArg::Off => "off",
            GateArg::Monitor => "monitor",
            GateArg::Enforce => "enforce",
        }
    }
}

impl From<GateArg> for GateMode {
    fn from(value: GateArg) -> Self {
        match value {
            GateArg::Off => GateMode::Off,
            GateArg::Monitor => GateMode::Monitor,
            GateArg::Enforce => GateMode::EnforceHash,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "litricd",
    version = litric_core::ENGINE_VERSION,
    about = "Litric Defender background service (local API backend)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the API server in the foreground.
    Serve {
        /// Loopback address to listen on. Anything non-loopback is refused.
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: String,
        /// Directory for settings, history, quarantine and the vault key.
        #[arg(long, default_value = "./litric-data")]
        data_dir: PathBuf,
        /// Directory containing .lrs detection rules.
        #[arg(long, default_value = "rules")]
        rules: PathBuf,
        /// Optional signed threat database directory.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Bearer token file (created with random content if missing).
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Print the bearer token to stdout at startup. Only use on a trusted console.
        #[arg(long)]
        print_token: bool,
        /// Best-effort process gate: suspend new processes, scan, then resume
        /// (monitor) or terminate on an exact malicious hash (enforce).
        #[arg(long, value_enum, default_value = "off")]
        process_gate: GateArg,
    },
    /// Entry point used by the Service Control Manager. Not for interactive use.
    RunService {
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: String,
        /// Defaults to %ProgramData%\Litric Defender in service mode.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Defaults to the `rules` folder next to the executable.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Defaults to `<data-dir>\db` when that directory exists.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Process gate mode. The installed service defaults to `monitor`:
        /// it reports what it would block but terminates nothing. Pass
        /// `--process-gate enforce` to allow hash-matched termination.
        #[arg(long, value_enum, default_value = "monitor")]
        process_gate: GateArg,
    },
    /// Print (creating if needed) the API token.
    Token {
        #[arg(long, default_value = "./litric-data/api.token")]
        token_file: PathBuf,
    },
    /// Install, remove or query the Windows service.
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceAction {
    /// Register this executable as an auto-start Windows service.
    Install {
        /// Print the exact SCM operations without performing them.
        #[arg(long)]
        dry_run: bool,
        /// Process gate mode the service starts with. `monitor` (the default)
        /// reports but never terminates; `enforce` allows hash-matched kills.
        #[arg(long, value_enum, default_value = "monitor")]
        process_gate: GateArg,
    },
    /// Stop and delete the service. User data and quarantine are preserved.
    Uninstall {
        #[arg(long)]
        dry_run: bool,
    },
    /// Show the SCM's view of the service.
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Serve {
            addr,
            data_dir,
            rules,
            db,
            token_file,
            print_token,
            process_gate,
        }) => serve(
            &addr,
            &data_dir,
            &rules,
            db.as_deref(),
            token_file,
            print_token,
            process_gate,
        ),
        Some(Command::RunService {
            addr,
            data_dir,
            rules,
            db,
            process_gate,
        }) => run_service(&addr, data_dir, rules, db, process_gate),
        Some(Command::Token { token_file }) => match load_or_create_token(&token_file) {
            Ok(t) => {
                println!("{t}");
                println!("(stored in {})", token_file.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("litricd: cannot manage token: {e}");
                ExitCode::from(2)
            }
        },
        #[cfg(windows)]
        Some(Command::Service { action }) => service_command(action),
        None => {
            eprintln!("litricd: no command given; run `litricd --help`");
            ExitCode::from(2)
        }
    }
}

/// A started daemon: the listener plus the state it serves.
struct Running {
    handle: server::ServerHandle,
    token_path: PathBuf,
    state: Arc<AppState>,
}

fn start(
    addr: &str,
    data_dir: &Path,
    rules_dir: &Path,
    db_dir: Option<&Path>,
    token_file: Option<PathBuf>,
    print_token: bool,
    gate: GateMode,
) -> Result<Running, Box<dyn std::error::Error + Send + Sync>> {
    // `serve` (local mode) has no installer step that could have hardened this
    // directory, so do it here before the token or vault key exists. When
    // `run-service` already hardened the same path this is idempotent.
    #[cfg(windows)]
    {
        std::fs::create_dir_all(data_dir)?;
        winsvc::restrict_to_system_and_admins(data_dir)?;
    }

    let token_path = token_file.unwrap_or_else(|| data_dir.join("api.token"));
    let token = load_or_create_token(&token_path)?;
    let engine = build_engine(rules_dir, db_dir)?;
    let vault = QuarantineVault::open(
        &data_dir.join("quarantine"),
        &data_dir.join("vault.key"),
    )?;
    let state = AppState::new(engine, vault, data_dir, token.clone())?;

    if gate != GateMode::Off {
        // Starting the gate requires the platform module; a failure here fails
        // the daemon start rather than silently running without protection.
        let handle = processgate::spawn(
            state.engine.clone(),
            Box::new(processgate::windows::WindowsControl::new()),
            gate,
            GateConfig::default(),
            processgate::windows::protected_set(),
        )?;
        state.set_process_gate(Arc::new(handle));
    }

    let handle = server::serve(state.clone(), addr)?;
    let _ = print_token;
    Ok(Running {
        handle,
        token_path,
        state,
    })
}

fn serve(
    addr: &str,
    data_dir: &Path,
    rules_dir: &Path,
    db_dir: Option<&Path>,
    token_file: Option<PathBuf>,
    print_token: bool,
    gate: GateArg,
) -> ExitCode {
    let running = match start(
        addr,
        data_dir,
        rules_dir,
        db_dir,
        token_file,
        print_token,
        gate.into(),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("litricd: cannot start: {e}");
            return ExitCode::from(2);
        }
    };

    println!("Litric Defender service {}", litric_core::ENGINE_VERSION);
    println!("listening   : http://{}", running.handle.addr);
    println!("data dir    : {}", data_dir.display());
    println!("token file  : {}", running.token_path.display());
    println!("rules       : {} loaded", running.state.engine.rules().len());
    println!(
        "threat db   : v{} ({:?})",
        running.state.engine.db().version(),
        running.state.engine.db().trust
    );
    println!("real-time   : NOT ACTIVE (no kernel sensor in this build)");
    match running.state.process_gate() {
        Some(handle) => println!(
            "proc gate   : {} (best-effort: suspend, scan, resume; hash-only block)",
            handle.mode().as_str()
        ),
        None => println!("proc gate   : off"),
    }
    println!("press Ctrl+C to stop");
    if print_token {
        println!("bearer token: {}", running.state.token);
    }

    // The listener thread owns the accept loop; park this thread until the
    // process is interrupted or the server stops itself.
    loop {
        std::thread::sleep(Duration::from_millis(500));
        if !running.handle.is_running() {
            if let Some(gate) = running.state.process_gate() {
                gate.stop();
            }
            return ExitCode::from(1);
        }
    }
}

#[cfg(windows)]
fn run_service(
    addr: &str,
    data_dir: Option<PathBuf>,
    rules: Option<PathBuf>,
    db: Option<PathBuf>,
    gate: GateArg,
) -> ExitCode {
    let data_dir = data_dir.unwrap_or_else(winsvc::program_data_dir);
    let rules = rules.unwrap_or_else(exe_rules_dir);
    // A signed database installed next to the service data is picked up without
    // extra arguments; absent, the engine runs with rules only and says so.
    let db = db.or_else(|| {
        let candidate = data_dir.join("db");
        candidate.is_dir().then_some(candidate)
    });

    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        eprintln!("litricd: cannot create {}: {e}", data_dir.display());
        return ExitCode::from(2);
    }
    // The data directory holds the API token and the vault key. Refuse to serve
    // them from a location any local user can read.
    if let Err(e) = winsvc::restrict_to_system_and_admins(&data_dir) {
        eprintln!(
            "litricd: refusing to start: cannot restrict {} to SYSTEM/Administrators: {e}",
            data_dir.display()
        );
        return ExitCode::from(2);
    }

    let log = match winsvc::ServiceLog::open(&data_dir) {
        Ok(l) => Some(Arc::new(l)),
        Err(e) => {
            eprintln!("litricd: cannot open service log: {e}");
            None
        }
    };

    let say = {
        let log = log.clone();
        move |message: String| match log.as_ref() {
            Some(log) => log.write(&message),
            None => eprintln!("litricd: {message}"),
        }
    };

    say(format!(
        "Litric Defender service {} starting (data {}, rules {}, db {}, gate {})",
        litric_core::ENGINE_VERSION,
        data_dir.display(),
        rules.display(),
        db.as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "none".into()),
        GateMode::from(gate).as_str()
    ));

    let addr = addr.to_string();
    let body = {
        let data_dir = data_dir.clone();
        let rules = rules.clone();
        let say = say.clone();
        move |_ctx: winsvc::ServiceContext, stop: winsvc::StopToken| -> u32 {
            match start(
                &addr,
                &data_dir,
                &rules,
                db.as_deref(),
                None,
                false,
                gate.into(),
            ) {
                Ok(running) => {
                    say(format!(
                        "listening on http://{} with {} rules",
                        running.handle.addr,
                        running.state.engine.rules().len()
                    ));
                    while !stop.wait_timeout(Duration::from_millis(500)) {}
                    if let Some(gate) = running.state.process_gate() {
                        gate.stop();
                        say(format!(
                            "process gate stopped: seen={} scanned={} blocked={} unprotected={}",
                            gate.stats().seen,
                            gate.stats().scanned,
                            gate.stats().blocked,
                            gate.stats().unprotected
                        ));
                    }
                    running.handle.shutdown();
                    say("stop requested; API listener shut down".to_string());
                    0
                }
                Err(e) => {
                    say(format!("cannot start: {e}"));
                    1
                }
            }
        }
    };

    match winsvc::run(body) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("litricd: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(windows)]
fn service_command(action: ServiceAction) -> ExitCode {
    match action {
        ServiceAction::Install {
            dry_run,
            process_gate,
        } => {
            let extra = format!("--process-gate {}", process_gate.as_str());
            let line = match winsvc::installed_command_line_with(&extra) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("litricd: cannot resolve this executable: {e}");
                    return ExitCode::from(2);
                }
            };
            if dry_run {
                for step in winsvc::planned_operations(&line) {
                    println!("{step}");
                }
                println!("dry run: nothing was changed");
                return ExitCode::SUCCESS;
            }
            if !winsvc::is_elevated() {
                eprintln!("litricd: {}", winsvc::ServiceError::AccessDenied);
                eprintln!("hint: rerun this command from an elevated (administrator) prompt");
                return ExitCode::from(5);
            }
            match winsvc::install(&extra) {
                Ok(winsvc::InstallOutcome::Created) => {
                    println!(
                        "installed service {} (auto-start, LocalSystem, delayed start)",
                        winsvc::SERVICE_NAME
                    );
                    println!("binary: {line}");
                    println!("the service will start at the next boot; start it now with:");
                    println!("  sc.exe start {}", winsvc::SERVICE_NAME);
                    ExitCode::SUCCESS
                }
                Ok(winsvc::InstallOutcome::Updated) => {
                    println!(
                        "service {} already existed and now points at {line}",
                        winsvc::SERVICE_NAME
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("litricd: cannot install service: {e}");
                    match e {
                        winsvc::ServiceError::AccessDenied => ExitCode::from(5),
                        _ => ExitCode::from(2),
                    }
                }
            }
        }
        ServiceAction::Uninstall { dry_run } => {
            if dry_run {
                println!("would stop and delete service {}", winsvc::SERVICE_NAME);
                println!("would not touch user data, quarantine, Defender, or the firewall");
                println!("dry run: nothing was changed");
                return ExitCode::SUCCESS;
            }
            if !winsvc::is_elevated() {
                eprintln!("litricd: {}", winsvc::ServiceError::AccessDenied);
                return ExitCode::from(5);
            }
            match winsvc::uninstall() {
                Ok(()) => {
                    println!("removed service {}", winsvc::SERVICE_NAME);
                    println!("user data and quarantine were left in place on purpose");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("litricd: cannot remove service: {e}");
                    match e {
                        winsvc::ServiceError::AccessDenied => ExitCode::from(5),
                        _ => ExitCode::from(2),
                    }
                }
            }
        }
        ServiceAction::Status => match winsvc::status() {
            Ok(s) => {
                println!("service : {}", winsvc::SERVICE_NAME);
                println!("state   : {}", s.state.label());
                println!("pid     : {}", s.process_id);
                ExitCode::SUCCESS
            }
            Err(winsvc::ServiceError::NotInstalled) => {
                println!("service {} is not installed", winsvc::SERVICE_NAME);
                ExitCode::from(3)
            }
            Err(e) => {
                eprintln!("litricd: {e}");
                ExitCode::from(2)
            }
        },
    }
}

/// `rules` next to the executable when it exists (installed layout), otherwise
/// the working-directory `rules` (source checkout).
fn exe_rules_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join("rules")))
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| PathBuf::from("rules"))
}

fn build_engine(
    rules_dir: &Path,
    db_dir: Option<&Path>,
) -> Result<Engine, Box<dyn std::error::Error + Send + Sync>> {
    let db = match db_dir {
        Some(dir) => {
            let db = ThreatDb::load_for_runtime(dir, litric_core::ENGINE_VERSION)?;
            if db.trust == DbTrust::DevelopmentOnly {
                eprintln!(
                    "litricd: warning: using a DEVELOPMENT-signed threat database; \
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
                // A broken rule file must not stop the service; it is reported
                // and skipped, and the status endpoint shows the rule count.
                Err(e) => eprintln!("litricd: rule error in {}: {e}", path.display()),
            }
        }
    }
    for r in &db.payload.rules {
        if let Ok(mut parsed) = parse_rule_file(&r.text, &format!("db:{}", r.name)) {
            rules.append(&mut parsed);
        }
    }
    let ruleset = RuleSet::compile(rules)?;
    Ok(Engine::new(ruleset, db, EngineConfig::default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn gate_of(args: &[&str]) -> GateArg {
        match Cli::parse_from(args).command {
            Some(Command::Serve { process_gate, .. })
            | Some(Command::RunService { process_gate, .. }) => process_gate,
            _ => panic!("expected a serve or run-service command"),
        }
    }

    /// Safety default: a foreground daemon must not touch processes unless asked.
    #[test]
    fn serve_defaults_to_gate_off() {
        assert_eq!(gate_of(&["litricd", "serve"]), GateArg::Off);
    }

    /// Safety default: the installed service reports, it does not terminate.
    #[test]
    fn run_service_defaults_to_monitor_not_enforce() {
        assert_eq!(gate_of(&["litricd", "run-service"]), GateArg::Monitor);
    }

    /// Enforcement stays available, but only as an explicit choice.
    #[test]
    fn enforce_is_opt_in() {
        assert_eq!(
            gate_of(&["litricd", "run-service", "--process-gate", "enforce"]),
            GateArg::Enforce
        );
        assert_eq!(
            gate_of(&["litricd", "serve", "--process-gate", "enforce"]),
            GateArg::Enforce
        );
    }
}
