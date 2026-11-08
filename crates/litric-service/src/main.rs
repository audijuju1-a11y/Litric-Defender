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

/// CLI spelling of the real-time file monitor switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum RealtimeArg {
    Off,
    On,
}

impl RealtimeArg {
    fn as_str(self) -> &'static str {
        match self {
            RealtimeArg::Off => "off",
            RealtimeArg::On => "on",
        }
    }
}

/// Tuning for the user-mode real-time file monitor (`--realtime on`).
#[derive(Debug, Clone, Default, clap::Args)]
struct RealtimeFlags {
    /// Extra directory to watch in real time (repeatable). Added to the default
    /// high-risk folders: every profile's Downloads, Desktop, Documents, Temp
    /// and Startup, plus the system temp and all-users Startup folders.
    #[arg(long = "realtime-watch")]
    watch: Vec<PathBuf>,
    /// Watch only the `--realtime-watch` directories, not the default folders.
    #[arg(long = "realtime-no-default-dirs")]
    no_default_dirs: bool,
    /// Detect and log only; never move a file into the vault.
    #[arg(long = "realtime-alert-only")]
    alert_only: bool,
    /// Do not scan files that already exist when the monitor starts.
    #[arg(long = "realtime-no-sweep")]
    no_sweep: bool,
    /// Do not feed file events to the RansomShield behaviour engine (the scanner still runs).
    #[arg(long = "realtime-no-ransomware")]
    no_ransomware: bool,
    /// Put decoy files in a "Litric Decoys" folder inside every watched Documents and Desktop
    /// folder. Any change to a decoy is a conclusive ransomware signal. Off by default because it
    /// creates files in the user's folders.
    #[arg(long = "realtime-decoys")]
    decoys: bool,
    /// Extra folder to fill with decoy files (repeatable). Must lie inside a watched directory.
    #[arg(long = "realtime-decoy-dir")]
    decoy_dirs: Vec<PathBuf>,
}

/// Upper bound on files the startup sweep will visit before it reports itself truncated.
const SWEEP_MAX_FILES: u64 = 500_000;

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
        /// User-mode real-time file monitor: scan files after they are written
        /// and move malicious ones into the encrypted vault. Off for a foreground
        /// `serve`; the `real-time protection` setting can also request it.
        #[arg(long, value_enum, default_value = "off")]
        realtime: RealtimeArg,
        #[command(flatten)]
        realtime_flags: RealtimeFlags,
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
        /// User-mode real-time file monitor. On by default in the installed
        /// service; it scans after the write and cannot block before execution.
        #[arg(long, value_enum, default_value = "on")]
        realtime: RealtimeArg,
        #[command(flatten)]
        realtime_flags: RealtimeFlags,
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
        /// Real-time file monitor the service starts with (`on` by default).
        #[arg(long, value_enum, default_value = "on")]
        realtime: RealtimeArg,
        #[command(flatten)]
        realtime_flags: RealtimeFlags,
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
            realtime,
            realtime_flags,
        }) => serve(
            &addr,
            &data_dir,
            &rules,
            db.as_deref(),
            token_file,
            print_token,
            process_gate,
            (realtime == RealtimeArg::On).then_some(realtime_flags),
        ),
        Some(Command::RunService {
            addr,
            data_dir,
            rules,
            db,
            process_gate,
            realtime,
            realtime_flags,
        }) => run_service(
            &addr,
            data_dir,
            rules,
            db,
            process_gate,
            (realtime == RealtimeArg::On).then_some(realtime_flags),
        ),
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
    realtime: Option<RealtimeFlags>,
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

    // The saved "real-time protection" setting can request the monitor even when the
    // command line did not.
    let realtime = realtime.or_else(|| state.realtime_requested.then(RealtimeFlags::default));
    if let Some(flags) = realtime {
        match start_realtime(&state, rules_dir, db_dir, data_dir, &flags) {
            Ok((monitor, bridge)) => {
                state.set_realtime(Arc::new(monitor));
                if let Some(bridge) = bridge {
                    state.set_ransomware(Arc::new(bridge));
                }
            }
            // Not fatal: scans and the API still work, and `/status` reports this error
            // instead of a protection that is not there.
            Err(e) => state.set_realtime_error(e.to_string()),
        }
    }

    let handle = server::serve(state.clone(), addr)?;
    let _ = print_token;
    Ok(Running {
        handle,
        token_path,
        state,
    })
}

/// Starts the user-mode real-time file monitor on its own pipeline (a second copy of the
/// same rules and threat database), sharing the service's encrypted quarantine vault.
fn start_realtime(
    state: &Arc<AppState>,
    rules_dir: &Path,
    db_dir: Option<&Path>,
    data_dir: &Path,
    flags: &RealtimeFlags,
) -> Result<
    (litric_monitor::Monitor, Option<litric_service::shield::ShieldBridge>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let engine = build_engine(rules_dir, db_dir)?;
    let pipeline = litric_pipeline::Pipeline::new(engine)
        .with_trust_provider(Box::new(litric_pipeline::WinTrustProvider));

    let mut dirs = if flags.no_default_dirs {
        Vec::new()
    } else {
        litric_monitor::default_watch_dirs()
    };
    for d in &flags.watch {
        if !dirs.contains(d) {
            dirs.push(d.clone());
        }
    }

    // The saved `alert_only` setting forbids automatic quarantine everywhere.
    let settings_alert_only = state
        .store
        .lock()
        .map(|s| s.settings.alert_only)
        .unwrap_or(false);

    let mut cfg = litric_monitor::MonitorConfig::new(dirs.clone());
    cfg.auto_quarantine = !(flags.alert_only || settings_alert_only);
    cfg.log_path = Some(data_dir.join("realtime-events.jsonl"));
    // The data directory holds the token, settings, history and vault key; none of it is a
    // scan target and every write there would otherwise be an event.
    cfg.exclude.push(data_dir.to_path_buf());
    cfg.throttle = Duration::from_millis(2);

    // The ransomware behaviour layer taps the same OS watcher, so both layers see the same events.
    let bridge = if flags.no_ransomware {
        None
    } else {
        Some(start_ransomware_bridge(state, &dirs, data_dir, flags)?)
    };
    if let Some(b) = &bridge {
        cfg.observer = Some(b.observer());
    }

    let monitor = match litric_monitor::Monitor::start(Arc::new(pipeline), state.vault.clone(), cfg) {
        Ok(m) => m,
        Err(e) => {
            if let Some(b) = &bridge {
                b.shutdown();
            }
            return Err(e.into());
        }
    };
    if !flags.no_sweep {
        monitor.start_sweep(SWEEP_MAX_FILES);
    }
    Ok((monitor, bridge))
}

/// Builds the RansomShield bridge: decoy folders (only when asked), the temp folders that are
/// ignored unless named explicitly, and the incident log.
fn start_ransomware_bridge(
    state: &Arc<AppState>,
    watched: &[PathBuf],
    data_dir: &Path,
    flags: &RealtimeFlags,
) -> Result<litric_service::shield::ShieldBridge, Box<dyn std::error::Error + Send + Sync>> {
    use litric_service::shield::{deploy_decoys, ShieldBridge, ShieldScope, DECOY_FOLDER};

    let mut decoy_dirs: Vec<PathBuf> = flags.decoy_dirs.clone();
    if flags.decoys {
        for d in watched {
            let name = d
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if name == "documents" || name == "desktop" {
                decoy_dirs.push(d.join(DECOY_FOLDER));
            }
        }
    }
    decoy_dirs.sort();
    decoy_dirs.dedup();

    // A decoy nobody watches protects nothing and must not look like it does.
    let mut problems = Vec::new();
    for d in &decoy_dirs {
        let n = litric_monitor::norm_path(&d.to_string_lossy(), cfg!(windows));
        let covered = watched
            .iter()
            .any(|w| litric_monitor::is_under(&n, &litric_monitor::norm_path(&w.to_string_lossy(), cfg!(windows))));
        if !covered {
            problems.push(format!("{}: not inside a watched directory, changes there would not be seen", d.display()));
        }
    }
    let (_decoys, created, mut errors) = deploy_decoys(&decoy_dirs);
    errors.append(&mut problems);

    // Build output, installers and caches write to temp folders constantly; they are not user
    // documents. They are ignored unless the operator named one with `--realtime-watch`.
    let mut skip: Vec<PathBuf> = vec![std::env::temp_dir()];
    for d in watched {
        let is_temp = d
            .file_name()
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case("temp"))
            .unwrap_or(false);
        if is_temp && !skip.contains(d) {
            skip.push(d.clone());
        }
    }

    let scope = ShieldScope {
        skip,
        explicit: flags.watch.clone(),
        decoy_dirs,
    };
    Ok(ShieldBridge::start(
        state.ranshield.clone(),
        scope,
        created,
        errors,
        Some(data_dir.join("ransomware-events.jsonl")),
    )?)
}

/// One line describing the monitor for the console / service log.
fn realtime_summary(state: &AppState) -> String {
    let ransomware = match state.ransomware() {
        Some(b) if b.is_running() => ", RansomShield feed ACTIVE (alert-only)",
        Some(_) => ", RansomShield feed STOPPED",
        None => ", RansomShield feed off",
    };
    match state.realtime() {
        Some(m) => format!(
            "ACTIVE, user mode (scans after write, cannot block before execution): {} \
             director(ies) watched, auto-quarantine {}{}",
            m.watched().len(),
            if m.status_json()["auto_quarantine"] == true {
                "on"
            } else {
                "off (alert only)"
            },
            ransomware
        ),
        None => match state.realtime_error() {
            Some(e) => format!("NOT ACTIVE: {e}"),
            None => "NOT ACTIVE (not requested; pass --realtime on)".to_string(),
        },
    }
}

fn serve(
    addr: &str,
    data_dir: &Path,
    rules_dir: &Path,
    db_dir: Option<&Path>,
    token_file: Option<PathBuf>,
    print_token: bool,
    gate: GateArg,
    realtime: Option<RealtimeFlags>,
) -> ExitCode {
    let running = match start(
        addr,
        data_dir,
        rules_dir,
        db_dir,
        token_file,
        print_token,
        gate.into(),
        realtime,
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
    println!("real-time   : {}", realtime_summary(&running.state));
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
            running.state.shutdown_realtime();
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
    realtime: Option<RealtimeFlags>,
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
        "Litric Defender service {} starting (data {}, rules {}, db {}, gate {}, realtime {})",
        litric_core::ENGINE_VERSION,
        data_dir.display(),
        rules.display(),
        db.as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "none".into()),
        GateMode::from(gate).as_str(),
        if realtime.is_some() { "on" } else { "off" }
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
                realtime.clone(),
            ) {
                Ok(running) => {
                    say(format!(
                        "listening on http://{} with {} rules",
                        running.handle.addr,
                        running.state.engine.rules().len()
                    ));
                    say(format!("real-time file monitor: {}", realtime_summary(&running.state)));
                    while !stop.wait_timeout(Duration::from_millis(500)) {}
                    running.state.shutdown_realtime();
                    if let Some(monitor) = running.state.realtime() {
                        let s = monitor.stats();
                        say(format!(
                            "real-time monitor stopped: scanned={} malicious={} quarantined={} \
                             quarantine_failed={} dropped_events={} sweep_visited={}",
                            s.scanned.load(std::sync::atomic::Ordering::Relaxed),
                            s.malicious.load(std::sync::atomic::Ordering::Relaxed),
                            s.quarantined.load(std::sync::atomic::Ordering::Relaxed),
                            s.quarantine_failed.load(std::sync::atomic::Ordering::Relaxed),
                            s.events_dropped.load(std::sync::atomic::Ordering::Relaxed),
                            s.sweep_visited.load(std::sync::atomic::Ordering::Relaxed)
                        ));
                    }
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
            realtime,
            realtime_flags,
        } => {
            let mut extra = format!(
                "--process-gate {} --realtime {}",
                process_gate.as_str(),
                realtime.as_str()
            );
            for dir in &realtime_flags.watch {
                let text = dir.display().to_string();
                if text.contains('"') {
                    eprintln!("litricd: --realtime-watch path may not contain a double quote: {text}");
                    return ExitCode::from(2);
                }
                // a trailing backslash would escape the closing quote on the command line
                extra.push_str(&format!(
                    " --realtime-watch \"{}\"",
                    text.trim_end_matches('\\')
                ));
            }
            if realtime_flags.no_default_dirs {
                extra.push_str(" --realtime-no-default-dirs");
            }
            if realtime_flags.alert_only {
                extra.push_str(" --realtime-alert-only");
            }
            if realtime_flags.no_sweep {
                extra.push_str(" --realtime-no-sweep");
            }
            if realtime_flags.no_ransomware {
                extra.push_str(" --realtime-no-ransomware");
            }
            if realtime_flags.decoys {
                extra.push_str(" --realtime-decoys");
            }
            for dir in &realtime_flags.decoy_dirs {
                let text = dir.display().to_string();
                if text.contains('"') {
                    eprintln!("litricd: --realtime-decoy-dir path may not contain a double quote: {text}");
                    return ExitCode::from(2);
                }
                extra.push_str(&format!(
                    " --realtime-decoy-dir \"{}\"",
                    text.trim_end_matches('\\')
                ));
            }
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

    fn realtime_of(args: &[&str]) -> (RealtimeArg, RealtimeFlags) {
        match Cli::parse_from(args).command {
            Some(Command::Serve {
                realtime,
                realtime_flags,
                ..
            })
            | Some(Command::RunService {
                realtime,
                realtime_flags,
                ..
            }) => (realtime, realtime_flags),
            _ => panic!("expected a serve or run-service command"),
        }
    }

    /// A foreground `serve` stays quiet unless the operator asks for the monitor.
    #[test]
    fn serve_defaults_to_realtime_off() {
        assert_eq!(realtime_of(&["litricd", "serve"]).0, RealtimeArg::Off);
    }

    /// The installed service is the product: the monitor is on unless switched off.
    #[test]
    fn run_service_defaults_to_realtime_on() {
        assert_eq!(realtime_of(&["litricd", "run-service"]).0, RealtimeArg::On);
        assert_eq!(
            realtime_of(&["litricd", "run-service", "--realtime", "off"]).0,
            RealtimeArg::Off
        );
    }

    #[test]
    fn realtime_flags_are_parsed_and_default_to_the_safe_behaviour() {
        let (arg, f) = realtime_of(&["litricd", "serve"]);
        assert_eq!(arg, RealtimeArg::Off);
        assert!(f.watch.is_empty() && !f.no_default_dirs && !f.alert_only && !f.no_sweep);

        let (arg, f) = realtime_of(&[
            "litricd",
            "serve",
            "--realtime",
            "on",
            "--realtime-watch",
            "C:\\a",
            "--realtime-watch",
            "D:\\b",
            "--realtime-no-default-dirs",
            "--realtime-alert-only",
            "--realtime-no-sweep",
        ]);
        assert_eq!(arg, RealtimeArg::On);
        assert_eq!(f.watch, vec![PathBuf::from("C:\\a"), PathBuf::from("D:\\b")]);
        assert!(f.no_default_dirs && f.alert_only && f.no_sweep);
    }

    /// Decoy files are created in the user's folders, so they are opt-in; the behaviour layer
    /// itself is on whenever the monitor is.
    #[test]
    fn ransomware_layer_is_on_with_the_monitor_but_decoys_are_opt_in() {
        let (_, f) = realtime_of(&["litricd", "run-service"]);
        assert!(!f.no_ransomware && !f.decoys && f.decoy_dirs.is_empty());
        let (_, f) = realtime_of(&[
            "litricd",
            "serve",
            "--realtime-no-ransomware",
            "--realtime-decoys",
            "--realtime-decoy-dir",
            "C:\\d1",
            "--realtime-decoy-dir",
            "C:\\d2",
        ]);
        assert!(f.no_ransomware && f.decoys);
        assert_eq!(f.decoy_dirs, vec![PathBuf::from("C:\\d1"), PathBuf::from("C:\\d2")]);
    }
}
