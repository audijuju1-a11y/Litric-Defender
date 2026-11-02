//! `litricd` — the Litric Defender background service backend.
//!
//! Runs a loopback HTTP/JSON API over the detection engine. Designed to be the
//! single source of truth for the Windows UI: no UI process scans files itself.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use litric_core::engine::{Engine, EngineConfig};
use litric_core::quarantine::QuarantineVault;
use litric_core::rules::{parse_rule_file, RuleSet, Rule};
use litric_core::threatdb::ThreatDb;
use litric_service::{load_or_create_token, server, AppState};

#[derive(Parser)]
#[command(
    name = "litricd",
    version = litric_core::ENGINE_VERSION,
    about = "Litric Defender background service (local API backend)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
    },
    /// Print (creating if needed) the API token.
    Token {
        #[arg(long, default_value = "./litric-data/api.token")]
        token_file: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            addr,
            data_dir,
            rules,
            db,
            token_file,
            print_token,
        } => serve(&addr, &data_dir, &rules, db.as_deref(), token_file, print_token),
        Command::Token { token_file } => match load_or_create_token(&token_file) {
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
    }
}

fn serve(
    addr: &str,
    data_dir: &Path,
    rules_dir: &Path,
    db_dir: Option<&Path>,
    token_file: Option<PathBuf>,
    print_token: bool,
) -> ExitCode {
    let token_path = token_file.unwrap_or_else(|| data_dir.join("api.token"));
    let token = match load_or_create_token(&token_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("litricd: cannot load API token: {e}");
            return ExitCode::from(2);
        }
    };

    let engine = match build_engine(rules_dir, db_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("litricd: cannot initialise engine: {e}");
            return ExitCode::from(2);
        }
    };

    let vault = match QuarantineVault::open(
        &data_dir.join("quarantine"),
        &data_dir.join("vault.key"),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("litricd: cannot open quarantine vault: {e}");
            return ExitCode::from(2);
        }
    };

    let state = match AppState::new(engine, vault, data_dir, token.clone()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("litricd: cannot initialise state: {e}");
            return ExitCode::from(2);
        }
    };

    let handle = match server::serve(state.clone(), addr) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("litricd: cannot start API server: {e}");
            return ExitCode::from(2);
        }
    };

    println!("Litric Defender service {}", litric_core::ENGINE_VERSION);
    println!("listening   : http://{}", handle.addr);
    println!("data dir    : {}", data_dir.display());
    println!("token file  : {}", token_path.display());
    println!(
        "rules       : {} loaded",
        state.engine.rules().len()
    );
    println!(
        "threat db   : v{} ({:?})",
        state.engine.db().version(),
        state.engine.db().trust
    );
    println!("real-time   : NOT ACTIVE (no kernel sensor in this build)");
    println!("press Ctrl+C to stop");
    if print_token {
        println!("bearer token: {token}");
    }

    // The listener thread owns the accept loop; park this thread until the
    // process is interrupted.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
        if !handle.is_running() {
            return ExitCode::from(1);
        }
    }
}

fn build_engine(
    rules_dir: &Path,
    db_dir: Option<&Path>,
) -> Result<Engine, Box<dyn std::error::Error>> {
    let db = match db_dir {
        Some(dir) => ThreatDb::open_dir(dir, &[], true, litric_core::ENGINE_VERSION)?,
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
