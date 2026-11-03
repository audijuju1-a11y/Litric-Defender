//! `litric-agent` — read-only SafeOS host fact collector for Windows.
//!
//! Usage:
//!   litric-agent                          # collect and POST to litricd
//!   litric-agent --print                  # collect and print facts JSON only
//!   litric-agent --dry-run                # show the collector script, run nothing
//!   litric-agent --fixture facts.json     # offline/test path, no PowerShell
//!
//! The agent never changes host configuration. If it cannot read something, that
//! capability is reported unavailable.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use litric_agent::{
    collect, facts_from_json_text, facts_json, submit, summary, COLLECT_SCRIPT,
};

#[derive(Parser)]
#[command(
    name = "litric-agent",
    version,
    about = "Litric SafeOS platform agent: read-only Windows host facts for litricd",
    long_about = "Collects host facts (edition, build, virtualization, Hyper-V/Sandbox features, \
                  RAM, free disk, WinNAT) and reports them to the local litricd on 127.0.0.1. \
                  Read-only: it never enables features, creates networks or changes services."
)]
struct Cli {
    /// Read facts from a JSON file instead of probing (offline testing).
    #[arg(long, value_name = "PATH")]
    fixture: Option<PathBuf>,
    /// Print facts JSON and exit without contacting the daemon.
    #[arg(long)]
    print: bool,
    /// Print what would be executed and exit; runs nothing.
    #[arg(long)]
    dry_run: bool,
    /// Daemon address.
    #[arg(long, value_name = "HOST:PORT", default_value = "127.0.0.1:8787")]
    addr: String,
    /// Daemon token file (default ./litric-data/api.token or LITRIC_TOKEN_FILE).
    #[arg(long, value_name = "PATH")]
    token_file: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.dry_run {
        println!("collector: powershell.exe -NoProfile -NonInteractive -Command <script>");
        println!("daemon   : POST http://{}/api/v1/safeos/host-facts", cli.addr);
        println!("mutation : none (read-only queries only)");
        println!("\n--- collector script ---\n{}", COLLECT_SCRIPT.trim());
        return ExitCode::SUCCESS;
    }

    let facts = match &cli.fixture {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => match facts_from_json_text(&text) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: {}: {e}", path.display());
                    return ExitCode::from(2);
                }
            },
            Err(e) => {
                eprintln!("error: cannot read {}: {e}", path.display());
                return ExitCode::from(2);
            }
        },
        None => match collect() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("error: {e}");
                eprintln!("hint: on Windows run without --fixture; on other systems use --fixture");
                return ExitCode::from(2);
            }
        },
    };

    if cli.print {
        println!("{}", serde_json::to_string_pretty(&facts_json(&facts)).unwrap());
        return ExitCode::SUCCESS;
    }

    let token_path = cli
        .token_file
        .clone()
        .or_else(|| std::env::var_os("LITRIC_TOKEN_FILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("litric-data/api.token"));
    let token = match std::fs::read_to_string(&token_path) {
        Ok(t) => t.trim().to_string(),
        Err(e) => {
            eprintln!("error: cannot read the API token at {}: {e}", token_path.display());
            eprintln!("hint: start litricd (it writes api.token) or pass --token-file");
            return ExitCode::from(2);
        }
    };

    match submit(&cli.addr, &token, &facts) {
        Ok((200, body)) => {
            print!("{}", summary(&facts));
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            println!(
                "reported to litricd: host_facts_known={} state={}",
                v["host_facts_known"], v["state"]
            );
            ExitCode::SUCCESS
        }
        Ok((401, _)) => {
            eprintln!("error: the daemon at {} rejected the API token", cli.addr);
            eprintln!("hint: check {} or run `litricd token`", token_path.display());
            ExitCode::from(2)
        }
        Ok((code, body)) => {
            eprintln!("error: daemon rejected the report (HTTP {code}): {body}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("hint: start litricd, or use --print to inspect facts offline");
            ExitCode::from(2)
        }
    }
}
