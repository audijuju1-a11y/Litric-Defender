//! litric-rtp: console runner for the real-time file monitor.
//!
//! This is a console program, not a Windows Service. Running it at boot as a service is not
//! implemented. See the crate docs for what this layer does and does not protect against.
use litric_core::engine::{Engine, EngineConfig};
use litric_core::quarantine::QuarantineVault;
use litric_core::rules::{parse_rule_file, RuleSet};
use litric_core::threatdb::ThreatDb;
use litric_monitor::{Monitor, MonitorConfig};
use litric_pipeline::Pipeline;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn usage() -> ! {
    eprintln!("usage: litric-rtp --watch DIR [--watch DIR..] --vault DIR --key FILE --rules DIR [--log FILE] [--max-mb N] [--no-quarantine]\n       [--sigdb-store DIR --trusted-keys FILE]   (verified imported/native signature database)");
    std::process::exit(2);
}

fn main() {
    let mut watch = Vec::new();
    let (mut vault, mut key, mut rules, mut log, mut store, mut keys) = (None, None, None, None, None, None);
    let mut max_mb = 256u64;
    let mut auto_q = true;
    let mut a = std::env::args().skip(1);
    while let Some(arg) = a.next() {
        let mut val = || a.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--watch" => watch.push(PathBuf::from(val())),
            "--vault" => vault = Some(PathBuf::from(val())),
            "--key" => key = Some(PathBuf::from(val())),
            "--rules" => rules = Some(PathBuf::from(val())),
            "--log" => log = Some(PathBuf::from(val())),
            "--sigdb-store" => store = Some(PathBuf::from(val())),
            "--trusted-keys" => keys = Some(PathBuf::from(val())),
            "--max-mb" => max_mb = val().parse().unwrap_or_else(|_| usage()),
            "--no-quarantine" => auto_q = false,
            _ => usage(),
        }
    }
    let (Some(vault), Some(key), Some(rules)) = (vault, key, rules) else { usage() };
    if watch.is_empty() {
        usage();
    }

    // rules: every .lrs file; a file that fails to parse stops startup (never silently dropped)
    let mut all = Vec::new();
    let mut files: Vec<_> = std::fs::read_dir(&rules).unwrap_or_else(|e| fail(&format!("cannot read rules dir: {e}"))).flatten().map(|e| e.path()).filter(|p| p.extension().map_or(false, |x| x == "lrs")).collect();
    files.sort();
    for f in &files {
        let t = std::fs::read_to_string(f).unwrap_or_else(|e| fail(&format!("{}: {e}", f.display())));
        match parse_rule_file(&t, &f.display().to_string()) {
            Ok(mut r) => all.append(&mut r),
            Err(e) => fail(&format!("{}: {e}", f.display())),
        }
    }
    if all.is_empty() {
        fail("no rules loaded: refusing to start with nothing to detect with");
    }
    let n_rules = all.len();
    let rs = RuleSet::compile(all).unwrap_or_else(|e| fail(&format!("rule compile: {e}")));
    let engine = Engine::new(rs, ThreatDb::empty(), EngineConfig::default());
    let mut pipeline = Pipeline::new(engine);

    if let (Some(store), Some(keyfile)) = (store, keys) {
        let mut tk = sigdb::TrustedKeys::new();
        for line in std::fs::read_to_string(&keyfile).unwrap_or_else(|e| fail(&format!("trusted keys: {e}"))).lines() {
            let l = line.trim();
            if !l.is_empty() && !l.starts_with('#') {
                tk.add_hex(l).unwrap_or_else(|e| fail(&format!("trusted key: {e:?}")));
            }
        }
        let st = sigdb::Store::open(&store).unwrap_or_else(|e| fail(&format!("sigdb store: {e}")));
        match st.load_active(&tk) {
            Ok(Some(db)) => {
                eprintln!("signature database loaded and verified ({} rules)", db.rule_count());
                pipeline = pipeline.with_signature_scanner(scanner::Scanner::new(Arc::new(db), scanner::Limits::default()));
            }
            Ok(None) => eprintln!("WARNING: signature store is empty; running with native rules only"),
            Err(e) => fail(&format!("signature database failed verification: {e:?}")),
        }
    }
    pipeline = pipeline.with_trust_provider(Box::new(litric_pipeline::WinTrustProvider));

    let v = QuarantineVault::open(&vault, &key).unwrap_or_else(|e| fail(&format!("quarantine vault: {e}")));
    let mut cfg = MonitorConfig::new(watch);
    cfg.log_path = log;
    cfg.max_file_bytes = max_mb << 20;
    cfg.auto_quarantine = auto_q;
    let m = Monitor::start(Arc::new(pipeline), Arc::new(v), cfg).unwrap_or_else(|e| fail(&e.to_string()));
    eprintln!("litric-rtp: watching with {n_rules} native rules (post-write scanning; NOT pre-execution blocking)");

    let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s2 = stopping.clone();
    ctrlc::set_handler(move || s2.store(true, std::sync::atomic::Ordering::Relaxed)).ok();
    let mut last_report = String::new();
    while !stopping.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(2));
        let h = m.health();
        let line = format!("{:?}", h.degraded);
        if !h.degraded.is_empty() && line != last_report {
            eprintln!("PROTECTION DEGRADED: {line}");
            last_report = line;
        }
        if !h.running {
            eprintln!("monitor stopped unexpectedly");
            std::process::exit(1);
        }
    }
    m.stop();
}

fn fail(msg: &str) -> ! {
    eprintln!("litric-rtp: {msg}");
    std::process::exit(1)
}
