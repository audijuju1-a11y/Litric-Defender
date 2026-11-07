//! litric-scan
//!   litric-scan --pubkey <hex> (--store <dir> | --db <file> --sig <file>)
//!               [--quarantine <dir> [--move]] [--max-pattern-mb N] <path>...
//! Exit codes: 0 complete, no detections | 1 detections | 2 incomplete scan
//!             3 no usable / empty signature database (nothing can be claimed)
//!             4 heuristically suspicious files (no known-malware match)
use scanner::*;
use sigdb::{Database, Store, TrustedKeys};
use std::path::PathBuf;
use std::sync::{atomic::AtomicBool, Arc};

fn main() {
    let mut a = std::env::args().skip(1);
    let (mut pubkey, mut store, mut dbf, mut sigf, mut qdir) = (None, None, None, None, None);
    let (mut mv, mut paths) = (false, vec![]);
    let mut limits = Limits::default();
    while let Some(x) = a.next() {
        match x.as_str() {
            "--pubkey" => pubkey = a.next(),
            "--store" => store = a.next(),
            "--db" => dbf = a.next(),
            "--sig" => sigf = a.next(),
            "--quarantine" => qdir = a.next(),
            "--move" => mv = true,
            "--max-pattern-mb" => limits.max_pattern_scan_bytes = a.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(32) << 20,
            _ => paths.push(PathBuf::from(x)),
        }
    }
    if paths.is_empty() {
        eprintln!("usage: litric-scan --pubkey HEX (--store DIR | --db F --sig F) [--quarantine DIR [--move]] PATH...");
        std::process::exit(2);
    }
    let loaded: Result<Database, String> = (|| {
        let mut keys = TrustedKeys::new();
        keys.add_hex(pubkey.as_deref().ok_or("--pubkey required")?).map_err(|e| e.to_string())?;
        if let Some(dir) = &store {
            Store::open(dir).and_then(|_| Ok(())).map_err(|e| e.to_string())?;
            Store::open(dir).unwrap().load_active(&keys).map_err(|e| e.to_string())?.ok_or_else(|| "no database installed".to_string())
        } else {
            let path = std::path::PathBuf::from(dbf.as_deref().ok_or("--store or --db required")?);
            let sig = std::fs::read_to_string(sigf.as_deref().ok_or("--sig required")?).map_err(|e| e.to_string())?;
            sigdb::load_file(&path, &sig, &keys).map_err(|e| e.to_string())
        }
    })();
    let (scanner, db_ok) = match loaded {
        Ok(db) => {
            let ok = db.rule_count() > 0;
            (Scanner::new(Arc::new(db), limits), ok)
        }
        Err(e) => {
            eprintln!("DATABASE PROBLEM: {e}");
            (Scanner::without_database(limits, &e), false)
        }
    };
    let cancel = AtomicBool::new(false);
    let mut total = Report::default();
    let mut all: Vec<FileResult> = vec![];
    for p in &paths {
        let r = scanner.scan_path(p, &cancel, &mut |_| {});
        total.files_seen += r.files_seen;
        total.no_threat_found += r.no_threat_found;
        total.allowlisted += r.allowlisted;
        total.detected += r.detected;
        total.suspicious += r.suspicious;
        total.weak_anomalies += r.weak_anomalies;
        total.unscannable += r.unscannable;
        total.skipped += r.skipped;
        total.errors += r.errors;
        total.bytes += r.bytes;
        total.warnings = r.warnings.clone();
        total.db_rules = r.db_rules;
        total.db_sources = r.db_sources.clone();
        all.extend(r.results);
    }
    let q = qdir.map(|d| quarantine::Quarantine::open(d).expect("cannot open quarantine"));
    for fr in &all {
        match &fr.outcome {
            scanner::Outcome::Detected(ds) => {
                let top = ds.iter().max_by_key(|d| (d.severity, d.confidence)).unwrap();
                println!("DETECTED {}: {} (rule {}, {:?}, confidence {}%)", fr.path.display(), top.family, top.rule_id, top.severity, top.confidence);
                if let Some(q) = &q {
                    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
                    let info = quarantine::Info { family: top.family.clone(), rule_id: top.rule_id.clone(), severity: format!("{:?}", top.severity) };
                    let mode = if mv { quarantine::Mode::MoveAfterVerify } else { quarantine::Mode::CopyOnly };
                    match q.add(&fr.path, &info, mode, t) {
                        Ok(id) => println!("  quarantined as {id} ({mode:?})"),
                        Err(e) => println!("  quarantine FAILED: {e}"),
                    }
                }
            }
            scanner::Outcome::Suspicious(risk) => {
                println!("SUSPICIOUS {}: heuristic score {} ({:?}); not a confirmed detection", fr.path.display(), risk.score, risk.level);
                for r in &risk.reasons {
                    println!("  +{} [{:?}] {}", r.weight, r.category, r.text);
                }
            }
            scanner::Outcome::Unscannable(m) => println!("UNSCANNABLE {}: {m}", fr.path.display()),
            scanner::Outcome::Skipped(m) => println!("SKIPPED {}: {m}", fr.path.display()),
            scanner::Outcome::Error(m) => println!("ERROR {}: {m}", fr.path.display()),
            _ => {}
        }
    }
    for src in &total.db_sources {
        println!("database source: {src}");
    }
    for w in &total.warnings {
        println!("WARNING: {w}");
    }
    println!(
        "files {} | no threat found {} | allowlisted {} | detected {} | suspicious {} | weak anomalies {} | unscannable {} | skipped {} | errors {} | rules loaded {}",
        total.files_seen, total.no_threat_found, total.allowlisted, total.detected, total.suspicious, total.weak_anomalies, total.unscannable, total.skipped, total.errors, total.db_rules
    );
    println!("(\"no threat found\" means no loaded rule matched; it is not a guarantee of safety)");
    let incomplete = total.unscannable + total.skipped + total.errors > 0;
    std::process::exit(if total.detected > 0 { 1 } else if total.suspicious > 0 { 4 } else if !db_ok { 3 } else if incomplete { 2 } else { 0 });
}
