//! Reproducible pipeline benchmark on a SYNTHETIC corpus.
//! Not a detection-rate or false-positive measurement; it measures throughput only.
//! Run: cargo run --release -p litric-pipeline --example bench
use clamav_import::{import_dir, Options};
use litric_core::engine::{Engine, EngineConfig};
use litric_core::rules::{parse_rule_file, RuleSet};
use litric_core::threatdb::ThreatDb;
use litric_pipeline::Pipeline;
use peanalysis::builder::{pseudo_random, PeBuilder};
use scanner::{Limits, Scanner};
use sigdb::Database;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let mut all_rules = Vec::new();
    for f in ["core.lrs", "extended.lrs"] {
        let t = std::fs::read_to_string(format!("{}/../../rules/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        all_rules.extend(parse_rule_file(&t, f).unwrap());
    }
    println!("native rules loaded: {}", all_rules.len());
    let rs = RuleSet::compile(all_rules).unwrap();
    let engine = Engine::new(rs, ThreatDb::empty(), EngineConfig::default());

    // ClamAV-format fixture DB: N synthetic MD5 rules + a few NDB patterns
    let n_hash: usize = std::env::var("BENCH_HASHES").ok().and_then(|v| v.parse().ok()).unwrap_or(200_000);
    let dir = std::env::temp_dir().join(format!("litric_bench_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut hdb = String::with_capacity(n_hash * 50);
    let mut x: u64 = 0x1234_5678_9abc_def0;
    for i in 0..n_hash {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        let y = x.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        hdb.push_str(&format!("{:016x}{:016x}:{}:Synthetic.Hash.{}\n", x, y, 1000 + (i % 5000), i));
    }
    std::fs::write(dir.join("synthetic.hdb"), hdb).unwrap();
    let mut ndb = String::new();
    for i in 0..500u32 {
        ndb.push_str(&format!("Synthetic.Pat.{i}:0:*:{:08x}{:08x}{:08x}\n", 0xA5A5_0000u32 ^ i, 0x5A5A_1111u32 ^ (i * 7), 0xC3C3_2222u32 ^ (i * 13)));
    }
    std::fs::write(dir.join("synthetic.ndb"), ndb).unwrap();
    let t = Instant::now();
    let o = import_dir(&dir, &Options { serial: 1, created: 1, source_note: "synthetic benchmark fixture".into() }).unwrap();
    let import_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let db = Database::parse(&o.db).unwrap();
    let load_s = t.elapsed().as_secs_f64();
    let mode = std::env::var("BENCH_MODE").unwrap_or_else(|_| "both".into());
    let p = match mode.as_str() {
        "native" => Pipeline::new(engine),
        "clam" => Pipeline::new(Engine::new(RuleSet::empty(), ThreatDb::empty(), EngineConfig::default())).with_signature_scanner(Scanner::new(Arc::new(db), Limits::default())),
        _ => Pipeline::new(engine).with_signature_scanner(Scanner::new(Arc::new(db), Limits::default())),
    };
    println!("mode: {mode}");
    if std::env::var("BENCH_CLASSES").is_ok() {
        let mut cls: std::collections::BTreeMap<&str, (f64, usize, usize)> = Default::default();
        let mut mk: Vec<(String, Vec<u8>)> = Vec::new();
        for i in 0..40 { mk.push((format!("d{i}.txt"), format!("benign document {i}. ").repeat(50 + i * 7).into_bytes())); }
        for i in 0..40 { mk.push((format!("b{i}.bin"), pseudo_random(4096 + i * 1500, i as u64 + 1))); }
        for i in 0..40 { let mut b = PeBuilder::benign(i % 2 == 0); b.sections[0].data = pseudo_random(0x600 + (i % 7) * 0x400, 1000 + i as u64); mk.push((format!("a{i}.exe"), b.build())); }
        for (n, d) in &mk {
            let key = if n.ends_with(".txt") { "txt" } else if n.ends_with(".bin") { "random-bin" } else { "pe" };
            let t = Instant::now();
            let _ = p.scan_bytes(n, d);
            let e = cls.entry(key).or_default();
            e.0 += t.elapsed().as_secs_f64(); e.1 += d.len(); e.2 += 1;
        }
        for (k, (t, b, n)) in cls { println!("class {k}: {n} files, {:.2} MiB, {:.3}s => {:.1} MiB/s", b as f64 / 1048576.0, t, b as f64 / 1048576.0 / t); }
    }

    // deterministic corpus: text, pseudo-random (high entropy), benign PEs
    let mut corpus: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..300 {
        corpus.push((format!("doc{i}.txt"), format!("benign document {i}. ").repeat(50 + i * 7).into_bytes()));
    }
    for i in 0..200 {
        corpus.push((format!("blob{i}.bin"), pseudo_random(4096 + i * 1500, i as u64 + 1)));
    }
    for i in 0..100 {
        let mut b = PeBuilder::benign(i % 2 == 0);
        b.sections[0].data = pseudo_random(0x600 + (i % 7) * 0x400, 1000 + i as u64);
        corpus.push((format!("app{i}.exe"), b.build()));
    }
    let total_bytes: usize = corpus.iter().map(|c| c.1.len()).sum();
    // warm-up pass, then 5 timed passes
    for (n, d) in &corpus { let _ = p.scan_bytes(n, d); }
    let mut times = Vec::new();
    let mut flagged = 0usize;
    for _ in 0..5 {
        flagged = 0;
        let t = Instant::now();
        for (n, d) in &corpus {
            let r = p.scan_bytes(n, d);
            if r.verdict >= litric_core::engine::Verdict::Suspicious { flagged += 1; }
        }
        times.push(t.elapsed().as_secs_f64());
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = times[times.len() / 2];
    println!("BENCH (synthetic corpus; throughput only; build={})", if cfg!(debug_assertions) { "DEBUG" } else { "release" });
    println!("hash rules: {n_hash}, ndb rules: 500, import: {import_s:.2}s, db parse: {load_s:.2}s");
    println!("corpus: {} files, {:.1} MiB", corpus.len(), total_bytes as f64 / 1048576.0);
    println!("median pass: {med:.3}s  ({:.0} files/s, {:.1} MiB/s)   min {:.3}s  max {:.3}s", corpus.len() as f64 / med, total_bytes as f64 / 1048576.0 / med, times[0], times[4]);
    {
        let mut by: std::collections::BTreeMap<String, usize> = Default::default();
        for (n, d) in &corpus {
            let r = p.scan_bytes(n, d);
            if r.verdict >= litric_core::engine::Verdict::Suspicious {
                for s in &r.native.signals { *by.entry(s.id.to_string()).or_default() += 1; }
            }
        }
        println!("signals among flagged files: {by:?}");
    }
    println!("synthetic files flagged suspicious+: {flagged} of {} (synthetic benign corpus; NOT a false-positive rate)", corpus.len());
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for l in s.lines() { if l.starts_with("VmHWM") { println!("peak RSS: {}", l.trim()); } }
    }
}
