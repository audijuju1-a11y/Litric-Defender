//! Times individual analysis stages on a synthetic buffer. Dev tool.
use litric_core::format::detect;
use litric_core::heuristics::{self, AnalysisInput};
use litric_core::rules::RuleSet;
use std::time::Instant;
fn rnd(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 }).collect()
}
fn t<R>(label: &str, reps: u32, mut f: impl FnMut() -> R) {
    let s = Instant::now();
    for _ in 0..reps { std::hint::black_box(f()); }
    println!("{label:<28} {:>9.3} ms/iter", s.elapsed().as_secs_f64() * 1000.0 / reps as f64);
}
fn main() {
    let data = rnd(300_000, 7);
    println!("buffer: {} bytes (random)", data.len());
    t("sha256", 20, || litric_core::hash::sha256_bytes(&data));
    t("format::detect", 20, || detect(&data));
    let fmt = detect(&data);
    t("heuristics::analyze (all)", 5, || heuristics::analyze(&AnalysisInput { data: &data, format: fmt, ext: "bin", file_name: "x.bin", pe: None, path: None }));
    let eng = litric_core::engine::Engine::new(RuleSet::empty(), litric_core::threatdb::ThreatDb::empty(), litric_core::engine::EngineConfig::default());
    t("Engine::analyze_bytes (full)", 5, || eng.analyze_bytes("x.bin", &data));
    let txt = "benign document text. ".repeat(14000).into_bytes();
    t("Engine::analyze_bytes (text)", 5, || eng.analyze_bytes("x.txt", &txt));
    let core = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules/core.lrs")).unwrap();
    let crs = RuleSet::compile(litric_core::rules::parse_rule_file(&core, "core.lrs").unwrap()).unwrap();
    t("RuleSet(core.lrs).scan rnd", 5, || crs.scan(&data, None, "bin", "bin"));
    t("RuleSet(core.lrs).scan txt", 5, || crs.scan(&txt, None, "txt", "txt"));
    let eng2 = litric_core::engine::Engine::new(crs, litric_core::threatdb::ThreatDb::empty(), litric_core::engine::EngineConfig::default());
    t("Engine+core rules (random)", 5, || eng2.analyze_bytes("x.bin", &data));
    let rs = RuleSet::empty();
    t("RuleSet(empty).scan", 5, || rs.scan(&data, None, "bin", "bin"));
}
