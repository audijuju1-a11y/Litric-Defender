//! Synthetic scale measurement (NOT real ClamAV data).
//! usage: scale <rules>   -> prints load time, RSS, lookup rate
use sigdb::*;
use std::time::Instant;

fn rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status").ok().and_then(|t| {
        t.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<f64>().ok())
    }).unwrap_or(0.0) / 1024.0
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let mut text = String::with_capacity(n * 110);
    text.push_str(&format!("LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count {n}\n"));
    let mut sample = vec![];
    for i in 0..n {
        let (a, b) = (rnd(), rnd());
        let h = format!("{a:016x}{b:016x}");
        if i % (n / 1000).max(1) == 0 { sample.push((h.clone(), (i % 100_000) as u32)); }
        text.push_str(&format!("HX clam.h.{i} Win.Trojan.Family{} high 90 md5 {h} {}\n", rnd() % 5000, i % 100_000));
    }
    text.push_str("END\n");
    let bytes = text.into_bytes();
    let text_mb = bytes.len() as f64 / 1048576.0;
    drop(rnd);
    let before = rss_mb();
    let t = Instant::now();
    let db = Database::parse(&bytes).expect("parse");
    let load = t.elapsed();
    drop(bytes);
    let after = rss_mb();
    // lookups: all sampled hits + misses
    let t = Instant::now();
    let (mut hits, mut total) = (0usize, 0usize);
    for _ in 0..1000 {
        for (h, size) in &sample {
            total += 1;
            if db.lookup_file(Algo::Md5, &hex_decode(h).unwrap(), *size as u64).is_some() { hits += 1; }
            total += 1;
            if db.lookup_file(Algo::Md5, &hex_decode(h).unwrap(), *size as u64 + 1).is_some() { hits += 1; }
        }
    }
    let look = t.elapsed();
    println!("rules={n} text={text_mb:.0} MiB parse={:.2}s  RSS before_parse={before:.0} MiB after(text freed)={after:.0} MiB  => RSS/rules = {:.0} bytes/rule (includes ~2 MiB process baseline; peak during parse NOT measured)", load.as_secs_f64(), after * 1048576.0 / n as f64);
    println!("lookups={total} hits={hits} time={:.2}s ({:.0}/s, includes hex decode)", look.as_secs_f64(), total as f64 / look.as_secs_f64());
}
