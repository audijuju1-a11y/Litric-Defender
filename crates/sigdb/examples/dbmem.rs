//! usage: dbmem <db file>  -> RSS growth caused by holding the parsed database (text freed)
use sigdb::Database;
fn rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status").ok().and_then(|t| t.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<f64>().ok())).unwrap_or(0.0) / 1024.0
}
fn main() {
    let path = std::env::args().nth(1).expect("db path");
    let base = rss_mb();
    let bytes = std::fs::read(&path).unwrap();
    let t = std::time::Instant::now();
    let db = Database::parse(&bytes).unwrap();
    let el = t.elapsed();
    drop(bytes);
    let after = rss_mb();
    println!("rules={} ndb={} parse={:.2}s RSS baseline={base:.0} MiB after={after:.0} MiB => ~{:.0} bytes/rule", db.rule_count(), db.ndb.len(), el.as_secs_f64(), (after - base) * 1048576.0 / db.rule_count() as f64);
}
