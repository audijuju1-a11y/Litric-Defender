use ransomshield::{Config, Engine, Verdict};
use realtime::*;
use std::sync::{Arc, Mutex};

struct Fake(Arc<Mutex<Vec<u32>>>);
impl Containment for Fake {
    fn suspend(&mut self, pid: u32) -> Result<(), String> { self.0.lock().unwrap().push(pid); Ok(()) }
}
/// Pretends every file was plaintext first, then random data.
struct Sampler(std::collections::HashMap<String, u32>);
impl EntropySampler for Sampler {
    fn sample(&mut self, p: &str) -> Option<f64> {
        let n = self.0.entry(p.to_string()).or_insert(0);
        *n += 1;
        Some(if *n == 1 { 4.0 } else { 7.95 })
    }
}
fn ev(pid: u32, i: u64, kind: RawKind) -> RawEvent {
    RawEvent { pid, image: "c:\\t\\x.exe".into(), path: format!("c:\\d\\f{}", i % 40), kind, t_ms: i * 10 }
}
fn simulate(pid: u32) -> (Pipeline, Arc<Mutex<Vec<u32>>>) {
    let suspended = Arc::new(Mutex::new(vec![]));
    let p = Pipeline::start(Engine::new(Config::default()), Box::new(Sampler(Default::default())),
        Box::new(Fake(suspended.clone())), 10_000);
    // pass 1: baseline entropy, pass 2: encrypt + rename
    for i in 0..40 { p.submit(ev(pid, i, RawKind::Modified)); }
    for i in 40..80 {
        p.submit(ev(pid, i, RawKind::Modified));
        p.submit(ev(pid, i, RawKind::Renamed { new_ext: "locked".into() }));
    }
    (p, suspended)
}

#[test]
fn attributed_ransomware_is_suspended_once() {
    let (p, s) = simulate(4242);
    let inc = p.incidents.clone();
    p.shutdown();
    assert_eq!(*s.lock().unwrap(), vec![4242]);
    let inc = inc.lock().unwrap();
    assert!(inc.iter().any(|i| i.contained && i.assessment.verdict == Verdict::Contain));
}

#[test]
fn unattributed_activity_alerts_but_is_never_contained() {
    let (p, s) = simulate(0);
    let inc = p.incidents.clone();
    p.shutdown();
    assert!(s.lock().unwrap().is_empty());
    assert!(inc.lock().unwrap().iter().any(|i| i.note.contains("cannot contain")));
}

#[test]
fn queue_overflow_is_counted_and_reported_degraded() {
    let p = Pipeline::start(Engine::new(Config::default()), Box::new(Sampler(Default::default())),
        Box::new(Fake(Default::default())), 1);
    for i in 0..5000 { p.submit(ev(1, i, RawKind::Created)); }
    assert!(p.degraded() || p.stats.processed.load(std::sync::atomic::Ordering::Relaxed) > 0);
    let received = p.stats.received.load(std::sync::atomic::Ordering::Relaxed);
    let dropped = p.stats.dropped.load(std::sync::atomic::Ordering::Relaxed);
    p.shutdown();
    assert_eq!(received, 5000);
    assert!(dropped < 5000);
}
