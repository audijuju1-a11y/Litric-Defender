//! End-to-end tests with REAL file-system notifications through
//! `ReadDirectoryChangesW` on Windows.
use litric_core::engine::{Engine, EngineConfig};
use litric_core::quarantine::QuarantineVault;
use litric_core::rules::{parse_rule_file, RuleSet};
use litric_core::threatdb::ThreatDb;
use litric_monitor::{Monitor, MonitorConfig};
use litric_pipeline::Pipeline;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn eicar() -> Vec<u8> {
    concat!("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EI", "CAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").as_bytes().to_vec()
}

struct Env {
    root: PathBuf,
    watch: PathBuf,
    vault_dir: PathBuf,
    key: PathBuf,
}

fn env(name: &str) -> Env {
    let root = std::env::temp_dir().join(format!("litric_mon_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let watch = root.join("watched");
    std::fs::create_dir_all(&watch).unwrap();
    Env { vault_dir: root.join("vault"), key: root.join("vault.key"), watch, root }
}

fn pipeline() -> Arc<Pipeline> {
    let mut rules = parse_rule_file(include_str!("../../../rules/core.lrs"), "core.lrs").unwrap();
    rules.extend(parse_rule_file(include_str!("../../../rules/extended.lrs"), "extended.lrs").unwrap());
    let engine = Engine::new(RuleSet::compile(rules).unwrap(), ThreatDb::empty(), EngineConfig::default());
    Arc::new(Pipeline::new(engine))
}

fn start(e: &Env, tweak: impl FnOnce(&mut MonitorConfig)) -> (Monitor, Arc<QuarantineVault>) {
    let vault = Arc::new(QuarantineVault::open(&e.vault_dir, &e.key).unwrap());
    let mut cfg = MonitorConfig::new(vec![e.watch.clone()]);
    cfg.debounce = Duration::from_millis(250);
    cfg.log_path = Some(e.root.join("events.jsonl"));
    tweak(&mut cfg);
    (Monitor::start(pipeline(), vault.clone(), cfg).unwrap(), vault)
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(15) {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for: {what}");
}

#[test]
fn a_dropped_test_malware_file_is_detected_quarantined_and_restorable() {
    let e = env("quarantine");
    let (m, vault) = start(&e, |_| {});
    let f = e.watch.join("invoice.com");
    std::fs::write(&f, eicar()).unwrap();
    wait_for("quarantine", || m.stats().quarantined.load(Relaxed) == 1);
    assert!(!f.exists(), "original must be removed after a verified vault write");
    let entries = vault.list();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].original_path, f.display().to_string());
    // reversible: restore returns the exact bytes
    let restored = vault.restore(&entries[0].id, Some(&e.root.join("restored.bin"))).unwrap();
    assert_eq!(std::fs::read(restored).unwrap(), eicar());
    let log = std::fs::read_to_string(e.root.join("events.jsonl")).unwrap();
    assert!(log.contains("\"event\":\"quarantined\""), "{log}");
    assert!(m.health().degraded.is_empty(), "{:?}", m.health());
    m.stop();
}

#[test]
fn a_benign_file_is_left_alone() {
    let e = env("benign");
    let (m, vault) = start(&e, |_| {});
    let f = e.watch.join("notes.txt");
    std::fs::write(&f, b"meeting notes: nothing to see").unwrap();
    wait_for("scan", || m.stats().scanned.load(Relaxed) >= 1);
    assert!(f.exists());
    assert_eq!(m.stats().quarantined.load(Relaxed), 0);
    assert!(vault.list().is_empty());
    m.stop();
}

#[test]
fn a_file_written_in_pieces_is_scanned_only_once_complete() {
    let e = env("slowwrite");
    let (m, vault) = start(&e, |c| c.debounce = Duration::from_millis(500));
    let f = e.watch.join("slow.com");
    let data = eicar();
    let (a, b) = data.split_at(data.len() / 2);
    {
        use std::io::Write;
        let mut h = std::fs::File::create(&f).unwrap();
        h.write_all(a).unwrap();
        h.flush().unwrap();
        std::thread::sleep(Duration::from_millis(200)); // shorter than the debounce window
        h.write_all(b).unwrap();
    }
    wait_for("quarantine of the completed file", || m.stats().quarantined.load(Relaxed) == 1);
    assert_eq!(vault.list().len(), 1);
    assert_eq!(m.stats().scanned.load(Relaxed), 1, "the half-written file must not have been scanned (and passed) first");
    m.stop();
}

#[test]
fn new_files_in_new_subdirectories_are_covered() {
    let e = env("subdir");
    let (m, _v) = start(&e, |_| {});
    let sub = e.watch.join("a").join("b");
    std::fs::create_dir_all(&sub).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    std::fs::write(sub.join("x.com"), eicar()).unwrap();
    wait_for("quarantine in a new subdirectory", || m.stats().quarantined.load(Relaxed) == 1);
    m.stop();
}

#[test]
fn the_vault_inside_the_watched_tree_is_never_scanned_so_there_is_no_loop() {
    let root = std::env::temp_dir().join(format!("litric_mon_selfwatch_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let e = Env { watch: root.clone(), vault_dir: root.join("vault"), key: root.join("vault.key"), root: root.clone() };
    let (m, vault) = start(&e, |_| {});
    std::fs::write(root.join("a.com"), eicar()).unwrap();
    wait_for("quarantine", || m.stats().quarantined.load(Relaxed) == 1);
    std::thread::sleep(Duration::from_secs(1)); // let any (wrong) re-scan of vault files happen
    assert_eq!(m.stats().quarantined.load(Relaxed), 1);
    assert_eq!(m.stats().malicious.load(Relaxed), 1, "vault/log writes must not be scanned");
    assert_eq!(vault.list().len(), 1);
    m.stop();
}

#[test]
fn oversized_files_are_skipped_loudly_not_called_clean() {
    let e = env("big");
    let (m, _v) = start(&e, |c| c.max_file_bytes = 1024);
    let f = e.watch.join("big.bin");
    std::fs::write(&f, vec![7u8; 4096]).unwrap();
    wait_for("skip", || m.stats().skipped_too_large.load(Relaxed) == 1);
    assert!(f.exists());
    let h = m.health();
    assert!(h.degraded.iter().any(|d| d.contains("NOT scanned")), "{h:?}");
    m.stop();
}

#[test]
fn auto_quarantine_can_be_switched_off_and_the_file_is_then_only_reported() {
    let e = env("noauto");
    let (m, vault) = start(&e, |c| c.auto_quarantine = false);
    let f = e.watch.join("x.com");
    std::fs::write(&f, eicar()).unwrap();
    wait_for("detection", || m.stats().malicious.load(Relaxed) == 1);
    std::thread::sleep(Duration::from_millis(300));
    assert!(f.exists(), "policy forbids moving the file");
    assert!(vault.list().is_empty());
    m.stop();
}

#[test]
fn queue_overflow_is_counted_and_reported_as_degraded_protection() {
    let e = env("overflow");
    let (m, _v) = start(&e, |c| {
        c.queue_cap = 2;
        c.throttle = Duration::from_millis(300); // slow worker so the queue backs up
        c.debounce = Duration::from_millis(50);
    });
    for i in 0..300 {
        std::fs::write(e.watch.join(format!("f{i}.txt")), format!("file {i}")).unwrap();
    }
    wait_for("overflow detected", || m.stats().events_dropped.load(Relaxed) > 0);
    let h = m.health();
    assert!(h.degraded.iter().any(|d| d.contains("dropped")), "{h:?}");
    m.stop();
}

#[test]
fn startup_refuses_missing_directories_and_empty_config() {
    let e = env("startup");
    let vault = Arc::new(QuarantineVault::open(&e.vault_dir, &e.key).unwrap());
    assert!(Monitor::start(pipeline(), vault.clone(), MonitorConfig::new(vec![])).is_err());
    assert!(Monitor::start(pipeline(), vault, MonitorConfig::new(vec![Path::new("/definitely/not/here").to_path_buf()])).is_err());
}

// ---- startup sweep, log rotation, shutdown, status (added with the service integration) ----

#[test]
fn the_startup_sweep_quarantines_malware_that_existed_before_the_monitor_started() {
    let e = env("sweep");
    let nested = e.watch.join("old").join("deeper");
    std::fs::create_dir_all(&nested).unwrap();
    let old = nested.join("dropper.com");
    std::fs::write(&old, eicar()).unwrap();
    std::fs::write(e.watch.join("readme.txt"), b"benign").unwrap();
    let (m, vault) = start(&e, |_| {});
    // no change event exists for a file that was already there
    std::thread::sleep(Duration::from_millis(600));
    assert!(old.exists(), "the event path alone must not see pre-existing files");
    m.start_sweep(10_000);
    m.start_sweep(10_000); // second call is a no-op
    wait_for("sweep to finish", || m.stats().sweep_finished.load(Relaxed));
    assert!(!old.exists(), "sweep must quarantine the pre-existing EICAR file");
    assert!(e.watch.join("readme.txt").exists(), "benign files are never touched");
    assert_eq!(vault.list().len(), 1);
    assert_eq!(m.stats().sweep_visited.load(Relaxed), 2);
    let status = m.status_json();
    assert_eq!(status["sweep"]["finished"], true);
    assert_eq!(status["stats"]["quarantined"], 1);
    assert!(m.health().degraded.is_empty(), "{:?}", m.health());
    m.stop();
}

#[test]
fn the_sweep_skips_the_vault_and_reports_a_file_limit_as_degraded_protection() {
    let root = std::env::temp_dir().join(format!("litric_mon_sweeplimit_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for i in 0..8 {
        std::fs::write(root.join(format!("f{i}.txt")), b"x").unwrap();
    }
    let e = Env { watch: root.clone(), vault_dir: root.join("vault"), key: root.join("vault.key"), root: root.clone() };
    let (m, vault) = start(&e, |_| {});
    // a malicious-looking file inside the vault directory must never be scanned
    std::fs::write(e.vault_dir.join("stray.com"), eicar()).unwrap();
    m.start_sweep(3);
    wait_for("sweep to finish", || m.stats().sweep_finished.load(Relaxed));
    assert_eq!(m.stats().malicious.load(Relaxed), 0, "vault contents are excluded");
    assert!(vault.list().is_empty());
    assert!(m.stats().sweep_truncated.load(Relaxed));
    let h = m.health();
    assert!(h.degraded.iter().any(|d| d.contains("file limit")), "{h:?}");
    m.stop();
}

#[test]
fn the_event_log_rotates_to_dot_1_and_keeps_recording() {
    let e = env("rotate");
    let log = e.root.join("events.jsonl");
    let (m, _v) = start(&e, |c| {
        c.log_max_bytes = 600;
        c.debounce = Duration::from_millis(100);
    });
    for i in 0..12 {
        std::fs::write(e.watch.join(format!("m{i}.com")), eicar()).unwrap();
        std::thread::sleep(Duration::from_millis(60));
    }
    wait_for("all quarantined", || m.stats().quarantined.load(Relaxed) == 12);
    let rotated = PathBuf::from(format!("{}.1", log.display()));
    assert!(rotated.exists(), "the log was never rotated");
    assert!(std::fs::metadata(&log).unwrap().len() < 600 + 700, "the active log must stay near its cap");
    assert!(!m.recent_events(5).is_empty());
    m.stop();
}

#[test]
fn shutdown_is_idempotent_and_reported_in_health() {
    let e = env("shutdown");
    let (m, _v) = start(&e, |_| {});
    assert!(m.health().running);
    m.shutdown();
    m.shutdown();
    let h = m.health();
    assert!(!h.running);
    assert!(h.degraded.iter().any(|d| d.contains("not running")), "{h:?}");
}

#[test]
fn default_watch_dirs_only_lists_directories_that_exist_and_has_no_duplicates() {
    let dirs = litric_monitor::default_watch_dirs();
    let mut seen = std::collections::HashSet::new();
    for d in &dirs {
        assert!(d.is_dir(), "{} does not exist", d.display());
        assert!(seen.insert(litric_monitor::norm_path(&d.to_string_lossy(), cfg!(windows))), "duplicate {}", d.display());
    }
    assert!(!dirs.is_empty(), "the temp directory is always a candidate");
}
