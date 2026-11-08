//! Connects the real-time file monitor to the RansomShield behavioural engine and the HoneyVault.
//!
//! The monitor owns the one OS file watcher. This bridge taps it ([`litric_monitor::Observer`]) and
//! turns every raw change into a RansomShield [`FsEvent`], so the file scanner (signatures, rules,
//! quarantine) and the ransomware behaviour engine run side by side on the same events and report
//! through the same service.
//!
//! # What this is, stated plainly
//!
//! * **No process attribution.** A file-change notification does not say which process made the
//!   change. Every event is therefore attributed to pid `0`, a single bucket for "unknown actor",
//!   and the bridge can raise an alert but can never suspend or kill anything. The response is
//!   alert-only until a process-aware source (ETW or a minifilter) exists.
//! * **Tumbling window.** The engine keeps cumulative per-pid counters (distinct extensions,
//!   high-entropy writes, deletions). Pid `0` lives as long as the service, so without a reset those
//!   counters would eventually trip on ordinary use (a build, an archive extraction). The bucket is
//!   reset every `window`, which turns the counters back into the burst rates they were designed as.
//! * **Only `Critical` is an incident.** `Critical` needs conclusive evidence (a decoy was written,
//!   recovery was destroyed) or burst + encryption-like entropy + marker-extension renames together.
//!   `Suspicious` alone is counted but not reported as an incident: archive extraction produces it.
//! * **The ring of decoys is the strongest signal.** Decoy files sit in dedicated folders that no
//!   legitimate program writes into; any change under such a folder is a conclusive event.
//! * **Overflow is never hidden.** A full queue drops the event, counts it, and `status_json`
//!   reports the bridge as degraded.

use litric_core::entropy::shannon;
use litric_core::ranshield::{DecoyKind, FsEvent, HoneyVault, Level, RansomShield};
use litric_monitor::{is_under, norm_path, ChangeKind, FsChange, Observer};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How many bytes at the start of a file are sampled for entropy.
const ENTROPY_SAMPLE_BYTES: usize = 64 * 1024;
/// Incidents kept in memory for `/status`; older ones remain only in the log file.
const MAX_INCIDENTS: usize = 100;
/// Bound on the hand-off queue between the OS watcher thread and the analysis thread.
const QUEUE_CAP: usize = 50_000;
/// Bound on remembered "write whose file vanished" paths.
const MAX_LOST_WRITES: usize = 20_000;
/// A repeat incident of the same level inside this window is not reported again.
const INCIDENT_COOLDOWN: Duration = Duration::from_secs(30);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Name of the folder created inside a protected directory to hold decoy files.
pub const DECOY_FOLDER: &str = "Litric Decoys";

/// Where the bridge looks, and what it deliberately ignores.
#[derive(Debug, Clone, Default)]
pub struct ShieldScope {
    /// Changes under these directories are ignored (e.g. the system temp folder, where builds and
    /// installers write constantly) unless they are also under an `explicit` directory.
    pub skip: Vec<PathBuf>,
    /// Directories the operator asked for by name; never skipped.
    pub explicit: Vec<PathBuf>,
    /// Decoy folders: any change under one is a conclusive event.
    pub decoy_dirs: Vec<PathBuf>,
}

#[derive(Debug, Default)]
struct ShieldStats {
    received: AtomicU64,
    dropped: AtomicU64,
    analysed: AtomicU64,
    skipped_scope: AtomicU64,
    decoy_touches: AtomicU64,
    suspicious_observations: AtomicU64,
    critical_observations: AtomicU64,
    incidents_total: AtomicU64,
    window_resets: AtomicU64,
    log_errors: AtomicU64,
    worker_panics: AtomicU64,
}

/// A reported ransomware-behaviour incident.
#[derive(Debug, Clone)]
pub struct ShieldIncident {
    pub t_unix: u64,
    pub level: &'static str,
    pub score: u32,
    pub reasons: Vec<String>,
    pub actions: Vec<&'static str>,
    pub trigger_path: String,
}

impl ShieldIncident {
    fn to_json(&self) -> Value {
        json!({
            "t": self.t_unix,
            "level": self.level,
            "score": self.score,
            "reasons": self.reasons,
            "recommended_actions": self.actions,
            "trigger_path": self.trigger_path,
            // Stated on every incident so no consumer can mistake it for a contained attack.
            "contained": false,
            "note": "The acting process is unknown (user-mode file notifications carry no process \
                     id), so nothing was suspended or blocked. This is an alert.",
        })
    }
}

/// The running bridge. Create with [`ShieldBridge::start`], hand [`ShieldBridge::observer`] to the
/// monitor, and call [`ShieldBridge::shutdown`] after the monitor has stopped.
pub struct ShieldBridge {
    tx: Mutex<Option<SyncSender<FsChange>>>,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    stats: Arc<ShieldStats>,
    incidents: Arc<Mutex<VecDeque<ShieldIncident>>>,
    decoy_dirs: Vec<PathBuf>,
    decoy_files: usize,
    decoy_errors: Vec<String>,
    log_path: Option<PathBuf>,
}

/// Creates (idempotently) the decoy files in each `dir` and returns the HoneyVault plus any errors.
/// Existing decoy files are left alone; nothing outside `dir` is touched.
pub fn deploy_decoys(dirs: &[PathBuf]) -> (HoneyVault, usize, Vec<String>) {
    let mut vault = HoneyVault::new();
    let mut total = 0usize;
    let mut errors = Vec::new();
    let kinds = [DecoyKind::Document, DecoyKind::Spreadsheet, DecoyKind::Image, DecoyKind::Database];
    for d in dirs {
        match vault.deploy(d, &kinds, 2) {
            Ok(n) => total += n,
            Err(e) => errors.push(format!("{}: {e}", d.display())),
        }
    }
    (vault, total, errors)
}

impl ShieldBridge {
    /// Starts the analysis thread. `shield` is the service's shared engine, so events posted through
    /// `/api/v1/ranshield/events` and events from the live file monitor are judged by one engine.
    ///
    /// `decoy_files` / `decoy_errors` describe the decoys deployed by the caller (before the monitor
    /// started, so deployment itself is not an event).
    pub fn start(
        shield: Arc<Mutex<RansomShield>>,
        scope: ShieldScope,
        decoy_files: usize,
        decoy_errors: Vec<String>,
        log_path: Option<PathBuf>,
    ) -> std::io::Result<ShieldBridge> {
        let (tx, rx) = sync_channel::<FsChange>(QUEUE_CAP);
        let stats = Arc::new(ShieldStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let incidents = Arc::new(Mutex::new(VecDeque::new()));

        let window = lock(&shield).config().window;
        let mut worker = Worker {
            shield,
            window,
            window_start: Instant::now(),
            skip: scope.skip.iter().map(|p| norm_path(&p.to_string_lossy(), cfg!(windows))).collect(),
            explicit: scope.explicit.iter().map(|p| norm_path(&p.to_string_lossy(), cfg!(windows))).collect(),
            decoy_norm: scope.decoy_dirs.iter().map(|p| norm_path(&p.to_string_lossy(), cfg!(windows))).collect(),
            pending_from: None,
            lost_writes: Default::default(),
            stats: stats.clone(),
            incidents: incidents.clone(),
            last_report: None,
            log: log_path.as_ref().and_then(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).ok()),
        };
        let stop2 = stop.clone();
        let handle = std::thread::Builder::new().name("litric-ransomshield".into()).spawn(move || loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(change) => {
                    // a bug in analysis must not end protection
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker.handle(change)));
                    if r.is_err() {
                        worker.stats.worker_panics.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if stop2.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        })?;

        Ok(ShieldBridge {
            tx: Mutex::new(Some(tx)),
            stop,
            worker: Mutex::new(Some(handle)),
            stats,
            incidents,
            decoy_dirs: scope.decoy_dirs,
            decoy_files,
            decoy_errors,
            log_path,
        })
    }

    /// The tap to put in `MonitorConfig::observer`. Never blocks: a full queue drops and counts.
    pub fn observer(&self) -> Observer {
        let tx = lock(&self.tx).clone();
        let stats = self.stats.clone();
        Observer::new(move |change| {
            stats.received.fetch_add(1, Ordering::Relaxed);
            match &tx {
                Some(tx) => match tx.try_send(change) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                        stats.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                },
                None => {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    }

    /// Waits until every queued change has been analysed (tests and shutdown).
    pub fn wait_idle(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        loop {
            let r = self.stats.received.load(Ordering::Relaxed);
            let d = self.stats.dropped.load(Ordering::Relaxed);
            if r.saturating_sub(d) <= self.stats.analysed.load(Ordering::Relaxed) + self.stats.skipped_scope.load(Ordering::Relaxed) {
                return true;
            }
            if start.elapsed() > timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Reasons protection from this layer is degraded; empty when everything it owns works.
    pub fn degraded(&self) -> Vec<String> {
        let mut d = Vec::new();
        let dropped = self.stats.dropped.load(Ordering::Relaxed);
        if dropped > 0 {
            d.push(format!("{dropped} file change(s) were dropped before ransomware analysis (queue full)"));
        }
        let panics = self.stats.worker_panics.load(Ordering::Relaxed);
        if panics > 0 {
            d.push(format!("{panics} ransomware analysis step(s) crashed and were skipped"));
        }
        let logerr = self.stats.log_errors.load(Ordering::Relaxed);
        if logerr > 0 {
            d.push(format!("{logerr} incident(s) could not be written to the incident log"));
        }
        for e in &self.decoy_errors {
            d.push(format!("decoy folder could not be prepared: {e}"));
        }
        if !self.is_running() {
            d.push("the ransomware analysis thread is not running".into());
        }
        d
    }

    pub fn is_running(&self) -> bool {
        lock(&self.worker).as_ref().map_or(false, |w| !w.is_finished())
    }

    pub fn incidents(&self) -> Vec<ShieldIncident> {
        lock(&self.incidents).iter().cloned().collect()
    }

    pub fn status_json(&self) -> Value {
        let c = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let s = &self.stats;
        json!({
            "running": self.is_running(),
            "mode": "alert-only: file notifications do not identify the acting process, so nothing \
                     is suspended or blocked",
            "degraded": self.degraded(),
            "decoys": {
                "folders": self.decoy_dirs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "files_created_this_start": self.decoy_files,
            },
            "stats": {
                "changes_received": c(&s.received),
                "changes_dropped": c(&s.dropped),
                "analysed": c(&s.analysed),
                "ignored_out_of_scope": c(&s.skipped_scope),
                "decoy_touches": c(&s.decoy_touches),
                "suspicious_observations": c(&s.suspicious_observations),
                "critical_observations": c(&s.critical_observations),
                "incidents": c(&s.incidents_total),
                "window_resets": c(&s.window_resets),
            },
            "log": self.log_path.as_ref().map(|p| p.display().to_string()),
            "incidents": lock(&self.incidents).iter().rev().take(20).map(ShieldIncident::to_json).collect::<Vec<_>>(),
        })
    }

    /// Stops the analysis thread after it drains what is queued. Call after the monitor has stopped.
    /// Safe to call more than once.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        drop(lock(&self.tx).take());
        if let Some(w) = lock(&self.worker).take() {
            let _ = w.join();
        }
    }
}

impl Drop for ShieldBridge {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Worker {
    shield: Arc<Mutex<RansomShield>>,
    window: Duration,
    window_start: Instant,
    skip: Vec<String>,
    explicit: Vec<String>,
    decoy_norm: Vec<String>,
    /// Old name of a rename, waiting for its new name.
    pending_from: Option<PathBuf>,
    /// Paths whose write was reported but which no longer existed when analysed. Ransomware writes
    /// then renames at once, so by the time the write is looked at the old name is gone; if the
    /// path then shows up as the source of a rename, the entropy is taken from the new name.
    lost_writes: std::collections::HashSet<PathBuf>,
    stats: Arc<ShieldStats>,
    incidents: Arc<Mutex<VecDeque<ShieldIncident>>>,
    last_report: Option<(Level, Instant)>,
    log: Option<std::fs::File>,
}

impl Worker {
    fn in_scope(&self, path: &Path) -> bool {
        let n = norm_path(&path.to_string_lossy(), cfg!(windows));
        if self.decoy_norm.iter().any(|d| is_under(&n, d)) {
            return true; // a decoy is always in scope
        }
        if self.skip.iter().any(|s| is_under(&n, s)) {
            return self.explicit.iter().any(|e| is_under(&n, e));
        }
        true
    }

    fn is_decoy(&self, path: &Path) -> bool {
        let n = norm_path(&path.to_string_lossy(), cfg!(windows));
        self.decoy_norm.iter().any(|d| is_under(&n, d))
    }

    fn handle(&mut self, change: FsChange) {
        if !self.in_scope(&change.path) {
            self.stats.skipped_scope.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.stats.analysed.fetch_add(1, Ordering::Relaxed);

        // Tumbling window: see the module docs.
        if self.window_start.elapsed() >= self.window {
            lock(&self.shield).forget_process(0);
            self.window_start = Instant::now();
            self.lost_writes.clear();
            self.stats.window_resets.fetch_add(1, Ordering::Relaxed);
        }

        let events = if self.is_decoy(&change.path) {
            self.stats.decoy_touches.fetch_add(1, Ordering::Relaxed);
            // keep rename bookkeeping consistent even though the decoy hit decides the outcome
            if change.kind == ChangeKind::RenamedTo {
                self.pending_from = None;
            }
            vec![FsEvent::DecoyTouched { pid: 0, decoy: change.path.display().to_string() }]
        } else {
            self.to_events(&change)
        };
        for event in events {
            let assessment = lock(&self.shield).observe(event);
            match assessment.level {
                Level::Critical => {
                    self.stats.critical_observations.fetch_add(1, Ordering::Relaxed);
                    self.report(&assessment, &change.path);
                }
                Level::Suspicious => {
                    self.stats.suspicious_observations.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    fn to_events(&mut self, change: &FsChange) -> Vec<FsEvent> {
        match change.kind {
            ChangeKind::Created | ChangeKind::Modified => match sample(&change.path) {
                Some((bytes, entropy)) => vec![FsEvent::Write { pid: 0, path: change.path.clone(), bytes, entropy }],
                None => {
                    // not a regular file any more (renamed or deleted already), or a directory
                    if self.lost_writes.len() < MAX_LOST_WRITES && !change.path.is_dir() {
                        self.lost_writes.insert(change.path.clone());
                    }
                    Vec::new()
                }
            },
            ChangeKind::Removed => {
                self.lost_writes.remove(&change.path);
                vec![FsEvent::Delete { pid: 0, path: change.path.clone() }]
            }
            ChangeKind::RenamedFrom => {
                self.pending_from = Some(change.path.clone());
                Vec::new()
            }
            ChangeKind::RenamedTo => {
                let from = self.pending_from.take().unwrap_or_else(|| change.path.clone());
                let mut out = Vec::new();
                if self.lost_writes.remove(&from) {
                    // the content written under the old name now lives under the new one
                    if let Some((bytes, entropy)) = sample(&change.path) {
                        out.push(FsEvent::Write { pid: 0, path: change.path.clone(), bytes, entropy });
                    }
                }
                out.push(FsEvent::Rename { pid: 0, from, to: change.path.clone() });
                out
            }
        }
    }

    /// Records a `Critical` assessment once per cooldown; the same attack must not flood the log.
    fn report(&mut self, a: &litric_core::ranshield::Assessment, trigger: &Path) {
        let now = Instant::now();
        if let Some((level, at)) = self.last_report {
            if level >= a.level && now.duration_since(at) < INCIDENT_COOLDOWN {
                return;
            }
        }
        self.last_report = Some((a.level, now));
        let incident = ShieldIncident {
            t_unix: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            level: a.level.as_str(),
            score: a.score,
            reasons: a.reasons.clone(),
            actions: a.actions.iter().map(|x| x.as_str()).collect(),
            trigger_path: trigger.display().to_string(),
        };
        self.stats.incidents_total.fetch_add(1, Ordering::Relaxed);
        if let Some(f) = self.log.as_mut() {
            if writeln!(f, "{}", incident.to_json()).is_err() {
                self.stats.log_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut ring = lock(&self.incidents);
        if ring.len() >= MAX_INCIDENTS {
            ring.pop_front();
        }
        ring.push_back(incident);
    }
}

/// Size and entropy of the start of a regular file. `None` for directories, symlinks and anything
/// that vanished: an unreadable file is not guessed about. A file that exists but cannot be read
/// (locked) is reported with entropy 0.0 so that it still counts as a write but never as an
/// encrypted one.
fn sample(path: &Path) -> Option<(u64, f64)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mut buf = vec![0u8; ENTROPY_SAMPLE_BYTES];
    let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut buf)) {
        Ok(n) => n,
        Err(_) => return Some((meta.len(), 0.0)),
    };
    if n == 0 {
        return Some((meta.len(), 0.0));
    }
    Some((meta.len(), shannon(&buf[..n])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use litric_core::ranshield::RansomShieldConfig;
    use litric_monitor::{Monitor, MonitorConfig};
    use std::sync::atomic::Ordering::Relaxed;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("litric_shield_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn shield() -> Arc<Mutex<RansomShield>> {
        Arc::new(Mutex::new(RansomShield::new(RansomShieldConfig::default())))
    }

    /// Deterministic bytes that look encrypted (entropy ~8 bits/byte).
    fn random_bytes(seed: u64, n: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Feeds changes straight to a bridge (no OS watcher) so the policy is tested deterministically.
    fn feed(b: &ShieldBridge, kind: ChangeKind, path: &Path) {
        b.observer().notify(FsChange { kind, path: path.to_path_buf() });
    }

    #[test]
    fn sample_reports_high_entropy_for_random_data_and_low_for_text() {
        let d = dir("sample");
        std::fs::write(d.join("r.bin"), random_bytes(1, 8192)).unwrap();
        std::fs::write(d.join("t.txt"), "hello hello hello hello ".repeat(100)).unwrap();
        assert!(sample(&d.join("r.bin")).unwrap().1 > 7.5);
        assert!(sample(&d.join("t.txt")).unwrap().1 < 4.5);
        assert!(sample(&d).is_none(), "directories are not sampled");
        assert!(sample(&d.join("missing")).is_none());
    }

    #[test]
    fn a_decoy_touch_is_a_critical_incident_with_an_honest_alert_only_note() {
        let d = dir("decoy");
        let decoys = d.join(DECOY_FOLDER);
        let (_hv, n, errs) = deploy_decoys(&[decoys.clone()]);
        assert!(n > 0 && errs.is_empty(), "{errs:?}");
        let b = ShieldBridge::start(
            shield(),
            ShieldScope { decoy_dirs: vec![decoys.clone()], ..Default::default() },
            n,
            errs,
            None,
        )
        .unwrap();
        let victim = std::fs::read_dir(&decoys).unwrap().next().unwrap().unwrap().path();
        feed(&b, ChangeKind::Modified, &victim);
        assert!(b.wait_idle(Duration::from_secs(5)));
        let inc = b.incidents();
        assert_eq!(inc.len(), 1, "{inc:?}");
        assert_eq!(inc[0].level, "critical");
        assert!(inc[0].reasons.iter().any(|r| r.contains("decoy")), "{:?}", inc[0].reasons);
        let j = b.status_json();
        assert_eq!(j["incidents"][0]["contained"], false);
        assert_eq!(j["stats"]["decoy_touches"], 1);
        b.shutdown();
    }

    #[test]
    fn encrypt_and_rename_in_a_burst_is_critical_but_the_same_volume_of_text_edits_is_not() {
        let d = dir("burst");
        let b = ShieldBridge::start(shield(), ShieldScope::default(), 0, vec![], None).unwrap();

        // 60 ordinary text files edited: writes burst, but nothing looks encrypted or renamed.
        for i in 0..60 {
            let p = d.join(format!("note{i}.txt"));
            std::fs::write(&p, "plain text ".repeat(200)).unwrap();
            feed(&b, ChangeKind::Modified, &p);
        }
        assert!(b.wait_idle(Duration::from_secs(10)));
        assert!(b.incidents().is_empty(), "benign edits must not be an incident: {:?}", b.incidents());

        // The ransomware pattern: overwrite with random data and rename to a marker extension.
        for i in 0..30 {
            let from = d.join(format!("doc{i}.docx"));
            std::fs::write(&from, random_bytes(i as u64 + 7, 8192)).unwrap();
            feed(&b, ChangeKind::Modified, &from);
            let to = d.join(format!("doc{i}.docx.locked"));
            std::fs::rename(&from, &to).unwrap();
            feed(&b, ChangeKind::RenamedFrom, &from);
            feed(&b, ChangeKind::RenamedTo, &to);
        }
        assert!(b.wait_idle(Duration::from_secs(10)));
        let inc = b.incidents();
        assert_eq!(inc.len(), 1, "one incident per cooldown, not one per file: {inc:?}; status {}", b.status_json());
        assert_eq!(inc[0].level, "critical");
        assert!(inc[0].reasons.iter().any(|r| r.contains("high-entropy")), "{:?}", inc[0].reasons);
        assert!(inc[0].reasons.iter().any(|r| r.contains("renames")), "{:?}", inc[0].reasons);
        b.shutdown();
    }

    #[test]
    fn the_skipped_temp_folder_is_ignored_unless_the_operator_named_it() {
        let temp = dir("scope_temp");
        let named = temp.join("named");
        std::fs::create_dir_all(&named).unwrap();
        let b = ShieldBridge::start(
            shield(),
            ShieldScope { skip: vec![temp.clone()], explicit: vec![named.clone()], decoy_dirs: vec![] },
            0,
            vec![],
            None,
        )
        .unwrap();
        let ignored = temp.join("a.bin");
        std::fs::write(&ignored, random_bytes(3, 4096)).unwrap();
        let kept = named.join("b.bin");
        std::fs::write(&kept, random_bytes(4, 4096)).unwrap();
        feed(&b, ChangeKind::Created, &ignored);
        feed(&b, ChangeKind::Created, &kept);
        assert!(b.wait_idle(Duration::from_secs(5)));
        assert_eq!(b.stats.skipped_scope.load(Relaxed), 1);
        assert_eq!(b.stats.analysed.load(Relaxed), 1);
        b.shutdown();
    }

    #[test]
    fn a_full_queue_drops_and_reports_degraded_protection() {
        let b = ShieldBridge::start(shield(), ShieldScope::default(), 0, vec![], None).unwrap();
        b.shutdown(); // sender gone: every further change is dropped, and says so
        feed(&b, ChangeKind::Created, Path::new("x"));
        assert_eq!(b.stats.dropped.load(Relaxed), 1);
        assert!(b.degraded().iter().any(|d| d.contains("dropped")), "{:?}", b.degraded());
    }

    /// A ransomware-style run with NO decoys, on real OS events: the behaviour alone must be enough.
    /// Each file is overwritten with random bytes and renamed at once, so the old name is already
    /// gone when the write is analysed (the race the bridge has to survive). A ransom note is
    /// dropped too. Only the test's own temp files are touched.
    #[test]
    fn a_simulated_ransomware_run_is_detected_from_real_events_without_decoys() {
        use litric_core::quarantine::QuarantineVault;
        let root = dir("sim");
        let watch = root.join("docs");
        std::fs::create_dir_all(&watch).unwrap();
        for i in 0..60 {
            std::fs::write(watch.join(format!("file{i}.docx")), "original document text ".repeat(50)).unwrap();
        }
        let b = Arc::new(ShieldBridge::start(shield(), ShieldScope::default(), 0, vec![], None).unwrap());
        let vault = Arc::new(QuarantineVault::open(&root.join("vault"), &root.join("vault.key")).unwrap());
        let engine = litric_core::engine::Engine::new(
            litric_core::rules::RuleSet::compile(vec![]).unwrap(),
            litric_core::threatdb::ThreatDb::empty(),
            litric_core::engine::EngineConfig::default(),
        );
        let mut cfg = MonitorConfig::new(vec![watch.clone()]);
        cfg.debounce = Duration::from_millis(50);
        cfg.observer = Some(b.observer());
        let m = Monitor::start(Arc::new(litric_pipeline::Pipeline::new(engine)), vault, cfg).unwrap();
        std::thread::sleep(Duration::from_millis(300));

        for i in 0..60 {
            let from = watch.join(format!("file{i}.docx"));
            std::fs::write(&from, random_bytes(1000 + i as u64, 16 * 1024)).unwrap(); // "encrypt"
            std::fs::rename(&from, watch.join(format!("file{i}.docx.locked"))).unwrap();
        }
        std::fs::write(watch.join("README_RESTORE_FILES.txt"), "your files are encrypted (test)").unwrap();

        let start = Instant::now();
        while b.incidents().is_empty() && start.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let inc = b.incidents();
        assert!(!inc.is_empty(), "ransomware-style run not detected; status: {}", b.status_json());
        assert_eq!(inc[0].level, "critical");
        assert_eq!(b.status_json()["incidents"][0]["contained"], false);
        m.shutdown();
        b.shutdown();
    }

    /// Extracting an archive of photos writes many high-entropy files, which is not ransomware.
    #[test]
    fn extracting_many_compressed_files_is_not_an_incident() {
        let d = dir("extract");
        let b = ShieldBridge::start(shield(), ShieldScope::default(), 0, vec![], None).unwrap();
        for i in 0..80 {
            let p = d.join(format!("photo{i}.jpg"));
            std::fs::write(&p, random_bytes(500 + i as u64, 16 * 1024)).unwrap();
            feed(&b, ChangeKind::Created, &p);
        }
        assert!(b.wait_idle(Duration::from_secs(10)));
        assert!(b.incidents().is_empty(), "{:?}", b.incidents());
        b.shutdown();
    }

    /// The whole chain with the real OS watcher: file write -> monitor tap -> bridge -> engine.
    #[test]
    fn a_decoy_written_on_disk_reaches_the_engine_through_the_real_monitor_tap() {
        use litric_core::quarantine::QuarantineVault;
        let root = dir("tap");
        let watch = root.join("docs");
        let decoys = watch.join(DECOY_FOLDER);
        let (_hv, n, errs) = deploy_decoys(&[decoys.clone()]);
        assert!(n > 0 && errs.is_empty(), "{errs:?}");

        let b = Arc::new(
            ShieldBridge::start(
                shield(),
                ShieldScope { decoy_dirs: vec![decoys.clone()], ..Default::default() },
                n,
                errs,
                None,
            )
            .unwrap(),
        );
        let vault = Arc::new(QuarantineVault::open(&root.join("vault"), &root.join("vault.key")).unwrap());
        let engine = litric_core::engine::Engine::new(
            litric_core::rules::RuleSet::compile(vec![]).unwrap(),
            litric_core::threatdb::ThreatDb::empty(),
            litric_core::engine::EngineConfig::default(),
        );
        let pipeline = Arc::new(litric_pipeline::Pipeline::new(engine));
        let mut cfg = MonitorConfig::new(vec![watch.clone()]);
        cfg.debounce = Duration::from_millis(50);
        cfg.observer = Some(b.observer());
        let m = Monitor::start(pipeline, vault, cfg).unwrap();

        std::thread::sleep(Duration::from_millis(300));
        let victim = std::fs::read_dir(&decoys).unwrap().next().unwrap().unwrap().path();
        std::fs::write(&victim, random_bytes(99, 4096)).unwrap();

        let start = Instant::now();
        while b.incidents().is_empty() && start.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let inc = b.incidents();
        assert!(!inc.is_empty(), "no incident from a real decoy write; status: {}", b.status_json());
        assert_eq!(inc[0].level, "critical");
        m.shutdown();
        b.shutdown();
    }
}
