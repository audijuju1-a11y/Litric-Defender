//! Litric real-time file protection (user mode).
//!
//! ```text
//! OS change notifications (`ReadDirectoryChangesW` via `notify`)
//!   -> bounded queue (overflow is counted and reported as DEGRADED, never hidden)
//!   -> per-path debounce until the file stops changing
//!   -> Pipeline::scan_path  (native engine + imported signatures + optional YARA + Authenticode)
//!   -> Malicious: verified move into the encrypted quarantine vault (reversible)
//!      Suspicious: alert only;  Unknown / incomplete: logged, never "clean"
//! ```
//!
//! # What this is NOT (stated plainly)
//! * **Post-write, not pre-execution.** A file is scanned *after* it was written. Between the
//!   write and the verdict a user can run it. Blocking before execution needs a kernel
//!   minifilter, which is not part of this crate.
//! * **No process attribution.** File-change notifications do not say which process wrote the
//!   file, so this layer cannot suspend a ransomware process.
//! * **Not a cure for dropped events.** Heavy bursts can overflow the OS buffer or the queue;
//!   that is counted and surfaced as degraded protection, and a periodic full scan is still needed.
//! * Files that existed before the monitor started are not scanned by it.

use litric_core::engine::Verdict;
use litric_core::quarantine::QuarantineVault;
use litric_pipeline::{Action, Pipeline};
use notify::{EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub watch_dirs: Vec<PathBuf>,
    /// Paths under any of these are never scanned (the vault, the log, caches).
    pub exclude: Vec<PathBuf>,
    /// Files larger than this are *skipped and counted*, never reported clean.
    pub max_file_bytes: u64,
    /// A path is scanned only after this long without further change events.
    pub debounce: Duration,
    pub queue_cap: usize,
    /// Quarantine `Malicious` files automatically (reversible: encrypted vault).
    pub auto_quarantine: bool,
    /// Optional JSON-lines event log.
    pub log_path: Option<PathBuf>,
    /// Pause after each scan (I/O and CPU throttling).
    pub throttle: Duration,
    /// Retries when a file is locked/in use.
    pub lock_retries: u32,
}

impl MonitorConfig {
    pub fn new(watch_dirs: Vec<PathBuf>) -> Self {
        MonitorConfig {
            watch_dirs,
            exclude: Vec::new(),
            max_file_bytes: 256 << 20,
            debounce: Duration::from_millis(400),
            queue_cap: 10_000,
            auto_quarantine: true,
            log_path: None,
            throttle: Duration::ZERO,
            lock_retries: 5,
        }
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    pub events_seen: AtomicU64,
    pub events_dropped: AtomicU64,
    pub scanned: AtomicU64,
    pub malicious: AtomicU64,
    pub suspicious: AtomicU64,
    pub quarantined: AtomicU64,
    pub quarantine_failed: AtomicU64,
    pub skipped_too_large: AtomicU64,
    pub skipped_not_regular: AtomicU64,
    pub unscannable: AtomicU64,
    pub worker_panics: AtomicU64,
    pub watcher_errors: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    pub running: bool,
    /// Empty = every layer this crate owns is working. Non-empty = protection is degraded.
    pub degraded: Vec<String>,
}

#[derive(Debug)]
pub enum StartError {
    NoWatchDirs,
    MissingDir(PathBuf),
    Watch(String),
}
impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::NoWatchDirs => write!(f, "no directories to watch"),
            StartError::MissingDir(p) => write!(f, "watch directory does not exist: {}", p.display()),
            StartError::Watch(e) => write!(f, "cannot start the file watcher: {e}"),
        }
    }
}
impl std::error::Error for StartError {}

pub struct Monitor {
    stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
    watcher_alive: Arc<AtomicBool>,
    _watcher: notify::RecommendedWatcher,
    worker: Option<JoinHandle<()>>,
}

/// Normalises a path string for comparison: on Windows paths are case-insensitive, may use `/`
/// or `\\`, and may carry the `\\?\` extended prefix; none of that may let a vault path escape
/// the exclusion check.
pub fn norm_path(s: &str, windows: bool) -> String {
    if !windows {
        return s.trim_end_matches('/').to_string();
    }
    let mut t = s.replace('/', "\\");
    if let Some(r) = t.strip_prefix("\\\\?\\UNC\\") {
        t = format!("\\\\{r}");
    } else if let Some(r) = t.strip_prefix("\\\\?\\") {
        t = r.to_string();
    }
    t.trim_end_matches('\\').to_lowercase()
}

/// True when `path` equals `root` or lies below it (component-boundary aware).
pub fn is_under(path: &str, root: &str) -> bool {
    if root.is_empty() {
        return false;
    }
    path == root || (path.starts_with(root) && matches!(path.as_bytes().get(root.len()), Some(b'/') | Some(b'\\')))
}

struct Ctx {
    excl_norm: Vec<String>,
    pipeline: Arc<Pipeline>,
    vault: Arc<QuarantineVault>,
    cfg: MonitorConfig,
    stats: Arc<Stats>,
    log: Mutex<Option<std::fs::File>>,
}

impl Ctx {
    fn log(&self, ev: &str, path: &Path, extra: serde_json::Value) {
        let line = serde_json::json!({
            "t": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            "event": ev,
            "path": path.display().to_string(),
            "detail": extra,
        });
        if let Ok(mut g) = self.log.lock() {
            if let Some(f) = g.as_mut() {
                let _ = writeln!(f, "{line}");
            }
        }
    }

    fn excluded(&self, p: &Path) -> bool {
        let n = norm_path(&p.to_string_lossy(), cfg!(windows));
        self.excl_norm.iter().any(|e| is_under(&n, e))
    }

    fn process(&self, path: &Path) {
        if self.excluded(path) {
            return;
        }
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => return, // already gone (temp file) - nothing to scan
        };
        if !meta.is_file() {
            // symlinks and reparse points are never followed; directories are not scanned
            if meta.file_type().is_symlink() {
                self.stats.skipped_not_regular.fetch_add(1, Ordering::Relaxed);
                self.log("skipped_not_regular", path, serde_json::json!({"reason": "symlink or reparse point not followed"}));
            }
            return;
        }
        if meta.len() > self.cfg.max_file_bytes {
            self.stats.skipped_too_large.fetch_add(1, Ordering::Relaxed);
            self.log("skipped_too_large", path, serde_json::json!({"size": meta.len(), "limit": self.cfg.max_file_bytes}));
            return;
        }
        let mut last_err = None;
        let mut report = None;
        for attempt in 0..=self.cfg.lock_retries {
            match self.pipeline.scan_path(path, self.cfg.max_file_bytes) {
                Ok(r) => {
                    report = Some(r);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Err(e) => {
                    last_err = Some(e.to_string());
                    std::thread::sleep(Duration::from_millis(100 * (attempt as u64 + 1)));
                }
            }
        }
        let Some(r) = report else {
            self.stats.unscannable.fetch_add(1, Ordering::Relaxed);
            self.log("unscannable", path, serde_json::json!({"error": last_err}));
            return;
        };
        self.stats.scanned.fetch_add(1, Ordering::Relaxed);
        let sha_hex = r.native.sha256.to_hex();
        let threat = r.threat_name().unwrap_or_else(|| "unnamed".into());
        match r.verdict {
            Verdict::Malicious => {
                self.stats.malicious.fetch_add(1, Ordering::Relaxed);
                if self.cfg.auto_quarantine && r.action == Action::Quarantine {
                    let family = r.native.family.clone().or_else(|| r.clamav.first().map(|d| d.family.clone()));
                    match self.vault.quarantine_file_checked(path, &sha_hex, &threat, family.as_deref(), r.native.score, false) {
                        Ok(meta) if meta.original_removed => {
                            self.stats.quarantined.fetch_add(1, Ordering::Relaxed);
                            self.log("quarantined", path, serde_json::json!({"threat": threat, "sha256": sha_hex, "id": meta.id, "reasons": r.reasons}));
                        }
                        Ok(meta) => {
                            self.stats.quarantine_failed.fetch_add(1, Ordering::Relaxed);
                            self.log("quarantine_incomplete", path, serde_json::json!({"threat": threat, "id": meta.id, "note": "original was NOT removed"}));
                        }
                        Err(e) => {
                            self.stats.quarantine_failed.fetch_add(1, Ordering::Relaxed);
                            self.log("quarantine_failed", path, serde_json::json!({"threat": threat, "error": e.to_string()}));
                        }
                    }
                } else {
                    self.log("malicious_detected", path, serde_json::json!({"threat": threat, "sha256": sha_hex, "auto_quarantine": self.cfg.auto_quarantine}));
                }
            }
            Verdict::Suspicious => {
                self.stats.suspicious.fetch_add(1, Ordering::Relaxed);
                self.log("suspicious", path, serde_json::json!({"threat": threat, "sha256": sha_hex, "reasons": r.reasons}));
            }
            _ => {
                if !r.incomplete.is_empty() {
                    self.log("scanned_incomplete", path, serde_json::json!({"verdict": r.verdict.as_str(), "incomplete": r.incomplete}));
                }
            }
        }
        if !self.cfg.throttle.is_zero() {
            std::thread::sleep(self.cfg.throttle);
        }
    }
}

impl Monitor {
    pub fn start(pipeline: Arc<Pipeline>, vault: Arc<QuarantineVault>, mut cfg: MonitorConfig) -> Result<Monitor, StartError> {
        if cfg.watch_dirs.is_empty() {
            return Err(StartError::NoWatchDirs);
        }
        for d in &cfg.watch_dirs {
            if !d.is_dir() {
                return Err(StartError::MissingDir(d.clone()));
            }
        }
        // never scan ourselves: the vault and the log
        cfg.exclude.push(vault.dir().to_path_buf());
        if let Some(l) = &cfg.log_path {
            cfg.exclude.push(l.clone());
        }
        let log = match &cfg.log_path {
            Some(p) => std::fs::OpenOptions::new().create(true).append(true).open(p).ok(),
            None => None,
        };
        let stats = Arc::new(Stats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let watcher_alive = Arc::new(AtomicBool::new(true));
        let (tx, rx) = sync_channel::<PathBuf>(cfg.queue_cap.max(1));

        let excl_norm: Vec<String> = cfg
            .exclude
            .iter()
            .flat_map(|e| {
                let raw = norm_path(&e.to_string_lossy(), cfg!(windows));
                let canon = std::fs::canonicalize(e).map(|c| norm_path(&c.to_string_lossy(), cfg!(windows))).ok();
                [Some(raw), canon].into_iter().flatten()
            })
            .collect();
        let ctx = Arc::new(Ctx { excl_norm, pipeline, vault, cfg: cfg.clone(), stats: stats.clone(), log: Mutex::new(log) });

        let st = stats.clone();
        let tx2: SyncSender<PathBuf> = tx;
        let alive = watcher_alive.clone();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(ev) => {
                if matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for p in ev.paths {
                        st.events_seen.fetch_add(1, Ordering::Relaxed);
                        match tx2.try_send(p) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                st.events_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Disconnected(_)) => alive.store(false, Ordering::Relaxed),
                        }
                    }
                }
            }
            Err(_) => {
                st.watcher_errors.fetch_add(1, Ordering::Relaxed);
            }
        })
        .map_err(|e| StartError::Watch(e.to_string()))?;
        for d in &cfg.watch_dirs {
            watcher.watch(d, RecursiveMode::Recursive).map_err(|e| StartError::Watch(format!("{}: {e}", d.display())))?;
        }

        let stop2 = stop.clone();
        let debounce = cfg.debounce;
        let worker = std::thread::Builder::new()
            .name("litric-monitor".into())
            .spawn(move || {
                let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
                loop {
                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(p) => {
                            pending.insert(p, Instant::now());
                            while let Ok(p) = rx.try_recv() {
                                pending.insert(p, Instant::now());
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => {}
                    }
                    let now = Instant::now();
                    let ready: Vec<PathBuf> = pending.iter().filter(|(_, t)| now.duration_since(**t) >= debounce).map(|(p, _)| p.clone()).collect();
                    for p in ready {
                        pending.remove(&p);
                        let c = ctx.clone();
                        let pp = p.clone();
                        // a bug in a parser must not stop protection
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || c.process(&pp))).is_err() {
                            ctx.stats.worker_panics.fetch_add(1, Ordering::Relaxed);
                            ctx.log("worker_panic", &p, serde_json::json!({}));
                        }
                    }
                    if stop2.load(Ordering::Relaxed) && pending.is_empty() {
                        break;
                    }
                }
            })
            .map_err(|e| StartError::Watch(e.to_string()))?;

        Ok(Monitor { stats, stop, watcher_alive, _watcher: watcher, worker: Some(worker) })
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn health(&self) -> Health {
        let mut degraded = Vec::new();
        let s = &self.stats;
        let dropped = s.events_dropped.load(Ordering::Relaxed);
        if dropped > 0 {
            degraded.push(format!("{dropped} file events were dropped (queue full); files may be unscanned"));
        }
        let we = s.watcher_errors.load(Ordering::Relaxed);
        if we > 0 {
            degraded.push(format!("the OS file watcher reported {we} error(s) (possible buffer overflow); events may have been lost"));
        }
        let pan = s.worker_panics.load(Ordering::Relaxed);
        if pan > 0 {
            degraded.push(format!("{pan} scan(s) crashed and were skipped"));
        }
        let un = s.unscannable.load(Ordering::Relaxed);
        if un > 0 {
            degraded.push(format!("{un} file(s) could not be read and were NOT scanned"));
        }
        let big = s.skipped_too_large.load(Ordering::Relaxed);
        if big > 0 {
            degraded.push(format!("{big} file(s) exceeded the size limit and were NOT scanned"));
        }
        let qf = s.quarantine_failed.load(Ordering::Relaxed);
        if qf > 0 {
            degraded.push(format!("{qf} malicious file(s) could not be quarantined"));
        }
        let running = self.watcher_alive.load(Ordering::Relaxed) && self.worker.as_ref().map_or(false, |w| !w.is_finished());
        if !running {
            degraded.push("the monitor is not running".into());
        }
        Health { running, degraded }
    }

    /// Finish queued work and stop.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_paths_compare_case_insensitively_and_ignore_the_extended_prefix() {
        let vault = norm_path(r"C:\ProgramData\Litric\Vault", true);
        assert!(is_under(&norm_path(r"\\?\c:\programdata\LITRIC\vault\a.lq", true), &vault));
        assert!(is_under(&norm_path("C:/ProgramData/Litric/Vault/sub/b.lq", true), &vault));
        assert!(is_under(&vault, &vault));
    }

    #[test]
    fn a_sibling_with_the_same_prefix_is_not_excluded() {
        let vault = norm_path(r"C:\Data\vault", true);
        assert!(!is_under(&norm_path(r"C:\Data\vault2\x.exe", true), &vault));
        let v = norm_path("/var/lib/litric/vault", false);
        assert!(!is_under(&norm_path("/var/lib/litric/vault-old/x", false), &v));
        assert!(is_under(&norm_path("/var/lib/litric/vault/x", false), &v));
    }

    #[test]
    fn unc_paths_are_normalised() {
        assert_eq!(norm_path(r"\\?\UNC\srv\share\dir\", true), r"\\srv\share\dir");
    }
}
