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
//! * Files that existed before the monitor started are not scanned by the *event* path. Call
//!   [`Monitor::start_sweep`] to walk the watched directories once in the background; the sweep
//!   is bounded, never follows reparse points, and reports what it could not read as degraded.

use litric_core::engine::Verdict;
use litric_core::quarantine::QuarantineVault;
use litric_pipeline::{Action, Pipeline};
use notify::{EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Default size at which the JSON-lines event log is rotated to `<log>.1`.
pub const DEFAULT_LOG_MAX_BYTES: u64 = 8 << 20;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What the OS reported for a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Created,
    Modified,
    Removed,
    /// The old name of a rename (the path no longer exists under this name).
    RenamedFrom,
    /// The new name of a rename.
    RenamedTo,
}

/// One raw file-system change, handed to an [`Observer`] before any debounce or scan decision.
#[derive(Debug, Clone)]
pub struct FsChange {
    pub kind: ChangeKind,
    pub path: PathBuf,
}

/// A tap on the monitor's single OS watcher, so other systems (the RansomShield behavioural engine)
/// see the same events without opening a second watcher on the same directories.
///
/// It runs on the OS-facing watcher thread: it must return immediately and never read files or
/// block, or the OS notification buffer overflows and events are lost. Paths under the monitor's
/// exclude list (vault, log) are never delivered.
#[derive(Clone)]
pub struct Observer(Arc<dyn Fn(FsChange) + Send + Sync>);

impl Observer {
    pub fn new(f: impl Fn(FsChange) + Send + Sync + 'static) -> Self {
        Observer(Arc::new(f))
    }

    /// Delivers one change, exactly as the watcher would (used by tests and synthetic sources).
    pub fn notify(&self, change: FsChange) {
        (self.0)(change)
    }
}

impl std::fmt::Debug for Observer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Observer(..)")
    }
}

/// Translates a `notify` event into the raw changes an [`Observer`] receives. Metadata-only and
/// access events are not changes to content or names and are dropped.
fn changes_of(ev: &notify::Event) -> Vec<FsChange> {
    use notify::event::{ModifyKind, RenameMode};
    let one = |kind: ChangeKind, p: &PathBuf| FsChange { kind, path: p.clone() };
    match &ev.kind {
        EventKind::Create(_) => ev.paths.iter().map(|p| one(ChangeKind::Created, p)).collect(),
        EventKind::Remove(_) => ev.paths.iter().map(|p| one(ChangeKind::Removed, p)).collect(),
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => ev.paths.iter().map(|p| one(ChangeKind::RenamedFrom, p)).collect(),
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => ev.paths.iter().map(|p| one(ChangeKind::RenamedTo, p)).collect(),
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            let mut v = Vec::new();
            if let Some(p) = ev.paths.first() {
                v.push(one(ChangeKind::RenamedFrom, p));
            }
            if let Some(p) = ev.paths.get(1) {
                v.push(one(ChangeKind::RenamedTo, p));
            }
            v
        }
        EventKind::Modify(ModifyKind::Metadata(_)) => Vec::new(),
        EventKind::Modify(_) => ev.paths.iter().map(|p| one(ChangeKind::Modified, p)).collect(),
        _ => Vec::new(),
    }
}

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
    /// The event log is renamed to `<log>.1` (replacing the previous one) past this size.
    pub log_max_bytes: u64,
    /// Optional tap on every raw change (see [`Observer`]).
    pub observer: Option<Observer>,
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
            log_max_bytes: DEFAULT_LOG_MAX_BYTES,
            observer: None,
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
    /// Files visited by the startup sweep (each one went through the same scan path as an event).
    pub sweep_visited: AtomicU64,
    /// Directories or entries the sweep could not read; their contents were NOT scanned.
    pub sweep_errors: AtomicU64,
    pub sweep_running: AtomicBool,
    pub sweep_finished: AtomicBool,
    /// The sweep stopped at its file limit; the remainder was NOT scanned.
    pub sweep_truncated: AtomicBool,
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
    watcher: Mutex<Option<notify::RecommendedWatcher>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    sweeper: Mutex<Option<JoinHandle<()>>>,
    ctx: Arc<Ctx>,
    /// Directories the OS watcher accepted.
    watched: Vec<PathBuf>,
    /// `"<dir>: <reason>"` for directories the OS watcher refused. Reported as degraded.
    unwatched: Vec<String>,
    started_unix: u64,
}

/// High-risk, user-writable locations worth watching by default on Windows: every profile's
/// Downloads, Desktop, Documents, Temp and Startup folder, plus the system temp and the
/// all-users Startup folder. Only directories that exist *and can be opened* by this process
/// are returned, so the result is what can actually be covered; the monitor reports the
/// directories it really watches.
pub fn default_watch_dirs() -> Vec<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    let sysdrive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let per_profile = [
        "Downloads",
        "Desktop",
        "Documents",
        "AppData\\Local\\Temp",
        "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    ];
    if let Ok(rd) = std::fs::read_dir(PathBuf::from(format!("{sysdrive}\\Users"))) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_lowercase();
            if matches!(name.as_str(), "all users" | "default" | "default user" | "defaultuser0") {
                continue;
            }
            let base = e.path();
            for sub in per_profile {
                cands.push(base.join(sub));
            }
        }
    }
    if let Some(up) = std::env::var_os("USERPROFILE") {
        let base = PathBuf::from(up);
        for sub in per_profile {
            cands.push(base.join(sub));
        }
    }
    if let Some(root) = std::env::var_os("SystemRoot") {
        cands.push(PathBuf::from(root).join("Temp"));
    }
    if let Some(pd) = std::env::var_os("ProgramData") {
        cands.push(PathBuf::from(pd).join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
    }
    cands.push(std::env::temp_dir());

    let mut out: Vec<PathBuf> = Vec::new();
    for c in cands {
        let key = norm_path(&c.to_string_lossy(), cfg!(windows));
        if c.is_dir() && !out.iter().any(|o| norm_path(&o.to_string_lossy(), cfg!(windows)) == key) {
            out.push(c);
        }
    }
    out
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
    log_path: Option<PathBuf>,
    log_bytes: AtomicU64,
}

impl Ctx {
    fn log(&self, ev: &str, path: &Path, extra: serde_json::Value) {
        let line = serde_json::json!({
            "t": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            "event": ev,
            "path": path.display().to_string(),
            "detail": extra,
        })
        .to_string();
        let mut g = lock(&self.log);
        if g.is_none() {
            return;
        }
        let total = self.log_bytes.fetch_add(line.len() as u64 + 1, Ordering::Relaxed) + line.len() as u64 + 1;
        if total > self.cfg.log_max_bytes {
            self.rotate_log(&mut g);
        }
        if let Some(f) = g.as_mut() {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Keeps one previous generation (`<log>.1`) so the log cannot grow without bound.
    fn rotate_log(&self, slot: &mut Option<std::fs::File>) {
        let Some(p) = &self.log_path else { return };
        *slot = None; // close our handle before renaming
        let mut old = p.as_os_str().to_owned();
        old.push(".1");
        let _ = std::fs::rename(p, PathBuf::from(old));
        *slot = std::fs::OpenOptions::new().create(true).append(true).open(p).ok();
        self.log_bytes.store(0, Ordering::Relaxed);
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
            let mut rotated = l.as_os_str().to_owned();
            rotated.push(".1");
            cfg.exclude.push(PathBuf::from(rotated));
        }
        let log = match &cfg.log_path {
            Some(p) => std::fs::OpenOptions::new().create(true).append(true).open(p).ok(),
            None => None,
        };
        let log_bytes = cfg.log_path.as_ref().and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len()).unwrap_or(0);
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
        let ctx = Arc::new(Ctx {
            excl_norm,
            pipeline,
            vault,
            cfg: cfg.clone(),
            stats: stats.clone(),
            log: Mutex::new(log),
            log_path: cfg.log_path.clone(),
            log_bytes: AtomicU64::new(log_bytes),
        });

        let st = stats.clone();
        let tx2: SyncSender<PathBuf> = tx;
        let alive = watcher_alive.clone();
        let tap = cfg.observer.clone().map(|o| (o, ctx.clone()));
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(ev) => {
                if let Some((observer, c)) = &tap {
                    for change in changes_of(&ev) {
                        if !c.excluded(&change.path) {
                            observer.notify(change);
                        }
                    }
                }
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
        // A directory the OS refuses to watch (access denied, vanished) degrades protection and is
        // reported; it only stops startup when *nothing* could be watched.
        let mut watched: Vec<PathBuf> = Vec::new();
        let mut unwatched: Vec<String> = Vec::new();
        for d in &cfg.watch_dirs {
            match watcher.watch(d, RecursiveMode::Recursive) {
                Ok(()) => watched.push(d.clone()),
                Err(e) => unwatched.push(format!("{}: {e}", d.display())),
            }
        }
        if watched.is_empty() {
            return Err(StartError::Watch(unwatched.join("; ")));
        }

        let worker_ctx = ctx.clone();
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
                        // all senders gone (watcher dropped): do not spin while draining `pending`
                        Err(RecvTimeoutError::Disconnected) => std::thread::sleep(Duration::from_millis(50)),
                    }
                    let now = Instant::now();
                    let ready: Vec<PathBuf> = pending.iter().filter(|(_, t)| now.duration_since(**t) >= debounce).map(|(p, _)| p.clone()).collect();
                    for p in ready {
                        pending.remove(&p);
                        let c = worker_ctx.clone();
                        let pp = p.clone();
                        // a bug in a parser must not stop protection
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || c.process(&pp))).is_err() {
                            worker_ctx.stats.worker_panics.fetch_add(1, Ordering::Relaxed);
                            worker_ctx.log("worker_panic", &p, serde_json::json!({}));
                        }
                    }
                    if stop2.load(Ordering::Relaxed) && pending.is_empty() {
                        break;
                    }
                }
            })
            .map_err(|e| StartError::Watch(e.to_string()))?;

        let started_unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Ok(Monitor {
            stats,
            stop,
            watcher_alive,
            watcher: Mutex::new(Some(watcher)),
            worker: Mutex::new(Some(worker)),
            sweeper: Mutex::new(None),
            ctx,
            watched,
            unwatched,
            started_unix,
        })
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Directories the OS watcher accepted.
    pub fn watched(&self) -> &[PathBuf] {
        &self.watched
    }

    /// Walk every watched directory once, in a background thread, and push each regular file
    /// through the same scan path as a change event. This closes the "files that already existed
    /// at startup" gap. Bounded by `max_files`; reparse points/symlinks are never followed;
    /// anything unreadable or past the limit is counted and reported as degraded protection.
    /// Calling it twice is a no-op.
    pub fn start_sweep(&self, max_files: u64) {
        let mut slot = lock(&self.sweeper);
        if slot.is_some() {
            return;
        }
        let ctx = self.ctx.clone();
        let stop = self.stop.clone();
        let stats = self.stats.clone();
        let mut stack: Vec<PathBuf> = self.watched.clone();
        stats.sweep_running.store(true, Ordering::Relaxed);
        let spawned = std::thread::Builder::new().name("litric-monitor-sweep".into()).spawn(move || {
            let mut visited = 0u64;
            'walk: while let Some(dir) = stack.pop() {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if ctx.excluded(&dir) {
                    continue;
                }
                let rd = match std::fs::read_dir(&dir) {
                    Ok(r) => r,
                    Err(_) => {
                        stats.sweep_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                for entry in rd {
                    if stop.load(Ordering::Relaxed) {
                        break 'walk;
                    }
                    let Ok(entry) = entry else {
                        stats.sweep_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let Ok(ft) = entry.file_type() else {
                        stats.sweep_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let p = entry.path();
                    if ft.is_symlink() {
                        // symlinks, junctions and other reparse points are never followed
                        continue;
                    }
                    if ft.is_dir() {
                        stack.push(p);
                        continue;
                    }
                    if !ft.is_file() {
                        continue;
                    }
                    if visited >= max_files {
                        stats.sweep_truncated.store(true, Ordering::Relaxed);
                        break 'walk;
                    }
                    visited += 1;
                    stats.sweep_visited.fetch_add(1, Ordering::Relaxed);
                    let c = ctx.clone();
                    let pp = p.clone();
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || c.process(&pp))).is_err() {
                        stats.worker_panics.fetch_add(1, Ordering::Relaxed);
                        ctx.log("worker_panic", &p, serde_json::json!({"during": "sweep"}));
                    }
                }
            }
            stats.sweep_running.store(false, Ordering::Relaxed);
            stats.sweep_finished.store(true, Ordering::Relaxed);
        });
        match spawned {
            Ok(h) => *slot = Some(h),
            Err(_) => {
                self.stats.sweep_running.store(false, Ordering::Relaxed);
                self.stats.sweep_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Machine-readable state for the service API. Everything here is a counter or a fact; it
    /// never says "protected".
    pub fn status_json(&self) -> serde_json::Value {
        let h = self.health();
        let s = &self.stats;
        let c = |a: &AtomicU64| a.load(Ordering::Relaxed);
        serde_json::json!({
            "running": h.running,
            "degraded": h.degraded,
            "mode": "user-mode file-change notifications: scans after a file is written; cannot block before execution",
            "watched": self.watched.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "unwatched": self.unwatched,
            "auto_quarantine": self.ctx.cfg.auto_quarantine,
            "started_unix": self.started_unix,
            "log": self.ctx.log_path.as_ref().map(|p| p.display().to_string()),
            "stats": {
                "events_seen": c(&s.events_seen),
                "events_dropped": c(&s.events_dropped),
                "scanned": c(&s.scanned),
                "malicious": c(&s.malicious),
                "suspicious": c(&s.suspicious),
                "quarantined": c(&s.quarantined),
                "quarantine_failed": c(&s.quarantine_failed),
                "skipped_too_large": c(&s.skipped_too_large),
                "skipped_not_regular": c(&s.skipped_not_regular),
                "unscannable": c(&s.unscannable),
                "worker_panics": c(&s.worker_panics),
                "watcher_errors": c(&s.watcher_errors),
            },
            "sweep": {
                "running": s.sweep_running.load(Ordering::Relaxed),
                "finished": s.sweep_finished.load(Ordering::Relaxed),
                "visited": c(&s.sweep_visited),
                "errors": c(&s.sweep_errors),
                "truncated": s.sweep_truncated.load(Ordering::Relaxed),
            },
        })
    }

    /// The last `limit` records of the JSON-lines event log (oldest first). Empty when no log
    /// path was configured or the log cannot be read.
    pub fn recent_events(&self, limit: usize) -> Vec<serde_json::Value> {
        let Some(p) = &self.ctx.log_path else { return Vec::new() };
        let Ok(text) = std::fs::read_to_string(p) else { return Vec::new() };
        let mut v: Vec<serde_json::Value> = text.lines().rev().take(limit).filter_map(|l| serde_json::from_str(l).ok()).collect();
        v.reverse();
        v
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
        if !self.unwatched.is_empty() {
            degraded.push(format!("{} director(ies) could NOT be watched: {}", self.unwatched.len(), self.unwatched.join("; ")));
        }
        let se = s.sweep_errors.load(Ordering::Relaxed);
        if se > 0 {
            degraded.push(format!("the startup sweep could not read {se} director(ies)/entr(ies); their files were NOT scanned"));
        }
        if s.sweep_truncated.load(Ordering::Relaxed) {
            degraded.push("the startup sweep stopped at its file limit; remaining existing files were NOT scanned".into());
        }
        let running = self.watcher_alive.load(Ordering::Relaxed)
            && lock(&self.watcher).is_some()
            && lock(&self.worker).as_ref().map_or(false, |w| !w.is_finished());
        if !running {
            degraded.push("the monitor is not running".into());
        }
        Health { running, degraded }
    }

    /// Finish queued work and stop. Safe to call more than once and through a shared reference
    /// (the service keeps the monitor in an `Arc`).
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        // join the worker while the watcher is still alive: dropping the watcher first would
        // disconnect the channel under a worker that is still draining
        let worker = lock(&self.worker).take();
        if let Some(w) = worker {
            let _ = w.join();
        }
        let sweeper = lock(&self.sweeper).take();
        if let Some(w) = sweeper {
            let _ = w.join();
        }
        drop(lock(&self.watcher).take());
    }

    /// Finish queued work and stop.
    pub fn stop(self) {
        self.shutdown();
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.shutdown();
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
