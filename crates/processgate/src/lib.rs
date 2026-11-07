//! Litric process gate — best-effort containment for newly started processes.
//!
//! This closes the gap that matters most in practice: a user double-clicks a
//! downloaded executable in Explorer and the scanner never gets a chance to look
//! at it. The gate watches process creation, **suspends** every thread of a new
//! process, scans its image, and then resumes it or terminates it.
//!
//! # What this is, stated plainly
//!
//! * **Best-effort, not a kernel guarantee.** There is a window between
//!   `CreateProcess` returning and the gate suspending the threads; code can run
//!   in that window. A Microsoft-signed minifilter or a documented process-creation
//!   callback is the only way to close it, and this build has neither.
//! * **Hash-only enforcement.** A process is terminated only when the scanned
//!   image's SHA-256 is listed as malicious in the signed threat database. Rule,
//!   heuristic and score-based verdicts are reported but never kill anything:
//!   this repository has already measured a rule-level false positive on
//!   `kernel32.dll`, so acting on rules alone would be unsafe.
//! * **Protected by location and identity.** Images under `%SystemRoot%`,
//!   `%ProgramFiles%`, `%ProgramData%\Microsoft`, the Litric install directory,
//!   this process, its ancestors, and PIDs 0/4 are never suspended or killed.
//! * **Nothing is deleted.** Terminating a process is reversible for the user
//!   (the file is still on disk). The gate does not move or delete files.
//! * **Every observation is recorded**, including failures to suspend, so a
//!   degraded gate is visible instead of pretending to protect.
//!
//! The platform half lives in [`windows`]; all policy is pure and unit-tested
//! here so the dangerous decisions do not depend on an untestable code path.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use litric_core::engine::{Engine, Verdict};
use litric_core::threatdb::EntryKind;
use serde::Serialize;

#[cfg(windows)]
pub mod windows;

/// How the gate reacts to a malicious image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// Off: the gate is not started at all.
    Off,
    /// Suspend, scan, resume; report what *would* have been blocked.
    Monitor,
    /// Terminate only on an exact malicious hash match.
    EnforceHash,
}

impl GateMode {
    pub fn as_str(self) -> &'static str {
        match self {
            GateMode::Off => "off",
            GateMode::Monitor => "monitor",
            GateMode::EnforceHash => "enforce-hash",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" => Some(GateMode::Off),
            "monitor" | "audit" | "detect" => Some(GateMode::Monitor),
            "enforce" | "enforce-hash" | "block" => Some(GateMode::EnforceHash),
            _ => None,
        }
    }
}

/// What the gate did with one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Alert,
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Alert => "alert",
            Action::Block => "block",
        }
    }
}

/// A policy decision plus the reason, so a log line explains itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub reason: &'static str,
}

/// The single place that decides whether Litric may kill a process.
///
/// Deliberately ordered: protection checks come first, and an exact hash match
/// is required before `Block` is possible.
pub fn decide(
    mode: GateMode,
    malicious: bool,
    hash_listed: bool,
    protected_pid: bool,
    protected_path: bool,
) -> Decision {
    if protected_pid {
        return Decision {
            action: Action::Allow,
            reason: "protected-process",
        };
    }
    if protected_path {
        return Decision {
            action: Action::Allow,
            reason: "protected-image-path",
        };
    }
    if !malicious {
        return Decision {
            action: Action::Allow,
            reason: "no-malicious-verdict",
        };
    }
    if !hash_listed {
        return Decision {
            action: Action::Alert,
            reason: "rule-or-heuristic-only",
        };
    }
    match mode {
        GateMode::Off => Decision {
            action: Action::Allow,
            reason: "gate-off",
        },
        GateMode::Monitor => Decision {
            action: Action::Alert,
            reason: "monitor-mode",
        },
        GateMode::EnforceHash => Decision {
            action: Action::Block,
            reason: "hash-listed-malicious",
        },
    }
}

/// Paths and PIDs the gate must never touch.
#[derive(Debug, Clone)]
pub struct ProtectedSet {
    roots: Vec<String>,
    self_pid: u32,
    ancestors: Vec<u32>,
}

impl ProtectedSet {
    pub fn new(roots: Vec<PathBuf>, self_pid: u32, ancestors: Vec<u32>) -> Self {
        ProtectedSet {
            roots: roots
                .into_iter()
                .map(|p| normalize_path(&p))
                .filter(|p| !p.is_empty())
                .collect(),
            self_pid,
            ancestors,
        }
    }

    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    pub fn is_protected_pid(&self, pid: u32) -> bool {
        pid <= 4 || pid == self.self_pid || self.ancestors.contains(&pid)
    }

    pub fn is_protected_path(&self, path: &Path) -> bool {
        let candidate = normalize_path(path);
        self.roots.iter().any(|root| under(&candidate, root))
    }
}

fn normalize_path(path: &Path) -> String {
    let mut text = path.display().to_string().replace('/', "\\");
    while text.ends_with('\\') && text.len() > 3 {
        text.pop();
    }
    text.to_ascii_lowercase()
}

fn under(candidate: &str, root: &str) -> bool {
    candidate == root
        || (candidate.starts_with(root)
            && candidate.as_bytes().get(root.len()) == Some(&b'\\'))
}

/// One process from a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub parent: u32,
    pub name: String,
}

/// A process whose threads are suspended; dropping it resumes them.
pub trait Suspension {
    fn resume(self: Box<Self>) -> Result<(), String>;
    fn terminate(self: Box<Self>) -> Result<(), String>;
}

/// The OS surface the gate needs. Implemented for real in [`windows`] and by a
/// deterministic fake in the unit tests.
pub trait ProcControl: Send {
    fn snapshot(&mut self) -> Vec<ProcInfo>;
    fn image_path(&mut self, pid: u32) -> Option<PathBuf>;
    fn suspend(&mut self, pid: u32) -> Result<Box<dyn Suspension>, String>;
}

/// Gate tunables.
#[derive(Debug, Clone)]
pub struct GateConfig {
    pub poll: Duration,
    /// Images larger than this are not scanned while suspended; they are
    /// reported as skipped instead of freezing the process for a long read.
    pub max_scan_bytes: u64,
    /// How many new processes one tick may suspend, so a fork bomb cannot stall
    /// the machine behind a queue of suspended processes.
    pub max_per_tick: usize,
}

impl Default for GateConfig {
    fn default() -> Self {
        GateConfig {
            poll: Duration::from_millis(250),
            max_scan_bytes: 64 * 1024 * 1024,
            max_per_tick: 8,
        }
    }
}

#[derive(Debug, Default)]
pub struct Counters {
    pub seen: AtomicU64,
    pub scanned: AtomicU64,
    pub allowed: AtomicU64,
    pub alerted: AtomicU64,
    pub blocked: AtomicU64,
    pub unprotected: AtomicU64,
    pub vanished: AtomicU64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GateEvent {
    pub t_ms: u64,
    pub pid: u32,
    pub image: Option<String>,
    pub action: &'static str,
    pub reason: &'static str,
    pub verdict: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GateStats {
    pub seen: u64,
    pub scanned: u64,
    pub allowed: u64,
    pub alerted: u64,
    pub blocked: u64,
    pub unprotected: u64,
    pub vanished: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GateStatus {
    pub mode: &'static str,
    pub running: bool,
    pub stats: GateStats,
    pub recent: Vec<GateEvent>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Handle shared with the API/UI. Stopping it is cooperative.
pub struct GateHandle {
    stop: Arc<AtomicBool>,
    mode: GateMode,
    counters: Arc<Counters>,
    recent: Arc<Mutex<VecDeque<GateEvent>>>,
}

impl GateHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn mode(&self) -> GateMode {
        self.mode
    }

    pub fn stats(&self) -> GateStats {
        GateStats {
            seen: self.counters.seen.load(Ordering::Relaxed),
            scanned: self.counters.scanned.load(Ordering::Relaxed),
            allowed: self.counters.allowed.load(Ordering::Relaxed),
            alerted: self.counters.alerted.load(Ordering::Relaxed),
            blocked: self.counters.blocked.load(Ordering::Relaxed),
            unprotected: self.counters.unprotected.load(Ordering::Relaxed),
            vanished: self.counters.vanished.load(Ordering::Relaxed),
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<GateEvent> {
        let guard = self
            .recent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.iter().rev().take(limit).cloned().collect()
    }

    /// Honest one-line state for the API/UI.
    pub fn status(&self) -> GateStatus {
        GateStatus {
            mode: self.mode.as_str(),
            running: !self.stop.load(Ordering::SeqCst),
            stats: self.stats(),
            recent: self.recent(50),
        }
    }
}

/// The gate loop. `tick` is public so tests drive it without threads.
pub struct Gate {
    engine: Arc<Engine>,
    control: Box<dyn ProcControl>,
    mode: GateMode,
    config: GateConfig,
    protected: ProtectedSet,
    baseline: Vec<u32>,
    counters: Arc<Counters>,
    recent: Arc<Mutex<VecDeque<GateEvent>>>,
}

impl Gate {
    pub fn new(
        engine: Arc<Engine>,
        mut control: Box<dyn ProcControl>,
        mode: GateMode,
        config: GateConfig,
        protected: ProtectedSet,
    ) -> Self {
        // Everything already running is out of scope: the gate protects what
        // starts *after* it does, and never retroactively suspends the desktop.
        let baseline = control.snapshot().into_iter().map(|p| p.pid).collect();
        Gate {
            engine,
            control,
            mode,
            config,
            protected,
            baseline,
            counters: Arc::new(Counters::default()),
            recent: Arc::new(Mutex::new(VecDeque::with_capacity(64))),
        }
    }

    pub fn counters(&self) -> Arc<Counters> {
        self.counters.clone()
    }

    pub fn recent(&self) -> Arc<Mutex<VecDeque<GateEvent>>> {
        self.recent.clone()
    }

    /// Processes one snapshot. Returns how many new processes were examined.
    pub fn tick(&mut self) -> usize {
        let snapshot = self.control.snapshot();
        let mut handled = 0usize;
        for proc in snapshot {
            if self.baseline.contains(&proc.pid) {
                continue;
            }
            if handled >= self.config.max_per_tick {
                break;
            }
            self.baseline.push(proc.pid);
            handled += 1;
            self.counters.seen.fetch_add(1, Ordering::Relaxed);
            self.examine(proc);
        }
        handled
    }

    fn examine(&mut self, proc: ProcInfo) {
        if self.protected.is_protected_pid(proc.pid) {
            self.counters.allowed.fetch_add(1, Ordering::Relaxed);
            self.record(
                proc.pid,
                None,
                Action::Allow,
                "protected-process",
                "",
                "core or ancestor process",
            );
            return;
        }

        let image = match self.control.image_path(proc.pid) {
            Some(p) => p,
            None => {
                self.counters.vanished.fetch_add(1, Ordering::Relaxed);
                self.record(
                    proc.pid,
                    None,
                    Action::Allow,
                    "image-unknown",
                    "",
                    "process ended before its image could be resolved",
                );
                return;
            }
        };

        if self.protected.is_protected_path(&image) {
            self.counters.allowed.fetch_add(1, Ordering::Relaxed);
            self.record(
                proc.pid,
                Some(&image),
                Action::Allow,
                "protected-image-path",
                "",
                "Windows or vendor directory; never suspended by the gate",
            );
            return;
        }

        match std::fs::metadata(&image) {
            Ok(meta) if meta.len() > self.config.max_scan_bytes => {
                self.counters.unprotected.fetch_add(1, Ordering::Relaxed);
                self.record(
                    proc.pid,
                    Some(&image),
                    Action::Allow,
                    "image-too-large",
                    "",
                    "larger than the gate scan cap; not suspended",
                );
                return;
            }
            Err(e) => {
                self.counters.unprotected.fetch_add(1, Ordering::Relaxed);
                self.record(
                    proc.pid,
                    Some(&image),
                    Action::Allow,
                    "image-unreadable",
                    "",
                    &e.to_string(),
                );
                return;
            }
            _ => {}
        }

        let suspension = match self.control.suspend(proc.pid) {
            Ok(s) => s,
            Err(e) => {
                // The process may already have exited, or we lack access. Either
                // way it ran unscanned and the caller must see that.
                self.counters.unprotected.fetch_add(1, Ordering::Relaxed);
                self.record(
                    proc.pid,
                    Some(&image),
                    Action::Allow,
                    "suspend-failed",
                    "",
                    &e,
                );
                return;
            }
        };

        let report = match self.engine.analyze_path(&image, self.config.max_scan_bytes) {
            Ok((report, _)) => report,
            Err(e) => {
                let _ = suspension.resume();
                self.counters.unprotected.fetch_add(1, Ordering::Relaxed);
                self.record(
                    proc.pid,
                    Some(&image),
                    Action::Allow,
                    "scan-failed",
                    "",
                    &e.to_string(),
                );
                return;
            }
        };
        self.counters.scanned.fetch_add(1, Ordering::Relaxed);

        let hash_listed = matches!(
            self.engine.db().lookup(&report.sha256),
            Some(entry) if entry.kind == EntryKind::Malicious
        );
        let decision = decide(
            self.mode,
            report.verdict == Verdict::Malicious,
            hash_listed,
            false,
            false,
        );

        let detail = format!(
            "sha256={} score={} threat={}",
            report.sha256.to_hex(),
            report.score,
            report.threat_name.as_deref().unwrap_or("-")
        );

        match decision.action {
            Action::Block => {
                let outcome = suspension.terminate();
                match outcome {
                    Ok(()) => {
                        self.counters.blocked.fetch_add(1, Ordering::Relaxed);
                        self.record(
                            proc.pid,
                            Some(&image),
                            Action::Block,
                            decision.reason,
                            report.verdict.as_str(),
                            &detail,
                        );
                    }
                    Err(e) => {
                        self.counters.unprotected.fetch_add(1, Ordering::Relaxed);
                        self.record(
                            proc.pid,
                            Some(&image),
                            Action::Allow,
                            "terminate-failed",
                            report.verdict.as_str(),
                            &format!("{detail}; {e}"),
                        );
                    }
                }
            }
            Action::Alert | Action::Allow => {
                let _ = suspension.resume();
                if decision.action == Action::Alert {
                    self.counters.alerted.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.counters.allowed.fetch_add(1, Ordering::Relaxed);
                }
                self.record(
                    proc.pid,
                    Some(&image),
                    decision.action,
                    decision.reason,
                    report.verdict.as_str(),
                    &detail,
                );
            }
        }
    }

    fn record(
        &self,
        pid: u32,
        image: Option<&Path>,
        action: Action,
        reason: &'static str,
        verdict: &str,
        detail: &str,
    ) {
        let event = GateEvent {
            t_ms: now_ms(),
            pid,
            image: image.map(|p| p.display().to_string()),
            action: action.as_str(),
            reason,
            verdict: verdict.to_string(),
            detail: detail.to_string(),
        };
        let mut guard = self
            .recent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.len() >= 200 {
            guard.pop_front();
        }
        guard.push_back(event);
    }

    /// Runs until `stop` is set.
    pub fn run(mut self, stop: Arc<AtomicBool>) {
        while !stop.load(Ordering::SeqCst) {
            self.tick();
            std::thread::sleep(self.config.poll);
        }
    }
}

/// Starts the gate on a background thread.
pub fn spawn(
    engine: Arc<Engine>,
    control: Box<dyn ProcControl>,
    mode: GateMode,
    config: GateConfig,
    protected: ProtectedSet,
) -> std::io::Result<GateHandle> {
    let stop = Arc::new(AtomicBool::new(false));
    let gate = Gate::new(engine, control, mode, config, protected);
    let handle = GateHandle {
        stop: stop.clone(),
        mode,
        counters: gate.counters(),
        recent: gate.recent(),
    };
    std::thread::Builder::new()
        .name("litric-process-gate".into())
        .spawn(move || gate.run(stop))?;
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use litric_core::engine::EngineConfig;
    use litric_core::rules::RuleSet;
    use litric_core::threatdb::{build_signed, dev_signing_key, DbPayload, HashEntry, ThreatDb};
    use std::collections::HashMap;

    struct FakeSuspension {
        pid: u32,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Suspension for FakeSuspension {
        fn resume(self: Box<Self>) -> Result<(), String> {
            self.log.lock().unwrap().push(format!("resume:{}", self.pid));
            Ok(())
        }

        fn terminate(self: Box<Self>) -> Result<(), String> {
            self.log.lock().unwrap().push(format!("kill:{}", self.pid));
            Ok(())
        }
    }

    struct FakeControl {
        /// What exists when the gate is constructed (never acted on).
        baseline: Vec<ProcInfo>,
        procs: Vec<ProcInfo>,
        primed: bool,
        images: HashMap<u32, PathBuf>,
        fail_suspend: bool,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl ProcControl for FakeControl {
        fn snapshot(&mut self) -> Vec<ProcInfo> {
            if !self.primed {
                self.primed = true;
                return self.baseline.clone();
            }
            self.procs.clone()
        }

        fn image_path(&mut self, pid: u32) -> Option<PathBuf> {
            self.images.get(&pid).cloned()
        }

        fn suspend(&mut self, pid: u32) -> Result<Box<dyn Suspension>, String> {
            if self.fail_suspend {
                return Err("access denied".into());
            }
            self.log.lock().unwrap().push(format!("suspend:{pid}"));
            Ok(Box::new(FakeSuspension {
                pid,
                log: self.log.clone(),
            }))
        }
    }

    fn engine_with_db(hashes: Vec<HashEntry>) -> Engine {
        let payload = DbPayload {
            schema: litric_core::threatdb::DB_FORMAT_VERSION,
            db_version: 1,
            min_engine: litric_core::ENGINE_VERSION.to_string(),
            hashes,
            ..Default::default()
        };
        let (p, m) = build_signed(&payload, &dev_signing_key()).unwrap();
        let db = ThreatDb::verify_loaded(&p, &m, &[], true, litric_core::ENGINE_VERSION).unwrap();
        Engine::new(RuleSet::empty(), db, EngineConfig::default())
    }

    fn hash_of(path: &Path) -> String {
        let data = std::fs::read(path).unwrap();
        litric_core::hash::sha256_bytes(&data).to_hex()
    }

    fn temp_file(name: &str, body: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("litric-gate-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.exe");
        std::fs::write(&path, body).unwrap();
        path
    }

    fn gate_for(
        mode: GateMode,
        image: &Path,
        engine: Engine,
        fail_suspend: bool,
    ) -> (Gate, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut images = HashMap::new();
        images.insert(4242u32, image.to_path_buf());
        let control = FakeControl {
            // 100 is the "already running" baseline; 4242 starts afterwards.
            baseline: vec![ProcInfo {
                pid: 100,
                parent: 1,
                name: "explorer.exe".into(),
            }],
            procs: vec![
                ProcInfo {
                    pid: 100,
                    parent: 1,
                    name: "explorer.exe".into(),
                },
                ProcInfo {
                    pid: 4242,
                    parent: 100,
                    name: "sample.exe".into(),
                },
            ],
            primed: false,
            images,
            fail_suspend,
            log: log.clone(),
        };
        let protected = ProtectedSet::new(vec![], 999, vec![100]);
        let gate = Gate::new(
            Arc::new(engine),
            Box::new(control),
            mode,
            GateConfig::default(),
            protected,
        );
        (gate, log)
    }

    #[test]
    fn baseline_processes_are_never_touched() {
        let image = temp_file("baseline", b"MZ harmless");
        let (mut gate, log) = gate_for(
            GateMode::EnforceHash,
            &image,
            engine_with_db(vec![]),
            false,
        );
        // First tick: 4242 is new and is examined (allowed, unknown).
        gate.tick();
        let calls = log.lock().unwrap().clone();
        assert!(!calls.iter().any(|c| c.starts_with("kill:100")));
        assert!(!calls.iter().any(|c| c == "suspend:100"));
        let _ = std::fs::remove_dir_all(image.parent().unwrap());
    }

    #[test]
    fn only_an_exact_hash_match_can_be_blocked() {
        let image = temp_file("hash", b"MZ this is a harmless test image");
        let sha = hash_of(&image);
        let entry = HashEntry {
            sha256: sha.clone(),
            name: "Test.Synthetic.Hash".into(),
            family: None,
            severity: Some("high".into()),
            kind: EntryKind::Malicious,
            source: Some("test".into()),
            license: None,
        };
        let (mut gate, log) = gate_for(
            GateMode::EnforceHash,
            &image,
            engine_with_db(vec![entry]),
            false,
        );
        gate.tick();
        let calls = log.lock().unwrap().clone();
        assert!(calls.contains(&"kill:4242".to_string()), "{calls:?}");
        let _ = std::fs::remove_dir_all(image.parent().unwrap());
    }

    #[test]
    fn monitor_mode_reports_but_resumes() {
        let image = temp_file("monitor", b"MZ monitor sample");
        let sha = hash_of(&image);
        let entry = HashEntry {
            sha256: sha,
            name: "Test.Synthetic.Hash".into(),
            family: None,
            severity: None,
            kind: EntryKind::Malicious,
            source: Some("test".into()),
            license: None,
        };
        let (mut gate, log) = gate_for(
            GateMode::Monitor,
            &image,
            engine_with_db(vec![entry]),
            false,
        );
        gate.tick();
        let calls = log.lock().unwrap().clone();
        assert!(calls.contains(&"resume:4242".to_string()), "{calls:?}");
        assert!(!calls.iter().any(|c| c.starts_with("kill:")), "{calls:?}");
        let _ = std::fs::remove_dir_all(image.parent().unwrap());
    }

    #[test]
    fn a_failed_suspend_never_kills_and_is_counted() {
        let image = temp_file("fail", b"MZ fail sample");
        let sha = hash_of(&image);
        let entry = HashEntry {
            sha256: sha,
            name: "Test.Synthetic.Hash".into(),
            family: None,
            severity: None,
            kind: EntryKind::Malicious,
            source: Some("test".into()),
            license: None,
        };
        let (mut gate, log) = gate_for(
            GateMode::EnforceHash,
            &image,
            engine_with_db(vec![entry]),
            true,
        );
        gate.tick();
        let calls = log.lock().unwrap().clone();
        assert!(!calls.iter().any(|c| c.starts_with("kill:")), "{calls:?}");
        assert_eq!(gate.counters().unprotected.load(Ordering::Relaxed), 1);
        let _ = std::fs::remove_dir_all(image.parent().unwrap());
    }

    #[test]
    fn protected_paths_are_skipped_before_suspension() {
        let root = std::env::temp_dir().join(format!("litric-prot-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let image = root.join("inside.exe");
        std::fs::write(&image, b"MZ").unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let mut images = HashMap::new();
        images.insert(4242u32, image.clone());
        let control = FakeControl {
            baseline: vec![],
            procs: vec![ProcInfo {
                pid: 4242,
                parent: 1,
                name: "inside.exe".into(),
            }],
            primed: false,
            images,
            fail_suspend: false,
            log: log.clone(),
        };
        let protected = ProtectedSet::new(vec![root.clone()], 999, vec![]);
        let mut gate = Gate::new(
            Arc::new(engine_with_db(vec![])),
            Box::new(control),
            GateMode::EnforceHash,
            GateConfig::default(),
            protected,
        );
        gate.tick();
        assert!(log.lock().unwrap().is_empty(), "must not suspend");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn policy_table_is_explicit() {
        use Action::*;
        let cases = [
            (GateMode::EnforceHash, true, true, false, false, Block),
            (GateMode::EnforceHash, true, false, false, false, Alert),
            (GateMode::EnforceHash, false, false, false, false, Allow),
            (GateMode::Monitor, true, true, false, false, Alert),
            (GateMode::Off, true, true, false, false, Allow),
            (GateMode::EnforceHash, true, true, true, false, Allow),
            (GateMode::EnforceHash, true, true, false, true, Allow),
        ];
        for (mode, malicious, hash, pid, path, expected) in cases {
            let d = decide(mode, malicious, hash, pid, path);
            assert_eq!(d.action, expected, "{mode:?} {malicious} {hash}");
        }
    }

    #[test]
    fn protected_set_handles_case_and_separators() {
        let set = ProtectedSet::new(vec![PathBuf::from(r"C:\Windows")], 10, vec![20]);
        assert!(set.is_protected_path(Path::new(r"c:\windows\system32\cmd.exe")));
        assert!(set.is_protected_path(Path::new(r"C:/Windows/System32/cmd.exe")));
        assert!(!set.is_protected_path(Path::new(r"C:\WindowsApps\x.exe")));
        assert!(!set.is_protected_path(Path::new(r"D:\Windows\x.exe")));
        assert!(set.is_protected_pid(4));
        assert!(set.is_protected_pid(10));
        assert!(set.is_protected_pid(20));
        assert!(!set.is_protected_pid(30));
    }

    #[test]
    fn mode_parsing_is_explicit_and_rejects_garbage() {
        assert_eq!(GateMode::parse("monitor"), Some(GateMode::Monitor));
        assert_eq!(GateMode::parse("ENFORCE"), Some(GateMode::EnforceHash));
        assert_eq!(GateMode::parse("off"), Some(GateMode::Off));
        assert_eq!(GateMode::parse("yolo"), None);
    }
}
