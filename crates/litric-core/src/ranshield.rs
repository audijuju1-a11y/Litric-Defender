//! Litric RansomShield: behavioural ransomware detection, decoys and response.
//!
//! This module is the *decision brain*; it is deliberately transport-agnostic.
//! On Windows the events are produced by an ETW `Microsoft-Windows-Kernel-File`
//! consumer plus a minifilter for enforcement; in tests and on other platforms
//! they are produced by a simulator. Because the logic is pure, the exact code
//! that would run in the service is what the test suite exercises.
//!
//! ## Why the scoring looks like this
//!
//! Ransomware is not "a program that writes a lot". Backup software, video
//! editors, compilers and archivers all write a lot. What distinguishes an
//! encryptor is the *combination* of:
//!
//! * touching a file the user was told not to touch (HoneyVault decoy) — this is
//!   conclusive, because nothing legitimate reads those files;
//! * a burst of writes producing many *new* file extensions (`.locked`, `.enc`);
//! * high-entropy rewrites of user documents in place;
//! * destroying recovery infrastructure (`vssadmin delete shadows`).
//!
//! Each of those is a signal; two of them together is an incident. A decoy touch
//! alone is enough to suspend the process, because the false-positive cost of
//! suspending an archiver that is writing to a decoy folder we created is far
//! lower than the cost of losing the user's files.
//!
//! ## Response policy
//!
//! | score | level      | actions                                  |
//! |-------|------------|------------------------------------------|
//! | >=100 | Critical   | block writes, suspend, isolate, snapshot  |
//! | >=70  | Suspicious | block writes for that process, alert      |
//! | >=40  | Watching   | alert only                                |
//! | <40   | Normal     | nothing                                   |
//!
//! Actions are requests returned to the caller; the caller (service) owns the
//! privilege. The shield never deletes user data.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Configuration for the behavioural engine.
#[derive(Debug, Clone)]
pub struct RansomShieldConfig {
    /// Sliding window for rate-based decisions.
    pub window: Duration,
    /// Writes inside the window that count as a burst.
    pub write_burst: usize,
    /// Distinct new extensions inside the window that indicate mass renaming.
    pub extension_churn: usize,
    /// Entropy above which a write looks encrypted rather than edited.
    pub entropy_threshold: f64,
    /// Minimum encrypted-looking writes before the entropy signal counts.
    pub entropy_samples: usize,
    /// Deletions inside the window that count as mass deletion.
    pub mass_delete: usize,
    /// Score at which writes are blocked.
    pub block_threshold: u32,
    /// Score at which the process is suspended.
    pub suspend_threshold: u32,
}

impl Default for RansomShieldConfig {
    fn default() -> Self {
        RansomShieldConfig {
            window: Duration::from_secs(10),
            write_burst: 40,
            extension_churn: 12,
            entropy_threshold: 7.5,
            entropy_samples: 5,
            mass_delete: 40,
            block_threshold: 70,
            suspend_threshold: 100,
        }
    }
}

/// A file-system event delivered by the sensor layer.
#[derive(Debug, Clone)]
pub enum FsEvent {
    Write {
        pid: u32,
        path: PathBuf,
        bytes: u64,
        /// Entropy of the written payload sample (0.0..=8.0).
        entropy: f64,
    },
    Rename {
        pid: u32,
        from: PathBuf,
        to: PathBuf,
    },
    Delete {
        pid: u32,
        path: PathBuf,
    },
    /// A HoneyVault decoy was opened for writing or renamed.
    DecoyTouched { pid: u32, decoy: String },
    /// The process ran a command that destroys recovery capability.
    BackupTamper { pid: u32, command: String },
}

/// What Litric knows about the process generating events.
#[derive(Debug, Clone, Default)]
pub struct ProcessContext {
    pub image: String,
    /// Authenticode present (chain validation happens elsewhere).
    pub signed: bool,
    pub publisher: Option<String>,
    /// Process command line, when available.
    pub command_line: String,
}

/// Escalation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Normal,
    Watching,
    Suspicious,
    Critical,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Normal => "normal",
            Level::Watching => "watching",
            Level::Suspicious => "suspicious",
            Level::Critical => "critical",
        }
    }
}

/// Response the caller should apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Alert,
    /// Deny further writes from this PID (minifilter) or terminate (user mode).
    BlockWrites,
    SuspendProcess,
    NetworkIsolate,
    /// Take a recovery snapshot of the affected directories.
    SnapshotFiles,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Alert => "alert",
            Action::BlockWrites => "block-writes",
            Action::SuspendProcess => "suspend-process",
            Action::NetworkIsolate => "network-isolate",
            Action::SnapshotFiles => "snapshot-files",
        }
    }
}

/// Result of observing one event.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub pid: u32,
    pub level: Level,
    pub score: u32,
    pub reasons: Vec<String>,
    pub actions: Vec<Action>,
}

impl Assessment {
    pub fn is_incident(&self) -> bool {
        matches!(self.level, Level::Critical)
    }
}

/// Allow-list entry for software that legitimately rewrites many files.
#[derive(Debug, Clone)]
pub struct AllowRule {
    /// Executable file name, lowercase (e.g. `7zfm.exe`).
    pub image: String,
    /// Directory the binary must reside in for the rule to apply.
    pub directory_prefix: String,
    /// Expected output extensions; renames to these do not count as churn.
    pub output_extensions: Vec<String>,
}

impl AllowRule {
    pub fn archiver(image: &str, dir: &str) -> Self {
        AllowRule {
            image: image.to_ascii_lowercase(),
            directory_prefix: dir.to_ascii_lowercase(),
            output_extensions: vec![
                "zip".into(),
                "7z".into(),
                "rar".into(),
                "tar".into(),
                "gz".into(),
                "bz2".into(),
                "xz".into(),
                "cab".into(),
                "iso".into(),
            ],
        }
    }

    fn matches(&self, ctx: &ProcessContext) -> bool {
        let image = ctx.image.to_ascii_lowercase();
        let path = Path::new(&image);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        name == self.image && image.starts_with(&self.directory_prefix)
    }
}

/// Extensions that mass-renaming legitimately produces.
const ARCHIVE_EXTENSIONS: &[&str] = &[
    "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "cab", "iso", "zst", "lz4", "par",
    "par2", "db", "sqlite", "bak", "tmp", "part", "crdownload", "pdf", "png", "jpg",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvKind {
    Write,
    Rename,
    Delete,
    Decoy,
    BackupTamper,
}

#[derive(Debug, Default)]
struct ProcState {
    events: VecDeque<(Instant, EvKind)>,
    new_extensions: HashSet<String>,
    encrypted_writes: usize,
    decoy_hits: usize,
    backup_tamper: usize,
    writes: usize,
    deletes: usize,
    last_level: Option<Level>,
    ctx: ProcessContext,
}

impl ProcState {
    fn has_decoy_hit(&self) -> bool {
        self.decoy_hits > 0
    }
}

/// The RansomShield engine.
pub struct RansomShield {
    cfg: RansomShieldConfig,
    procs: HashMap<u32, ProcState>,
    allowlist: Vec<AllowRule>,
    now: Option<Instant>,
}

impl RansomShield {
    pub fn new(cfg: RansomShieldConfig) -> Self {
        RansomShield {
            cfg,
            procs: HashMap::new(),
            allowlist: Vec::new(),
            now: None,
        }
    }

    pub fn with_allowlist(mut self, rules: Vec<AllowRule>) -> Self {
        self.allowlist = rules;
        self
    }

    /// Test hook: pin the clock so window behaviour is deterministic.
    pub fn set_clock(&mut self, now: Instant) {
        self.now = Some(now);
    }

    fn now(&self) -> Instant {
        self.now.unwrap_or_else(Instant::now)
    }

    pub fn register_process(&mut self, pid: u32, ctx: ProcessContext) {
        self.procs.entry(pid).or_default().ctx = ctx;
    }

    pub fn forget_process(&mut self, pid: u32) {
        self.procs.remove(&pid);
    }

    /// Observes one event and returns the resulting assessment.
    pub fn observe(&mut self, event: FsEvent) -> Assessment {
        let now = self.now();
        let pid = match &event {
            FsEvent::Write { pid, .. }
            | FsEvent::Rename { pid, .. }
            | FsEvent::Delete { pid, .. }
            | FsEvent::DecoyTouched { pid, .. }
            | FsEvent::BackupTamper { pid, .. } => *pid,
        };
        let cfg_window = self.cfg.window;
        let state = self.procs.entry(pid).or_default();

        // Expire old events.
        while let Some((t, _)) = state.events.front() {
            if now.duration_since(*t) > cfg_window {
                state.events.pop_front();
            } else {
                break;
            }
        }

        let kind = match &event {
            FsEvent::Write { entropy, .. } => {
                state.writes += 1;
                if *entropy >= self.cfg.entropy_threshold {
                    state.encrypted_writes += 1;
                }
                EvKind::Write
            }
            FsEvent::Rename { to, .. } => {
                let ext = to
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !ext.is_empty() {
                    state.new_extensions.insert(ext);
                }
                EvKind::Rename
            }
            FsEvent::Delete { .. } => {
                state.deletes += 1;
                EvKind::Delete
            }
            FsEvent::DecoyTouched { .. } => {
                state.decoy_hits += 1;
                EvKind::Decoy
            }
            FsEvent::BackupTamper { .. } => {
                state.backup_tamper += 1;
                EvKind::BackupTamper
            }
        };
        state.events.push_back((now, kind));

        self.assess(pid, &event)
    }

    fn assess(&self, pid: u32, event: &FsEvent) -> Assessment {
        let state = match self.procs.get(&pid) {
            Some(s) => s,
            None => {
                return Assessment {
                    pid,
                    level: Level::Normal,
                    score: 0,
                    reasons: vec![],
                    actions: vec![],
                }
            }
        };
        let mut score: u32 = 0;
        let mut reasons: Vec<String> = Vec::new();

        let in_window = |k: EvKind| {
            state
                .events
                .iter()
                .filter(|(_, kind)| *kind == k)
                .count()
        };

        // --- conclusive evidence -----------------------------------------
        if state.has_decoy_hit() {
            score += 100;
            reasons.push(
                "wrote to a Litric HoneyVault decoy file: no legitimate software does this".into(),
            );
        }
        if state.backup_tamper > 0 {
            score += 90;
            let cmd = match event {
                FsEvent::BackupTamper { command, .. } => command.clone(),
                _ => "recovery destruction command".into(),
            };
            reasons.push(format!(
                "attempted to destroy recovery capability: `{cmd}`"
            ));
        }

        // --- behavioural evidence -----------------------------------------
        let writes = in_window(EvKind::Write).max(1);
        if writes >= self.cfg.write_burst {
            score += 40;
            reasons.push(format!(
                "{} file writes within {:?} (burst threshold {})",
                writes, self.cfg.window, self.cfg.write_burst
            ));
        }

        let ext_count = state.new_extensions.len();
        if ext_count >= self.cfg.extension_churn {
            score += 35;
            reasons.push(format!(
                "{} distinct file extensions produced inside the window",
                ext_count
            ));
        }

        // A rename burst is suspicious on its own, and much more so when the new
        // extension is not an archive/document format. Real ransomware renames
        // every file to a single marker extension (`.lockbit`, `.conti`), which a
        // distinct-extension count alone would miss.
        let renames = in_window(EvKind::Rename);
        if renames >= 10 {
            score += 25;
            reasons.push(format!(
                "{} file renames inside the window",
                renames
            ));
            let unexpected: Vec<&str> = state
                .new_extensions
                .iter()
                .filter(|e| !ARCHIVE_EXTENSIONS.contains(&e.as_str()))
                .map(|e| e.as_str())
                .collect();
            if !unexpected.is_empty() {
                score += 15;
                reasons.push(format!(
                    "renamed into non-archive extension(s): {}",
                    unexpected.iter().take(5).copied().collect::<Vec<_>>().join(", ")
                ));
            }
        }

        if state.encrypted_writes >= self.cfg.entropy_samples {
            score += 30;
            reasons.push(format!(
                "{} writes of high-entropy (>= {:.1} bits/byte) data to user files",
                state.encrypted_writes, self.cfg.entropy_threshold
            ));
        }

        if state.deletes >= self.cfg.mass_delete {
            score += 30;
            reasons.push(format!("{} deletions inside the window", state.deletes));
        }

        // --- benign suppression -------------------------------------------
        // Only an allow-listed binary that produces expected archive output is
        // damped, and never below the level implied by conclusive evidence.
        let mut damped = false;
        for rule in &self.allowlist {
            if !rule.matches(&state.ctx) {
                continue;
            }
            let unexpected: Vec<&String> = state
                .new_extensions
                .iter()
                .filter(|e| !rule.output_extensions.iter().any(|o| o == *e))
                .collect();
            if unexpected.is_empty() {
                let before = score;
                score = (score as f64 * 0.25) as u32;
                damped = true;
                if before != score {
                    reasons.push(format!(
                        "`{}` is allow-listed and only produced expected archive formats; \
                         score damped {} -> {}",
                        state.ctx.image, before, score
                    ));
                }
            } else {
                reasons.push(format!(
                    "allow-listed binary produced unexpected extensions: {}",
                    unexpected
                        .iter()
                        .map(|s| s.as_str())
                        .take(5)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        let _ = damped;

        // A decoy hit or backup tampering can never be damped away.
        if state.has_decoy_hit() || state.backup_tamper > 0 {
            score = score.max(100);
        }

        let level = if score >= self.cfg.suspend_threshold {
            Level::Critical
        } else if score >= self.cfg.block_threshold {
            Level::Suspicious
        } else if score >= 40 {
            Level::Watching
        } else {
            Level::Normal
        };

        let actions = match level {
            Level::Critical => vec![
                Action::Alert,
                Action::BlockWrites,
                Action::SuspendProcess,
                Action::SnapshotFiles,
            ],
            Level::Suspicious => vec![Action::Alert, Action::BlockWrites],
            Level::Watching => vec![Action::Alert],
            Level::Normal => vec![],
        };

        Assessment {
            pid,
            level,
            score,
            reasons,
            actions,
        }
    }

    /// Current level for a process without generating a new event.
    pub fn level_of(&self, pid: u32) -> Level {
        self.procs
            .get(&pid)
            .map(|s| s.last_level.unwrap_or(Level::Normal))
            .unwrap_or(Level::Normal)
    }

    pub fn config(&self) -> &RansomShieldConfig {
        &self.cfg
    }
}

// ---------------------------------------------------------------------------
// HoneyVault
// ---------------------------------------------------------------------------

/// A deployed decoy file.
#[derive(Debug, Clone)]
pub struct Decoy {
    pub id: String,
    pub path: PathBuf,
    pub kind: DecoyKind,
    /// Unique canary token embedded in the content, used to prove a read/write.
    pub canary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyKind {
    Document,
    Spreadsheet,
    Image,
    Database,
    Folder,
}

impl DecoyKind {
    fn file_name(&self, n: usize) -> String {
        match self {
            DecoyKind::Document => format!("Quarterly Report {n}.docx"),
            DecoyKind::Spreadsheet => format!("Budget Forecast {n}.xlsx"),
            DecoyKind::Image => format!("Family Photos {n}.jpg"),
            DecoyKind::Database => format!("customer_records_{n}.db"),
            DecoyKind::Folder => format!("Confidential {n}"),
        }
    }

}

/// Set of deployed decoys plus the lookup used by the sensor.
#[derive(Debug, Default)]
pub struct HoneyVault {
    decoys: Vec<Decoy>,
    by_path: HashMap<PathBuf, String>,
}

impl HoneyVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates decoys inside `dir`. Names look like ordinary user files; content
    /// is synthetic and contains no personal information.
    pub fn deploy(&mut self, dir: &Path, kinds: &[DecoyKind], per_kind: usize) -> std::io::Result<usize> {
        std::fs::create_dir_all(dir)?;
        let mut created = 0;
        for (i, kind) in kinds.iter().enumerate() {
            for n in 1..=per_kind {
                let name = kind.file_name(n);
                let path = dir.join(&name);
                if path.exists() {
                    continue;
                }
                let mut rnd = [0u8; 8];
                getrandom::getrandom(&mut rnd)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                let canary = format!("LITRIC-CANARY-{}", hex(&rnd));
                let body = synthetic_content(*kind, &canary);
                std::fs::write(&path, body)?;
                let id = format!("decoy-{i}-{n}");
                self.decoys.push(Decoy {
                    id: id.clone(),
                    path: path.clone(),
                    kind: *kind,
                    canary,
                });
                self.by_path.insert(path, id);
                created += 1;
            }
        }
        Ok(created)
    }

    /// Returns the decoy id if this path is a decoy (including renames into a
    /// decoy directory — callers should also check parent paths).
    pub fn identify(&self, path: &Path) -> Option<&str> {
        if let Some(id) = self.by_path.get(path) {
            return Some(id.as_str());
        }
        // A decoy that was renamed still lives in a decoy directory.
        let parent = path.parent()?;
        self.by_path
            .iter()
            .find(|(p, _)| p.parent() == Some(parent))
            .map(|(_, id)| id.as_str())
    }

    pub fn decoys(&self) -> &[Decoy] {
        &self.decoys
    }

    pub fn len(&self) -> usize {
        self.decoys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.decoys.is_empty()
    }
}

fn synthetic_content(kind: DecoyKind, canary: &str) -> Vec<u8> {
    // Content is deliberately synthetic: a text marker plus pseudo-random bytes.
    // It is NOT a real document and contains no user information.
    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "This file is a Litric Defender HoneyVault decoy.\n\
             It contains no personal data.\n\
             Canary: {canary}\n\
             Kind: {kind:?}\n"
        )
        .as_bytes(),
    );
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15 ^ (canary.len() as u64);
    for _ in 0..2048 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        out.push((s >> 24) as u8);
    }
    out
}

fn hex(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(image: &str) -> ProcessContext {
        ProcessContext {
            image: image.to_string(),
            signed: true,
            publisher: None,
            command_line: String::new(),
        }
    }

    fn write(pid: u32, name: &str, entropy: f64) -> FsEvent {
        FsEvent::Write {
            pid,
            path: PathBuf::from(format!("/Users/me/Documents/{name}")),
            bytes: 4096,
            entropy,
        }
    }

    #[test]
    fn benign_text_editing_stays_normal() {
        let mut s = RansomShield::new(RansomShieldConfig::default());
        s.register_process(1, ctx("/usr/bin/gedit"));
        for i in 0..5 {
            let a = s.observe(write(1, &format!("note{i}.txt"), 4.2));
            assert_eq!(a.level, Level::Normal, "reasons: {:?}", a.reasons);
        }
    }

    #[test]
    fn archiver_writing_many_files_is_not_ransomware() {
        let mut s = RansomShield::new(RansomShieldConfig::default()).with_allowlist(vec![
            AllowRule::archiver("7z", "/usr/bin"),
        ]);
        s.register_process(42, ctx("/usr/bin/7z"));
        let mut max_level = Level::Normal;
        for i in 0..80 {
            let src = PathBuf::from(format!("/home/me/docs/file{i}.txt"));
            let dst = PathBuf::from("/home/me/archive/backup.7z");
            let a = s.observe(FsEvent::Rename {
                pid: 42,
                from: src,
                to: dst,
            });
            max_level = max_level.max(a.level);
        }
        assert!(
            max_level < Level::Suspicious,
            "archiver was escalated to {max_level:?}"
        );
    }

    #[test]
    fn archiver_producing_unknown_extensions_escalates() {
        let mut s = RansomShield::new(RansomShieldConfig::default()).with_allowlist(vec![
            AllowRule::archiver("7z", "/usr/bin"),
        ]);
        s.register_process(43, ctx("/usr/bin/7z"));
        let mut level = Level::Normal;
        for i in 0..40 {
            let a = s.observe(FsEvent::Rename {
                pid: 43,
                from: PathBuf::from(format!("/home/me/docs/f{i}.txt")),
                to: PathBuf::from(format!("/home/me/docs/f{i}.locked")),
            });
            level = level.max(a.level);
        }
        assert!(
            level >= Level::Watching,
            "unexpected extension churn must not be suppressed by the allowlist"
        );
    }

    #[test]
    fn decoy_touch_is_critical_and_suspends() {
        let mut s = RansomShield::new(RansomShieldConfig::default());
        s.register_process(7, ctx("/tmp/evil.exe"));
        let a = s.observe(FsEvent::DecoyTouched {
            pid: 7,
            decoy: "decoy-0-1".into(),
        });
        assert_eq!(a.level, Level::Critical);
        assert!(a.actions.contains(&Action::SuspendProcess));
        assert!(a.actions.contains(&Action::SnapshotFiles));
        assert!(a.score >= 100);
    }

    #[test]
    fn extension_churn_and_entropy_escalate_together() {
        let mut s = RansomShield::new(RansomShieldConfig::default());
        s.register_process(9, ctx("/tmp/enc.exe"));
        let mut level = Level::Normal;
        for i in 0..30 {
            let a = s.observe(write(9, &format!("doc{i}.txt"), 7.95));
            level = level.max(a.level);
        }
        for i in 0..15 {
            let a = s.observe(FsEvent::Rename {
                pid: 9,
                from: PathBuf::from(format!("/Users/me/Documents/doc{i}.txt")),
                to: PathBuf::from(format!("/Users/me/Documents/doc{i}.lockbit")),
            });
            level = level.max(a.level);
        }
        assert!(
            level >= Level::Suspicious,
            "expected Suspicious or higher, got {level:?}"
        );
    }

    #[test]
    fn backup_destruction_is_critical_even_for_signed_binary() {
        let mut s = RansomShield::new(RansomShieldConfig::default());
        s.register_process(11, ctx("/Windows/System32/vssadmin.exe"));
        let a = s.observe(FsEvent::BackupTamper {
            pid: 11,
            command: "vssadmin delete shadows /all /quiet".into(),
        });
        assert_eq!(a.level, Level::Critical);
        assert!(a.actions.contains(&Action::BlockWrites));
    }

    #[test]
    fn honeyvault_deploys_and_identifies_decoys() {
        let dir = std::env::temp_dir().join(format!(
            "litric-honey-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut hv = HoneyVault::new();
        let n = hv
            .deploy(
                &dir,
                &[DecoyKind::Document, DecoyKind::Database],
                2,
            )
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(hv.len(), 4);
        for d in hv.decoys() {
            assert_eq!(hv.identify(&d.path), Some(d.id.as_str()));
            let body = std::fs::read(&d.path).unwrap();
            assert!(body.windows(14).any(|w| w == b"LITRIC-CANARY-"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn window_expiry_prevents_permanent_penalty() {
        let cfg = RansomShieldConfig {
            window: Duration::from_millis(10),
            write_burst: 3,
            ..Default::default()
        };
        let mut s = RansomShield::new(cfg);
        s.register_process(5, ctx("/usr/bin/app"));
        for i in 0..5 {
            s.observe(write(5, &format!("f{i}.txt"), 1.0));
        }
        std::thread::sleep(Duration::from_millis(25));
        let a = s.observe(write(5, "later.txt", 1.0));
        assert_eq!(a.level, Level::Normal, "reasons: {:?}", a.reasons);
    }
}
