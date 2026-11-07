//! Litric RansomShield core.
//!
//! Platform-independent behavioral analysis. The Windows front-ends
//! (ETW / file-change watchers / later a minifilter) only translate OS
//! activity into `FileEvent`s and feed them to `Engine`. Nothing here
//! touches the OS, so it is fully unit-testable.
//!
//! Decisions are multi-signal and explainable: every verdict carries
//! the evidence that produced it. No single weak signal can block.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

/// Shannon entropy in bits/byte (0.0 ..= 8.0). Empty input => 0.0.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileOp {
    /// Content written. `entropy_before` is None when unknown (new file).
    Write { entropy_before: Option<f64>, entropy_after: f64 },
    Rename { new_ext: String },
    Delete,
    Create,
}

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub pid: u32,
    pub image: String, // process image path
    pub path: String,
    pub op: FileOp,
    /// Milliseconds on a monotonic clock.
    pub t_ms: u64,
}

/// Something that touches shadow copies / backups (vssadmin delete, etc).
#[derive(Debug, Clone)]
pub struct BackupTamperEvent {
    pub pid: u32,
    pub image: String,
    pub t_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Verified trusted or nothing notable.
    Allow,
    /// Weak anomaly: log only.
    Observe,
    /// Strongly suspicious: protect more, alert user.
    Suspicious,
    /// Credible ransomware: contain (suspend process).
    Contain,
}

#[derive(Debug, Clone)]
pub struct Assessment {
    pub pid: u32,
    pub score: u32,
    pub verdict: Verdict,
    /// Human-readable evidence, one line per contributing signal.
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub window: Duration,
    /// Files touched per window before volume signals fire.
    pub bulk_threshold: usize,
    pub high_entropy: f64,
    pub entropy_jump: f64,
    pub observe_at: u32,
    pub suspicious_at: u32,
    pub contain_at: u32,
    /// Lowercase image paths the user/policy marked as trusted
    /// (e.g. backup tool, archiver). Trusted processes are never
    /// contained, but canary hits are still recorded as evidence.
    pub trusted_images: HashSet<String>,
    /// Extensions commonly appended by ransomware (lowercase, no dot).
    pub suspicious_exts: HashSet<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10),
            bulk_threshold: 20,
            high_entropy: 7.5,
            entropy_jump: 2.5,
            observe_at: 20,
            suspicious_at: 50,
            contain_at: 80,
            trusted_images: HashSet::new(),
            suspicious_exts: ["locked", "encrypted", "enc", "crypt", "crypted", "lockbit", "ryk"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

#[derive(Default)]
struct ProcState {
    image: String,
    events: VecDeque<FileEvent>,
    canary_hits: HashSet<String>,
    backup_tamper: bool,
}

pub struct Engine {
    cfg: Config,
    procs: HashMap<u32, ProcState>,
    canaries: HashSet<String>,
}

impl Engine {
    pub fn new(cfg: Config) -> Self {
        Self { cfg, procs: HashMap::new(), canaries: HashSet::new() }
    }

    /// Register decoy (HoneyVault) file paths. Legit software has no
    /// reason to modify them, so a write/rename/delete is high-signal.
    pub fn add_canary(&mut self, path: &str) {
        self.canaries.insert(norm(path));
    }

    pub fn on_backup_tamper(&mut self, ev: BackupTamperEvent) -> Assessment {
        let st = self.procs.entry(ev.pid).or_default();
        st.image = ev.image;
        st.backup_tamper = true;
        self.assess(ev.pid, ev.t_ms)
    }

    pub fn on_file_event(&mut self, ev: FileEvent) -> Assessment {
        let (pid, now) = (ev.pid, ev.t_ms);
        let win = self.cfg.window.as_millis() as u64;
        let is_canary = self.canaries.contains(&norm(&ev.path));
        let st = self.procs.entry(pid).or_default();
        st.image = ev.image.clone();
        if is_canary && !matches!(ev.op, FileOp::Create) {
            st.canary_hits.insert(norm(&ev.path));
        }
        st.events.push_back(ev);
        while st.events.front().map_or(false, |e| now.saturating_sub(e.t_ms) > win) {
            st.events.pop_front();
        }
        self.assess(pid, now)
    }

    /// Forget a process (call on process exit).
    pub fn on_process_exit(&mut self, pid: u32) {
        self.procs.remove(&pid);
    }

    fn assess(&self, pid: u32, _now: u64) -> Assessment {
        let st = &self.procs[&pid];
        let mut score = 0u32;
        let mut evidence = Vec::new();

        let mut touched: HashSet<&str> = HashSet::new();
        let (mut hi_ent, mut jumps, mut renames, mut deletes) = (0usize, 0usize, 0usize, 0usize);
        let mut sus_ext = 0usize;
        for e in &st.events {
            touched.insert(e.path.as_str());
            match &e.op {
                FileOp::Write { entropy_before, entropy_after } => {
                    if *entropy_after >= self.cfg.high_entropy {
                        hi_ent += 1;
                        if let Some(b) = entropy_before {
                            if entropy_after - b >= self.cfg.entropy_jump {
                                jumps += 1;
                            }
                        }
                    }
                }
                FileOp::Rename { new_ext } => {
                    renames += 1;
                    if self.cfg.suspicious_exts.contains(&new_ext.to_lowercase()) {
                        sus_ext += 1;
                    }
                }
                FileOp::Delete => deletes += 1,
                FileOp::Create => {}
            }
        }
        let bulk = touched.len() >= self.cfg.bulk_threshold;

        if bulk {
            score += 15;
            evidence.push(format!("{} distinct files touched in {}s window", touched.len(), self.cfg.window.as_secs()));
        }
        // Entropy alone is NOT enough (archivers/media produce it too).
        if hi_ent >= 5 {
            score += 15;
            evidence.push(format!("{hi_ent} writes produced high-entropy content (>= {:.1})", self.cfg.high_entropy));
        }
        // Existing low-entropy files turning into random data is the real tell.
        if jumps >= 5 {
            score += 30;
            evidence.push(format!("{jumps} existing files jumped to high entropy (encryption pattern)"));
        }
        if sus_ext >= 3 {
            score += 25;
            evidence.push(format!("{sus_ext} renames to known ransomware-style extensions"));
        } else if renames >= self.cfg.bulk_threshold {
            score += 10;
            evidence.push(format!("{renames} bulk renames"));
        }
        if deletes >= self.cfg.bulk_threshold {
            score += 10;
            evidence.push(format!("{deletes} bulk deletions"));
        }
        if !st.canary_hits.is_empty() {
            score += 40;
            evidence.push(format!("{} HoneyVault decoy file(s) modified", st.canary_hits.len()));
        }
        if st.backup_tamper {
            score += 35;
            evidence.push("attempted to delete/disable backups or shadow copies".into());
        }

        // Correlation: independent strong signal classes together are far
        // more credible than any one alone.
        let strong = [
            jumps >= 5,
            sus_ext >= 3,
            !st.canary_hits.is_empty(),
            st.backup_tamper,
        ]
        .iter()
        .filter(|&&b| b)
        .count();
        if strong >= 2 {
            score += 15;
            evidence.push(format!("{strong} independent strong signals correlate"));
        }

        let trusted = self.cfg.trusted_images.contains(&st.image.to_lowercase());
        let mut verdict = if score >= self.cfg.contain_at {
            Verdict::Contain
        } else if score >= self.cfg.suspicious_at {
            Verdict::Suspicious
        } else if score >= self.cfg.observe_at {
            Verdict::Observe
        } else {
            Verdict::Allow
        };
        if trusted && verdict > Verdict::Observe {
            verdict = Verdict::Observe;
            evidence.push("process is on the trusted list: containment withheld, kept as evidence".into());
        }
        Assessment { pid, score, verdict, evidence }
    }
}

fn norm(p: &str) -> String {
    p.replace('/', "\\").to_lowercase()
}
