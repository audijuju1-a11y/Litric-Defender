//! Litric real-time pipeline.
//!
//! Sources (OS watchers) push `RawEvent`s into a bounded queue. A worker
//! converts them to RansomShield events, tracks last-known entropy per
//! file, and triggers containment through the `Containment` trait.
//!
//! Honest limits, enforced in code:
//!  * A source that cannot name the acting process reports `pid == 0`.
//!    Such activity can raise alerts but is NEVER contained.
//!  * The queue is bounded. Overflow drops events and is counted in
//!    `Stats::dropped`; callers must surface it as degraded protection.

use ransomshield::{Assessment, BackupTamperEvent, Engine, FileEvent, FileOp, Verdict};
use std::collections::HashMap;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;

pub mod tamper;
pub mod windows;

#[derive(Debug, Clone)]
pub enum RawKind {
    Created,
    Modified,
    Renamed { new_ext: String },
    Deleted,
    /// Shadow copy / backup destruction attempt (needs process-creation source).
    BackupTamper,
    /// Seed the known-good entropy of a file (no detection, no engine event).
    Baseline { entropy: f64 },
}

#[derive(Debug, Clone)]
pub struct RawEvent {
    /// 0 = unknown actor (e.g. ReadDirectoryChangesW cannot attribute).
    pub pid: u32,
    pub image: String,
    pub path: String,
    pub kind: RawKind,
    pub t_ms: u64,
}

/// Reads a file's entropy (sampled). Injected so tests need no disk.
pub trait EntropySampler: Send {
    fn sample(&mut self, path: &str) -> Option<f64>;
}

/// Response action. Real impl suspends the process on Windows.
pub trait Containment: Send {
    fn suspend(&mut self, pid: u32) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub assessment: Assessment,
    pub contained: bool,
    pub note: String,
}

#[derive(Default)]
pub struct Stats {
    pub received: AtomicU64,
    pub dropped: AtomicU64,
    pub processed: AtomicU64,
    pub contained: AtomicU64,
}

pub struct Pipeline {
    tx: Option<SyncSender<RawEvent>>,
    worker: Option<JoinHandle<()>>,
    pub stats: Arc<Stats>,
    pub incidents: Arc<Mutex<Vec<Incident>>>,
}

impl Pipeline {
    pub fn start(
        engine: Engine,
        sampler: Box<dyn EntropySampler>,
        containment: Box<dyn Containment>,
        queue_cap: usize,
    ) -> Self {
        let (tx, rx) = sync_channel::<RawEvent>(queue_cap);
        let stats = Arc::new(Stats::default());
        let incidents = Arc::new(Mutex::new(Vec::new()));
        let (s2, i2) = (stats.clone(), incidents.clone());
        let worker = std::thread::spawn(move || run(rx, engine, sampler, containment, s2, i2));
        Self { tx: Some(tx), worker: Some(worker), stats, incidents }
    }

    /// Non-blocking. Never stalls the OS-facing source thread.
    pub fn submit(&self, ev: RawEvent) {
        self.stats.received.fetch_add(1, Ordering::Relaxed);
        if let Some(tx) = &self.tx {
            if let Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) = tx.try_send(ev) {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Wait until every accepted event has been processed (tests/shutdown).
    pub fn wait_idle(&self, timeout: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        loop {
            let r = self.stats.received.load(Ordering::Relaxed);
            let d = self.stats.dropped.load(Ordering::Relaxed);
            if r - d == self.stats.processed.load(Ordering::Relaxed) {
                return true;
            }
            if start.elapsed() > timeout {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    /// True when events were lost: protection must be shown as degraded.
    pub fn degraded(&self) -> bool {
        self.stats.dropped.load(Ordering::Relaxed) > 0
    }

    /// Drain and stop. Returns when all queued events are processed.
    pub fn shutdown(mut self) {
        self.tx.take();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

fn run(
    rx: Receiver<RawEvent>,
    mut engine: Engine,
    mut sampler: Box<dyn EntropySampler>,
    mut cont: Box<dyn Containment>,
    stats: Arc<Stats>,
    incidents: Arc<Mutex<Vec<Incident>>>,
) {
    let mut last_entropy: HashMap<String, f64> = HashMap::new();
    let mut handled: std::collections::HashSet<u32> = Default::default();
    while let Ok(ev) = rx.recv() {
        if let RawKind::Baseline { entropy } = ev.kind {
            last_entropy.insert(ev.path, entropy);
            stats.processed.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let a = match ev.kind {
            RawKind::BackupTamper => engine.on_backup_tamper(BackupTamperEvent {
                pid: ev.pid,
                image: ev.image.clone(),
                t_ms: ev.t_ms,
            }),
            _ => {
                let op = match &ev.kind {
                    RawKind::Created => FileOp::Create,
                    RawKind::Deleted => {
                        last_entropy.remove(&ev.path);
                        FileOp::Delete
                    }
                    RawKind::Renamed { new_ext } => FileOp::Rename { new_ext: new_ext.clone() },
                    _ => {
                        let after = sampler.sample(&ev.path);
                        let before = last_entropy.get(&ev.path).copied();
                        match after {
                            Some(x) => {
                                last_entropy.insert(ev.path.clone(), x);
                                FileOp::Write { entropy_before: before, entropy_after: x }
                            }
                            // Unreadable (locked/denied): do not guess entropy.
                            None => FileOp::Create,
                        }
                    }
                };
                engine.on_file_event(FileEvent {
                    pid: ev.pid,
                    image: ev.image.clone(),
                    path: ev.path.clone(),
                    op,
                    t_ms: ev.t_ms,
                })
            }
        };
        stats.processed.fetch_add(1, Ordering::Relaxed);

        if a.verdict >= Verdict::Suspicious && !handled.contains(&a.pid) {
            let (mut contained, mut note) = (false, String::from("alert only"));
            if a.verdict == Verdict::Contain {
                if a.pid == 0 {
                    note = "credible ransomware activity but actor unknown: cannot contain".into();
                } else {
                    match cont.suspend(a.pid) {
                        Ok(()) => {
                            contained = true;
                            note = "process suspended".into();
                            stats.contained.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => note = format!("containment FAILED: {e}"),
                    }
                }
            }
            // One incident per escalation level per pid; contain wins.
            if contained || a.verdict == Verdict::Contain || a.verdict == Verdict::Suspicious {
                if a.verdict == Verdict::Contain {
                    handled.insert(a.pid);
                }
                incidents.lock().unwrap().push(Incident { assessment: a, contained, note });
            }
        }
    }
}

/// Samples the first 64 KiB of a file and returns its Shannon entropy.
/// Returns None if the file cannot be read (locked/denied): callers must
/// not guess in that case.
pub struct FsSampler;
impl EntropySampler for FsSampler {
    fn sample(&mut self, path: &str) -> Option<f64> {
        use std::io::Read;
        let mut f = std::fs::File::open(path).ok()?;
        let mut buf = vec![0u8; 64 * 1024];
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        Some(ransomshield::shannon_entropy(&buf[..n]))
    }
}
