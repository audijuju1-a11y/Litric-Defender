//! Assembles the real-time defense. All logic here is platform-independent
//! and covered by an end-to-end test; only the OS event sources and the
//! process-suspend action live in `realtime::windows`.

use honeyvault::{Decoy, Tamper};
use ransomshield::{Config, Engine};
use realtime::{Containment, FsSampler, EntropySampler, Incident, Pipeline, RawEvent, RawKind};
use recovery::{Report, Vault};
use std::path::{Path, PathBuf};
use std::sync::{atomic::Ordering, Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod supervisor;

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub struct ServiceConfig {
    pub protected_dirs: Vec<PathBuf>,
    pub vault_dir: PathBuf,
    /// Images (full path) that must never be auto-contained, e.g. backup tools.
    pub trusted_images: Vec<String>,
    pub queue_cap: usize,
}

#[derive(Debug)]
pub struct Status {
    /// True when events were lost or a decoy was tampered/missing.
    pub degraded: bool,
    pub dropped: u64,
    pub contained: u64,
    pub incidents: usize,
    pub decoy_tamper: Vec<Tamper>,
    pub snapshot_errors: usize,
}

/// Pause snapshots this long after any new incident, so the vault is not
/// filled with already-encrypted versions while an attack is unfolding.
pub const FREEZE_MS: u64 = 10 * 60 * 1000;
/// Every Nth tick is a full pass (defeats mtime timestomping).
pub const FULL_EVERY: u64 = 12;

#[derive(Debug)]
pub enum Tick {
    /// Snapshots paused until the given time because of recent incidents.
    Frozen { until_ms: u64 },
    Done(Report),
}

#[derive(Default)]
struct TickState {
    last_ms: u64,
    ticks: u64,
    seen_incidents: usize,
    frozen_until: u64,
}

pub struct Defender {
    pub pipeline: Arc<Pipeline>,
    pub vault: Vault,
    pub decoys: Vec<Decoy>,
    snapshot: Report,
    dirs: Vec<PathBuf>,
    tick: Mutex<TickState>,
}

impl Defender {
    pub fn start(cfg: ServiceConfig, containment: Box<dyn Containment>) -> std::io::Result<Self> {
        let vault = Vault::open(&cfg.vault_dir)?;
        let mut ecfg = Config::default();
        ecfg.trusted_images.extend(cfg.trusted_images.iter().map(|s| s.to_lowercase()));
        let mut engine = Engine::new(ecfg);

        let mut decoys = vec![];
        let mut snapshot = Report::default();
        for d in &cfg.protected_dirs {
            let ds = honeyvault::deploy(d)?;
            for x in &ds {
                engine.add_canary(&x.path.to_string_lossy());
            }
            decoys.extend(ds);
            let r = vault.snapshot_tree(d, now_ms())?;
            snapshot.stored += r.stored;
            snapshot.unchanged += r.unchanged;
            snapshot.errors.extend(r.errors);
        }

        let start_ms = now_ms();
        let pipeline = Arc::new(Pipeline::start(engine, Box::new(FsSampler), containment, cfg.queue_cap));
        // Known-good entropy baseline: without it the first write to each
        // file has no "before" value and the encryption jump is invisible.
        let mut sampler = FsSampler;
        for d in &cfg.protected_dirs {
            baseline(d, 0, &mut sampler, &pipeline);
        }
        let tick = Mutex::new(TickState { last_ms: start_ms, ..Default::default() });
        Ok(Self { pipeline, vault, decoys, snapshot, dirs: cfg.protected_dirs.clone(), tick })
    }

    /// Periodic snapshot. Call every few minutes. New/changed files get
    /// versioned; frozen after any new incident so attack-time (possibly
    /// encrypted) content cannot crowd out good versions.
    pub fn tick(&self, now: u64) -> std::io::Result<Tick> {
        let mut st = self.tick.lock().unwrap();
        let incidents = self.pipeline.incidents.lock().unwrap().len();
        if incidents > st.seen_incidents {
            st.seen_incidents = incidents;
            st.frozen_until = now + FREEZE_MS;
        }
        if now < st.frozen_until {
            return Ok(Tick::Frozen { until_ms: st.frozen_until });
        }
        st.ticks += 1;
        let full = st.ticks % FULL_EVERY == 0;
        let mut total = Report::default();
        for d in &self.dirs {
            let r = if full {
                self.vault.snapshot_tree(d, now)?
            } else {
                self.vault.snapshot_tree_incremental(d, now, st.last_ms)?
            };
            total.stored += r.stored;
            total.unchanged += r.unchanged;
            total.errors.extend(r.errors);
        }
        st.last_ms = now;
        Ok(Tick::Done(total))
    }

    pub fn feed(&self, ev: RawEvent) {
        self.pipeline.submit(ev);
    }

    pub fn status(&self) -> Status {
        let s = &self.pipeline.stats;
        let decoy_tamper = honeyvault::check(&self.decoys);
        let dropped = s.dropped.load(Ordering::Relaxed);
        Status {
            degraded: dropped > 0 || !decoy_tamper.is_empty() || !self.snapshot.errors.is_empty(),
            dropped,
            contained: s.contained.load(Ordering::Relaxed),
            incidents: self.pipeline.incidents.lock().unwrap().len(),
            decoy_tamper,
            snapshot_errors: self.snapshot.errors.len(),
        }
    }

    /// Stop and return all incidents. Only valid when no source thread
    /// still holds the pipeline.
    pub fn stop(self) -> Vec<Incident> {
        let incidents = self.pipeline.incidents.clone();
        if let Ok(p) = Arc::try_unwrap(self.pipeline) {
            p.shutdown();
        }
        let v = incidents.lock().unwrap().clone();
        v
    }
}

fn baseline(dir: &Path, depth: usize, s: &mut dyn EntropySampler, p: &Pipeline) {
    if depth > 32 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        let path = e.path();
        if ft.is_symlink() {
            continue;
        } else if ft.is_dir() {
            baseline(&path, depth + 1, s, p);
        } else if ft.is_file() {
            let ps = path.to_string_lossy().to_string();
            if let Some(entropy) = s.sample(&ps) {
                p.submit(RawEvent { pid: 0, image: String::new(), path: ps, kind: RawKind::Baseline { entropy }, t_ms: 0 });
            }
        }
    }
}
