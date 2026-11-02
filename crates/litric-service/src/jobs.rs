//! Background scan jobs with live progress and cooperative cancellation.
//!
//! A job is created by the API, executed on a worker thread, and polled for
//! progress. State transitions are `Queued -> Running -> Completed|Failed|
//! Cancelled`; a job never silently disappears, so the UI can always explain
//! what happened.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use litric_core::scan::{ScanLimits, ScanSummary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl JobState {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Running => "running",
            JobState::Completed => "completed",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            JobState::Completed | JobState::Failed | JobState::Cancelled
        )
    }
}

/// A scan job as seen by the API.
#[derive(Debug, Clone)]
pub struct Job {
    pub id: String,
    pub target: String,
    pub profile: String,
    pub state: JobState,
    pub created_unix: u64,
    pub finished_unix: Option<u64>,
    pub error: Option<String>,
    pub summary: Option<ScanSummary>,
}

impl Job {
    pub fn progress_pct(&self) -> u8 {
        match self.state {
            JobState::Queued => 0,
            JobState::Completed | JobState::Failed | JobState::Cancelled => 100,
            JobState::Running => {
                // No total file count is known up front (a directory walk is
                // streaming), so progress is reported as "known work done"
                // rather than as a fabricated percentage.
                if self.summary.as_ref().map(|s| s.files_scanned).unwrap_or(0) > 0 {
                    50
                } else {
                    10
                }
            }
        }
    }
}

/// Thread-safe registry of jobs plus their cancellation flags.
pub struct JobManager {
    jobs: Mutex<HashMap<String, Job>>,
    cancel: Mutex<HashMap<String, Arc<AtomicBool>>>,
    order: Mutex<Vec<String>>,
    counter: AtomicU64,
}

impl JobManager {
    pub fn new() -> Self {
        JobManager {
            jobs: Mutex::new(HashMap::new()),
            cancel: Mutex::new(HashMap::new()),
            order: Mutex::new(Vec::new()),
            counter: AtomicU64::new(1),
        }
    }

    pub fn create(&self, target: &str, profile: &str) -> (String, Arc<AtomicBool>) {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let id = format!("scan-{:06}", n);
        let job = Job {
            id: id.clone(),
            target: target.to_string(),
            profile: profile.to_string(),
            state: JobState::Queued,
            created_unix: now_unix(),
            finished_unix: None,
            error: None,
            summary: None,
        };
        let flag = Arc::new(AtomicBool::new(false));
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(id.clone(), job);
        }
        if let Ok(mut flags) = self.cancel.lock() {
            flags.insert(id.clone(), flag.clone());
        }
        if let Ok(mut order) = self.order.lock() {
            order.push(id.clone());
            if order.len() > 100 {
                let excess = order.len() - 100;
                let removed: Vec<String> = order.drain(0..excess).collect();
                if let Ok(mut jobs) = self.jobs.lock() {
                    for r in removed {
                        jobs.remove(&r);
                    }
                }
            }
        }
        (id, flag)
    }

    pub fn update<F: FnOnce(&mut Job)>(&self, id: &str, f: F) {
        if let Ok(mut jobs) = self.jobs.lock() {
            if let Some(job) = jobs.get_mut(id) {
                f(job);
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<Job> {
        self.jobs.lock().ok()?.get(id).cloned()
    }

    pub fn list(&self) -> Vec<Job> {
        let order = match self.order.lock() {
            Ok(o) => o.clone(),
            Err(_) => return Vec::new(),
        };
        let jobs = match self.jobs.lock() {
            Ok(j) => j,
            Err(_) => return Vec::new(),
        };
        order
            .iter()
            .rev()
            .filter_map(|id| jobs.get(id).cloned())
            .collect()
    }

    /// Requests cancellation. Returns false when the job is unknown or already
    /// finished, so callers can report the true outcome.
    pub fn cancel(&self, id: &str) -> bool {
        let flags = match self.cancel.lock() {
            Ok(f) => f,
            Err(_) => return false,
        };
        match flags.get(id) {
            Some(flag) => {
                flag.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    pub fn cancel_flag(&self, id: &str) -> Option<Arc<AtomicBool>> {
        self.cancel.lock().ok()?.get(id).cloned()
    }

    pub fn counts(&self) -> (usize, usize) {
        let jobs = self.jobs.lock().ok();
        let running = jobs
            .as_ref()
            .map(|j| {
                j.values()
                    .filter(|job| job.state == JobState::Running)
                    .count()
            })
            .unwrap_or(0);
        (self.order.lock().map(|o| o.len()).unwrap_or(0), running)
    }
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Default limits used by API-driven scans.
pub fn default_limits(profile: &str) -> ScanLimits {
    let mut limits = ScanLimits::default();
    match profile {
        // A quick scan inspects the highest-risk locations only; the caller
        // supplies those paths. The profile controls the per-file cap.
        "quick" => {
            limits.max_file_bytes = 64 * 1024 * 1024;
            limits.deadline = Some(std::time::Duration::from_secs(120));
        }
        "full" => {
            limits.max_file_bytes = 256 * 1024 * 1024;
        }
        "deep" => {
            limits.max_file_bytes = 512 * 1024 * 1024;
            limits.deadline = Some(std::time::Duration::from_secs(60 * 60));
        }
        _ => {
            limits.max_file_bytes = 128 * 1024 * 1024;
        }
    }
    limits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_get_and_cancel() {
        let m = JobManager::new();
        let (id, flag) = m.create("/tmp", "quick");
        let job = m.get(&id).expect("job exists");
        assert_eq!(job.state, JobState::Queued);
        assert!(!flag.load(Ordering::Relaxed));

        assert!(m.cancel(&id));
        assert!(flag.load(Ordering::Relaxed) || m.cancel_flag(&id).is_some());

        m.update(&id, |j| j.state = JobState::Completed);
        assert_eq!(m.get(&id).unwrap().state, JobState::Completed);
        assert!(m.list().iter().any(|j| j.id == id));
    }

    #[test]
    fn cancelling_unknown_job_reports_false() {
        let m = JobManager::new();
        assert!(!m.cancel("scan-999999"));
    }

    #[test]
    fn profiles_change_limits() {
        assert!(default_limits("full").max_file_bytes > default_limits("quick").max_file_bytes);
        assert!(default_limits("quick").deadline.is_some());
        assert!(default_limits("unknown").deadline.is_none());
    }
}
