//! Litric Defender local API backend.
//!
//! Architecture: the Windows UI (or any local client) talks to a loopback-only
//! HTTP/JSON API. The API owns no detection logic — it drives `litric-core`
//! which is the same code the CLI uses and the same code the test suite covers.
//!
//! Security posture of this backend:
//!
//! * **Loopback only.** The listener binds 127.0.0.1 and rejects any peer that
//!   is not a loopback address, so a misconfigured bind cannot expose the
//!   control plane to the network.
//! * **Bearer token.** A 32-byte random token is generated on first run into a
//!   0600 file. Comparison is constant-time. Every route except `/health`
//!   requires it, so a hostile local process cannot drive scans or restore
//!   quarantined malware without reading the file.
//! * **Bounded bodies.** Requests are capped at 1 MiB; over-long bodies are
//!   rejected before parsing.
//! * **No arbitrary execution.** Paths are canonicalised and must exist; the
//!   API never accepts a command line.
//! * **Honest status.** `/status` derives capabilities from what is actually
//!   implemented and reports `limited`, never `protected`, on a host without a
//!   kernel sensor.

pub mod api;
pub mod jobs;
pub mod server;
pub mod store;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use litric_core::engine::Engine;
use litric_core::quarantine::QuarantineVault;
use litric_core::ranshield::RansomShield;
use litric_safeos::model::HostFacts;

use crate::jobs::JobManager;
use crate::store::Store;

/// Shared, thread-safe service state.
pub struct AppState {
    pub engine: Arc<Engine>,
    pub vault: Arc<QuarantineVault>,
    pub jobs: Arc<JobManager>,
    pub store: Arc<Mutex<Store>>,
    pub ranshield: Arc<Mutex<RansomShield>>,
    /// Last facts reported by the platform agent. `None` means "not collected",
    /// which SafeOS treats as every backend unavailable.
    pub host_facts: Mutex<Option<HostFacts>>,
    pub token: String,
    pub data_dir: PathBuf,
    pub started: Instant,
    /// True when the caller asked for real-time protection (policy), not when it
    /// is actually running. Capability probes live in `api::status_json`.
    pub realtime_requested: bool,
}

impl AppState {
    pub fn new(
        engine: Engine,
        vault: QuarantineVault,
        data_dir: &Path,
        token: String,
    ) -> std::io::Result<Arc<AppState>> {
        let store = Store::open(data_dir)?;
        let realtime_requested = store.settings.realtime_requested;
        Ok(Arc::new(AppState {
            engine: Arc::new(engine),
            vault: Arc::new(vault),
            jobs: Arc::new(JobManager::new()),
            store: Arc::new(Mutex::new(store)),
            ranshield: Arc::new(Mutex::new(RansomShield::new(Default::default()))),
            host_facts: Mutex::new(None),
            token,
            data_dir: data_dir.to_path_buf(),
            started: Instant::now(),
            realtime_requested,
        }))
    }
}

/// Loads the API token, creating a 32-byte random one on first run.
pub fn load_or_create_token(path: &Path) -> std::io::Result<String> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let t = existing.trim().to_string();
        if t.len() >= 32 {
            return Ok(t);
        }
    }
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| std::io::Error::other(e.to_string()))?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{token}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(token)
}

/// Constant-time string comparison for the bearer token.
///
/// Length is compared first (not secret in a meaningful sense for a 64-char hex
/// token), then bytes with a fixed accumulator so timing does not leak the
/// matching prefix length.
pub fn token_matches(expected: &str, provided: &str) -> bool {
    let a = expected.as_bytes();
    let b = provided.as_bytes();
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison_is_exact() {
        assert!(token_matches("abc123", "abc123"));
        assert!(!token_matches("abc123", "abc124"));
        assert!(!token_matches("abc123", "abc12"));
        assert!(!token_matches("", ""));
    }

    #[test]
    fn token_file_is_created_once_and_reused() {
        let dir = std::env::temp_dir().join(format!(
            "litric-token-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let path = dir.join("api.token");
        let a = load_or_create_token(&path).unwrap();
        let b = load_or_create_token(&path).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
