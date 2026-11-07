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
//!   file under the data directory. Comparison is constant-time. Every route
//!   except `/health` requires it, so a hostile local process cannot drive scans
//!   or restore quarantined malware without reading the file. The service data
//!   directory is DACL-hardened at startup, and local CLI vaults are hardened by
//!   the CLI before use (`litric_core::winplatform::acl`).
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
#[cfg(windows)]
pub mod winsvc;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use litric_core::engine::Engine;
use litric_core::quarantine::QuarantineVault;
use litric_core::ranshield::RansomShield;
use litric_safeos::model::HostFacts;

use crate::jobs::JobManager;
use crate::store::Store;

/// Result of asking the platform to validate an Authenticode chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureTrust {
    /// WinVerifyTrust accepted the chain to a trusted root.
    Valid,
    /// A signature is present but the chain is invalid, untrusted, or tampered.
    Invalid,
    /// Verification could not be performed (for example, the file type is not
    /// supported by the platform verifier). Never treated as trusted.
    Unverified,
}

impl SignatureTrust {
    pub fn is_valid(self) -> bool {
        self == SignatureTrust::Valid
    }
}

/// The platform trust boundary for Authenticode chain validation.
///
/// `safeos_assess` consumes this trait rather than inventing a trust result. The
/// production implementation calls WinVerifyTrust; tests inject a deterministic
/// verifier so the allowlist decision path remains testable.
pub trait SignatureVerifier: Send + Sync {
    fn verify(&self, path: &Path) -> SignatureTrust;
}

/// Production verifier: WinVerifyTrust on Windows, unavailable elsewhere.
pub struct PlatformSignatureVerifier;

impl SignatureVerifier for PlatformSignatureVerifier {
    fn verify(&self, path: &Path) -> SignatureTrust {
        platform_signature_trust(path)
    }
}

fn platform_signature_trust(path: &Path) -> SignatureTrust {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: ptr::null_mut(),
        pSIPClientData: ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: ptr::null_mut(),
        pwszURLReference: ptr::null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: ptr::null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // WinVerifyTrust returns 0 only when the policy provider accepts the chain.
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };
    // Always release the provider state allocated by the VERIFY call.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        );
    }

    if status == 0 {
        SignatureTrust::Valid
    } else {
        SignatureTrust::Invalid
    }
}

/// Shared, thread-safe service state.
pub struct AppState {
    pub engine: Arc<Engine>,
    pub vault: Arc<QuarantineVault>,
    pub jobs: Arc<JobManager>,
    pub store: Arc<Mutex<Store>>,
    pub ranshield: Arc<Mutex<RansomShield>>,
    /// Platform Authenticode verifier used by `safeos_assess` and related paths.
    pub signature_verifier: Arc<dyn SignatureVerifier>,
    /// Last facts reported by the platform agent. `None` means "not collected",
    /// which SafeOS treats as every backend unavailable.
    pub host_facts: Mutex<Option<HostFacts>>,
    pub token: String,
    pub data_dir: PathBuf,
    /// Process gate, when the operator enabled one. `None` means the gate is
    /// not running and the API must say so instead of implying protection.
    pub process_gate: Mutex<Option<Arc<processgate::GateHandle>>>,
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
        Self::new_with_verifier(
            engine,
            vault,
            data_dir,
            token,
            Arc::new(PlatformSignatureVerifier),
        )
    }

    /// Constructs state with an explicit signature verifier. Production callers
    /// use `new`; tests use this to exercise both trust outcomes deterministically.
    pub fn new_with_verifier(
        engine: Engine,
        vault: QuarantineVault,
        data_dir: &Path,
        token: String,
        signature_verifier: Arc<dyn SignatureVerifier>,
    ) -> std::io::Result<Arc<AppState>> {
        let store = Store::open(data_dir)?;
        let realtime_requested = store.settings.realtime_requested;
        Ok(Arc::new(AppState {
            engine: Arc::new(engine),
            vault: Arc::new(vault),
            jobs: Arc::new(JobManager::new()),
            store: Arc::new(Mutex::new(store)),
            ranshield: Arc::new(Mutex::new(RansomShield::new(Default::default()))),
            signature_verifier,
            host_facts: Mutex::new(None),
            token,
            data_dir: data_dir.to_path_buf(),
            process_gate: Mutex::new(None),
            started: Instant::now(),
            realtime_requested,
        }))
    }

    /// Attaches a running process gate to this state.
    pub fn set_process_gate(&self, handle: Arc<processgate::GateHandle>) {
        let mut guard = self
            .process_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(handle);
    }

    /// The gate handle, if one is running.
    pub fn process_gate(&self) -> Option<Arc<processgate::GateHandle>> {
        self.process_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
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
