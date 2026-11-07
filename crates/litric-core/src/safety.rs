//! Litric Safety Guard — the single gate in front of every destructive file
//! operation.
//!
//! The product goal is "never damage the user's machine", so every path that can
//! remove or overwrite user data is forced through this module:
//!
//! * **Protected locations** (Windows system directories, Program Files,
//!   ProgramData, the user-profile root, the boot/recovery trees, the Litric
//!   policy and audit files themselves) can never be removed, renamed or written
//!   over. This is checked against the *canonical* path, not the string the
//!   caller supplied.
//! * **Scope.** A removal is only permitted for the exact object the caller was
//!   authorised to act on, or below the directory the user explicitly asked to
//!   scan. A relative path, a `..` segment or a symlink cannot escape it.
//! * **Digest re-verification.** Before the unlink, the file is hashed again and
//!   compared with the digest the scanner classified. A file swapped between
//!   scan and quarantine is refused.
//! * **Removal budget.** At most `max_removals_per_minute` files and
//!   `max_removal_bytes_per_minute` bytes may be authorised in a rolling
//!   minute. A bug, a runaway loop or a compromised caller cannot wipe a disk.
//! * **Append-only, hash-chained audit.** Every allowed removal, every refusal
//!   and every outcome is written with `prev`/`hash` fields. Deleting or editing
//!   a line is detectable with [`verify_audit_file`]. If the chain is already
//!   broken, destructive operations are refused (fail closed).
//!
//! The guard does **not** replace the vault's own integrity checks; it is an
//! additional, independent barrier. It also does not promise to stop a malicious
//! kernel driver or an attacker who already has the user's privileges — it
//! bounds what *Litric itself* is allowed to do.
//!
//! Configuration lives in `<vault>/safety-policy.json` and is written once with
//! safe defaults. An unreadable or invalid policy makes removals fail closed
//! rather than fall back to a permissive mode.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::hash::{sha256_bytes, sha256_file};

/// File name of the safety policy inside the vault directory.
pub const SAFETY_POLICY_FILE: &str = "safety-policy.json";
/// File name of the append-only audit log inside the vault directory.
pub const SAFETY_AUDIT_FILE: &str = "safety-audit.jsonl";
/// Current policy schema. A different value is refused, not guessed at.
pub const SAFETY_POLICY_SCHEMA: u32 = 1;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const RATE_WINDOW_SECONDS: u64 = 60;

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Persisted safety policy. Every field is enforced; none is decorative.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SafetyPolicy {
    pub schema: u32,
    /// Absolute directories whose entire contents are protected.
    pub protected_paths: Vec<String>,
    /// Absolute paths protected as individual objects (their children are not
    /// automatically protected).
    pub protected_exact: Vec<String>,
    /// Extra allowlist. When non-empty, a removal must also be inside one of
    /// these roots. Empty means "anywhere except protected paths".
    pub allowed_removal_roots: Vec<String>,
    /// Hard cap on authorised removals in a rolling minute.
    pub max_removals_per_minute: u32,
    /// Hard cap on authorised removal bytes in a rolling minute.
    pub max_removal_bytes_per_minute: u64,
    /// Re-hash a file immediately before unlinking it. Turning this off weakens
    /// the scan-to-delete race protection and is not recommended.
    pub rehash_before_delete: bool,
    /// Permit `purge`, which destroys quarantine evidence permanently. Purge
    /// still requires an explicit confirmation at the API/CLI layer.
    pub allow_permanent_delete: bool,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        SafetyPolicy {
            schema: SAFETY_POLICY_SCHEMA,
            protected_paths: default_protected_paths(),
            protected_exact: default_protected_exact_paths(),
            allowed_removal_roots: Vec::new(),
            max_removals_per_minute: 256,
            max_removal_bytes_per_minute: 4 * 1024 * 1024 * 1024,
            rehash_before_delete: true,
            allow_permanent_delete: true,
        }
    }
}

impl SafetyPolicy {
    /// Rejects a policy the guard cannot enforce honestly.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != SAFETY_POLICY_SCHEMA {
            return Err(format!(
                "unsupported safety policy schema {} (expected {SAFETY_POLICY_SCHEMA})",
                self.schema
            ));
        }
        if self.protected_paths.is_empty() && self.protected_exact.is_empty() {
            return Err(
                "refusing a policy with no protected paths: that would disable a core safety control"
                    .into(),
            );
        }
        for (field, list) in [
            ("protected_paths", &self.protected_paths),
            ("protected_exact", &self.protected_exact),
            ("allowed_removal_roots", &self.allowed_removal_roots),
        ] {
            for p in list {
                if !Path::new(p).is_absolute() {
                    return Err(format!("{field} entry `{p}` is not an absolute path"));
                }
            }
        }
        Ok(())
    }

    /// Reads a policy file. A missing file is not an error at the call site; the
    /// guard materialises the defaults. An unreadable or invalid file *is* an
    /// error and the guard stays fail-closed.
    pub fn load(path: &Path) -> Result<SafetyPolicy, String> {
        let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let policy: SafetyPolicy = serde_json::from_slice(&bytes)
            .map_err(|e| format!("{} is not a valid safety policy: {e}", path.display()))?;
        policy.validate()?;
        Ok(policy)
    }
}

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// `%SystemDrive%` is usually `C:` — a *drive-relative* path, not an absolute
/// one — so `env_path` would reject it and silently drop the boot/recovery
/// protections. Build an absolute root (`C:\`) explicitly instead.
#[cfg(windows)]
fn system_drive_root() -> Option<PathBuf> {
    let raw = std::env::var_os("SystemDrive")?;
    let s = raw.to_string_lossy();
    let s = s.trim_end_matches(['\\', '/']);
    if s.is_empty() {
        return None;
    }
    Some(PathBuf::from(format!("{s}\\")))
}

/// System locations that must never be removed by Litric.
///
/// The list is resolved from the live environment at first use; it is never
/// guessed from a hard-coded drive letter.
pub fn default_protected_paths() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    #[cfg(windows)]
    {
        for var in [
            "SystemRoot",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramW6432",
            "ProgramData",
            "CommonProgramFiles",
            "CommonProgramFiles(x86)",
        ] {
            if let Some(p) = env_path(var) {
                out.push(normalize_path(&p));
            }
        }
        if let Some(drive) = system_drive_root() {
            for sub in ["Recovery", "Boot", "$Recycle.Bin", "System Volume Information"] {
                out.push(normalize_existing(&drive.join(sub)));
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

/// Individual paths protected as objects rather than subtrees.
pub fn default_protected_exact_paths() -> Vec<String> {
    let mut out = Vec::new();

    #[cfg(windows)]
    {
        if let Some(drive) = system_drive_root() {
            out.push(normalize_path(&drive));
        }
        if let Some(profile) = env_path("USERPROFILE") {
            out.push(normalize_path(&profile));
        }
    }

    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

/// Normalises a path for comparison: Windows verbatim prefixes removed, `\`
/// folded to `/`, case folded on Windows, `.`/`..` resolved lexically and a
/// trailing separator removed.
///
/// Lexical resolution is deliberate: protected-path checks must not be
/// bypassable with `C:\Windows\..\Windows\System32` or `..\..\`.
pub fn normalize_path(p: &Path) -> String {
    let raw = p.to_string_lossy();
    let mut s = if cfg!(windows) {
        raw.replace('\\', "/")
    } else {
        raw.to_string()
    };

    if cfg!(windows) {
        if let Some(rest) = s.strip_prefix("//?/UNC/") {
            s = format!("//{rest}");
        } else if let Some(rest) = s.strip_prefix("//?/") {
            s = rest.to_string();
        }
        s = s.to_ascii_lowercase();
    }

    let absolute = s.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in s.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    let mut out = if absolute {
        format!("/{joined}")
    } else {
        joined
    };
    while out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

fn is_same_or_under(child: &str, root: &str) -> bool {
    if child == root {
        return true;
    }
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return child.starts_with('/');
    }
    child
        .strip_prefix(root)
        .map(|rest| rest.starts_with('/'))
        .unwrap_or(false)
}

fn absolutize(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}

/// Normalises a path that is expected to exist.
///
/// Windows returns long names from `canonicalize` even when the input used an
/// 8.3 short name (`AUDIM_~1`). Comparing a short-name policy entry with a
/// canonical target would silently disable a protected-path rule, so every
/// comparison resolves the real path first.
fn normalize_existing(p: &Path) -> String {
    match fs::canonicalize(p) {
        Ok(c) => normalize_path(&c),
        Err(_) => normalize_path(&absolutize(p)),
    }
}

/// Normalises a path that may not exist yet (a restore destination or an audit
/// file that has not been written). The parent is canonicalised when possible.
fn normalize_loose(p: &Path) -> String {
    match resolve_for_check(p, false) {
        Ok(p) => normalize_path(&p),
        Err(_) => normalize_path(&absolutize(p)),
    }
}

/// Canonicalises a target for a check. Existing files are canonicalised fully;
/// a path that does not exist yet (a restore destination) has its parent
/// canonicalised so a symlinked directory cannot smuggle it elsewhere.
fn resolve_for_check(path: &Path, must_exist: bool) -> Result<PathBuf, SafetyError> {
    let abs = absolutize(path);
    if must_exist {
        return fs::canonicalize(&abs)
            .map_err(|e| SafetyError::Io(format!("cannot resolve {}: {e}", abs.display())));
    }
    match (abs.parent(), abs.file_name()) {
        (Some(parent), Some(name)) => match fs::canonicalize(parent) {
            Ok(cp) => Ok(cp.join(name)),
            Err(_) => Ok(abs),
        },
        _ => Ok(abs),
    }
}

// ---------------------------------------------------------------------------
// Errors and results
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyError {
    /// The target is inside a protected system location or is the Litric
    /// policy/audit file.
    Protected { path: String, rule: String },
    /// The target is outside the scope the caller was authorised for.
    OutsideScope { path: String, scope: String },
    /// Directories, device nodes and other non-regular objects are never
    /// removed by the guard.
    NotRegularFile(String),
    /// A symbolic link is refused; Litric deletes the file it inspected, never
    /// whatever the link points at.
    Symlink(String),
    /// The file changed after it was scanned.
    Changed { expected: String, actual: String },
    /// The removal budget for the rolling minute is exhausted.
    RateLimited { reason: String },
    /// The policy could not be trusted, so destructive work is refused.
    PolicyUntrusted(String),
    /// The audit chain is already broken, so no further destructive work is
    /// permitted.
    AuditUntrusted(String),
    Io(String),
}

impl fmt::Display for SafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SafetyError::Protected { path, rule } => write!(
                f,
                "refused by safety policy: `{path}` is inside protected location `{rule}`"
            ),
            SafetyError::OutsideScope { path, scope } => write!(
                f,
                "refused by safety policy: `{path}` is outside the authorised scope ({scope})"
            ),
            SafetyError::NotRegularFile(p) => {
                write!(f, "refused by safety policy: not a regular file: `{p}`")
            }
            SafetyError::Symlink(p) => write!(
                f,
                "refused by safety policy: `{p}` is a symbolic link; Litric never deletes through a link"
            ),
            SafetyError::Changed { expected, actual } => write!(
                f,
                "refused by safety policy: the file changed after the scan (expected {expected}, found {actual})"
            ),
            SafetyError::RateLimited { reason } => write!(
                f,
                "refused by the safety removal budget: {reason}; the file was left in place"
            ),
            SafetyError::PolicyUntrusted(m) => write!(
                f,
                "refused by safety policy: the policy cannot be trusted ({m})"
            ),
            SafetyError::AuditUntrusted(m) => write!(
                f,
                "refused by safety policy: the audit log chain is broken ({m})"
            ),
            SafetyError::Io(m) => write!(f, "safety check I/O error: {m}"),
        }
    }
}

impl std::error::Error for SafetyError {}

/// What a caller is allowed to remove.
#[derive(Debug, Clone)]
pub enum RemovalScope {
    /// Exactly this object. Used for an explicit "quarantine this file" call.
    Exact(PathBuf),
    /// Anything below this directory. Used for a scan the user explicitly
    /// started on that directory.
    Under(PathBuf),
}

impl RemovalScope {
    fn describe(&self) -> String {
        match self {
            RemovalScope::Exact(p) => format!("exactly {}", p.display()),
            RemovalScope::Under(p) => format!("below {}", p.display()),
        }
    }

    fn root(&self) -> &Path {
        match self {
            RemovalScope::Exact(p) | RemovalScope::Under(p) => p,
        }
    }

    fn allows(&self, target: &str) -> bool {
        let root = normalize_loose(self.root());
        match self {
            RemovalScope::Exact(_) => target == root,
            RemovalScope::Under(_) => is_same_or_under(target, &root),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// One audit record. `hash` covers every other field plus `prev`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub unix: u64,
    pub operation: String,
    pub decision: String,
    pub path: String,
    pub sha256: Option<String>,
    pub detail: String,
    pub prev: String,
    pub hash: String,
}

#[derive(Serialize)]
struct AuditHashInput<'a> {
    seq: u64,
    unix: u64,
    operation: &'a str,
    decision: &'a str,
    path: &'a str,
    sha256: Option<&'a str>,
    detail: &'a str,
    prev: &'a str,
}

fn audit_hash(input: &AuditHashInput<'_>) -> String {
    let bytes = serde_json::to_vec(input).unwrap_or_default();
    sha256_bytes(&bytes).to_hex()
}

/// Result of verifying an audit log chain.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuditVerification {
    pub path: String,
    pub records: usize,
    pub ok: bool,
    pub first_problem: Option<String>,
    pub last_hash: Option<String>,
}

/// Verifies every line of an audit log and the `prev`/`seq` chain.
///
/// A record removed from the middle, edited, reordered or appended without the
/// correct `prev` is reported with its line number. A truncated final line is
/// also a problem: the writer never leaves one behind on purpose.
pub fn verify_audit_file(path: &Path) -> AuditVerification {
    let mut out = AuditVerification {
        path: path.display().to_string(),
        records: 0,
        ok: true,
        first_problem: None,
        last_hash: None,
    };

    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return out,
        Err(e) => {
            out.ok = false;
            out.first_problem = Some(format!("cannot read audit log: {e}"));
            return out;
        }
    };

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut expected_seq = 1u64;
    for (i, line) in text.lines().enumerate() {
        let line_no = i + 1;
        if line.trim().is_empty() {
            out.ok = false;
            out.first_problem
                .get_or_insert_with(|| format!("line {line_no}: empty record"));
            continue;
        }
        let record: AuditRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                out.ok = false;
                out.first_problem.get_or_insert_with(|| {
                    format!("line {line_no}: unreadable record ({e})")
                });
                continue;
            }
        };
        out.records += 1;
        let computed = audit_hash(&AuditHashInput {
            seq: record.seq,
            unix: record.unix,
            operation: &record.operation,
            decision: &record.decision,
            path: &record.path,
            sha256: record.sha256.as_deref(),
            detail: &record.detail,
            prev: &record.prev,
        });
        if record.seq != expected_seq {
            out.ok = false;
            out.first_problem.get_or_insert_with(|| {
                format!(
                    "line {line_no}: sequence {} does not follow {}",
                    record.seq, expected_seq
                )
            });
        }
        if record.prev != expected_prev {
            out.ok = false;
            out.first_problem.get_or_insert_with(|| {
                format!(
                    "line {line_no}: prev hash does not match the previous record (chain broken)"
                )
            });
        }
        if record.hash != computed {
            out.ok = false;
            out.first_problem.get_or_insert_with(|| {
                format!("line {line_no}: record hash does not match its contents (edited)")
            });
        }
        expected_prev = record.hash.clone();
        expected_seq = record.seq.saturating_add(1);
        out.last_hash = Some(record.hash);
    }

    if out.ok {
        out.last_hash = Some(expected_prev);
    }
    out
}

#[derive(Debug)]
struct AuditState {
    seq: u64,
    last_hash: String,
    problem: Option<String>,
}

/// Opens the audit file and verifies the existing chain. A broken chain is
/// remembered and blocks further removals; it never gets repaired by guessing.
fn open_audit(path: &Path) -> AuditState {
    let verification = verify_audit_file(path);
    if !verification.ok {
        return AuditState {
            seq: 0,
            last_hash: GENESIS_HASH.to_string(),
            problem: verification.first_problem,
        };
    }
    AuditState {
        seq: verification.records as u64,
        last_hash: verification
            .last_hash
            .unwrap_or_else(|| GENESIS_HASH.to_string()),
        problem: None,
    }
}

// ---------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------

struct Budget {
    window_start: u64,
    count: u64,
    bytes: u64,
}

struct Inner {
    policy: SafetyPolicy,
    /// OS locations protected in code, independent of what the policy file says.
    /// A hand-edited or truncated policy can narrow the extra list; it can never
    /// unprotect the Windows system trees.
    builtin_protected_paths: Vec<String>,
    builtin_protected_exact: Vec<String>,
    policy_path: PathBuf,
    audit_path: PathBuf,
    policy_error: Option<String>,
    audit: Mutex<AuditState>,
    budget: Mutex<Budget>,
    authorized_removals: AtomicU64,
    authorized_bytes: AtomicU64,
}

/// The one gate every destructive operation must call.
#[derive(Clone)]
pub struct SafetyGuard {
    inner: Arc<Inner>,
}

impl fmt::Debug for SafetyGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafetyGuard")
            .field("policy_path", &self.inner.policy_path)
            .field("audit_path", &self.inner.audit_path)
            .field("policy_error", &self.inner.policy_error)
            .finish()
    }
}

impl SafetyGuard {
    /// Opens the guard rooted at `dir`, materialising a safe default policy when
    /// none exists. This never fails: a missing policy is replaced by the
    /// built-in safe policy, while an unreadable/invalid one is recorded and
    /// blocks destructive work.
    pub fn open(dir: &Path) -> SafetyGuard {
        let _ = fs::create_dir_all(dir);
        let policy_path = dir.join(SAFETY_POLICY_FILE);
        let audit_path = dir.join(SAFETY_AUDIT_FILE);

        let (policy, policy_error) = match fs::read(&policy_path) {
            Ok(_) => match SafetyPolicy::load(&policy_path) {
                Ok(p) => (p, None),
                Err(e) => (SafetyPolicy::default(), Some(e)),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let policy = SafetyPolicy::default();
                let _ = write_json_atomic(&policy_path, &policy);
                (policy, None)
            }
            Err(e) => (
                SafetyPolicy::default(),
                Some(format!("cannot read {}: {e}", policy_path.display())),
            ),
        };

        let audit_state = open_audit(&audit_path);

        SafetyGuard {
            inner: Arc::new(Inner {
                policy,
                builtin_protected_paths: default_protected_paths(),
                builtin_protected_exact: default_protected_exact_paths(),
                policy_path,
                audit_path,
                policy_error,
                audit: Mutex::new(audit_state),
                budget: Mutex::new(Budget {
                    window_start: now_unix(),
                    count: 0,
                    bytes: 0,
                }),
                authorized_removals: AtomicU64::new(0),
                authorized_bytes: AtomicU64::new(0),
            }),
        }
    }

    pub fn policy(&self) -> &SafetyPolicy {
        &self.inner.policy
    }

    pub fn policy_path(&self) -> &Path {
        &self.inner.policy_path
    }

    pub fn audit_path(&self) -> &Path {
        &self.inner.audit_path
    }

    pub fn policy_error(&self) -> Option<&str> {
        self.inner.policy_error.as_deref()
    }

    pub fn audit_problem(&self) -> Option<String> {
        self.inner
            .audit
            .lock()
            .ok()
            .and_then(|a| a.problem.clone())
    }

    /// Total removals/bytes authorised by this guard since start.
    pub fn authorised_totals(&self) -> (u64, u64) {
        (
            self.inner.authorized_removals.load(Ordering::Relaxed),
            self.inner.authorized_bytes.load(Ordering::Relaxed),
        )
    }

    /// Verifies the audit chain on disk.
    pub fn verify_audit(&self) -> AuditVerification {
        verify_audit_file(&self.inner.audit_path)
    }

    /// Machine-readable status for the API/UI.
    pub fn status_json(&self) -> serde_json::Value {
        let verification = self.verify_audit();
        let (removals, bytes) = self.authorised_totals();
        serde_json::json!({
            "policy_path": self.inner.policy_path.display().to_string(),
            "audit_path": self.inner.audit_path.display().to_string(),
            "policy_trusted": self.inner.policy_error.is_none(),
            "policy_error": self.inner.policy_error,
            "audit_problem": self.audit_problem(),
            "audit": verification,
            "authorised_removals": removals,
            "authorised_bytes": bytes,
            "policy": self.inner.policy,
        })
    }

    fn ensure_trusted(&self) -> Result<(), SafetyError> {
        if let Some(e) = &self.inner.policy_error {
            return Err(SafetyError::PolicyUntrusted(e.clone()));
        }
        if let Some(p) = self.audit_problem() {
            return Err(SafetyError::AuditUntrusted(p));
        }
        Ok(())
    }

    fn protected_reason(&self, target: &str) -> Option<(String, String)> {
        for root in self
            .inner
            .builtin_protected_paths
            .iter()
            .chain(self.inner.policy.protected_paths.iter())
        {
            let root = normalize_existing(Path::new(root));
            if is_same_or_under(target, &root) {
                return Some((root, "protected_paths".into()));
            }
        }
        for exact in self
            .inner
            .builtin_protected_exact
            .iter()
            .chain(self.inner.policy.protected_exact.iter())
        {
            let exact = normalize_existing(Path::new(exact));
            if target == exact {
                return Some((exact, "protected_exact".into()));
            }
        }
        // The guard's own configuration and evidence are always protected, even
        // if a policy author forgot to list them.
        for own in [&self.inner.policy_path, &self.inner.audit_path] {
            let own = normalize_loose(own);
            if target == own {
                return Some((own, "Litric safety configuration".into()));
            }
        }
        None
    }

    /// Read-only check used before work is done (for example before writing a
    /// vault entry). Performs no audit write and consumes no budget.
    pub fn check_removal(
        &self,
        path: &Path,
        scope: &RemovalScope,
    ) -> Result<ResolvedTarget, SafetyError> {
        self.ensure_trusted()?;
        let canonical = resolve_for_check(path, true)?;
        let meta = fs::symlink_metadata(path).map_err(|e| SafetyError::Io(format!(
            "cannot inspect {}: {e}",
            path.display()
        )))?;
        if meta.file_type().is_symlink() {
            return Err(SafetyError::Symlink(path.display().to_string()));
        }
        if !meta.is_file() {
            return Err(SafetyError::NotRegularFile(path.display().to_string()));
        }
        let target = normalize_path(&canonical);

        if let Some((rule, field)) = self.protected_reason(&target) {
            return Err(SafetyError::Protected {
                path: target,
                rule: format!("{rule} ({field})"),
            });
        }

        if !scope.allows(&target) {
            return Err(SafetyError::OutsideScope {
                path: target,
                scope: scope.describe(),
            });
        }

        if !self.inner.policy.allowed_removal_roots.is_empty() {
            let allowed = self
                .inner
                .policy
                .allowed_removal_roots
                .iter()
                .any(|root| is_same_or_under(&target, &normalize_existing(Path::new(root))));
            if !allowed {
                return Err(SafetyError::OutsideScope {
                    path: target,
                    scope: "the configured allowed_removal_roots".into(),
                });
            }
        }

        Ok(ResolvedTarget {
            canonical,
            normalised: target,
            size: meta.len(),
        })
    }

    /// Authorises one removal. The caller must call [`RemovalPermit::finish`]
    /// immediately after the unlink attempt.
    pub fn authorize_removal(
        &self,
        path: &Path,
        expected_sha256: Option<&str>,
        scope: &RemovalScope,
    ) -> Result<RemovalPermit, SafetyError> {
        let target = match self.check_removal(path, scope) {
            Ok(t) => t,
            Err(e) => {
                let _ = self.audit_event(
                    "remove_source",
                    "refused",
                    path,
                    expected_sha256,
                    &e.to_string(),
                );
                return Err(e);
            }
        };

        if let Some(expected) = expected_sha256 {
            if self.inner.policy.rehash_before_delete {
                let (digest, read, truncated) =
                    sha256_file(&target.canonical, target.size).map_err(|e| {
                        SafetyError::Io(format!(
                            "cannot re-hash {} before removal: {e}",
                            target.canonical.display()
                        ))
                    })?;
                let actual = digest.to_hex();
                if truncated || read != target.size || !actual.eq_ignore_ascii_case(expected) {
                    let err = SafetyError::Changed {
                        expected: expected.to_string(),
                        actual,
                    };
                    let _ = self.audit_event(
                        "remove_source",
                        "refused",
                        path,
                        expected_sha256,
                        &err.to_string(),
                    );
                    return Err(err);
                }
            }
        }

        self.take_budget(target.size).map_err(|e| {
            let _ = self.audit_event(
                "remove_source",
                "refused",
                path,
                expected_sha256,
                &e.to_string(),
            );
            e
        })?;

        self.audit_event(
            "remove_source",
            "allowed",
            path,
            expected_sha256,
            &format!(
                "{} bytes, scope {}",
                target.size,
                scope.describe()
            ),
        )
        .map_err(|e| SafetyError::AuditUntrusted(e.to_string()))?;

        self.inner
            .authorized_removals
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .authorized_bytes
            .fetch_add(target.size, Ordering::Relaxed);

        Ok(RemovalPermit {
            guard: self.clone(),
            path: path.to_path_buf(),
            sha256: expected_sha256.map(str::to_string),
            finished: false,
        })
    }

    /// Authorises writing a new file at `path` (restore/export). Protected
    /// locations are refused so a restored sample can never land in a system
    /// directory.
    pub fn authorize_write(&self, path: &Path, operation: &str) -> Result<(), SafetyError> {
        // Restoring user data is recovery, not destruction: an untrusted audit
        // chain must not block it. The protected-location check still applies.
        let canonical = resolve_for_check(path, false)?;
        let target = normalize_path(&canonical);
        if let Some((rule, field)) = self.protected_reason(&target) {
            let err = SafetyError::Protected {
                path: target,
                rule: format!("{rule} ({field})"),
            };
            let _ = self.audit_event(operation, "refused", path, None, &err.to_string());
            return Err(err);
        }
        self.audit_event(operation, "allowed", path, None, "write authorised")
    }

    /// Requires the policy to permit permanent deletion (purge).
    pub fn authorize_purge(&self, id: &str, entry: &Path) -> Result<(), SafetyError> {
        self.ensure_trusted()?;
        if !self.inner.policy.allow_permanent_delete {
            let err = SafetyError::Protected {
                path: entry.display().to_string(),
                rule: "allow_permanent_delete is false in the safety policy".into(),
            };
            let _ = self.audit_event("purge", "refused", entry, None, &err.to_string());
            return Err(err);
        }
        self.audit_event(
            "purge",
            "allowed",
            entry,
            None,
            &format!("quarantine id {id}"),
        )
    }

    /// Appends an audit record. Public so the vault can record outcomes that the
    /// guard did not itself initiate (purge completion, restore completion).
    pub fn audit_event(
        &self,
        operation: &str,
        decision: &str,
        path: &Path,
        sha256: Option<&str>,
        detail: &str,
    ) -> Result<(), SafetyError> {
        let mut state = self
            .inner
            .audit
            .lock()
            .map_err(|_| SafetyError::Io("audit lock poisoned".into()))?;
        if let Some(p) = &state.problem {
            return Err(SafetyError::AuditUntrusted(p.clone()));
        }
        let seq = state.seq + 1;
        let unix = now_unix();
        let path_str = path.display().to_string();
        let input = AuditHashInput {
            seq,
            unix,
            operation,
            decision,
            path: &path_str,
            sha256,
            detail,
            prev: &state.last_hash,
        };
        let hash = audit_hash(&input);
        let record = AuditRecord {
            seq,
            unix,
            operation: operation.to_string(),
            decision: decision.to_string(),
            path: path_str,
            sha256: sha256.map(str::to_string),
            detail: detail.to_string(),
            prev: state.last_hash.clone(),
            hash: hash.clone(),
        };
        let mut line = serde_json::to_string(&record)
            .map_err(|e| SafetyError::Io(format!("serialize audit record: {e}")))?;
        line.push('\n');

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.inner.audit_path)
            .map_err(|e| {
                let m = format!("cannot open audit log {}: {e}", self.inner.audit_path.display());
                state.problem = Some(m.clone());
                SafetyError::AuditUntrusted(m)
            })?;
        f.write_all(line.as_bytes())
            .and_then(|_| f.sync_data())
            .map_err(|e| {
                let m = format!("cannot append to audit log: {e}");
                state.problem = Some(m.clone());
                SafetyError::AuditUntrusted(m)
            })?;

        state.seq = seq;
        state.last_hash = hash;
        Ok(())
    }

    fn take_budget(&self, size: u64) -> Result<(), SafetyError> {
        let mut budget = self
            .inner
            .budget
            .lock()
            .map_err(|_| SafetyError::Io("budget lock poisoned".into()))?;
        let now = now_unix();
        if now.saturating_sub(budget.window_start) >= RATE_WINDOW_SECONDS {
            budget.window_start = now;
            budget.count = 0;
            budget.bytes = 0;
        }
        let count_limit = u64::from(self.inner.policy.max_removals_per_minute);
        let byte_limit = self.inner.policy.max_removal_bytes_per_minute;
        if budget.count + 1 > count_limit {
            return Err(SafetyError::RateLimited {
                reason: format!(
                    "{} removals already authorised in this minute (limit {})",
                    budget.count, count_limit
                ),
            });
        }
        if budget.bytes.saturating_add(size) > byte_limit {
            return Err(SafetyError::RateLimited {
                reason: format!(
                    "{} bytes already authorised in this minute (limit {})",
                    budget.bytes, byte_limit
                ),
            });
        }
        budget.count += 1;
        budget.bytes = budget.bytes.saturating_add(size);
        Ok(())
    }
}

/// A target that passed the read-only checks.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub canonical: PathBuf,
    pub normalised: String,
    pub size: u64,
}

/// Proof that one removal was authorised. Dropping it without `finish` records
/// an `abandoned` outcome instead of silently losing the result.
#[derive(Debug)]
pub struct RemovalPermit {
    guard: SafetyGuard,
    path: PathBuf,
    sha256: Option<String>,
    finished: bool,
}

impl RemovalPermit {
    /// Records the real outcome. Call this immediately after the unlink.
    pub fn finish(mut self, removed: bool, detail: &str) {
        self.finished = true;
        let decision = if removed { "completed" } else { "failed" };
        let _ = self.guard.audit_event(
            "remove_source",
            decision,
            &self.path,
            self.sha256.as_deref(),
            detail,
        );
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RemovalPermit {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.guard.audit_event(
                "remove_source",
                "abandoned",
                &self.path,
                self.sha256.as_deref(),
                "permit dropped without an outcome; the removal result is unrecorded",
            );
        }
    }
}

fn write_json_atomic(path: &Path, policy: &SafetyPolicy) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(policy).map_err(std::io::Error::other)?;
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempTree(PathBuf);

    impl TempTree {
        fn new(tag: &str) -> Self {
            let mut nonce = [0u8; 8];
            let _ = getrandom::getrandom(&mut nonce);
            let id: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let p = std::env::temp_dir().join(format!(
                "litric-safety-{tag}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&p).unwrap();
            TempTree(p)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            fs::write(&p, bytes).unwrap();
            p
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn policy(protected: &Path, budget: u32) -> SafetyPolicy {
        let mut p = SafetyPolicy::default();
        p.protected_paths = vec![normalize_path(protected)];
        p.protected_exact = Vec::new();
        p.max_removals_per_minute = budget;
        p.max_removal_bytes_per_minute = 1024 * 1024;
        p
    }

    fn guard(tag: &str, policy: SafetyPolicy) -> (SafetyGuard, TempTree) {
        let t = TempTree::new(tag);
        let dir = t.0.join("vault");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(SAFETY_POLICY_FILE),
            serde_json::to_vec_pretty(&policy).unwrap(),
        )
        .unwrap();
        (SafetyGuard::open(&dir), t)
    }

    #[test]
    fn protected_location_is_refused_and_the_file_survives() {
        let t = TempTree::new("protected");
        let protected = t.0.join("Windows");
        fs::create_dir_all(&protected).unwrap();
        let victim = protected.join("kernel32.dll");
        fs::write(&victim, b"do not delete").unwrap();

        let (g, _v) = guard("protected-g", policy(&protected, 10));
        let err = g
            .authorize_removal(&victim, None, &RemovalScope::Exact(victim.clone()))
            .unwrap_err();
        assert!(matches!(err, SafetyError::Protected { .. }), "{err}");
        assert!(victim.exists(), "a protected file must never be removed");
    }

    #[test]
    fn a_path_cannot_escape_the_scope_with_dot_dot() {
        let t = TempTree::new("scope");
        let root = t.0.join("scan-root");
        fs::create_dir_all(&root).unwrap();
        let outside = t.0.join("outside.txt");
        fs::write(&outside, b"outside").unwrap();
        let sneaky = root.join("..").join("outside.txt");

        let (g, _v) = guard("scope-g", policy(&t.0.join("nothing"), 10));
        let err = g
            .authorize_removal(&sneaky, None, &RemovalScope::Under(root.clone()))
            .unwrap_err();
        assert!(matches!(err, SafetyError::OutsideScope { .. }), "{err}");
        assert!(outside.exists());
    }

    #[test]
    fn a_file_that_changed_after_the_scan_is_refused() {
        let t = TempTree::new("changed");
        let root = t.0.join("scan");
        fs::create_dir_all(&root).unwrap();
        let f = t.file("scan/sample.bin", b"original content");
        let scanned = sha256_bytes(b"original content").to_hex();
        fs::write(&f, b"swapped content").unwrap();

        let (g, _v) = guard("changed-g", policy(&t.0.join("nothing"), 10));
        let err = g
            .authorize_removal(
                &f,
                Some(&scanned),
                &RemovalScope::Exact(f.clone()),
            )
            .unwrap_err();
        assert!(matches!(err, SafetyError::Changed { .. }), "{err}");
        assert!(f.exists(), "the swapped file must not be removed");
    }

    #[test]
    fn the_budget_stops_a_bulk_deletion() {
        let t = TempTree::new("budget");
        let root = t.0.join("scan");
        fs::create_dir_all(&root).unwrap();
        let (g, _v) = guard("budget-g", policy(&t.0.join("nothing"), 2));

        for i in 0..2 {
            let f = t.file(&format!("scan/{i}.bin"), b"x");
            let permit = g
                .authorize_removal(&f, None, &RemovalScope::Exact(f.clone()))
                .expect("first two removals fit the budget");
            fs::remove_file(&f).unwrap();
            permit.finish(true, "test");
            assert!(!f.exists());
        }
        let third = t.file("scan/third.bin", b"x");
        let err = g
            .authorize_removal(&third, None, &RemovalScope::Exact(third.clone()))
            .unwrap_err();
        assert!(matches!(err, SafetyError::RateLimited { .. }), "{err}");
        assert!(third.exists(), "the budget must stop the third removal");
    }

    #[test]
    fn the_audit_chain_records_allowed_refused_and_completed_outcomes() {
        let t = TempTree::new("audit");
        let root = t.0.join("scan");
        fs::create_dir_all(&root).unwrap();
        let f = t.file("scan/good.bin", b"data");
        let (g, _v) = guard("audit-g", policy(&t.0.join("nothing"), 10));

        let permit = g
            .authorize_removal(&f, None, &RemovalScope::Exact(f.clone()))
            .unwrap();
        fs::remove_file(&f).unwrap();
        permit.finish(true, "removed in test");

        let v = g.verify_audit();
        assert!(v.ok, "{v:?}");
        assert_eq!(v.records, 2, "allowed + completed");
        let text = fs::read_to_string(g.audit_path()).unwrap();
        assert!(text.contains("remove_source"));
        assert!(text.contains("completed"));
    }

    #[test]
    fn an_edited_audit_log_fails_verification_and_blocks_removal() {
        let t = TempTree::new("tamper");
        let root = t.0.join("scan");
        fs::create_dir_all(&root).unwrap();
        let f = t.file("scan/a.bin", b"data");
        let (g, _v) = guard("tamper-g", policy(&t.0.join("nothing"), 10));
        let permit = g
            .authorize_removal(&f, None, &RemovalScope::Exact(f.clone()))
            .unwrap();
        fs::remove_file(&f).unwrap();
        permit.finish(true, "removed");

        let audit = g.audit_path().to_path_buf();
        let text = fs::read_to_string(&audit).unwrap();
        let edited = text.replacen("\"detail\":\"removed", "\"detail\":\"changed", 1);
        fs::write(&audit, edited).unwrap();

        let v = verify_audit_file(&audit);
        assert!(!v.ok, "an edited record must be detected");
        assert!(v.first_problem.is_some());

        let dir = audit.parent().unwrap().to_path_buf();
        let reopened = SafetyGuard::open(&dir);
        let victim = t.file("scan/b.bin", b"x");
        let err = reopened
            .authorize_removal(&victim, None, &RemovalScope::Exact(victim.clone()))
            .unwrap_err();
        assert!(matches!(err, SafetyError::AuditUntrusted(_)), "{err}");
        assert!(victim.exists(), "a broken audit chain must block removals");
    }

    #[test]
    fn removing_a_middle_record_breaks_the_chain() {
        let t = TempTree::new("truncate");
        let root = t.0.join("scan");
        fs::create_dir_all(&root).unwrap();
        let (g, _v) = guard("truncate-g", policy(&t.0.join("nothing"), 10));
        for i in 0..2 {
            let f = t.file(&format!("scan/{i}.bin"), b"x");
            let permit = g
                .authorize_removal(&f, None, &RemovalScope::Exact(f.clone()))
                .unwrap();
            fs::remove_file(&f).unwrap();
            permit.finish(true, "removed");
        }
        let audit = g.audit_path().to_path_buf();
        let text = fs::read_to_string(&audit).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        // Remove the second record (a `completed` line).
        lines.remove(1);
        fs::write(&audit, format!("{}\n", lines.join("\n"))).unwrap();
        let v = verify_audit_file(&audit);
        assert!(!v.ok, "a removed record must be detected: {v:?}");
    }

    #[test]
    fn an_invalid_policy_fails_closed() {
        let t = TempTree::new("badpolicy");
        let dir = t.0.join("vault");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(SAFETY_POLICY_FILE), b"{ not json").unwrap();
        let g = SafetyGuard::open(&dir);
        assert!(g.policy_error().is_some());

        let f = t.file("user-file.txt", b"keep");
        let err = g
            .authorize_removal(&f, None, &RemovalScope::Exact(f.clone()))
            .unwrap_err();
        assert!(matches!(err, SafetyError::PolicyUntrusted(_)), "{err}");
        assert!(f.exists());
    }

    #[test]
    fn a_policy_with_no_protected_paths_is_rejected() {
        let mut p = SafetyPolicy::default();
        p.protected_paths.clear();
        p.protected_exact.clear();
        assert!(p.validate().is_err());
    }

    #[test]
    fn the_guard_protects_its_own_policy_and_audit_files() {
        let t = TempTree::new("ownfiles");
        let (g, _v) = guard("ownfiles-g", policy(&t.0.join("nothing"), 10));
        let policy = g.policy_path().to_path_buf();
        let err = g
            .authorize_removal(&policy, None, &RemovalScope::Exact(policy.clone()))
            .unwrap_err();
        assert!(matches!(err, SafetyError::Protected { .. }), "{err}");
        assert!(policy.exists());
    }

    #[test]
    fn directories_are_never_removed_by_the_guard() {
        let t = TempTree::new("dir");
        let (g, _v) = guard("dir-g", policy(&t.0.join("nothing"), 10));
        let dir = t.0.join("some-dir");
        fs::create_dir_all(&dir).unwrap();
        let err = g
            .authorize_removal(&dir, None, &RemovalScope::Exact(dir.clone()))
            .unwrap_err();
        assert!(matches!(err, SafetyError::NotRegularFile(_)), "{err}");
        assert!(dir.is_dir());
    }

    #[cfg(windows)]
    #[test]
    fn the_default_policy_protects_the_system_drive_trees() {
        let policy = SafetyPolicy::default();
        for suffix in ["/recovery", "/boot", "/$recycle.bin", "/system volume information"] {
            assert!(
                policy
                    .protected_paths
                    .iter()
                    .any(|p| p.ends_with(suffix)),
                "default policy is missing the {suffix} tree: {:?}",
                policy.protected_paths
            );
        }
        let drive = std::env::var("SystemDrive").expect("SystemDrive");
        let root = format!(
            "{}",
            drive.trim_end_matches(['\\', '/']).to_ascii_lowercase()
        );
        assert!(
            policy.protected_exact.contains(&root),
            "the drive root must be protected as an exact object: {:?}",
            policy.protected_exact
        );
        let profile = std::env::var("USERPROFILE").expect("USERPROFILE");
        assert!(
            policy
                .protected_exact
                .contains(&normalize_existing(Path::new(&profile))),
            "the user-profile root must be protected as an exact object: {:?}",
            policy.protected_exact
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_policy_cannot_unprotect_the_windows_system_trees() {
        // A policy that lists only its own temp directory used to be enough to
        // make a real system file removable. The built-in protection wins.
        let extra = TempTree::new("builtin-extra");
        let (g, _vault) = guard("builtin-protected", policy(&extra.0, 10));
        let system_file = Path::new(&std::env::var("SystemRoot").expect("SystemRoot"))
            .join("System32")
            .join("notepad.exe");
        assert!(system_file.is_file(), "fixture must exist: {system_file:?}");
        let err = g
            .check_removal(&system_file, &RemovalScope::Exact(system_file.clone()))
            .expect_err("system file must never be removable");
        assert!(matches!(err, SafetyError::Protected { .. }), "{err}");
        assert!(system_file.exists());
    }

    #[test]
    fn restoring_into_a_protected_location_is_refused() {
        let t = TempTree::new("write");
        let protected = t.0.join("Windows");
        fs::create_dir_all(&protected).unwrap();
        let (g, _v) = guard("write-g", policy(&protected, 10));
        let err = g
            .authorize_write(&protected.join("evil.dll"), "restore")
            .unwrap_err();
        assert!(matches!(err, SafetyError::Protected { .. }), "{err}");

        let ok = t.0.join("restore-ok.bin");
        g.authorize_write(&ok, "restore").unwrap();
    }

    #[test]
    fn path_normalisation_folds_separators_dots_and_verbatim_prefixes() {
        let base = std::env::temp_dir();
        let tricky = base.join(".").join("a").join("..").join("b");
        let expected = normalize_path(&base.join("b"));
        assert_eq!(normalize_path(&tricky), expected);

        #[cfg(windows)]
        {
            let verbatim = format!("\\\\?\\{}", base.join("c").display());
            assert_eq!(
                normalize_path(Path::new(&verbatim)),
                normalize_path(&base.join("c"))
            );
            assert_eq!(
                normalize_path(Path::new("C:\\Windows\\System32")),
                "c:/windows/system32"
            );
        }
    }
}
