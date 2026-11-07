//! Litric Quarantine Vault.
//!
//! Design constraints, in priority order:
//!
//! 1. **Never destroy evidence.** A file is encrypted, written, re-read,
//!    decrypted and hash-verified *before* the original is removed. If any step
//!    fails, the original stays where it is and the operation reports failure.
//! 2. **Confidentiality at rest.** Quarantined content is encrypted with
//!    XChaCha20-Poly1305. Malware encryptors, indexers and sync tools cannot read
//!    or re-detonate samples from the vault.
//! 3. **Tamper evidence.** The entry header is authenticated as AEAD associated
//!    data, so editing the recorded original path, hash or threat name makes
//!    decryption fail rather than silently mis-restoring.
//! 4. **No silent deletion.** `purge` requires an explicit call and is the only
//!    path that removes evidence; the default is retention.
//! 5. **One safety gate.** Every source removal and every restore target passes
//!    through [`crate::safety::SafetyGuard`]: protected system locations are
//!    refused, the file is re-hashed immediately before unlinking, removals are
//!    rate-limited, and every decision is written to a hash-chained audit log.
//!
//! Key management:
//! * A 32-byte random master key is generated on first use, sealed with
//!   machine-scoped DPAPI, and stored with a protected `SY/BA/OW` DACL. The
//!   vault directory is hardened on every open, not only by the service.
//! * A passphrase mode derives the key with Argon2id for portable vaults.
//!
//! Cryptographic primitives come from audited crates (`chacha20poly1305`,
//! `argon2`, `sha2`); Litric does not implement cryptography.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::hash::sha256_bytes;
use crate::safety::{RemovalScope, SafetyGuard};

pub const VAULT_MAGIC: &[u8; 6] = b"LQVF1\n";
const MASTER_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const INDEX_FILE: &str = "index.json";
const JOURNAL_FILE: &str = "ops.jsonl";

/// Entry payloads written by this version are a self-describing container: the
/// file body plus its named alternate data streams. Older entries have no
/// container marker and are treated as raw file bytes.
const PAYLOAD_MAGIC: &[u8; 8] = b"LQPAY1\0\0";
const PAYLOAD_VERSION_RAW: u32 = 0;
const PAYLOAD_VERSION_CONTAINER: u32 = 1;

/// Header of a DPAPI-wrapped key file. A bare 32-byte file is the legacy format
/// and is migrated on first open without losing access.
const KEY_FILE_MAGIC: &[u8] = b"LKDK1\n";
/// Additional entropy binds the sealed key to Litric's vault purpose, so another
/// DPAPI blob from the same machine cannot be substituted as a vault key.
const KEY_FILE_ENTROPY: &[u8] = b"LitricDefender.VaultKey.v1";

/// A 32-byte symmetric vault key.
#[derive(Clone)]
pub struct VaultKey([u8; MASTER_KEY_LEN]);

impl VaultKey {
    /// Generates a fresh random key using the OS CSPRNG.
    pub fn generate() -> Result<Self, VaultError> {
        let mut k = [0u8; MASTER_KEY_LEN];
        getrandom::getrandom(&mut k).map_err(|e| VaultError::Corrupt(format!("csprng: {e}")))?;
        Ok(VaultKey(k))
    }

    pub fn from_bytes(b: [u8; MASTER_KEY_LEN]) -> Self {
        VaultKey(b)
    }

    /// Loads a key file, or creates one if absent.
    ///
    /// New keys are DPAPI-wrapped on Windows. A legacy 32-byte plaintext key is
    /// still accepted and is upgraded in place, keeping the original bytes as
    /// `vault.key.legacy` so a failed upgrade can never lock the user out of
    /// their own quarantine.
    pub fn load_or_create(path: &Path) -> Result<Self, VaultError> {
        match fs::read(path) {
            Ok(raw) => Self::from_key_file(path, raw),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = VaultKey::generate()?;
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                write_key_file(path, &encode_key_file(&key.0)?)?;
                Ok(key)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn from_key_file(path: &Path, raw: Vec<u8>) -> Result<Self, VaultError> {
        if raw.starts_with(KEY_FILE_MAGIC) {
            let plain = decode_key_file(&raw[KEY_FILE_MAGIC.len()..])?;
            if plain.len() != MASTER_KEY_LEN {
                return Err(VaultError::Corrupt(format!(
                    "vault key must be {MASTER_KEY_LEN} bytes after unwrapping, found {}",
                    plain.len()
                )));
            }
            let mut k = [0u8; MASTER_KEY_LEN];
            k.copy_from_slice(&plain);
            return Ok(VaultKey(k));
        }
        if raw.len() == MASTER_KEY_LEN {
            let mut k = [0u8; MASTER_KEY_LEN];
            k.copy_from_slice(&raw);
            // Best effort: the raw key still works if the upgrade fails, and
            // the original file is not touched until the wrapped copy is
            // durable.
            let _ = upgrade_legacy_key(path, &raw);
            return Ok(VaultKey(k));
        }
        Err(VaultError::Corrupt(format!(
            "vault key file is neither DPAPI-wrapped nor {MASTER_KEY_LEN} bytes, found {}",
            raw.len()
        )))
    }

    /// Derives a key from a passphrase with Argon2id (for portable vaults).
    pub fn from_passphrase(passphrase: &[u8], salt: &[u8; 16]) -> Result<Self, VaultError> {
        let params = Params::new(64 * 1024, 3, 1, Some(MASTER_KEY_LEN))
            .map_err(|e| VaultError::Corrupt(format!("argon2 params: {e}")))?;
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; MASTER_KEY_LEN];
        a2.hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| VaultError::Corrupt(format!("argon2: {e}")))?;
        Ok(VaultKey(out))
    }
}

/// New keys are sealed with machine-scoped DPAPI before they reach disk.
fn encode_key_file(key: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>, VaultError> {
    let sealed = crate::winplatform::dpapi::protect(key, KEY_FILE_ENTROPY).map_err(|e| {
        VaultError::Corrupt(format!(
            "cannot protect the vault key with DPAPI, refusing to store it in plaintext: {e}"
        ))
    })?;
    let mut out = Vec::with_capacity(KEY_FILE_MAGIC.len() + sealed.len());
    out.extend_from_slice(KEY_FILE_MAGIC);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn decode_key_file(blob: &[u8]) -> Result<Vec<u8>, VaultError> {
    crate::winplatform::dpapi::unprotect(blob, KEY_FILE_ENTROPY).map_err(|e| {
        VaultError::Corrupt(format!(
            "vault key is DPAPI-wrapped but cannot be unwrapped on this machine/account: {e}. \
             The vault cannot be opened without its key; keep `vault.key` with the vault or \
             restore a backup of it."
        ))
    })
}

/// Writes through a temporary file and renames, so an interrupted write cannot
/// truncate an existing key.
fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = path.with_extension("key.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn upgrade_legacy_key(path: &Path, raw: &[u8]) -> Result<(), VaultError> {
    let backup = path.with_extension("key.legacy");
    if !backup.exists() {
        write_key_file(&backup, raw)?;
    }
    let mut key = [0u8; MASTER_KEY_LEN];
    key.copy_from_slice(raw);
    write_key_file(path, &encode_key_file(&key)?)
}

#[cfg(windows)]
fn protect_vault_paths(dir: &Path, key_path: &Path) -> Result<(), VaultError> {
    use crate::winplatform::acl::restrict_to_system_and_admins;

    let mut paths = vec![dir.to_path_buf(), key_path.to_path_buf()];
    // A migrated legacy key is plaintext by design (recovery copy) and must not
    // keep inherited `Users` access.
    let legacy = key_path.with_extension("key.legacy");
    if legacy.exists() {
        paths.push(legacy);
    }
    for path in paths {
        restrict_to_system_and_admins(&path).map_err(|e| {
            VaultError::Corrupt(format!(
                "cannot restrict the DACL of `{}` ({e}); refusing to use a vault that other \
                 local users could read (the vault must be on NTFS)",
                path.display()
            ))
        })?;
    }
    Ok(())
}

/// Metadata recorded for a quarantined object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineMeta {
    pub id: String,
    pub original_path: String,
    pub size: u64,
    pub sha256: String,
    pub threat_name: String,
    pub family: Option<String>,
    pub score: u32,
    pub quarantined_unix: u64,
    pub engine_version: String,
    /// Hex nonce; stored in the authenticated header.
    pub nonce: String,
    /// False when the object was copied (e.g. a read-only target).
    pub original_removed: bool,
    /// Why the source was retained, when that was not the caller's choice.
    /// `None` means the removal succeeded or `copy_only` was requested.
    #[serde(default)]
    pub source_retained_reason: Option<String>,
    /// 0 = legacy raw payload, 1 = container with alternate streams. Defaulting
    /// to 0 keeps vaults created before this field readable.
    #[serde(default)]
    pub payload_version: u32,
    /// Original visible timestamps. Defaulted for compatibility with old
    /// headers; `None` means the entry predates timestamp preservation.
    #[serde(default)]
    pub file_times: Option<QuarantineFileTimes>,
    /// Names and sizes of preserved alternate streams. The bytes live inside
    /// the encrypted payload, not in the (unencrypted) header.
    #[serde(default)]
    pub alternate_streams: Vec<StoredStream>,
}

impl QuarantineMeta {
    pub fn age_seconds(&self, now_unix: u64) -> u64 {
        now_unix.saturating_sub(self.quarantined_unix)
    }
}

/// A timestamp with nanosecond precision relative to the Unix epoch. Negative
/// seconds represent timestamps before 1970, which Windows files can have.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredTime {
    pub secs: i64,
    pub nanos: u32,
}

/// Original timestamps for a quarantined object. `None` fields were not
/// available from the filesystem at capture time.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineFileTimes {
    #[serde(default)]
    pub created: Option<StoredTime>,
    #[serde(default)]
    pub accessed: Option<StoredTime>,
    #[serde(default)]
    pub modified: Option<StoredTime>,
}

impl QuarantineFileTimes {
    fn capture(meta: &fs::Metadata) -> Self {
        Self {
            created: meta.created().ok().and_then(system_time_to_stored),
            accessed: meta.accessed().ok().and_then(system_time_to_stored),
            modified: meta.modified().ok().and_then(system_time_to_stored),
        }
    }

    fn is_empty(&self) -> bool {
        self.created.is_none() && self.accessed.is_none() && self.modified.is_none()
    }

    fn to_platform(self) -> Result<crate::winplatform::filemeta::FileTimes, VaultError> {
        Ok(crate::winplatform::filemeta::FileTimes {
            created: stored_time_to_system(self.created)?,
            accessed: stored_time_to_system(self.accessed)?,
            modified: stored_time_to_system(self.modified)?,
        })
    }
}

/// A named stream declared in the authenticated header. The bytes are in the
/// encrypted payload; the size lets `verify_all` detect structural mismatches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredStream {
    pub name: String,
    pub size: u64,
}

/// Decrypted entry contents.
struct EntryPayload {
    data: Vec<u8>,
    streams: Vec<crate::winplatform::filemeta::AlternateStream>,
}

/// One journal record. `intent` is written before a destructive step and `done`
/// after it; recovery only acts on intents that have no matching done record.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalOp {
    op_id: String,
    kind: String,
    id: String,
    target: Option<String>,
    sha256: Option<String>,
    state: String,
    unix: u64,
}

/// What `recover()` changed, preserved or refused to touch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub completed_restores: Vec<String>,
    pub indexed_entries: Vec<String>,
    pub cleaned_indexes: Vec<String>,
    pub reconciled: Vec<String>,
    pub pending: Vec<String>,
    pub conflicts: Vec<String>,
}

/// Persistent, encrypted quarantine store.
pub struct QuarantineVault {
    dir: PathBuf,
    key: VaultKey,
    safety: SafetyGuard,
}

impl QuarantineVault {
    /// Opens (creating if necessary) a vault directory with a key file placed
    /// alongside it.
    pub fn open(dir: &Path, key_path: &Path) -> Result<Self, VaultError> {
        fs::create_dir_all(dir)?;
        let key = VaultKey::load_or_create(key_path)?;
        // Enforced inside the vault, not at each call site: every binary that
        // opens a vault (CLI, daemon, watcher) gets the same DACL or fails.
        #[cfg(windows)]
        protect_vault_paths(dir, key_path)?;
        let vault = QuarantineVault {
            dir: dir.to_path_buf(),
            key,
            safety: SafetyGuard::open(dir),
        };
        // Reconcile interrupted operations without ever deleting user data on a
        // guess. A corrupt journal must not make the vault unopenable.
        let _ = vault.recover();
        Ok(vault)
    }

    /// The safety gate that guards every removal and restore performed by this
    /// vault. Exposed so the CLI and service can report the effective policy and
    /// verify the audit chain.
    pub fn safety(&self) -> &SafetyGuard {
        &self.safety
    }

    fn journal_path(&self) -> PathBuf {
        self.dir.join(JOURNAL_FILE)
    }

    fn append_op(&self, op: &JournalOp) -> Result<(), VaultError> {
        let mut line = serde_json::to_string(op)
            .map_err(|e| VaultError::Corrupt(format!("serialize journal: {e}")))?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.journal_path())?;
        f.write_all(line.as_bytes())?;
        f.sync_data()?;
        Ok(())
    }

    fn new_op_id() -> Result<String, VaultError> {
        let mut raw = [0u8; 8];
        getrandom::getrandom(&mut raw)
            .map_err(|e| VaultError::Corrupt(format!("csprng: {e}")))?;
        Ok(hex(&raw))
    }

    fn journal_intent(
        &self,
        kind: &str,
        id: &str,
        target: Option<&Path>,
        sha256: Option<&str>,
    ) -> Result<String, VaultError> {
        let op_id = Self::new_op_id()?;
        self.append_op(&JournalOp {
            op_id: op_id.clone(),
            kind: kind.to_string(),
            id: id.to_string(),
            target: target.map(|p| p.display().to_string()),
            sha256: sha256.map(|s| s.to_string()),
            state: "intent".into(),
            unix: now_unix(),
        })?;
        Ok(op_id)
    }

    fn journal_done(
        &self,
        op_id: &str,
        kind: &str,
        id: &str,
        target: Option<&Path>,
        sha256: Option<&str>,
    ) -> Result<(), VaultError> {
        self.append_op(&JournalOp {
            op_id: op_id.to_string(),
            kind: kind.to_string(),
            id: id.to_string(),
            target: target.map(|p| p.display().to_string()),
            sha256: sha256.map(|s| s.to_string()),
            state: "done".into(),
            unix: now_unix(),
        })
    }

    /// Reads metadata from an authenticated entry, independent of the index.
    fn meta_from_entry(&self, id: &str) -> Option<QuarantineMeta> {
        let entry = self.entry_path(id);
        self.read_entry_payload(&entry).ok().map(|(meta, _)| meta)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn entry_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.lq"))
    }

    /// Quarantines a file: encrypt → write → verify → remove original.
    ///
    /// `copy_only` keeps the original in place (used for detections where policy
    /// forbids moving the file, e.g. a locked system binary).
    pub fn quarantine_file(
        &self,
        path: &Path,
        threat_name: &str,
        family: Option<&str>,
        score: u32,
        copy_only: bool,
    ) -> Result<QuarantineMeta, VaultError> {
        self.quarantine_file_impl(path, threat_name, family, score, copy_only, None)
    }

    /// Quarantines a file only when its current bytes match `expected_sha256`.
    ///
    /// This binds the vault move to the exact digest the scanner analysed. If
    /// the path changed between the scan and this call, the operation is refused
    /// before writing an entry and the source is left untouched. The source is
    /// kept open, re-hashed through that handle, and deleted by handle, so a
    /// replacement at the path is not deleted. A writer that changes the object
    /// between the copy and the delete is detected by the re-hash and causes the
    /// source to be retained.
    pub fn quarantine_file_checked(
        &self,
        path: &Path,
        expected_sha256: &str,
        threat_name: &str,
        family: Option<&str>,
        score: u32,
        copy_only: bool,
    ) -> Result<QuarantineMeta, VaultError> {
        self.quarantine_file_impl(
            path,
            threat_name,
            family,
            score,
            copy_only,
            Some(expected_sha256),
        )
    }

    fn quarantine_file_impl(
        &self,
        path: &Path,
        threat_name: &str,
        family: Option<&str>,
        score: u32,
        copy_only: bool,
        expected_sha256: Option<&str>,
    ) -> Result<QuarantineMeta, VaultError> {
        // Keep one handle for the whole operation. The handle is what we read,
        // what we will re-hash and what can be marked for deletion, so a path
        // replacement cannot redirect the delete to another object. If DELETE
        // access is unavailable the file is still copied, but the source is
        // retained and reported honestly instead of being removed by path.
        let (mut source_file, delete_capable) =
            crate::winplatform::filemeta::open_source(path, !copy_only)?;
        let source_metadata = source_file.metadata()?;
        let stored_times = QuarantineFileTimes::capture(&source_metadata);
        let identity = crate::winplatform::filemeta::file_identity(&source_file)?;
        let mut data = Vec::new();
        source_file.read_to_end(&mut data)?;
        let digest = sha256_bytes(&data);
        if let Some(expected) = expected_sha256 {
            let actual = digest.to_hex();
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(VaultError::SourceChanged {
                    expected: expected.to_string(),
                    actual,
                });
            }
        }

        // Alternate streams are read by path, so verify that the path still
        // names the object we opened. The subsequent delete is handle-based, so
        // a later replacement is not deleted; this check prevents storing ADS
        // from a different object alongside the original body.
        let streams = crate::winplatform::filemeta::read_alternate_streams(path)?;
        let after_identity = crate::winplatform::filemeta::path_identity(path)?;
        if after_identity != identity {
            return Err(VaultError::SourceChanged {
                expected: digest.to_hex(),
                actual: "file identity changed while alternate streams were read".into(),
            });
        }

        // Refuse a protected or out-of-scope source before writing anything into
        // the vault. The authoritative, digest-bound check runs again immediately
        // before the unlink.
        if !copy_only {
            self.safety
                .check_removal(path, &RemovalScope::Exact(path.to_path_buf()))
                .map_err(|e| VaultError::SafetyRefused(e.to_string()))?;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Random id + nonce.
        let mut rnd = [0u8; 16];
        getrandom::getrandom(&mut rnd).map_err(|e| VaultError::Corrupt(format!("csprng: {e}")))?;
        let id = hex(&rnd);
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| VaultError::Corrupt(format!("csprng: {e}")))?;

        let mut meta = QuarantineMeta {
            id: id.clone(),
            original_path: path.display().to_string(),
            size: data.len() as u64,
            sha256: digest.to_hex(),
            threat_name: threat_name.to_string(),
            family: family.map(|f| f.to_string()),
            score,
            quarantined_unix: now,
            engine_version: crate::ENGINE_VERSION.to_string(),
            nonce: hex(&nonce),
            original_removed: false,
            source_retained_reason: None,
            payload_version: PAYLOAD_VERSION_CONTAINER,
            file_times: if stored_times.is_empty() {
                None
            } else {
                Some(stored_times)
            },
            alternate_streams: streams
                .iter()
                .map(|s| StoredStream {
                    name: s.name.clone(),
                    size: s.data.len() as u64,
                })
                .collect(),
        };

        let header = serde_json::to_vec(&meta)
            .map_err(|e| VaultError::Corrupt(format!("serialize header: {e}")))?;
        let payload = encode_payload(&data, &streams)?;
        let ciphertext = self.encrypt(&payload, &nonce, &header)?;

        let entry = self.entry_path(&id);
        let tmp = entry.with_extension("lq.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(VAULT_MAGIC)?;
            f.write_all(&(header.len() as u32).to_le_bytes())?;
            f.write_all(&header)?;
            f.write_all(&ciphertext)?;
            f.sync_all()?;
        }

        // Verify by reading back the *temp* copy and decrypting it before the
        // original is touched. (Reading `entry` here would race the rename.)
        let restored = self.read_entry_payload(&tmp).inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
        let verify_digest = sha256_bytes(&restored.1.data);
        if verify_digest != digest {
            let _ = fs::remove_file(&tmp);
            return Err(VaultError::IntegrityMismatch {
                expected: digest.to_hex(),
                actual: verify_digest.to_hex(),
            });
        }
        if !streams_equal(&restored.1.streams, &streams)
            || restored.0.file_times != meta.file_times
        {
            let _ = fs::remove_file(&tmp);
            return Err(VaultError::Corrupt(
                "quarantine entry did not preserve the captured ADS/timestamps".into(),
            ));
        }
        fs::rename(&tmp, &entry)?;

        // Journal the intent before touching the source or the index, so a crash
        // can be reconciled without guessing whether the original was removed.
        let op_id = match self.journal_intent("quarantine", &id, Some(path), Some(&meta.sha256))
        {
            Ok(op) => op,
            Err(e) => {
                let _ = fs::remove_file(&entry);
                return Err(e);
            }
        };

        // Index first with the conservative flag, so the entry is visible even if
        // the process dies before the source is removed.
        self.update_index(&meta, true)?;

        if !copy_only {
            if !delete_capable {
                meta.original_removed = false;
                meta.source_retained_reason = Some(
                    "the source could not be opened with delete access; the vault copy was kept and the source was not touched".into(),
                );
            } else {
                // Re-hash the exact opened object before deleting it. The path
                // may have been replaced; that must not lead to deleting a
                // different file, and content changed after the copy must not be
                // destroyed while the vault holds only the older bytes.
                let unchanged = sha256_open_file(&mut source_file)
                    .map(|d| d == digest)
                    .unwrap_or(false);
                let path_still_same = crate::winplatform::filemeta::path_identity(path)
                    .map(|current| current == identity)
                    .unwrap_or(false);
                if !unchanged || !path_still_same {
                    meta.original_removed = false;
                    meta.source_retained_reason = Some(if !unchanged {
                        "the source changed after it was copied; the original was retained".into()
                    } else {
                        "the source path identity changed after it was copied; the original was retained".into()
                    });
                } else {
                    let scope = RemovalScope::Exact(path.to_path_buf());
                    match self.safety.authorize_removal(path, Some(&meta.sha256), &scope) {
                        Ok(permit) => match crate::winplatform::filemeta::delete_by_handle(
                            &source_file,
                        ) {
                            Ok(()) => {
                                meta.original_removed = true;
                                permit.finish(
                                    true,
                                    "source removed by identity-checked handle after digest re-verification",
                                );
                            }
                            Err(e) => {
                                meta.original_removed = false;
                                meta.source_retained_reason =
                                    Some(format!("the original could not be removed: {e}"));
                                permit.finish(false, &format!("handle delete failed: {e}"));
                            }
                        },
                        Err(e) => {
                            // The encrypted copy exists and the source is untouched.
                            // This is reported honestly as a retained source, not a move.
                            meta.original_removed = false;
                            meta.source_retained_reason = Some(e.to_string());
                        }
                    }
                }
            }
            // The first index row was published before removal. This refresh is
            // best-effort: once the source is gone, an index write error must not
            // be reported as a failed quarantine. The encrypted entry remains and
            // can be found by id/recovered; returning Err here would falsely imply
            // the source was retained.
            let _ = self.update_index(&meta, true);
        }
        // Complete a delete-on-close before reporting success. A replacement at
        // the path is not affected because deletion was bound to this handle.
        drop(source_file);

        let _ = self.journal_done(&op_id, "quarantine", &id, Some(path), Some(&meta.sha256));
        Ok(meta)
    }

    /// Metadata for one entry, from the index or the authenticated header.
    pub fn inspect(&self, id: &str) -> Result<QuarantineMeta, VaultError> {
        self.list()
            .into_iter()
            .find(|m| m.id == id)
            .or_else(|| self.meta_from_entry(id))
            .ok_or_else(|| VaultError::NotFound(format!("no quarantine entry `{id}`")))
    }

    /// Reconciles interrupted operations. Idempotent; never deletes user files.
    pub fn recover(&self) -> Result<RecoveryReport, VaultError> {
        let raw = match fs::read_to_string(self.journal_path()) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RecoveryReport::default()),
            Err(e) => return Err(e.into()),
        };
        let ops: Vec<JournalOp> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let done: HashSet<&str> = ops
            .iter()
            .filter(|o| o.state == "done")
            .map(|o| o.op_id.as_str())
            .collect();
        let mut report = RecoveryReport::default();
        for op in ops.iter().filter(|o| o.state == "intent" && !done.contains(o.op_id.as_str())) {
            match op.kind.as_str() {
                "restore" => self.recover_restore(op, &mut report)?,
                "purge" => self.recover_purge(op, &mut report)?,
                "quarantine" => self.recover_quarantine(op, &mut report)?,
                other => report.conflicts.push(format!(
                    "unknown journal operation `{other}` for {}; left untouched",
                    op.id
                )),
            }
            let _ = self.append_op(&JournalOp {
                state: "done".into(),
                ..op.clone()
            });
        }
        Ok(report)
    }

    fn recover_restore(
        &self,
        op: &JournalOp,
        report: &mut RecoveryReport,
    ) -> Result<(), VaultError> {
        let Some(target) = op.target.as_ref().map(PathBuf::from) else {
            report.conflicts.push(format!("restore {} has no target; entry preserved", op.id));
            return Ok(());
        };
        let meta = self
            .list()
            .into_iter()
            .find(|m| m.id == op.id)
            .or_else(|| self.meta_from_entry(&op.id));
        let expected = op
            .sha256
            .clone()
            .or_else(|| meta.as_ref().map(|m| m.sha256.clone()));
        let entry = self.entry_path(&op.id);
        if target.exists() {
            let got = match fs::read(&target) {
                Ok(bytes) => sha256_bytes(&bytes).to_hex(),
                Err(e) => {
                    report.conflicts.push(format!(
                        "cannot read restore target `{}` for {}: {e}; both preserved",
                        target.display(),
                        op.id
                    ));
                    return Ok(());
                }
            };
            if Some(&got) == expected.as_ref() {
                if entry.exists() {
                    // Finish the metadata half of the interrupted restore before
                    // deleting the only remaining copy. If ADS or timestamps
                    // cannot be applied, keep both files and report a conflict.
                    match self.read_entry_payload(&entry) {
                        Ok((header_meta, payload)) => {
                            if header_meta.sha256 != got {
                                report.conflicts.push(format!(
                                    "interrupted restore {}: authenticated digest differs from the target; both preserved",
                                    op.id
                                ));
                                return Ok(());
                            }
                            if let Err(e) = apply_payload_metadata(
                                &target,
                                &header_meta,
                                &payload.streams,
                            ) {
                                report.conflicts.push(format!(
                                    "interrupted restore {}: cannot apply ADS/timestamps to `{}`: {e}; both preserved",
                                    op.id,
                                    target.display()
                                ));
                                return Ok(());
                            }
                            fs::remove_file(&entry)?;
                            self.update_index(&header_meta, false)?;
                        }
                        Err(e) => {
                            report.conflicts.push(format!(
                                "interrupted restore {}: authenticated entry is unreadable ({e}); both preserved",
                                op.id
                            ));
                            return Ok(());
                        }
                    }
                } else if let Some(meta) = &meta {
                    self.update_index(meta, false)?;
                }
                report.completed_restores.push(op.id.clone());
            } else {
                report.conflicts.push(format!(
                    "interrupted restore {}: `{}` exists with different content; entry and target preserved",
                    op.id,
                    target.display()
                ));
            }
        } else {
            report.pending.push(format!(
                "interrupted restore {}: target missing; entry preserved for a retry",
                op.id
            ));
        }
        Ok(())
    }

    fn recover_quarantine(
        &self,
        op: &JournalOp,
        report: &mut RecoveryReport,
    ) -> Result<(), VaultError> {
        let entry = self.entry_path(&op.id);
        let meta = self.list().into_iter().find(|m| m.id == op.id);
        if entry.exists() {
            match meta {
                None => {
                    if let Some(meta) = self.meta_from_entry(&op.id) {
                        self.update_index(&meta, true)?;
                        report.indexed_entries.push(op.id.clone());
                    } else {
                        report.conflicts.push(format!(
                            "quarantine {} has an unreadable entry; manual recovery required",
                            op.id
                        ));
                    }
                }
                Some(mut meta) => {
                    if let Some(original) = op.target.as_ref() {
                        if !meta.original_removed && !Path::new(original).exists() {
                            meta.original_removed = true;
                            self.update_index(&meta, true)?;
                            report.reconciled.push(op.id.clone());
                        }
                    }
                }
            }
        } else if meta.is_some() {
            let original_exists = op
                .target
                .as_ref()
                .map(|p| Path::new(p).exists())
                .unwrap_or(false);
            if original_exists {
                self.update_index(&meta.unwrap(), false)?;
                report.cleaned_indexes.push(op.id.clone());
            } else {
                report.conflicts.push(format!(
                    "quarantine {} has no entry and its source is missing; manual recovery required",
                    op.id
                ));
            }
        }
        Ok(())
    }

    fn recover_purge(
        &self,
        op: &JournalOp,
        report: &mut RecoveryReport,
    ) -> Result<(), VaultError> {
        let entry = self.entry_path(&op.id);
        let meta = self.list().into_iter().find(|m| m.id == op.id);
        if !entry.exists() {
            if let Some(meta) = meta {
                self.update_index(&meta, false)?;
                report.cleaned_indexes.push(op.id.clone());
            }
        } else if meta.is_none() {
            if let Some(meta) = self.meta_from_entry(&op.id) {
                self.update_index(&meta, true)?;
                report.indexed_entries.push(op.id.clone());
            }
        }
        Ok(())
    }

    /// Decrypts one entry and returns its authenticated header, body and named
    /// streams. The header is the authority; the JSON index is never trusted for
    /// a restore target.
    fn read_entry_payload(
        &self,
        entry: &Path,
    ) -> Result<(QuarantineMeta, EntryPayload), VaultError> {
        let raw = fs::read(entry)?;
        if raw.len() < VAULT_MAGIC.len() + 4 || &raw[..VAULT_MAGIC.len()] != VAULT_MAGIC {
            return Err(VaultError::Corrupt("bad vault magic".into()));
        }
        let hlen_off = VAULT_MAGIC.len();
        let hlen = u32::from_le_bytes([
            raw[hlen_off],
            raw[hlen_off + 1],
            raw[hlen_off + 2],
            raw[hlen_off + 3],
        ]) as usize;
        let hstart = hlen_off + 4;
        let hend = hstart
            .checked_add(hlen)
            .ok_or_else(|| VaultError::Corrupt("header length overflow".into()))?;
        if hend > raw.len() {
            return Err(VaultError::Corrupt("header length out of bounds".into()));
        }
        let header = &raw[hstart..hend];
        let ciphertext = &raw[hend..];

        let meta: QuarantineMeta = serde_json::from_slice(header)
            .map_err(|e| VaultError::Corrupt(format!("header json: {e}")))?;
        let nonce_bytes = unhex(&meta.nonce)
            .ok_or_else(|| VaultError::Corrupt("bad nonce encoding".into()))?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(VaultError::Corrupt("bad nonce length".into()));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);
        let plain = self.decrypt(ciphertext, &nonce, header)?;
        let payload = decode_payload(&plain, &meta)?;
        let digest = sha256_bytes(&payload.data);
        if digest.to_hex() != meta.sha256 {
            return Err(VaultError::IntegrityMismatch {
                expected: meta.sha256.clone(),
                actual: digest.to_hex(),
            });
        }
        Ok((meta, payload))
    }

    /// Decrypts one entry and returns its main file bytes (not alternate
    /// streams). Kept as a small public API for callers that only need content.
    pub fn read_entry_bytes(&self, entry: &Path) -> Result<Vec<u8>, VaultError> {
        Ok(self.read_entry_payload(entry)?.1.data)
    }

    /// Restores an entry to `dest` (or its original path when `dest` is None).
    ///
    /// Writes a temp file in the destination directory, verifies it, then renames
    /// into place. An existing destination is refused before anything is written.
    /// The journal intent is written first so a crash can be reconciled.
    pub fn restore(&self, id: &str, dest: Option<&Path>) -> Result<PathBuf, VaultError> {
        let entry = self.entry_path(id);
        if !entry.exists() {
            return Err(VaultError::NotFound(format!(
                "no quarantine entry `{id}`; it may already be restored or purged"
            )));
        }
        // The authenticated header is authoritative for the original path,
        // digest and metadata. The JSON index is not authenticated and must not
        // be able to redirect a restore.
        let (meta, payload) = self.read_entry_payload(&entry)?;
        let bytes = payload.data;
        let streams = payload.streams;

        let target = match dest {
            Some(p) => p.to_path_buf(),
            None => PathBuf::from(&meta.original_path),
        };
        if target.exists() {
            return Err(VaultError::Conflict(format!(
                "refusing to overwrite existing file {}",
                target.display()
            )));
        }
        // Restoring user data is a recovery operation, so a broken audit chain
        // does not block it. It must still refuse a protected destination.
        self.safety
            .authorize_write(&target, "restore")
            .map_err(|e| VaultError::SafetyRefused(e.to_string()))?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = target
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!(".litric-{id}.restore.tmp"));
        let _ = fs::remove_file(&tmp);

        let op_id = self.journal_intent("restore", id, Some(&target), Some(&meta.sha256))?;
        let result = (|| -> Result<(), VaultError> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            // Close the handle before hard-linking/removing the temp file. Windows
            // refuses some of those operations while a file is still open.
            drop(f);
            let written = fs::read(&tmp)?;
            if sha256_bytes(&written).to_hex() != meta.sha256 {
                return Err(VaultError::IntegrityMismatch {
                    expected: meta.sha256.clone(),
                    actual: sha256_bytes(&written).to_hex(),
                });
            }
            // Restore ADS before publishing. A hard link shares the file object,
            // so the streams and timestamps are already attached to the target
            // and no post-publish mutation is needed.
            write_streams_and_verify(&tmp, &streams)?;
            apply_entry_times(&tmp, &meta)?;

            // Publish without clobbering: hard_link fails atomically if the
            // target appeared after the pre-check. The temp file is in the
            // target's directory, so both are on the same filesystem. If the
            // filesystem has no hard links, fall back to create_new + write,
            // which is still an atomic no-clobber create.
            match fs::hard_link(&tmp, &target) {
                Ok(()) => {
                    let _ = fs::remove_file(&tmp);
                }
                Err(_) if target.exists() => {
                    return Err(VaultError::Conflict(format!(
                        "refusing to overwrite existing file {}",
                        target.display()
                    )));
                }
                Err(_) => {
                    let mut out = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&target)
                        .map_err(|e| {
                            if e.kind() == std::io::ErrorKind::AlreadyExists {
                                VaultError::Conflict(format!(
                                    "refusing to overwrite existing file {}",
                                    target.display()
                                ))
                            } else {
                                VaultError::Io(e)
                            }
                        })?;
                    let write_result = out.write_all(&bytes).and_then(|_| out.sync_all());
                    drop(out);
                    if let Err(e) = write_result {
                        let _ = fs::remove_file(&target);
                        return Err(VaultError::Io(e));
                    }
                    let copied = (|| -> Result<(), VaultError> {
                        write_streams_and_verify(&target, &streams)?;
                        let final_bytes = fs::read(&target)?;
                        if sha256_bytes(&final_bytes).to_hex() != meta.sha256 {
                            return Err(VaultError::IntegrityMismatch {
                                expected: meta.sha256.clone(),
                                actual: sha256_bytes(&final_bytes).to_hex(),
                            });
                        }
                        // Apply timestamps last: verification reads can update
                        // last-access time on filesystems that track it.
                        apply_entry_times(&target, &meta)?;
                        Ok(())
                    })();
                    if let Err(e) = copied {
                        let _ = fs::remove_file(&target);
                        let _ = fs::remove_file(&tmp);
                        return Err(e);
                    }
                    let _ = fs::remove_file(&tmp);
                }
            }
            fs::remove_file(&entry)?;
            self.update_index(&meta, false)?;
            Ok(())
        })();
        match &result {
            Ok(()) => {
                let _ = self.journal_done(&op_id, "restore", id, Some(&target), Some(&meta.sha256));
                let _ = self.safety.audit_event(
                    "restore",
                    "completed",
                    &target,
                    Some(&meta.sha256),
                    "restored and re-hashed",
                );
            }
            Err(e) => {
                // Leave the intent in place so recovery can finish or report it.
                let _ = fs::remove_file(&tmp);
                let _ = self.safety.audit_event(
                    "restore",
                    "failed",
                    &target,
                    Some(&meta.sha256),
                    &e.to_string(),
                );
            }
        }
        result?;
        Ok(target)
    }

    /// Lists quarantine metadata (index is authoritative; entries are verified
    /// for existence).
    pub fn list(&self) -> Vec<QuarantineMeta> {
        let path = self.dir.join(INDEX_FILE);
        let Ok(raw) = fs::read(path) else {
            return Vec::new();
        };
        serde_json::from_slice::<Vec<QuarantineMeta>>(&raw).unwrap_or_default()
    }

    /// Verifies every entry decrypts and matches its recorded hash.
    pub fn verify_all(&self) -> Vec<(String, bool, String)> {
        let mut out = Vec::new();
        for meta in self.list() {
            let entry = self.entry_path(&meta.id);
            match self.read_entry_payload(&entry) {
                Ok(_) => out.push((meta.id.clone(), true, "integrity ok".into())),
                Err(e) => out.push((meta.id.clone(), false, e.to_string())),
            }
        }
        out
    }

    /// Permanently removes an entry. Irreversible; callers must confirm with the
    /// user first. Journaled so a crash between unlink and index update is
    /// reconciled instead of leaving a ghost entry.
    pub fn purge(&self, id: &str) -> Result<(), VaultError> {
        let entry = self.entry_path(id);
        let meta = self.list().into_iter().find(|m| m.id == id);
        if !entry.exists() && meta.is_none() {
            return Err(VaultError::NotFound(format!(
                "no quarantine entry `{id}`; it may already be restored or purged"
            )));
        }
        self.safety
            .authorize_purge(id, &entry)
            .map_err(|e| VaultError::SafetyRefused(e.to_string()))?;
        let op_id = self.journal_intent("purge", id, None, None)?;
        if entry.exists() {
            fs::remove_file(&entry)?;
        }
        if let Some(meta) = meta {
            self.update_index(&meta, false)?;
        }
        let _ = self.journal_done(&op_id, "purge", id, None, None);
        let _ = self.safety.audit_event(
            "purge",
            "completed",
            &entry,
            None,
            &format!("quarantine id {id} permanently removed after explicit confirmation"),
        );
        Ok(())
    }

    fn encrypt(
        &self,
        plain: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key.0));
        cipher
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: plain,
                    aad,
                },
            )
            .map_err(|_| VaultError::Authentication)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key.0));
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| VaultError::Authentication)
    }

    fn update_index(&self, meta: &QuarantineMeta, add: bool) -> Result<(), VaultError> {
        let mut entries = self.list();
        entries.retain(|m| m.id != meta.id);
        if add {
            entries.push(meta.clone());
        }
        let json = serde_json::to_vec_pretty(&entries)
            .map_err(|e| VaultError::Corrupt(format!("serialize index: {e}")))?;
        let path = self.dir.join(INDEX_FILE);
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}

fn sha256_open_file(file: &mut fs::File) -> io::Result<crate::hash::Digest32> {
    use sha2::{Digest, Sha256};
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    Ok(crate::hash::Digest32(digest))
}

fn system_time_to_stored(t: SystemTime) -> Option<StoredTime> {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => Some(StoredTime {
            secs: i64::try_from(d.as_secs()).ok()?,
            nanos: d.subsec_nanos(),
        }),
        Err(e) => {
            let d = e.duration();
            let secs = i64::try_from(d.as_secs()).ok()?;
            if d.subsec_nanos() == 0 {
                Some(StoredTime {
                    secs: secs.checked_neg()?,
                    nanos: 0,
                })
            } else {
                Some(StoredTime {
                    secs: secs.checked_neg()?.checked_sub(1)?,
                    nanos: 1_000_000_000 - d.subsec_nanos(),
                })
            }
        }
    }
}

fn stored_time_to_system(t: Option<StoredTime>) -> Result<Option<SystemTime>, VaultError> {
    let Some(t) = t else {
        return Ok(None);
    };
    if t.nanos >= 1_000_000_000 {
        return Err(VaultError::Corrupt("timestamp nanoseconds out of range".into()));
    }
    let value = if t.secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(t.secs as u64, t.nanos))
    } else {
        let abs = t.secs.unsigned_abs();
        if t.nanos == 0 {
            UNIX_EPOCH.checked_sub(Duration::new(abs, 0))
        } else {
            UNIX_EPOCH.checked_sub(Duration::new(
                abs.checked_sub(1).ok_or_else(|| {
                    VaultError::Corrupt("timestamp range underflow".into())
                })?,
                1_000_000_000 - t.nanos,
            ))
        }
    };
    value
        .map(Some)
        .ok_or_else(|| VaultError::Corrupt("timestamp is outside the supported range".into()))
}

fn encode_payload(
    data: &[u8],
    streams: &[crate::winplatform::filemeta::AlternateStream],
) -> Result<Vec<u8>, VaultError> {
    if streams.len() > crate::winplatform::filemeta::MAX_ALTERNATE_STREAMS {
        return Err(VaultError::Corrupt("too many alternate streams".into()));
    }
    let mut total = 0u64;
    let mut out = Vec::with_capacity(PAYLOAD_MAGIC.len() + 4 + 8 + data.len());
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&(streams.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
    for stream in streams {
        let name = crate::winplatform::filemeta::validate_stream_name(&stream.name)
            .map_err(VaultError::Corrupt)?;
        if name != stream.name {
            return Err(VaultError::Corrupt(format!(
                "alternate stream name was not normalized: {}",
                stream.name
            )));
        }
        if name.len() > u16::MAX as usize {
            return Err(VaultError::Corrupt("alternate stream field overflow".into()));
        }
        total = total
            .checked_add(stream.data.len() as u64)
            .ok_or_else(|| VaultError::Corrupt("alternate-stream total overflow".into()))?;
        if total > crate::winplatform::filemeta::MAX_ALTERNATE_TOTAL_BYTES {
            return Err(VaultError::Corrupt(
                "alternate streams exceed the total size limit".into(),
            ));
        }
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(stream.data.len() as u64).to_le_bytes());
        out.extend_from_slice(&stream.data);
    }
    Ok(out)
}

fn take_bytes<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], VaultError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| VaultError::Corrupt("payload length overflow".into()))?;
    if end > input.len() {
        return Err(VaultError::Corrupt("payload length out of bounds".into()));
    }
    let slice = &input[*pos..end];
    *pos = end;
    Ok(slice)
}

fn take_u16(input: &[u8], pos: &mut usize) -> Result<u16, VaultError> {
    let b = take_bytes(input, pos, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn take_u32(input: &[u8], pos: &mut usize) -> Result<u32, VaultError> {
    let b = take_bytes(input, pos, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn take_u64(input: &[u8], pos: &mut usize) -> Result<u64, VaultError> {
    let b = take_bytes(input, pos, 8)?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn decode_payload(plain: &[u8], meta: &QuarantineMeta) -> Result<EntryPayload, VaultError> {
    if meta.payload_version == PAYLOAD_VERSION_RAW {
        if !meta.alternate_streams.is_empty() {
            return Err(VaultError::Corrupt(
                "legacy payload unexpectedly declares alternate streams".into(),
            ));
        }
        return Ok(EntryPayload {
            data: plain.to_vec(),
            streams: Vec::new(),
        });
    }
    if meta.payload_version != PAYLOAD_VERSION_CONTAINER {
        return Err(VaultError::Corrupt(format!(
            "unsupported quarantine payload version {}",
            meta.payload_version
        )));
    }
    if plain.len() < PAYLOAD_MAGIC.len() + 4 + 8 || &plain[..PAYLOAD_MAGIC.len()] != PAYLOAD_MAGIC {
        return Err(VaultError::Corrupt("bad payload magic".into()));
    }
    let mut pos = PAYLOAD_MAGIC.len();
    let count = take_u32(plain, &mut pos)? as usize;
    if count > crate::winplatform::filemeta::MAX_ALTERNATE_STREAMS {
        return Err(VaultError::Corrupt("too many alternate streams".into()));
    }
    if count != meta.alternate_streams.len() {
        return Err(VaultError::Corrupt(
            "payload stream count does not match the header".into(),
        ));
    }
    let main_len = take_u64(plain, &mut pos)?;
    if main_len != meta.size {
        return Err(VaultError::Corrupt(
            "payload body length does not match the header".into(),
        ));
    }
    let main_len = usize::try_from(main_len)
        .map_err(|_| VaultError::Corrupt("payload body length is too large".into()))?;
    let data = take_bytes(plain, &mut pos, main_len)?.to_vec();
    let mut streams = Vec::with_capacity(count);
    let mut total = 0u64;
    for declared in &meta.alternate_streams {
        let name_len = take_u16(plain, &mut pos)? as usize;
        if name_len == 0 || name_len > 255 {
            return Err(VaultError::Corrupt("invalid alternate-stream name length".into()));
        }
        let name = String::from_utf8(take_bytes(plain, &mut pos, name_len)?.to_vec())
            .map_err(|_| VaultError::Corrupt("alternate-stream name is not UTF-8".into()))?;
        let name = crate::winplatform::filemeta::validate_stream_name(&name)
            .map_err(VaultError::Corrupt)?;
        let len = take_u64(plain, &mut pos)?;
        if len > crate::winplatform::filemeta::MAX_ALTERNATE_STREAM_BYTES {
            return Err(VaultError::Corrupt(
                "alternate stream exceeds the per-stream size limit".into(),
            ));
        }
        total = total
            .checked_add(len)
            .ok_or_else(|| VaultError::Corrupt("alternate-stream total overflow".into()))?;
        if total > crate::winplatform::filemeta::MAX_ALTERNATE_TOTAL_BYTES {
            return Err(VaultError::Corrupt(
                "alternate streams exceed the total size limit".into(),
            ));
        }
        let len = usize::try_from(len)
            .map_err(|_| VaultError::Corrupt("alternate stream length is too large".into()))?;
        let data = take_bytes(plain, &mut pos, len)?.to_vec();
        if name != declared.name || data.len() as u64 != declared.size {
            return Err(VaultError::Corrupt(
                "alternate-stream metadata does not match the header".into(),
            ));
        }
        streams.push(crate::winplatform::filemeta::AlternateStream { name, data });
    }
    if pos != plain.len() {
        return Err(VaultError::Corrupt("trailing bytes in quarantine payload".into()));
    }
    Ok(EntryPayload { data, streams })
}

fn streams_equal(
    a: &[crate::winplatform::filemeta::AlternateStream],
    b: &[crate::winplatform::filemeta::AlternateStream],
) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| {
            x.name.eq_ignore_ascii_case(&y.name) && x.data == y.data
        })
}

fn write_streams_and_verify(
    path: &Path,
    streams: &[crate::winplatform::filemeta::AlternateStream],
) -> Result<(), VaultError> {
    if streams.is_empty() {
        return Ok(());
    }
    crate::winplatform::filemeta::write_alternate_streams(path, streams)?;
    let actual = crate::winplatform::filemeta::read_alternate_streams(path)?;
    if !streams_equal(&actual, streams) {
        return Err(VaultError::IntegrityMismatch {
            expected: format!("{} preserved alternate streams", streams.len()),
            actual: format!("{} alternate streams after write", actual.len()),
        });
    }
    Ok(())
}

fn apply_entry_times(path: &Path, meta: &QuarantineMeta) -> Result<(), VaultError> {
    if let Some(times) = &meta.file_times {
        crate::winplatform::filemeta::apply_file_times(path, &times.to_platform()?)?;
    }
    Ok(())
}

fn apply_payload_metadata(
    path: &Path,
    meta: &QuarantineMeta,
    streams: &[crate::winplatform::filemeta::AlternateStream],
) -> Result<(), VaultError> {
    write_streams_and_verify(path, streams)?;
    apply_entry_times(path, meta)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)? as u8;
        let lo = (bytes[i + 1] as char).to_digit(16)? as u8;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_base(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "litric-vault-{}-{}-{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn vault(tag: &str) -> (QuarantineVault, PathBuf) {
        let base = fresh_base(tag);
        let dir = base.join("quarantine");
        let key = base.join("vault.key");
        (QuarantineVault::open(&dir, &key).unwrap(), base)
    }

    #[cfg(windows)]
    #[test]
    fn a_new_key_file_is_dpapi_wrapped_and_reopens() {
        let (v, base) = vault("keywrap");
        drop(v);
        let key_path = base.join("vault.key");
        let stored = fs::read(&key_path).unwrap();
        assert!(
            stored.starts_with(KEY_FILE_MAGIC),
            "a new key must be DPAPI-wrapped, not plaintext"
        );
        assert!(
            stored.len() > KEY_FILE_MAGIC.len() + MASTER_KEY_LEN,
            "wrapped file should contain a DPAPI blob"
        );

        let reopened = QuarantineVault::open(&base.join("quarantine"), &key_path).unwrap();
        assert_eq!(reopened.list().len(), 0);
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn vault_and_key_get_a_protected_dacl() {
        let (v, base) = vault("acldir");
        drop(v);
        for path in [base.join("quarantine"), base.join("vault.key")] {
            let sddl = crate::winplatform::acl::dacl_sddl(&path).unwrap();
            assert!(sddl.starts_with("D:P"), "{}: {sddl}", path.display());
            for sid in ["SY", "BA", "OW"] {
                assert!(
                    sddl.contains(&format!("(A;OICI;FA;;;{sid})")),
                    "{} missing {sid}: {sddl}",
                    path.display()
                );
            }
            assert!(
                !sddl.contains(";;;BU)") && !sddl.contains(";;;WD)"),
                "{} still grants Users/Everyone: {sddl}",
                path.display()
            );
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn a_legacy_plaintext_key_is_upgraded_and_kept_as_backup() {
        let base = fresh_base("keymigrate");
        let key_path = base.join("vault.key");
        let legacy = [9u8; MASTER_KEY_LEN];
        fs::write(&key_path, legacy).unwrap();

        let dir = base.join("quarantine");
        let v = QuarantineVault::open(&dir, &key_path).unwrap();
        let stored = fs::read(&key_path).unwrap();
        assert!(
            stored.starts_with(KEY_FILE_MAGIC),
            "legacy key should have been wrapped in place"
        );
        assert_eq!(
            fs::read(base.join("vault.key.legacy")).unwrap(),
            legacy,
            "the original bytes must be preserved for recovery"
        );

        // The migrated key must still decrypt existing content.
        let sample = base.join("sample.bin");
        fs::write(&sample, b"content protected by the legacy key").unwrap();
        let meta = v
            .quarantine_file(&sample, "Test.Legacy", None, 50, false)
            .unwrap();
        drop(v);
        let reopened = QuarantineVault::open(&dir, &key_path).unwrap();
        let restored = reopened
            .restore(&meta.id, Some(&base.join("restored.bin")))
            .unwrap();
        assert_eq!(
            fs::read(restored).unwrap(),
            b"content protected by the legacy key"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn a_corrupt_wrapped_key_is_rejected_without_being_rewritten() {
        let base = fresh_base("keycorrupt");
        let key_path = base.join("vault.key");
        let mut broken = KEY_FILE_MAGIC.to_vec();
        broken.extend_from_slice(&[0xAB; 48]);
        fs::write(&key_path, &broken).unwrap();

        let err = match QuarantineVault::open(&base.join("quarantine"), &key_path) {
            Ok(_) => panic!("a corrupt wrapped key must not open the vault"),
            Err(e) => e,
        };
        assert!(
            format!("{err}").contains("cannot be unwrapped"),
            "error must explain the key problem: {err}"
        );
        assert_eq!(fs::read(&key_path).unwrap(), broken, "key file was modified");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn quarantine_preserves_alternate_streams_and_timestamps() {
        let (v, base) = vault("ads-times");
        let sample = base.join("sample.bin");
        let content = b"content with ADS metadata";
        fs::write(&sample, content).unwrap();
        let streams = vec![
            crate::winplatform::filemeta::AlternateStream {
                name: ":Zone.Identifier:$DATA".into(),
                data: b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec(),
            },
            crate::winplatform::filemeta::AlternateStream {
                name: ":LitricTest:$DATA".into(),
                data: vec![0, 1, 2, 255],
            },
        ];
        crate::winplatform::filemeta::write_alternate_streams(&sample, &streams).unwrap();
        let stamp = UNIX_EPOCH + Duration::from_secs(1_690_000_123);
        crate::winplatform::filemeta::apply_file_times(
            &sample,
            &crate::winplatform::filemeta::FileTimes {
                created: Some(stamp),
                accessed: Some(stamp),
                modified: Some(stamp),
            },
        )
        .unwrap();

        let meta = v
            .quarantine_file(&sample, "Test.Ads", None, 80, false)
            .expect("quarantine with ADS");
        assert!(meta.original_removed, "{:?}", meta.source_retained_reason);
        assert_eq!(meta.payload_version, PAYLOAD_VERSION_CONTAINER);
        assert_eq!(meta.alternate_streams.len(), 2);
        assert!(meta.file_times.is_some(), "timestamps were not recorded");

        let restored = v
            .restore(&meta.id, Some(&base.join("restored.bin")))
            .expect("restore with ADS");
        assert_eq!(fs::read(&restored).unwrap(), content);
        let actual = crate::winplatform::filemeta::read_alternate_streams(&restored).unwrap();
        let mut expected = streams.clone();
        expected.sort_by_key(|s| s.name.to_ascii_lowercase());
        assert_eq!(actual, expected, "alternate streams were not restored");

        let times = crate::winplatform::filemeta::capture_file_times(
            &fs::File::open(&restored).unwrap(),
        )
        .unwrap();
        for (label, actual) in [
            ("created", times.created),
            ("modified", times.modified),
        ] {
            let actual = actual.unwrap_or_else(|| panic!("{label} timestamp missing"));
            assert_eq!(
                actual.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                1_690_000_123,
                "{label} timestamp was not restored"
            );
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn legacy_raw_entries_without_new_metadata_still_restore() {
        let (v, base) = vault("legacy-payload");
        let content = b"legacy raw payload";
        let mut meta = QuarantineMeta {
            id: "legacy-entry".into(),
            original_path: base.join("original.bin").display().to_string(),
            size: content.len() as u64,
            sha256: sha256_bytes(content).to_hex(),
            threat_name: "Test.Legacy".into(),
            family: None,
            score: 50,
            quarantined_unix: 1,
            engine_version: "legacy".into(),
            nonce: hex(&[7u8; NONCE_LEN]),
            original_removed: true,
            source_retained_reason: None,
            payload_version: PAYLOAD_VERSION_RAW,
            file_times: None,
            alternate_streams: Vec::new(),
        };
        let mut header_value = serde_json::to_value(&meta).unwrap();
        // Simulate a header written before payload_version/file_times/ADS existed.
        for field in ["payload_version", "file_times", "alternate_streams"] {
            header_value.as_object_mut().unwrap().remove(field);
        }
        let header = serde_json::to_vec(&header_value).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&unhex(&meta.nonce).unwrap());
        let ciphertext = v.encrypt(content, &nonce, &header).unwrap();
        let entry = v.entry_path(&meta.id);
        let mut raw = Vec::new();
        raw.extend_from_slice(VAULT_MAGIC);
        raw.extend_from_slice(&(header.len() as u32).to_le_bytes());
        raw.extend_from_slice(&header);
        raw.extend_from_slice(&ciphertext);
        fs::write(&entry, raw).unwrap();
        v.update_index(&meta, true).unwrap();
        // The header is authoritative even though the index row is present.
        meta.payload_version = PAYLOAD_VERSION_RAW;

        let restored = v
            .restore(&meta.id, Some(&base.join("legacy-restored.bin")))
            .expect("legacy entry must still restore");
        assert_eq!(fs::read(restored).unwrap(), content);
        assert!(v.list().is_empty());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn roundtrip_quarantine_and_restore() {
        let (v, base) = vault("rt");
        let sample = base.join("malware.bin");
        let content = b"pretend this is malware \x00\x01\x02";
        fs::write(&sample, content).unwrap();

        let meta = v
            .quarantine_file(&sample, "Test.Threat", Some("TestFam"), 90, false)
            .unwrap();
        assert!(
            !sample.exists(),
            "original must be removed: {:?}",
            meta.source_retained_reason
        );
        assert_eq!(meta.sha256, sha256_bytes(content).to_hex());
        assert_eq!(v.list().len(), 1);

        // Ciphertext on disk must not contain the plaintext.
        let entry = v.entry_path(&meta.id);
        let raw = fs::read(&entry).unwrap();
        assert!(
            !raw.windows(content.len()).any(|w| w == content),
            "quarantine file leaked plaintext"
        );

        let restored = v.restore(&meta.id, Some(&base.join("restored.bin"))).unwrap();
        assert_eq!(fs::read(&restored).unwrap(), content);
        assert!(v.list().is_empty());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn header_tampering_is_detected() {
        let (v, base) = vault("tamper");
        let sample = base.join("a.bin");
        fs::write(&sample, b"content").unwrap();
        let meta = v
            .quarantine_file(&sample, "T", None, 50, false)
            .unwrap();

        let entry = v.entry_path(&meta.id);
        let mut raw = fs::read(&entry).unwrap();
        // Flip a byte inside the header JSON (original path) — AEAD must fail.
        let hlen_off = VAULT_MAGIC.len();
        let hlen = u32::from_le_bytes([
            raw[hlen_off],
            raw[hlen_off + 1],
            raw[hlen_off + 2],
            raw[hlen_off + 3],
        ]) as usize;
        let hstart = hlen_off + 4;
        let pos = raw[hstart..hstart + hlen]
            .windows(5)
            .position(|w| w == b"a.bin")
            .map(|p| hstart + p + 1)
            .expect("path in header");
        raw[pos] = b'z';
        fs::write(&entry, &raw).unwrap();

        let err = v.read_entry_bytes(&entry).unwrap_err();
        assert!(
            matches!(err, VaultError::Authentication | VaultError::Corrupt(_)),
            "unexpected error: {err}"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let (v, base) = vault("wrongkey");
        let sample = base.join("a.bin");
        fs::write(&sample, b"secret").unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, false).unwrap();

        let other = QuarantineVault::open(
            v.dir(),
            &base.join("other.key"),
        )
        .unwrap();
        let err = other.read_entry_bytes(&v.entry_path(&meta.id)).unwrap_err();
        assert!(matches!(err, VaultError::Authentication));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn restore_never_overwrites() {
        let (v, base) = vault("overwrite");
        let sample = base.join("a.bin");
        fs::write(&sample, b"x").unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, false).unwrap();
        let dest = base.join("exists.bin");
        fs::write(&dest, b"occupied").unwrap();
        assert!(v.restore(&meta.id, Some(&dest)).is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"occupied");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn quarantine_refuses_a_protected_source_and_writes_nothing() {
        let (v, base) = vault("protected-src");
        let protected = base.join("Windows");
        fs::create_dir_all(&protected).unwrap();
        let sample = protected.join("payload.bin");
        fs::write(&sample, b"malware-shaped bytes").unwrap();

        let mut policy = crate::safety::SafetyPolicy::default();
        policy.protected_paths = vec![protected.display().to_string()];
        policy.protected_exact = Vec::new();
        fs::write(
            v.dir().join(crate::safety::SAFETY_POLICY_FILE),
            serde_json::to_vec_pretty(&policy).unwrap(),
        )
        .unwrap();
        let reopened = QuarantineVault::open(v.dir(), &base.join("vault.key")).unwrap();

        let err = reopened
            .quarantine_file(&sample, "Test.Threat", None, 100, false)
            .unwrap_err();
        assert!(matches!(err, VaultError::SafetyRefused(_)), "{err}");
        assert!(sample.exists(), "protected source must be untouched");
        assert!(reopened.list().is_empty(), "no vault entry may be created");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn restore_refuses_a_protected_destination() {
        let (v, base) = vault("protected-dst");
        let sample = base.join("sample.bin");
        fs::write(&sample, b"payload").unwrap();
        let meta = v
            .quarantine_file(&sample, "Test.Threat", None, 100, false)
            .unwrap();

        let protected = base.join("System32");
        fs::create_dir_all(&protected).unwrap();
        let mut policy = crate::safety::SafetyPolicy::default();
        policy.protected_paths = vec![protected.display().to_string()];
        policy.protected_exact = Vec::new();
        fs::write(
            v.dir().join(crate::safety::SAFETY_POLICY_FILE),
            serde_json::to_vec_pretty(&policy).unwrap(),
        )
        .unwrap();
        let reopened = QuarantineVault::open(v.dir(), &base.join("vault.key")).unwrap();

        let target = protected.join("evil.dll");
        let err = reopened.restore(&meta.id, Some(&target)).unwrap_err();
        assert!(matches!(err, VaultError::SafetyRefused(_)), "{err}");
        assert!(!target.exists(), "nothing may be written into a protected path");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn the_audit_chain_records_a_quarantine_removal() {
        let (v, base) = vault("audit-quarantine");
        let sample = base.join("sample.bin");
        fs::write(&sample, b"payload").unwrap();
        let meta = v
            .quarantine_file(&sample, "Test.Threat", None, 100, false)
            .unwrap();
        assert!(meta.original_removed);

        let verification = v.safety().verify_audit();
        assert!(verification.ok, "{verification:?}");
        assert!(
            verification.records >= 2,
            "allowed + completed must both be recorded, got {verification:?}"
        );
        let text = fs::read_to_string(v.safety().audit_path()).unwrap();
        assert!(text.contains("remove_source"));
        assert!(text.contains(&meta.sha256));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn copy_only_keeps_original() {
        let (v, base) = vault("copy");
        let sample = base.join("a.bin");
        fs::write(&sample, b"x").unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, true).unwrap();
        assert!(sample.exists());
        assert!(!meta.original_removed);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn checked_quarantine_refuses_a_changed_source_before_writing() {
        let (v, base) = vault("checked");
        let sample = base.join("a.bin");
        fs::write(&sample, b"scanned bytes").unwrap();
        let wrong = sha256_bytes(b"different bytes").to_hex();

        let err = v
            .quarantine_file_checked(&sample, &wrong, "T", None, 50, false)
            .unwrap_err();
        assert!(
            matches!(err, VaultError::SourceChanged { .. }),
            "unexpected error: {err}"
        );
        assert_eq!(fs::read(&sample).unwrap(), b"scanned bytes");
        assert!(v.list().is_empty(), "a refused move must not create an entry");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn checked_quarantine_moves_matching_source() {
        let (v, base) = vault("checked-ok");
        let sample = base.join("a.bin");
        let content = b"malicious fixture";
        fs::write(&sample, content).unwrap();
        let digest = sha256_bytes(content).to_hex();

        let meta = v
            .quarantine_file_checked(&sample, &digest, "T", None, 50, false)
            .unwrap();
        assert_eq!(meta.sha256, digest);
        assert!(meta.original_removed, "{:?}", meta.source_retained_reason);
        assert!(!sample.exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn verify_all_reports_integrity() {
        let (v, base) = vault("verify");
        let sample = base.join("a.bin");
        fs::write(&sample, b"data").unwrap();
        v.quarantine_file(&sample, "T", None, 50, false).unwrap();
        let report = v.verify_all();
        assert_eq!(report.len(), 1);
        assert!(report[0].1, "entry should verify: {:?}", report);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn passphrase_derivation_is_deterministic() {
        let salt = [7u8; 16];
        let a = VaultKey::from_passphrase(b"correct horse", &salt).unwrap();
        let b = VaultKey::from_passphrase(b"correct horse", &salt).unwrap();
        let c = VaultKey::from_passphrase(b"wrong horse", &salt).unwrap();
        assert_eq!(a.0, b.0);
        assert_ne!(a.0, c.0);
    }

    #[test]
    fn truncated_entry_is_rejected() {
        let (v, base) = vault("trunc");
        let sample = base.join("a.bin");
        fs::write(&sample, b"data").unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, false).unwrap();
        let entry = v.entry_path(&meta.id);
        let raw = fs::read(&entry).unwrap();
        fs::write(&entry, &raw[..raw.len() / 2]).unwrap();
        assert!(v.read_entry_bytes(&entry).is_err());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn double_restore_and_restore_after_purge_are_not_found() {
        let (v, base) = vault("terminal");
        let sample = base.join("a.bin");
        fs::write(&sample, b"data").unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, false).unwrap();
        let dest = base.join("restored.bin");
        assert!(v.restore(&meta.id, Some(&dest)).is_ok());
        assert!(matches!(
            v.restore(&meta.id, Some(&base.join("again.bin"))),
            Err(VaultError::NotFound(_))
        ));

        let sample2 = base.join("b.bin");
        fs::write(&sample2, b"data2").unwrap();
        let meta2 = v.quarantine_file(&sample2, "T", None, 50, false).unwrap();
        v.purge(&meta2.id).unwrap();
        assert!(matches!(
            v.restore(&meta2.id, Some(&base.join("gone.bin"))),
            Err(VaultError::NotFound(_))
        ));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn corrupted_entry_is_refused_before_creating_a_target() {
        let (v, base) = vault("corrupt");
        let sample = base.join("a.bin");
        fs::write(&sample, b"sensitive").unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, false).unwrap();
        let entry = v.entry_path(&meta.id);
        let mut raw = fs::read(&entry).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        fs::write(&entry, raw).unwrap();

        let dest = base.join("should-not-exist.bin");
        let err = v.restore(&meta.id, Some(&dest)).unwrap_err();
        assert!(
            matches!(
                err,
                VaultError::Authentication | VaultError::IntegrityMismatch { .. }
            ),
            "unexpected error: {err}"
        );
        assert!(!dest.exists(), "a corrupt entry must not create a target");
        assert!(entry.exists(), "evidence must be preserved");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn recovery_completes_an_interrupted_restore() {
        let (v, base) = vault("rec-restore");
        let sample = base.join("a.bin");
        let content = b"restored content";
        fs::write(&sample, content).unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, false).unwrap();
        let target = base.join("restored.bin");
        // Simulate: the rename landed, then the process died before index/entry
        // cleanup. Recovery must recognise the identical bytes and finish.
        fs::write(&target, content).unwrap();
        v.journal_intent("restore", &meta.id, Some(&target), Some(&meta.sha256))
            .unwrap();

        let report = v.recover().unwrap();
        assert!(report.completed_restores.contains(&meta.id));
        assert!(!v.entry_path(&meta.id).exists());
        assert!(v.list().is_empty());
        assert_eq!(fs::read(&target).unwrap(), content);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn opening_the_vault_completes_an_interrupted_restore() {
        let (v, base) = vault("open-rec");
        let sample = base.join("a.bin");
        let content = b"open recovery";
        fs::write(&sample, content).unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, false).unwrap();
        let target = base.join("restored.bin");
        fs::write(&target, content).unwrap();
        v.journal_intent("restore", &meta.id, Some(&target), Some(&meta.sha256))
            .unwrap();
        drop(v);

        // `open` runs recovery; no separate recover() call is needed here.
        let v = QuarantineVault::open(&base.join("quarantine"), &base.join("vault.key"))
            .expect("reopen vault");
        assert!(!v.entry_path(&meta.id).exists());
        assert!(v.list().is_empty());
        assert_eq!(fs::read(&target).unwrap(), content);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn recovery_indexes_an_orphaned_quarantine_entry() {
        let (v, base) = vault("rec-index");
        let sample = base.join("a.bin");
        fs::write(&sample, b"orphan").unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, false).unwrap();
        fs::remove_file(v.dir.join(INDEX_FILE)).unwrap();
        v.journal_intent("quarantine", &meta.id, Some(&sample), Some(&meta.sha256))
            .unwrap();

        let report = v.recover().unwrap();
        assert!(report.indexed_entries.contains(&meta.id));
        assert_eq!(v.list().len(), 1);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn recovery_cleans_an_index_after_a_completed_purge() {
        let (v, base) = vault("rec-purge");
        let sample = base.join("a.bin");
        fs::write(&sample, b"purge").unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, false).unwrap();
        fs::remove_file(v.entry_path(&meta.id)).unwrap();
        v.journal_intent("purge", &meta.id, None, None).unwrap();

        let report = v.recover().unwrap();
        assert!(report.cleaned_indexes.contains(&meta.id));
        assert!(v.list().is_empty());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn recovery_preserves_a_conflicting_restore_target() {
        let (v, base) = vault("rec-conflict");
        let sample = base.join("a.bin");
        fs::write(&sample, b"vaulted").unwrap();
        let meta = v.quarantine_file(&sample, "T", None, 50, false).unwrap();
        let target = base.join("occupied.bin");
        fs::write(&target, b"someone else's file").unwrap();
        v.journal_intent("restore", &meta.id, Some(&target), Some(&meta.sha256))
            .unwrap();

        let report = v.recover().unwrap();
        assert!(!report.conflicts.is_empty());
        assert!(v.entry_path(&meta.id).exists());
        assert_eq!(fs::read(&target).unwrap(), b"someone else's file");
        assert_eq!(v.list().len(), 1);
        let _ = fs::remove_dir_all(&base);
    }
}
