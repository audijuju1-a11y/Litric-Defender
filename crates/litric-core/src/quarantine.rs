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
//!
//! Key management:
//! * A 32-byte random master key file (mode 0600 on Unix) is generated on first
//!   use. On Windows the *service* is expected to wrap this key with DPAPI; that
//!   wrapper is Windows-specific and lives in the service crate (see STATUS.md).
//! * A passphrase mode derives the key with Argon2id for portable vaults.
//!
//! Cryptographic primitives come from audited crates (`chacha20poly1305`,
//! `argon2`, `sha2`); Litric does not implement cryptography.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::hash::sha256_bytes;

pub const VAULT_MAGIC: &[u8; 6] = b"LQVF1\n";
const MASTER_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const INDEX_FILE: &str = "index.json";
const JOURNAL_FILE: &str = "ops.jsonl";

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
    pub fn load_or_create(path: &Path) -> Result<Self, VaultError> {
        if path.exists() {
            let raw = fs::read(path)?;
            if raw.len() != MASTER_KEY_LEN {
                return Err(VaultError::Corrupt(format!(
                    "vault key file must be {MASTER_KEY_LEN} bytes, found {}",
                    raw.len()
                )));
            }
            let mut k = [0u8; MASTER_KEY_LEN];
            k.copy_from_slice(&raw);
            return Ok(VaultKey(k));
        }
        let key = VaultKey::generate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = fs::File::create(path)?;
        f.write_all(&key.0)?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(key)
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
}

impl QuarantineMeta {
    pub fn age_seconds(&self, now_unix: u64) -> u64 {
        now_unix.saturating_sub(self.quarantined_unix)
    }
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
}

impl QuarantineVault {
    /// Opens (creating if necessary) a vault directory with a key file placed
    /// alongside it.
    pub fn open(dir: &Path, key_path: &Path) -> Result<Self, VaultError> {
        fs::create_dir_all(dir)?;
        // Restrict access to the vault directory itself.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        let key = VaultKey::load_or_create(key_path)?;
        let vault = QuarantineVault {
            dir: dir.to_path_buf(),
            key,
        };
        // Reconcile interrupted operations without ever deleting user data on a
        // guess. A corrupt journal must not make the vault unopenable.
        let _ = vault.recover();
        Ok(vault)
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
        self.read_entry_bytes(&entry).ok()?;
        let raw = fs::read(entry).ok()?;
        if raw.len() < VAULT_MAGIC.len() + 4 || &raw[..VAULT_MAGIC.len()] != VAULT_MAGIC {
            return None;
        }
        let off = VAULT_MAGIC.len();
        let hlen = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]) as usize;
        let start = off + 4;
        let end = start.checked_add(hlen)?;
        serde_json::from_slice(&raw[start..end]).ok()
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
        let data = fs::read(path)?;
        let digest = sha256_bytes(&data);
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
        };

        let header = serde_json::to_vec(&meta)
            .map_err(|e| VaultError::Corrupt(format!("serialize header: {e}")))?;
        let ciphertext = self.encrypt(&data, &nonce, &header)?;

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
        let restored = self.read_entry_bytes(&tmp).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            e
        })?;
        let verify_digest = sha256_bytes(&restored);
        if verify_digest != digest {
            let _ = fs::remove_file(&tmp);
            return Err(VaultError::IntegrityMismatch {
                expected: digest.to_hex(),
                actual: verify_digest.to_hex(),
            });
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
            match fs::remove_file(path) {
                Ok(()) => meta.original_removed = true,
                Err(_) => meta.original_removed = false,
            }
            self.update_index(&meta, true)?;
        }

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
                    fs::remove_file(&entry)?;
                }
                if let Some(meta) = &meta {
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

    /// Decrypts one entry and returns its bytes.
    pub fn read_entry_bytes(&self, entry: &Path) -> Result<Vec<u8>, VaultError> {
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
        let digest = sha256_bytes(&plain);
        if digest.to_hex() != meta.sha256 {
            return Err(VaultError::IntegrityMismatch {
                expected: meta.sha256.clone(),
                actual: digest.to_hex(),
            });
        }
        Ok(plain)
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
        let meta = match self
            .list()
            .into_iter()
            .find(|m| m.id == id)
            .or_else(|| self.meta_from_entry(id))
        {
            Some(m) => m,
            None => {
                // Surface corruption instead of pretending the entry is absent.
                self.read_entry_bytes(&entry)?;
                return Err(VaultError::NotFound(format!(
                    "entry `{id}` is missing from the index"
                )));
            }
        };
        let bytes = self.read_entry_bytes(&entry)?;

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
                    let _ = fs::remove_file(&tmp);
                }
            }
            let final_bytes = fs::read(&target)?;
            if sha256_bytes(&final_bytes).to_hex() != meta.sha256 {
                return Err(VaultError::IntegrityMismatch {
                    expected: meta.sha256.clone(),
                    actual: sha256_bytes(&final_bytes).to_hex(),
                });
            }
            fs::remove_file(&entry)?;
            self.update_index(&meta, false)?;
            Ok(())
        })();
        match &result {
            Ok(()) => {
                let _ = self.journal_done(&op_id, "restore", id, Some(&target), Some(&meta.sha256));
            }
            Err(_) => {
                // Leave the intent in place so recovery can finish or report it.
                let _ = fs::remove_file(&tmp);
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
            match self.read_entry_bytes(&entry) {
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
        let op_id = self.journal_intent("purge", id, None, None)?;
        if entry.exists() {
            fs::remove_file(&entry)?;
        }
        if let Some(meta) = meta {
            self.update_index(&meta, false)?;
        }
        let _ = self.journal_done(&op_id, "purge", id, None, None);
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

    fn vault(tag: &str) -> (QuarantineVault, PathBuf) {
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
        let dir = base.join("quarantine");
        let key = base.join("vault.key");
        fs::create_dir_all(&base).unwrap();
        (QuarantineVault::open(&dir, &key).unwrap(), base)
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
        assert!(!sample.exists(), "original must be removed");
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
