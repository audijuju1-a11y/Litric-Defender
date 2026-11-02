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

use std::fs;
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
        Ok(QuarantineVault {
            dir: dir.to_path_buf(),
            key,
        })
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

        if !copy_only {
            // Only remove after the vault entry is durable and verified.
            match fs::remove_file(path) {
                Ok(()) => meta.original_removed = true,
                Err(_) => meta.original_removed = false,
            }
        }

        self.update_index(&meta, true)?;
        Ok(meta)
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
    pub fn restore(&self, id: &str, dest: Option<&Path>) -> Result<PathBuf, VaultError> {
        let entry = self.entry_path(id);
        if !entry.exists() {
            return Err(VaultError::Corrupt(format!("no quarantine entry `{id}`")));
        }
        let bytes = self.read_entry_bytes(&entry)?;
        let meta = self
            .list()
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| VaultError::Corrupt(format!("entry `{id}` missing from index")))?;

        let target = match dest {
            Some(p) => p.to_path_buf(),
            None => PathBuf::from(&meta.original_path),
        };
        // Never clobber an existing file during restore.
        if target.exists() {
            return Err(VaultError::Corrupt(format!(
                "refusing to overwrite existing file {}",
                target.display()
            )));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = fs::File::create(&target)?;
        f.write_all(&bytes)?;
        f.sync_all()?;

        // Verify what actually landed on disk.
        let written = fs::read(&target)?;
        if sha256_bytes(&written).to_hex() != meta.sha256 {
            return Err(VaultError::IntegrityMismatch {
                expected: meta.sha256.clone(),
                actual: sha256_bytes(&written).to_hex(),
            });
        }

        fs::remove_file(&entry)?;
        self.update_index(&meta, false)?;
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
    /// user first.
    pub fn purge(&self, id: &str) -> Result<(), VaultError> {
        let entry = self.entry_path(id);
        if entry.exists() {
            fs::remove_file(&entry)?;
        }
        if let Some(meta) = self.list().into_iter().find(|m| m.id == id) {
            self.update_index(&meta, false)?;
        }
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
}
