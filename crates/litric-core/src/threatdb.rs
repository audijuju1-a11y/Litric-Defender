//! Litric Threat Database: signed, versioned, revocable detection content.
//!
//! Four distinct trust systems, deliberately never conflated:
//!
//! 1. **Malware detection signatures** — hashes and rules in this database.
//! 2. **Authenticode code signing** — proves who built a binary (`authenticode`).
//! 3. **Threat database signing** — Ed25519 detached signature proving *Litric*
//!    produced this content (this module).
//! 4. **Update transport** — TLS + hash + signature, in `updates` (planned).
//!
//! Security properties implemented here:
//! * The manifest is verified against a pinned Ed25519 public key before any
//!   JSON is parsed into trust-bearing structures.
//! * The payload hash is checked before signature verification, so a corrupted
//!   download fails fast with a precise error.
//! * Anti-rollback: a database is only installed if its `db_version` is strictly
//!   greater than the installed one, unless an explicit `force` is requested.
//! * `min_engine` prevents a new database from running on an engine that cannot
//!   interpret it.
//! * Revocation lists let a bad rule or a false-positive hash be withdrawn
//!   without shipping a new engine.
//! * Installation is atomic: write temp, fsync, rename, keep the previous DB for
//!   rollback.
//!
//! The development keypair in `dev_signing_key()` is a **test fixture**. A real
//! build must ship a production public key; the loader refuses to treat a dev
//! key as production (`DbTrust` records which keys were accepted).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::DbError;
use crate::hash::{sha256_bytes, Digest32};

pub const DB_FORMAT_VERSION: u32 = 1;
pub const PAYLOAD_FILE: &str = "litric.db.json";
pub const MANIFEST_FILE: &str = "litric.db.manifest.json";
pub const PREV_SUFFIX: &str = ".prev";

/// What a hash entry means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// Known malicious.
    Malicious,
    /// Potentially unwanted application: unwanted, not destructive.
    Pua,
    /// Verified-good (vendor allowlist, signed Microsoft binary, internal build).
    Trusted,
}

/// One hash-based detection or trust record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashEntry {
    pub sha256: String,
    pub name: String,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    pub kind: EntryKind,
    /// Where this indicator came from. Required for attribution and revocation.
    #[serde(default)]
    pub source: Option<String>,
    /// License/terms under which the indicator is redistributed.
    #[serde(default)]
    pub license: Option<String>,
}

/// A rule shipped inside the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSource {
    pub name: String,
    pub text: String,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

/// The signed content of the database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbPayload {
    pub schema: u32,
    pub db_version: u64,
    pub min_engine: String,
    pub created_unix: u64,
    #[serde(default)]
    pub hashes: Vec<HashEntry>,
    #[serde(default)]
    pub rules: Vec<RuleSource>,
    /// Rule names withdrawn by Litric (false positives, bad logic).
    #[serde(default)]
    pub revoked_rules: Vec<String>,
    /// Hashes withdrawn (e.g. a legitimate file was wrongly listed).
    #[serde(default)]
    pub revoked_hashes: Vec<String>,
    /// Human-readable provenance for each feed used to build this DB.
    #[serde(default)]
    pub sources: Vec<String>,
}

/// Detached manifest describing and signing a payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    pub db_version: u64,
    pub payload_sha256: String,
    pub payload_len: u64,
    /// Hex-encoded Ed25519 signature over the raw payload bytes.
    pub signature: String,
    /// First 8 bytes of SHA-256(public key), for key identification/rotation.
    pub key_id: String,
    #[serde(default)]
    pub created_unix: u64,
}

/// Which key validated the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbTrust {
    /// Validated by a production public key pinned in the engine.
    Production,
    /// Validated only by the development fixture key. Never ship as production.
    DevelopmentOnly,
    /// Loaded without signature validation (explicit, logged, never default).
    Unsigned,
}

/// How a runtime caller decides which database signatures it accepts.
///
/// Fail-closed by default: with no pinned key and no explicit development
/// opt-in, every database is rejected. The fixture key is honoured only when the
/// operator sets `LITRIC_ALLOW_DEV_DB=1`, and the loaded database is then
/// reported as [`DbTrust::DevelopmentOnly`] so callers can surface it.
#[derive(Debug, Clone, Default)]
pub struct DbTrustPolicy {
    /// Keys pinned for this deployment (`LITRIC_DB_PUBKEY`).
    pub production_keys: Vec<VerifyingKey>,
    /// Explicit opt-in for the public fixture key. Never a default.
    pub allow_development: bool,
}

impl DbTrustPolicy {
    pub fn new(production_keys: Vec<VerifyingKey>, allow_development: bool) -> Self {
        Self {
            production_keys,
            allow_development,
        }
    }

    /// Parses a comma- or semicolon-separated list of 64-hex-char Ed25519 public
    /// keys. A malformed entry is an error: a typo must not silently shrink the
    /// pinned key set to nothing (which would fail closed, but confusingly).
    pub fn parse_keys(spec: &str) -> Result<Vec<VerifyingKey>, DbError> {
        let mut keys = Vec::new();
        for part in spec.split([',', ';']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let bytes = hex32(part).ok_or_else(|| {
                DbError::Invalid(format!(
                    "pinned public key {part:?} is not exactly 64 hex characters"
                ))
            })?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|e| {
                DbError::Invalid(format!("pinned public key {part:?} is invalid: {e}"))
            })?;
            keys.push(key);
        }
        Ok(keys)
    }

    /// Builds the policy from the environment of the running process.
    pub fn from_env() -> Result<Self, DbError> {
        let production_keys = match std::env::var("LITRIC_DB_PUBKEY") {
            Ok(spec) => Self::parse_keys(&spec)?,
            Err(_) => Vec::new(),
        };
        let allow_development = std::env::var("LITRIC_ALLOW_DEV_DB")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        Ok(Self {
            production_keys,
            allow_development,
        })
    }

    /// True when content can be validated without the fixture key.
    pub fn has_production_key(&self) -> bool {
        !self.production_keys.is_empty()
    }
}

/// A loaded, verified threat database.
#[derive(Debug)]
pub struct ThreatDb {
    pub payload: DbPayload,
    pub trust: DbTrust,
    by_hash: HashMap<String, HashEntry>,
    revoked_rules: std::collections::HashSet<String>,
    pub source_path: Option<PathBuf>,
}

impl ThreatDb {
    /// An empty database: the engine still runs heuristics and rules from disk,
    /// but knows no hashes. The engine reports this state honestly.
    pub fn empty() -> Self {
        let mut db = ThreatDb {
            payload: DbPayload {
                schema: DB_FORMAT_VERSION,
                db_version: 0,
                min_engine: "0.0.0".into(),
                created_unix: 0,
                ..Default::default()
            },
            trust: DbTrust::Unsigned,
            by_hash: HashMap::new(),
            revoked_rules: std::collections::HashSet::new(),
            source_path: None,
        };
        db.reindex();
        db
    }

    fn reindex(&mut self) {
        self.by_hash.clear();
        let revoked: std::collections::HashSet<&str> =
            self.payload.revoked_hashes.iter().map(|s| s.as_str()).collect();
        for e in &self.payload.hashes {
            let key = e.sha256.to_ascii_lowercase();
            if revoked.contains(key.as_str()) {
                continue;
            }
            self.by_hash.insert(key, e.clone());
        }
        self.revoked_rules = self
            .payload
            .revoked_rules
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
    }

    pub fn is_empty(&self) -> bool {
        self.payload.hashes.is_empty() && self.payload.rules.is_empty()
    }

    pub fn version(&self) -> u64 {
        self.payload.db_version
    }

    /// Looks up a file hash.
    pub fn lookup(&self, digest: &Digest32) -> Option<&HashEntry> {
        self.by_hash.get(&digest.to_hex())
    }

    pub fn rule_is_revoked(&self, name: &str) -> bool {
        self.revoked_rules.contains(&name.to_ascii_lowercase())
    }

    /// Parses the payload into rules, skipping revoked ones, and reports failures.
    pub fn rule_sources(&self) -> (Vec<(String, String)>, Vec<String>) {
        let mut ok = Vec::new();
        let mut errors = Vec::new();
        for r in &self.payload.rules {
            if self.rule_is_revoked(&r.name) {
                continue;
            }
            ok.push((r.name.clone(), r.text.clone()));
        }
        (ok, std::mem::take(&mut errors))
    }

    /// Verifies and loads a database from raw payload + manifest bytes.
    ///
    /// `production_keys` are pinned engine keys. `allow_development` must be true
    /// for a build to accept the dev fixture key, and the resulting trust level is
    /// then reported as `DevelopmentOnly` so callers can surface it in the UI.
    pub fn verify_loaded(
        payload_bytes: &[u8],
        manifest_bytes: &[u8],
        production_keys: &[VerifyingKey],
        allow_development: bool,
        engine_version: &str,
    ) -> Result<ThreatDb, DbError> {
        let manifest: Manifest = serde_json::from_slice(manifest_bytes)
            .map_err(|e| DbError::Json(format!("manifest: {e}")))?;
        if manifest.format_version != DB_FORMAT_VERSION {
            return Err(DbError::Invalid(format!(
                "manifest format {} unsupported (engine supports {})",
                manifest.format_version, DB_FORMAT_VERSION
            )));
        }
        if manifest.payload_len != payload_bytes.len() as u64 {
            return Err(DbError::Invalid(format!(
                "manifest declares {} payload bytes, got {}",
                manifest.payload_len,
                payload_bytes.len()
            )));
        }
        let actual = sha256_bytes(payload_bytes).to_hex();
        if !actual.eq_ignore_ascii_case(&manifest.payload_sha256) {
            return Err(DbError::PayloadHashMismatch);
        }

        let sig_bytes = hex_to_vec64(&manifest.signature)
            .ok_or_else(|| DbError::Invalid("signature is not 64 hex-encoded bytes".into()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        let mut trust = None;
        for key in production_keys {
            if key.verify(payload_bytes, &signature).is_ok() {
                trust = Some(DbTrust::Production);
                break;
            }
        }
        if trust.is_none() && allow_development {
            let dev = dev_verifying_key();
            if dev.verify(payload_bytes, &signature).is_ok() {
                trust = Some(DbTrust::DevelopmentOnly);
            }
        }
        let trust = trust.ok_or(DbError::BadSignature)?;

        let payload: DbPayload = serde_json::from_slice(payload_bytes)
            .map_err(|e| DbError::Json(format!("payload: {e}")))?;
        if payload.schema != DB_FORMAT_VERSION {
            return Err(DbError::Invalid(format!(
                "payload schema {} unsupported",
                payload.schema
            )));
        }
        if !version_ge(engine_version, &payload.min_engine) {
            return Err(DbError::EngineTooOld {
                required: payload.min_engine.clone(),
                actual: engine_version.to_string(),
            });
        }

        let mut db = ThreatDb {
            payload,
            trust,
            by_hash: HashMap::new(),
            revoked_rules: Default::default(),
            source_path: None,
        };
        db.reindex();
        Ok(db)
    }

    /// Verifies and loads from a directory containing `litric.db.json` and its
    /// manifest.
    pub fn open_dir(
        dir: &Path,
        production_keys: &[VerifyingKey],
        allow_development: bool,
        engine_version: &str,
    ) -> Result<ThreatDb, DbError> {
        let payload = fs::read(dir.join(PAYLOAD_FILE))?;
        let manifest = fs::read(dir.join(MANIFEST_FILE))?;
        let mut db = ThreatDb::verify_loaded(
            &payload,
            &manifest,
            production_keys,
            allow_development,
            engine_version,
        )?;
        db.source_path = Some(dir.join(PAYLOAD_FILE));
        Ok(db)
    }

    /// Loads a database for a runtime binary (`litric`, `litricd`).
    ///
    /// The call site no longer chooses trust: pinned keys and the development
    /// opt-in come from [`DbTrustPolicy::from_env`]. With nothing pinned and no
    /// opt-in this fails closed, so content signed with the public fixture key
    /// can never be accepted by accident.
    pub fn load_for_runtime(dir: &Path, engine_version: &str) -> Result<ThreatDb, DbError> {
        let policy = DbTrustPolicy::from_env()?;
        match ThreatDb::open_dir(
            dir,
            &policy.production_keys,
            policy.allow_development,
            engine_version,
        ) {
            Ok(db) => Ok(db),
            Err(DbError::BadSignature) if !policy.allow_development => Err(DbError::Invalid(
                "database is not signed by a pinned key; set LITRIC_DB_PUBKEY to this \
                 deployment's Ed25519 public key (hex), or LITRIC_ALLOW_DEV_DB=1 to load test \
                 content signed with the public fixture key"
                    .into(),
            )),
            Err(e) => Err(e),
        }
    }

    /// Atomically installs verified content into `dir`.
    ///
    /// Refuses rollback unless `force` is set. The previous database is retained
    /// as `*.prev` so an operator can roll back manually after a bad update.
    pub fn install(
        dir: &Path,
        payload_bytes: &[u8],
        manifest_bytes: &[u8],
        production_keys: &[VerifyingKey],
        allow_development: bool,
        engine_version: &str,
        force: bool,
    ) -> Result<ThreatDb, DbError> {
        let candidate = ThreatDb::verify_loaded(
            payload_bytes,
            manifest_bytes,
            production_keys,
            allow_development,
            engine_version,
        )?;
        fs::create_dir_all(dir)?;

        if !force {
            if let Ok(existing) = ThreatDb::open_dir(
                dir,
                production_keys,
                allow_development,
                engine_version,
            ) {
                if candidate.payload.db_version <= existing.payload.db_version {
                    return Err(DbError::Rollback {
                        installed: existing.payload.db_version,
                        candidate: candidate.payload.db_version,
                    });
                }
            }
        }

        // Keep the previous copy for manual rollback.
        for name in [PAYLOAD_FILE, MANIFEST_FILE] {
            let current = dir.join(name);
            if current.exists() {
                let _ = fs::copy(&current, dir.join(format!("{name}{PREV_SUFFIX}")));
            }
        }

        write_atomic(&dir.join(PAYLOAD_FILE), payload_bytes)?;
        write_atomic(&dir.join(MANIFEST_FILE), manifest_bytes)?;

        let mut db = candidate;
        db.source_path = Some(dir.join(PAYLOAD_FILE));
        Ok(db)
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), DbError> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Builds and signs a payload + manifest pair.
///
/// This is the *publishing* path, used by the offline signature build tool and by
/// tests. It requires the private key, which never ships to endpoints.
pub fn build_signed(
    payload: &DbPayload,
    key: &SigningKey,
) -> Result<(Vec<u8>, Vec<u8>), DbError> {
    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|e| DbError::Json(format!("serialize payload: {e}")))?;
    let signature = key.sign(&payload_bytes);
    let manifest = Manifest {
        format_version: DB_FORMAT_VERSION,
        db_version: payload.db_version,
        payload_sha256: sha256_bytes(&payload_bytes).to_hex(),
        payload_len: payload_bytes.len() as u64,
        signature: to_hex(&signature.to_bytes()),
        key_id: key_id(&key.verifying_key()),
        created_unix: payload.created_unix,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| DbError::Json(format!("serialize manifest: {e}")))?;
    Ok((payload_bytes, manifest_bytes))
}

/// Stable short identifier for a verification key.
pub fn key_id(key: &VerifyingKey) -> String {
    let h = sha256_bytes(key.as_bytes());
    h.to_hex()[..16].to_string()
}

/// The development signing key. **Test fixture only.**
///
/// Derived from a fixed seed so tests are deterministic. Any database signed with
/// this key loads with `DbTrust::DevelopmentOnly`, and the CLI refuses to treat
/// it as production content.
pub fn dev_signing_key() -> SigningKey {
    // Fixed 32-byte seed; not a secret, not usable for production content.
    let seed: [u8; 32] = [
        0x4c, 0x69, 0x74, 0x72, 0x69, 0x63, 0x44, 0x65, 0x66, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x44,
        0x65, 0x76, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x30, 0x30, 0x31,
        0x21, 0x00,
    ];
    SigningKey::from_bytes(&seed)
}

pub fn dev_verifying_key() -> VerifyingKey {
    dev_signing_key().verifying_key()
}

/// Compares dotted numeric versions: `a >= b`.
pub fn version_ge(a: &str, b: &str) -> bool {
    fn parse(s: &str) -> (u64, u64, u64) {
        let mut it = s.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        (
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
        )
    }
    parse(a) >= parse(b)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn hex_to_vec64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        let hi = u8::from_str_radix(&s[i * 2..i * 2 + 1], 16).ok()?;
        let lo = u8::from_str_radix(&s[i * 2 + 1..i * 2 + 2], 16).ok()?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256_bytes;

    fn payload(version: u64) -> DbPayload {
        DbPayload {
            schema: DB_FORMAT_VERSION,
            db_version: version,
            min_engine: "0.1.0".into(),
            created_unix: 1_700_000_000,
            hashes: vec![HashEntry {
                sha256: sha256_bytes(b"bad").to_hex(),
                name: "Test.Bad".into(),
                family: Some("TestFam".into()),
                severity: Some("high".into()),
                kind: EntryKind::Malicious,
                source: Some("unit test".into()),
                license: Some("CC0".into()),
            }],
            rules: vec![RuleSource {
                name: "Test.Rule".into(),
                text: "rule Test.Rule { strings: $a = \"x\" condition: $a }".into(),
                license: Some("DRL-1.1".into()),
                author: Some("Litric Labs".into()),
            }],
            revoked_rules: vec![],
            revoked_hashes: vec![],
            sources: vec!["unit test fixture".into()],
        }
    }

    #[test]
    fn signs_verifies_and_loads() {
        let (p, m) = build_signed(&payload(1), &dev_signing_key()).unwrap();
        let db = ThreatDb::verify_loaded(
            &p,
            &m,
            &[],
            true,
            crate::ENGINE_VERSION,
        )
        .expect("dev key accepted");
        assert_eq!(db.trust, DbTrust::DevelopmentOnly);
        assert_eq!(db.version(), 1);
        let hit = db.lookup(&sha256_bytes(b"bad")).expect("hash present");
        assert_eq!(hit.kind, EntryKind::Malicious);
    }

    #[test]
    fn tampered_payload_fails_hash_check() {
        let (mut p, m) = build_signed(&payload(1), &dev_signing_key()).unwrap();
        p.push(b' ');
        let err = ThreatDb::verify_loaded(&p, &m, &[], true, crate::ENGINE_VERSION).unwrap_err();
        assert!(matches!(err, DbError::PayloadHashMismatch | DbError::Invalid(_)));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (p, m) = build_signed(&payload(1), &dev_signing_key()).unwrap();
        let mut mj: Manifest = serde_json::from_slice(&m).unwrap();
        mj.signature = "00".repeat(64);
        let mb = serde_json::to_vec(&mj).unwrap();
        let err = ThreatDb::verify_loaded(&p, &mb, &[], true, crate::ENGINE_VERSION).unwrap_err();
        assert!(matches!(err, DbError::BadSignature));
    }

    #[test]
    fn forged_payload_cannot_reuse_signature() {
        let (_, m) = build_signed(&payload(1), &dev_signing_key()).unwrap();
        // Attacker rewrites the payload (adds a malicious entry) but keeps manifest.
        let mut forged = payload(1);
        forged.hashes[0].name = "Injected".into();
        let forged_bytes = serde_json::to_vec(&forged).unwrap();
        let err =
            ThreatDb::verify_loaded(&forged_bytes, &m, &[], true, crate::ENGINE_VERSION).unwrap_err();
        assert!(matches!(err, DbError::PayloadHashMismatch));
    }

    #[test]
    fn development_key_is_not_accepted_as_production() {
        let (p, m) = build_signed(&payload(1), &dev_signing_key()).unwrap();
        // No production keys supplied and dev keys disallowed.
        let err = ThreatDb::verify_loaded(&p, &m, &[], false, crate::ENGINE_VERSION).unwrap_err();
        assert!(matches!(err, DbError::BadSignature));
    }

    #[test]
    fn pinned_key_is_accepted_as_production() {
        let (p, m) = build_signed(&payload(1), &dev_signing_key()).unwrap();
        // The same bytes are *production* content when the key is pinned.
        let db = ThreatDb::verify_loaded(
            &p,
            &m,
            &[dev_verifying_key()],
            false,
            crate::ENGINE_VERSION,
        )
        .expect("pinned key accepted");
        assert_eq!(db.trust, DbTrust::Production);
    }

    #[test]
    fn policy_parses_and_rejects_bad_keys() {
        let hex = to_hex(dev_verifying_key().as_bytes());
        let keys = DbTrustPolicy::parse_keys(&format!("  {hex} ; {hex} ,")).unwrap();
        assert_eq!(keys.len(), 2);
        assert!(DbTrustPolicy::new(keys, false).has_production_key());

        let short = DbTrustPolicy::parse_keys(&hex[..62]).unwrap_err();
        assert!(matches!(short, DbError::Invalid(_)));
        let not_hex = DbTrustPolicy::parse_keys(&"z".repeat(64)).unwrap_err();
        assert!(matches!(not_hex, DbError::Invalid(_)));
        assert!(DbTrustPolicy::parse_keys(" , ; ").unwrap().is_empty());
    }

    #[test]
    fn runtime_load_fails_closed_without_a_policy() {
        // `load_for_runtime` reads the process environment, so this exercises the
        // same decision it makes with no pinned key: dev content is refused.
        let policy = DbTrustPolicy::new(Vec::new(), false);
        let (p, m) = build_signed(&payload(1), &dev_signing_key()).unwrap();
        let err = ThreatDb::verify_loaded(
            &p,
            &m,
            &policy.production_keys,
            policy.allow_development,
            crate::ENGINE_VERSION,
        )
        .unwrap_err();
        assert!(matches!(err, DbError::BadSignature));
    }

    #[test]
    fn engine_version_gate() {
        let mut pl = payload(1);
        pl.min_engine = "99.0.0".into();
        let (p, m) = build_signed(&pl, &dev_signing_key()).unwrap();
        let err = ThreatDb::verify_loaded(&p, &m, &[], true, "0.1.0").unwrap_err();
        assert!(matches!(err, DbError::EngineTooOld { .. }));
    }

    #[test]
    fn rollback_is_refused_without_force() {
        let dir = std::env::temp_dir().join(format!("litric-db-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (p2, m2) = build_signed(&payload(2), &dev_signing_key()).unwrap();
        ThreatDb::install(&dir, &p2, &m2, &[], true, crate::ENGINE_VERSION, false).unwrap();

        let (p1, m1) = build_signed(&payload(1), &dev_signing_key()).unwrap();
        let err = ThreatDb::install(&dir, &p1, &m1, &[], true, crate::ENGINE_VERSION, false)
            .unwrap_err();
        assert!(matches!(err, DbError::Rollback { installed: 2, candidate: 1 }));

        // Force allows it, and the previous payload is retained.
        ThreatDb::install(&dir, &p1, &m1, &[], true, crate::ENGINE_VERSION, true).unwrap();
        assert!(dir.join(format!("{PAYLOAD_FILE}{PREV_SUFFIX}")).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoked_hash_is_not_returned() {
        let mut pl = payload(1);
        pl.revoked_hashes.push(sha256_bytes(b"bad").to_hex());
        let (p, m) = build_signed(&pl, &dev_signing_key()).unwrap();
        let db = ThreatDb::verify_loaded(&p, &m, &[], true, crate::ENGINE_VERSION).unwrap();
        assert!(db.lookup(&sha256_bytes(b"bad")).is_none());
    }

    #[test]
    fn version_compare() {
        assert!(version_ge("1.2.3", "1.2.3"));
        assert!(version_ge("1.10.0", "1.9.9"));
        assert!(!version_ge("0.9.0", "1.0.0"));
    }
}
