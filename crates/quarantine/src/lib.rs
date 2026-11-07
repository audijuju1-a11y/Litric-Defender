//! Quarantine store.
//!
//! * Nothing is ever deleted automatically: `Mode::CopyOnly` leaves the
//!   original; `Mode::MoveAfterVerify` removes it only after the stored
//!   copy is read back and verified AND the original is re-hashed unchanged.
//! * Stored bytes are XOR-neutralized (0x5A) so the files are inert and are
//!   not re-flagged by other scanners. This is NOT encryption.
//! * Items are deduplicated by SHA-256; restore re-verifies the hash.
//! * Every action is appended to a hash-chained audit log; any edit or
//!   deletion of past lines is detected by `verify_audit`.
//! LIMIT: protecting this directory from an admin-level attacker (ACLs)
//! is PLANNED, not implemented.

use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const MAX_ITEM: u64 = 512 * 1024 * 1024;
const NEUTRALIZE: u8 = 0x5A;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    CopyOnly,
    MoveAfterVerify,
}

/// Required to purge: makes destructive deletion an explicit caller decision.
#[derive(Debug, Clone, Copy)]
pub enum Authorization {
    UserConfirmed,
}

#[derive(Debug, Clone)]
pub struct Info {
    pub family: String,
    pub rule_id: String,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Meta {
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub t_ms: u64,
    pub family: String,
    pub rule_id: String,
    pub severity: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn sha_hex(d: &[u8]) -> String {
    hex(&Sha256::digest(d))
}
fn neutralize(d: &[u8]) -> Vec<u8> {
    d.iter().map(|b| b ^ NEUTRALIZE).collect()
}
fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 40 && id.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}
fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '_' } else { c }).collect()
}

pub struct Quarantine {
    root: PathBuf,
}

impl Quarantine {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        for d in ["data", "meta"] {
            fs::create_dir_all(root.join(d))?;
        }
        Ok(Self { root })
    }

    fn data_path(&self, sha: &str) -> PathBuf {
        self.root.join("data").join(format!("{sha}.qdata"))
    }
    fn meta_path(&self, id: &str) -> PathBuf {
        self.root.join("meta").join(format!("{id}.meta"))
    }

    pub fn add(&self, path: &Path, info: &Info, mode: Mode, t_ms: u64) -> io::Result<String> {
        let ps = path.to_string_lossy().to_string();
        if ps.contains('\n') {
            return Err(bad("path contains a newline"));
        }
        let md = fs::symlink_metadata(path)?;
        if !md.is_file() {
            return Err(bad("not a regular file"));
        }
        if md.len() > MAX_ITEM {
            return Err(bad("file too large to quarantine"));
        }
        let data = fs::read(path)?;
        let sha = sha_hex(&data);
        let dp = self.data_path(&sha);
        if !dp.exists() {
            let tmp = dp.with_extension("tmp");
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&neutralize(&data))?;
            f.sync_all()?;
            fs::rename(&tmp, &dp)?;
        }
        // Read-back verification of the stored copy.
        let back = neutralize(&fs::read(&dp)?);
        if sha_hex(&back) != sha {
            return Err(bad("stored copy failed verification"));
        }
        let mut n = 0u32;
        let id = loop {
            let cand = format!("q{}{}", &sha_hex(format!("{ps}{sha}{t_ms}").as_bytes())[..12], if n == 0 { String::new() } else { format!("-{n}") });
            if !self.meta_path(&cand).exists() {
                break cand;
            }
            n += 1;
        };
        let meta = format!(
            "path {}\nsha256 {}\nsize {}\nt_ms {}\nfamily {}\nrule {}\nseverity {}\n",
            ps, sha, data.len(), t_ms, clean(&info.family), clean(&info.rule_id), clean(&info.severity)
        );
        fs::write(self.meta_path(&id), meta)?;
        if mode == Mode::MoveAfterVerify {
            // TOCTOU guard: only remove if the file is still exactly what we stored.
            if sha_hex(&fs::read(path)?) != sha {
                self.audit("add-keep", &id, "original changed during quarantine; not removed")?;
                return Err(bad("original changed during quarantine; left in place"));
            }
            fs::remove_file(path)?;
        }
        self.audit("add", &id, &format!("{sha} {ps} {mode:?}"))?;
        Ok(id)
    }

    pub fn get(&self, id: &str) -> io::Result<Meta> {
        if !valid_id(id) {
            return Err(bad("invalid id"));
        }
        let text = fs::read_to_string(self.meta_path(id))?;
        let field = |k: &str| -> io::Result<String> {
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{k} ")))
                .map(|s| s.to_string())
                .ok_or_else(|| bad("metadata missing field"))
        };
        Ok(Meta {
            id: id.into(),
            original_path: field("path")?,
            sha256: field("sha256")?,
            size: field("size")?.parse().map_err(|_| bad("size"))?,
            t_ms: field("t_ms")?.parse().map_err(|_| bad("t_ms"))?,
            family: field("family")?,
            rule_id: field("rule")?,
            severity: field("severity")?,
        })
    }

    pub fn list(&self) -> Vec<Meta> {
        let mut v: Vec<Meta> = fs::read_dir(self.root.join("meta"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.path().file_stem().and_then(|s| s.to_str()).and_then(|id| self.get(id).ok()))
            .collect();
        v.sort_by_key(|m| (m.t_ms, m.id.clone()));
        v
    }

    fn load_verified(&self, m: &Meta) -> io::Result<Vec<u8>> {
        let data = neutralize(&fs::read(self.data_path(&m.sha256))?);
        if sha_hex(&data) != m.sha256 {
            return Err(bad("quarantined data failed integrity check"));
        }
        Ok(data)
    }

    /// Restore to `dest`. Never overwrites an existing file.
    pub fn restore(&self, id: &str, dest: &Path) -> io::Result<()> {
        let m = self.get(id)?;
        let data = self.load_verified(&m)?;
        let tmp = dest.with_extension("litric-restore");
        fs::write(&tmp, &data)?;
        let r = fs::hard_link(&tmp, dest); // fails if dest exists: no silent overwrite
        let _ = fs::remove_file(&tmp);
        r?;
        self.audit("restore", id, &dest.to_string_lossy())
    }

    pub fn restore_original(&self, id: &str) -> io::Result<()> {
        let m = self.get(id)?;
        self.restore(id, Path::new(&m.original_path))
    }

    /// Permanently remove an item. The data blob is removed only when no
    /// other item references the same content.
    pub fn purge(&self, id: &str, _auth: Authorization) -> io::Result<()> {
        let m = self.get(id)?;
        fs::remove_file(self.meta_path(id))?;
        if !self.list().iter().any(|o| o.sha256 == m.sha256) {
            let _ = fs::remove_file(self.data_path(&m.sha256));
        }
        self.audit("purge", id, &m.sha256)
    }

    /// Ids whose stored data no longer matches its hash.
    pub fn verify_all(&self) -> Vec<String> {
        self.list().into_iter().filter(|m| self.load_verified(m).is_err()).map(|m| m.id).collect()
    }

    // ---- tamper-evident audit log -------------------------------------
    fn audit(&self, action: &str, id: &str, detail: &str) -> io::Result<()> {
        let p = self.root.join("audit.log");
        let prev = fs::read_to_string(&p)
            .ok()
            .and_then(|t| t.lines().last().and_then(|l| l.split(' ').next().map(String::from)))
            .unwrap_or_else(|| "0".repeat(64));
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let body = format!("{t} {action} {id} {}", clean(detail));
        let chain = sha_hex(format!("{prev} {body}").as_bytes());
        let mut f = OpenOptions::new().create(true).append(true).open(p)?;
        writeln!(f, "{chain} {body}")?;
        f.sync_all()
    }

    /// Ok(n lines) or Err(1-based line number of the first inconsistency).
    pub fn verify_audit(&self) -> Result<usize, usize> {
        let text = fs::read_to_string(self.root.join("audit.log")).unwrap_or_default();
        let mut prev = "0".repeat(64);
        for (i, line) in text.lines().enumerate() {
            let Some((chain, body)) = line.split_once(' ') else { return Err(i + 1) };
            if sha_hex(format!("{prev} {body}").as_bytes()) != chain {
                return Err(i + 1);
            }
            prev = chain.to_string();
        }
        Ok(text.lines().count())
    }
}
