//! Recovery Vault: content-addressed versions of protected files.
//!
//! Objects are named by SHA-256 and re-verified on restore, so a
//! corrupted or tampered object is never silently restored.
//! LIMIT: this is plain user-mode storage. Protecting the vault directory
//! from deletion by an admin-level attacker (ACLs, offline copy) is a
//! separate PLANNED item.

use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const MAX_FILE: u64 = 256 * 1024 * 1024;
const MAX_DEPTH: usize = 32;

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    pub t_ms: u64,
    pub hash: String,
    pub size: u64,
}

#[derive(Debug, Default)]
pub struct Report {
    pub stored: usize,
    pub unchanged: usize,
    pub errors: Vec<String>,
}

pub struct Vault {
    root: PathBuf,
}

impl Vault {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("index"))?;
        Ok(Self { root })
    }

    fn index_file(&self, path: &Path) -> PathBuf {
        self.root.join("index").join(sha256_hex(path.to_string_lossy().as_bytes()))
    }
    fn object_path(&self, h: &str) -> PathBuf {
        self.root.join("objects").join(&h[..2]).join(h)
    }

    pub fn versions(&self, path: &Path) -> Vec<Version> {
        let Ok(text) = fs::read_to_string(self.index_file(path)) else { return vec![] };
        text.lines()
            .filter_map(|l| {
                let mut p = l.splitn(4, ' ');
                Some(Version {
                    t_ms: p.next()?.parse().ok()?,
                    hash: p.next()?.to_string(),
                    size: p.next()?.parse().ok()?,
                })
            })
            .collect()
    }

    /// Stores a new version unless identical to the latest. Ok(None) = unchanged.
    pub fn snapshot_file(&self, path: &Path, t_ms: u64) -> io::Result<Option<String>> {
        let meta = fs::metadata(path)?;
        if meta.len() > MAX_FILE {
            return Err(io::Error::new(io::ErrorKind::Other, "file too large for vault"));
        }
        let data = fs::read(path)?;
        let hash = sha256_hex(&data);
        if self.versions(path).last().map_or(false, |v| v.hash == hash) {
            return Ok(None);
        }
        let obj = self.object_path(&hash);
        if !obj.exists() {
            fs::create_dir_all(obj.parent().unwrap())?;
            let tmp = obj.with_extension("tmp");
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
            fs::rename(&tmp, &obj)?;
        }
        let mut idx = OpenOptions::new().create(true).append(true).open(self.index_file(path))?;
        writeln!(idx, "{} {} {} {}", t_ms, hash, data.len(), path.display())?;
        Ok(Some(hash))
    }

    /// Recursively snapshot a tree. Symlinks/reparse points are skipped
    /// (avoids loops and escaping the protected tree).
    pub fn snapshot_tree(&self, root: &Path, t_ms: u64) -> io::Result<Report> {
        let mut rep = Report::default();
        self.walk(root, t_ms, None, 0, &mut rep);
        Ok(rep)
    }

    /// Like `snapshot_tree` but skips (without reading) files that already
    /// have a version and whose mtime is older than `since_ms` (minus 1 s
    /// slack). LIMIT: an attacker can set mtimes backwards (timestomping),
    /// so callers should run a full pass periodically.
    pub fn snapshot_tree_incremental(&self, root: &Path, t_ms: u64, since_ms: u64) -> io::Result<Report> {
        let mut rep = Report::default();
        self.walk(root, t_ms, Some(since_ms), 0, &mut rep);
        Ok(rep)
    }

    fn walk(&self, dir: &Path, t_ms: u64, since: Option<u64>, depth: usize, rep: &mut Report) {
        if depth > MAX_DEPTH || dir.starts_with(&self.root) {
            return;
        }
        let rd = match fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) => return rep.errors.push(format!("{}: {e}", dir.display())),
        };
        for ent in rd.flatten() {
            let Ok(ft) = ent.file_type() else { continue };
            let p = ent.path();
            if ft.is_symlink() {
                continue;
            } else if ft.is_dir() {
                self.walk(&p, t_ms, since, depth + 1, rep);
            } else if ft.is_file() {
                if let Some(since) = since {
                    let mtime = ent.metadata().and_then(|m| m.modified()).ok().and_then(|m| {
                        m.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_millis() as u64)
                    });
                    if let Some(ms) = mtime {
                        if ms < since.saturating_sub(1000) && !self.versions(&p).is_empty() {
                            rep.unchanged += 1;
                            continue;
                        }
                    }
                }
                match self.snapshot_file(&p, t_ms) {
                    Ok(Some(_)) => rep.stored += 1,
                    Ok(None) => rep.unchanged += 1,
                    Err(e) => rep.errors.push(format!("{}: {e}", p.display())),
                }
            }
        }
    }

    /// Restore the newest version taken at or before `t_ms` to `dest`.
    /// Verifies the object hash before writing; writes atomically.
    pub fn restore(&self, path: &Path, t_ms: u64, dest: &Path) -> io::Result<Version> {
        let v = self
            .versions(path)
            .into_iter()
            .filter(|v| v.t_ms <= t_ms)
            .last()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no version at that time"))?;
        let data = fs::read(self.object_path(&v.hash))?;
        if sha256_hex(&data) != v.hash {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "vault object failed integrity check"));
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = dest.with_extension("litric-restore");
        fs::write(&tmp, &data)?;
        fs::rename(&tmp, dest)?;
        Ok(v)
    }

    /// Returns hashes of objects whose content no longer matches their name.
    pub fn verify(&self) -> Vec<String> {
        let mut bad = vec![];
        let Ok(top) = fs::read_dir(self.root.join("objects")) else { return bad };
        for d in top.flatten() {
            let Ok(files) = fs::read_dir(d.path()) else { continue };
            for f in files.flatten() {
                let name = f.file_name().to_string_lossy().to_string();
                match fs::read(f.path()) {
                    Ok(data) if sha256_hex(&data) == name => {}
                    _ => bad.push(name),
                }
            }
        }
        bad
    }
}
