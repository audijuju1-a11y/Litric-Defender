//! Secure file broker: the only path by which data crosses the isolation boundary.
//!
//! Import copies a file into a per-session staging directory and verifies the copy
//! against the source hash. Export writes to a temporary file, verifies it, runs a
//! caller-supplied scan gate, and only then commits. The source is never modified,
//! and an existing destination is never replaced without explicit approval.

use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use litric_core::hash::sha256_bytes;

/// Default maximum size of a file that may be staged (2 GiB).
pub const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum BrokerError {
    Io(String),
    Empty,
    TooLarge { size: u64, limit: u64 },
    Symlink(PathBuf),
    NotRegularFile(PathBuf),
    UnsafeName(String),
    OutsideStaging(PathBuf),
    WouldOverwrite(PathBuf),
    HashMismatch { expected: String, actual: String },
    RejectedByScan(String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::Io(e) => write!(f, "I/O error: {e}"),
            BrokerError::Empty => write!(f, "refusing to stage an empty file"),
            BrokerError::TooLarge { size, limit } => {
                write!(f, "file is {size} bytes, above the {limit}-byte broker limit")
            }
            BrokerError::Symlink(p) => write!(f, "refusing to follow a symbolic link: {}", p.display()),
            BrokerError::NotRegularFile(p) => {
                write!(f, "not a regular file: {}", p.display())
            }
            BrokerError::UnsafeName(n) => write!(f, "unsafe file name rejected: `{n}`"),
            BrokerError::OutsideStaging(p) => {
                write!(f, "path is outside the broker staging area: {}", p.display())
            }
            BrokerError::WouldOverwrite(p) => write!(
                f,
                "destination already exists and overwrite was not approved: {}",
                p.display()
            ),
            BrokerError::HashMismatch { expected, actual } => {
                write!(f, "hash mismatch: expected {expected}, got {actual}")
            }
            BrokerError::RejectedByScan(m) => write!(f, "export rejected by scan gate: {m}"),
        }
    }
}

impl std::error::Error for BrokerError {}

impl From<io::Error> for BrokerError {
    fn from(e: io::Error) -> Self {
        BrokerError::Io(e.to_string())
    }
}

/// A staged import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub staged: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

/// A committed export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exported {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub replaced_existing: bool,
}

/// Root-scoped staging broker.
#[derive(Debug, Clone)]
pub struct Broker {
    root: PathBuf,
    max_bytes: u64,
}

impl Broker {
    pub fn new(root: &Path) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        let root = fs::canonicalize(root)?;
        Ok(Broker {
            root,
            max_bytes: DEFAULT_MAX_BYTES,
        })
    }

    pub fn with_max_bytes(mut self, limit: u64) -> Self {
        self.max_bytes = limit;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Copies `source` into staging and verifies the copy. The source is unchanged.
    pub fn import(&self, source: &Path) -> Result<Imported, BrokerError> {
        let meta = fs::symlink_metadata(source)?;
        if meta.file_type().is_symlink() {
            return Err(BrokerError::Symlink(source.to_path_buf()));
        }
        if !meta.is_file() {
            return Err(BrokerError::NotRegularFile(source.to_path_buf()));
        }
        if meta.len() == 0 {
            return Err(BrokerError::Empty);
        }
        if meta.len() > self.max_bytes {
            return Err(BrokerError::TooLarge {
                size: meta.len(),
                limit: self.max_bytes,
            });
        }
        let name = safe_file_name(source)?;

        let session = self.root.join(format!("import-{}", unique()));
        let input = session.join("input");
        fs::create_dir_all(&input)?;
        let staged = input.join(&name);

        fs::copy(source, &staged)?;

        let expected = hash_file(source, self.max_bytes)?;
        let actual = hash_file(&staged, self.max_bytes)?;
        if expected != actual {
            let _ = fs::remove_dir_all(&session);
            return Err(BrokerError::HashMismatch { expected, actual });
        }

        Ok(Imported {
            staged,
            sha256: actual,
            bytes: meta.len(),
        })
    }

    /// Exports a staged file to `dest`. Refuses to replace anything unless
    /// `approve_overwrite` is true, and hashes the written bytes before committing.
    pub fn export(
        &self,
        staged: &Path,
        dest: &Path,
        approve_overwrite: bool,
    ) -> Result<Exported, BrokerError> {
        self.export_gated(staged, dest, approve_overwrite, |_| Ok(()))
    }

    /// Export with a scan gate that runs against the fully written temporary file.
    /// If the gate rejects, the destination is untouched and the staged copy stays.
    pub fn export_gated<F>(
        &self,
        staged: &Path,
        dest: &Path,
        approve_overwrite: bool,
        gate: F,
    ) -> Result<Exported, BrokerError>
    where
        F: FnOnce(&Path) -> Result<(), String>,
    {
        let staged_meta = fs::symlink_metadata(staged)?;
        if staged_meta.file_type().is_symlink() {
            return Err(BrokerError::Symlink(staged.to_path_buf()));
        }
        if !staged_meta.is_file() {
            return Err(BrokerError::NotRegularFile(staged.to_path_buf()));
        }
        if staged_meta.len() == 0 {
            return Err(BrokerError::Empty);
        }
        if staged_meta.len() > self.max_bytes {
            return Err(BrokerError::TooLarge {
                size: staged_meta.len(),
                limit: self.max_bytes,
            });
        }

        // Only files inside the broker's own staging tree may be exported.
        let canonical = fs::canonicalize(staged)?;
        if !canonical.starts_with(&self.root) {
            return Err(BrokerError::OutsideStaging(staged.to_path_buf()));
        }

        let name = safe_file_name(dest)?;
        let parent = dest.parent().ok_or_else(|| {
            BrokerError::UnsafeName(dest.display().to_string())
        })?;
        if !parent.is_dir() {
            return Err(BrokerError::Io(format!(
                "destination directory does not exist: {}",
                parent.display()
            )));
        }

        let exists = dest.exists();
        if exists {
            let dmeta = fs::symlink_metadata(dest)?;
            if dmeta.file_type().is_symlink() {
                return Err(BrokerError::Symlink(dest.to_path_buf()));
            }
            if !approve_overwrite {
                return Err(BrokerError::WouldOverwrite(dest.to_path_buf()));
            }
        }

        let temp = parent.join(format!(".litric-{}-{}", unique(), name));
        let result = (|| -> Result<Exported, BrokerError> {
            fs::copy(&canonical, &temp)?;
            File::open(&temp)?.sync_all()?;

            let expected = hash_file(&canonical, self.max_bytes)?;
            let actual = hash_file(&temp, self.max_bytes)?;
            if expected != actual {
                return Err(BrokerError::HashMismatch { expected, actual });
            }

            gate(&temp).map_err(BrokerError::RejectedByScan)?;

            match fs::rename(&temp, dest) {
                Ok(()) => {}
                Err(_) if exists => {
                    // Windows rename cannot replace; the verified temp is kept
                    // until the old file is removed, so a crash leaves both.
                    fs::remove_file(dest)?;
                    fs::rename(&temp, dest)?;
                }
                Err(e) => return Err(BrokerError::Io(e.to_string())),
            }

            Ok(Exported {
                path: dest.to_path_buf(),
                sha256: actual,
                bytes: staged_meta.len(),
                replaced_existing: exists,
            })
        })();

        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    /// True when a path is inside this broker's staging root.
    pub fn owns(&self, path: &Path) -> bool {
        fs::canonicalize(path)
            .map(|p| p.starts_with(&self.root))
            .unwrap_or(false)
    }
}

fn safe_file_name(path: &Path) -> Result<String, BrokerError> {
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(BrokerError::UnsafeName(path.display().to_string()));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| BrokerError::UnsafeName(path.display().to_string()))?;
    // Reject NTFS alternate data streams and characters that enable path tricks.
    if name.is_empty()
        || name.contains(':')
        || name.contains('\0')
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
    {
        return Err(BrokerError::UnsafeName(name.to_string()));
    }
    Ok(name.to_string())
}

fn hash_file(path: &Path, limit: u64) -> Result<String, BrokerError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.len() > limit {
        return Err(BrokerError::TooLarge {
            size: meta.len(),
            limit,
        });
    }
    let data = fs::read(path)?;
    Ok(sha256_bytes(&data).to_hex())
}

fn unique() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}-{}", std::process::id(), nanos, COUNTER.fetch_add(1, Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempTree(PathBuf);

    impl TempTree {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "litric-broker-{tag}-{}-{}",
                std::process::id(),
                unique()
            ));
            fs::create_dir_all(&p).unwrap();
            TempTree(p)
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn import_copies_and_verifies_without_touching_the_source() {
        let t = TempTree::new("import");
        let src = t.0.join("sample.bin");
        fs::write(&src, b"payload bytes").unwrap();
        let before = fs::read(&src).unwrap();

        let broker = Broker::new(&t.0.join("stage")).unwrap();
        let imported = broker.import(&src).unwrap();

        assert_eq!(fs::read(&src).unwrap(), before, "source must be unchanged");
        assert_eq!(fs::read(&imported.staged).unwrap(), before);
        assert_eq!(imported.bytes, 13);
        assert_eq!(imported.sha256, sha256_bytes(&before).to_hex());
        assert!(imported.staged.starts_with(broker.root()));
    }

    #[test]
    fn export_commits_a_verified_copy() {
        let t = TempTree::new("export");
        let src = t.0.join("sample.bin");
        fs::write(&src, b"payload bytes").unwrap();
        let broker = Broker::new(&t.0.join("stage")).unwrap();
        let imported = broker.import(&src).unwrap();

        let out_dir = t.0.join("out");
        fs::create_dir_all(&out_dir).unwrap();
        let dest = out_dir.join("exported.bin");
        let exported = broker.export(&imported.staged, &dest, false).unwrap();

        assert_eq!(fs::read(&dest).unwrap(), b"payload bytes");
        assert_eq!(exported.sha256, imported.sha256);
        assert!(!exported.replaced_existing);
    }

    #[test]
    fn existing_destination_is_refused_without_approval() {
        let t = TempTree::new("overwrite");
        let src = t.0.join("sample.bin");
        fs::write(&src, b"new content").unwrap();
        let broker = Broker::new(&t.0.join("stage")).unwrap();
        let imported = broker.import(&src).unwrap();

        let dest = t.0.join("existing.bin");
        fs::write(&dest, b"original content").unwrap();

        let err = broker.export(&imported.staged, &dest, false).unwrap_err();
        assert_eq!(err, BrokerError::WouldOverwrite(dest.clone()));
        assert_eq!(fs::read(&dest).unwrap(), b"original content", "original preserved");
    }

    #[test]
    fn approved_overwrite_replaces_the_file() {
        let t = TempTree::new("approved");
        let src = t.0.join("sample.bin");
        fs::write(&src, b"new content").unwrap();
        let broker = Broker::new(&t.0.join("stage")).unwrap();
        let imported = broker.import(&src).unwrap();

        let dest = t.0.join("existing.bin");
        fs::write(&dest, b"old").unwrap();
        let exported = broker.export(&imported.staged, &dest, true).unwrap();
        assert!(exported.replaced_existing);
        assert_eq!(fs::read(&dest).unwrap(), b"new content");
    }

    #[test]
    fn scan_gate_rejection_leaves_destination_absent_and_staging_intact() {
        let t = TempTree::new("gate");
        let src = t.0.join("sample.bin");
        fs::write(&src, b"payload").unwrap();
        let broker = Broker::new(&t.0.join("stage")).unwrap();
        let imported = broker.import(&src).unwrap();

        let dest = t.0.join("out.bin");
        let err = broker
            .export_gated(&imported.staged, &dest, false, |_| {
                Err("malicious payload".to_string())
            })
            .unwrap_err();
        assert_eq!(err, BrokerError::RejectedByScan("malicious payload".into()));
        assert!(!dest.exists());
        assert!(imported.staged.exists(), "staged copy preserved");
    }

    #[test]
    fn traversal_and_ads_names_are_rejected() {
        let t = TempTree::new("traversal");
        let broker = Broker::new(&t.0.join("stage")).unwrap();
        let src = t.0.join("ok.bin");
        fs::write(&src, b"x").unwrap();
        let imported = broker.import(&src).unwrap();

        for bad in ["../escape.bin", "file.txt:ads"] {
            let dest = t.0.join(bad);
            let err = broker.export(&imported.staged, &dest, true).unwrap_err();
            assert!(matches!(err, BrokerError::UnsafeName(_)), "{bad}: {err:?}");
        }
    }

    #[test]
    fn oversized_files_are_refused() {
        let t = TempTree::new("size");
        let src = t.0.join("big.bin");
        fs::write(&src, vec![0u8; 64]).unwrap();
        let broker = Broker::new(&t.0.join("stage"))
            .unwrap()
            .with_max_bytes(16);
        assert!(matches!(
            broker.import(&src).unwrap_err(),
            BrokerError::TooLarge { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused() {
        let t = TempTree::new("symlink");
        let real = t.0.join("real.bin");
        fs::write(&real, b"data").unwrap();
        let link = t.0.join("link.bin");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let broker = Broker::new(&t.0.join("stage")).unwrap();
        assert!(matches!(
            broker.import(&link).unwrap_err(),
            BrokerError::Symlink(_)
        ));
    }

    #[test]
    fn export_outside_staging_is_refused() {
        let t = TempTree::new("outside");
        let broker = Broker::new(&t.0.join("stage")).unwrap();
        let foreign = t.0.join("foreign.bin");
        fs::write(&foreign, b"data").unwrap();
        assert!(matches!(
            broker.export(&foreign, &t.0.join("out.bin"), true).unwrap_err(),
            BrokerError::OutsideStaging(_)
        ));
    }
}
