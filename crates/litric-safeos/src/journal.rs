//! Session journal and recovery planner.
//!
//! The journal is an append-only JSONL file with `sync_data` after every record, so
//! a crash or power loss leaves a readable history ending in the last known state.
//! A session whose last state was `preparing` or `running` is treated as crashed
//! and marked for recovery — its disks are never deleted automatically.
//!
//! Cleanup only ever targets directories this module created, inside the journal
//! root, for a validated session id. It is idempotent.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: String,
    pub app: String,
    pub level: String,
    pub backend: String,
    pub state: String,
    #[serde(default)]
    pub note: String,
    pub updated_unix: u64,
}

/// A session that did not finish cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCase {
    pub id: String,
    pub app: String,
    pub last_state: String,
    pub action: &'static str,
}

/// Append-only session journal.
#[derive(Debug, Clone)]
pub struct Journal {
    root: PathBuf,
    file: PathBuf,
}

impl Journal {
    pub fn open(root: &Path) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        Ok(Journal {
            root: root.to_path_buf(),
            file: root.join("sessions.jsonl"),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn start(&self, app: &str, level: &str, backend: &str) -> io::Result<SessionRecord> {
        let record = SessionRecord {
            id: format!("{}-{}", now(), unique()),
            app: app.to_string(),
            level: level.to_string(),
            backend: backend.to_string(),
            state: "preparing".into(),
            note: String::new(),
            updated_unix: now(),
        };
        self.append(&record)?;
        Ok(record)
    }

    pub fn update(&self, id: &str, state: &str, note: &str) -> io::Result<()> {
        validate_id(id)?;
        let app = self
            .latest(id)?
            .map(|r| r.app)
            .unwrap_or_default();
        let level = self.latest(id)?.map(|r| r.level).unwrap_or_default();
        let backend = self.latest(id)?.map(|r| r.backend).unwrap_or_default();
        self.append(&SessionRecord {
            id: id.to_string(),
            app,
            level,
            backend,
            state: state.to_string(),
            note: note.to_string(),
            updated_unix: now(),
        })
    }

    /// All parsed records plus the number of lines that could not be parsed.
    /// Corrupt lines are counted, not hidden, and do not block recovery.
    pub fn records(&self) -> io::Result<(Vec<SessionRecord>, usize)> {
        let text = match fs::read_to_string(&self.file) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        let mut corrupt = 0;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<SessionRecord>(line) {
                Ok(r) => out.push(r),
                Err(_) => corrupt += 1,
            }
        }
        Ok((out, corrupt))
    }

    pub fn latest(&self, id: &str) -> io::Result<Option<SessionRecord>> {
        let (records, _) = self.records()?;
        Ok(records.into_iter().rfind(|r| r.id == id))
    }

    /// Sessions that never reached a terminal state. Their storage must be
    /// preserved and offered for recovery, never deleted.
    pub fn recover(&self) -> io::Result<Vec<RecoveryCase>> {
        let (records, _) = self.records()?;
        let mut last: Vec<SessionRecord> = Vec::new();
        for r in records {
            match last.iter_mut().find(|s| s.id == r.id) {
                Some(slot) => *slot = r,
                None => last.push(r),
            }
        }
        Ok(last
            .into_iter()
            .filter(|r| r.state == "preparing" || r.state == "running")
            .map(|r| RecoveryCase {
                id: r.id,
                app: r.app,
                last_state: r.state,
                action: "preserve session storage and offer user-directed recovery",
            })
            .collect())
    }

    /// Directories cleanup would remove. Empty when already cleaned.
    pub fn plan_cleanup(&self, id: &str) -> io::Result<Vec<PathBuf>> {
        validate_id(id)?;
        let session = self.root.join(id);
        let mut out = Vec::new();
        for sub in ["input", "output", "vm"] {
            let p = session.join(sub);
            if p.is_dir() {
                out.push(p);
            }
        }
        Ok(out)
    }

    /// Removes this session's broker directories only. Idempotent.
    pub fn cleanup(&self, id: &str) -> io::Result<usize> {
        let mut removed = 0;
        for path in self.plan_cleanup(id)? {
            if path.is_dir() && path.starts_with(&self.root) {
                fs::remove_dir_all(&path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn append(&self, record: &SessionRecord) -> io::Result<()> {
        let mut line = serde_json::to_string(record).map_err(io::Error::other)?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file)?;
        f.write_all(line.as_bytes())?;
        f.sync_data()?;
        Ok(())
    }
}

fn validate_id(id: &str) -> io::Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid session id `{id}`"),
        ))
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unique() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}", std::process::id(), nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempTree(PathBuf);

    impl TempTree {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "litric-journal-{tag}-{}-{}",
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
    fn state_transitions_are_recorded_in_order() {
        let t = TempTree::new("states");
        let j = Journal::open(&t.0).unwrap();
        let s = j.start("app.exe", "unknown", "windows_sandbox").unwrap();
        j.update(&s.id, "running", "").unwrap();
        j.update(&s.id, "completed", "clean exit").unwrap();

        let latest = j.latest(&s.id).unwrap().unwrap();
        assert_eq!(latest.state, "completed");
        assert_eq!(latest.note, "clean exit");
        let (all, corrupt) = j.records().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(corrupt, 0);
        assert!(j.recover().unwrap().is_empty());
    }

    #[test]
    fn a_running_session_that_never_finished_is_a_recovery_case() {
        let t = TempTree::new("crash");
        let j = Journal::open(&t.0).unwrap();
        let s = j.start("app.exe", "suspicious", "hyperv").unwrap();
        j.update(&s.id, "running", "").unwrap();

        let cases = j.recover().unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].id, s.id);
        assert_eq!(cases[0].action, "preserve session storage and offer user-directed recovery");
    }

    #[test]
    fn cleanup_is_idempotent_and_only_touches_session_dirs() {
        let t = TempTree::new("cleanup");
        let j = Journal::open(&t.0).unwrap();
        let s = j.start("app.exe", "unknown", "windows_sandbox").unwrap();
        fs::create_dir_all(t.0.join(&s.id).join("input")).unwrap();
        fs::create_dir_all(t.0.join(&s.id).join("output")).unwrap();
        let unrelated = t.0.join("user-data.txt");
        fs::write(&unrelated, b"keep me").unwrap();

        assert_eq!(j.cleanup(&s.id).unwrap(), 2);
        assert_eq!(j.cleanup(&s.id).unwrap(), 0, "second cleanup is a no-op");
        assert!(unrelated.exists(), "unrelated files are never removed");
    }

    #[test]
    fn invalid_session_ids_are_rejected() {
        let t = TempTree::new("badid");
        let j = Journal::open(&t.0).unwrap();
        assert!(j.update("../escape", "running", "").is_err());
        assert!(j.plan_cleanup("..").is_err());
    }

    #[test]
    fn corrupt_lines_are_counted_not_fatal() {
        let t = TempTree::new("corrupt");
        let j = Journal::open(&t.0).unwrap();
        let s = j.start("app.exe", "unknown", "windows_sandbox").unwrap();
        let mut f = OpenOptions::new().append(true).open(t.0.join("sessions.jsonl")).unwrap();
        f.write_all(b"{not json}\n").unwrap();
        let (records, corrupt) = j.records().unwrap();
        assert_eq!(corrupt, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(j.latest(&s.id).unwrap().unwrap().state, "preparing");
    }
}
