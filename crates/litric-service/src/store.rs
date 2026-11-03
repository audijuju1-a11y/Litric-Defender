//! Persisted service state: settings and scan history.
//!
//! Writes are atomic (temp file + rename) so a power loss cannot leave a
//! half-written configuration that the service would then refuse to load.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const SETTINGS_FILE: &str = "settings.json";
pub const HISTORY_FILE: &str = "history.json";
const MAX_HISTORY: usize = 200;

/// User-tunable policy. Every field is honoured by the service; nothing here is
/// decorative.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Request real-time protection. This is a *request*: the status endpoint
    /// reports whether it is actually active, which on a host without the kernel
    /// sensor it is not.
    pub realtime_requested: bool,
    /// Lower CPU/IO priority for background scans.
    pub eco_mode: bool,
    /// Reuse scan results for unchanged files.
    pub scan_cache: bool,
    /// Days to keep quarantined objects before offering them for review.
    pub retention_days: u32,
    /// Never quarantine automatically; only alert.
    pub alert_only: bool,
    /// Scan removable drives when attached (requires the Windows sensor; off).
    pub scan_removable: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            realtime_requested: false,
            eco_mode: false,
            scan_cache: true,
            retention_days: 30,
            alert_only: false,
            scan_removable: false,
        }
    }
}

impl Settings {
    /// Rejects values the service cannot honour, instead of silently clamping.
    pub fn validate(&self) -> Result<(), String> {
        if self.retention_days > 3650 {
            return Err("retention_days must be <= 3650".into());
        }
        Ok(())
    }
}

/// One completed scan, for the UI's history view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub job_id: String,
    pub target: String,
    pub finished_unix: u64,
    pub files_scanned: u64,
    pub malicious: u64,
    pub suspicious: u64,
    pub unknown: u64,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct HistoryFile {
    entries: Vec<HistoryEntry>,
}

/// Durable service state.
pub struct Store {
    dir: PathBuf,
    pub settings: Settings,
    pub history: Vec<HistoryEntry>,
}

impl Store {
    pub fn open(dir: &Path) -> std::io::Result<Store> {
        fs::create_dir_all(dir)?;
        let settings = match fs::read(dir.join(SETTINGS_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Settings::default(),
        };
        let history = match fs::read(dir.join(HISTORY_FILE)) {
            Ok(bytes) => serde_json::from_slice::<HistoryFile>(&bytes)
                .map(|h| h.entries)
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let store = Store {
            dir: dir.to_path_buf(),
            settings,
            history,
        };
        // Materialise defaults so the files exist and are inspectable.
        store.save_settings()?;
        Ok(store)
    }

    pub fn save_settings(&self) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(&self.settings)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        write_atomic(&self.dir.join(SETTINGS_FILE), &json)
    }

    pub fn save_history(&self) -> std::io::Result<()> {
        let file = HistoryFile {
            entries: self.history.clone(),
        };
        let json =
            serde_json::to_vec_pretty(&file).map_err(|e| std::io::Error::other(e.to_string()))?;
        write_atomic(&self.dir.join(HISTORY_FILE), &json)
    }

    /// Appends a scan result, keeping only the most recent entries.
    pub fn record(&mut self, entry: HistoryEntry) -> std::io::Result<()> {
        self.history.push(entry);
        if self.history.len() > MAX_HISTORY {
            let excess = self.history.len() - MAX_HISTORY;
            self.history.drain(0..excess);
        }
        self.save_history()
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "litric-store-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn settings_roundtrip_and_reload() {
        let d = dir("settings");
        let mut s = Store::open(&d).unwrap();
        assert_eq!(s.settings.retention_days, 30);
        s.settings.eco_mode = true;
        s.settings.retention_days = 7;
        s.save_settings().unwrap();

        let reloaded = Store::open(&d).unwrap();
        assert!(reloaded.settings.eco_mode);
        assert_eq!(reloaded.settings.retention_days, 7);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn corrupt_settings_fall_back_to_defaults() {
        let d = dir("corrupt");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join(SETTINGS_FILE), b"{ not json").unwrap();
        let s = Store::open(&d).unwrap();
        assert_eq!(s.settings.retention_days, 30);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn history_is_capped() {
        let d = dir("history");
        let mut s = Store::open(&d).unwrap();
        for i in 0..(MAX_HISTORY + 25) {
            s.record(HistoryEntry {
                job_id: format!("j{i}"),
                target: "/x".into(),
                finished_unix: i as u64,
                files_scanned: 1,
                malicious: 0,
                suspicious: 0,
                unknown: 1,
                cancelled: false,
            })
            .unwrap();
        }
        assert_eq!(s.history.len(), MAX_HISTORY);
        assert_eq!(s.history.last().unwrap().job_id, format!("j{}", MAX_HISTORY + 24));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn validation_rejects_absurd_retention() {
        let s = Settings {
            retention_days: 99_999,
            ..Default::default()
        };
        assert!(s.validate().is_err());
    }
}
