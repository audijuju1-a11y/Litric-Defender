//! Scan orchestration: targets, budgets, caching and honest accounting.
//!
//! Rules that this module enforces:
//!
//! * **Unknown is not clean.** `unknown` files are counted separately and never
//!   added to `clean`. The summary can therefore show "0 clean" for a directory
//!   the engine has no knowledge about, which is the truth.
//! * **Skipped is not clean.** Over-size, over-budget, unreadable and errored
//!   files each have their own counter.
//! * **No unbounded work.** A scan has a file cap, a byte cap per file, a wall
//!   clock deadline and a bounded error list.
//! * **No re-scanning.** A cache keyed on (path, size, mtime) allows smart scans
//!   to skip unchanged files; the cache is invalidated when either mtime or size
//!   changes.
//! * **Never follows links out of scope.** Symlinks and reparse points are
//!   skipped by default; hard links are de-duplicated by inode on Unix.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::engine::{Engine, FileReport, Verdict};

/// Hard limits applied to every scan.
#[derive(Debug, Clone)]
pub struct ScanLimits {
    /// Files larger than this are sampled, not fully read (and flagged).
    pub max_file_bytes: u64,
    /// Stop after this many files have been examined.
    pub max_files: u64,
    /// Wall-clock budget for the whole scan.
    pub deadline: Option<Duration>,
    /// Follow symbolic links / reparse points while walking.
    pub follow_links: bool,
    /// Paths (and their subtrees) that are never scanned.
    pub excluded_roots: Vec<PathBuf>,
}

impl Default for ScanLimits {
    fn default() -> Self {
        ScanLimits {
            max_file_bytes: 128 * 1024 * 1024,
            max_files: 2_000_000,
            deadline: None,
            follow_links: false,
            excluded_roots: Vec::new(),
        }
    }
}

/// Cached result for an unchanged file.
#[derive(Debug, Clone)]
pub struct CachedVerdict {
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub sha256: String,
    pub verdict: Verdict,
    pub score: u32,
    pub threat_name: Option<String>,
}

/// Smart-scan cache. Not persisted by this layer; the service owns persistence.
#[derive(Debug, Default)]
pub struct ScanCache {
    entries: HashMap<PathBuf, CachedVerdict>,
    hits: u64,
    misses: u64,
}

impl ScanCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(
        &mut self,
        path: &Path,
        size: u64,
        modified: Option<SystemTime>,
    ) -> Option<&CachedVerdict> {
        match self.entries.get(path) {
            Some(e) if e.size == size && e.modified == modified => {
                self.hits += 1;
                self.entries.get(path)
            }
            Some(_) => {
                self.misses += 1;
                None
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    pub fn insert(&mut self, path: PathBuf, v: CachedVerdict) {
        self.entries.insert(path, v);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn hits(&self) -> u64 {
        self.hits
    }

    pub fn misses(&self) -> u64 {
        self.misses
    }
}

/// Outcome for one file.
#[derive(Debug, Clone)]
pub struct FileOutcome {
    pub path: PathBuf,
    pub verdict: Verdict,
    pub score: u32,
    pub threat_name: Option<String>,
    pub sha256: Option<String>,
    pub truncated: bool,
    pub cached: bool,
    pub error: Option<String>,
}

/// Why a file was not scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    TooLarge,
    BudgetFiles,
    BudgetTime,
    Excluded,
    LinkNotFollowed,
    Duplicate,
    Unreadable,
    Empty,
}

/// Aggregate, honest counters for one scan.
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    pub files_seen: u64,
    pub files_scanned: u64,
    pub clean: u64,
    pub unknown: u64,
    pub suspicious: u64,
    pub malicious: u64,
    pub skipped: u64,
    pub skipped_too_large: u64,
    pub skipped_budget: u64,
    pub skipped_links: u64,
    pub skipped_duplicates: u64,
    pub unreadable: u64,
    pub truncated: u64,
    pub cache_hits: u64,
    pub bytes_scanned: u64,
    pub duration: Duration,
    pub errors: Vec<(PathBuf, String)>,
    pub detections: Vec<FileOutcome>,
}

impl ScanSummary {
    pub fn files_per_second(&self) -> f64 {
        let s = self.duration.as_secs_f64();
        if s > 0.0 {
            self.files_scanned as f64 / s
        } else {
            0.0
        }
    }

    pub fn mb_per_second(&self) -> f64 {
        let s = self.duration.as_secs_f64();
        if s > 0.0 {
            (self.bytes_scanned as f64 / (1024.0 * 1024.0)) / s
        } else {
            0.0
        }
    }

    /// Every non-clean category, for the UI's "not verified" figure.
    pub fn not_verified(&self) -> u64 {
        self.unknown + self.suspicious + self.malicious + self.unreadable
    }

    fn record(&mut self, outcome: &FileOutcome) {
        match outcome.verdict {
            Verdict::Clean => self.clean += 1,
            Verdict::Unknown => self.unknown += 1,
            Verdict::Suspicious => self.suspicious += 1,
            Verdict::Malicious => self.malicious += 1,
        }
        if outcome.verdict != Verdict::Clean {
            self.detections.push(outcome.clone());
        }
    }
}

/// The scanner: engine + limits + optional cache.
pub struct Scanner<'a> {
    engine: &'a Engine,
    pub limits: ScanLimits,
    pub cache: Option<&'a mut ScanCache>,
    /// Hard stop used by the walker as well as the engine.
    pub max_errors_recorded: usize,
}

impl<'a> Scanner<'a> {
    pub fn new(engine: &'a Engine, limits: ScanLimits) -> Self {
        Scanner {
            engine,
            limits,
            cache: None,
            max_errors_recorded: 64,
        }
    }

    pub fn with_cache(mut self, cache: &'a mut ScanCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Scans a single file, honouring the above limits.
    pub fn scan_file(&mut self, path: &Path, summary: &mut ScanSummary) -> Option<FileOutcome> {
        summary.files_seen += 1;
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                summary.unreadable += 1;
                if summary.errors.len() < self.max_errors_recorded {
                    summary.errors.push((path.to_path_buf(), e.to_string()));
                }
                return None;
            }
        };
        if meta.file_type().is_symlink() && !self.limits.follow_links {
            summary.skipped_links += 1;
            summary.skipped += 1;
            return None;
        }
        if !meta.is_file() {
            return None;
        }
        let size = meta.len();
        let modified = meta.modified().ok();

        // Cache lookup for unchanged files.
        if let Some(cache) = self.cache.as_mut() {
            if let Some(hit) = cache.get(path, size, modified) {
                let outcome = FileOutcome {
                    path: path.to_path_buf(),
                    verdict: hit.verdict,
                    score: hit.score,
                    threat_name: hit.threat_name.clone(),
                    sha256: Some(hit.sha256.clone()),
                    truncated: false,
                    cached: true,
                    error: None,
                };
                summary.cache_hits += 1;
                summary.files_scanned += 1;
                summary.record(&outcome);
                return Some(outcome);
            }
        }

        if size > self.limits.max_file_bytes {
            summary.skipped_too_large += 1;
            summary.skipped += 1;
        }

        let (report, truncated) = match self.engine.analyze_path(path, self.limits.max_file_bytes) {
            Ok(v) => v,
            Err(e) => {
                summary.unreadable += 1;
                if summary.errors.len() < self.max_errors_recorded {
                    summary.errors.push((path.to_path_buf(), e.to_string()));
                }
                return None;
            }
        };
        if truncated {
            summary.truncated += 1;
        }
        summary.files_scanned += 1;
        summary.bytes_scanned += report.size.min(self.limits.max_file_bytes);

        let outcome = FileOutcome {
            path: path.to_path_buf(),
            verdict: report.verdict,
            score: report.score,
            threat_name: report.threat_name.clone(),
            sha256: Some(report.sha256.to_hex()),
            truncated,
            cached: false,
            error: None,
        };
        summary.record(&outcome);

        if let Some(cache) = self.cache.as_mut() {
            if !truncated {
                cache.insert(
                    path.to_path_buf(),
                    CachedVerdict {
                        size,
                        modified,
                        sha256: report.sha256.to_hex(),
                        verdict: report.verdict,
                        score: report.score,
                        threat_name: report.threat_name.clone(),
                    },
                );
            }
        }
        Some(outcome)
    }

    /// Scans a file and returns the full report (used by on-demand scans and the
    /// CLI, where the caller wants evidence, not just a verdict).
    pub fn analyze_file(&self, path: &Path) -> std::io::Result<(FileReport, bool)> {
        self.engine.analyze_path(path, self.limits.max_file_bytes)
    }

    /// Scans a file or a directory tree.
    pub fn scan_path(&mut self, root: &Path) -> ScanSummary {
        let started = Instant::now();
        let mut summary = ScanSummary::default();
        let deadline = self.limits.deadline.map(|d| Instant::now() + d);

        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
        let mut seen_inodes: HashSet<(u64, u64)> = HashSet::new();

        while let Some(path) = stack.pop() {
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    summary.skipped_budget += stack.len() as u64 + 1;
                    break;
                }
            }
            if summary.files_seen >= self.limits.max_files {
                summary.skipped_budget += 1;
                break;
            }
            if self.is_excluded(&path) {
                summary.skipped += 1;
                continue;
            }

            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    summary.unreadable += 1;
                    if summary.errors.len() < self.max_errors_recorded {
                        summary.errors.push((path.clone(), e.to_string()));
                    }
                    continue;
                }
            };

            if meta.file_type().is_symlink() && !self.limits.follow_links {
                summary.skipped_links += 1;
                summary.skipped += 1;
                continue;
            }

            if meta.is_dir() {
                match std::fs::read_dir(&path) {
                    Ok(rd) => {
                        for entry in rd.flatten() {
                            stack.push(entry.path());
                        }
                    }
                    Err(e) => {
                        summary.unreadable += 1;
                        if summary.errors.len() < self.max_errors_recorded {
                            summary.errors.push((path.clone(), e.to_string()));
                        }
                    }
                }
                continue;
            }

            // Hard-link de-duplication on Unix: the same inode is scanned once.
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let key = (meta.dev(), meta.ino());
                if !seen_inodes.insert(key) {
                    summary.skipped_duplicates += 1;
                    summary.skipped += 1;
                    continue;
                }
            }

            self.scan_file(&path, &mut summary);
        }

        summary.duration = started.elapsed();
        summary
    }

    fn is_excluded(&self, path: &Path) -> bool {
        self.limits
            .excluded_roots
            .iter()
            .any(|root| path.starts_with(root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{EngineConfig, Engine};
    use crate::rules::{parse_rule_file, RuleSet};
    use crate::threatdb::ThreatDb;
    use std::fs;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "litric-scan-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn engine() -> Engine {
        let rules = r#"
rule Eicar.Test {
    meta:
        description = "EICAR test file"
        severity = "critical"
        family = "EICAR-Test"
    strings:
        $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $s
}
"#;
        let rs = RuleSet::compile(parse_rule_file(rules, "test").unwrap()).unwrap();
        Engine::new(rs, ThreatDb::empty(), EngineConfig::default())
    }

    #[test]
    fn directory_scan_accounts_every_category() {
        let dir = temp_dir("acct");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(
            dir.join("eicar.com"),
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();
        fs::write(dir.join("sub/notes.txt"), b"hello there\n").unwrap();
        fs::write(dir.join("empty.bin"), b"").unwrap();

        let e = engine();
        let mut s = Scanner::new(&e, ScanLimits::default());
        let summary = s.scan_path(&dir);

        assert_eq!(summary.files_scanned, 3, "summary: {summary:?}");
        assert_eq!(summary.malicious, 1);
        assert_eq!(summary.unknown, 2, "plain files must be unknown, not clean");
        assert_eq!(summary.clean, 0);
        // Malicious files are also "not verified clean".
        assert_eq!(summary.not_verified(), 3);
        assert!(summary.detections.iter().any(|d| d
            .threat_name
            .as_deref()
            .map(|n| n.contains("Eicar"))
            .unwrap_or(false)));
        assert!(summary.files_per_second() > 0.0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_skips_unchanged_files() {
        let dir = temp_dir("cache");
        fs::write(dir.join("a.bin"), b"some content").unwrap();
        let e = engine();
        let mut cache = ScanCache::new();
        let s1 = {
            let mut s = Scanner::new(&e, ScanLimits::default()).with_cache(&mut cache);
            s.scan_path(&dir)
        };
        assert_eq!(s1.cache_hits, 0);
        let s2 = {
            let mut s = Scanner::new(&e, ScanLimits::default()).with_cache(&mut cache);
            s.scan_path(&dir)
        };
        assert_eq!(s2.cache_hits, 1);

        // Modifying the file must invalidate the entry.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(dir.join("a.bin"), b"some different content").unwrap();
        let s3 = {
            let mut s = Scanner::new(&e, ScanLimits::default()).with_cache(&mut cache);
            s.scan_path(&dir)
        };
        assert_eq!(s3.cache_hits, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_budget_stops_the_walk() {
        let dir = temp_dir("budget");
        for i in 0..20 {
            fs::write(dir.join(format!("f{i}.bin")), b"x").unwrap();
        }
        let e = engine();
        let limits = ScanLimits {
            max_files: 5,
            ..Default::default()
        };
        let mut s = Scanner::new(&e, limits);
        let summary = s.scan_path(&dir);
        assert!(summary.files_scanned <= 5, "summary: {summary:?}");
        assert!(summary.skipped_budget > 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn excluded_roots_are_not_walked() {
        let dir = temp_dir("excl");
        fs::create_dir_all(dir.join("vault")).unwrap();
        fs::write(dir.join("vault/secret.bin"), b"x").unwrap();
        fs::write(dir.join("a.bin"), b"x").unwrap();
        let e = engine();
        let limits = ScanLimits {
            excluded_roots: vec![dir.join("vault")],
            ..Default::default()
        };
        let mut s = Scanner::new(&e, limits);
        let summary = s.scan_path(&dir);
        assert_eq!(summary.files_scanned, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn hard_links_are_deduplicated() {
        let dir = temp_dir("hardlink");
        let a = dir.join("a.bin");
        fs::write(&a, b"duplicate content").unwrap();
        let b = dir.join("b.bin");
        if fs::hard_link(&a, &b).is_ok() {
            let e = engine();
            let mut s = Scanner::new(&e, ScanLimits::default());
            let summary = s.scan_path(&dir);
            assert_eq!(summary.files_scanned, 1);
            assert_eq!(summary.skipped_duplicates, 1);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
