//! Litric scanner core.
//!
//! Honesty rules enforced here:
//!  * `NoThreatFound` means "no loaded rule matched", never "safe".
//!  * Skipped / Unscannable / Error files are never counted as clean and
//!    make the report incomplete.
//!  * An empty or tiny signature database produces an explicit warning.
//!  * Symlinks and reparse points are not followed.
//!  * Each file is opened once; hash and pattern matching use the same bytes
//!    (no check-then-use race on the content).

pub mod ndb;

use aho_corasick::AhoCorasick;
use sha2::{Digest, Sha256};
use sigdb::{Algo, Database, Severity, Target};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::fs;

pub const MAX_STORED_RESULTS: usize = 100_000;
pub const MAX_DETECTIONS_PER_FILE: usize = 32;
pub const LOW_COVERAGE_RULES: usize = 1000;

#[derive(Debug, Clone)]
pub struct Limits {
    /// Files up to this size are fully buffered for pattern matching.
    pub max_pattern_scan_bytes: u64,
    /// Files above this are skipped entirely (not even hashed).
    pub max_hash_bytes: u64,
    pub max_depth: usize,
    /// Work units per file for extended-signature (NDB) evaluation.
    pub ndb_budget: i64,
}
impl Default for Limits {
    fn default() -> Self {
        Self { max_pattern_scan_bytes: 32 << 20, max_hash_bytes: 4 << 30, max_depth: 32, ndb_budget: 50_000_000 }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    Hash,
    SectionHash,
    Pattern,
    /// ClamAV-style extended signature (NDB).
    Extended,
    /// ClamAV-style logical signature (LDB).
    Logical,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub rule_id: String,
    pub family: String,
    pub severity: Severity,
    pub confidence: u8,
    pub method: Method,
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// No loaded rule matched. NOT a statement that the file is safe.
    NoThreatFound,
    /// Matched the known-good list; detection suppressed.
    Allowlisted,
    Detected(Vec<Detection>),
    /// Heuristic verdict: multiple independent signals, no known-malware match.
    /// This is NOT a claim that the file is malware.
    Suspicious(peanalysis::Risk),
    /// Could not be fully analysed (e.g. too large for pattern matching).
    Unscannable(String),
    Skipped(String),
    Error(String),
}

#[derive(Debug, Clone)]
pub struct FileResult {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: Option<String>,
    pub kind: Target,
    /// Heuristic analysis (PE files only). Present for Weak anomalies too.
    pub risk: Option<peanalysis::Risk>,
    pub outcome: Outcome,
}

#[derive(Debug, Default)]
pub struct Report {
    pub files_seen: u64,
    pub no_threat_found: u64,
    pub allowlisted: u64,
    pub detected: u64,
    pub suspicious: u64,
    /// PE files with weak anomalies only (logged, not alerted).
    pub weak_anomalies: u64,
    pub unscannable: u64,
    pub skipped: u64,
    pub errors: u64,
    pub bytes: u64,
    /// Everything except `NoThreatFound` (bounded by MAX_STORED_RESULTS).
    pub results: Vec<FileResult>,
    pub warnings: Vec<String>,
    pub duration: Duration,
    pub db_serial: Option<u64>,
    pub db_rules: usize,
    /// Provenance lines recorded in the database (where its content came from).
    pub db_sources: Vec<String>,
    pub cancelled: bool,
}

impl Report {
    /// True only when every file was fully analysed and the scan finished.
    pub fn is_complete(&self) -> bool {
        !self.cancelled && self.unscannable + self.skipped + self.errors == 0
    }
    pub fn detections(&self) -> impl Iterator<Item = &FileResult> {
        self.results.iter().filter(|r| matches!(r.outcome, Outcome::Detected(_)))
    }
}

#[derive(Debug, Clone)]
pub struct Progress {
    pub files_done: u64,
    pub bytes: u64,
    pub detections: u64,
    pub current: PathBuf,
}


/// PE facts supplied by the caller's own parser (Litric core), so the
/// signature layer does not need a second PE parser.
#[derive(Debug, Clone, Default)]
pub struct PeFacts {
    pub entry_offset: Option<u64>,
    /// (raw_pointer, raw_size) for every section.
    pub sections: Vec<(u32, u32)>,
}

struct MatchOut {
    found: Vec<Detection>,
    section_limit_hit: bool,
    ndb_budget_hit: bool,
}

/// Result of `Scanner::scan_bytes`.
#[derive(Debug, Clone)]
pub struct BufferScan {
    pub sha256: Option<String>,
    pub detections: Vec<Detection>,
    pub allowlisted: bool,
    /// Reasons this check did not cover everything. Empty = fully evaluated.
    pub incomplete: Vec<String>,
}

pub struct Scanner {
    db: Arc<Database>,
    ac: Option<AhoCorasick>,
    ndb_index: ndb::NdbIndex,
    limits: Limits,
    warnings: Vec<String>,
}

pub fn detect_kind(data: &[u8], ext: Option<&str>) -> Target {
    if data.len() >= 0x40 && &data[..2] == b"MZ" {
        let e = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        if e.checked_add(4).map_or(false, |end| end <= data.len()) && &data[e..e + 4] == b"PE\0\0" {
            return Target::Pe;
        }
    }
    if data.starts_with(b"\x7fELF") {
        return Target::Elf;
    }
    if data.starts_with(b"PK\x03\x04") {
        return Target::Zip;
    }
    if data.starts_with(b"%PDF-") {
        return Target::Pdf;
    }
    if data.starts_with(b"#!") {
        return Target::Script;
    }
    match ext.map(|e| e.to_ascii_lowercase()).as_deref() {
        Some("ps1" | "vbs" | "vbe" | "js" | "jse" | "bat" | "cmd" | "wsf" | "hta") => Target::Script,
        _ => Target::Any,
    }
}

fn is_reparse(md: &fs::Metadata) -> bool {
    if md.file_type().is_symlink() {
        return true;
    }
    use std::os::windows::fs::MetadataExt;
    // FILE_ATTRIBUTE_REPARSE_POINT. The refusal path is implemented, but the
    // suite has no Windows symlink/junction fixture (see docs/LIMITATIONS.md).
    md.file_attributes() & 0x400 != 0
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Scanner {
    pub fn new(db: Arc<Database>, limits: Limits) -> Self {
        let mut warnings = vec![];
        let n = db.rule_count();
        if n == 0 {
            warnings.push("signature database is EMPTY: nothing can be detected by signature; results say nothing about safety".into());
        } else if n < LOW_COVERAGE_RULES {
            warnings.push(format!("signature database has only {n} rules: coverage is very limited"));
        }
        let ac = if db.patterns.is_empty() {
            None
        } else {
            AhoCorasick::new(db.patterns.iter().map(|p| p.pattern.as_slice())).ok()
        };
        if !db.patterns.is_empty() && ac.is_none() {
            warnings.push("pattern matcher failed to build: pattern signatures are NOT active".into());
        }
        let (ndb_index, ndb_warn) = ndb::NdbIndex::build(&db.ndb, &db.ldb);
        warnings.extend(ndb_warn);
        Self { db, ac, ndb_index, limits, warnings }
    }

    /// Scanner with no database at all (load failure). Reports say so.
    pub fn without_database(limits: Limits, reason: &str) -> Self {
        let mut s = Self::new(Arc::new(Database::default()), limits);
        s.warnings = vec![format!("NO signature database loaded: {reason}")];
        s
    }

    pub fn scan_file(&self, path: &Path) -> FileResult {
        let mut r = FileResult { path: path.to_path_buf(), size: 0, sha256: None, kind: Target::Any, risk: None, outcome: Outcome::NoThreatFound };
        let md = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                r.outcome = Outcome::Error(format!("cannot stat: {e}"));
                return r;
            }
        };
        if is_reparse(&md) {
            r.outcome = Outcome::Skipped("symlink/reparse point (not followed)".into());
            return r;
        }
        if !md.is_file() {
            r.outcome = Outcome::Skipped("not a regular file".into());
            return r;
        }
        let mut f = match fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                r.outcome = Outcome::Error(format!("cannot open: {e}"));
                return r;
            }
        };
        let size = f.metadata().map(|m| m.len()).unwrap_or(md.len());
        r.size = size;
        if size > self.limits.max_hash_bytes {
            r.outcome = Outcome::Skipped(format!("larger than {} MiB hash limit", self.limits.max_hash_bytes >> 20));
            return r;
        }
        let keep = size <= self.limits.max_pattern_scan_bytes;
        let mut buf: Vec<u8> = Vec::new();
        let mut hasher = Sha256::new();
        // Legacy digests are computed only when the database has rules that use them.
        let mut md5h = self.db.needs(Algo::Md5).then(md5::Md5::new);
        let mut sha1h = self.db.needs(Algo::Sha1).then(sha1::Sha1::new);
        let mut chunk = vec![0u8; 1 << 20];
        let mut total = 0u64;
        loop {
            match f.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&chunk[..n]);
                    if let Some(h) = md5h.as_mut() {
                        h.update(&chunk[..n]);
                    }
                    if let Some(h) = sha1h.as_mut() {
                        h.update(&chunk[..n]);
                    }
                    total += n as u64;
                    if keep {
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    if total > self.limits.max_hash_bytes {
                        r.outcome = Outcome::Skipped("file grew beyond hash limit while reading".into());
                        return r;
                    }
                }
                Err(e) => {
                    r.outcome = Outcome::Error(format!("read failed: {e}"));
                    return r;
                }
            }
        }
        r.size = total;
        let digest: [u8; 32] = hasher.finalize().into();
        r.sha256 = Some(hex(&digest));

        let md5d: Option<Vec<u8>> = md5h.map(|h| h.finalize().to_vec());
        let sha1d: Option<Vec<u8>> = sha1h.map(|h| h.finalize().to_vec());
        let allowed = self.db.allow.contains(&digest)
            || self.db.is_allowed(Algo::Sha256, &digest, total)
            || md5d.as_deref().map_or(false, |d| self.db.is_allowed(Algo::Md5, d, total))
            || sha1d.as_deref().map_or(false, |d| self.db.is_allowed(Algo::Sha1, d, total));
        if allowed {
            r.outcome = Outcome::Allowlisted;
            return r;
        }
        let mut analysis_crashed = false;
        let mut pe_in: Option<PeFacts> = None;
        if keep {
            r.kind = detect_kind(&buf, path.extension().and_then(|e| e.to_str()));
        }
        if keep && r.kind == Target::Pe {
            // Defense in depth: a parser bug must never take the scanner down.
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| peanalysis::analyze(&buf))) {
                Ok(Some((info, risk))) => {
                    r.risk = Some(risk);
                    pe_in = Some(PeFacts {
                        entry_offset: info.entry_offset,
                        sections: info.sections.iter().map(|s| (s.raw_ptr, s.raw_size)).collect(),
                    });
                }
                Ok(None) => {}
                Err(_) => analysis_crashed = true,
            }
        }
        let m = self.match_content(&buf, keep, &digest, md5d.as_deref(), sha1d.as_deref(), total, r.kind, pe_in.as_ref());
        let (found, section_limit_hit, ndb_budget_hit) = (m.found, m.section_limit_hit, m.ndb_budget_hit);
        r.outcome = if !found.is_empty() {
            Outcome::Detected(found)
        } else if analysis_crashed {
            Outcome::Error("PE analysis crashed (contained); file NOT analysed".into())
        } else if let Some(risk) = r.risk.clone().filter(|k| k.level >= peanalysis::Level::Suspicious) {
            Outcome::Suspicious(risk)
        } else if ndb_budget_hit {
            Outcome::Unscannable("extended/logical-signature evaluation budget exceeded; they were not fully evaluated for this file".into())
        } else if section_limit_hit {
            Outcome::Unscannable("PE section hashing stopped at its work limit (overlapping sections); analysis incomplete".into())
        } else if !keep {
            Outcome::Unscannable(format!("larger than {} MiB pattern-scan limit: hash-only check done", self.limits.max_pattern_scan_bytes >> 20))
        } else {
            Outcome::NoThreatFound
        };
        r
    }

    /// Signature matching over one in-memory buffer whose digests are already
    /// known. Shared by `scan_file` and `scan_bytes` so both paths have
    /// identical semantics.
    #[allow(clippy::too_many_arguments)]
    fn match_content(
        &self,
        buf: &[u8],
        keep: bool,
        digest: &[u8; 32],
        md5d: Option<&[u8]>,
        sha1d: Option<&[u8]>,
        total: u64,
        kind: Target,
        pe: Option<&PeFacts>,
    ) -> MatchOut {
        let mut found: Vec<Detection> = vec![];
        if let Some(rule) = self.db.hash_rules.get(digest) {
            found.push(Detection { rule_id: rule.id.clone(), family: rule.family.clone(), severity: rule.severity, confidence: rule.confidence, method: Method::Hash });
        }
        let file_hits = [
            (Algo::Sha256, Some(digest.to_vec())),
            (Algo::Md5, md5d.map(|d| d.to_vec())),
            (Algo::Sha1, sha1d.map(|d| d.to_vec())),
        ];
        for (algo, d) in file_hits {
            if let Some(rule) = d.and_then(|d| self.db.lookup_file(algo, &d, total)) {
                found.push(Detection { rule_id: rule.id, family: rule.family, severity: rule.severity, confidence: rule.confidence, method: Method::Hash });
            }
        }
        if keep {
            if let Some(ac) = &self.ac {
                let mut seen: HashSet<usize> = HashSet::new();
                for m in ac.find_overlapping_iter(buf) {
                    let idx = m.pattern().as_usize();
                    let pr = &self.db.patterns[idx];
                    if (pr.target == Target::Any || pr.target == kind) && seen.insert(idx) {
                        found.push(Detection { rule_id: pr.rule.id.clone(), family: pr.rule.family.clone(), severity: pr.rule.severity, confidence: pr.rule.confidence, method: Method::Pattern });
                        if found.len() >= MAX_DETECTIONS_PER_FILE {
                            break;
                        }
                    }
                }
            }
        }
        let mut section_limit_hit = false;
        let mut pe_ctx: Option<ndb::PeCtx> = None;
        if keep && kind == Target::Pe {
            if let Some(p) = pe {
                pe_ctx = Some(ndb::PeCtx { entry_offset: p.entry_offset, section_starts: p.sections.iter().map(|s| s.0 as u64).collect() });
                if self.db.has_section_rules() {
                    section_limit_hit = self.scan_section_list(buf, &p.sections, &mut found);
                }
            }
        }
        let mut ndb_budget_hit = false;
        if keep && (!self.db.ndb.is_empty() || !self.db.ldb.is_empty()) {
            let mut budget = self.limits.ndb_budget;
            let mut out = ndb::ScanOut::default();
            if self.ndb_index.scan(&self.db.ndb, &self.db.ldb, buf, kind, pe_ctx.as_ref(), &mut budget, &mut out).is_err() {
                ndb_budget_hit = true;
            }
            for ri in out.ndb_hits {
                let rule = self.db.ndb_rule(ri as usize);
                if !found.iter().any(|f| f.rule_id == rule.id) {
                    found.push(Detection { rule_id: rule.id, family: rule.family, severity: rule.severity, confidence: rule.confidence, method: Method::Extended });
                }
            }
            // A logical rule fires only if at least one subsignature matched AND its expression holds.
            let mut logical: Vec<(&u32, &Vec<u32>)> = out.ldb_counts.iter().collect();
            logical.sort_by_key(|(ri, _)| **ri);
            for (ri, counts) in logical {
                let lr = &self.db.ldb[*ri as usize];
                if counts.iter().any(|c| *c > 0) && lr.expr.eval(counts) {
                    let rule = self.db.ldb_rule(*ri as usize);
                    if !found.iter().any(|f| f.rule_id == rule.id) {
                        found.push(Detection { rule_id: rule.id, family: rule.family, severity: rule.severity, confidence: rule.confidence, method: Method::Logical });
                    }
                }
            }
        }
        MatchOut { found, section_limit_hit, ndb_budget_hit }
    }

    /// Match an in-memory buffer against the loaded signature database.
    ///
    /// This is the entry point the Litric pipeline uses: the caller (Litric's
    /// own file identification and PE parser) supplies the target kind and PE
    /// facts, so no second PE parser runs. Returns every detection plus an
    /// explicit list of reasons the check was incomplete — never a silent skip.
    pub fn scan_bytes(&self, data: &[u8], kind: Target, pe: Option<&PeFacts>) -> BufferScan {
        let mut incomplete = Vec::new();
        let total = data.len() as u64;
        if total > self.limits.max_hash_bytes {
            incomplete.push(format!("larger than {} MiB hash limit; not checked", self.limits.max_hash_bytes >> 20));
            return BufferScan { sha256: None, detections: vec![], allowlisted: false, incomplete };
        }
        let keep = total <= self.limits.max_pattern_scan_bytes;
        let digest: [u8; 32] = Sha256::digest(data).into();
        let md5d: Option<Vec<u8>> = self.db.needs(Algo::Md5).then(|| md5::Md5::digest(data).to_vec());
        let sha1d: Option<Vec<u8>> = self.db.needs(Algo::Sha1).then(|| sha1::Sha1::digest(data).to_vec());
        let allowed = self.db.allow.contains(&digest)
            || self.db.is_allowed(Algo::Sha256, &digest, total)
            || md5d.as_deref().map_or(false, |d| self.db.is_allowed(Algo::Md5, d, total))
            || sha1d.as_deref().map_or(false, |d| self.db.is_allowed(Algo::Sha1, d, total));
        if allowed {
            return BufferScan { sha256: Some(hex(&digest)), detections: vec![], allowlisted: true, incomplete };
        }
        let m = self.match_content(data, keep, &digest, md5d.as_deref(), sha1d.as_deref(), total, kind, pe);
        if m.ndb_budget_hit {
            incomplete.push("extended/logical-signature evaluation budget exceeded".into());
        }
        if m.section_limit_hit {
            incomplete.push("PE section hashing stopped at its work limit".into());
        }
        if !keep {
            incomplete.push(format!("larger than {} MiB pattern-scan limit: hash-only check done", self.limits.max_pattern_scan_bytes >> 20));
        }
        if kind == Target::Pe && pe.is_none() && (self.db.has_section_rules() || !self.db.ndb.is_empty() || !self.db.ldb.is_empty()) {
            incomplete.push("PE facts unavailable: section-hash and offset-anchored signatures were not evaluated".into());
        }
        BufferScan { sha256: Some(hex(&digest)), detections: m.found, allowlisted: false, incomplete }
    }

    /// Database provenance and load-time warnings (e.g. empty database).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Hash each PE section's raw bytes and look them up. Returns true if the
    /// work limit (2x file size, defeats overlapping-section amplification) was hit.
    fn scan_section_list(&self, data: &[u8], sections: &[(u32, u32)], found: &mut Vec<Detection>) -> bool {
        let limit = (data.len() as u64).saturating_mul(2);
        let mut hashed = 0u64;
        let (need_md5, need_sha1) = (self.db.needs(Algo::Md5), self.db.needs(Algo::Sha1));
        for &(raw_ptr, raw_size) in sections {
            if raw_size == 0 || (raw_ptr as usize) >= data.len() {
                continue;
            }
            let end = (raw_ptr as u64 + raw_size as u64).min(data.len() as u64) as usize;
            let slice = &data[raw_ptr as usize..end];
            hashed += slice.len() as u64;
            if hashed > limit {
                return true;
            }
            let size = slice.len() as u64;
            let mut cands: Vec<(Algo, Vec<u8>)> = vec![(Algo::Sha256, Sha256::digest(slice).to_vec())];
            if need_md5 {
                cands.push((Algo::Md5, md5::Md5::digest(slice).to_vec()));
            }
            if need_sha1 {
                cands.push((Algo::Sha1, sha1::Sha1::digest(slice).to_vec()));
            }
            for (algo, d) in cands {
                if let Some(rule) = self.db.lookup_section(algo, &d, size) {
                    if !found.iter().any(|f| f.rule_id == rule.id) {
                        found.push(Detection { rule_id: rule.id, family: rule.family, severity: rule.severity, confidence: rule.confidence, method: Method::SectionHash });
                    }
                }
            }
        }
        false
    }

    pub fn scan_path(&self, path: &Path, cancel: &AtomicBool, progress: &mut dyn FnMut(&Progress)) -> Report {
        let start = Instant::now();
        let mut rep = Report { warnings: self.warnings.clone(), db_serial: Some(self.db.serial).filter(|_| self.db.rule_count() > 0 || self.db.serial > 0), db_rules: self.db.rule_count(), db_sources: self.db.sources.clone(), ..Default::default() };
        self.visit(path, 0, &mut rep, cancel, progress);
        rep.duration = start.elapsed();
        rep
    }

    fn record(&self, rep: &mut Report, r: FileResult, progress: &mut dyn FnMut(&Progress)) {
        rep.files_seen += 1;
        rep.bytes += r.size;
        match &r.outcome {
            Outcome::NoThreatFound => rep.no_threat_found += 1,
            Outcome::Allowlisted => rep.allowlisted += 1,
            Outcome::Detected(_) => rep.detected += 1,
            Outcome::Suspicious(_) => rep.suspicious += 1,
            Outcome::Unscannable(_) => rep.unscannable += 1,
            Outcome::Skipped(_) => rep.skipped += 1,
            Outcome::Error(_) => rep.errors += 1,
        }
        if r.risk.as_ref().map_or(false, |k| k.level == peanalysis::Level::Weak) && !matches!(r.outcome, Outcome::Suspicious(_)) {
            rep.weak_anomalies += 1;
        }
        progress(&Progress { files_done: rep.files_seen, bytes: rep.bytes, detections: rep.detected, current: r.path.clone() });
        if !matches!(r.outcome, Outcome::NoThreatFound) {
            if rep.results.len() < MAX_STORED_RESULTS {
                rep.results.push(r);
            } else if !rep.warnings.iter().any(|w| w.starts_with("result list truncated")) {
                rep.warnings.push(format!("result list truncated at {MAX_STORED_RESULTS} entries (counters remain exact)"));
            }
        }
    }

    fn visit(&self, p: &Path, depth: usize, rep: &mut Report, cancel: &AtomicBool, progress: &mut dyn FnMut(&Progress)) {
        if cancel.load(Ordering::Relaxed) {
            rep.cancelled = true;
            return;
        }
        let md = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(e) => {
                let r = FileResult { path: p.to_path_buf(), size: 0, sha256: None, kind: Target::Any, risk: None, outcome: Outcome::Error(format!("cannot stat: {e}")) };
                return self.record(rep, r, progress);
            }
        };
        if is_reparse(&md) {
            let r = FileResult { path: p.to_path_buf(), size: 0, sha256: None, kind: Target::Any, risk: None, outcome: Outcome::Skipped("symlink/reparse point (not followed)".into()) };
            return self.record(rep, r, progress);
        }
        if md.is_dir() {
            if depth >= self.limits.max_depth {
                let r = FileResult { path: p.to_path_buf(), size: 0, sha256: None, kind: Target::Any, risk: None, outcome: Outcome::Skipped("directory depth limit".into()) };
                return self.record(rep, r, progress);
            }
            match fs::read_dir(p) {
                Ok(rd) => {
                    for e in rd.flatten() {
                        self.visit(&e.path(), depth + 1, rep, cancel, progress);
                        if rep.cancelled {
                            return;
                        }
                    }
                }
                Err(e) => {
                    let r = FileResult { path: p.to_path_buf(), size: 0, sha256: None, kind: Target::Any, risk: None, outcome: Outcome::Error(format!("cannot read directory: {e}")) };
                    self.record(rep, r, progress);
                }
            }
        } else {
            let r = self.scan_file(p);
            self.record(rep, r, progress);
        }
    }
}
