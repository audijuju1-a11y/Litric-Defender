//! Optional YARA module for the Litric pipeline.
//!
//! **Provenance:** the YARA language, compiler and matcher are provided by the
//! external `yara-x` crate (VirusTotal, BSD-3-Clause). None of that engine is
//! Litric code and Litric does not claim to have written it. This crate is the
//! Litric-owned *integration*: rule loading policy, limits, metadata mapping,
//! honest reporting of what was not evaluated, and keeping YARA results
//! separate from Litric-native results (`Source::Yara`).
//!
//! Compatibility: Litric makes **no** claim of full YARA compatibility. What is
//! verified is only what `tests/` and `docs/YARA_COMPAT.md` list.
//!
//! Limits enforced here: per-scan timeout, per-rule-file size, rule-file count,
//! input size, and matches per pattern. Memory inside the engine is bounded
//! only indirectly (input cap + match cap); there is no hard RSS limit.

use litric_pipeline::{ExternalDetection, RuleModule, RuleOutput, Source};
use sigdb::Severity;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Limits {
    pub scan_timeout: Duration,
    pub max_rule_file_bytes: u64,
    pub max_rule_files: usize,
    /// Inputs larger than this are not scanned (reported as incomplete).
    pub max_input_bytes: usize,
    pub max_matches_per_pattern: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { scan_timeout: Duration::from_secs(5), max_rule_file_bytes: 1 << 20, max_rule_files: 10_000, max_input_bytes: 256 << 20, max_matches_per_pattern: 1000 }
    }
}

/// Outcome of loading rule files. Nothing is skipped silently.
#[derive(Debug, Default, Clone)]
pub struct LoadReport {
    pub loaded_files: Vec<PathBuf>,
    pub rejected: Vec<(PathBuf, String)>,
    pub warnings: Vec<String>,
    /// Number of rules in the compiled set.
    pub rule_count: usize,
}

pub struct YaraModule {
    rules: yara_x::Rules,
    limits: Limits,
    pub load: LoadReport,
}

fn sev_from(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

impl YaraModule {
    /// Compile every `.yar` / `.yara` file in `dir` (non-recursive is NOT
    /// assumed: subdirectories are walked, symlinks are not followed). Files
    /// that fail to compile are rejected individually and reported; the rest
    /// still load.
    pub fn from_dir(dir: &Path, limits: Limits) -> std::io::Result<Self> {
        let mut files = Vec::new();
        collect(dir, &mut files, 0)?;
        files.sort();
        let mut load = LoadReport::default();
        let mut sources: Vec<(PathBuf, String)> = Vec::new();
        for f in files {
            let ext = f.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase());
            if !matches!(ext.as_deref(), Some("yar" | "yara")) {
                continue;
            }
            if sources.len() >= limits.max_rule_files {
                load.rejected.push((f, format!("rule file count limit {} reached", limits.max_rule_files)));
                continue;
            }
            match std::fs::metadata(&f) {
                Ok(m) if m.len() > limits.max_rule_file_bytes => {
                    load.rejected.push((f, format!("larger than {} bytes", limits.max_rule_file_bytes)));
                    continue;
                }
                Err(e) => {
                    load.rejected.push((f, format!("cannot stat: {e}")));
                    continue;
                }
                _ => {}
            }
            let text = match std::fs::read_to_string(&f) {
                Ok(t) => t,
                Err(e) => {
                    load.rejected.push((f, format!("cannot read as UTF-8 text: {e}")));
                    continue;
                }
            };
            // Validate on its own so one bad file cannot poison the set.
            let mut probe = yara_x::Compiler::new();
            match probe.add_source(text.as_str()) {
                Ok(_) => sources.push((f, text)),
                Err(e) => load.rejected.push((f, format!("compile error: {e}"))),
            }
        }
        let mut c = yara_x::Compiler::new();
        for (i, (f, text)) in sources.iter().enumerate() {
            // distinct namespaces so identical rule names in different files do not collide
            c.new_namespace(&format!("f{i}"));
            if let Err(e) = c.add_source(text.as_str()) {
                load.rejected.push((f.clone(), format!("compile error in combined set: {e}")));
            } else {
                load.loaded_files.push(f.clone());
            }
        }
        load.warnings.extend(c.warnings().iter().map(|w| w.to_string()));
        let rules = c.build();
        load.rule_count = rules.iter().count();
        Ok(YaraModule { rules, limits, load })
    }

    /// Compile rules from in-memory source (tests, embedded rules).
    pub fn from_source(src: &str, limits: Limits) -> Result<Self, String> {
        let mut c = yara_x::Compiler::new();
        c.add_source(src).map_err(|e| e.to_string())?;
        let mut load = LoadReport::default();
        load.warnings.extend(c.warnings().iter().map(|w| w.to_string()));
        let rules = c.build();
        load.rule_count = rules.iter().count();
        Ok(YaraModule { rules, limits, load })
    }
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) -> std::io::Result<()> {
    if depth > 16 {
        return Ok(());
    }
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let ft = e.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            collect(&e.path(), out, depth + 1)?;
        } else if ft.is_file() {
            out.push(e.path());
        }
    }
    Ok(())
}

impl RuleModule for YaraModule {
    fn name(&self) -> &str {
        "yara"
    }

    fn scan(&self, _name: &str, data: &[u8]) -> RuleOutput {
        let mut out = RuleOutput::default();
        if self.load.rule_count == 0 {
            out.incomplete.push("no YARA rules loaded".into());
            return out;
        }
        if data.len() > self.limits.max_input_bytes {
            out.incomplete.push(format!("input larger than {} MiB; not scanned", self.limits.max_input_bytes >> 20));
            return out;
        }
        let mut s = yara_x::Scanner::new(&self.rules);
        s.set_timeout(self.limits.scan_timeout);
        s.max_matches_per_pattern(self.limits.max_matches_per_pattern);
        match s.scan(data) {
            Ok(res) => {
                for r in res.matching_rules() {
                    let mut sev = Severity::Low;
                    let mut conf: u8 = 50;
                    let mut family = r.identifier().to_string();
                    for (k, v) in r.metadata() {
                        match (k, v) {
                            ("severity", yara_x::MetaValue::String(x)) => sev = sev_from(x),
                            ("confidence", yara_x::MetaValue::Integer(n)) => conf = n.clamp(0, 100) as u8,
                            ("family", yara_x::MetaValue::String(x)) => family = x.to_string(),
                            _ => {}
                        }
                    }
                    out.detections.push(ExternalDetection { source: Source::Yara, rule_id: format!("{}:{}", r.namespace(), r.identifier()), family, severity: sev, confidence: conf, method: "yara".into() });
                }
            }
            Err(yara_x::errors::ScanError::Timeout) => out.incomplete.push(format!("scan exceeded {:?} timeout; results are partial/absent", self.limits.scan_timeout)),
            Err(e) => out.incomplete.push(format!("scan error: {e}")),
        }
        out
    }
}
