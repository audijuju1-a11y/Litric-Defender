//! Litric detection pipeline.
//!
//! ```text
//! bytes -> Litric file identification + hashing + native rules/heuristics   (litric-core, Litric-owned)
//!       -> ClamAV-derived signature adapter (hash / section hash / NDB / LDB) (scanner + sigdb, Litric-owned matcher,
//!                                                                              ClamAV-sourced DATA only)
//!       -> optional rule module (YARA)                                        (external engine, see `RuleModule`)
//!       -> aggregation -> classification -> action
//! ```
//!
//! Provenance is never blended: every detection carries a [`Source`], and the
//! native report is kept untouched next to the external lists.
//!
//! Honesty rules:
//! * An incomplete check (budget hit, archive members not covered, missing PE
//!   facts) is listed in `incomplete` and prevents a `Clean` verdict.
//! * A file with no detections is `Unknown`, not `Clean`, unless the native
//!   engine positively allow-listed it. Unsigned/unknown never implies malware.

use litric_core::engine::{Engine, FileReport, Verdict};
use litric_core::format::{self, FileFormat, ScriptKind};
use scanner::{PeFacts, Scanner};
use litric_wintrust::Trust;
use sigdb::{Severity, Target};
use std::path::Path;

/// Where a detection came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// Litric rules, heuristics and hash database (written by Litric).
    LitricNative,
    /// Signature *data* imported from ClamAV, matched by Litric's own matcher.
    ClamavDerived,
    /// External YARA engine (not Litric-written code).
    Yara,
}

impl Source {
    pub fn as_str(&self) -> &'static str {
        match self {
            Source::LitricNative => "litric-native",
            Source::ClamavDerived => "clamav-derived",
            Source::Yara => "yara",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExternalDetection {
    pub source: Source,
    pub rule_id: String,
    pub family: String,
    pub severity: Severity,
    /// 0..=100
    pub confidence: u8,
    /// Matching method label (hash, section-hash, pattern, extended, logical, yara).
    pub method: String,
}

/// An optional additional rule engine (YARA). Implementations must enforce
/// their own CPU/memory/time limits and report anything they could not do via
/// `RuleOutput::incomplete`.
pub trait RuleModule: Send + Sync {
    fn name(&self) -> &str;
    fn scan(&self, name: &str, data: &[u8]) -> RuleOutput;
}

#[derive(Debug, Clone, Default)]
pub struct RuleOutput {
    pub detections: Vec<ExternalDetection>,
    pub incomplete: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing found; no action. (Does not mean safe.)
    Allow,
    /// Record only; the file is unknown or incompletely checked.
    LogOnly,
    Alert,
    Quarantine,
}

/// Why a taxonomy category was attached to a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// A built-in signal or rule that is specific evidence for the category.
    Evidence,
    /// Derived from the detection's name (naming-convention heuristic only).
    NamingConvention,
}

#[derive(Debug, Clone)]
pub struct CategoryHit {
    pub id: u16,
    pub name: &'static str,
    pub basis: Basis,
    /// The signal id, rule name or detection name that led here.
    pub via: String,
}

#[derive(Debug, Clone)]
pub struct PipelineReport {
    pub native: FileReport,
    pub clamav: Vec<ExternalDetection>,
    pub yara: Vec<ExternalDetection>,
    pub incomplete: Vec<String>,
    pub verdict: Verdict,
    pub action: Action,
    /// Human-readable decisive reasons, ordered by weight.
    pub reasons: Vec<String>,
    /// Threat classification against the 190-category taxonomy. Empty when the
    /// file is not a threat or nothing maps; never guessed.
    pub categories: Vec<CategoryHit>,
    /// Authenticode result for path scans (`None` for buffer scans or when no
    /// provider is configured). A good signature never removes a detection.
    pub signature: Option<Trust>,
}

impl PipelineReport {
    /// Highest-severity threat name across all sources.
    pub fn threat_name(&self) -> Option<String> {
        let mut best: Option<(u8, String)> = None;
        let mut consider = |rank: u8, n: String| {
            if best.as_ref().map_or(true, |(r, _)| rank > *r) {
                best = Some((rank, n));
            }
        };
        if let Some(n) = &self.native.threat_name {
            consider(if self.native.verdict == Verdict::Malicious { 5 } else { 1 }, n.clone());
        }
        for d in self.clamav.iter().chain(self.yara.iter()) {
            consider(sev_rank(d.severity), d.rule_id.clone());
        }
        best.map(|(_, n)| n)
    }
}

fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 4,
        Severity::Critical => 6,
    }
}

/// Supplies Authenticode trust for a file on disk. The default implementation
/// calls `WinVerifyTrust` (Windows only); tests inject their own.
pub trait TrustProvider: Send + Sync {
    fn verify(&self, path: &Path) -> Trust;
}

/// Default provider: documented Windows API, `Unsupported` elsewhere.
pub struct WinTrustProvider;
impl TrustProvider for WinTrustProvider {
    fn verify(&self, path: &Path) -> Trust {
        litric_wintrust::verify_file(path)
    }
}

pub struct Pipeline {
    trust: Option<Box<dyn TrustProvider>>,
    engine: Engine,
    clam: Option<Scanner>,
    rules: Vec<Box<dyn RuleModule>>,
    /// Warnings collected at construction (empty database etc.).
    warnings: Vec<String>,
}

fn target_for(fmt: FileFormat) -> Target {
    match fmt {
        FileFormat::Pe => Target::Pe,
        FileFormat::Elf => Target::Elf,
        FileFormat::Zip | FileFormat::Ooxml | FileFormat::Jar => Target::Zip,
        FileFormat::Pdf => Target::Pdf,
        FileFormat::Script(_) => Target::Script,
        _ => Target::Any,
    }
}

fn is_archive(fmt: FileFormat) -> bool {
    matches!(
        fmt,
        FileFormat::Zip
            | FileFormat::Ooxml
            | FileFormat::Jar
            | FileFormat::Rar
            | FileFormat::SevenZip
            | FileFormat::Gzip
            | FileFormat::Bzip2
            | FileFormat::Xz
            | FileFormat::Cab
            | FileFormat::Iso
    )
}

impl Pipeline {
    pub fn new(engine: Engine) -> Self {
        Pipeline { trust: None, engine, clam: None, rules: Vec::new(), warnings: Vec::new() }
    }

    /// Attach the ClamAV-derived signature matcher (built from an already
    /// verified Litric database; see `clamav-import`).
    pub fn with_signature_scanner(mut self, s: Scanner) -> Self {
        self.warnings.extend(s.warnings().iter().cloned());
        self.clam = Some(s);
        self
    }

    pub fn with_trust_provider(mut self, t: Box<dyn TrustProvider>) -> Self {
        self.trust = Some(t);
        self
    }

    /// Scan a file on disk: reads it (bounded), runs the pipeline, then attaches
    /// the Authenticode result. A signature that was tampered with or revoked
    /// raises an otherwise-clean verdict to `Suspicious`; a valid signature never
    /// lowers a verdict, because signed malware exists.
    pub fn scan_path(&self, path: &Path, max_bytes: u64) -> std::io::Result<PipelineReport> {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_file() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file (symlinks and directories are not followed)"));
        }
        if meta.len() > max_bytes {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("file is {} bytes, above the {max_bytes}-byte scan limit", meta.len())));
        }
        let data = std::fs::read(path)?;
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
        let mut r = self.scan_bytes(name, &data);
        if let Some(t) = &self.trust {
            let tr = t.verify(path);
            match &tr {
                Trust::Rejected { code, reason } => {
                    r.reasons.push(format!("authenticode: signature rejected ({reason}, 0x{code:08X})"));
                    let hostile = matches!(*code, 0x80096010 | 0x80096004 | 0x80092026 | 0x800B010C | 0x800B0111);
                    if hostile && r.verdict < Verdict::Suspicious {
                        r.verdict = Verdict::Suspicious;
                        r.action = Action::Alert;
                    }
                }
                Trust::Error(e) => r.incomplete.push(format!("authenticode: {e}")),
                Trust::Unsupported => r.incomplete.push("authenticode: signature verification unavailable on this platform".into()),
                Trust::Trusted | Trust::NoEmbeddedSignature => {}
            }
            r.signature = Some(tr);
        }
        Ok(r)
    }

    pub fn with_rule_module(mut self, m: Box<dyn RuleModule>) -> Self {
        self.rules.push(m);
        self
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn scan_bytes(&self, name: &str, data: &[u8]) -> PipelineReport {
        // 1. native engine (identification, hashing, rules, PE, archives, scripts, heuristics)
        let native = self.engine.analyze_bytes(name, data);
        let fmt = format::detect(data);
        let mut incomplete: Vec<String> = Vec::new();
        let mut clamav: Vec<ExternalDetection> = Vec::new();

        // 2. ClamAV-derived signature adapter
        if let Some(s) = &self.clam {
            let pe = if fmt == FileFormat::Pe { pe_facts(data) } else { None };
            let r = s.scan_bytes(data, target_for(fmt), pe.as_ref());
            for d in r.detections {
                clamav.push(ExternalDetection {
                    source: Source::ClamavDerived,
                    rule_id: d.rule_id,
                    family: d.family,
                    severity: d.severity,
                    confidence: d.confidence,
                    method: format!("{:?}", d.method).to_lowercase(),
                });
            }
            for i in r.incomplete {
                incomplete.push(format!("clamav-adapter: {i}"));
            }
            if r.allowlisted && clamav.is_empty() {
                // allow-list only suppresses the external list; native stays authoritative
            }
            if is_archive(fmt) {
                incomplete.push("clamav-adapter: archive members are not evaluated against imported signatures (only the container bytes)".into());
            }
        } else {
            incomplete.push("clamav-adapter: no signature database loaded".into());
        }

        // 3. optional rule module(s)
        let mut yara: Vec<ExternalDetection> = Vec::new();
        for m in &self.rules {
            let out = m.scan(name, data);
            yara.extend(out.detections);
            for i in out.incomplete {
                incomplete.push(format!("{}: {i}", m.name()));
            }
        }

        if native.archive_truncated {
            incomplete.push("native: archive inspection truncated by a safety budget".into());
        }

        // 4. aggregation
        let (verdict, mut reasons) = aggregate(&native, &clamav, &yara, &incomplete);
        let action = match verdict {
            Verdict::Malicious => Action::Quarantine,
            Verdict::Suspicious => Action::Alert,
            Verdict::Unknown => Action::LogOnly,
            Verdict::Clean => Action::Allow,
        };
        reasons.dedup();
        let categories = if verdict >= Verdict::Suspicious { classify(&native, &clamav, &yara) } else { Vec::new() };
        PipelineReport { native, clamav, yara, incomplete, verdict, action, reasons, categories, signature: None }
    }
}

fn classify(native: &FileReport, clam: &[ExternalDetection], yara: &[ExternalDetection]) -> Vec<CategoryHit> {
    use litric_core::taxonomy;
    let mut out: Vec<CategoryHit> = Vec::new();
    let mut add = |id: u16, basis: Basis, via: &str| {
        if !out.iter().any(|h| h.id == id) {
            if let Some(c) = taxonomy::get(id) {
                out.push(CategoryHit { id, name: c.name, basis, via: via.to_string() });
            }
        }
    };
    for sig in &native.signals {
        for id in taxonomy::by_evidence(sig.id) {
            add(id, Basis::Evidence, sig.id);
        }
    }
    for r in &native.rules {
        for id in taxonomy::by_evidence(&r.name) {
            add(id, Basis::Evidence, &r.name);
        }
    }
    for d in clam.iter().chain(yara.iter()) {
        for n in [&d.family, &d.rule_id] {
            for id in taxonomy::classify_name(n) {
                add(id, Basis::NamingConvention, n);
            }
        }
    }
    out.sort_by_key(|h| h.id);
    out
}

fn pe_facts(data: &[u8]) -> Option<PeFacts> {
    let info = litric_core::pe::parse(data).ok()?;
    let entry_offset = litric_core::pe::rva_to_offset(&info.sections, info.size_of_headers, info.entry_point_rva).map(|o| o as u64);
    Some(PeFacts { entry_offset, sections: info.sections.iter().map(|s| (s.raw_pointer, s.raw_size)).collect() })
}

/// External detections are classified by severity AND confidence so a weak or
/// low-severity match cannot by itself condemn a file.
fn external_verdict(d: &ExternalDetection) -> Verdict {
    match (d.severity, d.confidence) {
        (Severity::High | Severity::Critical, c) if c >= 80 => Verdict::Malicious,
        (Severity::Medium, c) if c >= 90 => Verdict::Malicious,
        (Severity::Low, _) => Verdict::Suspicious,
        _ => Verdict::Suspicious,
    }
}

fn aggregate(native: &FileReport, clam: &[ExternalDetection], yara: &[ExternalDetection], incomplete: &[String]) -> (Verdict, Vec<String>) {
    let mut v = native.verdict;
    let mut reasons = Vec::new();
    if native.is_threat() {
        reasons.push(format!("litric-native: {} (score {})", native.verdict.as_str(), native.score));
    }
    for d in clam.iter().chain(yara.iter()) {
        let dv = external_verdict(d);
        reasons.push(format!("{}: {} [{} / sev {:?} / conf {}] -> {}", d.source.as_str(), d.rule_id, d.method, d.severity, d.confidence, dv.as_str()));
        if dv > v {
            v = dv;
        }
    }
    // Never Clean unless positively allow-listed AND fully checked AND nothing found.
    if v == Verdict::Clean && (!incomplete.is_empty() || !clam.is_empty() || !yara.is_empty()) {
        v = if clam.is_empty() && yara.is_empty() { Verdict::Unknown } else { Verdict::Suspicious };
        if !incomplete.is_empty() {
            reasons.push("downgraded from clean: some checks were incomplete".into());
        }
    }
    (v, reasons)
}

/// Script kind name for reports (kept here so callers do not depend on core internals).
pub fn script_kind_name(k: ScriptKind) -> &'static str {
    match k {
        ScriptKind::PowerShell => "powershell",
        ScriptKind::Vbs => "vbs",
        ScriptKind::Js => "js",
        ScriptKind::Batch => "batch",
        ScriptKind::Shell => "shell",
        #[allow(unreachable_patterns)]
        _ => "other",
    }
}
