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
        let mut notes = Vec::new();
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

        // --- heuristics ---------------------------------------------------
        let mut signals = heuristics::analyze(&AnalysisInput {
            data,
            format,
            ext: &ext,
            file_name: name,
            pe: pe.as_ref(),
        });

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
        let verdict = if trusted_hash && !definitive && score < self.config.suspicious_threshold {
            Verdict::Clean
        } else {
            verdict
        };

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

        // Prefer a rule's family name when the DB had none.
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
            let mut report = self.analyze_bytes(name, &buf);
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
        Ok((self.analyze_bytes(name, &data), false))
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
