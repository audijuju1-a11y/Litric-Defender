//! Deterministic risk classification for an application about to be launched.
//!
//! This module consumes evidence produced elsewhere (the engine's verdict, hash
//! reputation, signature state) and produces one of four levels with explicit
//! reasons. It never makes a file "trusted" because it is signed: signature
//! *presence* is structural, chain validation is a separate fact.

use crate::model::ExecutionLevel;

/// Hash reputation from the signed threat database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashTrust {
    Unknown,
    Allowlisted,
    Pua,
    Malicious,
}

/// Evidence about one application, already gathered by callers.
#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationFacts {
    /// `clean` | `unknown` | `suspicious` | `malicious` from the scan engine.
    pub verdict: String,
    pub score: u32,
    pub confidence: f64,
    /// A structurally plausible Authenticode blob exists (not chain-validated).
    pub signature_present: bool,
    /// The chain was validated to a trusted root by a platform verifier.
    pub signature_chain_valid: bool,
    pub hash_trust: HashTrust,
}

impl Default for ApplicationFacts {
    fn default() -> Self {
        ApplicationFacts {
            verdict: "unknown".into(),
            score: 0,
            confidence: 0.0,
            signature_present: false,
            signature_chain_valid: false,
            hash_trust: HashTrust::Unknown,
        }
    }
}

/// Classification plus the evidence that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct RiskAssessment {
    pub level: ExecutionLevel,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub rationale: String,
}

impl RiskAssessment {
    fn new(level: ExecutionLevel, confidence: f64, evidence: Vec<String>, rationale: &str) -> Self {
        RiskAssessment {
            level,
            confidence,
            evidence,
            rationale: rationale.to_string(),
        }
    }
}

/// Classifies an application. Order matters: hostile evidence wins over trust.
pub fn assess(facts: &ApplicationFacts) -> RiskAssessment {
    let mut evidence = Vec::new();

    if facts.hash_trust == HashTrust::Malicious {
        evidence.push("SHA-256 is listed as malicious in the signed threat database".into());
        return RiskAssessment::new(
            ExecutionLevel::Malicious,
            0.99,
            evidence,
            "hash reputation is definitive; do not execute on the host",
        );
    }

    if facts.verdict.eq_ignore_ascii_case("malicious") {
        evidence.push(format!(
            "scan engine returned malicious with score {}/100",
            facts.score
        ));
        return RiskAssessment::new(
            ExecutionLevel::Malicious,
            facts.confidence.max(0.9),
            evidence,
            "malicious verdict blocks host execution",
        );
    }

    if facts.verdict.eq_ignore_ascii_case("suspicious") || facts.hash_trust == HashTrust::Pua {
        if facts.verdict.eq_ignore_ascii_case("suspicious") {
            evidence.push(format!(
                "scan engine returned suspicious with score {}/100",
                facts.score
            ));
        }
        if facts.hash_trust == HashTrust::Pua {
            evidence.push("SHA-256 is classified as potentially unwanted".into());
        }
        return RiskAssessment::new(
            ExecutionLevel::Suspicious,
            facts.confidence.max(0.6),
            evidence,
            "multiple indicators warrant full VM isolation",
        );
    }

    // Trust requires a *validated* chain plus an allowlisted hash. An unsigned or
    // merely signed binary is not trusted, and unsigned is not malicious.
    let allowlisted = facts.hash_trust == HashTrust::Allowlisted;
    if allowlisted && facts.signature_chain_valid && facts.signature_present && facts.score < 30 {
        evidence.push("SHA-256 is allowlisted and the signing chain validated".into());
        return RiskAssessment::new(
            ExecutionLevel::Trusted,
            0.9,
            evidence,
            "known publisher and allowlisted content may run on the host",
        );
    }

    if facts.signature_present && !facts.signature_chain_valid {
        evidence.push(
            "a signature blob is present but its chain was not validated; it does not grant trust"
                .into(),
        );
    }
    if !facts.signature_present {
        evidence.push("no Authenticode signature; unsigned is not evidence of malice".into());
    }
    if allowlisted {
        evidence.push("SHA-256 is allowlisted but signature/score conditions were not met".into());
    }
    if !allowlisted {
        evidence.push("no reputation record for this SHA-256".into());
    }
    evidence.push("absence of detection does not prove safety".into());

    RiskAssessment::new(
        ExecutionLevel::Unknown,
        0.5,
        evidence,
        "unverified application: route through isolation, not host execution",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_unsigned_app_is_level_one_not_malicious() {
        let a = assess(&ApplicationFacts::default());
        assert_eq!(a.level, ExecutionLevel::Unknown);
        assert!(a
            .evidence
            .iter()
            .any(|e| e.contains("unsigned is not evidence of malice")));
        assert!(a.confidence <= 0.5);
    }

    #[test]
    fn malicious_hash_is_level_three() {
        let facts = ApplicationFacts {
            hash_trust: HashTrust::Malicious,
            ..Default::default()
        };
        let a = assess(&facts);
        assert_eq!(a.level, ExecutionLevel::Malicious);
        assert!(a.confidence > 0.95);
    }

    #[test]
    fn suspicious_verdict_is_level_two() {
        let facts = ApplicationFacts {
            verdict: "suspicious".into(),
            score: 45,
            confidence: 0.7,
            ..Default::default()
        };
        let a = assess(&facts);
        assert_eq!(a.level, ExecutionLevel::Suspicious);
        assert!(a.evidence.iter().any(|e| e.contains("45/100")));
    }

    #[test]
    fn unvalidated_signature_never_grants_trust() {
        let facts = ApplicationFacts {
            signature_present: true,
            signature_chain_valid: false,
            hash_trust: HashTrust::Allowlisted,
            ..Default::default()
        };
        let a = assess(&facts);
        assert_eq!(a.level, ExecutionLevel::Unknown);
        assert!(a.evidence.iter().any(|e| e.contains("chain was not validated")));
    }

    #[test]
    fn validated_chain_plus_allowlist_is_trusted() {
        let facts = ApplicationFacts {
            verdict: "clean".into(),
            score: 5,
            confidence: 0.95,
            signature_present: true,
            signature_chain_valid: true,
            hash_trust: HashTrust::Allowlisted,
        };
        let a = assess(&facts);
        assert_eq!(a.level, ExecutionLevel::Trusted);
    }

    #[test]
    fn malicious_beats_allowlist() {
        let facts = ApplicationFacts {
            hash_trust: HashTrust::Malicious,
            signature_present: true,
            signature_chain_valid: true,
            ..Default::default()
        };
        assert_eq!(assess(&facts).level, ExecutionLevel::Malicious);
    }
}
