//! Pre-execution policy for a scan-before-launch gate.
//!
//! This module is deliberately independent of process creation. It answers one
//! question: given a completed scan and a small policy, may this file execute?
//!
//! The defaults are fail-closed:
//!
//! * malicious -> quarantine (or block when quarantine is disabled)
//! * suspicious -> block
//! * unknown -> block unless the caller explicitly overrides it
//! * truncated -> block, because the whole file was not inspected
//! * clean -> allow
//!
//! `Unknown` is not `Clean`. A scanner that allows every unrecognised file has
//! not protected anything; it has only moved the decision to an attacker.

use crate::engine::Verdict;

/// What the pre-execution gate should do with the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightAction {
    /// The file may be launched.
    Allow,
    /// Refuse to launch; leave the file in place.
    Block,
    /// Refuse to launch and move the file into the encrypted vault.
    Quarantine,
}

impl PreflightAction {
    pub fn as_str(self) -> &'static str {
        match self {
            PreflightAction::Allow => "allow",
            PreflightAction::Block => "block",
            PreflightAction::Quarantine => "quarantine_and_block",
        }
    }
}

/// Caller-controlled exceptions. Both are explicit opt-ins; neither is a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreflightPolicy {
    /// Permit a file whose verdict is `Unknown`.
    pub allow_unknown: bool,
    /// Move a malicious file into quarantine. Opt-in: when false (the default)
    /// the file is still blocked, but it is left exactly where it was.
    pub quarantine_malicious: bool,
}

impl Default for PreflightPolicy {
    fn default() -> Self {
        PreflightPolicy {
            allow_unknown: false,
            // Safety first: blocking is not destructive. Moving the original is
            // an explicit `--quarantine` decision, never a default.
            quarantine_malicious: false,
        }
    }
}

/// A deterministic decision with a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightDecision {
    pub action: PreflightAction,
    pub reason: &'static str,
    pub warning: Option<&'static str>,
}

/// Decides whether a completed scan permits execution.
///
/// Malicious evidence takes priority over truncation: if the inspected prefix is
/// already malicious, the file must not run even if the rest was not read.
pub fn decide(
    verdict: Verdict,
    truncated: bool,
    policy: PreflightPolicy,
) -> PreflightDecision {
    if verdict == Verdict::Malicious {
        if policy.quarantine_malicious {
            return PreflightDecision {
                action: PreflightAction::Quarantine,
                reason: "malicious content must not execute; quarantine before launch",
                warning: None,
            };
        }
        return PreflightDecision {
            action: PreflightAction::Block,
            reason: "malicious content must not execute",
            warning: Some(
                "quarantine is opt-in; the original file was left in place (pass --quarantine to move it)",
            ),
        };
    }

    if truncated {
        return PreflightDecision {
            action: PreflightAction::Block,
            reason: "the scan was truncated, so the whole file was not inspected",
            warning: None,
        };
    }

    match verdict {
        Verdict::Clean => PreflightDecision {
            action: PreflightAction::Allow,
            reason: "trusted allowlist entry with no positive evidence",
            warning: None,
        },
        Verdict::Suspicious => PreflightDecision {
            action: PreflightAction::Block,
            reason: "suspicious content requires investigation before launch",
            warning: None,
        },
        Verdict::Unknown if policy.allow_unknown => PreflightDecision {
            action: PreflightAction::Allow,
            reason: "no detection matched; execution was explicitly allowed",
            warning: Some(
                "UNKNOWN is not clean; --allow-unknown bypassed the fail-closed default",
            ),
        },
        Verdict::Unknown => PreflightDecision {
            action: PreflightAction::Block,
            reason: "no detection matched; UNKNOWN is not clean",
            warning: None,
        },
        // Malicious was handled above so this arm is unreachable, but keeping it
        // explicit prevents a future variant from silently becoming allowed.
        Verdict::Malicious => unreachable!("malicious verdict handled before match"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PreflightPolicy {
        PreflightPolicy::default()
    }

    #[test]
    fn malicious_is_blocked_and_left_in_place_by_default() {
        let d = decide(Verdict::Malicious, false, policy());
        assert_eq!(d.action, PreflightAction::Block);
        assert!(d.warning.is_some(), "the retained original must be reported");
    }

    #[test]
    fn malicious_is_quarantined_only_when_explicitly_enabled() {
        let d = decide(
            Verdict::Malicious,
            false,
            PreflightPolicy {
                quarantine_malicious: true,
                ..policy()
            },
        );
        assert_eq!(d.action, PreflightAction::Quarantine);
    }

    #[test]
    fn suspicious_is_blocked() {
        let d = decide(Verdict::Suspicious, false, policy());
        assert_eq!(d.action, PreflightAction::Block);
    }

    #[test]
    fn unknown_is_blocked_without_an_explicit_override() {
        let d = decide(Verdict::Unknown, false, policy());
        assert_eq!(d.action, PreflightAction::Block);
    }

    #[test]
    fn unknown_can_be_allowed_only_explicitly() {
        let d = decide(
            Verdict::Unknown,
            false,
            PreflightPolicy {
                allow_unknown: true,
                ..policy()
            },
        );
        assert_eq!(d.action, PreflightAction::Allow);
        assert!(d.warning.is_some());
    }

    #[test]
    fn clean_is_allowed() {
        let d = decide(Verdict::Clean, false, policy());
        assert_eq!(d.action, PreflightAction::Allow);
    }

    #[test]
    fn truncated_scan_never_allows_a_non_malicious_file() {
        for verdict in [Verdict::Clean, Verdict::Unknown, Verdict::Suspicious] {
            let d = decide(
                verdict,
                true,
                PreflightPolicy {
                    allow_unknown: true,
                    quarantine_malicious: true,
                },
            );
            assert_eq!(
                d.action,
                PreflightAction::Block,
                "truncated {verdict:?} must not execute"
            );
        }
    }

    #[test]
    fn malicious_prefix_wins_over_truncation() {
        let blocked = decide(Verdict::Malicious, true, policy());
        assert_eq!(blocked.action, PreflightAction::Block);
        let opt_in = decide(
            Verdict::Malicious,
            true,
            PreflightPolicy {
                quarantine_malicious: true,
                ..policy()
            },
        );
        assert_eq!(opt_in.action, PreflightAction::Quarantine);
    }
}
