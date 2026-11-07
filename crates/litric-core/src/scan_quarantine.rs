//! Quarantine actions for detections produced by an on-demand scan.
//!
//! A scan summary is evidence: it records the exact digest that was classified.
//! This module moves only `Malicious` outcomes, and only when the source still
//! matches that digest. `Clean` and `Unknown` outcomes are never candidates,
//! even when a caller asks for automatic quarantine.
//!
//! Failures are returned per file. The caller decides the process exit status;
//! this layer never pretends a failed move succeeded.

use serde::Serialize;

use crate::engine::Verdict;
use crate::quarantine::{QuarantineMeta, QuarantineVault};
use crate::scan::ScanSummary;

/// One file that could not be moved, with the reason the original was retained.
#[derive(Debug, Clone, Serialize)]
pub struct QuarantineFailure {
    pub path: String,
    pub error: String,
}

/// Result of the post-scan quarantine pass.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanQuarantineReport {
    /// Number of `Malicious` detections the pass attempted to handle.
    pub malicious_seen: u64,
    /// Number of files whose original was removed after a verified vault write.
    pub quarantined: u64,
    /// Number of files that were refused or failed to move.
    pub failures: u64,
    /// Metadata for entries that made it into the vault, including partial moves.
    pub entries: Vec<QuarantineMeta>,
    /// Per-file failures. A non-empty list must produce a non-zero exit status.
    pub errors: Vec<QuarantineFailure>,
}

impl ScanQuarantineReport {
    fn failure(&mut self, path: impl Into<String>, error: impl Into<String>) {
        self.failures += 1;
        self.errors.push(QuarantineFailure {
            path: path.into(),
            error: error.into(),
        });
    }
}

/// Moves every `Malicious` outcome in `summary` into the encrypted vault.
///
/// Safety properties:
/// * only `Malicious` is eligible; `Suspicious`, `Unknown` and `Clean` are
///   untouched;
/// * a truncated scan is refused because the digest may not cover the file;
/// * a missing scan digest is refused;
/// * the vault checks the current digest before writing, and only removes the
///   source after decrypting and hash-verifying the stored copy;
/// * a vault move that leaves the original in place is reported as a failure.
pub fn quarantine_malicious(
    summary: &ScanSummary,
    vault: &QuarantineVault,
) -> ScanQuarantineReport {
    let mut report = ScanQuarantineReport::default();

    for outcome in summary
        .detections
        .iter()
        .filter(|d| d.verdict == Verdict::Malicious)
    {
        report.malicious_seen += 1;
        let path = outcome.path.display().to_string();

        if outcome.truncated {
            report.failure(
                path,
                "the scan was truncated; refusing to move a file whose full contents were not verified",
            );
            continue;
        }

        let Some(expected) = outcome.sha256.as_deref() else {
            report.failure(path, "the scan did not record a SHA-256 digest");
            continue;
        };

        let threat = outcome.threat_name.as_deref().unwrap_or("Malware.Scan");
        match vault.quarantine_file_checked(
            &outcome.path,
            expected,
            threat,
            None,
            outcome.score,
            false,
        ) {
            Ok(meta) => {
                let removed = meta.original_removed;
                let digest_matches = meta.sha256.eq_ignore_ascii_case(expected);
                report.entries.push(meta);
                if !digest_matches {
                    report.failure(
                        path,
                        "the vault entry digest differs from the scanned digest",
                    );
                } else if !removed {
                    report.failure(
                        path,
                        "the encrypted copy was written but the original could not be removed",
                    );
                } else {
                    report.quarantined += 1;
                }
            }
            Err(e) => report.failure(path, format!("quarantine failed: {e}")),
        }
    }

    report
}
