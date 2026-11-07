//! Bounded ZIP-family inspection for the portable detection engine.
//!
//! This layer never extracts to disk. It reads a limited number of members into
//! memory, rejects unsafe/path-traversal names, and hands each member to the
//! caller for the same rule/heuristic/hash analysis as a standalone file.
//!
//! Resource limits are part of the security boundary, not a performance tweak:
//! a small archive can claim a huge or highly-compressed member. The limits
//! below stop that expansion, report what was not inspected, and never present
//! a skipped member as clean.

use std::io::{Cursor, Read};

use zip::ZipArchive;

use crate::engine::Verdict;

/// Hard limits applied to one archive layer.
#[derive(Debug, Clone)]
pub struct ArchiveLimits {
    /// Maximum number of central-directory entries considered.
    pub max_entries: usize,
    /// Maximum uncompressed bytes for one member.
    pub max_member_bytes: u64,
    /// Maximum uncompressed bytes for all members in this layer.
    pub max_total_bytes: u64,
    /// Maximum nested archive depth. The top-level archive is depth 0.
    pub max_depth: usize,
    /// Maximum uncompressed-to-compressed ratio for one member.
    pub max_ratio: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        ArchiveLimits {
            max_entries: 512,
            max_member_bytes: 16 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_depth: 3,
            max_ratio: 1_000,
        }
    }
}

/// A member report produced by the caller's normal engine analysis.
#[derive(Debug, Clone)]
pub struct MemberReport {
    pub name: String,
    pub verdict: Verdict,
    pub score: u32,
    pub threat_name: Option<String>,
    pub family: Option<String>,
}

/// Bounded inspection result for one archive layer.
#[derive(Debug, Clone, Default)]
pub struct ArchiveScan {
    pub entries: usize,
    pub scanned: usize,
    pub skipped: usize,
    pub truncated: bool,
    pub members: Vec<MemberReport>,
    pub notes: Vec<String>,
}

impl ArchiveScan {
    /// Highest member verdict, if any member was inspected.
    pub fn worst(&self) -> Option<&MemberReport> {
        self.members.iter().max_by_key(|m| m.verdict)
    }

    fn note(&mut self, text: impl Into<String>) {
        if self.notes.len() < 32 {
            self.notes.push(text.into());
        }
    }
}

/// Reads a ZIP/OOXML/JAR container and calls `analyze` for each safe member.
///
/// The callback receives `(member_name, member_bytes, child_depth)`. It must
/// return a report; this function does not decide a verdict and does not touch
/// the filesystem. A malformed or unsupported member is reported in `notes`
/// and counted as skipped, never silently treated as clean.
pub fn inspect_zip<F>(
    data: &[u8],
    depth: usize,
    limits: &ArchiveLimits,
    mut analyze: F,
) -> ArchiveScan
where
    F: FnMut(&str, &[u8], usize) -> MemberReport,
{
    let mut scan = ArchiveScan::default();
    if depth >= limits.max_depth {
        scan.note(format!(
            "archive depth limit reached at depth {depth}; nested members were not inspected"
        ));
        scan.truncated = true;
        return scan;
    }

    let mut archive = match ZipArchive::new(Cursor::new(data)) {
        Ok(a) => a,
        Err(e) => {
            scan.note(format!("archive could not be parsed: {e}"));
            return scan;
        }
    };
    scan.entries = archive.len();
    if scan.entries > limits.max_entries {
        scan.note(format!(
            "archive has {} entries; only the first {} are considered",
            scan.entries, limits.max_entries
        ));
        scan.truncated = true;
    }

    let mut total: u64 = 0;
    for index in 0..archive.len().min(limits.max_entries) {
        let member = match archive.by_index(index) {
            Ok(m) => m,
            Err(e) => {
                scan.skipped += 1;
                scan.note(format!("archive entry {index} could not be opened: {e}"));
                continue;
            }
        };
        if member.is_dir() {
            continue;
        }
        let Some(name) = safe_member_name(member.name()) else {
            scan.skipped += 1;
            scan.note(format!(
                "archive entry {index} has an unsafe name and was not inspected"
            ));
            continue;
        };

        let size = member.size();
        if size == 0 {
            scan.skipped += 1;
            continue;
        }
        if size > limits.max_member_bytes {
            scan.skipped += 1;
            scan.note(format!(
                "archive member `{name}` is {size} bytes, above the {} byte member cap; not inspected",
                limits.max_member_bytes
            ));
            continue;
        }
        if total.saturating_add(size) > limits.max_total_bytes {
            scan.note(format!(
                "archive total byte cap ({} bytes) reached before `{name}`; remaining members not inspected",
                limits.max_total_bytes
            ));
            scan.truncated = true;
            break;
        }
        let compressed = member.compressed_size();
        if compressed == 0 || size > compressed.saturating_mul(limits.max_ratio) {
            scan.skipped += 1;
            scan.note(format!(
                "archive member `{name}` has an implausible compression ratio ({size} bytes from \
                 {compressed} bytes); not inspected"
            ));
            continue;
        }

        let limit = limits.max_member_bytes.saturating_add(1);
        let mut bytes = Vec::new();
        if let Err(e) = member.take(limit).read_to_end(&mut bytes) {
            scan.skipped += 1;
            scan.note(format!("archive member `{name}` could not be read: {e}"));
            continue;
        }
        if bytes.len() as u64 > limits.max_member_bytes {
            scan.skipped += 1;
            scan.note(format!(
                "archive member `{name}` expanded beyond the {} byte member cap; not inspected",
                limits.max_member_bytes
            ));
            continue;
        }
        total = total.saturating_add(bytes.len() as u64);
        scan.scanned += 1;
        let report = analyze(&name, &bytes, depth + 1);
        if report.verdict >= Verdict::Suspicious {
            scan.note(format!(
                "archive member `{name}` classified {} (score {}, {})",
                report.verdict.as_str(),
                report.score,
                report.threat_name.as_deref().unwrap_or("unclassified")
            ));
        }
        scan.members.push(report);
    }

    if scan.skipped > 0 || scan.truncated {
        scan.note(format!(
            "archive accounting: {} entry/entries, {} inspected, {} skipped{}",
            scan.entries,
            scan.scanned,
            scan.skipped,
            if scan.truncated {
                ", result truncated by limits"
            } else {
                ""
            }
        ));
    }
    scan
}

/// Normalizes a ZIP member name for reporting and rejects paths that could be
/// dangerous if a future consumer ever writes members out.
fn safe_member_name(raw: &str) -> Option<String> {
    let normalized = raw.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.contains('\0')
        || normalized.split('/').any(|part| part == "..")
    {
        return None;
    }
    // Reject Windows drive-absolute names such as C:/payload.exe.
    let bytes = normalized.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return None;
    }
    let limited: String = normalized.chars().take(240).collect();
    Some(limited)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn zip_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in files {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
                )
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn report(name: &str, data: &[u8], _depth: usize) -> MemberReport {
        MemberReport {
            name: name.to_string(),
            verdict: if data.windows(5).any(|w| w == b"EICAR") {
                Verdict::Malicious
            } else {
                Verdict::Unknown
            },
            score: 0,
            threat_name: None,
            family: None,
        }
    }

    #[test]
    fn finds_a_member_and_preserves_its_name() {
        let data = zip_bytes(&[("nested/payload.txt", b"prefix EICAR suffix")]);
        let scan = inspect_zip(&data, 0, &ArchiveLimits::default(), report);
        assert_eq!(scan.scanned, 1);
        assert_eq!(scan.worst().unwrap().name, "nested/payload.txt");
        assert_eq!(scan.worst().unwrap().verdict, Verdict::Malicious);
        assert!(scan.notes.iter().any(|n| n.contains("payload.txt")));
    }

    #[test]
    fn rejects_path_traversal_names_without_analyzing_them() {
        let data = zip_bytes(&[("../escape.txt", b"EICAR"), ("safe.txt", b"ordinary")]);
        let scan = inspect_zip(&data, 0, &ArchiveLimits::default(), report);
        assert_eq!(scan.scanned, 1);
        assert!(scan.notes.iter().any(|n| n.contains("unsafe name")));
        assert_eq!(scan.worst().unwrap().name, "safe.txt");
    }

    #[test]
    fn member_byte_limit_skips_expansion() {
        let data = zip_bytes(&[("large.txt", b"0123456789")]);
        let limits = ArchiveLimits {
            max_member_bytes: 4,
            ..Default::default()
        };
        let scan = inspect_zip(&data, 0, &limits, report);
        assert_eq!(scan.scanned, 0);
        assert_eq!(scan.skipped, 1);
        assert!(scan.notes.iter().any(|n| n.contains("member cap")));
    }

    #[test]
    fn depth_limit_is_explicit() {
        let data = zip_bytes(&[("a.txt", b"data")]);
        let limits = ArchiveLimits {
            max_depth: 0,
            ..Default::default()
        };
        let scan = inspect_zip(&data, 0, &limits, report);
        assert_eq!(scan.scanned, 0);
        assert!(scan.truncated);
        assert!(scan.notes.iter().any(|n| n.contains("depth limit")));
    }
}
