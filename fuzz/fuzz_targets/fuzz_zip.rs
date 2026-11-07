#![no_main]

use libfuzzer_sys::fuzz_target;

use litric_core::archive::{inspect_zip, ArchiveLimits, MemberReport};
use litric_core::engine::Verdict;

/// Analyze a member and, when it is itself a ZIP-family container, recurse
/// within the same depth/limit rules used by the engine. Recursion is capped by
/// `ArchiveLimits::max_depth`; this function never touches the filesystem.
fn analyze_member(name: &str, data: &[u8], depth: usize) -> MemberReport {
    let nested = if depth < ArchiveLimits::default().max_depth
        && (data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06"))
    {
        inspect_zip(data, depth, &ArchiveLimits::default(), analyze_member)
    } else {
        Default::default()
    };

    MemberReport {
        name: name.to_string(),
        verdict: nested
            .worst()
            .map(|member| member.verdict)
            .unwrap_or(Verdict::Unknown),
        score: 0,
        threat_name: None,
        family: None,
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = inspect_zip(data, 0, &ArchiveLimits::default(), analyze_member);
});
