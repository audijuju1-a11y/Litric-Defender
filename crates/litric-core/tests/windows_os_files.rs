//! Regression tests against real Windows system binaries.
//!
//! The native engine must not convict an OS-owned file for importing or
//! exporting common API names. This caught a real false positive: kernel32.dll
//! was reported MALICIOUS by an API-presence rule and injection heuristics.

use litric_core::engine::{Engine, EngineConfig, Verdict};
use litric_core::rules::{parse_rule_file, RuleSet};
use litric_core::threatdb::ThreatDb;
use std::path::{Path, PathBuf};

const CORE: &str = include_str!("../../../rules/core.lrs");
const EXTENDED: &str = include_str!("../../../rules/extended.lrs");

fn engine() -> Engine {
    let mut rules = parse_rule_file(CORE, "core.lrs").expect("core.lrs parses");
    rules.extend(parse_rule_file(EXTENDED, "extended.lrs").expect("extended.lrs parses"));
    let rs = RuleSet::compile(rules).expect("rules compile");
    Engine::new(rs, ThreatDb::empty(), EngineConfig::default())
}

fn system32(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").expect("Windows-only test: SystemRoot must be set");
    Path::new(&root).join("System32").join(name)
}

fn analyse(path: &Path) {
    let (report, truncated) = engine()
        .analyze_path(path, 128 * 1024 * 1024)
        .unwrap_or_else(|e| panic!("{} cannot be read: {e}", path.display()));
    assert!(!truncated, "{} was truncated", path.display());
    assert_ne!(
        report.verdict,
        Verdict::Malicious,
        "{} was reported MALICIOUS (score {}): {:?}",
        path.display(),
        report.score,
        report
            .rules
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        !report
            .rules
            .iter()
            .any(|m| m.name == "Inject.ProcessHollowing"),
        "{} matched the API-presence injection rule",
        path.display()
    );
}

#[test]
fn kernel32_exports_are_not_malware_evidence() {
    analyse(&system32("kernel32.dll"));
}

#[test]
fn signed_system_binaries_are_not_convicted_by_api_names() {
    analyse(&system32("notepad.exe"));
    analyse(&system32("drivers\\hwpolicy.sys"));
    // UCPD.sys embeds an mshta URL string for browser-association handling.
    // A string match inside an OS-owned binary is not loader behaviour.
    analyse(&system32("drivers\\UCPD.sys"));
}
