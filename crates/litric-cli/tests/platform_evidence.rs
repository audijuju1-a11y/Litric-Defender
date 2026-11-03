//! Mechanical evidence-provenance checks.
//!
//! The suite has only been executed on Linux. A test may be Windows-excluded
//! only if it carries an explicit `// POSIX-ONLY-TEST:` marker, appears in the
//! readiness gate's `test_evidence`, and appears in the same list in
//! `docs/SAFEOS_READINESS.md`. This file fails when any of those drift apart.
//!
//! This file itself is portable: it only reads source/doc text and the gate JSON.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use litric_service::api::{
    readiness_json, POSIX_ONLY_TESTS, SUITE_EXECUTED_ON, WINDOWS_SUITE_EXECUTION,
    WINDOWS_SUITE_REASON,
};
use serde_json::Value;

const READINESS_DOC: &str = include_str!("../../../docs/SAFEOS_READINESS.md");
const EVIDENCE_BEGIN: &str = "<!-- TEST-EVIDENCE-BEGIN -->";
const EVIDENCE_END: &str = "<!-- TEST-EVIDENCE-END -->";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn test_name(lines: &[&str], test_index: usize) -> Option<String> {
    for line in &lines[test_index + 1..] {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("fn ") {
            return rest
                .split('(')
                .next()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string);
        }
    }
    None
}

/// Tests that cannot run on Windows: either the whole file is excluded, or a
/// `#[cfg(unix)]` / `#[cfg(not(windows))]` attribute sits immediately above the
/// test. These are exactly the tests that need POSIX-ONLY markers.
fn windows_excluded_tests(src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let file_wide = lines.iter().any(|line| {
        let trimmed = line.trim();
        trimmed == "#![cfg(not(windows))]" || trimmed == "#![cfg(unix)]"
    });
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() != "#[test]" {
            continue;
        }
        let mut excluded = file_wide;
        for previous in lines[i.saturating_sub(6)..i].iter() {
            let trimmed = previous.trim();
            if trimmed == "#[cfg(unix)]" || trimmed == "#[cfg(not(windows))]" {
                excluded = true;
            }
        }
        if excluded {
            if let Some(name) = test_name(&lines, i) {
                out.push(name);
            }
        }
    }
    out
}

fn posix_markers(src: &str) -> Vec<String> {
    src.lines()
        .filter_map(|line| line.trim().strip_prefix("// POSIX-ONLY-TEST:"))
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .collect()
}

fn doc_evidence() -> Value {
    let after_begin = READINESS_DOC
        .split(EVIDENCE_BEGIN)
        .nth(1)
        .expect("readiness doc is missing TEST-EVIDENCE-BEGIN");
    let block = after_begin
        .split(EVIDENCE_END)
        .next()
        .expect("readiness doc is missing TEST-EVIDENCE-END");
    let json = block
        .split("```json")
        .nth(1)
        .expect("TEST-EVIDENCE block is missing a json fence")
        .split("```")
        .next()
        .expect("TEST-EVIDENCE json fence is not closed");
    serde_json::from_str(json.trim()).expect("TEST-EVIDENCE block is not valid JSON")
}

#[test]
fn posix_labels_match_source_gate_and_doc() {
    let root = repo_root();
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files);

    let mut marked = BTreeSet::new();
    let mut excluded = BTreeSet::new();
    for path in files {
        let src = fs::read_to_string(&path).expect("read Rust source");
        let relative = path
            .strip_prefix(&root)
            .expect("source is under the workspace")
            .to_string_lossy()
            .replace('\\', "/");
        let relative = relative.strip_prefix("crates/").unwrap_or(&relative);
        for marker in posix_markers(&src) {
            marked.insert(marker);
        }
        for name in windows_excluded_tests(&src) {
            excluded.insert(format!("{relative}::{name}"));
        }
    }

    assert_eq!(
        marked, excluded,
        "every Windows-excluded test must carry one POSIX-ONLY-TEST marker, and every marker must name an excluded test"
    );

    let expected: BTreeSet<String> = POSIX_ONLY_TESTS
        .iter()
        .map(|id| id.to_string())
        .collect();
    assert_eq!(
        marked, expected,
        "the POSIX_ONLY_TESTS constant must match the source markers exactly"
    );

    let gate = readiness_json();
    let evidence = &gate["test_evidence"];
    let gate_tests: BTreeSet<String> = evidence["posix_only_tests"]
        .as_array()
        .expect("gate posix_only_tests array")
        .iter()
        .map(|v| v.as_str().expect("test id string").to_string())
        .collect();
    assert_eq!(gate_tests, expected, "gate POSIX list drifted from source");
    assert_eq!(evidence["suite_executed_on"], SUITE_EXECUTED_ON);
    assert_eq!(evidence["windows_suite_execution"], WINDOWS_SUITE_EXECUTION);
    assert_eq!(evidence["windows_suite_reason"], WINDOWS_SUITE_REASON);

    let doc = doc_evidence();
    assert_eq!(
        &doc,
        evidence,
        "docs/SAFEOS_READINESS.md TEST-EVIDENCE block must equal the readiness gate"
    );
}

#[test]
fn unverified_capabilities_are_derived_from_the_gate() {
    let gate = readiness_json();
    let caps = gate["capabilities"]
        .as_object()
        .expect("gate capabilities object");
    let unverified = gate["test_evidence"]["unverified_capabilities"]
        .as_object()
        .expect("gate unverified capabilities object");

    for (name, cap) in caps {
        let state = cap["state"].as_str().expect("capability state");
        if state == "READY" {
            assert!(
                !unverified.contains_key(name),
                "READY capability {name} must not be listed as unverified"
            );
        } else {
            let allowed = unverified
                .get(name)
                .unwrap_or_else(|| panic!("non-READY capability {name} is missing from the doc/gate unverified list"))
                .as_array()
                .expect("unverified states array");
            assert!(
                allowed.iter().any(|v| v.as_str() == Some(state)),
                "{name} state {state} is not accepted by the unverified list"
            );
        }
    }
    for name in unverified.keys() {
        let cap = caps
            .get(name)
            .unwrap_or_else(|| panic!("unverified list names unknown capability {name}"));
        assert_ne!(
            cap["state"].as_str(),
            Some("READY"),
            "unverified list must not contain READY capability {name}"
        );
    }
}
