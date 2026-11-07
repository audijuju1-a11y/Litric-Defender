//! Mechanical evidence-provenance checks for the Windows-only build.
//!
//! The readiness gate's `test_evidence`, `docs/SAFEOS_READINESS.md` and the
//! source tree must agree. This test also fails if a POSIX-only test gate or an
//! exclusion marker is reintroduced in this Windows-only tree.

use std::fs;
use std::path::{Path, PathBuf};

use litric_service::api::{
    readiness_json, SUITE_EXECUTED_ON, WINDOWS_EXCLUDED_TESTS, WINDOWS_SUITE_EXECUTION,
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
fn readiness_doc_matches_gate_and_no_posix_gate_returns() {
    let root = repo_root();
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files);
    for path in files {
        let src = fs::read_to_string(&path).expect("read Rust source");
        for (lineno, line) in src.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed == "#[cfg(unix)]"
                || trimmed == "#[cfg(not(windows))]"
                || trimmed == "#![cfg(unix)]"
                || trimmed == "#![cfg(not(windows))]"
            {
                panic!(
                    "{}:{} still gates a non-Windows build; this repository is Windows-only",
                    path.display(),
                    lineno + 1
                );
            }
            if trimmed.starts_with("// POSIX-ONLY-TEST:")
                || trimmed.starts_with("// WINDOWS-EXCLUDED-TEST:")
            {
                panic!(
                    "{}:{} still carries a platform-exclusion marker",
                    path.display(),
                    lineno + 1
                );
            }
        }
    }

    assert!(
        WINDOWS_EXCLUDED_TESTS.is_empty(),
        "the Windows-only suite must not exclude tests"
    );

    let gate = readiness_json();
    let evidence = &gate["test_evidence"];
    assert_eq!(evidence["suite_executed_on"], SUITE_EXECUTED_ON);
    assert_eq!(evidence["windows_suite_execution"], WINDOWS_SUITE_EXECUTION);
    assert_eq!(evidence["windows_suite_reason"], WINDOWS_SUITE_REASON);
    assert_eq!(
        evidence["windows_excluded_tests"]
            .as_array()
            .expect("gate windows_excluded_tests array")
            .len(),
        0
    );

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
                .unwrap_or_else(|| {
                    panic!("non-READY capability {name} is missing from the doc/gate unverified list")
                })
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
