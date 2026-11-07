use litric_core::engine::{Engine, EngineConfig, Verdict};
use litric_core::rules::RuleSet;
use litric_core::threatdb::ThreatDb;
use litric_pipeline::{Action, Pipeline, RuleModule, Source};
use litric_yara::{Limits, YaraModule};
use std::path::PathBuf;
use std::time::Duration;

fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("litric_yara_{n}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn engine() -> Engine {
    Engine::new(RuleSet::empty(), ThreatDb::empty(), EngineConfig::default())
}

const STRONG: &str = r#"
rule Fixture_Strong {
  meta:
    severity = "high"
    confidence = 95
    family = "Fixture.Family"
  strings:
    $a = "LITRIC-YARA-FIXTURE"
    $h = { 4D 5A 90 00 }
    $re = /fix[a-z]ure/
  condition:
    $a and ($h or $re)
}
rule Fixture_Unlabelled {
  strings: $x = "UNLABELLED-MARKER"
  condition: $x
}
"#;

#[test]
fn string_hex_regex_and_boolean_conditions_match() {
    let m = YaraModule::from_source(STRONG, Limits::default()).unwrap();
    let hit = m.scan("f", b"..LITRIC-YARA-FIXTURE.. fixture");
    assert_eq!(hit.detections.len(), 1);
    assert_eq!(hit.detections[0].family, "Fixture.Family");
    assert_eq!(hit.detections[0].confidence, 95);
    assert_eq!(hit.detections[0].source, Source::Yara);
    // string present but the OR branch is absent -> condition false
    assert!(m.scan("f", b"LITRIC-YARA-FIXTURE only").detections.is_empty());
    // hex branch
    let mut d = b"LITRIC-YARA-FIXTURE".to_vec();
    d.extend_from_slice(&[0x4d, 0x5a, 0x90, 0x00]);
    assert_eq!(m.scan("f", &d).detections.len(), 1);
}

#[test]
fn rules_without_metadata_get_conservative_defaults_and_cannot_convict_alone() {
    let m = YaraModule::from_source(STRONG, Limits::default()).unwrap();
    let p = Pipeline::new(engine()).with_rule_module(Box::new(m));
    let r = p.scan_bytes("a.txt", b"UNLABELLED-MARKER");
    assert_eq!(r.yara.len(), 1);
    assert_eq!(r.verdict, Verdict::Suspicious);
    assert_eq!(r.action, Action::Alert);
    assert!(r.clamav.is_empty());
    assert!(!r.native.is_threat(), "YARA result must not leak into the native report");
}

#[test]
fn labelled_high_severity_rule_convicts_through_the_pipeline() {
    let m = YaraModule::from_source(STRONG, Limits::default()).unwrap();
    let p = Pipeline::new(engine()).with_rule_module(Box::new(m));
    let r = p.scan_bytes("a.bin", b"LITRIC-YARA-FIXTURE fixture");
    assert_eq!(r.verdict, Verdict::Malicious);
    assert_eq!(r.action, Action::Quarantine);
}

#[test]
fn directory_loading_accepts_yar_and_yara_and_reports_every_rejection() {
    let d = tmp("dir");
    std::fs::write(d.join("good.yar"), STRONG).unwrap();
    std::fs::write(d.join("also_good.yara"), "rule Other { condition: false }").unwrap();
    std::fs::write(d.join("broken.yar"), "rule Broken { strings: $a = condition: }").unwrap();
    std::fs::write(d.join("ignored.txt"), "rule NotLoaded { condition: true }").unwrap();
    let big = format!("// {}\nrule Big {{ condition: false }}", "x".repeat(2 << 20));
    std::fs::write(d.join("huge.yar"), big).unwrap();
    let m = YaraModule::from_dir(&d, Limits::default()).unwrap();
    assert_eq!(m.load.loaded_files.len(), 2, "{:?}", m.load);
    assert_eq!(m.load.rejected.len(), 2, "broken + oversized must both be reported: {:?}", m.load.rejected);
    assert!(m.load.rejected.iter().any(|(p, r)| p.ends_with("broken.yar") && r.contains("compile error")));
    assert!(m.load.rejected.iter().any(|(p, r)| p.ends_with("huge.yar") && r.contains("larger than")));
    assert_eq!(m.scan("f", b"UNLABELLED-MARKER").detections.len(), 1);
}

#[test]
fn identical_rule_names_in_different_files_do_not_collide() {
    let d = tmp("ns");
    std::fs::write(d.join("a.yar"), "rule Same { strings: $a = \"AAA\" condition: $a }").unwrap();
    std::fs::write(d.join("b.yar"), "rule Same { strings: $a = \"BBB\" condition: $a }").unwrap();
    let m = YaraModule::from_dir(&d, Limits::default()).unwrap();
    assert_eq!(m.load.loaded_files.len(), 2, "{:?}", m.load);
    assert_eq!(m.scan("f", b"AAA BBB").detections.len(), 2);
}

#[test]
fn empty_rule_set_is_disclosed_not_treated_as_clean() {
    let d = tmp("empty");
    let m = YaraModule::from_dir(&d, Limits::default()).unwrap();
    let r = m.scan("f", b"anything");
    assert!(r.detections.is_empty());
    assert!(r.incomplete.iter().any(|i| i.contains("no YARA rules")));
    let p = Pipeline::new(engine()).with_rule_module(Box::new(m));
    assert_ne!(p.scan_bytes("f", b"anything").verdict, Verdict::Clean);
}

#[test]
fn oversized_input_is_reported_not_scanned() {
    let m = YaraModule::from_source(STRONG, Limits { max_input_bytes: 16, ..Limits::default() }).unwrap();
    let r = m.scan("f", &[b'A'; 64]);
    assert!(r.detections.is_empty());
    assert!(r.incomplete.iter().any(|i| i.contains("not scanned")));
}

#[test]
fn a_pathological_rule_hits_the_timeout_and_is_reported() {
    // quadratic work that never matches; (0..filesize) is inclusive in YARA so an
    // "all" form would be undefined at the end and prove nothing about the timeout
    let src = r#"rule Slow { condition: for any i in (0..filesize) : (for any j in (0..filesize) : (uint8(i) != uint8(j) + 1 and uint8(i) == 99)) }"#;
    let m = YaraModule::from_source(src, Limits { scan_timeout: Duration::from_millis(200), ..Limits::default() }).unwrap();
    let data = vec![7u8; 20_000];
    let started = std::time::Instant::now();
    let r = m.scan("f", &data);
    assert!(started.elapsed() < Duration::from_secs(20), "timeout was not enforced");
    assert!(r.incomplete.iter().any(|i| i.contains("timeout")), "{:?}", r);
}
