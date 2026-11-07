use scanner::*;
use sigdb::{hex_encode, sha256, Database, Severity};
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

/// Standard harmless AV test string, assembled at runtime so this source
/// file itself is not flagged by real antivirus products.
fn eicar() -> Vec<u8> {
    concat!("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EI", "CAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").as_bytes().to_vec()
}

fn db(rules: &str) -> Arc<Database> {
    let n = rules.lines().filter(|l| l.starts_with("H ") || l.starts_with("P ")).count();
    let text = format!("LITRIC-SIGDB 1\nserial 1\ncreated 1\nmin-engine 1\nrule-count {n}\n{rules}END\n");
    Arc::new(Database::parse(text.as_bytes()).unwrap_or_else(|e| panic!("{e}")))
}
fn eicar_rule(target: &str) -> String {
    format!("P eicar.test Eicar-Test-File low 100 {target} {}\n", hex_encode(&eicar()))
}
fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("litric_scan_{n}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn scan(s: &Scanner, p: &Path) -> Report {
    s.scan_path(p, &AtomicBool::new(false), &mut |_| {})
}
fn fake_pe(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; 0x80];
    v[0] = b'M';
    v[1] = b'Z';
    v[0x3c] = 0x40;
    v[0x40..0x44].copy_from_slice(b"PE\0\0");
    v.extend_from_slice(payload);
    v
}

#[test]
fn eicar_is_detected_inside_larger_data() {
    let d = tmp("eicar");
    let mut data = vec![b'x'; 5000];
    data.extend(eicar());
    data.extend(vec![b'y'; 5000]);
    std::fs::write(d.join("t.bin"), &data).unwrap();
    let rep = scan(&Scanner::new(db(&eicar_rule("any")), Limits::default()), &d);
    assert_eq!(rep.detected, 1);
    let r = rep.detections().next().unwrap();
    assert!(r.sha256.is_some());
    match &r.outcome {
        Outcome::Detected(v) => assert_eq!((v[0].rule_id.as_str(), v[0].method.clone()), ("eicar.test", Method::Pattern)),
        _ => unreachable!(),
    }
}

#[test]
fn pattern_spanning_the_1mib_read_chunk_boundary_is_found() {
    let d = tmp("chunk");
    let mut data = vec![b'a'; (1 << 20) - 10];
    data.extend(eicar());
    data.extend(vec![b'b'; 100]);
    std::fs::write(d.join("big.bin"), &data).unwrap();
    let rep = scan(&Scanner::new(db(&eicar_rule("any")), Limits::default()), &d);
    assert_eq!(rep.detected, 1);
}

#[test]
fn hash_rule_detects_and_allowlist_overrides() {
    let d = tmp("hash");
    std::fs::write(d.join("k.bin"), b"known-bad-content").unwrap();
    let h = hex_encode(&sha256(b"known-bad-content"));
    let rules = format!("H bad.hash Bad.Fam critical 95 {h}\n");
    let rep = scan(&Scanner::new(db(&rules), Limits::default()), &d);
    assert_eq!(rep.detected, 1);
    if let Outcome::Detected(v) = &rep.results[0].outcome {
        assert_eq!((v[0].method.clone(), v[0].severity), (Method::Hash, Severity::Critical));
    }
    let rep = scan(&Scanner::new(db(&format!("{rules}A {h}\n")), Limits::default()), &d);
    assert_eq!((rep.detected, rep.allowlisted), (0, 1));
}

#[test]
fn revoked_rule_is_not_applied() {
    let d = tmp("revoked");
    std::fs::write(d.join("t.bin"), eicar()).unwrap();
    let rep = scan(&Scanner::new(db(&format!("{}R eicar.test\n", eicar_rule("any"))), Limits::default()), &d);
    assert_eq!(rep.detected, 0);
}

#[test]
fn target_filter_applies_to_detected_file_kind() {
    let d = tmp("target");
    std::fs::write(d.join("note.txt"), eicar()).unwrap();
    let s = Scanner::new(db(&eicar_rule("pe")), Limits::default());
    assert_eq!(scan(&s, &d).detected, 0, "pe-only rule must not fire on a text file");
    std::fs::write(d.join("prog.exe"), fake_pe(&eicar())).unwrap();
    assert_eq!(scan(&s, &d).detected, 1);
    assert_eq!(detect_kind(&fake_pe(b""), None), sigdb::Target::Pe);
    assert_eq!(detect_kind(b"MZ junk", None), sigdb::Target::Any, "MZ without PE header is not PE");
    assert_eq!(detect_kind(b"echo hi", Some("BAT")), sigdb::Target::Script);
}

#[test]
fn duplicate_matches_of_one_rule_report_once() {
    let d = tmp("dupmatch");
    let mut data = eicar();
    data.extend(eicar());
    std::fs::write(d.join("t.bin"), data).unwrap();
    let rep = scan(&Scanner::new(db(&eicar_rule("any")), Limits::default()), &d);
    if let Outcome::Detected(v) = &rep.results[0].outcome {
        assert_eq!(v.len(), 1);
    } else {
        panic!()
    }
}

#[test]
fn oversize_file_is_unscannable_not_clean_and_report_is_incomplete() {
    let d = tmp("big");
    std::fs::write(d.join("big.bin"), vec![b'z'; 3 << 20]).unwrap();
    let lim = Limits { max_pattern_scan_bytes: 1 << 20, ..Limits::default() };
    let rep = scan(&Scanner::new(db(&eicar_rule("any")), lim), &d);
    assert_eq!((rep.unscannable, rep.no_threat_found), (1, 0));
    assert!(!rep.is_complete());
}

#[test]
fn hash_rule_still_catches_oversize_files() {
    let d = tmp("bighash");
    let data = vec![b'q'; 3 << 20];
    std::fs::write(d.join("big.bin"), &data).unwrap();
    let rules = format!("H big.bad Big.Fam high 80 {}\n", hex_encode(&sha256(&data)));
    let lim = Limits { max_pattern_scan_bytes: 1 << 20, ..Limits::default() };
    assert_eq!(scan(&Scanner::new(db(&rules), lim), &d).detected, 1);
}

#[test]
fn empty_or_missing_database_warns_loudly() {
    let d = tmp("emptydb");
    std::fs::write(d.join("a.txt"), b"hello").unwrap();
    let rep = scan(&Scanner::new(db(""), Limits::default()), &d);
    assert_eq!(rep.no_threat_found, 1);
    assert!(rep.warnings.iter().any(|w| w.contains("EMPTY")));
    let rep = scan(&Scanner::without_database(Limits::default(), "load failed"), &d);
    assert!(rep.warnings.iter().any(|w| w.contains("NO signature database")));
    let rep = scan(&Scanner::new(db(&eicar_rule("any")), Limits::default()), &d);
    assert!(rep.warnings.iter().any(|w| w.contains("very limited")));
}

#[test]
fn missing_path_is_an_error_not_clean() {
    let rep = scan(&Scanner::new(db(&eicar_rule("any")), Limits::default()), Path::new("/definitely/not/here"));
    assert_eq!((rep.errors, rep.no_threat_found), (1, 0));
    assert!(!rep.is_complete());
}

#[test]
fn directory_depth_limit_is_reported_and_counters_add_up() {
    let d = tmp("depth");
    let mut p = d.clone();
    for i in 0..4 {
        p = p.join(format!("d{i}"));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("f.txt"), b"x").unwrap();
    }
    let lim = Limits { max_depth: 2, ..Limits::default() };
    let rep = scan(&Scanner::new(db(&eicar_rule("any")), lim), &d);
    assert!(rep.skipped >= 1 && !rep.is_complete());
    assert_eq!(rep.files_seen, rep.no_threat_found + rep.allowlisted + rep.detected + rep.unscannable + rep.skipped + rep.errors);
}

#[test]
fn cancellation_stops_and_marks_incomplete() {
    let d = tmp("cancel");
    for i in 0..5 {
        std::fs::write(d.join(format!("{i}.txt")), b"x").unwrap();
    }
    let cancel = AtomicBool::new(true);
    let rep = Scanner::new(db(&eicar_rule("any")), Limits::default()).scan_path(&d, &cancel, &mut |_| {});
    assert!(rep.cancelled && !rep.is_complete());
}

#[test]
fn progress_callback_reports_every_file() {
    let d = tmp("progress");
    for i in 0..4 {
        std::fs::write(d.join(format!("{i}.txt")), b"x").unwrap();
    }
    let mut seen = 0;
    Scanner::new(db(&eicar_rule("any")), Limits::default()).scan_path(&d, &AtomicBool::new(false), &mut |p| seen = p.files_done);
    assert_eq!(seen, 4);
}

#[test]
fn empty_file_is_handled() {
    let d = tmp("emptyfile");
    std::fs::write(d.join("e"), b"").unwrap();
    assert_eq!(scan(&Scanner::new(db(&eicar_rule("any")), Limits::default()), &d).no_threat_found, 1);
}

#[test]
fn packer_style_pe_is_suspicious_not_detected_and_benign_pe_is_not_flagged() {
    use peanalysis::builder::*;
    let d = tmp("pe");
    let mut packed = PeBuilder::benign(false);
    packed.sections = vec![
        Sec { name: "UPX0".into(), data: vec![], vsize: 0x10000, chars: RWX },
        Sec::new("UPX1", pseudo_random(8192, 99), RWX),
    ];
    packed.entry_section = 1;
    packed.imports = vec![("KERNEL32.dll".into(), vec!["LoadLibraryA".into(), "GetProcAddress".into(), "ExitProcess".into()])];
    std::fs::write(d.join("packed.exe"), packed.build()).unwrap();
    std::fs::write(d.join("normal.exe"), PeBuilder::benign(true).build()).unwrap();
    let rep = scan(&Scanner::new(db(&eicar_rule("any")), Limits::default()), &d);
    assert_eq!((rep.detected, rep.suspicious, rep.no_threat_found), (0, 1, 1));
    let r = rep.results.iter().find(|r| matches!(r.outcome, Outcome::Suspicious(_))).unwrap();
    assert!(r.path.ends_with("packed.exe"));
    assert!(r.risk.as_ref().unwrap().reasons.len() >= 3);
    assert!(rep.is_complete(), "a suspicious verdict is not an incomplete scan");
}

#[test]
fn known_signature_takes_precedence_over_heuristics_and_keeps_risk_data() {
    use peanalysis::builder::*;
    let d = tmp("pe_sig");
    let mut b = PeBuilder::benign(false);
    b.sections[1].data = eicar();
    std::fs::write(d.join("p.exe"), b.build()).unwrap();
    let rep = scan(&Scanner::new(db(&eicar_rule("pe")), Limits::default()), &d);
    assert_eq!((rep.detected, rep.suspicious), (1, 0));
    assert!(rep.results[0].risk.is_some());
}
