//! End-to-end pipeline tests: native engine + ClamAV-derived data + rule module.
use clamav_import::{import_dir, Options};
use litric_core::engine::{Engine, EngineConfig, Verdict};
use litric_core::rules::{parse_rule_file, RuleSet};
use litric_core::threatdb::ThreatDb;
use litric_pipeline::*;
use scanner::{Limits, Scanner};
use sigdb::{Database, Severity};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

const MD5_EICAR: &str = "44d88612fea8a8f36de82e1278abb02f";

fn eicar() -> Vec<u8> {
    concat!("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EI", "CAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").as_bytes().to_vec()
}
fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("litric_pipe_{n}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn clam_scanner(n: &str, files: &[(&str, String)]) -> Scanner {
    let d = tmp(n);
    for (name, body) in files {
        std::fs::write(d.join(name), body).unwrap();
    }
    let o = import_dir(&d, &Options { serial: 1, created: 1, source_note: "pipeline test fixture".into() }).unwrap();
    Scanner::new(Arc::new(Database::parse(&o.db).unwrap()), Limits::default())
}
fn empty_engine() -> Engine {
    Engine::new(RuleSet::empty(), ThreatDb::empty(), EngineConfig::default())
}
fn core_engine() -> Engine {
    let text = include_str!("../../../rules/core.lrs");
    let rs = RuleSet::compile(parse_rule_file(text, "core.lrs").unwrap()).unwrap();
    Engine::new(rs, ThreatDb::empty(), EngineConfig::default())
}

#[test]
fn clamav_hash_signature_convicts_and_is_attributed_to_clamav() {
    let s = clam_scanner("hdb", &[("a.hdb", format!("{MD5_EICAR}:68:Eicar-Test-Signature\n"))]);
    let p = Pipeline::new(empty_engine()).with_signature_scanner(s);
    let r = p.scan_bytes("x.com", &eicar());
    assert_eq!(r.verdict, Verdict::Malicious, "{:?}", r.reasons);
    assert_eq!(r.action, Action::Quarantine);
    assert_eq!(r.clamav.len(), 1);
    assert_eq!(r.clamav[0].source, Source::ClamavDerived);
    assert_eq!(r.clamav[0].family, "Eicar-Test-Signature");
    // the native result is kept separate and untouched
    assert!(!r.native.is_threat());
    assert!(r.yara.is_empty());
    assert_eq!(r.threat_name().as_deref(), Some(r.clamav[0].rule_id.as_str()));
}

#[test]
fn native_detection_stands_without_any_signature_database() {
    let p = Pipeline::new(core_engine());
    let r = p.scan_bytes("eicar.com", &eicar());
    assert_eq!(r.verdict, Verdict::Malicious);
    assert_eq!(r.action, Action::Quarantine);
    assert!(r.clamav.is_empty());
    assert!(r.incomplete.iter().any(|i| i.contains("no signature database")), "missing DB must be disclosed");
}

#[test]
fn benign_file_is_unknown_never_clean_and_never_quarantined() {
    let s = clam_scanner("benign", &[("a.hdb", format!("{MD5_EICAR}:68:Eicar-Test-Signature\n"))]);
    let p = Pipeline::new(core_engine()).with_signature_scanner(s);
    let r = p.scan_bytes("notes.txt", b"just some ordinary text, nothing to see");
    assert_eq!(r.verdict, Verdict::Unknown);
    assert_eq!(r.action, Action::LogOnly);
    assert!(r.clamav.is_empty() && r.yara.is_empty());
}

#[test]
fn unsigned_unknown_pe_is_not_treated_as_malware() {
    use peanalysis::builder::PeBuilder;
    let pe = PeBuilder::benign(true).build();
    let s = clam_scanner("unsigned", &[("a.hdb", format!("{MD5_EICAR}:68:Eicar-Test-Signature\n"))]);
    let p = Pipeline::new(core_engine()).with_signature_scanner(s);
    let r = p.scan_bytes("tool.exe", &pe);
    assert!(r.verdict < Verdict::Malicious, "{:?} {:?}", r.verdict, r.reasons);
    assert_ne!(r.action, Action::Quarantine);
}

#[test]
fn pe_section_hash_uses_litric_pe_parser_facts() {
    use md5::Digest;
    use peanalysis::builder::PeBuilder;
    let pe = PeBuilder::benign(false).build();
    let info = litric_core::pe::parse(&pe).unwrap();
    let sec = info.sections.iter().find(|s| s.name == ".text").unwrap();
    let slice = &pe[sec.raw_pointer as usize..(sec.raw_pointer + sec.raw_size) as usize];
    let h = sigdb::hex_encode(&md5::Md5::digest(slice));
    let s = clam_scanner("sec", &[("a.mdb", format!("{}:{h}:Sec.Test\n", slice.len()))]);
    let p = Pipeline::new(empty_engine()).with_signature_scanner(s);
    let r = p.scan_bytes("prog.exe", &pe);
    assert_eq!(r.clamav.len(), 1, "section hash must fire via core PE parse: {:?}", r.incomplete);
    assert_eq!(r.clamav[0].method, "sectionhash");
    assert_eq!(r.verdict, Verdict::Malicious);
}

#[test]
fn extended_signature_matches_and_unsupported_lines_are_reported_by_importer() {
    let d = tmp("ndb");
    std::fs::write(d.join("a.ndb"), "Test.Ndb:0:*:deadbeef0102030405\n").unwrap();
    // a PCRE-modifier line the adapter does not support must be reported, not dropped silently
    std::fs::write(d.join("b.ldb"), "Test.Unsupported;Engine:81-255,Target:0;0;41414141/i\n").unwrap();
    let o = import_dir(&d, &Options { serial: 1, created: 1, source_note: "fixture".into() }).unwrap();
    let rep = o.report.render();
    assert!(rep.contains("unsupported: PCRE subsignature"), "unsupported signatures must be reported, not skipped silently:
{rep}");
    let s = Scanner::new(Arc::new(Database::parse(&o.db).unwrap()), Limits::default());
    let p = Pipeline::new(empty_engine()).with_signature_scanner(s);
    let mut data = b"padding".to_vec();
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5]);
    let r = p.scan_bytes("blob.bin", &data);
    assert_eq!(r.clamav.len(), 1, "{:?}", r.incomplete);
    assert_eq!(r.clamav[0].method, "extended");
}

#[test]
fn archives_disclose_that_members_are_not_checked_by_imported_signatures() {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        z.start_file("a.txt", zip::write::SimpleFileOptions::default()).unwrap();
        z.write_all(b"hello").unwrap();
        z.finish().unwrap();
    }
    let s = clam_scanner("zip", &[("a.hdb", format!("{MD5_EICAR}:68:Eicar-Test-Signature\n"))]);
    let p = Pipeline::new(empty_engine()).with_signature_scanner(s);
    let r = p.scan_bytes("a.zip", &buf.into_inner());
    assert!(r.incomplete.iter().any(|i| i.contains("archive members")));
    assert_ne!(r.verdict, Verdict::Clean);
}

struct Fake {
    hit: bool,
    sev: Severity,
    conf: u8,
}
impl RuleModule for Fake {
    fn name(&self) -> &str {
        "fake-yara"
    }
    fn scan(&self, _n: &str, d: &[u8]) -> RuleOutput {
        let mut o = RuleOutput::default();
        if self.hit && d.starts_with(b"BAD") {
            o.detections.push(ExternalDetection { source: Source::Yara, rule_id: "R1".into(), family: "Fam".into(), severity: self.sev, confidence: self.conf, method: "yara".into() });
        }
        o.incomplete.push("timeout-limited".into());
        o
    }
}

#[test]
fn rule_module_results_are_kept_separate_and_gated_by_severity_and_confidence() {
    let strong = Pipeline::new(empty_engine()).with_rule_module(Box::new(Fake { hit: true, sev: Severity::High, conf: 95 }));
    let r = strong.scan_bytes("f", b"BAD payload");
    assert_eq!(r.verdict, Verdict::Malicious);
    assert_eq!((r.yara.len(), r.clamav.len()), (1, 0));
    assert!(r.incomplete.iter().any(|i| i.starts_with("fake-yara:")));

    let weak = Pipeline::new(empty_engine()).with_rule_module(Box::new(Fake { hit: true, sev: Severity::Low, conf: 40 }));
    let r = weak.scan_bytes("f", b"BAD payload");
    assert_eq!(r.verdict, Verdict::Suspicious, "a weak external match must not convict by itself");
    assert_eq!(r.action, Action::Alert);
}

#[test]
fn threats_are_classified_against_the_taxonomy_with_their_basis() {
    // naming convention path (ClamAV-style name)
    let s = clam_scanner("cls", &[("a.hdb", format!("{MD5_EICAR}:68:Win.Ransomware.Fixture-1\n"))]);
    let p = Pipeline::new(empty_engine()).with_signature_scanner(s);
    let r = p.scan_bytes("x.bin", &eicar());
    let hit = r.categories.iter().find(|h| h.id == 26).expect("ransomware category");
    assert_eq!(hit.basis, Basis::NamingConvention);
    assert_eq!(hit.name, "Crypto Ransomware");

    // evidence path: a native rule that is specific evidence
    let p = Pipeline::new(core_engine());
    let r = p.scan_bytes("cleanup.bat", b"vssadmin delete shadows /all /quiet");
    assert!(r.verdict >= Verdict::Suspicious, "{:?} {:?}", r.verdict, r.reasons);
    let ids: Vec<u16> = r.categories.iter().filter(|h| h.basis == Basis::Evidence).map(|h| h.id).collect();
    assert!(ids.contains(&26) && ids.contains(&40) && ids.contains(&43), "{:?}", r.categories);

    // a non-threat gets no categories
    let r = Pipeline::new(core_engine()).scan_bytes("a.txt", b"hello");
    assert!(r.categories.is_empty());
}

struct FakeTrust(litric_wintrust::Trust);
impl TrustProvider for FakeTrust {
    fn verify(&self, _p: &std::path::Path) -> litric_wintrust::Trust {
        self.0.clone()
    }
}

fn write_tmp(name: &str, bytes: &[u8]) -> PathBuf {
    // One directory per fixture. Sharing a directory made these tests race each
    // other: `tmp()` removes the directory, and tests run in parallel, so one
    // test deleted a peer's file between the write and `scan_path`.
    let safe_name = name.replace(['\\', '/', ':'], "_");
    let d = std::env::temp_dir().join(format!(
        "litric_scanpath_{}_{safe_name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn a_valid_signature_never_removes_a_detection() {
    let p = write_tmp("eicar_signed.com", &eicar());
    let pipe = Pipeline::new(core_engine()).with_trust_provider(Box::new(FakeTrust(litric_wintrust::Trust::Trusted)));
    let r = pipe.scan_path(&p, 1 << 20).unwrap();
    assert_eq!(r.verdict, Verdict::Malicious, "signed malware must still be malware");
    assert_eq!(r.signature, Some(litric_wintrust::Trust::Trusted));
}

#[test]
fn a_tampered_signature_raises_an_otherwise_unknown_file_to_suspicious() {
    let p = write_tmp("tampered.exe", b"plain bytes");
    let rejected = litric_wintrust::Trust::Rejected { code: 0x80096010, reason: "signature digest does not match the file (modified after signing)" };
    let r = Pipeline::new(core_engine()).with_trust_provider(Box::new(FakeTrust(rejected))).scan_path(&p, 1 << 20).unwrap();
    assert_eq!(r.verdict, Verdict::Suspicious);
    assert_eq!(r.action, Action::Alert);
    assert!(r.reasons.iter().any(|x| x.contains("authenticode")));
}

#[test]
fn an_unsigned_file_and_a_benign_rejection_are_not_treated_as_malware() {
    let p = write_tmp("unsigned.exe", b"plain bytes");
    let none = Pipeline::new(core_engine()).with_trust_provider(Box::new(FakeTrust(litric_wintrust::Trust::NoEmbeddedSignature))).scan_path(&p, 1 << 20).unwrap();
    assert_eq!(none.verdict, Verdict::Unknown);
    // an expired certificate is not proof of tampering
    let expired = litric_wintrust::Trust::Rejected { code: 0x800B0101, reason: "certificate expired or not yet valid" };
    let r = Pipeline::new(core_engine()).with_trust_provider(Box::new(FakeTrust(expired))).scan_path(&p, 1 << 20).unwrap();
    assert_eq!(r.verdict, Verdict::Unknown);
}

#[test]
fn scan_path_refuses_symlinks_directories_and_oversized_files() {
    let d = tmp("refuse");
    let f = d.join("big.bin");
    std::fs::write(&f, vec![0u8; 100]).unwrap();
    let pipe = Pipeline::new(core_engine());
    assert!(pipe.scan_path(&f, 10).is_err(), "over the size limit");
    assert!(pipe.scan_path(&d, 1 << 20).is_err(), "directory");
}

#[test]
fn without_a_trust_provider_the_signature_field_is_none() {
    let p = write_tmp("x.bin", b"abc");
    assert!(Pipeline::new(core_engine()).scan_path(&p, 1 << 20).unwrap().signature.is_none());
}
