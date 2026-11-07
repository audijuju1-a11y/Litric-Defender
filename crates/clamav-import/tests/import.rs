use clamav_import::*;
use sigdb::{hex_decode, Algo, Database, Install, Severity, Store, TrustedKeys};
use std::path::PathBuf;

const MD5_ABC: &str = "900150983cd24fb0d6963f7d28e17f72";
const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const MD5_EICAR: &str = "44d88612fea8a8f36de82e1278abb02f";

fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("litric_imp_{n}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn opts() -> Options {
    Options { serial: 7, created: 1_700_000_000, source_note: "unit-test fixture, no real ClamAV data".into() }
}
fn run(n: &str, files: &[(&str, &str)]) -> (Output, Database) {
    let d = tmp(n);
    for (name, body) in files {
        std::fs::write(d.join(name), body).unwrap();
    }
    let o = import_dir(&d, &opts()).unwrap();
    let db = Database::parse(&o.db).unwrap_or_else(|e| panic!("{e}\n{}", String::from_utf8_lossy(&o.db)));
    (o, db)
}
fn file<'a>(o: &'a Output, name: &str) -> &'a FileReport {
    o.report.files.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("{name} missing from report"))
}

#[test]
fn hdb_md5_lines_import_with_extra_fields_and_the_real_eicar_entry() {
    let (o, db) = run("hdb", &[("test.hdb", &format!("{MD5_ABC}:3:Test.Abc\n\n{MD5_EICAR}:68:Eicar-Test-Signature:51:255\r\n"))]);
    let f = file(&o, "test.hdb");
    assert_eq!((f.lines, f.imported, f.rejected), (2, 2, 0));
    let r = db.lookup_file(Algo::Md5, &hex_decode(MD5_EICAR).unwrap(), 68).unwrap();
    assert_eq!((r.family.as_str(), r.severity, r.confidence), ("Eicar-Test-Signature", Severity::High, 90));
    assert!(db.lookup_file(Algo::Md5, &hex_decode(MD5_ABC).unwrap(), 3).is_some());
    assert!(db.sources.iter().any(|s| s.contains("unit-test fixture")));
}

#[test]
fn hash_type_must_match_the_file_type_and_bad_lines_are_rejected_with_line_numbers() {
    let hdb = format!("{SHA1_ABC}:3:Wrong.Type\nnothex{}:3:Bad.Hex\n{MD5_ABC}:xx:Bad.Size\n{MD5_ABC}:3:\nonly:two\n{MD5_ABC}:4294967296:Too.Big\n{MD5_ABC}:3:Name:5:x\n", "z".repeat(26));
    let hsb = format!("{MD5_ABC}:3:Wrong.Type\n{SHA1_ABC}:3:Sha1.Ok\n{SHA256_ABC}:3:Sha256.Ok\n");
    let (o, db) = run("types", &[("a.hdb", &hdb), ("b.hsb", &hsb)]);
    let a = file(&o, "a.hdb");
    assert_eq!((a.imported, a.rejected), (0, 7), "{:?}", a.samples);
    assert!(a.samples[0].starts_with("line 1: rejected"));
    let b = file(&o, "b.hsb");
    assert_eq!((b.imported, b.rejected), (2, 1));
    assert_eq!(db.rule_count(), 2);
}

#[test]
fn wildcard_size_is_reported_as_unsupported_not_dropped_silently() {
    let (o, db) = run("wild", &[("w.hdb", &format!("{MD5_ABC}:*:Wild.Sig\n{MD5_ABC}:3:Normal\n"))]);
    let f = file(&o, "w.hdb");
    assert_eq!((f.imported, f.unsupported_lines, f.rejected), (1, 1, 0));
    assert!(f.samples.iter().any(|s| s.contains("wildcard")));
    assert_eq!(db.rule_count(), 1);
    assert!(o.report.render().contains("unsupported lines 1"));
}

#[test]
fn pe_section_hash_files_use_size_then_hash_layout() {
    let (o, db) = run("sec", &[("s.mdb", &format!("512:{MD5_ABC}:Sec.Md5\n")), ("t.msb", &format!("1024:{SHA256_ABC}:Sec.Sha256\n"))]);
    assert_eq!(db.rule_count(), 2);
    assert_eq!(db.lookup_section(Algo::Md5, &hex_decode(MD5_ABC).unwrap(), 512).unwrap().family, "Sec.Md5");
    assert!(db.lookup_section(Algo::Sha256, &hex_decode(SHA256_ABC).unwrap(), 1024).is_some());
    assert!(db.lookup_file(Algo::Md5, &hex_decode(MD5_ABC).unwrap(), 512).is_none());
    assert_eq!(file(&o, "s.mdb").imported, 1);
}

#[test]
fn allowlists_fp_and_sfp_become_allow_entries() {
    let (o, db) = run("fp", &[("x.fp", &format!("{MD5_ABC}:3:Clean.File\n")), ("y.sfp", &format!("{SHA256_ABC}:3:Clean2\n"))]);
    assert_eq!(db.rule_count(), 0);
    assert!(db.is_allowed(Algo::Md5, &hex_decode(MD5_ABC).unwrap(), 3));
    assert!(db.is_allowed(Algo::Sha256, &hex_decode(SHA256_ABC).unwrap(), 3));
    assert_eq!(o.report.total(|f| f.allow_entries), 2);
}

#[test]
fn ignore_lists_disable_signatures_by_name_and_are_reported() {
    let (o, db) = run("ign", &[("a.hdb", &format!("{MD5_ABC}:3:Noisy.FP\n{MD5_EICAR}:68:Keep.Me\n")), ("daily.ign2", "Noisy.FP\n")]);
    assert_eq!(db.rule_count(), 1);
    assert_eq!(file(&o, "a.hdb").dropped_by_ignore, 1);
    assert!(o.report.warnings.iter().any(|w| w.contains("disabled by")));
}

#[test]
fn every_input_file_appears_in_the_report_and_unsupported_ones_say_why() {
    let (o, db) = run(
        "unsup",
        &[
            ("main.cdb", "Cont.A:1:2:3\nCont.B:1:2:3\n"),
            ("daily.ftm", "0:0:ffd8ffe0:JPEG\n"),
            ("bc.cbc", "ClamBC..."),
            ("main.cvd", "ClamAV-VDB:..."),
            ("weird.xyz", "???"),
            ("rules.yar", "rule x { condition: true }"),
            ("ok.hdb", &format!("{MD5_ABC}:3:Ok\n")),
        ],
    );
    assert_eq!(o.report.files.len(), 7, "no file may be missing from the report");
    assert_eq!(o.report.unsupported_files(), 6);
    for n in ["main.cdb", "daily.ftm", "bc.cbc", "main.cvd", "weird.xyz", "rules.yar"] {
        let f = file(&o, n);
        assert!(!f.supported && f.reason.is_some(), "{n}");
    }
    assert_eq!(file(&o, "main.cdb").lines, 2);
    assert!(file(&o, "bc.cbc").reason.as_ref().unwrap().contains("never executed"));
    assert!(file(&o, "main.cvd").reason.as_ref().unwrap().contains("NOT implemented"));
    assert!(o.report.warnings.iter().any(|w| w.contains("NOT imported")));
    assert_eq!(db.rule_count(), 1);
}

#[test]
fn duplicates_are_dropped_once_and_counted() {
    let (o, db) = run("dup", &[("a.hdb", &format!("{MD5_ABC}:3:First\n{MD5_ABC}:3:Second\n{MD5_ABC}:4:OtherSize\n"))]);
    assert_eq!((file(&o, "a.hdb").imported, file(&o, "a.hdb").duplicates), (2, 1));
    assert_eq!(db.lookup_file(Algo::Md5, &hex_decode(MD5_ABC).unwrap(), 3).unwrap().family, "First");
}

#[test]
fn pua_signatures_are_low_severity_and_names_are_sanitized() {
    let (_, db) = run(
        "pua",
        &[
            ("a.hdu", &format!("{MD5_ABC}:3:Win.Adware.Thing\n")),
            ("b.hdb", &format!("{MD5_EICAR}:68:PUA.Win.Tool/with spaces{{x}}\n")),
        ],
    );
    let r = db.lookup_file(Algo::Md5, &hex_decode(MD5_ABC).unwrap(), 3).unwrap();
    assert_eq!((r.severity, r.confidence), (Severity::Low, 50));
    let r = db.lookup_file(Algo::Md5, &hex_decode(MD5_EICAR).unwrap(), 68).unwrap();
    assert_eq!((r.severity, r.family.as_str()), (Severity::Low, "PUA.Win.Tool_with_spaces_x_"));
    assert!(r.id.starts_with("clam.h."));
}

#[test]
fn a_source_note_is_mandatory_and_output_is_deterministic() {
    let d = tmp("note");
    std::fs::write(d.join("a.hdb"), format!("{MD5_ABC}:3:A\n")).unwrap();
    for bad in ["", "   ", "has\nnewline"] {
        let o = Options { source_note: bad.into(), ..opts() };
        assert!(import_dir(&d, &o).is_err(), "{bad:?}");
    }
    let (a, b) = (import_dir(&d, &opts()).unwrap(), import_dir(&d, &opts()).unwrap());
    assert_eq!(a.db, b.db);
}

#[test]
fn pipeline_import_sign_install_load_lookup() {
    let (o, _) = run("e2e", &[("a.hdb", &format!("{MD5_EICAR}:68:Eicar-Test-Signature\n"))]);
    let seed = [5u8; 32];
    let mut keys = TrustedKeys::new();
    keys.add_hex(&sigdb::hex_encode(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().as_bytes())).unwrap();
    let store = Store::open(tmp("e2e_store")).unwrap();
    assert_eq!(store.install(&o.db, &sigdb::sign_bundle(&seed, &o.db), &keys).unwrap(), Install::Installed { serial: 7 });
    let db = store.load_active(&keys).unwrap().unwrap();
    assert!(db.lookup_file(Algo::Md5, &hex_decode(MD5_EICAR).unwrap(), 68).is_some());
}


// ------------------------------------------------------------------ NDB

#[test]
fn ndb_supported_lines_import_with_fl_fields_and_load_as_valid_rules() {
    let (o, db) = run(
        "ndb_ok",
        &[("a.ndb", "Win.Test.A:1:EP+0:e8??????ffd0:51:255\nWin.Test.B:0:*:aabbccdd{2-4}eeff\nElf.Test:6:EOF-16:7f454c46\nPdf.Test:10:0:255044462d\n")],
    );
    let f = file(&o, "a.ndb");
    assert_eq!((f.lines, f.imported, f.rejected, f.unsupported_lines), (4, 4, 0, 0), "{:?}", f.samples);
    assert_eq!(db.ndb.len(), 4);
    assert_eq!(db.ndb[0].target, sigdb::Target::Pe);
}

#[test]
fn ndb_unsupported_features_are_counted_by_reason_never_dropped_silently() {
    let lines = [
        "A:3:*:aabbccdd",                  // html target
        "B:9:*:aabbccdd",                  // mach-o target
        "C:0:*:aabb!(11|22)ccdd",          // negated alternative
        "D:0:*:aabb(B)ccdd",               // boundary
        "E:0:*:aabb[2-4]ccdd",             // anchored range
        "F:0:VI:aabbccdd",                 // version info offset
        "G:0:*:aa??bb{2}ccddeeff",         // no anchor
        "H:0:EP+0:aabbccdd",               // EP offset but target any
        "I:0:*:aabb(1?|22)ccdd",           // wildcard in alternative
        "J:0:S1-4:aabbccdd",               // negative section offset
        "K:0:*:aabbccdd",                  // valid control
    ];
    let (o, db) = run("ndb_unsup", &[("u.ndb", &lines.join("\n"))]);
    let f = file(&o, "u.ndb");
    assert_eq!((f.imported, f.unsupported_lines, f.rejected), (1, 10, 0), "{:?}", f.unsupported_reasons);
    assert_eq!(db.ndb.len(), 1);
    let reasons: Vec<&String> = f.unsupported_reasons.keys().collect();
    for want in ["target type 3", "target type 9", "negated", "(B)/(L)", "anchored byte range", "version-info", "no exact-byte anchor", "only supported with target type 1", "wildcards or other syntax", "section"] {
        assert!(reasons.iter().any(|r| r.contains(want)), "missing reason containing {want:?}: {reasons:?}");
    }
    let text = o.report.render();
    assert!(text.contains("unsupported x1: signature: negated"));
}

#[test]
fn ndb_malformed_lines_are_rejected_and_duplicates_ndu_and_ignore_work() {
    let body = "NoColons\nA:0:*:zz\nB:x:*:aabbcc\nC:0:EP+q:aabbcc\n:0:*:aabbcc\nD:0:*:aabbcc:1:x\n\nOK:0:*:aabbccdd\nOK2:0:*:aabbccdd\nIgn.Me:0:*:11223344\n";
    let (o, db) = run("ndb_misc", &[("m.ndb", body), ("x.ign2", "Ign.Me\n"), ("p.ndu", "Adware.X:0:*:99887766\n")]);
    let f = file(&o, "m.ndb");
    assert_eq!((f.imported, f.rejected, f.duplicates, f.dropped_by_ignore), (1, 6, 1, 1), "{:?}", f.samples);
    assert_eq!(db.ndb.len(), 2);
    let pua = (0..db.ndb.len()).map(|i| db.ndb_rule(i)).find(|r| r.family == "Adware.X").unwrap();
    assert_eq!((pua.severity, pua.confidence), (Severity::Low, 50));
}

// ------------------------------------------------------------------ LDB

#[test]
fn ldb_supported_lines_import_and_load_as_valid_rules() {
    let body = "Win.L.A;Target:1,FileSize:100-9999,Engine:51-255;(0&1)|2;11223344;EP+0:e8??????ffd0;S1+0:aabbccdd\n\
                Elf.L.B;Target:6;0&1;7f454c46;EOF-8:aabbccdd\n\
                Any.L.C;Target:0;0>2;deadbeef\n";
    let (o, db) = run("ldb_ok", &[("t.ldb", body)]);
    let f = file(&o, "t.ldb");
    assert_eq!((f.lines, f.imported, f.rejected, f.unsupported_lines), (3, 3, 0, 0), "{:?}", f.samples);
    assert_eq!(db.ldb.len(), 3);
    assert_eq!(db.ldb[0].constraints.filesize, Some((100, 9999)));
    assert_eq!(db.ldb[0].subs.len(), 3);
}

#[test]
fn ldb_unsupported_features_are_counted_by_reason() {
    let lines = [
        "A;Target:0;0&1;aabbccdd;/regex/i",                       // pcre (also no offset form)
        "B;Target:0;0&1;aabbccdd;eeff0011::i",                    // modifiers
        "C;Target:0;0&1;aabbccdd;${6-7}0$",                       // macro
        "D;Target:0;0;0(>>2#ib2)",                                // byte compare
        "E;Target:0;0;fuzzy_img#1234",                            // fuzzy hash
        "F;Target:0,EntryPoint:100-200;0;aabbccdd",               // entry point constraint
        "G;Target:0,Container:CL_TYPE_ZIP;0;aabbccdd",            // container
        "H;Target:3;0;aabbccdd",                                  // html target
        "I;Target:0;0&1|2;aabbccdd;eeff0011;22334455",            // mixed precedence
        "J;Target:0;(0|1)>2;aabbccdd;eeff0011",                   // group count
        "K;Target:0;0>1,2;aabbccdd",                              // distinct count
        "L;Target:0;0;aa??bb{2}ccddeeff",                         // unlocatable
        "M;Target:0;0;EP+0:aabbccdd",                             // EP with non-PE target
        "N;Target:0;0&1;aabbccdd;bbccddee",                       // valid control
    ];
    let (o, db) = run("ldb_unsup", &[("u.ldb", &lines.join("\n"))]);
    let f = file(&o, "u.ldb");
    assert_eq!((f.imported, f.unsupported_lines, f.rejected), (1, 13, 0), "{:?}", f.unsupported_reasons);
    assert_eq!(db.ldb.len(), 1);
    let reasons: Vec<&String> = f.unsupported_reasons.keys().collect();
    for want in ["PCRE", "modifiers", "macro", "byte-compare", "EntryPoint", "container", "target type 3", "mixed in one group", "parenthesised group", "distinct-subsignature", "no exact-byte anchor", "only supported with target type 1"] {
        assert!(reasons.iter().any(|r| r.contains(want)), "missing reason containing {want:?}: {reasons:?}");
    }
}

#[test]
fn ldb_malformed_lines_rejected_and_duplicates_pua_ignore_work() {
    let body = "NoSemicolons\nA;Target:0;0\nB;Target:0;0&;aabbccdd\nC;Target:0;0&1;aabbccdd\nD;Target:0;0;zz\n;Target:0;0;aabbccdd\nE;Bogus;0;aabbccdd\n\
                Dup1;Target:0;0;aabbccdd\nDup2;Target:0;0;aabbccdd\nIgn.Me;Target:0;0;11223344\n";
    let (o, db) = run("ldb_misc", &[("m.ldb", body), ("x.ign2", "Ign.Me\n"), ("p.ldu", "Adware.L;Target:0;0;99887766\n")]);
    let f = file(&o, "m.ldb");
    assert_eq!((f.imported, f.rejected, f.duplicates, f.dropped_by_ignore), (1, 7, 1, 1), "{:?}", f.samples);
    assert_eq!(db.ldb.len(), 2);
    let pua = (0..db.ldb.len()).map(|i| db.ldb_rule(i)).find(|r| r.family == "Adware.L").unwrap();
    assert_eq!((pua.severity, pua.confidence), (Severity::Low, 50));
}
