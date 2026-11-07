//! Scanner behaviour with databases produced by the ClamAV adapter.
use scanner::*;
use sigdb::Database;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

const MD5_ABC: &str = "900150983cd24fb0d6963f7d28e17f72";
const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const MD5_EICAR: &str = "44d88612fea8a8f36de82e1278abb02f";

fn eicar() -> Vec<u8> {
    concat!("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EI", "CAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").as_bytes().to_vec()
}
fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("litric_clam_{n}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn scanner_from(n: &str, files: &[(&str, String)]) -> Scanner {
    let d = tmp(&format!("{n}_sigs"));
    for (name, body) in files {
        std::fs::write(d.join(name), body).unwrap();
    }
    let o = clamav_import::import_dir(&d, &clamav_import::Options { serial: 1, created: 1, source_note: "test fixture".into() }).unwrap();
    Scanner::new(Arc::new(Database::parse(&o.db).unwrap()), Limits::default())
}
fn scan(s: &Scanner, p: &Path) -> Report {
    s.scan_path(p, &AtomicBool::new(false), &mut |_| {})
}

#[test]
fn eicar_matches_the_real_clamav_style_md5_entry_and_requires_exact_size() {
    let s = scanner_from("eicar", &[("a.hdb", format!("{MD5_EICAR}:68:Eicar-Test-Signature\n"))]);
    let d = tmp("eicar_files");
    std::fs::write(d.join("eicar.com"), eicar()).unwrap();
    let rep = scan(&s, &d);
    assert_eq!(rep.detected, 1, "MD5 of the 68-byte EICAR string must match");
    if let Outcome::Detected(v) = &rep.results[0].outcome {
        assert_eq!((v[0].family.as_str(), v[0].method.clone()), ("Eicar-Test-Signature", Method::Hash));
    }
    assert_eq!(rep.db_sources.len(), 2);
    assert!(rep.db_sources[0].contains("test fixture"));
    // trailing newline changes both hash and size: must NOT match
    let d2 = tmp("eicar_nl");
    let mut with_nl = eicar();
    with_nl.push(b'\n');
    std::fs::write(d2.join("eicar_nl.com"), with_nl).unwrap();
    assert_eq!(scan(&s, &d2).detected, 0);
}

#[test]
fn sha1_and_sha256_file_hashes_match_and_size_must_agree() {
    let s = scanner_from("sha", &[("a.hsb", format!("{SHA1_ABC}:3:Sha1.Sig\n")), ("b.hsb", format!("{SHA256_ABC}:3:Sha256.Sig\n"))]);
    let d = tmp("sha_files");
    std::fs::write(d.join("abc.txt"), b"abc").unwrap();
    let rep = scan(&s, &d);
    let Outcome::Detected(v) = &rep.results[0].outcome else { panic!("{:?}", rep.results[0].outcome) };
    let mut fam: Vec<_> = v.iter().map(|x| x.family.clone()).collect();
    fam.sort();
    assert_eq!(fam, ["Sha1.Sig", "Sha256.Sig"]);
    let s2 = scanner_from("sha_size", &[("a.hsb", format!("{SHA256_ABC}:4:Wrong.Size\n"))]);
    assert_eq!(scan(&s2, &d).detected, 0);
}

#[test]
fn clamav_fp_allowlist_overrides_a_detection() {
    let s = scanner_from("fp", &[("a.hdb", format!("{MD5_ABC}:3:Noisy.Sig\n")), ("a.fp", format!("{MD5_ABC}:3:Known.Good\n"))]);
    let d = tmp("fp_files");
    std::fs::write(d.join("abc.txt"), b"abc").unwrap();
    let rep = scan(&s, &d);
    assert_eq!((rep.detected, rep.allowlisted), (0, 1));
}

fn section_md5(data: &[u8], name: &str) -> (String, usize) {
    use md5::Digest;
    let info = peanalysis::parse(data).unwrap();
    let s = info.sections.iter().find(|s| s.name == name).unwrap();
    let end = (s.raw_ptr as usize + s.raw_size as usize).min(data.len());
    let slice = &data[s.raw_ptr as usize..end];
    (sigdb::hex_encode(&md5::Md5::digest(slice)), slice.len())
}

#[test]
fn pe_section_hash_signature_detects_the_pe_and_not_other_files() {
    use peanalysis::builder::*;
    let pe = PeBuilder::benign(false).build();
    let (h, size) = section_md5(&pe, ".text");
    let s = scanner_from("sec", &[("a.mdb", format!("{size}:{h}:Sec.Test\n"))]);
    let d = tmp("sec_files");
    std::fs::write(d.join("prog.exe"), &pe).unwrap();
    std::fs::write(d.join("other.txt"), b"not a pe").unwrap();
    let mut other = PeBuilder::benign(true);
    other.sections[0].data = pseudo_random(0x600, 3);
    std::fs::write(d.join("different.exe"), other.build()).unwrap();
    let rep = scan(&s, &d);
    assert_eq!(rep.detected, 1, "{:?}", rep.results.iter().map(|r| &r.path).collect::<Vec<_>>());
    let r = rep.detections().next().unwrap();
    assert!(r.path.ends_with("prog.exe"));
    if let Outcome::Detected(v) = &r.outcome {
        assert_eq!((v[0].family.as_str(), v[0].method.clone()), ("Sec.Test", Method::SectionHash));
    }
}

#[test]
fn overlapping_section_amplification_is_bounded_and_reported_incomplete() {
    use peanalysis::builder::*;
    let mut pe = PeBuilder::benign(false).build();
    let len = pe.len();
    let n = peanalysis::parse(&pe).unwrap().sections.len();
    let table = 0x58 + 0xE0;
    for i in 0..n {
        let o = table + i * 40;
        pe[o + 16..o + 20].copy_from_slice(&((len - 0x200) as u32).to_le_bytes());
        pe[o + 20..o + 24].copy_from_slice(&0x200u32.to_le_bytes());
    }
    let s = scanner_from("amp", &[("a.mdb", format!("512:{MD5_ABC}:Never.Matches\n"))]);
    let d = tmp("amp_files");
    std::fs::write(d.join("overlap.exe"), &pe).unwrap();
    let rep = scan(&s, &d);
    assert_eq!((rep.unscannable, rep.no_threat_found), (1, 0), "{:?}", rep.results.iter().map(|r| &r.outcome).collect::<Vec<_>>());
    assert!(!rep.is_complete());
}

#[test]
fn legacy_digests_are_computed_only_when_the_database_needs_them() {
    // sha256-only database must still work (no md5/sha1 work needed)
    let s = scanner_from("only256", &[("a.hsb", format!("{SHA256_ABC}:3:Only.Sha256\n"))]);
    let d = tmp("only256_files");
    std::fs::write(d.join("abc.txt"), b"abc").unwrap();
    assert_eq!(scan(&s, &d).detected, 1);
}
