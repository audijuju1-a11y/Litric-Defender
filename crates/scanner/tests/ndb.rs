use scanner::*;
use sigdb::Database;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("litric_ndb_{n}_{}_{}", std::process::id(), SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn db(rules: &[&str]) -> Arc<Database> {
    let mut body = String::new();
    for (i, r) in rules.iter().enumerate() {
        // r = "<target> <offset> <sig>"
        body.push_str(&format!("NDB r.{i} Fam.{i} high 90 {r}\n"));
    }
    let text = format!("LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count {}\n{body}END\n", rules.len());
    Arc::new(Database::parse(text.as_bytes()).unwrap_or_else(|e| panic!("{e}\n{text}")))
}
fn scan_with(d: Arc<Database>, lim: Limits, p: &Path) -> Report {
    Scanner::new(d, lim).scan_path(p, &AtomicBool::new(false), &mut |_| {})
}
/// Does a one-file scan with a single rule detect it?
fn hits(rule: &str, data: &[u8]) -> bool {
    let d = tmp("one");
    std::fs::write(d.join("f.bin"), data).unwrap();
    let rep = scan_with(db(&[rule]), Limits::default(), &d);
    assert_eq!(rep.errors, 0);
    rep.detected == 1
}
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[test]
fn exact_bytes_anywhere() {
    assert!(hits("any * deadbeef", &cat(&[b"junk junk", &[0xde, 0xad, 0xbe, 0xef], b"more"])));
    assert!(!hits("any * deadbeef", b"junk with no marker at all"));
}

#[test]
fn byte_and_nibble_wildcards() {
    let d = [0x11, 0x22, 0x33, 0x44, 0xaa, 0x55, 0xbb];
    assert!(hits("any * 11223344aa??bb", &d));
    assert!(hits("any * 11223344aa5?bb", &d));
    assert!(hits("any * 11223344aa?5bb", &d));
    assert!(!hits("any * 11223344aa6?bb", &d));
    assert!(!hits("any * 11223344aa?6bb", &d));
}

#[test]
fn gaps_and_any() {
    let d = [0x11, 0x22, 0x33, 0x44, 0xaa, 0x01, 0x02, 0xbb];
    assert!(hits("any * 11223344aa{2}bb", &d));
    assert!(!hits("any * 11223344aa{1}bb", &d));
    assert!(!hits("any * 11223344aa{3}bb", &d));
    assert!(hits("any * 11223344aa{1-3}bb", &d));
    assert!(!hits("any * 11223344aa{3-5}bb", &d));
    assert!(hits("any * 11223344aa{-2}bb", &d));
    assert!(hits("any * 11223344aa{2-}bb", &d));
    assert!(!hits("any * 11223344aa{3-}bb", &d));
    assert!(hits("any * 11223344aa*bb", &d));
    assert!(!hits("any * 11223344aa*cc", &d));
    assert!(hits("any * 11223344aa{0}01", &d[..6]));
}

#[test]
fn alternatives_of_different_lengths() {
    let sig = "any * 11223344(aa|bbcc)ddee";
    assert!(hits(sig, &[0x11, 0x22, 0x33, 0x44, 0xaa, 0xdd, 0xee]));
    assert!(hits(sig, &[0x11, 0x22, 0x33, 0x44, 0xbb, 0xcc, 0xdd, 0xee]));
    assert!(!hits(sig, &[0x11, 0x22, 0x33, 0x44, 0xbb, 0xdd, 0xee]));
    assert!(!hits(sig, &[0x11, 0x22, 0x33, 0x44, 0xdd, 0xee]));
}

#[test]
fn absolute_offset_maxshift_and_eof() {
    let mut f = vec![0u8; 40];
    f[10..14].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert!(hits("any 10 deadbeef", &f));
    assert!(!hits("any 9 deadbeef", &f));
    assert!(!hits("any 11 deadbeef", &f));
    assert!(hits("any 8,2 deadbeef", &f), "start window [8,10]");
    assert!(hits("any 10,5 deadbeef", &f));
    assert!(!hits("any 11,5 deadbeef", &f));
    assert!(!hits("any 0 deadbeef", &f));
    let tail = cat(&[&vec![7u8; 30], &[0xde, 0xad, 0xbe, 0xef]]);
    assert!(hits("any EOF-4 deadbeef", &tail));
    assert!(!hits("any EOF-5 deadbeef", &tail));
    assert!(!hits("any EOF-4 deadbeef", &cat(&[&tail, b"x"])));
}

#[test]
fn pe_entry_point_and_section_offsets_use_the_parsed_pe() {
    use peanalysis::builder::*;
    let pe = PeBuilder::benign(false).build();
    // .text begins at the entry point with the repeating pattern 55 8B EC 83 EC 10 90 C3
    assert!(hits("pe EP+0 558bec83ec10", &pe));
    assert!(hits("pe EP+1 8bec83ec10", &pe));
    assert!(!hits("pe EP+1 558bec83ec10", &pe));
    assert!(hits("pe EP+8 558bec83ec10", &pe), "pattern repeats every 8 bytes");
    assert!(hits("pe S0+0 558bec83ec10", &pe));
    assert!(hits("pe S1+0 48656c6c6f", &pe), "section 1 (.rdata) starts with Hello");
    assert!(!hits("pe S0+0 48656c6c6f", &pe));
    // a section-relative signature written for a non-PE file can never match
    assert!(!hits("pe S1+0 48656c6c6f", b"Hello, I am plain text"));
    assert!(!hits("pe EP+0 558bec83ec10", b"\x55\x8b\xec\x83\xec\x10 not a pe"));
}

#[test]
fn target_types_filter_by_detected_file_kind() {
    let elf = cat(&[b"\x7fELF", &[0u8; 20]]);
    assert!(hits("elf 0 7f454c46", &elf));
    assert!(!hits("elf * 454c46", b"text that mentions ELF but is not one"), "too-short anchors aside, kind must match");
    let text_with_magic_inside = cat(&[b"some header ", b"\x7fELF"]);
    assert!(!hits("elf * 7f454c46", &text_with_magic_inside));
    assert!(hits("any * 7f454c46", &text_with_magic_inside));
    assert!(hits("pdf 0 255044462d", b"%PDF-1.7 rest"));
    assert!(!hits("pdf * 255044462d", b"not a pdf %PDF- inside text"));
}

#[test]
fn two_rules_sharing_an_anchor_both_report_and_repeats_report_once() {
    let d = tmp("share");
    std::fs::write(d.join("f.bin"), cat(&[&[0xde, 0xad, 0xbe, 0xef, 1], &[0xde, 0xad, 0xbe, 0xef, 1], &[0xde, 0xad, 0xbe, 0xef, 2]])).unwrap();
    let rep = scan_with(db(&["any * deadbeef01", "any * deadbeef02", "any * deadbeef99"]), Limits::default(), &d);
    let scanner::Outcome::Detected(v) = &rep.results[0].outcome else { panic!() };
    assert_eq!(v.len(), 2);
    assert!(v.iter().all(|x| x.method == Method::Extended));
}

#[test]
fn pathological_backtracking_is_budgeted_and_reported_incomplete() {
    let d = tmp("budget");
    let mut data = vec![0xaa, 0xbb, 0xcc, 0xdd];
    data.extend(vec![0xaa; 30_000]);
    std::fs::write(d.join("evil.bin"), data).unwrap();
    let sig = format!("any * aabbccdd{}ee", "{0-30000}aa".repeat(6));
    let lim = Limits { ndb_budget: 2_000_000, ..Limits::default() };
    let t = std::time::Instant::now();
    let rep = scan_with(db(&[&sig]), lim, &d);
    assert!(t.elapsed().as_secs() < 20, "must stop promptly: {:?}", t.elapsed());
    assert_eq!((rep.unscannable, rep.detected, rep.no_threat_found), (1, 0, 0));
    assert!(!rep.is_complete());
    assert!(matches!(&rep.results[0].outcome, scanner::Outcome::Unscannable(m) if m.contains("budget")));
}

#[test]
fn many_rules_over_random_data_finish_within_budget_and_find_the_planted_one() {
    let d = tmp("many");
    let mut x: u64 = 0x1234_5678_9ABC_DEF1;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let mut data: Vec<u8> = (0..2 * 1024 * 1024).map(|_| rnd() as u8).collect();
    let planted = [0x13, 0x37, 0xc0, 0xde, 0xfa, 0xce];
    data[1_000_000..1_000_006].copy_from_slice(&planted);
    std::fs::write(d.join("r.bin"), &data).unwrap();
    let mut rules: Vec<String> = (0..3000).map(|i| format!("any * {:08x}{:02x}", rnd() as u32, i as u8)).collect();
    rules.push(format!("any * {}", planted.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    let refs: Vec<&str> = rules.iter().map(|s| s.as_str()).collect();
    let rep = scan_with(db(&refs), Limits::default(), &d);
    assert_eq!((rep.detected, rep.unscannable), (1, 0), "{:?}", rep.results.iter().map(|r| &r.outcome).collect::<Vec<_>>());
}

#[test]
fn clamav_ndb_eicar_through_import_sign_install_scan() {
    let eicar = concat!("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EI", "CAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").as_bytes().to_vec();
    let hex: String = eicar.iter().map(|b| format!("{b:02x}")).collect();
    // second signature: same string with wildcards and a gap
    let wild = format!("{}??{}{{4}}{}", &hex[..20], &hex[22..40], &hex[48..]);
    let sigs = tmp("ndb_sigs");
    std::fs::write(sigs.join("t.ndb"), format!("Eicar-Test-Signature:0:*:{hex}\nEicar.Wild:0:*:{wild}\n")).unwrap();
    let o = clamav_import::import_dir(&sigs, &clamav_import::Options { serial: 1, created: 1, source_note: "ndb test fixture".into() }).unwrap();
    assert_eq!(o.report.total(|f| f.imported), 2, "{}", o.report.render());
    let seed = [11u8; 32];
    let mut keys = sigdb::TrustedKeys::new();
    keys.add_hex(&sigdb::hex_encode(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().as_bytes())).unwrap();
    let store = sigdb::Store::open(tmp("ndb_store")).unwrap();
    store.install(&o.db, &sigdb::sign_bundle(&seed, &o.db), &keys).unwrap();
    let live = Arc::new(store.load_active(&keys).unwrap().unwrap());
    let files = tmp("ndb_files");
    std::fs::write(files.join("eicar.com"), &eicar).unwrap();
    std::fs::write(files.join("clean.txt"), b"nothing to see here").unwrap();
    let rep = scan_with(live, Limits::default(), &files);
    assert_eq!((rep.detected, rep.no_threat_found), (1, 1));
    let scanner::Outcome::Detected(v) = &rep.results[0].outcome else { panic!() };
    let mut fam: Vec<_> = v.iter().map(|d| d.family.as_str()).collect();
    fam.sort();
    assert_eq!(fam, ["Eicar-Test-Signature", "Eicar.Wild"], "wildcard/gap variant must also match");
}

#[test]
fn anchors_of_2_3_4_and_longer_bytes_all_find_candidates_at_any_position() {
    // anchor length 2 ("4d5a" then ?? then 00)
    assert!(hits("any * 4d5a??00", &cat(&[b"xxxx", &[0x4d, 0x5a, 0x77, 0x00], b"yy"])));
    assert!(!hits("any * 4d5a??00", &cat(&[b"xxxx", &[0x4d, 0x5a, 0x77, 0x01], b"yy"])));
    // anchor length 3
    assert!(hits("any * 4d5a90??00", &cat(&[b"..", &[0x4d, 0x5a, 0x90, 0x11, 0x00]])));
    assert!(hits("any * 414243??44", b"zzABC?Dzz"), "?? matches any byte, including a literal '?'");
    assert!(!hits("any * 414243??44", b"zzABCDzz"), "?? consumes exactly one byte");
    assert!(hits("any * 414243??44", &cat(&[b"zz", &[0x41, 0x42, 0x43, 0x99, 0x44]])));
    // anchor longer than 4 bytes: prefilter uses the first 4, the full signature must still match
    let sig = "any * 0102030405060708";
    assert!(hits(sig, &[9, 1, 2, 3, 4, 5, 6, 7, 8, 9]));
    assert!(!hits(sig, &[9, 1, 2, 3, 4, 5, 6, 7, 99, 9]), "same 4-byte key, different tail: must not match");
    // match at the very start and very end of the data
    assert!(hits("any * 0102030405", &[1, 2, 3, 4, 5]));
    assert!(hits("any * 4d5a", &[0x4d, 0x5a]));
    assert!(!hits("any * 4d5a", &[0x4d]));
}
