use scanner::*;
use sigdb::Database;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("litric_ldb_{n}_{}_{}", std::process::id(), SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn db(extra_lines: &[&str]) -> Arc<Database> {
    let text = format!("LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count {}\n{}\nEND\n", extra_lines.len(), extra_lines.join("\n"));
    Arc::new(Database::parse(text.as_bytes()).unwrap_or_else(|e| panic!("{e}\n{text}")))
}
fn scan(d: Arc<Database>, lim: Limits, p: &Path) -> Report {
    Scanner::new(d, lim).scan_path(p, &AtomicBool::new(false), &mut |_| {})
}
/// spec = "<target> <constraints> <expr> <sub> <sub> ..."
fn hits(spec: &str, data: &[u8]) -> bool {
    let d = tmp("one");
    std::fs::write(d.join("f.bin"), data).unwrap();
    let rep = scan(db(&[&format!("LDB r.0 Fam.0 high 90 {spec}")]), Limits::default(), &d);
    assert_eq!(rep.errors, 0);
    rep.detected == 1
}
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}
const A: &[u8] = &[0x11, 0x22, 0x33, 0x44];
const B: &[u8] = &[0x55, 0x66, 0x77, 0x88];
const C: &[u8] = &[0x99, 0xaa, 0xbb, 0xcc];

#[test]
fn and_or_and_parentheses_over_subsignatures() {
    let subs = "*:11223344 *:55667788 *:99aabbcc";
    let both = cat(&[b"..", A, b"..", B]);
    assert!(hits(&format!("any - 0&1 {subs}"), &both));
    assert!(!hits(&format!("any - 0&1 {subs}"), &cat(&[b"..", A, b".."])));
    assert!(hits(&format!("any - 0|1 {subs}"), &cat(&[b"..", B])));
    assert!(!hits(&format!("any - 0|1 {subs}"), b"nothing here"));
    assert!(hits(&format!("any - (0|1)&2 {subs}"), &cat(&[A, C])));
    assert!(!hits(&format!("any - (0|1)&2 {subs}"), &cat(&[A, B])));
    assert!(hits(&format!("any - 0&(1|2) {subs}"), &cat(&[A, C])));
    assert!(hits(&format!("any - ((0&1)|(0&2)) {subs}"), &cat(&[A, C])));
    assert!(!hits(&format!("any - ((0&1)|(0&2)) {subs}"), &cat(&[B, C])));
    assert!(hits("any - 0 *:11223344", A), "single subsignature");
}

#[test]
fn match_count_conditions_count_every_start_position() {
    let three = cat(&[A, b"-", A, b"-", A]);
    let s = "*:11223344";
    assert!(hits(&format!("any - 0=3 {s}"), &three));
    assert!(!hits(&format!("any - 0=2 {s}"), &three));
    assert!(hits(&format!("any - 0>2 {s}"), &three));
    assert!(!hits(&format!("any - 0>3 {s}"), &three));
    assert!(hits(&format!("any - 0<4 {s}"), &three));
    assert!(!hits(&format!("any - 0<3 {s}"), &three));
    // overlapping occurrences count separately: 10 x 0xAA contains 3 starts of a 8-byte pattern
    let a10 = vec![0xaau8; 10];
    assert!(hits("any - 0=3 *:aaaaaaaaaaaaaaaa", &a10));
    // conditions combine with & and |
    let sub2 = "*:11223344 *:55667788";
    assert!(hits(&format!("any - 0>1&1 {sub2}"), &cat(&[A, A, B])));
    assert!(!hits(&format!("any - 0>1&1 {sub2}"), &cat(&[A, B])));
}

#[test]
fn a_rule_needs_at_least_one_matching_subsignature_even_if_its_expression_is_true_at_zero() {
    assert!(!hits("any - 0<5 *:11223344", b"nothing to match here"), "documented semantics: no matched subsignature, no detection");
    assert!(hits("any - 0<5 *:11223344", A));
}

#[test]
fn file_size_and_section_count_constraints() {
    let data = cat(&[A, &vec![0u8; 96]]); // 100 bytes
    assert!(hits("any FileSize:100-100 0 *:11223344", &data));
    assert!(hits("any FileSize:50-200 0 *:11223344", &data));
    assert!(!hits("any FileSize:101-200 0 *:11223344", &data));
    assert!(!hits("any FileSize:1-99 0 *:11223344", &data));
    use peanalysis::builder::*;
    let pe = PeBuilder::benign(false); // 3 sections + .idata = 4
    let mut b = pe.clone();
    b.sections[1].data = cat(&[b"Hello", &vec![1u8; 40]]);
    let bytes = b.build();
    assert!(hits("pe NumberOfSections:4-4 0 *:48656c6c6f", &bytes));
    assert!(hits("pe NumberOfSections:3-5 0 *:48656c6c6f", &bytes));
    assert!(!hits("pe NumberOfSections:5-6 0 *:48656c6c6f", &bytes));
    assert!(!hits("any NumberOfSections:1-9 0 *:11223344", A), "a section-count constraint cannot hold for a non-PE file");
}

#[test]
fn per_subsignature_offsets_and_pe_relative_offsets() {
    let f = cat(&[A, &[0u8; 20], B]);
    assert!(hits("any - 0&1 0:11223344 24:55667788", &f));
    assert!(!hits("any - 0&1 0:11223344 25:55667788", &f));
    assert!(hits("any - 0&1 0:11223344 EOF-4:55667788", &f));
    assert!(!hits("any - 0&1 4:11223344 EOF-4:55667788", &f));
    use peanalysis::builder::*;
    let pe = PeBuilder::benign(false).build();
    assert!(hits("pe - 0&1 EP+0:558bec83ec10 S1+0:48656c6c6f", &pe));
    assert!(!hits("pe - 0&1 EP+1:558bec83ec10 S1+0:48656c6c6f", &pe));
}

#[test]
fn target_types_apply_to_the_whole_rule() {
    let elf = cat(&[b"\x7fELF", &[0u8; 12], A]);
    assert!(hits("elf - 0&1 0:7f454c46 *:11223344", &elf));
    assert!(!hits("pe - 0&1 *:7f454c46 *:11223344", &elf));
    assert!(hits("any - 0&1 *:7f454c46 *:11223344", &elf));
}

#[test]
fn logical_and_extended_rules_report_together_with_their_methods() {
    let d = tmp("mixed");
    std::fs::write(d.join("f.bin"), cat(&[A, b"..", B, b"..", C])).unwrap();
    let rep = scan(
        db(&["NDB n.1 Ndb.Hit high 90 any * 99aabbcc", "LDB l.1 Ldb.Hit high 90 any - 0&1 *:11223344 *:55667788", "LDB l.2 Ldb.Miss high 90 any - 0&1 *:11223344 *:deadbeef"]),
        Limits::default(),
        &d,
    );
    let Outcome::Detected(v) = &rep.results[0].outcome else { panic!() };
    let mut got: Vec<_> = v.iter().map(|x| (x.family.as_str(), x.method.clone())).collect();
    got.sort_by(|a, b| a.0.cmp(b.0));
    assert_eq!(got, vec![("Ldb.Hit", Method::Logical), ("Ndb.Hit", Method::Extended)]);
}

#[test]
fn constraint_filters_limit_work_and_rules_apply_independently_per_file() {
    let d = tmp("perfile");
    std::fs::write(d.join("small.bin"), cat(&[A, B])).unwrap();
    std::fs::write(d.join("big.bin"), cat(&[A, B, &vec![0u8; 5000]])).unwrap();
    let rep = scan(db(&["LDB l.1 Ldb.Small high 90 any FileSize:1-100 0&1 *:11223344 *:55667788"]), Limits::default(), &d);
    assert_eq!(rep.detected, 1);
    assert!(rep.detections().next().unwrap().path.ends_with("small.bin"));
}

#[test]
fn logical_rule_flooding_is_budgeted_and_reported_incomplete() {
    let d = tmp("flood");
    std::fs::write(d.join("zeros.bin"), vec![0u8; 2 * 1024 * 1024]).unwrap();
    let lines: Vec<String> = (0..40).map(|i| format!("LDB l.{i} Flood.{i} high 90 any - 0&1 *:00000000 *:ffee{i:02x}dd")).collect();
    let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    let t = std::time::Instant::now();
    let rep = scan(db(&refs), Limits { ndb_budget: 1_000_000, ..Limits::default() }, &d);
    assert!(t.elapsed().as_secs() < 20, "{:?}", t.elapsed());
    assert_eq!((rep.unscannable, rep.detected, rep.no_threat_found), (1, 0, 0));
    assert!(!rep.is_complete());
}

#[test]
fn clamav_ldb_through_import_binary_sign_install_scan() {
    let sigs = tmp("ldb_sigs");
    std::fs::write(
        sigs.join("t.ldb"),
        "Win.Logic.A;Target:0,FileSize:10-1000;(0&1)|2;11223344;55667788;99aabbcc\nWin.Logic.Count;Target:0;0>1;aabbccdd\nPUA.Logic.Low;Target:0;0;deadbeefcafe\n",
    )
    .unwrap();
    let o = clamav_import::import_dir(&sigs, &clamav_import::Options { serial: 1, created: 1, source_note: "ldb test fixture".into() }).unwrap();
    assert_eq!(o.report.total(|f| f.imported), 3, "{}", o.report.render());
    let bin = sigdb::binary::encode(&Database::parse(&o.db).unwrap());
    let seed = [13u8; 32];
    let mut keys = sigdb::TrustedKeys::new();
    keys.add_hex(&sigdb::hex_encode(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().as_bytes())).unwrap();
    let store = sigdb::Store::open(tmp("ldb_store")).unwrap();
    store.install(&bin, &sigdb::sign_bundle(&seed, &bin), &keys).unwrap();
    let live = Arc::new(store.load_active(&keys).unwrap().unwrap());
    let files = tmp("ldb_files");
    std::fs::write(files.join("both.bin"), cat(&[A, b"padding", B])).unwrap();
    std::fs::write(files.join("twice.bin"), cat(&[b"aa", &[0xaa, 0xbb, 0xcc, 0xdd], b"..", &[0xaa, 0xbb, 0xcc, 0xdd]])).unwrap();
    std::fs::write(files.join("once.bin"), cat(&[b"..", &[0xaa, 0xbb, 0xcc, 0xdd]])).unwrap();
    std::fs::write(files.join("clean.txt"), b"nothing to see").unwrap();
    let rep = scan(live, Limits::default(), &files);
    let mut det: Vec<(String, String)> = rep
        .detections()
        .map(|r| {
            let Outcome::Detected(v) = &r.outcome else { unreachable!() };
            (r.path.file_name().unwrap().to_string_lossy().to_string(), v[0].family.clone())
        })
        .collect();
    det.sort();
    assert_eq!(det, vec![("both.bin".into(), "Win.Logic.A".into()), ("twice.bin".into(), "Win.Logic.Count".into())]);
}
