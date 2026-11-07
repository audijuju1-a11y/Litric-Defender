use sigdb::{hex_encode, sign_bundle};
use std::path::PathBuf;
use std::process::Command;

const SEED: [u8; 32] = [3; 32];

fn eicar() -> Vec<u8> {
    concat!("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EI", "CAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").as_bytes().to_vec()
}
fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("litric_cli_{n}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn pubhex() -> String {
    hex_encode(ed25519_dalek::SigningKey::from_bytes(&SEED).verifying_key().as_bytes())
}
fn write_db(dir: &PathBuf, rules: &str) -> (PathBuf, PathBuf) {
    let n = rules.lines().count();
    let db = format!("LITRIC-SIGDB 1\nserial 1\ncreated 1\nmin-engine 1\nrule-count {n}\n{rules}END\n").into_bytes();
    let (dp, sp) = (dir.join("db.lsdb"), dir.join("db.sig"));
    std::fs::write(&dp, &db).unwrap();
    std::fs::write(&sp, sign_bundle(&SEED, &db)).unwrap();
    (dp, sp)
}
fn run(args: &[&str]) -> (i32, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_litric-scan")).args(args).output().unwrap();
    (o.status.code().unwrap(), String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr))
}

fn setup(name: &str, rules: &str) -> (PathBuf, Vec<String>) {
    let d = tmp(name);
    let (db, sig) = write_db(&d, rules);
    let args = vec!["--pubkey".into(), pubhex(), "--db".into(), db.to_str().unwrap().into(), "--sig".into(), sig.to_str().unwrap().into()];
    (d, args)
}
fn go(base: &[String], extra: &[&str]) -> (i32, String) {
    let mut a: Vec<&str> = base.iter().map(|s| s.as_str()).collect();
    a.extend_from_slice(extra);
    run(&a)
}
fn eicar_rule() -> String {
    format!("P eicar.test Eicar-Test-File low 100 any {}\n", hex_encode(&eicar()))
}

#[test]
fn benign_directory_exits_0_but_never_claims_safety() {
    let (d, base) = setup("benign", &eicar_rule());
    let g = d.join("good");
    std::fs::create_dir_all(&g).unwrap();
    std::fs::write(g.join("a.txt"), b"hello").unwrap();
    let (c, out) = go(&base, &[g.to_str().unwrap()]);
    assert_eq!(c, 0, "{out}");
    assert!(out.contains("very limited"), "tiny database must be called out: {out}");
    assert!(out.contains("not a guarantee"));
}

#[test]
fn detection_exits_1_and_quarantine_copy_then_move_behave() {
    let (d, base) = setup("detect", &eicar_rule());
    let f = d.join("sample.bin");
    std::fs::write(&f, eicar()).unwrap();
    let q = d.join("q");
    let (c, out) = go(&base, &["--quarantine", q.to_str().unwrap(), f.to_str().unwrap()]);
    assert_eq!(c, 1, "{out}");
    assert!(out.contains("DETECTED") && out.contains("Eicar-Test-File"));
    assert!(f.exists(), "copy-only must keep the original");
    let (c, out) = go(&base, &["--quarantine", q.to_str().unwrap(), "--move", f.to_str().unwrap()]);
    assert_eq!(c, 1, "{out}");
    assert!(!f.exists(), "--move removes the original after verification");
    assert_eq!(std::fs::read_dir(q.join("meta")).unwrap().count(), 2);
    assert_eq!(std::fs::read_dir(q.join("data")).unwrap().count(), 1, "same content stored once");
}

#[test]
fn tampered_database_exits_3_even_if_the_file_would_have_been_detected() {
    let (d, base) = setup("tamper", &eicar_rule());
    let dbp = d.join("db.lsdb");
    let mut b = std::fs::read(&dbp).unwrap();
    b[20] ^= 1;
    std::fs::write(&dbp, b).unwrap();
    let f = d.join("sample.bin");
    std::fs::write(&f, eicar()).unwrap();
    let (c, out) = go(&base, &[f.to_str().unwrap()]);
    assert_eq!(c, 3, "{out}");
    assert!(out.contains("DATABASE PROBLEM") && out.contains("NO signature database"));
}

#[test]
fn empty_database_exits_3() {
    let (d, base) = setup("emptydb", "");
    let f = d.join("a.txt");
    std::fs::write(&f, b"x").unwrap();
    let (c, out) = go(&base, &[f.to_str().unwrap()]);
    assert_eq!(c, 3, "{out}");
    assert!(out.contains("EMPTY"));
}

#[test]
fn incomplete_scan_exits_2() {
    let (d, base) = setup("incomplete", &eicar_rule());
    let f = d.join("a.txt");
    std::fs::write(&f, b"some bytes").unwrap();
    let (c, out) = go(&base, &["--max-pattern-mb", "0", f.to_str().unwrap()]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains("UNSCANNABLE"));
}

#[test]
fn suspicious_pe_exits_4_with_reasons() {
    use peanalysis::builder::*;
    let (d, base) = setup("susp", &eicar_rule());
    let mut packed = PeBuilder::benign(false);
    packed.sections = vec![
        Sec { name: "UPX0".into(), data: vec![], vsize: 0x10000, chars: RWX },
        Sec::new("UPX1", pseudo_random(8192, 99), RWX),
    ];
    packed.entry_section = 1;
    packed.imports = vec![("KERNEL32.dll".into(), vec!["LoadLibraryA".into(), "GetProcAddress".into(), "ExitProcess".into()])];
    let f = d.join("packed.exe");
    std::fs::write(&f, packed.build()).unwrap();
    let (c, out) = go(&base, &[f.to_str().unwrap()]);
    assert_eq!(c, 4, "{out}");
    assert!(out.contains("SUSPICIOUS") && out.contains("known packer") && out.contains("not a confirmed detection"));
}

#[test]
fn binary_database_works_through_the_cli_and_tampering_is_exit_3() {
    let d = tmp("binary_db");
    let n = 1;
    let text = format!("LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count {n}\nsource binary cli test\nHX eicar.md5 Eicar-Test-Signature high 90 md5 44d88612fea8a8f36de82e1278abb02f 68\nEND\n");
    let db = sigdb::Database::parse(text.as_bytes()).unwrap();
    let bin = sigdb::binary::encode(&db);
    let (dp, sp) = (d.join("db.bin"), d.join("db.sig"));
    std::fs::write(&dp, &bin).unwrap();
    std::fs::write(&sp, sign_bundle(&SEED, &bin)).unwrap();
    let sample = d.join("eicar.com");
    std::fs::write(&sample, eicar()).unwrap();
    let base = vec!["--pubkey".to_string(), pubhex(), "--db".into(), dp.to_str().unwrap().into(), "--sig".into(), sp.to_str().unwrap().into()];
    let (c, out) = go(&base, &[sample.to_str().unwrap()]);
    assert_eq!(c, 1, "{out}");
    assert!(out.contains("DETECTED") && out.contains("database source: binary cli test"), "{out}");
    // flip one byte in the last section: streaming verification must refuse the whole database
    let mut bad = bin.clone();
    let i = bad.len() - 3;
    bad[i] ^= 1;
    std::fs::write(&dp, bad).unwrap();
    let (c, out) = go(&base, &[sample.to_str().unwrap()]);
    assert_eq!(c, 3, "{out}");
    assert!(out.contains("DATABASE PROBLEM") && out.contains("NO signature database"), "{out}");
    // installing through the store and scanning with --store
    std::fs::write(&dp, &bin).unwrap();
    let store_dir = d.join("store");
    let mut keys = sigdb::TrustedKeys::new();
    keys.add_hex(&pubhex()).unwrap();
    let st = sigdb::Store::open(&store_dir).unwrap();
    st.install_file(&dp, &sign_bundle(&SEED, &bin), &keys).unwrap();
    let args = vec!["--pubkey".to_string(), pubhex(), "--store".into(), store_dir.to_str().unwrap().into()];
    let (c, out) = go(&args, &[sample.to_str().unwrap()]);
    assert_eq!(c, 1, "{out}");
}
