use sigdb::*;

const SEED: [u8; 32] = [7; 32];
const SEED2: [u8; 32] = [9; 32];

fn pubhex(seed: &[u8; 32]) -> String {
    hex_encode(ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().as_bytes())
}
fn keys(seed: &[u8; 32]) -> TrustedKeys {
    let mut k = TrustedKeys::new();
    k.add_hex(&pubhex(seed)).unwrap();
    k
}
fn db(serial: u64, extra: &str) -> Vec<u8> {
    let h = hex_encode(&sha256(b"known-bad"));
    format!(
        "LITRIC-SIGDB 1\nserial {serial}\ncreated 1730000000\nmin-engine 1\nrule-count 2\n\
         H test.hash Test.Family high 90 {h}\nP test.pat Test.Pat medium 70 any 4142434445\n{extra}END\n"
    )
    .into_bytes()
}
fn tmp(n: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("litric_sigdb_{n}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn valid_database_parses() {
    let d = Database::parse(&db(5, "")).unwrap();
    assert_eq!((d.serial, d.rule_count()), (5, 2));
    assert_eq!(d.hash_rules.values().next().unwrap().severity, Severity::High);
}

#[test]
fn malformed_databases_are_rejected_whole() {
    let good = String::from_utf8(db(1, "")).unwrap();
    let bad: Vec<(String, &str)> = vec![
        (good.replace("LITRIC-SIGDB 1", "LITRIC-SIGDB 3"), "unknown version"),
        (good.replace("END\n", ""), "truncated"),
        (good.replace("rule-count 2", "rule-count 3"), "count mismatch"),
        (good.replace("4142434445", "41424"), "odd hex"),
        (good.replace("4142434445", "414243"), "pattern too short"),
        (good.replace("high 90", "huge 90"), "severity"),
        (good.replace("high 90", "high 101"), "confidence"),
        (good.replace("test.pat", "test.hash"), "duplicate id"),
        (good.replace("END\n", "END\nH x y low 1 00\n"), "data after END"),
        (good.replace("serial 1\n", "serial 1\nserial 2\n"), "dup header"),
        (good.replace("any 41", "weird 41"), "target"),
        (good.replace("created 1730000000\n", ""), "missing header"),
        (good.replace("H test.hash", "H bad id"), "field count"),
    ];
    for (b, why) in bad {
        assert!(Database::parse(b.as_bytes()).is_err(), "should reject: {why}");
    }
    assert!(Database::parse(&[0xff, 0xfe]).is_err());
}

#[test]
fn revocation_removes_rules_and_allowlist_loads() {
    let h = hex_encode(&sha256(b"good"));
    let d = Database::parse(&db(1, &format!("A {h}\nR test.pat\n")).iter().map(|b| *b).collect::<Vec<_>>()).unwrap_or_else(|e| panic!("{e}"));
    assert!(d.patterns.is_empty());
    assert_eq!(d.allow.len(), 1);
}

#[test]
fn signature_good_tampered_wrong_key_revoked() {
    let bytes = db(1, "");
    let sig = sign_bundle(&SEED, &bytes);
    assert!(verify_bundle(&bytes, &sig, &keys(&SEED)).is_ok());
    let mut tampered = bytes.clone();
    *tampered.iter_mut().find(|b| **b == b'9').unwrap() = b'8';
    assert!(matches!(verify_bundle(&tampered, &sig, &keys(&SEED)), Err(Error::BadSignature(_))));
    assert!(matches!(verify_bundle(&bytes, &sig, &keys(&SEED2)), Err(Error::UnknownKey(_))));
    // rotation: trust new key, revoke old key id
    let mut k = keys(&SEED2);
    k.add_hex(&pubhex(&SEED)).unwrap();
    let old_id = sig.split(' ').next().unwrap().to_string();
    k.revoke(&old_id);
    assert!(matches!(verify_bundle(&bytes, &sig, &k), Err(Error::KeyRevoked(_))));
    assert!(verify_bundle(&bytes, &sign_bundle(&SEED2, &bytes), &k).is_ok());
    assert!(verify_bundle(&bytes, "garbage", &keys(&SEED)).is_err());
}

#[test]
fn install_rejects_rollback_reuse_and_unsigned_and_is_idempotent() {
    let dir = tmp("install");
    let s = Store::open(&dir).unwrap();
    let k = keys(&SEED);
    assert!(s.load_active(&k).unwrap().is_none());

    let v5 = db(5, "");
    assert_eq!(s.install(&v5, &sign_bundle(&SEED, &v5), &k).unwrap(), Install::Installed { serial: 5 });
    assert_eq!(s.load_active(&k).unwrap().unwrap().serial, 5);
    assert_eq!(s.install(&v5, &sign_bundle(&SEED, &v5), &k).unwrap(), Install::AlreadyCurrent);

    let v4 = db(4, "");
    assert!(matches!(s.install(&v4, &sign_bundle(&SEED, &v4), &k), Err(Error::Rollback { current: 5, offered: 4 })));
    let v5b = db(5, "R nothing\n");
    assert!(matches!(s.install(&v5b, &sign_bundle(&SEED, &v5b), &k), Err(Error::SerialReuse(5))));
    let v6 = db(6, "");
    assert!(s.install(&v6, &sign_bundle(&SEED2, &v6), &k).is_err(), "unsigned/wrong key");
    assert_eq!(s.load_active(&k).unwrap().unwrap().serial, 5, "failed installs change nothing");

    let mut min = String::from_utf8(db(7, "")).unwrap().replace("min-engine 1", "min-engine 99").into_bytes();
    assert!(matches!(s.install(&min, &sign_bundle(&SEED, &min), &k), Err(Error::EngineTooOld { need: 99 })));
    min.clear();
    assert_eq!(s.install(&v6, &sign_bundle(&SEED, &v6), &k).unwrap(), Install::Installed { serial: 6 });
}

#[test]
fn tampered_active_bundle_and_corrupt_floor_are_detected() {
    let dir = tmp("tamper");
    let s = Store::open(&dir).unwrap();
    let k = keys(&SEED);
    let v1 = db(1, "");
    s.install(&v1, &sign_bundle(&SEED, &v1), &k).unwrap();
    let p = dir.join("active.bundle");
    let mut b = std::fs::read(&p).unwrap();
    let i = b.len() - 10;
    b[i] ^= 0x01;
    std::fs::write(&p, b).unwrap();
    assert!(s.load_active(&k).is_err(), "modified active database must not load");

    std::fs::write(dir.join("state.txt"), "garbage").unwrap();
    let v2 = db(2, "");
    assert!(matches!(s.install(&v2, &sign_bundle(&SEED, &v2), &k), Err(Error::Corrupt(_))), "never reset the rollback floor");
}

// ---------------------------------------------------------------- format v2

fn v2(body: &str) -> Vec<u8> {
    let n = body.lines().filter(|l| l.starts_with("H ") || l.starts_with("P ") || l.starts_with("HX ") || l.starts_with("S ")).count();
    format!("LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count {n}\n{body}END\n").into_bytes()
}
const MD5_ABC: &str = "900150983cd24fb0d6963f7d28e17f72";
const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[test]
fn v2_hash_tables_lookup_by_algorithm_digest_and_exact_size() {
    let db = Database::parse(&v2(&format!(
        "source clamav-import test fixture\nHX r.md5 Fam.A high 90 md5 {MD5_ABC} 3\nHX r.sha1 Fam.B low 50 sha1 {SHA1_ABC} 3\nHX r.s256 Fam.A critical 99 sha256 {SHA256_ABC} 3\n\
         S sec.1 Fam.S medium 70 md5 {MD5_ABC} 512\nAX md5 {MD5_ABC} 99\n"
    )))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(db.rule_count(), 4);
    assert_eq!(db.sources, vec!["clamav-import test fixture".to_string()]);
    let md5 = hex_decode(MD5_ABC).unwrap();
    let r = db.lookup_file(Algo::Md5, &md5, 3).unwrap();
    assert_eq!((r.id.as_str(), r.family.as_str(), r.severity, r.confidence), ("r.md5", "Fam.A", Severity::High, 90));
    assert!(db.lookup_file(Algo::Md5, &md5, 4).is_none(), "size must match exactly");
    assert!(db.lookup_file(Algo::Sha1, &md5, 3).is_none());
    assert_eq!(db.lookup_file(Algo::Sha256, &hex_decode(SHA256_ABC).unwrap(), 3).unwrap().severity, Severity::Critical);
    assert_eq!(db.lookup_section(Algo::Md5, &md5, 512).unwrap().id, "sec.1");
    assert!(db.lookup_section(Algo::Md5, &md5, 3).is_none(), "file rules and section rules are separate");
    assert!(db.is_allowed(Algo::Md5, &md5, 99) && !db.is_allowed(Algo::Md5, &md5, 3));
    assert!(db.needs(Algo::Md5) && db.needs(Algo::Sha1) && db.needs(Algo::Sha256));
    assert!(db.has_section_rules());
    assert!(db.lookup_file(Algo::Md5, &md5, u64::MAX).is_none());
}

#[test]
fn v2_records_are_rejected_in_v1_and_malformed_v2_records_are_rejected() {
    let v1_with_hx = format!("LITRIC-SIGDB 1\nserial 1\ncreated 1\nmin-engine 1\nrule-count 1\nHX r Fam high 90 md5 {MD5_ABC} 3\nEND\n");
    assert!(Database::parse(v1_with_hx.as_bytes()).is_err());
    let bad = [
        format!("HX r Fam high 90 md4 {MD5_ABC} 3\n"),
        format!("HX r Fam high 90 md5 {SHA1_ABC} 3\n"),
        format!("HX r Fam high 90 md5 {MD5_ABC} -1\n"),
        format!("HX r Fam high 90 md5 {MD5_ABC} 4294967296\n"),
        format!("HX r Fam huge 90 md5 {MD5_ABC} 3\n"),
        format!("HX r Fam high 90 md5 {MD5_ABC}\n"),
        format!("AX md5 {MD5_ABC}\n"),
        "source \n".to_string(),
        format!("source {}\n", "x".repeat(201)),
    ];
    for b in bad {
        assert!(Database::parse(&v2(&b)).is_err(), "should reject: {b}");
    }
    let dup = format!("HX a F high 90 md5 {MD5_ABC} 3\nHX b F high 90 md5 {MD5_ABC} 3\n");
    assert!(Database::parse(&v2(&dup)).is_err(), "duplicate (algo,hash,size) must be rejected");
    let same_hash_other_size = format!("HX a F high 90 md5 {MD5_ABC} 3\nHX b F high 90 md5 {MD5_ABC} 4\n");
    assert!(Database::parse(&v2(&same_hash_other_size)).is_ok());
}

#[test]
fn v2_revocation_removes_compact_rules() {
    let b = format!("HX r.keep F high 90 md5 {MD5_ABC} 3\nHX r.drop F high 90 sha1 {SHA1_ABC} 3\nR r.drop\n");
    let db = Database::parse(&v2(&b)).unwrap();
    assert_eq!(db.rule_count(), 1);
    assert!(db.lookup_file(Algo::Sha1, &hex_decode(SHA1_ABC).unwrap(), 3).is_none());
}

#[test]
fn v2_bundle_signs_and_installs_like_v1() {
    let dir = tmp("v2install");
    let s = Store::open(&dir).unwrap();
    let k = keys(&SEED);
    let b = v2(&format!("HX r F high 90 md5 {MD5_ABC} 3\n"));
    assert_eq!(s.install(&b, &sign_bundle(&SEED, &b), &k).unwrap(), Install::Installed { serial: 1 });
    assert_eq!(s.load_active(&k).unwrap().unwrap().rule_count(), 1);
}
