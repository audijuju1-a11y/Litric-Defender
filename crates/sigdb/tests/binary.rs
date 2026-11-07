use sigdb::binary::{self, assemble, content_digest, encode, sections_of};
use sigdb::*;

const SEED: [u8; 32] = [21; 32];
const MD5: &str = "900150983cd24fb0d6963f7d28e17f72";
const SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
const SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn keys() -> TrustedKeys {
    let mut k = TrustedKeys::new();
    k.add_hex(&hex_encode(ed25519_dalek::SigningKey::from_bytes(&SEED).verifying_key().as_bytes())).unwrap();
    k
}
fn tmp(n: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("litric_bin_{n}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// A database exercising every record type.
fn full_text(serial: u64) -> String {
    let h = hex_encode(&sha256(b"known-bad"));
    let body = format!(
        "source unit test fixture\nsource second provenance line\n\
         H nat.hash Nat.Fam high 90 {h}\nH nat.revoked Nat.Gone high 90 {}\nP nat.pat Nat.Pat medium 70 pe 4142434445\nP nat.pat2 Nat.Pat low 50 any deadbeef01\n\
         A {}\nR nat.revoked\n\
         HX r.md5 Fam.A high 90 md5 {MD5} 3\nHX r.sha1 Fam.B low 50 sha1 {SHA1} 3\nHX r.s256 Fam.A critical 99 sha256 {SHA256} 3\nHX r.md5b Fam.C medium 60 md5 {MD5} 4\n\
         S sec.1 Fam.S medium 70 md5 {MD5} 512\nS sec.2 Fam.S medium 70 sha256 {SHA256} 1024\nAX md5 {MD5} 99\nAX sha1 {SHA1} 7\n\
         NDB n.1 Win.A high 90 pe EP+0 e8??????ffd0\nNDB n.2 Win.B high 90 any * aabbccdd{{2-4}}eeff\nNDB n.3 Elf.C high 90 elf EOF-16 7f454c46\n\
         NDB n.4 Alt.D low 50 any 10,5 11223344(aa|bbcc)ddee\nNDB n.5 Sec.E high 90 pe S1+16 a1b2c3d4\nNDB n.6 Star.F high 90 pdf * 25504446*2d3e\nLDB l.1 Logic.A high 90 pe FileSize:10-9999,NumberOfSections:2-9 (0&1)|2 *:11223344 EP+0:e8??????ffd0 S1+0:aabbccdd\nLDB l.2 Logic.B low 50 any - 0>2 *:deadbeef01\n",
        hex_encode(&sha256(b"revoked")),
        hex_encode(&sha256(b"good")),
    );
    let n = body.lines().filter(|l| ["H ", "P ", "HX ", "S ", "NDB ", "LDB "].iter().any(|p| l.starts_with(p))).count();
    format!("LITRIC-SIGDB 2\nserial {serial}\ncreated 1700000000\nmin-engine 2\nrule-count {n}\n{body}END\n")
}
fn full_db(serial: u64) -> Database {
    Database::parse(full_text(serial).as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn round_trip_preserves_every_record_type() {
    let db = full_db(5);
    let bin = encode(&db);
    assert!(binary::is_binary(&bin));
    let back = binary::load_bytes(&bin, None).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(content_digest(&db), content_digest(&back));
    assert_eq!(encode(&back), bin, "encoding is canonical: re-encoding a decoded database gives identical bytes");
    assert_eq!((back.serial, back.created, back.rule_count()), (db.serial, db.created, db.rule_count()));
    assert_eq!(back.sources, db.sources);
    // semantic spot checks, independent of the serializer
    let md5 = hex_decode(MD5).unwrap();
    assert_eq!(back.lookup_file(Algo::Md5, &md5, 3).unwrap().id, "r.md5");
    assert_eq!(back.lookup_file(Algo::Md5, &md5, 4).unwrap().family, "Fam.C");
    assert!(back.lookup_file(Algo::Md5, &md5, 5).is_none());
    assert_eq!(back.lookup_file(Algo::Sha256, &hex_decode(SHA256).unwrap(), 3).unwrap().severity, Severity::Critical);
    assert_eq!(back.lookup_section(Algo::Sha256, &hex_decode(SHA256).unwrap(), 1024).unwrap().id, "sec.2");
    assert!(back.is_allowed(Algo::Md5, &md5, 99) && back.is_allowed(Algo::Sha1, &hex_decode(SHA1).unwrap(), 7));
    assert_eq!(back.hash_rules.len(), 1, "revoked native rule stays removed");
    assert!(back.revoked.contains("nat.revoked"));
    assert_eq!(back.patterns.len(), 2);
    assert_eq!(back.allow.len(), 1);
    assert_eq!(back.ndb.len(), 6);
    for i in 0..6 {
        assert_eq!(back.ndb[i].target, db.ndb[i].target);
        assert_eq!(back.ndb[i].offset, db.ndb[i].offset);
        assert_eq!(back.ndb[i].code, db.ndb[i].code);
        assert_eq!(back.ndb_rule(i).id, db.ndb_rule(i).id);
        assert_eq!(back.ndb_rule(i).family, db.ndb_rule(i).family);
    }
    assert_eq!(back.ndb_rule(4).id, "n.5");
    assert_eq!(back.ldb.len(), 2);
    for i in 0..2 {
        assert_eq!(back.ldb[i].target, db.ldb[i].target);
        assert_eq!(back.ldb[i].constraints, db.ldb[i].constraints);
        assert_eq!(back.ldb[i].expr_text, db.ldb[i].expr_text);
        assert_eq!(back.ldb[i].expr, db.ldb[i].expr);
        assert_eq!(back.ldb[i].subs.len(), db.ldb[i].subs.len());
        for (a, b) in back.ldb[i].subs.iter().zip(&db.ldb[i].subs) {
            assert_eq!((&a.offset, &a.code), (&b.offset, &b.code));
        }
        assert_eq!(back.ldb_rule(i).id, db.ldb_rule(i).id);
    }
    assert_eq!(back.ldb_rule(0).family, "Logic.A");
}

#[test]
fn empty_database_round_trips() {
    let text = "LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count 0\nEND\n";
    let db = Database::parse(text.as_bytes()).unwrap();
    let back = binary::load_bytes(&encode(&db), None).unwrap();
    assert_eq!((back.rule_count(), back.serial), (0, 1));
}

#[test]
fn signature_covers_the_header_and_hashes_cover_every_section() {
    let db = full_db(5);
    let bin = encode(&db);
    let sig = sign_bundle(&SEED, &bin);
    assert!(verify_bundle(&bin, &sig, &keys()).is_ok());
    assert_eq!(content_digest(&load_verified_bytes(&bin, &sig, &keys()).unwrap()), content_digest(&db));
    let hl = binary::signed_region(&bin).unwrap().len();
    // every single header byte is protected
    for i in 0..hl {
        let mut b = bin.clone();
        b[i] ^= 0x01;
        assert!(load_verified_bytes(&b, &sig, &keys()).is_err(), "header byte {i} flip was accepted");
        assert!(verify_bundle(&b, &sig, &keys()).is_err());
    }
    // every sampled section byte is protected by its section hash
    let step = ((bin.len() - hl) / 400).max(1);
    for i in (hl..bin.len()).step_by(step) {
        let mut b = bin.clone();
        b[i] ^= 0x80;
        assert!(load_verified_bytes(&b, &sig, &keys()).is_err(), "section byte {i} flip was accepted");
        assert!(verify_bundle(&b, &sig, &keys()).is_err());
    }
    // truncation anywhere, and appended data
    for len in (0..bin.len()).step_by(7) {
        assert!(load_verified_bytes(&bin[..len], &sig, &keys()).is_err(), "truncated to {len}");
    }
    let mut longer = bin.clone();
    longer.push(0);
    assert!(load_verified_bytes(&longer, &sig, &keys()).is_err(), "trailing byte");
    // wrong / revoked key
    let mut other = TrustedKeys::new();
    other.add_hex(&hex_encode(ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key().as_bytes())).unwrap();
    assert!(matches!(verify_bundle(&bin, &sig, &other), Err(Error::UnknownKey(_))));
    let mut rev = keys();
    rev.revoke(sig.split(' ').next().unwrap());
    assert!(matches!(verify_bundle(&bin, &sig, &rev), Err(Error::KeyRevoked(_))));
}

#[test]
fn store_installs_binary_streams_it_back_and_enforces_rollback_and_tamper_rules() {
    let dir = tmp("store");
    let s = Store::open(&dir).unwrap();
    let b5 = encode(&full_db(5));
    assert_eq!(s.install(&b5, &sign_bundle(&SEED, &b5), &keys()).unwrap(), Install::Installed { serial: 5 });
    assert_eq!(content_digest(&s.load_active(&keys()).unwrap().unwrap()), content_digest(&full_db(5)));
    assert_eq!(s.install(&b5, &sign_bundle(&SEED, &b5), &keys()).unwrap(), Install::AlreadyCurrent);
    let b4 = encode(&full_db(4));
    assert!(matches!(s.install(&b4, &sign_bundle(&SEED, &b4), &keys()), Err(Error::Rollback { current: 5, offered: 4 })));
    let other5 = encode(&Database::parse(full_text(5).replace("Fam.A", "Fam.Z").as_bytes()).unwrap());
    assert!(matches!(s.install(&other5, &sign_bundle(&SEED, &other5), &keys()), Err(Error::SerialReuse(5))));
    // text and binary of the same serial are different bytes: rejected as reuse, not silently swapped
    let t5 = full_text(5).into_bytes();
    assert!(matches!(s.install(&t5, &sign_bundle(&SEED, &t5), &keys()), Err(Error::SerialReuse(5))));
    // upgrade path: a higher serial may switch format
    let t6 = full_text(6).into_bytes();
    assert_eq!(s.install(&t6, &sign_bundle(&SEED, &t6), &keys()).unwrap(), Install::Installed { serial: 6 });
    assert_eq!(s.load_active(&keys()).unwrap().unwrap().serial, 6);
    let b7 = encode(&full_db(7));
    assert_eq!(s.install(&b7, &sign_bundle(&SEED, &b7), &keys()).unwrap(), Install::Installed { serial: 7 });
    // on-disk tamper of a section byte is detected by the streaming loader
    let p = dir.join("active.bundle");
    let mut raw = std::fs::read(&p).unwrap();
    let n = raw.len();
    raw[n - 5] ^= 0xFF;
    std::fs::write(&p, raw).unwrap();
    assert!(s.load_active(&keys()).is_err());
}

#[test]
fn install_file_streams_from_disk_for_binary_and_text() {
    let dir = tmp("install_file");
    std::fs::create_dir_all(&dir).unwrap();
    let s = Store::open(dir.join("store")).unwrap();
    let b = encode(&full_db(3));
    let f = dir.join("db.bin");
    std::fs::write(&f, &b).unwrap();
    let sig = sign_bundle(&SEED, &b);
    assert_eq!(s.install_file(&f, &sig, &keys()).unwrap(), Install::Installed { serial: 3 });
    assert_eq!(s.install_file(&f, &sig, &keys()).unwrap(), Install::AlreadyCurrent);
    assert_eq!(content_digest(&s.load_active(&keys()).unwrap().unwrap()), content_digest(&full_db(3)));
    let t = full_text(4).into_bytes();
    let tf = dir.join("db.txt");
    std::fs::write(&tf, &t).unwrap();
    assert_eq!(s.install_file(&tf, &sign_bundle(&SEED, &t), &keys()).unwrap(), Install::Installed { serial: 4 });
    assert!(s.install_file(&dir.join("missing"), &sig, &keys()).is_err());
}

// ---------------------------------------------------------------- signed but malformed

/// Build a container from (possibly corrupted) sections with CORRECT hashes and a VALID signature.
fn forged(mutate: impl FnOnce(&mut Vec<(u32, Vec<u8>)>)) -> Result<Database, Error> {
    let db = full_db(5);
    let mut secs = sections_of(&db);
    mutate(&mut secs);
    let bin = assemble(5, 1_700_000_000, 2, db.rule_count() as u64, &secs);
    let sig = sign_bundle(&SEED, &bin);
    let r = load_verified_bytes(&bin, &sig, &keys());
    if std::env::var("LITRIC_TEST_VERBOSE").is_ok() {
        eprintln!("FORGED => {}", match &r { Ok(_) => "ACCEPTED".to_string(), Err(e) => e.to_string() });
    }
    r
}
fn sec(secs: &mut Vec<(u32, Vec<u8>)>, ty: u32) -> &mut Vec<u8> {
    &mut secs.iter_mut().find(|s| s.0 == ty).unwrap_or_else(|| panic!("no section {ty:#x}")).1
}

#[test]
fn control_forgery_without_changes_loads() {
    assert!(forged(|_| {}).is_ok());
}

#[test]
fn signed_files_with_malformed_tables_are_rejected() {
    // md5 file table = 0x100: [count u64][keys 16*n][sizes 4*n][meta 12*n]; here n = 2 (same hash, sizes 3 and 4)
    assert!(forged(|s| { let t = sec(s, 0x100); let n = 2; let ks = 8; let ss = ks + 16 * n; t.swap(ss, ss + 4); t.swap(ss + 1, ss + 5); t.swap(ss + 2, ss + 6); t.swap(ss + 3, ss + 7); }).is_err(), "unsorted sizes");
    assert!(forged(|s| { let t = sec(s, 0x100); let ss = 8 + 16 * 2; let (a, b) = (t[ss..ss + 4].to_vec(), ss + 4); t[b..b + 4].copy_from_slice(&a); }).is_err(), "duplicate (hash,size)");
    assert!(forged(|s| { sec(s, 0x100).pop(); }).is_err(), "length not matching count");
    assert!(forged(|s| { sec(s, 0x100).push(0); }).is_err(), "extra byte");
    assert!(forged(|s| { sec(s, 0x100)[..8].copy_from_slice(&u64::MAX.to_le_bytes()); }).is_err(), "huge count");
    assert!(forged(|s| { sec(s, 0x100)[..8].copy_from_slice(&3u64.to_le_bytes()); }).is_err(), "count/length mismatch");
    // meta of first entry starts at 8 + 16*2 + 4*2 = 48
    assert!(forged(|s| { sec(s, 0x100)[48..52].copy_from_slice(&999u32.to_le_bytes()); }).is_err(), "family index out of range");
    assert!(forged(|s| { sec(s, 0x100)[52..56].copy_from_slice(&u32::MAX.to_le_bytes()); }).is_err(), "id offset outside arena");
    assert!(forged(|s| { sec(s, 0x100)[56] = 0; }).is_err(), "empty id");
    assert!(forged(|s| { sec(s, 0x100)[56] = 200; }).is_err(), "id longer than 64");
    assert!(forged(|s| { sec(s, 0x100)[57] = 9; }).is_err(), "bad severity");
    assert!(forged(|s| { sec(s, 0x100)[58] = 101; }).is_err(), "bad confidence");
    assert!(forged(|s| { sec(s, 0x100)[59] = 1; }).is_err(), "padding byte must be zero");
}

#[test]
fn signed_files_with_malformed_support_sections_are_rejected() {
    assert!(forged(|s| { sec(s, 3)[0] = b' '; }).is_err(), "arena with a space");
    assert!(forged(|s| { sec(s, 3).extend_from_slice(&[0xff, 0xfe]); }).is_err(), "arena not ASCII ids");
    assert!(forged(|s| { sec(s, 2)[..4].copy_from_slice(&u32::MAX.to_le_bytes()); }).is_err(), "huge family count");
    assert!(forged(|s| { sec(s, 2).truncate(6); }).is_err(), "family table truncated");
    assert!(forged(|s| { sec(s, 2)[4] = 0; }).is_err(), "empty family name");
    assert!(forged(|s| { sec(s, 4).extend_from_slice(b"\nX bogus record"); }).is_err(), "unknown legacy record");
    assert!(forged(|s| { sec(s, 4).extend_from_slice(b"\nHX r Fam high 90 md5 00 1"); }).is_err(), "table record smuggled into legacy section");
    assert!(forged(|s| { sec(s, 1).extend_from_slice(b"\n"); }).is_err(), "empty source line");
    assert!(forged(|s| { sec(s, 1).push(7); }).is_err(), "control char in source");
    let mut dup = false;
    assert!(forged(|s| { let x = s[0].clone(); s.push(x); dup = true; }).is_err() && dup, "duplicate section type");
    assert!(forged(|s| s.push((0x999, vec![1, 2, 3]))).is_err(), "unknown section type");
}

#[test]
fn signed_files_with_malformed_extended_signatures_are_rejected() {
    // NDB record header: meta(12) target(1) tag(1) value(8) aux(4) maxshift(4) code_len(4) code...; first record at offset 8
    let rec0 = 8usize;
    assert!(forged(|s| { sec(s, 0x200)[rec0 + 12] = 9; }).is_err(), "bad target");
    assert!(forged(|s| { sec(s, 0x200)[rec0 + 13] = 9; }).is_err(), "bad offset tag");
    assert!(forged(|s| { sec(s, 0x200)[rec0 + 12] = 0; }).is_err(), "EP offset requires pe target");
    assert!(forged(|s| { sec(s, 0x200)[rec0 + 26..rec0 + 30].copy_from_slice(&u32::MAX.to_le_bytes()); }).is_err(), "maxshift out of range");
    assert!(forged(|s| { sec(s, 0x200)[rec0 + 34] = 0x09; }).is_err(), "unknown opcode in bytecode");
    assert!(forged(|s| { sec(s, 0x200)[rec0 + 30..rec0 + 34].copy_from_slice(&u32::MAX.to_le_bytes()); }).is_err(), "bytecode length past the end");
    assert!(forged(|s| { sec(s, 0x200)[rec0 + 30..rec0 + 34].copy_from_slice(&1u32.to_le_bytes()); }).is_err(), "bytecode truncated");
    assert!(forged(|s| { sec(s, 0x200).push(0); }).is_err(), "trailing byte");
    assert!(forged(|s| { sec(s, 0x200)[..8].copy_from_slice(&u64::MAX.to_le_bytes()); }).is_err(), "huge count");
    assert!(forged(|s| { sec(s, 0x200)[..8].copy_from_slice(&7u64.to_le_bytes()); }).is_err(), "count larger than records");
    assert!(forged(|s| { sec(s, 0x200).truncate(20); }).is_err(), "truncated record");
}

fn resign(mut bin: Vec<u8>) -> Result<Database, Error> {
    let sig = sign_bundle(&SEED, &bin);
    let r = load_verified_bytes(&bin, &sig, &keys());
    if std::env::var("LITRIC_TEST_VERBOSE").is_ok() {
        eprintln!("HEADER => {}", match &r { Ok(_) => "ACCEPTED".to_string(), Err(e) => e.to_string() });
    }
    bin.clear();
    r
}

#[test]
fn signed_files_with_malformed_headers_are_rejected() {
    let good = encode(&full_db(5));
    assert!(resign(good.clone()).is_ok());
    let set32 = |b: &mut Vec<u8>, o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let set64 = |b: &mut Vec<u8>, o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    let mut b = good.clone(); set32(&mut b, 12, 2); assert!(resign(b).is_err(), "unknown format version");
    let mut b = good.clone(); set32(&mut b, 8, 49); assert!(resign(b).is_err(), "header length lies");
    let mut b = good.clone(); set32(&mut b, 36, 9999); assert!(resign(b).is_err(), "too many sections");
    let mut b = good.clone(); set32(&mut b, 36, 1); assert!(resign(b).is_err(), "section count inconsistent with header length");
    let mut b = good.clone(); set32(&mut b, 32, 99); assert!(matches!(resign(b), Err(Error::EngineTooOld { need: 99 })));
    let mut b = good.clone(); set64(&mut b, 40, 12345); assert!(resign(b).is_err(), "rule count mismatch");
    let mut b = good.clone(); set64(&mut b, 40, u64::MAX); assert!(resign(b).is_err(), "rule count over limit");
    let mut b = good.clone(); set32(&mut b, 52, 1); assert!(resign(b).is_err(), "reserved field");
    let mut b = good.clone(); set64(&mut b, 56, 7); assert!(resign(b).is_err(), "first section offset not contiguous");
    let mut b = good.clone(); set64(&mut b, 64, u64::MAX); assert!(resign(b).is_err(), "section length overflow");
    let mut b = good.clone(); b.extend_from_slice(&[1, 2, 3]); assert!(resign(b).is_err(), "trailing data");
    let mut b = good.clone(); b.truncate(good.len() - 1); assert!(resign(b).is_err(), "truncated");
    let mut b = good.clone(); b.truncate(30); assert!(resign(b).is_err(), "header cut");
}

#[test]
fn structural_mutation_fuzz_never_panics() {
    let db = full_db(5);
    let base = sections_of(&db);
    let rc = db.rule_count() as u64;
    let mut x: u64 = 0xC0FFEE_D15EA5E;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let (mut ok, mut err) = (0u32, 0u32);
    for _ in 0..15_000 {
        let mut secs = base.clone();
        for _ in 0..(1 + rnd() % 4) {
            let i = (rnd() as usize) % secs.len();
            let data = &mut secs[i].1;
            match rnd() % 5 {
                0 if !data.is_empty() => { let at = (rnd() as usize) % data.len(); data[at] = rnd() as u8; }
                1 if !data.is_empty() => { let at = (rnd() as usize) % data.len(); data[at] ^= 1 << (rnd() % 8); }
                2 => { let n = if data.is_empty() { 0 } else { (rnd() as usize) % data.len() }; data.truncate(n); }
                3 => { for _ in 0..(1 + rnd() % 8) { data.push(rnd() as u8); } }
                _ if data.len() >= 8 => { let at = (rnd() as usize) % (data.len() - 7); data[at..at + 8].copy_from_slice(&rnd().to_le_bytes()); }
                _ => {}
            }
        }
        let bin = assemble(5, 1, 2, rc, &secs);
        match binary::load_bytes(&bin, None) { Ok(_) => ok += 1, Err(_) => err += 1 }
    }
    assert!(err > 10_000, "most mutations must be rejected: ok={ok} err={err}");
    // whole-file mutation
    let bin = encode(&db);
    for _ in 0..10_000 {
        let mut b = bin.clone();
        for _ in 0..(1 + rnd() % 3) { let at = (rnd() as usize) % b.len(); b[at] = rnd() as u8; }
        let _ = binary::load_bytes(&b, None);
    }
}

#[test]
fn binary_is_smaller_than_text_and_loads_identically_at_scale() {
    let n = 100_000usize;
    let mut x: u64 = 0x1234_5678_9ABC_DEF1;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let mut text = format!("LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count {n}\n");
    for i in 0..n {
        text.push_str(&format!("HX clam.h.{i} Win.Trojan.Fam{} high 90 md5 {:016x}{:016x} {}\n", rnd() % 500, rnd(), rnd(), i % 5000));
    }
    text.push_str("END\n");
    let db = Database::parse(text.as_bytes()).unwrap();
    let bin = encode(&db);
    assert!((bin.len() as f64) < text.len() as f64 * 0.7, "binary {} vs text {}", bin.len(), text.len());
    let back = binary::load_bytes(&bin, None).unwrap();
    assert_eq!(content_digest(&db), content_digest(&back));
    assert_eq!(back.rule_count(), n);
}

#[test]
fn signed_file_with_an_unlocatable_extended_signature_is_rejected() {
    use sigdb::ndb::{compile, parse_sig};
    let code = compile(&parse_sig("aa??bb{2}ccddeeff").unwrap().toks); // no >=2-byte anchor in the fixed prefix
    let make = |tag: u8, val: u64| {
        let code = code.clone();
        move |s: &mut Vec<(u32, Vec<u8>)>| {
            let meta: Vec<u8> = sec(s, 0x200)[8..20].to_vec();
            let mut o = 1u64.to_le_bytes().to_vec();
            o.extend_from_slice(&meta);
            o.push(0); // target any
            o.push(tag);
            o.extend_from_slice(&val.to_le_bytes());
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&(code.len() as u32).to_le_bytes());
            o.extend_from_slice(&code);
            *sec(s, 0x200) = o;
        }
    };
    // rule_count in the header will not match (1 instead of 6), so check the specific reason separately via the decoder
    let db = full_db(5);
    let mut secs = sections_of(&db);
    make(0, 0)(&mut secs);
    let bin = assemble(5, 1, 2, db.rule_count() as u64 - 5, &secs);
    let msg = binary::load_bytes(&bin, None).err().expect("must be rejected").to_string();
    assert!(msg.contains("cannot be located"), "{msg}");
    // same bytecode at an exact offset is acceptable
    let mut secs = sections_of(&db);
    make(1, 0)(&mut secs);
    let bin = assemble(5, 1, 2, db.rule_count() as u64 - 5, &secs);
    assert!(binary::load_bytes(&bin, None).is_ok());
}

#[test]
fn signed_files_with_malformed_logical_signatures_are_rejected() {
    // LDB record: meta(12) target(1) flags(1) [ranges 16 each] expr_len(2) expr nsub(1) subs{tag(1) val(8) aux(4) maxshift(4) code_len(4) code}
    // first record (l.1): flags = 3 -> two ranges (32 bytes) -> expr_len at 8+12+1+1+32 = 54
    let at = 8usize;
    let flags = at + 13;
    let el = at + 14 + 32;
    assert!(forged(|s| { sec(s, 0x201)[at + 12] = 9; }).is_err(), "bad target");
    assert!(forged(|s| { sec(s, 0x201)[flags] = 0b100; }).is_err(), "unknown constraint flag");
    assert!(forged(|s| { let r = sec(s, 0x201); r[at + 14..at + 22].copy_from_slice(&u64::MAX.to_le_bytes()); }).is_err(), "constraint min above max");
    assert!(forged(|s| { sec(s, 0x201)[el..el + 2].copy_from_slice(&0u16.to_le_bytes()); }).is_err(), "empty expression");
    assert!(forged(|s| { sec(s, 0x201)[el..el + 2].copy_from_slice(&600u16.to_le_bytes()); }).is_err(), "expression too long");
    assert!(forged(|s| { sec(s, 0x201)[el + 2] = b'x'; }).is_err(), "invalid expression character");
    assert!(forged(|s| { sec(s, 0x201)[el + 2] = b'&'; }).is_err(), "syntactically broken expression");
    let nsub_at = el + 2 + "(0&1)|2".len();
    assert!(forged(|s| { sec(s, 0x201)[nsub_at] = 0; }).is_err(), "zero subsignatures");
    assert!(forged(|s| { sec(s, 0x201)[nsub_at] = 2; }).is_err(), "expression refers past the subsignatures");
    assert!(forged(|s| { sec(s, 0x201)[nsub_at] = 200; }).is_err(), "too many subsignatures");
    assert!(forged(|s| { sec(s, 0x201)[nsub_at + 1] = 9; }).is_err(), "invalid offset tag");
    assert!(forged(|s| { sec(s, 0x201).push(0); }).is_err(), "trailing byte");
    assert!(forged(|s| { sec(s, 0x201).truncate(30); }).is_err(), "truncated record");
    assert!(forged(|s| { sec(s, 0x201)[..8].copy_from_slice(&u64::MAX.to_le_bytes()); }).is_err(), "huge count");
    assert!(forged(|s| { sec(s, 0x201)[..8].copy_from_slice(&9u64.to_le_bytes()); }).is_err(), "count larger than records");
    // first subsignature bytecode starts after: tag(1) val(8) aux(4) maxshift(4) code_len(4)
    let code0 = nsub_at + 1 + 21;
    assert!(forged(|s| { sec(s, 0x201)[code0] = 0x09; }).is_err(), "unknown opcode in subsignature bytecode");
}
