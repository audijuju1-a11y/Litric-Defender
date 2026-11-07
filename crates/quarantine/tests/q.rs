use quarantine::*;
use std::path::PathBuf;

fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("litric_q_{n}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn info() -> Info { Info { family: "Test.Fam".into(), rule_id: "r1".into(), severity: "high".into() } }

#[test]
fn copy_only_keeps_original_and_restore_is_exact_and_never_overwrites() {
    let d = tmp("copy");
    let f = d.join("sample.bin");
    std::fs::write(&f, b"pretend-malware-bytes").unwrap();
    let q = Quarantine::open(d.join("q")).unwrap();
    let id = q.add(&f, &info(), Mode::CopyOnly, 100).unwrap();
    assert!(f.exists(), "copy-only must not delete the original");
    // stored bytes are neutralized, not the plain content
    let blob = std::fs::read_dir(d.join("q/data")).unwrap().next().unwrap().unwrap().path();
    assert_ne!(std::fs::read(blob).unwrap(), b"pretend-malware-bytes");
    let out = d.join("restored.bin");
    q.restore(&id, &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"pretend-malware-bytes");
    assert!(q.restore(&id, &out).is_err(), "must not overwrite an existing file");
    assert!(q.restore_original(&id).is_err(), "original still exists");
    let m = q.get(&id).unwrap();
    assert_eq!((m.family.as_str(), m.size), ("Test.Fam", 21));
}

#[test]
fn move_removes_original_only_after_verification_then_restores_to_original_path() {
    let d = tmp("move");
    let f = d.join("evil.exe");
    std::fs::write(&f, b"AAAA").unwrap();
    let q = Quarantine::open(d.join("q")).unwrap();
    let id = q.add(&f, &info(), Mode::MoveAfterVerify, 1).unwrap();
    assert!(!f.exists());
    q.restore_original(&id).unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"AAAA");
}

#[test]
fn duplicates_share_one_blob_and_purge_needs_authorization_and_keeps_shared_data() {
    let d = tmp("dup");
    let (a, b) = (d.join("a.bin"), d.join("b.bin"));
    std::fs::write(&a, b"same").unwrap();
    std::fs::write(&b, b"same").unwrap();
    let q = Quarantine::open(d.join("q")).unwrap();
    let (i1, i2) = (q.add(&a, &info(), Mode::CopyOnly, 1).unwrap(), q.add(&b, &info(), Mode::CopyOnly, 2).unwrap());
    assert_ne!(i1, i2);
    assert_eq!(std::fs::read_dir(d.join("q/data")).unwrap().count(), 1);
    q.purge(&i1, Authorization::UserConfirmed).unwrap();
    assert_eq!(q.list().len(), 1);
    q.restore(&i2, &d.join("r.bin")).unwrap(); // blob survived
    q.purge(&i2, Authorization::UserConfirmed).unwrap();
    assert_eq!(std::fs::read_dir(d.join("q/data")).unwrap().count(), 0);
}

#[test]
fn corrupted_blob_is_detected_and_never_restored() {
    let d = tmp("corrupt");
    let f = d.join("x.bin");
    std::fs::write(&f, b"payload").unwrap();
    let q = Quarantine::open(d.join("q")).unwrap();
    let id = q.add(&f, &info(), Mode::CopyOnly, 1).unwrap();
    let blob = std::fs::read_dir(d.join("q/data")).unwrap().next().unwrap().unwrap().path();
    std::fs::write(blob, b"zzz").unwrap();
    assert_eq!(q.verify_all(), vec![id.clone()]);
    assert!(q.restore(&id, &d.join("o.bin")).is_err());
}

#[test]
fn path_traversal_ids_are_rejected() {
    let d = tmp("trav");
    let q = Quarantine::open(d.join("q")).unwrap();
    assert!(q.get("../../etc/passwd").is_err());
    assert!(q.restore("..", &d.join("o")).is_err());
}

#[test]
fn audit_log_detects_edits_and_deletions() {
    let d = tmp("audit");
    let f = d.join("x.bin");
    std::fs::write(&f, b"p").unwrap();
    let q = Quarantine::open(d.join("q")).unwrap();
    let id = q.add(&f, &info(), Mode::CopyOnly, 1).unwrap();
    q.restore(&id, &d.join("o.bin")).unwrap();
    assert_eq!(q.verify_audit(), Ok(2));
    let p = d.join("q/audit.log");
    let t = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, t.replace(" restore ", " add ")).unwrap();
    assert!(q.verify_audit().is_err(), "edited line");
    let first: String = t.lines().next().unwrap().to_string() + "\n";
    std::fs::write(&p, t.replacen(&first, "", 1)).unwrap();
    assert!(q.verify_audit().is_err(), "deleted line");
}
