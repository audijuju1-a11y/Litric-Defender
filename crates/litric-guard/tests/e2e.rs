use honeyvault::Tamper;
use realtime::{Containment, RawEvent, RawKind};
use service::{now_ms, Defender, ServiceConfig};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Fake(Arc<Mutex<Vec<u32>>>);
impl Containment for Fake {
    fn suspend(&mut self, pid: u32) -> Result<(), String> { self.0.lock().unwrap().push(pid); Ok(()) }
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("litric_{}_{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn setup(name: &str, n: usize) -> (Defender, PathBuf, PathBuf, Arc<Mutex<Vec<u32>>>, Vec<(PathBuf, Vec<u8>)>) {
    let docs = tmp(&format!("{name}_docs"));
    let vault = tmp(&format!("{name}_vault"));
    let mut originals = vec![];
    for i in 0..n {
        let p = docs.join(format!("doc{i}.txt"));
        let data = format!("File {i} quarterly notes: revenue grew and costs fell. ").repeat(60).into_bytes();
        std::fs::write(&p, &data).unwrap();
        originals.push((p, data));
    }
    let susp = Arc::new(Mutex::new(vec![]));
    let d = Defender::start(
        ServiceConfig { protected_dirs: vec![docs.clone()], vault_dir: vault.clone(), trusted_images: vec![], queue_cap: 10_000 },
        Box::new(Fake(susp.clone())),
    ).unwrap();
    assert!(d.pipeline.wait_idle(Duration::from_secs(5)));
    (d, docs, vault, susp, originals)
}

fn ev(pid: u32, path: &std::path::Path, kind: RawKind) -> RawEvent {
    RawEvent { pid, image: "c:\\temp\\evil.exe".into(), path: path.to_string_lossy().to_string(), kind, t_ms: now_ms() }
}

#[test]
fn ransomware_is_suspended_and_files_are_recovered_from_vault() {
    let (d, docs, _vault, susp, originals) = setup("e2e", 30);
    let before_attack = now_ms();
    std::thread::sleep(Duration::from_millis(5));

    // Phase 1: "encrypt" in place (pseudo-random bytes), feed Modified events.
    let mut x: u64 = 0x9E3779B97F4A7C15;
    for (p, data) in &originals {
        let junk: Vec<u8> = (0..data.len()).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 }).collect();
        std::fs::write(p, junk).unwrap();
        d.feed(ev(777, p, RawKind::Modified));
    }
    assert!(d.pipeline.wait_idle(Duration::from_secs(5)));
    // Phase 2: rename to .locked
    for (p, _) in &originals {
        let new = p.with_extension("locked");
        std::fs::rename(p, &new).unwrap();
        d.feed(ev(777, &new, RawKind::Renamed { new_ext: "locked".into() }));
    }
    assert!(d.pipeline.wait_idle(Duration::from_secs(5)));

    let status = d.status();
    assert!(!status.degraded, "{status:?}");
    assert_eq!(*susp.lock().unwrap(), vec![777], "attacker must be suspended exactly once");

    // Recovery: every original comes back byte-for-byte.
    let out = tmp("e2e_restore");
    for (p, data) in &originals {
        d.vault.restore(p, before_attack, &out.join(p.file_name().unwrap())).unwrap();
        assert_eq!(&std::fs::read(out.join(p.file_name().unwrap())).unwrap(), data);
    }
    assert!(d.vault.verify().is_empty());
    let incidents = d.stop();
    assert!(incidents.iter().any(|i| i.contained));
    let _ = docs;
}

#[test]
fn decoy_touch_is_reported_and_decoy_plus_backup_tamper_contains() {
    let (d, docs, _v, susp, _o) = setup("decoy", 3);
    let decoy = docs.join("_Budget_Summary.xlsx");
    std::fs::write(&decoy, b"overwritten").unwrap();
    d.feed(ev(9, &decoy, RawKind::Modified));
    assert!(d.pipeline.wait_idle(Duration::from_secs(5)));
    assert!(susp.lock().unwrap().is_empty(), "a decoy touch alone must not contain");
    let st = d.status();
    assert!(st.degraded);
    assert!(st.decoy_tamper.iter().any(|t| matches!(t, Tamper::Modified(p) if p == &decoy)));

    d.feed(RawEvent { pid: 9, image: "c:\\temp\\evil.exe".into(), path: String::new(), kind: RawKind::BackupTamper, t_ms: now_ms() });
    assert!(d.pipeline.wait_idle(Duration::from_secs(5)));
    assert_eq!(*susp.lock().unwrap(), vec![9]);
    d.stop();
}

#[test]
fn corrupted_vault_object_is_never_restored() {
    let (d, _docs, vault, _s, originals) = setup("corrupt", 2);
    let (p, _) = &originals[0];
    let v = d.vault.versions(p).pop().unwrap();
    let obj = vault.join("objects").join(&v.hash[..2]).join(&v.hash);
    std::fs::write(&obj, b"tampered").unwrap();
    assert_eq!(d.vault.verify(), vec![v.hash.clone()]);
    assert!(d.vault.restore(p, now_ms(), &tmp("corrupt_out").join("x")).is_err());
    d.stop();
}

#[test]
fn periodic_snapshot_versions_new_files_skips_unchanged_and_freezes_on_incident() {
    use service::{Tick, FREEZE_MS};
    let (d, docs, _v, _s, originals) = setup("tick", 20);
    std::thread::sleep(Duration::from_millis(1100));

    // A new file appears after start: next tick must version it.
    let newf = docs.join("new_report.txt");
    std::fs::write(&newf, "created after service start").unwrap();
    let t1 = now_ms();
    match d.tick(t1).unwrap() {
        Tick::Done(r) => {
            assert_eq!(r.stored, 1, "only the new file is stored: {r:?}");
            assert!(r.unchanged >= 20, "unchanged files must be skipped: {r:?}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(d.vault.versions(&newf).len(), 1);

    // Attack -> incident -> snapshots freeze, vault keeps only good versions.
    let mut x: u64 = 0x1234_5678_9ABC_DEF1;
    for (p, data) in &originals {
        let junk: Vec<u8> = (0..data.len()).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 }).collect();
        std::fs::write(p, junk).unwrap();
        d.feed(ev(55, p, RawKind::Modified));
    }
    assert!(d.pipeline.wait_idle(Duration::from_secs(5)));
    for (p, _) in &originals {
        let new = p.with_extension("locked");
        std::fs::rename(p, &new).unwrap();
        d.feed(ev(55, &new, RawKind::Renamed { new_ext: "locked".into() }));
    }
    assert!(d.pipeline.wait_idle(Duration::from_secs(5)));
    let t2 = now_ms() + 5;
    assert!(matches!(d.tick(t2).unwrap(), Tick::Frozen { .. }));
    for (p, _) in &originals {
        assert_eq!(d.vault.versions(p).len(), 1, "no encrypted version may enter the vault");
    }
    // After the freeze window the service resumes.
    assert!(matches!(d.tick(t2 + FREEZE_MS + 1).unwrap(), Tick::Done(_)));
    d.stop();
}
