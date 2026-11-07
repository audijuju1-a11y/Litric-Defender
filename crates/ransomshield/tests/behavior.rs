use ransomshield::*;

fn ev(pid: u32, image: &str, path: String, op: FileOp, t: u64) -> FileEvent {
    FileEvent { pid, image: image.into(), path, op, t_ms: t }
}

#[test]
fn entropy_bounds() {
    assert_eq!(shannon_entropy(&[]), 0.0);
    assert_eq!(shannon_entropy(&[7u8; 1000]), 0.0);
    let all: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
}

#[test]
fn ransomware_like_behavior_is_contained() {
    let mut e = Engine::new(Config::default());
    let mut last = None;
    for i in 0..40u64 {
        let p = format!("C:\\Users\\a\\Docs\\f{i}.docx");
        e.on_file_event(ev(9, "c:\\temp\\x.exe", p.clone(),
            FileOp::Write { entropy_before: Some(4.2), entropy_after: 7.95 }, i * 50));
        last = Some(e.on_file_event(ev(9, "c:\\temp\\x.exe", p,
            FileOp::Rename { new_ext: "locked".into() }, i * 50 + 10)));
    }
    let a = last.unwrap();
    assert_eq!(a.verdict, Verdict::Contain, "{:?}", a);
    assert!(a.evidence.len() >= 3);
}

#[test]
fn archiver_high_entropy_new_files_not_contained() {
    // Many files, high entropy output, but NEW files (no entropy jump of
    // existing data, no ransomware extensions, no canaries).
    let mut e = Engine::new(Config::default());
    let mut last = None;
    for i in 0..60u64 {
        last = Some(e.on_file_event(ev(5, "c:\\tools\\zip.exe", format!("D:\\out\\a{i}.zip"),
            FileOp::Write { entropy_before: None, entropy_after: 7.99 }, i * 20)));
    }
    assert!(last.unwrap().verdict < Verdict::Contain);
}

#[test]
fn canary_plus_backup_tamper_contains() {
    let mut e = Engine::new(Config::default());
    e.add_canary("C:\\Users\\a\\Documents\\_vault_decoy.docx");
    let a1 = e.on_file_event(ev(7, "c:\\x\\m.exe", "c:/users/a/documents/_vault_decoy.docx".into(),
        FileOp::Write { entropy_before: Some(3.0), entropy_after: 7.9 }, 0));
    assert!(a1.verdict < Verdict::Contain);
    let a2 = e.on_backup_tamper(BackupTamperEvent { pid: 7, image: "c:\\x\\m.exe".into(), t_ms: 100 });
    assert_eq!(a2.verdict, Verdict::Contain, "{:?}", a2);
}

#[test]
fn trusted_process_is_not_contained_but_keeps_evidence() {
    let mut cfg = Config::default();
    cfg.trusted_images.insert("c:\\backup\\bk.exe".into());
    let mut e = Engine::new(cfg);
    e.add_canary("c:\\d\\decoy.txt");
    e.on_backup_tamper(BackupTamperEvent { pid: 3, image: "C:\\Backup\\bk.exe".into(), t_ms: 0 });
    let a = e.on_file_event(ev(3, "C:\\Backup\\bk.exe", "c:\\d\\decoy.txt".into(),
        FileOp::Write { entropy_before: None, entropy_after: 5.0 }, 10));
    assert_eq!(a.verdict, Verdict::Observe);
    assert!(a.evidence.iter().any(|l| l.contains("trusted")));
}

#[test]
fn window_expires_old_events() {
    let mut e = Engine::new(Config::default());
    for i in 0..30u64 {
        e.on_file_event(ev(1, "c:\\a.exe", format!("c:\\f{i}"), FileOp::Delete, i));
    }
    let a = e.on_file_event(ev(1, "c:\\a.exe", "c:\\late".into(), FileOp::Delete, 60_000));
    assert_eq!(a.verdict, Verdict::Allow);
}
