use realtime::{EntropySampler, FsSampler};
#[test]
fn fs_sampler_distinguishes_text_from_random_and_handles_missing() {
    let d = std::env::temp_dir().join(format!("litric_s_{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let t = d.join("a.txt");
    std::fs::write(&t, "hello world ".repeat(2000)).unwrap();
    let r = d.join("b.bin");
    // xorshift pseudo-random bytes, no extra deps
    let mut x: u64 = 0x2545F4914F6CDD1D;
    let bytes: Vec<u8> = (0..65536).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 }).collect();
    std::fs::write(&r, bytes).unwrap();
    let mut s = FsSampler;
    assert!(s.sample(t.to_str().unwrap()).unwrap() < 4.0);
    assert!(s.sample(r.to_str().unwrap()).unwrap() > 7.9);
    assert!(s.sample(d.join("nope").to_str().unwrap()).is_none());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn tamper_classifier_flags_destructive_and_ignores_benign() {
    use realtime::tamper::classify_command as c;
    assert!(c("C:\\Windows\\System32\\vssadmin.exe", "vssadmin  Delete   Shadows /all /quiet").is_some());
    assert!(c("wmic.exe", "wmic shadowcopy delete").is_some());
    assert!(c("bcdedit.exe", "bcdedit /set {default} recoveryenabled No").is_some());
    assert!(c("wbadmin.exe", "wbadmin delete catalog -quiet").is_some());
    assert!(c("vssadmin.exe", "vssadmin list shadows").is_none());
    assert!(c("bcdedit.exe", "bcdedit /enum").is_none());
    assert!(c("notepad.exe", "vssadmin delete shadows").is_none());
}
