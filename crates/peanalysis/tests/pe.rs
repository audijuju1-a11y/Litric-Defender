use peanalysis::builder::*;
use peanalysis::*;

fn packed() -> PeBuilder {
    let mut b = PeBuilder::benign(false);
    b.sections = vec![
        Sec { name: "UPX0".into(), data: vec![], vsize: 0x10000, chars: RWX },
        Sec::new("UPX1", pseudo_random(8192, 99), RWX),
    ];
    b.entry_section = 1;
    b.imports = vec![("KERNEL32.dll".into(), vec!["LoadLibraryA".into(), "GetProcAddress".into(), "ExitProcess".into()])];
    b
}
fn with_imports(extra: &[(&str, &[&str])]) -> PeBuilder {
    let mut b = PeBuilder::benign(false);
    b.imports = extra.iter().map(|(d, f)| (d.to_string(), f.iter().map(|s| s.to_string()).collect())).collect();
    b
}
fn codes(r: &Risk) -> Vec<&'static str> {
    r.reasons.iter().map(|x| x.code).collect()
}

#[test]
fn builder_output_parses_correctly_for_32_and_64_bit() {
    for is64 in [false, true] {
        let data = PeBuilder::benign(is64).build();
        let info = parse(&data).unwrap();
        assert_eq!(info.is_64, is64);
        assert!(!info.partial, "{:?}", info.anomalies);
        assert_eq!(info.entry_section.as_deref(), Some(".text"));
        let names: Vec<_> = info.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, [".text", ".rdata", ".data", ".idata"]);
        assert!(info.imports.contains(&("kernel32.dll".into(), "ExitProcess".into())));
        assert!(info.imports.contains(&("user32.dll".into(), "MessageBoxA".into())));
        assert_eq!(info.import_dlls, 2);
    }
}

#[test]
fn ordinary_program_scores_zero() {
    for is64 in [false, true] {
        let (_, r) = analyze(&PeBuilder::benign(is64).build()).unwrap();
        assert_eq!((r.score, r.level), (0, Level::None), "{:?}", codes(&r));
    }
}

#[test]
fn packer_style_binary_is_suspicious_with_explanations() {
    let (info, r) = analyze(&packed().build()).unwrap();
    assert!(r.level >= Level::Suspicious, "score {} {:?}", r.score, codes(&r));
    let c = codes(&r);
    for want in ["packer-section", "high-entropy-code", "empty-raw-large-virtual", "dynamic-imports-only", "section-wx"] {
        assert!(c.contains(&want), "missing {want}: {c:?}");
    }
    assert_eq!(info.entry_section.as_deref(), Some("UPX1"));
    assert!(r.reasons.iter().all(|x| !x.text.is_empty()));
}

#[test]
fn single_category_cannot_reach_suspicious_even_when_raw_score_is_high() {
    let mut b = with_imports(&[
        ("KERNEL32.dll", &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]),
        ("USER32.dll", &["SetWindowsHookExA", "GetAsyncKeyState"]),
    ]);
    b.sections[1].data = b"mimikatz".repeat(10);
    let (_, r) = analyze(&b.build()).unwrap();
    assert!(r.held_for_lack_of_corroboration, "{:?}", codes(&r));
    assert_eq!((r.score, r.level), (49, Level::Weak));
}

#[test]
fn corroboration_from_a_second_category_makes_it_suspicious() {
    let mut b = with_imports(&[
        ("KERNEL32.dll", &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]),
        ("USER32.dll", &["SetWindowsHookExA", "GetAsyncKeyState"]),
    ]);
    b.sections[1].data = b"mimikatz".repeat(10);
    b.sections[2].chars = RWX;
    let (_, r) = analyze(&b.build()).unwrap();
    assert!(r.level >= Level::Suspicious && !r.held_for_lack_of_corroboration, "{} {:?}", r.score, codes(&r));
}

#[test]
fn ransomware_like_combination_across_three_categories() {
    let mut b = with_imports(&[("KERNEL32.dll", &["FindFirstFileW", "FindNextFileW", "MoveFileExW"]), ("ADVAPI32.dll", &["CryptAcquireContextA"])]);
    b.sections[1].data = b"Your files have been encrypted. vssadmin delete shadows /all\0".repeat(4);
    b.sections.push(Sec::new(".text2", pseudo_random(8192, 5), CODE_RX));
    let (_, r) = analyze(&b.build()).unwrap();
    let c = codes(&r);
    assert!(r.level >= Level::Suspicious, "{} {c:?}", r.score);
    assert!(c.contains(&"file-encryption-combo") && c.contains(&"high-entropy-code"));
    assert_eq!(c.iter().filter(|x| **x == "string-indicator").count(), 2);
}

#[test]
fn signature_blob_is_reported_but_never_lowers_the_score() {
    let plain = packed().build();
    let mut b = packed();
    b.signature_blob = true;
    let signed = b.build();
    let (i1, r1) = analyze(&plain).unwrap();
    let (i2, r2) = analyze(&signed).unwrap();
    assert!(!i1.has_signature_blob && i2.has_signature_blob);
    assert_eq!(r1.score, r2.score);
}

#[test]
fn strings_match_utf16_and_ignore_case() {
    let mut b = PeBuilder::benign(false);
    let wide: Vec<u8> = "MiMiKaTz".bytes().flat_map(|c| [c, 0]).collect();
    b.sections[1].data = wide.repeat(5);
    let (_, r) = analyze(&b.build()).unwrap();
    assert!(r.reasons.iter().any(|x| x.text.contains("credential-theft")));
}

#[test]
fn non_pe_input_returns_none() {
    assert!(analyze(b"hello").is_none());
    assert!(analyze(b"MZ").is_none());
    let mut v = vec![0u8; 0x100];
    v[0] = b'M';
    v[1] = b'Z';
    v[0x3c] = 0xF0;
    assert!(analyze(&v).is_none(), "e_lfanew pointing at garbage");
}

#[test]
fn declared_section_count_and_import_counts_are_capped() {
    let mut data = PeBuilder::benign(false).build();
    data[0x46] = 0xFF;
    data[0x47] = 0xFF;
    let info = parse(&data).unwrap();
    assert!(info.partial && info.anomalies.iter().any(|a| a.contains("limit")), "{:?}", info.anomalies);
    assert!(info.sections.len() <= 96);

    let mut b = PeBuilder::benign(false);
    b.imports = vec![("big.dll".into(), (0..5000).map(|i| format!("f{i}")).collect())];
    let info = parse(&b.build()).unwrap();
    assert!(info.partial && info.imports.len() == 4096, "{}", info.imports.len());
}

#[test]
fn every_truncation_point_is_handled() {
    for base in [PeBuilder::benign(false).build(), PeBuilder::benign(true).build(), packed().build()] {
        for len in (0..base.len()).step_by(3) {
            let _ = analyze(&base[..len]);
        }
    }
}

#[test]
fn mutation_fuzz_never_panics_and_stays_fast() {
    let bases = [PeBuilder::benign(false).build(), PeBuilder::benign(true).build(), packed().build()];
    let mut x: u64 = 0xDEADBEEFCAFEF00D;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let start = std::time::Instant::now();
    let mut parsed = 0u32;
    for base in &bases {
        for _ in 0..2500 {
            let mut d = base.clone();
            match rnd() % 4 {
                0 => {
                    for _ in 0..(1 + rnd() % 8) {
                        let at = if rnd() % 10 < 7 { (rnd() % 0x400) as usize } else { (rnd() as usize) % d.len() };
                        let at = at.min(d.len() - 1);
                        d[at] = rnd() as u8;
                    }
                }
                1 => {
                    let at = ((rnd() % 0x3F0) as usize) & !3;
                    let v = rnd() as u32;
                    d[at..at + 4].copy_from_slice(&v.to_le_bytes());
                }
                2 => {
                    let at = ((rnd() % 0x3F0) as usize) & !3;
                    d[at..at + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
                }
                _ => {
                    let n = (rnd() as usize) % d.len();
                    d.truncate(n);
                }
            }
            if analyze(&d).is_some() {
                parsed += 1;
            }
        }
    }
    assert!(start.elapsed().as_secs() < 60, "too slow: {:?}", start.elapsed());
    assert!(parsed > 300, "mutations should still parse sometimes: {parsed}");
}
