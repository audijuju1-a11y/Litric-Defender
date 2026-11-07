//! End-to-end proof for scan-time quarantine.
//!
//! These tests execute the compiled `litric` binary against a real temporary
//! directory. A signed development database allowlists the clean fixture so the
//! scan produces all three categories: `Clean`, `Unknown`, and `Malicious`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use litric_core::hash::sha256_bytes;
use litric_core::winplatform::filemeta::{
    apply_file_times, capture_file_times, read_alternate_streams, write_alternate_streams,
    AlternateStream, FileTimes,
};
use litric_core::quarantine::QuarantineVault;
use litric_core::threatdb::{
    build_signed, dev_signing_key, DbPayload, EntryKind, HashEntry, ThreatDb,
    DB_FORMAT_VERSION,
};

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const CLEAN: &[u8] = b"clean fixture content\n";
const UNKNOWN: &[u8] = b"ordinary unknown fixture\n";

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn base(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "litric-scanq-{tag}-{}-{}",
        std::process::id(),
        nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn rules_dir(base: &Path) -> PathBuf {
    let dir = base.join("rules");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("eicar.lrs"),
        r#"
rule Eicar.Test {
    meta:
        description = "EICAR test file"
        severity = "critical"
        family = "EICAR-Test"
    strings:
        $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $s
}
"#,
    )
    .unwrap();
    dir
}

/// Builds a development-signed database that marks exactly `CLEAN` as trusted.
fn clean_db(base: &Path) -> PathBuf {
    let db = base.join("db");
    let payload = DbPayload {
        schema: DB_FORMAT_VERSION,
        db_version: 1,
        min_engine: litric_core::ENGINE_VERSION.to_string(),
        created_unix: 0,
        hashes: vec![HashEntry {
            sha256: sha256_bytes(CLEAN).to_hex(),
            name: "Fixture.Clean".into(),
            family: Some("Fixture".into()),
            severity: Some("trusted".into()),
            kind: EntryKind::Trusted,
            source: Some("scan quarantine e2e fixture".into()),
            license: Some("CC0".into()),
        }],
        ..Default::default()
    };
    let (payload_bytes, manifest_bytes) = build_signed(&payload, &dev_signing_key()).unwrap();
    ThreatDb::install(
        &db,
        &payload_bytes,
        &manifest_bytes,
        &[],
        true,
        litric_core::ENGINE_VERSION,
        false,
    )
    .unwrap();
    db
}

fn run_scan(
    target: &Path,
    rules: &Path,
    db: Option<&Path>,
    vault: &Path,
    key: &Path,
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_litric"));
    cmd.arg("--local").arg("scan").arg(target);
    cmd.arg("--rules").arg(rules);
    if let Some(db) = db {
        // Fixtures are signed with the public development key; the runtime only
        // accepts it when the operator opts in explicitly.
        cmd.env("LITRIC_ALLOW_DEV_DB", "1");
        cmd.arg("--db").arg(db);
    }
    cmd.arg("--quarantine-malicious")
        .arg("--vault-dir")
        .arg(vault)
        .arg("--vault-key")
        .arg(key)
        .arg("--json");
    cmd.output().expect("run litric")
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON: {e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn text(out: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Renders each byte of `text` as `0xNN -bxor 0xKK`, the constant-key form a
/// character-array dropper uses.
fn xor_codes(text: &str, key: u8) -> String {
    text.bytes()
        .map(|b| format!("0x{:02x} -bxor 0x{key:02x}", b ^ key))
        .collect::<Vec<_>>()
        .join(",")
}

fn zip_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        writer
            .start_file(
                *name,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn directory_scan_moves_only_malicious_and_is_safe_to_repeat() {
    let base = base("dir");
    let rules = rules_dir(&base);
    let db = clean_db(&base);
    let target = base.join("target");
    // Build nested components with `join` rather than embedding `/` in one
    // component: on Windows the latter produces a mixed `dir\sub/file` path and
    // breaks comparisons with the paths the scanner records.
    fs::create_dir_all(target.join("inbox").join("2026")).unwrap();
    fs::create_dir_all(target.join("docs").join("archive")).unwrap();
    let malicious = target.join("inbox").join("2026").join("eicar.com");
    let clean = target.join("docs").join("clean.txt");
    let unknown = target.join("docs").join("archive").join("unknown.txt");
    fs::write(&malicious, EICAR).unwrap();
    fs::write(&clean, CLEAN).unwrap();
    fs::write(&unknown, UNKNOWN).unwrap();

    let vault = base.join("vault");
    let key = base.join("vault.key");
    let first = run_scan(&target, &rules, Some(&db), &vault, &key);

    assert_eq!(first.status.code(), Some(1), "{}", text(&first));
    let first_json = json(&first);
    assert_eq!(first_json["clean"], 1, "{}", text(&first));
    assert_eq!(first_json["unknown"], 1, "{}", text(&first));
    assert_eq!(first_json["malicious"], 1, "{}", text(&first));
    assert_eq!(first_json["quarantine"]["quarantined"], 1, "{}", text(&first));
    assert_eq!(first_json["quarantine"]["failures"], 0, "{}", text(&first));

    assert!(!malicious.exists(), "malicious original must be moved");
    assert_eq!(fs::read(&clean).unwrap(), CLEAN, "clean file changed");
    assert_eq!(fs::read(&unknown).unwrap(), UNKNOWN, "unknown file changed");

    let opened = QuarantineVault::open(&vault, &key).unwrap();
    let entries = opened.list();
    assert_eq!(entries.len(), 1, "entries: {entries:?}");
    assert_eq!(entries[0].original_path, malicious.display().to_string());
    assert!(entries[0].original_removed);
    let verified = opened.verify_all();
    assert_eq!(verified.len(), 1);
    assert!(verified[0].1, "vault entry must decrypt and verify: {verified:?}");

    // The on-disk entry is encrypted: the EICAR marker must not be readable.
    for entry in fs::read_dir(&vault).unwrap().flatten() {
        if entry.path().extension().and_then(|e| e.to_str()) == Some("lq") {
            let raw = fs::read(entry.path()).unwrap();
            assert!(
                !raw.windows(EICAR.len()).any(|w| w == EICAR),
                "quarantine entry leaked plaintext"
            );
        }
    }

    // Re-running on the same directory must not fail or damage retained files.
    let second = run_scan(&target, &rules, Some(&db), &vault, &key);
    assert_eq!(second.status.code(), Some(0), "{}", text(&second));
    let second_json = json(&second);
    assert_eq!(second_json["files_scanned"], 2, "{}", text(&second));
    assert_eq!(second_json["malicious"], 0, "{}", text(&second));
    assert_eq!(second_json["quarantine"]["quarantined"], 0, "{}", text(&second));
    assert_eq!(second_json["quarantine"]["failures"], 0, "{}", text(&second));
    assert_eq!(fs::read(&clean).unwrap(), CLEAN);
    assert_eq!(fs::read(&unknown).unwrap(), UNKNOWN);
    assert_eq!(opened.list().len(), 1, "repeat scan must not lose the entry");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn scan_quarantine_preserves_alternate_streams_and_timestamps() {
    let base = base("ads-times");
    let rules = rules_dir(&base);
    let target = base.join("eicar-ads.com");
    let marker = b"LITRIC_E2E_ADS_MARKER_DO_NOT_LEAK";
    let streams = vec![
        AlternateStream {
            name: ":Zone.Identifier:$DATA".into(),
            data: b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec(),
        },
        AlternateStream {
            name: ":LitricE2E:$DATA".into(),
            data: marker.to_vec(),
        },
    ];
    fs::write(&target, EICAR).unwrap();
    write_alternate_streams(&target, &streams).unwrap();
    let stamp = UNIX_EPOCH + Duration::from_secs(1_680_000_123);
    apply_file_times(
        &target,
        &FileTimes {
            created: Some(stamp),
            accessed: Some(stamp),
            modified: Some(stamp),
        },
    )
    .unwrap();

    let vault = base.join("vault");
    let key = base.join("vault.key");
    let out = run_scan(&target, &rules, None, &vault, &key);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let report = json(&out);
    assert_eq!(report["malicious"], 1, "{}", text(&out));
    assert_eq!(report["quarantine"]["quarantined"], 1, "{}", text(&out));
    assert!(!target.exists(), "malicious original must be moved");

    // The stream bytes live in the encrypted payload, not in the plaintext
    // header. Assert that rather than assuming the AEAD layer was used.
    for entry in fs::read_dir(&vault).unwrap().flatten() {
        if entry.path().extension().and_then(|e| e.to_str()) == Some("lq") {
            let raw = fs::read(entry.path()).unwrap();
            assert!(
                !raw.windows(marker.len()).any(|w| w == marker),
                "quarantine entry leaked alternate-stream plaintext"
            );
        }
    }

    let opened = QuarantineVault::open(&vault, &key).unwrap();
    let entries = opened.list();
    assert_eq!(entries.len(), 1, "entries: {entries:?}");
    let meta = &entries[0];
    assert!(meta.original_removed, "{:?}", meta.source_retained_reason);
    assert_eq!(meta.payload_version, 1);
    assert_eq!(meta.alternate_streams.len(), 2);
    assert!(meta.file_times.is_some());

    let restored = opened
        .restore(&meta.id, Some(&base.join("restored.com")))
        .unwrap();
    assert_eq!(fs::read(&restored).unwrap(), EICAR);
    let actual = read_alternate_streams(&restored).unwrap();
    let mut expected = streams.clone();
    expected.sort_by_key(|s| s.name.to_ascii_lowercase());
    assert_eq!(actual, expected, "scan quarantine dropped alternate streams");

    let times = capture_file_times(&fs::File::open(&restored).unwrap()).unwrap();
    for (label, actual) in [("created", times.created), ("modified", times.modified)] {
        let actual = actual.unwrap_or_else(|| panic!("{label} timestamp missing"));
        assert_eq!(
            actual.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1_680_000_123,
            "{label} timestamp was not preserved by scan quarantine"
        );
    }
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn dev_signed_database_is_refused_without_explicit_opt_in() {
    let base = base("dev-db-refused");
    let rules = rules_dir(&base);
    let db = clean_db(&base);
    let target = base.join("clean.bin");
    fs::write(&target, CLEAN).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_litric"))
        .arg("--local")
        .arg("scan")
        .arg(&target)
        .arg("--rules")
        .arg(&rules)
        .arg("--db")
        .arg(&db)
        .arg("--json")
        .env_remove("LITRIC_ALLOW_DEV_DB")
        .env_remove("LITRIC_DB_PUBKEY")
        .output()
        .expect("run litric");

    assert!(!out.status.success(), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("LITRIC_DB_PUBKEY") && stderr.contains("LITRIC_ALLOW_DEV_DB"),
        "error must explain how to pin a key or opt in: {stderr}"
    );
    assert_eq!(fs::read(&target).unwrap(), CLEAN, "file must be untouched");
}

#[test]
fn single_file_target_is_quarantined() {
    let base = base("file");
    let rules = rules_dir(&base);
    let target = base.join("single-eicar.com");
    fs::write(&target, EICAR).unwrap();
    let vault = base.join("vault");
    let key = base.join("vault.key");

    let out = run_scan(&target, &rules, None, &vault, &key);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(!target.exists(), "single malicious target must be moved");
    let opened = QuarantineVault::open(&vault, &key).unwrap();
    assert_eq!(opened.list().len(), 1);
    assert!(opened.list()[0].original_removed);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn malicious_zip_member_quarantines_the_container_without_touching_benign_files() {
    let base = base("zip");
    let rules = rules_dir(&base);
    let target = base.join("target");
    fs::create_dir_all(&target).unwrap();
    let archive = target.join("invoice.zip");
    let members = [
        ("docs/readme.txt", b"ordinary text".as_slice()),
        ("bin/payload.txt", EICAR),
    ];
    fs::write(&archive, zip_bytes(&members)).unwrap();
    let clean = target.join("clean.txt");
    fs::write(&clean, CLEAN).unwrap();
    let vault = base.join("vault");
    let key = base.join("vault.key");

    let out = run_scan(&target, &rules, None, &vault, &key);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let j = json(&out);
    assert_eq!(j["malicious"], 1, "{}", text(&out));
    assert_eq!(j["quarantine"]["quarantined"], 1, "{}", text(&out));
    assert_eq!(j["quarantine"]["failures"], 0, "{}", text(&out));
    assert!(!archive.exists(), "malicious container must be moved");
    assert_eq!(fs::read(&clean).unwrap(), CLEAN, "benign file changed");

    let opened = QuarantineVault::open(&vault, &key).unwrap();
    let entries = opened.list();
    assert_eq!(entries.len(), 1, "entries: {entries:?}");
    assert_eq!(entries[0].original_path, archive.display().to_string());
    assert!(entries[0].original_removed);
    let verified = opened.verify_all();
    assert_eq!(verified.len(), 1);
    assert!(verified[0].1, "vault entry must decrypt and verify: {verified:?}");

    // The container is not quarantined by name alone: its hash must match what
    // the vault stored, and a second scan must not find anything left behind.
    let restored = opened
        .list()
        .first()
        .map(|e| e.sha256.clone())
        .unwrap_or_default();
    assert_eq!(restored, sha256_bytes(&zip_bytes(&members)).to_hex());

    let second = run_scan(&target, &rules, None, &vault, &key);
    assert_eq!(second.status.code(), Some(0), "{}", text(&second));
    assert_eq!(json(&second)["quarantine"]["failures"], 0, "{}", text(&second));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn an_encoded_powershell_dropper_is_quarantined() {
    let base = base("ps1-enc");
    let rules = rules_dir(&base);
    let target = base.join("target");
    fs::create_dir_all(&target).unwrap();
    // The only readable evidence of the payload is inside the encoded command:
    // no rule can match this file without decoding it first.
    let command = format!("Write-Host '{}'", String::from_utf8_lossy(EICAR));
    let script = format!(
        "powershell.exe -NoProfile -EncodedCommand {}\r\n",
        b64(&utf16le(&command))
    );
    let dropper = target.join("dropper.ps1");
    fs::write(&dropper, &script).unwrap();
    let clean = target.join("notes.txt");
    fs::write(&clean, CLEAN).unwrap();
    let vault = base.join("vault");
    let key = base.join("vault.key");

    let out = run_scan(&target, &rules, None, &vault, &key);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let j = json(&out);
    assert_eq!(j["malicious"], 1, "{}", text(&out));
    assert_eq!(j["quarantine"]["quarantined"], 1, "{}", text(&out));
    assert_eq!(j["quarantine"]["failures"], 0, "{}", text(&out));
    assert!(!dropper.exists(), "the encoded dropper must be moved");
    assert_eq!(fs::read(&clean).unwrap(), CLEAN, "benign file changed");

    let opened = QuarantineVault::open(&vault, &key).unwrap();
    let entries = opened.list();
    assert_eq!(entries.len(), 1, "entries: {entries:?}");
    assert_eq!(entries[0].original_path, dropper.display().to_string());
    assert!(entries[0].original_removed);
    assert!(opened.verify_all().iter().all(|(_, ok, _)| *ok));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn an_xor_char_array_dropper_is_quarantined() {
    let base = base("ps1-xor");
    let rules = rules_dir(&base);
    let target = base.join("target");
    fs::create_dir_all(&target).unwrap();
    // The EICAR string exists only as XORed character codes: no rule can match
    // this text until the array is decoded.
    let script = format!(
        "$s = -join ([char[]]({}))\r\nInvoke-Expression $s\r\n",
        xor_codes(std::str::from_utf8(EICAR).unwrap(), 0x5a)
    );
    assert!(!script.contains("EICAR"));
    let dropper = target.join("array-dropper.ps1");
    fs::write(&dropper, &script).unwrap();
    let clean = target.join("notes.txt");
    fs::write(&clean, CLEAN).unwrap();
    let vault = base.join("vault");
    let key = base.join("vault.key");

    let out = run_scan(&target, &rules, None, &vault, &key);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let j = json(&out);
    assert_eq!(j["malicious"], 1, "{}", text(&out));
    assert_eq!(j["quarantine"]["quarantined"], 1, "{}", text(&out));
    assert_eq!(j["quarantine"]["failures"], 0, "{}", text(&out));
    assert!(!dropper.exists(), "the char-array dropper must be moved");
    assert_eq!(fs::read(&clean).unwrap(), CLEAN, "benign file changed");

    let opened = QuarantineVault::open(&vault, &key).unwrap();
    let entries = opened.list();
    assert_eq!(entries.len(), 1, "entries: {entries:?}");
    assert_eq!(entries[0].original_path, dropper.display().to_string());
    assert!(entries[0].original_removed);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_failed_vault_write_retains_the_original_and_exits_4() {
    let base = base("fail");
    let rules = rules_dir(&base);
    let target = base.join("eicar.com");
    fs::write(&target, EICAR).unwrap();
    let vault = base.join("vault");
    let key = base.join("vault.key");
    fs::create_dir_all(&vault).unwrap();
    // Force the index publish to fail after encryption: the vault opens, but it
    // cannot write index.json because a directory occupies that path.
    fs::create_dir_all(vault.join("index.json")).unwrap();

    let out = run_scan(&target, &rules, None, &vault, &key);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert_eq!(fs::read(&target).unwrap(), EICAR, "failed move must keep source");
    let output = text(&out);
    assert!(
        output.contains("FAILED") || output.contains("quarantine failed"),
        "failure should be reported: {output}"
    );

    let _ = fs::remove_dir_all(&base);
}
