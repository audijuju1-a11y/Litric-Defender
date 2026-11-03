//! End-to-end tests: the real `litric` binary against a real `litricd` daemon.
//!
//! These invoke the compiled binary (not internal functions), so they prove the
//! client entrypoint — flags, token discovery, transport, rendering, exit codes —
//! actually works. A daemon that is stopped or a token that is missing/wrong must
//! produce a clear error rather than a silent in-process fallback.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use litric_core::engine::{Engine, EngineConfig};
use litric_core::quarantine::QuarantineVault;
use litric_core::rules::{parse_rule_file, RuleSet};
use litric_core::threatdb::ThreatDb;
use litric_service::{server, AppState};

const TOKEN: &str = "e2e-test-token-0123456789abcdef";

struct Daemon {
    handle: server::ServerHandle,
    base: PathBuf,
    token: PathBuf,
}

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn start(tag: &str) -> Daemon {
    let base = std::env::temp_dir().join(format!(
        "litric-e2e-{tag}-{}-{}",
        std::process::id(),
        nanos()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("temp dir");

    let rules = r#"
rule Eicar.Test {
    meta:
        description = "EICAR antivirus test file"
        severity = "critical"
        family = "EICAR-Test"
    strings:
        $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $s
}
"#;
    let rs = RuleSet::compile(parse_rule_file(rules, "e2e").expect("parse")).expect("compile");
    let engine = Engine::new(rs, ThreatDb::empty(), EngineConfig::default());
    let vault = QuarantineVault::open(&base.join("q"), &base.join("vault.key")).expect("vault");
    let state =
        AppState::new(engine, vault, &base.join("data"), TOKEN.to_string()).expect("state");
    let handle = server::serve(state, "127.0.0.1:0").expect("serve");

    let token = base.join("api.token");
    fs::write(&token, format!("{TOKEN}\n")).expect("write token");

    Daemon {
        handle,
        base,
        token,
    }
}

impl Daemon {
    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_litric"));
        cmd.arg("--addr")
            .arg(self.handle.addr.to_string())
            .arg("--token-file")
            .arg(&self.token);
        for a in args {
            cmd.arg(a);
        }
        cmd.output().expect("run litric binary")
    }

    fn workdir(&self, name: &str) -> PathBuf {
        let d = self.base.join(name);
        fs::create_dir_all(&d).expect("workdir");
        d
    }

    fn stop(&self) {
        self.handle.shutdown();
        std::thread::sleep(Duration::from_millis(300));
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.handle.shutdown();
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

#[test]
fn status_goes_through_the_daemon_and_reports_limited() {
    let d = start("status");
    let out = d.run(&["status"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("state        : limited"), "output: {text}");
    assert!(text.contains("NOT ACTIVE"), "output: {text}");
    assert!(!text.contains("state        : protected"), "must not invent protection");
    assert!(text.contains("daemon       :"), "should show which daemon was used");
    assert!(text.contains("rules        : 1"), "output: {text}");
}

#[test]
fn scan_detects_eicar_and_shows_terminal_result() {
    let d = start("scan");
    let dir = d.workdir("target");
    fs::write(
        dir.join("eicar.com"),
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    fs::write(dir.join("notes.txt"), b"harmless text\n").unwrap();

    let out = d.run(&["scan", dir.to_str().unwrap()]);
    let text = stdout(&out);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(text.contains("completed"), "output: {text}");
    assert!(text.contains("malicious 1"), "output: {text}");
    assert!(text.contains("Eicar.Test"), "output: {text}");
    assert!(text.contains("UNKNOWN, not clean"), "output: {text}");
    // Progress or detection lines must reference the scanned file.
    assert!(text.contains("eicar.com"), "output: {text}");
}

#[test]
fn scan_with_fail_on_threat_exits_non_zero() {
    let d = start("failon");
    let dir = d.workdir("target");
    fs::write(
        dir.join("eicar.com"),
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    let out = d.run(&["scan", dir.to_str().unwrap(), "--fail-on-threat"]);
    assert_eq!(out.status.code(), Some(1), "stdout: {}", stdout(&out));
}

#[test]
fn quarantine_add_then_list_round_trip() {
    let d = start("quarantine");
    let dir = d.workdir("files");
    let sample = dir.join("sample.bin");
    fs::write(&sample, b"pretend malware").unwrap();

    let add = d.run(&[
        "quarantine",
        "add",
        sample.to_str().unwrap(),
        "--threat",
        "Test.Sample",
    ]);
    assert!(add.status.success(), "stderr: {}", stderr(&add));
    assert!(stdout(&add).contains("quarantined"));
    assert!(!sample.exists(), "original must be moved into the vault");

    let list = d.run(&["quarantine", "list"]);
    assert!(list.status.success(), "stderr: {}", stderr(&list));
    let text = stdout(&list);
    assert!(text.contains("Test.Sample"), "output: {text}");
    assert!(text.contains("sample.bin"), "output: {text}");
    assert!(text.contains("sha256"), "output: {text}");
}

#[test]
fn empty_quarantine_lists_cleanly() {
    let d = start("emptyq");
    let out = d.run(&["quarantine", "list"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("quarantine is empty"));
}

#[test]
fn missing_token_file_is_actionable() {
    let d = start("notoken");
    let out = Command::new(env!("CARGO_BIN_EXE_litric"))
        .args([
            "--addr",
            &d.handle.addr.to_string(),
            "--token-file",
            "/definitely/not/here/api.token",
            "status",
        ])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("cannot read the API token"), "stderr: {err}");
    assert!(err.contains("litricd serve"), "stderr: {err}");
}

#[test]
fn stopped_daemon_is_reported_not_hidden() {
    let d = start("stopped");
    d.stop();
    let out = d.run(&["status"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("cannot reach the Litric daemon"),
        "stderr: {err}"
    );
    assert!(err.contains("--local"), "should mention standalone mode: {err}");
    // Crucially: nothing was printed as if the scan had run locally.
    assert!(!stdout(&out).contains("files scanned"));
}

#[test]
fn wrong_token_is_rejected_with_guidance() {
    let d = start("badtoken");
    let bogus = d.base.join("bogus.token");
    fs::write(&bogus, format!("{}\n", "f".repeat(64))).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_litric"))
        .args([
            "--addr",
            &d.handle.addr.to_string(),
            "--token-file",
            bogus.to_str().unwrap(),
            "status",
        ])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("rejected the API token"), "stderr: {err}");
    assert!(err.contains("litricd token"), "stderr: {err}");
}

#[test]
fn safeos_status_reports_unavailable_backends_honestly() {
    let d = start("safeos-status");
    let out = d.run(&["safeos", "status"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("UNAVAILABLE"), "output: {text}");
    assert!(text.contains("NOT COLLECTED"), "output: {text}");
    assert!(text.contains("NOT IMPLEMENTED"), "output: {text}");
}

#[test]
fn safeos_assess_blocks_malicious_sample() {
    let d = start("safeos-malicious");
    let dir = d.workdir("files");
    let f = dir.join("eicar.com");
    fs::write(
        &f,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    let out = d.run(&["safeos", "assess", f.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "stdout: {}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("level       : 3"), "output: {text}");
    assert!(text.contains("block_and_quarantine"), "output: {text}");
}

#[test]
fn safeos_assess_denies_unknown_app_instead_of_host_execution() {
    let d = start("safeos-unknown");
    let dir = d.workdir("files");
    let f = dir.join("notes.txt");
    fs::write(&f, b"just some notes\n").unwrap();
    let out = d.run(&["safeos", "assess", f.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "stdout: {}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("level       : 1"), "output: {text}");
    assert!(text.contains("action      : deny"), "output: {text}");
    assert!(
        text.contains("refusing to run an unverified application on the host"),
        "output: {text}"
    );
}

#[test]
fn analyze_reports_detection_through_daemon() {
    let d = start("analyze");
    let dir = d.workdir("files");
    let f = dir.join("eicar.com");
    fs::write(
        &f,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    let out = d.run(&["analyze", f.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "threat should exit 1");
    let text = stdout(&out);
    assert!(text.contains("MALICIOUS"), "output: {text}");
    assert!(text.contains("Eicar.Test"), "output: {text}");
    assert!(text.contains("sha256"), "output: {text}");
}

#[test]
fn quarantine_lifecycle_restore_purge_and_terminal_errors() {
    let d = start("qlife");
    let dir = d.workdir("files");
    let sample = dir.join("life.bin");
    let content = b"lifecycle sample";
    fs::write(&sample, content).unwrap();

    let add = d.run(&[
        "quarantine",
        "add",
        sample.to_str().unwrap(),
        "--threat",
        "Test.Life",
    ]);
    assert!(add.status.success(), "stderr: {}", stderr(&add));
    let add_text = stdout(&add);
    let id = add_text
        .split(" as ")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    assert!(!sample.exists());

    let verify = d.run(&["quarantine", "verify"]);
    assert!(verify.status.success(), "stderr: {}", stderr(&verify));
    assert!(stdout(&verify).contains("ok"), "output: {}", stdout(&verify));

    let restore = d.run(&["quarantine", "restore", &id]);
    assert!(restore.status.success(), "stderr: {}", stderr(&restore));
    assert_eq!(fs::read(&sample).unwrap(), content);
    assert!(stdout(&d.run(&["quarantine", "list"])).contains("quarantine is empty"));

    let again = d.run(&["quarantine", "restore", &id]);
    assert_eq!(again.status.code(), Some(2));
    assert!(
        stderr(&again).contains("no quarantine entry"),
        "stderr: {}",
        stderr(&again)
    );

    let sample2 = dir.join("purge.bin");
    fs::write(&sample2, b"purge me").unwrap();
    let add2 = d.run(&[
        "quarantine",
        "add",
        sample2.to_str().unwrap(),
        "--threat",
        "Test.Purge",
    ]);
    let id2 = stdout(&add2)
        .split(" as ")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    let purge = d.run(&["quarantine", "purge", &id2, "--confirm"]);
    assert!(purge.status.success(), "stderr: {}", stderr(&purge));
    let after = d.run(&["quarantine", "restore", &id2]);
    assert_eq!(after.status.code(), Some(2));
    assert!(stderr(&after).contains("no quarantine entry"));
}

#[test]
fn quarantine_refuses_overwrite_and_corrupt_entries() {
    let d = start("qhostile");
    let dir = d.workdir("files");
    let missing = d.run(&[
        "quarantine",
        "add",
        dir.join("does-not-exist.bin").to_str().unwrap(),
    ]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(
        stderr(&missing).contains("cannot access"),
        "stderr: {}",
        stderr(&missing)
    );
    let sample = dir.join("hostile.bin");
    fs::write(&sample, b"sensitive").unwrap();
    let add = d.run(&[
        "quarantine",
        "add",
        sample.to_str().unwrap(),
        "--threat",
        "Test.Hostile",
    ]);
    assert!(add.status.success(), "stderr: {}", stderr(&add));
    let id = stdout(&add)
        .split(" as ")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();

    let occupied = dir.join("keep.bin");
    fs::write(&occupied, b"keep me").unwrap();
    let restore = d.run(&[
        "quarantine",
        "restore",
        &id,
        "--dest",
        occupied.to_str().unwrap(),
    ]);
    assert_eq!(restore.status.code(), Some(2));
    assert!(
        stderr(&restore).contains("refusing to overwrite"),
        "stderr: {}",
        stderr(&restore)
    );
    assert_eq!(fs::read(&occupied).unwrap(), b"keep me");
    assert!(stdout(&d.run(&["quarantine", "list"])).contains("Test.Hostile"));

    let entry = d.base.join("q").join(format!("{id}.lq"));
    let mut raw = fs::read(&entry).expect("vault entry");
    let last = raw.len() - 1;
    raw[last] ^= 0xff;
    fs::write(&entry, raw).unwrap();

    let verify = d.run(&["quarantine", "verify"]);
    assert_eq!(verify.status.code(), Some(1));
    assert!(stdout(&verify).contains("FAIL"), "output: {}", stdout(&verify));

    let never = dir.join("never.bin");
    let restore = d.run(&[
        "quarantine",
        "restore",
        &id,
        "--dest",
        never.to_str().unwrap(),
    ]);
    assert_eq!(restore.status.code(), Some(2));
    let err = stderr(&restore);
    assert!(
        err.contains("integrity") || err.contains("authentication"),
        "stderr: {err}"
    );
    assert!(!never.exists(), "corrupt entry must not restore data");

    let purge = d.run(&["quarantine", "purge", &id, "--confirm"]);
    assert!(purge.status.success(), "stderr: {}", stderr(&purge));
    let after = d.run(&["quarantine", "restore", &id]);
    assert_eq!(after.status.code(), Some(2));
    assert!(stderr(&after).contains("no quarantine entry"));
}

#[test]
fn cancel_reports_unknown_and_finished_jobs() {
    let d = start("cancel");
    let unknown = d.run(&["cancel", "scan-999999"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(
        stderr(&unknown).contains("no scan job"),
        "stderr: {}",
        stderr(&unknown)
    );

    let dir = d.workdir("scan");
    fs::write(dir.join("a.txt"), b"hello").unwrap();
    let scan = d.run(&["scan", dir.to_str().unwrap()]);
    assert!(scan.status.success(), "stderr: {}", stderr(&scan));
    let text = stdout(&scan);
    let id = text
        .lines()
        .find(|l| l.contains("scan queued"))
        .and_then(|l| l.split_whitespace().nth(3))
        .expect("scan id")
        .to_string();
    let finished = d.run(&["cancel", &id]);
    assert_eq!(finished.status.code(), Some(2));
    assert!(
        stderr(&finished).contains("already finished"),
        "stderr: {}",
        stderr(&finished)
    );
}
