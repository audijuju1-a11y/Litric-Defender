//! End-to-end tests for `litric guard`.
//!
//! The target is the compiled CLI, not an internal function. Each test uses its
//! own rules, vault and canary file so a failed block is observable rather than
//! inferred from an exit code alone.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn base(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "litric-guard-{tag}-{}-{}",
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

fn run(args: &[String]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_litric"));
    for arg in args {
        cmd.arg(arg);
    }
    cmd.output().expect("run litric")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn malicious_script(base: &Path, canary: &Path) -> PathBuf {
    let path = base.join("malicious.cmd");
    let body = format!(
        "@echo off\r\nrem EICAR-STANDARD-ANTIVIRUS-TEST-FILE\r\necho launched> \"{}\"\r\n",
        canary.display()
    );
    fs::write(&path, body).unwrap();
    path
}

fn guard_command(target: &Path, rules: &Path, extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        "guard".to_string(),
        target.display().to_string(),
        "--rules".to_string(),
        rules.display().to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

#[test]
fn an_explicit_quarantine_moves_the_malicious_target_before_it_can_run() {
    let base = base("malicious");
    let rules = rules_dir(&base);
    let canary = base.join("canary.txt");
    let target = malicious_script(&base, &canary);
    let vault = base.join("vault");
    let key = base.join("vault.key");

    let args = guard_command(
        &target,
        &rules,
        &[
            "--quarantine",
            "--vault-dir",
            vault.to_str().unwrap(),
            "--vault-key",
            key.to_str().unwrap(),
        ],
    );
    let out = run(&args);

    assert_eq!(out.status.code(), Some(1), "stdout: {}\nstderr: {}", stdout(&out), stderr(&out));
    assert!(!target.exists(), "malicious target must be moved into quarantine");
    assert!(!canary.exists(), "the child process must never run");
    let index = fs::read_to_string(vault.join("index.json")).expect("quarantine index");
    assert!(index.contains("Eicar.Test"), "index: {index}");
    assert!(stdout(&out).contains("quarantine_and_block"), "stdout: {}", stdout(&out));
    assert!(stderr(&out).contains("refusing to execute"), "stderr: {}", stderr(&out));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn malicious_target_is_blocked_and_left_in_place_by_default() {
    let base = base("noq");
    let rules = rules_dir(&base);
    let canary = base.join("canary.txt");
    let target = malicious_script(&base, &canary);

    // No `--quarantine`: blocking must not touch the file. This is the safety
    // default the whole product is built around.
    let args = guard_command(&target, &rules, &[]);
    let out = run(&args);

    assert_eq!(out.status.code(), Some(1));
    assert!(target.exists(), "the default guard must retain the file");
    assert!(!canary.exists(), "the child process must never run");
    assert!(stderr(&out).contains("quarantine is opt-in"), "stderr: {}", stderr(&out));

    // The old flag must still parse and must also retain the file.
    let out = run(&guard_command(&target, &rules, &["--no-quarantine"]));
    assert_eq!(out.status.code(), Some(1));
    assert!(target.exists());

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn unknown_is_blocked_by_default() {
    let base = base("unknown");
    let rules = rules_dir(&base);
    let target = base.join("notes.txt");
    fs::write(&target, b"ordinary text with no malicious marker\n").unwrap();

    let out = run(&guard_command(&target, &rules, &[]));

    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("UNKNOWN"), "stdout: {}", stdout(&out));
    assert!(stderr(&out).contains("refusing to execute"), "stderr: {}", stderr(&out));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn unknown_can_run_only_with_the_explicit_override() {
    let base = base("allow");
    let rules = rules_dir(&base);
    let canary = base.join("canary.txt");

    // Windows `cmd /C` does not understand backslash-escaped quotes, which is
    // what Rust's argument quoting produces for `echo guarded> "path"` when the
    // path contains a space. `copy /Y NUL <path>` needs no shell redirection and
    // proves the same thing: the allowed child actually ran.
    let (shell, child_args) = (
        PathBuf::from(r"C:\Windows\System32\cmd.exe"),
        vec![
            "/C".to_string(),
            "copy".to_string(),
            "/Y".to_string(),
            "NUL".to_string(),
            canary.display().to_string(),
        ],
    );

    let mut args = guard_command(&shell, &rules, &["--allow-unknown"]);
    args.push("--".to_string());
    args.extend(child_args);
    let out = run(&args);

    assert_eq!(out.status.code(), Some(0), "stdout: {}\nstderr: {}", stdout(&out), stderr(&out));
    assert!(canary.exists(), "the allowed child must run");
    assert_eq!(fs::metadata(&canary).unwrap().len(), 0);
    assert!(stderr(&out).contains("UNKNOWN is not clean"), "stderr: {}", stderr(&out));

    let _ = fs::remove_dir_all(&base);
}
