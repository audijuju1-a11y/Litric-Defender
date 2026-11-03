//! End-to-end proof of the SafeOS launch contract on a non-Windows host.
//!
//! Every case goes through the real `litric` binary -> real `litricd` HTTP API.
//! Facts are reported exactly the way `litric-agent` reports them.
//!
//! Non-Windows by nature: on a Windows build the "ready" case would spawn a real
//! sandbox, so this file is not compiled there. The launcher itself and its gates
//! are still compiled for Windows by `cargo check --all-targets`. Every test here
//! carries a POSIX-ONLY-TEST marker checked by `platform_evidence`.

#![cfg(not(windows))]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use litric_core::engine::{Engine, EngineConfig};
use litric_core::quarantine::QuarantineVault;
use litric_core::rules::{parse_rule_file, RuleSet};
use litric_core::threatdb::ThreatDb;
use litric_service::{server, AppState};
use serde_json::{json, Value};

const TOKEN: &str = "safeos-launch-token-0123456789abcdef";

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
        "litric-launch-{tag}-{}-{}",
        std::process::id(),
        nanos()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();

    let rules = "rule Eicar.Test {\n meta:\n  description = \"EICAR\"\n  severity = \"critical\"\n strings:\n  $s = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\"\n condition:\n  $s\n}\n";
    let rs = RuleSet::compile(parse_rule_file(rules, "launch").unwrap()).unwrap();
    let engine = Engine::new(rs, ThreatDb::empty(), EngineConfig::default());
    let vault = QuarantineVault::open(&base.join("q"), &base.join("k")).unwrap();
    let state = AppState::new(engine, vault, &base.join("data"), TOKEN.to_string()).unwrap();
    let handle = server::serve(state, "127.0.0.1:0").unwrap();

    let token = base.join("api.token");
    fs::write(&token, format!("{TOKEN}\n")).unwrap();
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

    fn post(&self, path: &str, body: &Value) -> u16 {
        let body = body.to_string();
        let mut s = TcpStream::connect(self.handle.addr.to_string()).unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {TOKEN}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.handle.addr,
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        resp.lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }

    fn report(&self, facts: &Value) -> u16 {
        self.post("/api/v1/safeos/host-facts", facts)
    }

    fn app(&self) -> PathBuf {
        let dir = self.base.join("samples");
        fs::create_dir_all(&dir).unwrap();
        let app = dir.join("sample.exe");
        fs::write(&app, b"MZ-not-a-real-pe").unwrap();
        app
    }
}

fn good_facts() -> Value {
    json!({
        "known": true,
        "windows_edition": "Windows 11 Pro",
        "windows_build": 22631,
        "virtualization_enabled": true,
        "hyperv_feature_present": true,
        "sandbox_feature_present": true,
        "total_ram_mb": 16384,
        "free_disk_mb": 102400,
        "existing_nat_networks": 0,
        "nat_query_ok": true,
        "wsl_switches": 1,
        "docker_switches": 1
    })
}

fn with(patch: Value) -> Value {
    let mut base = good_facts();
    for (k, v) in patch.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

fn assert_refused(out: &Output, status: u16, needle: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected client error; stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!("HTTP {status}")),
        "expected HTTP {status}; stderr: {stderr}"
    );
    assert!(
        stderr.contains(needle),
        "expected `{needle}`; stderr: {stderr}"
    );
}

// POSIX-ONLY-TEST: litric-cli/tests/safeos_launch_verify.rs::every_readiness_blocker_is_named_and_reevaluated
// Windows counterpart UNPROVEN: this drives the non-Windows launch gate.
#[test]
fn every_readiness_blocker_is_named_and_reevaluated() {
    let d = start("blockers");
    let app = d.app();
    let app = app.to_str().unwrap();

    // 1. No facts at all.
    assert_refused(&d.run(&["safeos", "launch", app]), 409, "platform_agent");

    // 2. Each capability, one at a time, with the specific blocker named.
    let cases = [
        (
            json!({ "windows_build": 21999 }),
            "windows_build",
            "older than the supported minimum 22000",
        ),
        (
            json!({ "virtualization_enabled": false }),
            "virtualization",
            "VT-x/AMD-V",
        ),
        (
            json!({ "sandbox_feature_present": false }),
            "windows_sandbox",
            "not installed or not enabled",
        ),
        (
            json!({ "total_ram_mb": 2048 }),
            "memory",
            "below the 4096 MB minimum",
        ),
        (
            json!({ "free_disk_mb": 5120 }),
            "disk",
            "below the 10240 MB",
        ),
    ];
    for (patch, component, detail) in cases {
        assert_eq!(d.report(&with(patch)), 200);
        assert_refused(&d.run(&["safeos", "launch", app]), 409, component);
        assert_refused(&d.run(&["safeos", "launch", app]), 409, detail);
    }

    // 3. Facts are re-read on every launch: fixing them moves past readiness.
    assert_eq!(d.report(&good_facts()), 200);
    assert_refused(
        &d.run(&["safeos", "launch", app]),
        501,
        "requires a Windows build",
    );
}

// POSIX-ONLY-TEST: litric-cli/tests/safeos_launch_verify.rs::unsafe_paths_are_rejected_with_stable_messages
// Windows counterpart UNPROVEN: this is the non-Windows launch/path rule set.
#[test]
fn unsafe_paths_are_rejected_with_stable_messages() {
    let d = start("paths");
    assert_eq!(d.report(&good_facts()), 200);
    let app = d.app();
    // A real file whose name contains separators: the guest command must not be
    // allowed to walk out of C:\Litric\input\0.
    let evil = d.base.join(r"evil\..\..\Windows\cmd.exe");
    fs::write(&evil, b"MZ").unwrap();

    for (raw, needle) in [
        (r"C:\", "entire volume"),
        ("/", "entire volume"),
        (r"C:\Users\alice\app.exe", "user profile"),
        ("/home/alice/app.exe", "user profile"),
        (d.base.to_str().unwrap(), "must be a regular file"),
        (
            d.base.join("missing.exe").to_str().unwrap(),
            "cannot access",
        ),
        (evil.to_str().unwrap(), "path separator"),
    ] {
        assert_refused(&d.run(&["safeos", "launch", raw]), 400, needle);
    }
    let _ = app;
}

// POSIX-ONLY-TEST: litric-cli/tests/safeos_launch_verify.rs::a_valid_request_writes_a_locked_down_config_and_stops_at_the_platform_gate
// Windows counterpart UNPROVEN: the 501 platform-gate expectation and .wsb path
// assertions are only executed on this POSIX host.
#[test]
fn a_valid_request_writes_a_locked_down_config_and_stops_at_the_platform_gate() {
    let d = start("valid");
    assert_eq!(d.report(&good_facts()), 200);
    let app = d.app();
    let app_s = app.to_str().unwrap();

    // Linux build: prepare succeeds, then the compile-time platform gate refuses.
    assert_refused(
        &d.run(&["safeos", "launch", app_s]),
        501,
        "requires a Windows build",
    );
    assert_refused(
        &d.run(&["safeos", "launch", app_s, "--wait", "--json"]),
        501,
        "requires a Windows build",
    );

    let cfg_dir = d.base.join("data").join("safeos");
    let config = fs::read_dir(&cfg_dir)
        .expect("config dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "wsb").unwrap_or(false))
        .expect("wsb");
    let xml = fs::read_to_string(config).unwrap();
    assert!(xml.contains("<Networking>Disable</Networking>"), "{xml}");
    assert!(
        xml.contains("<ClipboardRedirection>Disable</ClipboardRedirection>"),
        "{xml}"
    );
    assert!(xml.contains("<AudioInput>Disable</AudioInput>"), "{xml}");
    assert!(xml.contains("<VideoInput>Disable</VideoInput>"), "{xml}");
    assert!(
        xml.contains("<PrinterRedirection>Disable</PrinterRedirection>"),
        "{xml}"
    );
    assert!(xml.contains("<vGPU>Disable</vGPU>"), "{xml}");
    assert!(xml.contains("<ReadOnly>true</ReadOnly>"), "{xml}");
    assert!(
        xml.contains(r"<SandboxFolder>C:\Litric\input\0</SandboxFolder>"),
        "{xml}"
    );
    assert!(xml.contains("sample.exe"), "{xml}");

    // Status reports this build honestly.
    let out = d.run(&["safeos", "status", "--json"]);
    assert!(out.status.success());
    let status: Value = serde_json::from_slice(&out.stdout).expect("status json");
    assert!(!status["windows_sandbox_launch_implemented"]
        .as_bool()
        .unwrap());
    assert!(!status["windows_sandbox_launch_verified"]
        .as_bool()
        .unwrap());
    assert_eq!(status["readiness"]["production_ready"], false);
    assert_eq!(
        status["readiness"]["capabilities"]["safeos_sandbox_guest_runtime"]["state"],
        "UNPROVEN"
    );
    let sandbox = status["backends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["kind"] == "windows_sandbox")
        .unwrap();
    assert_eq!(sandbox["host_supported"], true);
    assert_eq!(sandbox["available"], false);
}

// POSIX-ONLY-TEST: litric-cli/tests/safeos_launch_verify.rs::no_launch_path_executes_the_host_application
// Windows counterpart UNPROVEN: the positive control is a /bin/sh script made
// executable with POSIX mode bits.
#[test]
fn no_launch_path_executes_the_host_application() {
    let d = start("no-host-exec");
    let marker = d.base.join("HOST_EXECUTED.marker");
    let canary = d.base.join("samples").join("canary.exe");
    fs::create_dir_all(canary.parent().unwrap()).unwrap();
    let script = format!(
        "#!/bin/sh\nprintf 'host-executed\\n' >> '{}'\n",
        marker.display()
    );
    fs::write(&canary, script).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&canary, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let canary_s = canary.to_str().unwrap();

    // (a) Positive control inside the test: the canary really does leave a trace
    // when executed. Without this, "no marker" would prove nothing.
    // A just-written file can transiently return ETXTBSY on Linux (for example
    // while another process still has the write handle open); retry only that
    // error, with a hard bound, so a real launch failure still fails the test.
    let mut attempts = 0;
    let control = loop {
        match std::process::Command::new(&canary).status() {
            Ok(status) => break status,
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && attempts < 50 =>
            {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) => panic!("run the canary as a control: {error}"),
        }
    };
    assert!(control.success(), "control canary did not run");
    assert!(
        marker.exists(),
        "control canary did not create its marker; the test is invalid"
    );
    println!("control: marker after direct execution = present");
    fs::remove_file(&marker).expect("remove the control marker");
    println!("control: marker removed; launch cases follow");

    let check_no_trace = |label: &str| {
        assert!(!marker.exists(), "{label}: host marker was created");
        assert!(canary.is_file(), "{label}: the canary was removed");
        println!("{label}: marker=absent canary=present");
    };

    // (b) Refused before readiness: the artifact must not be touched.
    let out = d.run(&["safeos", "launch", canary_s]);
    println!(
        "launch no-facts: exit={:?} | {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("")
    );
    assert_refused(&out, 409, "platform_agent");
    check_no_trace("readiness refusal");

    // (c) Refused by the path rule: still no execution.
    assert_eq!(d.report(&good_facts()), 200);
    let out = d.run(&["safeos", "launch", r"C:\Users\alice\canary.exe"]);
    println!(
        "launch profile-path: exit={:?} | {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("")
    );
    assert_refused(&out, 400, "user profile");
    check_no_trace("path refusal");

    // (d) Valid request, including both CLI variants: readiness and .wsb
    // preparation succeed, then the compile-time platform gate refuses. The
    // target itself is never executed on the host.
    let cases: [&[&str]; 4] = [
        &["safeos", "launch", canary_s],
        &["safeos", "launch", canary_s, "--wait"],
        &["safeos", "launch", canary_s, "--json"],
        &["safeos", "launch", canary_s, "--wait", "--json"],
    ];
    for args in cases {
        let out = d.run(args);
        println!(
            "launch {args:?}: exit={:?} | {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("")
        );
        assert_refused(&out, 501, "requires a Windows build");
        check_no_trace("valid launch");
    }

    assert!(canary.is_file(), "the canary must not be removed");
    let configs = fs::read_dir(d.base.join("data").join("safeos"))
        .expect("config dir")
        .count();
    assert!(
        configs >= 1,
        "a valid request should have prepared a .wsb before the platform gate"
    );
    println!("prepared configs: {configs}");
}
