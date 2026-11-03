//! End-to-end: the real `litric-agent` binary reports facts to a real daemon,
//! and `/api/v1/safeos/status` reflects them without claiming launch capability.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use litric_core::engine::{Engine, EngineConfig};
use litric_core::quarantine::QuarantineVault;
use litric_core::rules::{parse_rule_file, RuleSet};
use litric_core::threatdb::ThreatDb;
use litric_service::{server, AppState};

const TOKEN: &str = "agent-e2e-token-0123456789abcdef";

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn test_base(tag: &str) -> std::path::PathBuf {
    let name = format!("litric-agent-{tag}-{}-{}", std::process::id(), nanos());
    #[cfg(windows)]
    {
        // Wine and Windows put `temp_dir()` under the user profile, which the
        // sandbox deliberately refuses to map. Use the system temp directory
        // for fixtures that must look like a non-profile application path.
        std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
            .join("Temp")
            .join(name)
    }
    #[cfg(not(windows))]
    {
        std::env::temp_dir().join(name)
    }
}

fn start(tag: &str) -> (server::ServerHandle, std::path::PathBuf) {
    let base = test_base(tag);
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let rules = "rule Eicar.Test {\n meta:\n  description = \"EICAR\"\n  severity = \"critical\"\n strings:\n  $s = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\"\n condition:\n  $s\n}\n";
    let rs = RuleSet::compile(parse_rule_file(rules, "agent").unwrap()).unwrap();
    let engine = Engine::new(rs, ThreatDb::empty(), EngineConfig::default());
    let vault = QuarantineVault::open(&base.join("q"), &base.join("k")).unwrap();
    let state = AppState::new(engine, vault, &base.join("data"), TOKEN.to_string()).unwrap();
    let handle = server::serve(state, "127.0.0.1:0").unwrap();
    let token = base.join("api.token");
    fs::write(&token, format!("{TOKEN}\n")).unwrap();
    (handle, token)
}

fn get_json(addr: &str, path: &str) -> serde_json::Value {
    let mut s = TcpStream::connect(addr).unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let body = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    serde_json::from_str(body).expect("json body")
}

fn post_json(addr: &str, path: &str, body: &serde_json::Value) -> (u16, serde_json::Value) {
    let body = body.to_string();
    let mut s = TcpStream::connect(addr).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let code = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (code, serde_json::from_str(body).unwrap_or_default())
}

fn write_fixture(path: &Path, nat_ok: bool) {
    let text = format!(
        r#"{{
  "known": true,
  "windows_edition": "Windows 11 Pro",
  "windows_build": 22631,
  "virtualization_enabled": true,
  "hyperv_feature_present": true,
  "sandbox_feature_present": true,
  "total_ram_mb": 16384,
  "free_disk_mb": 102400,
  "existing_nat_networks": 0,
  "nat_query_ok": {nat_ok},
  "wsl_switches": 1,
  "docker_switches": 1
}}"#
    );
    fs::write(path, text).unwrap();
}

#[test]
fn agent_report_updates_status_but_never_claims_a_launcher() {
    let (handle, token) = start("report");
    let addr = handle.addr.to_string();
    let base = token.parent().unwrap().to_path_buf();
    let fixture = base.join("facts.json");
    write_fixture(&fixture, true);

    let out = Command::new(env!("CARGO_BIN_EXE_litric-agent"))
        .args([
            "--fixture",
            fixture.to_str().unwrap(),
            "--addr",
            &addr,
            "--token-file",
            token.to_str().unwrap(),
        ])
        .output()
        .expect("run agent");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let status = get_json(&addr, "/api/v1/safeos/status");
    assert_eq!(status["host_facts_known"], true);
    assert_eq!(status["state"], "facts_reported");
    assert_eq!(status["host_facts"]["windows_build"], 22631);
    let backends = status["backends"].as_array().unwrap();
    let sandbox = backends
        .iter()
        .find(|b| b["kind"] == "windows_sandbox")
        .unwrap();
    assert_eq!(sandbox["host_supported"], true, "status: {status}");
    assert_eq!(status["windows_sandbox_launch_verified"], false);
    #[cfg(not(windows))]
    {
        assert_eq!(sandbox["available"], false, "status: {status}");
        assert!(
            sandbox["reason"].as_str().unwrap().contains("launcher is not implemented"),
            "status: {status}"
        );
        assert_eq!(status["windows_sandbox_launch_implemented"], false);
    }
    #[cfg(windows)]
    {
        // This build contains the launcher, but it has not been verified on
        // hardware; reporting "implemented" must not become "verified".
        assert_eq!(status["windows_sandbox_launch_implemented"], true);
    }
}

#[test]
fn failed_nat_query_is_refused_by_the_daemon_status() {
    let (handle, token) = start("nat");
    let addr = handle.addr.to_string();
    let base = token.parent().unwrap().to_path_buf();
    let fixture = base.join("facts.json");
    write_fixture(&fixture, false);

    let out = Command::new(env!("CARGO_BIN_EXE_litric-agent"))
        .args([
            "--fixture",
            fixture.to_str().unwrap(),
            "--addr",
            &addr,
            "--token-file",
            token.to_str().unwrap(),
        ])
        .output()
        .expect("run agent");
    assert!(out.status.success());

    let status = get_json(&addr, "/api/v1/safeos/status");
    let gateway = status["backends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["kind"] == "network_gateway")
        .unwrap()
        .clone();
    assert_eq!(gateway["host_supported"], false, "status: {status}");
    assert!(status["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["component"] == "network_gateway"));
}

#[test]
fn invalid_report_is_rejected_and_does_not_replace_good_facts() {
    let (handle, token) = start("invalid");
    let addr = handle.addr.to_string();
    let base = token.parent().unwrap().to_path_buf();
    let good = base.join("good.json");
    let bad = base.join("bad.json");
    write_fixture(&good, true);
    fs::write(&bad, r#"{"known":true,"windows_edition":"Windows 11 Pro"}"#).unwrap();

    for fixture in [&good, &bad] {
        let out = Command::new(env!("CARGO_BIN_EXE_litric-agent"))
            .args([
                "--fixture",
                fixture.to_str().unwrap(),
                "--addr",
                &addr,
                "--token-file",
                token.to_str().unwrap(),
            ])
            .output()
            .expect("run agent");
        if fixture == &bad {
            assert_eq!(out.status.code(), Some(2), "bad report must fail");
        } else {
            assert!(out.status.success());
        }
    }

    let status = get_json(&addr, "/api/v1/safeos/status");
    assert_eq!(status["host_facts_known"], true);
    assert_eq!(status["host_facts"]["windows_build"], 22631);
}

#[test]
fn launch_is_refused_until_facts_are_reported() {
    let (handle, token) = start("launch-not-ready");
    let addr = handle.addr.to_string();
    let base = token.parent().unwrap().to_path_buf();
    let app = base.join("sample.exe");
    fs::write(&app, b"MZ").unwrap();

    let (code, body) = post_json(
        &addr,
        "/api/v1/safeos/launch",
        &serde_json::json!({ "path": app.to_str().unwrap() }),
    );
    assert_eq!(code, 409, "body: {body}");
    assert!(body["error"].as_str().unwrap().contains("not ready"));
}

// POSIX-ONLY-TEST: litric-agent/tests/agent_e2e.rs::launch_refuses_politely_without_a_windows_launcher
// Windows counterpart UNPROVEN: this asserts the non-Windows 501 launch refusal.
#[cfg(not(windows))]
#[test]
fn launch_refuses_politely_without_a_windows_launcher() {
    let (handle, token) = start("launch-platform");
    let addr = handle.addr.to_string();
    let base = token.parent().unwrap().to_path_buf();
    let fixture = base.join("facts.json");
    let app = base.join("sample.exe");
    write_fixture(&fixture, true);
    fs::write(&app, b"MZ").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_litric-agent"))
        .args([
            "--fixture",
            fixture.to_str().unwrap(),
            "--addr",
            &addr,
            "--token-file",
            token.to_str().unwrap(),
        ])
        .output()
        .expect("run agent");
    assert!(out.status.success());

    let (code, body) = post_json(
        &addr,
        "/api/v1/safeos/launch",
        &serde_json::json!({ "path": app.to_str().unwrap() }),
    );
    assert_eq!(code, 501, "body: {body}");
    assert!(body["error"].as_str().unwrap().contains("Windows build"));
}

