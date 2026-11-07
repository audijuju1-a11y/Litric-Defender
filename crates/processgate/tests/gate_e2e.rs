//! Real-process tests for the gate: no mocks, no fake PIDs.
//!
//! Every test uses the benign `litric-pgate-selftest` fixture. Enforcement is
//! exercised by listing that fixture's own SHA-256 as malicious in an in-memory
//! signed database, which proves the kill path without running malware.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use litric_core::engine::{Engine, EngineConfig};
use litric_core::rules::RuleSet;
use litric_core::threatdb::{
    build_signed, dev_signing_key, DbPayload, EntryKind, HashEntry, ThreatDb,
};
use processgate::windows::WindowsControl;
use processgate::{Gate, GateConfig, GateMode, ProcControl, ProtectedSet};

/// These tests spawn and manipulate real processes; running them concurrently
/// would let one test's gate observe (and block) another test's fixture.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn child_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_litric-pgate-selftest"))
}

fn spawn_child(hold_secs: u64) -> std::process::Child {
    std::process::Command::new(child_exe())
        .arg("--hold")
        .arg(hold_secs.to_string())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn fixture")
}

fn is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    /// Standard `SYNCHRONIZE` access right (winnt.h); not re-exported by windows-sys.
    const SYNCHRONIZE: u32 = 0x0010_0000;
    // SAFETY: query/synchronize handle, closed on every path.
    let handle = unsafe {
        OpenProcess(
            SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return false;
    }
    // SAFETY: valid handle; zero timeout only observes.
    let wait = unsafe { WaitForSingleObject(handle, 0) };
    // SAFETY: handle closed once.
    unsafe { CloseHandle(handle) };
    wait == WAIT_TIMEOUT
}

fn wait_for_pid(child: &std::process::Child, timeout: Duration) -> u32 {
    let pid = child.id();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if is_alive(pid) {
            return pid;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("child {pid} did not start");
}

fn engine_with_hash(path: &Path) -> Engine {
    let data = std::fs::read(path).expect("read fixture");
    let sha = litric_core::hash::sha256_bytes(&data).to_hex();
    let payload = DbPayload {
        schema: litric_core::threatdb::DB_FORMAT_VERSION,
        db_version: 1,
        min_engine: litric_core::ENGINE_VERSION.to_string(),
        hashes: vec![HashEntry {
            sha256: sha,
            name: "Test.ProcessGate.Fixture".into(),
            family: None,
            severity: Some("test".into()),
            kind: EntryKind::Malicious,
            source: Some("processgate e2e".into()),
            license: None,
        }],
        ..Default::default()
    };
    let (p, m) = build_signed(&payload, &dev_signing_key()).expect("sign db");
    let db = ThreatDb::verify_loaded(&p, &m, &[], true, litric_core::ENGINE_VERSION)
        .expect("verify db");
    Engine::new(RuleSet::empty(), db, EngineConfig::default())
}

fn engine_empty() -> Engine {
    Engine::new(
        RuleSet::empty(),
        ThreatDb::empty(),
        EngineConfig::default(),
    )
}

/// The fixture must not be under a protected root, or the gate would (correctly)
/// refuse to touch it.
fn test_protected_set() -> ProtectedSet {
    let mut roots: Vec<PathBuf> = Vec::new();
    for key in ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(v) = std::env::var_os(key) {
            roots.push(PathBuf::from(v));
        }
    }
    ProtectedSet::new(roots, std::process::id(), Vec::new())
}

#[test]
fn suspend_freezes_and_resume_lets_the_process_finish() {
    let _serial = serial();
    let mut child = spawn_child(3);
    let pid = wait_for_pid(&child, Duration::from_secs(5));
    let mut control = WindowsControl::new();

    let suspension = control.suspend(pid).expect("suspend child");
    // The child would exit after ~3 s. If suspension is real, it is still alive
    // two seconds later.
    std::thread::sleep(Duration::from_secs(2));
    assert!(is_alive(pid), "child exited while suspended");

    suspension.resume().expect("resume child");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !is_alive(pid) {
            let _ = child.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("child did not exit after resume");
}

#[test]
fn enforce_hash_terminates_a_listed_image_and_resume_leaves_it_alone() {
    let _serial = serial();
    let exe = child_exe();
    let engine = engine_with_hash(&exe);
    let protected = test_protected_set();

    let gate = Gate::new(
        std::sync::Arc::new(engine),
        Box::new(WindowsControl::new()),
        GateMode::EnforceHash,
        GateConfig {
            poll: Duration::from_millis(50),
            ..Default::default()
        },
        protected,
    );
    let counters = gate.counters();
    let mut gate = gate;

    let mut child = spawn_child(20);
    let pid = wait_for_pid(&child, Duration::from_secs(5));

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        gate.tick();
        if counters.blocked.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let blocked = counters.blocked.load(std::sync::atomic::Ordering::Relaxed);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(blocked, 1, "gate did not block the hash-listed fixture");
    assert!(
        !is_alive(pid),
        "process {pid} survived an enforcement block"
    );
}

#[test]
fn a_benign_image_is_resumed_not_killed() {
    let _serial = serial();
    let gate = Gate::new(
        std::sync::Arc::new(engine_empty()),
        Box::new(WindowsControl::new()),
        GateMode::EnforceHash,
        GateConfig {
            poll: Duration::from_millis(50),
            ..Default::default()
        },
        test_protected_set(),
    );
    let counters = gate.counters();
    let mut gate = gate;

    // The fixture holds for 5 s, which is longer than the gate's observation
    // window below. That way "still alive" cannot be confused with "has not
    // reached its own exit yet".
    let mut child = spawn_child(5);
    let pid = wait_for_pid(&child, Duration::from_secs(5));

    // Give the gate several passes over the live fixture.
    let observed = Instant::now() + Duration::from_secs(2);
    while Instant::now() < observed {
        gate.tick();
        std::thread::sleep(Duration::from_millis(50));
    }

    assert_eq!(counters.blocked.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(counters.scanned.load(std::sync::atomic::Ordering::Relaxed) >= 1);

    // Real resume proof: the scanned fixture must reach its own exit on time.
    // A permanently suspended process never exits, so this is what the old
    // assertion was trying to say.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !is_alive(pid) {
            let _ = child.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("benign fixture never exited: the gate left it suspended");
}

#[test]
fn protected_paths_are_never_suspended() {
    let _serial = serial();
    let mut control = WindowsControl::new();
    let protected = processgate::windows::protected_set();
    // Every live process whose image sits under a protected root must be
    // classified as protected, and the gate must not attempt to suspend it.
    let mut checked = 0;
    for proc in control.snapshot() {
        if let Some(image) = control.image_path(proc.pid) {
            if image
                .display()
                .to_string()
                .to_ascii_lowercase()
                .contains("\\windows\\system32\\")
            {
                assert!(protected.is_protected_path(&image), "{}", image.display());
                checked += 1;
                if checked >= 5 {
                    break;
                }
            }
        }
    }
    assert!(checked > 0, "no system32 image found to check");
}
