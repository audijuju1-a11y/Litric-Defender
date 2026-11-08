//! HTTP routing and handlers for the Litric local API.
//!
//! `dispatch` is a pure function of (state, method, url, body). That keeps the
//! whole API testable without sockets, and means authentication/transport bugs
//! cannot hide inside business logic.

use std::path::PathBuf;
use std::sync::atomic::Ordering;

use litric_core::ranshield::{Assessment, FsEvent, Level, ProcessContext};
use litric_core::error::VaultError;
use litric_core::threatdb::EntryKind;
use litric_safeos::model::{backend_status, HostFacts, Readiness};
use litric_safeos::policy::{decide, BackendSet};
use litric_safeos::risk::{assess, ApplicationFacts, HashTrust};
use litric_core::scan::{ScanLimits, Scanner};
use serde_json::{json, Value};

use crate::jobs::{default_limits, now_unix, Job, JobState};
use crate::store::{HistoryEntry, Settings};
use crate::AppState;

/// One API response: status code plus a JSON body.
pub struct ApiResponse {
    pub status: u16,
    pub body: Value,
}

impl ApiResponse {
    pub fn to_json(&self) -> String {
        self.body.to_string()
    }
}

fn ok(body: Value) -> ApiResponse {
    ApiResponse { status: 200, body }
}

fn accepted(body: Value) -> ApiResponse {
    ApiResponse { status: 202, body }
}

fn err(status: u16, message: impl Into<String>) -> ApiResponse {
    ApiResponse {
        status,
        body: json!({ "error": message.into() }),
    }
}

fn bad_request(m: impl Into<String>) -> ApiResponse {
    err(400, m)
}

fn not_found(m: impl Into<String>) -> ApiResponse {
    err(404, m)
}

/// Routes and executes one request. Caller has already authenticated and read
/// the bounded body.
pub fn dispatch(state: &AppState, method: &str, url: &str, body: &[u8]) -> ApiResponse {
    let path = url.split('?').next().unwrap_or("/");
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let segs: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();

    match (method, segs.as_slice()) {
        ("GET", ["api", "v1", "health"]) => ok(health_json(state)),
        ("GET", ["api", "v1", "readiness"]) => ApiResponse {
            status: 503,
            body: readiness_json(),
        },
        ("GET", ["api", "v1", "status"]) => ok(status_json(state)),
        ("GET", ["api", "v1", "capabilities"]) => ok(json!({ "capabilities": capabilities() })),
        ("POST", ["api", "v1", "scan"]) => start_scan(state, body),
        ("GET", ["api", "v1", "scans"]) => ok(json!({
            "scans": state.jobs.list().iter().map(job_json).collect::<Vec<_>>()
        })),
        ("GET", ["api", "v1", "scans", id]) => match state.jobs.get(id) {
            Some(job) => ok(job_json(&job)),
            None => not_found(format!("no scan job `{id}`")),
        },
        ("POST", ["api", "v1", "scans", id, "cancel"]) => cancel_scan(state, id),
        ("POST", ["api", "v1", "analyze"]) => analyze(state, body),
        ("GET", ["api", "v1", "safety"]) => ok(state.vault.safety().status_json()),
        ("GET", ["api", "v1", "quarantine"]) => ok(json!({
            "entries": state
                .vault
                .list()
                .iter()
                .map(|m| serde_json::to_value(m).unwrap_or(Value::Null))
                .collect::<Vec<_>>()
        })),
        ("GET", ["api", "v1", "quarantine", "verify"]) => ok(json!({
            "results": state
                .vault
                .verify_all()
                .into_iter()
                .map(|(id, ok, msg)| json!({ "id": id, "ok": ok, "detail": msg }))
                .collect::<Vec<_>>()
        })),
        ("POST", ["api", "v1", "quarantine"]) => quarantine_add(state, body),
        ("POST", ["api", "v1", "quarantine", id, "restore"]) => {
            quarantine_restore(state, id, body)
        }
        ("DELETE", ["api", "v1", "quarantine", id]) => quarantine_purge(state, id, query, body),
        ("GET", ["api", "v1", "threat-db"]) => ok(threat_db_json(state)),
        ("GET", ["api", "v1", "settings"]) => ok(settings_json(state)),
        ("PUT", ["api", "v1", "settings"]) => update_settings(state, body),
        ("GET", ["api", "v1", "history"]) => ok(history_json(state)),
        ("GET", ["api", "v1", "realtime"]) => ok(realtime_json(state)),
        ("GET", ["api", "v1", "realtime", "events"]) => realtime_events(state, query),
        ("GET", ["api", "v1", "ranshield"]) => ok(ranshield_json(state)),
        ("POST", ["api", "v1", "ranshield", "events"]) => ranshield_events(state, body),
        ("GET", ["api", "v1", "safeos", "status"]) => ok(safeos_status(state)),
        ("POST", ["api", "v1", "safeos", "host-facts"]) => safeos_host_facts(state, body),
        ("POST", ["api", "v1", "safeos", "launch"]) => safeos_launch(state, body, query),
        ("POST", ["api", "v1", "safeos", "assess"]) => safeos_assess(state, body),
        _ => not_found(format!("no route for {method} {path}")),
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// Capability matrix, derived from what is actually implemented.
///
/// These are hard-coded `false` values **because the features are absent**, not
/// because of configuration. They must stay false until the corresponding code
/// exists and is tested.
pub fn capabilities() -> Value {
    json!({
        "on_demand_scan": true,
        "quarantine": true,
        "destructive_operation_guard": true,
        "threat_database": true,
        "behavioural_ransomware_engine": true,
        // ZIP/OOXML/JAR members are scanned recursively with hard limits;
        // RAR/7z/ISO/MSI/CAB/gzip readers do not exist yet.
        "archive_recursion": true,
        // Bounded base64/XOR/char-array layers behind explicit decode constructs,
        // charged to one shared step budget per file.
        "script_deobfuscation": true,
        // VBA modules extracted from OOXML/OLE2 and analysed as source.
        "vba_macros": true,
        // Performance-cache (p-code) presence is reported, not decompiled.
        "vba_pcode_detection": true,
        // Excel 4.0 macro sheets: OOXML formulas and legacy BIFF5/7/8 tokens analysed.
        "xlm_macros": true,
        "authenticode_chain_validation": false,
        "real_time_file_blocking": false,
        "kernel_sensor": false,
        "memory_scan": false,
        "network_filter": false,
        "windows_security_center": false,
        "windows_service_control_manager": false,
        "safeos_risk_assessment": true,
        "safeos_fail_closed_policy": true,
        "safeos_file_broker": true,
        "safeos_session_journal": true,
        "safeos_windows_sandbox_config": true,
        "safeos_host_agent": true,
        "safeos_host_facts_ingest": true,
        "safeos_windows_sandbox_launch": litric_safeos::sandbox::LAUNCH_IMPLEMENTED,
        "safeos_windows_sandbox_launch_verified": litric_safeos::sandbox::LAUNCH_VERIFIED_ON_WINDOWS,
        "safeos_hyperv_backend": false,
        "safeos_network_gateway": false
    })
}

/// Evidence provenance shared by the gate and the mechanical platform checks.
/// These values describe the native Windows run this repository performs;
/// changing them requires a recorded run, not inference from a cross-compile.
pub const SUITE_EXECUTED_ON: &str = "Windows 11 x86_64 (native, x86_64-pc-windows-gnu)";
pub const WINDOWS_SUITE_EXECUTION: &str = "READY";
pub const WINDOWS_SUITE_REASON: &str =
    "Full workspace suite executed natively on Windows 11 x86_64 with the x86_64-pc-windows-gnu toolchain on 2026-11-07; every test passed and no test is Windows-excluded.";

/// Windows-only repository: POSIX-only tests were removed together with the
/// support. This stays empty and `platform_evidence` enforces that no
/// `#[cfg(unix)]` or `#[cfg(not(windows))]` test reappears unnoticed.
pub const WINDOWS_EXCLUDED_TESTS: &[&str] = &[];

/// Fail-closed capability report. Anything without real evidence is UNPROVEN,
/// BLOCKED or NOT_IMPLEMENTED; nothing may be READY just because it compiles.
pub fn readiness_json() -> Value {
    let launch = if litric_safeos::sandbox::LAUNCH_IMPLEMENTED {
        "UNPROVEN"
    } else {
        "BLOCKED"
    };
    let caps = json!({
        "on_demand_scan": { "state": "READY", "evidence": "automated tests on native Windows 11 x86_64 (2026-11-06)" },
        "quarantine": { "state": "READY", "evidence": "lifecycle and recovery tests on native Windows 11 x86_64/NTFS (2026-11-06)" },
        "safeos_risk_assessment": { "state": "READY", "evidence": "automated tests on native Windows 11 x86_64 (2026-11-06)" },
        "safeos_fail_closed_policy": { "state": "READY", "evidence": "automated tests on native Windows 11 x86_64 (2026-11-06)" },
        "safeos_sandbox_config": { "state": "READY", "evidence": "automated .wsb tests on native Windows 11 x86_64 (2026-11-06)" },
        "safeos_sandbox_launch": {
            "state": launch,
            "reason": if litric_safeos::sandbox::LAUNCH_IMPLEMENTED {
                "compiled for Windows but never run on a real Windows 11 host"
            } else {
                "requires a Windows build"
            }
        },
        "safeos_sandbox_guest_runtime": {
            "state": "UNPROVEN",
            "reason": "no guest run has observed networking, clipboard or read-only mapping"
        },
        "test_suite_windows_execution": {
            "state": WINDOWS_SUITE_EXECUTION,
            "reason": WINDOWS_SUITE_REASON
        },
        "quarantine_windows_filesystem_semantics": {
            "state": "READY",
            "evidence": "no-clobber restore, occupied-destination refusal and journal recovery passed natively on Windows 11 x86_64/NTFS (2026-11-06)"
        },
        "safeos_hyperv_backend": { "state": "NOT_IMPLEMENTED" },
        "safeos_network_gateway": { "state": "NOT_IMPLEMENTED" },
        "safeos_behavior_monitoring": { "state": "NOT_IMPLEMENTED" },
        "safeos_ui": { "state": "NOT_IMPLEMENTED" },
        "safeos_installer": { "state": "NOT_IMPLEMENTED" },
        "safeos_vm_recovery": { "state": "UNPROVEN", "reason": "journal planner only; no VHDX recovery" }
    });
    let mut unverified = serde_json::Map::new();
    for (name, cap) in caps.as_object().expect("capabilities object") {
        let state = cap["state"].as_str().unwrap_or("UNPROVEN");
        if state == "READY" {
            continue;
        }
        let states = if name == "safeos_sandbox_launch" {
            json!(["BLOCKED", "UNPROVEN"])
        } else {
            json!([state])
        };
        unverified.insert(name.clone(), states);
    }
    json!({
        "production_ready": false,
        "verdict": "NOT PRODUCTION READY",
        "capabilities": caps,
        "test_evidence": {
            "suite_executed_on": SUITE_EXECUTED_ON,
            "windows_suite_execution": WINDOWS_SUITE_EXECUTION,
            "windows_suite_reason": WINDOWS_SUITE_REASON,
            "windows_excluded_tests": WINDOWS_EXCLUDED_TESTS,
            "unverified_capabilities": unverified
        }
    })
}

fn health_json(state: &AppState) -> Value {
    let (jobs_known, jobs_running) = state.jobs.counts();
    json!({
        "status": "ok",
        "protection_ready": false,
        "product": "Litric Defender",
        "engine_version": litric_core::ENGINE_VERSION,
        "uptime_seconds": state.started.elapsed().as_secs(),
        "jobs_known": jobs_known,
        "jobs_running": jobs_running,
    })
}

fn status_json(state: &AppState) -> Value {
    let mut cap = capabilities();
    // `real_time_file_blocking` stays false: nothing here blocks a write or an execution.
    // `realtime_file_monitor` is true only while the user-mode monitor is actually alive.
    let rt = state.realtime();
    let rt_health = rt.as_ref().map(|m| m.health());
    let realtime_active = rt_health.as_ref().map_or(false, |h| h.running);
    let ransomware_degraded = state.ransomware().map_or(false, |b| !b.degraded().is_empty());
    let realtime_degraded = rt_health.as_ref().map_or(false, |h| !h.degraded.is_empty()) || ransomware_degraded;
    cap["realtime_file_monitor"] = json!(realtime_active);
    let realtime_detail = realtime_json(state);
    let latest = state.jobs.list().into_iter().next();
    let (jobs_known, jobs_running) = state.jobs.counts();
    let quarantined = state.vault.list().len();
    let history_len = state.store.lock().map(|s| s.history.len()).unwrap_or(0);

    json!({
        "product": "Litric Defender",
        "engine": litric_core::ENGINE_NAME,
        "engine_version": litric_core::ENGINE_VERSION,
        // Never "protected": that word is reserved for a kernel pre-execution sensor.
        "state": if !realtime_active {
            "limited"
        } else if realtime_degraded {
            "realtime_degraded"
        } else {
            "realtime_user_mode"
        },
        "state_reason": if !realtime_active {
            "On-demand scanning, quarantine and behavioural analysis are active. \
             The real-time file monitor is NOT running, and real-time blocking is \
             unavailable: it requires a Microsoft-signed kernel file-system sensor, \
             which this build does not include. Litric is not replacing Microsoft \
             Defender on this host."
        } else if realtime_degraded {
            "The user-mode real-time monitor is running but degraded: some files may \
             not have been scanned (see `realtime.degraded`). It scans files after \
             they are written and cannot block execution. Keep Microsoft Defender active."
        } else {
            "The user-mode real-time monitor is running: files written in the watched \
             folders are scanned after the write and malicious ones are moved to the \
             encrypted vault. It cannot block a file before it executes. Keep \
             Microsoft Defender active."
        },
        "real_time_protection": realtime_active,
        "realtime": realtime_detail,
        "realtime_requested_by_user": state.realtime_requested,
        // Null when no gate runs. A gate is best-effort containment, not the
        // kernel pre-execution sensor that `state: protected` requires.
        "process_gate": state
            .process_gate()
            .map(|handle| serde_json::to_value(handle.status()).unwrap_or(Value::Null))
            .unwrap_or(Value::Null),
        "capabilities": cap,
        "readiness": readiness_json(),
        "rules_loaded": state.engine.rules().len(),
        "threat_database": threat_db_json(state),
        "quarantine_entries": quarantined,
        "history_entries": history_len,
        "jobs": { "known": jobs_known, "running": jobs_running },
        "last_scan": latest.map(|j| job_json(&j)),
        "uptime_seconds": state.started.elapsed().as_secs(),
    })
}

/// Detail of the user-mode real-time monitor, or an explicit "not running" with the reason.
fn realtime_json(state: &AppState) -> Value {
    match state.realtime() {
        Some(m) => {
            let mut v = m.status_json();
            // The behavioural layer rides on the same watcher; report it next to the scanner so one
            // glance shows whether every connected layer is alive, and degrade honestly if not.
            v["ransomware"] = match state.ransomware() {
                Some(b) => b.status_json(),
                None => json!({ "running": false, "note": "ransomware behaviour analysis is not attached to the monitor" }),
            };
            if let Some(b) = state.ransomware() {
                if let Some(list) = v["degraded"].as_array_mut() {
                    for d in b.degraded() {
                        list.push(Value::String(format!("ransomware layer: {d}")));
                    }
                }
            }
            v
        }
        None => json!({
            "running": false,
            "requested": state.realtime_requested,
            "error": state.realtime_error(),
            "note": "The real-time file monitor is not running; only on-demand scans are active.",
        }),
    }
}

/// `GET /api/v1/realtime/events?limit=N` — the tail of the monitor's JSON-lines event log.
fn realtime_events(state: &AppState, query: &str) -> ApiResponse {
    let limit = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("limit="))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 500);
    match state.realtime() {
        Some(m) => ok(json!({ "events": m.recent_events(limit) })),
        None => err(503, "the real-time file monitor is not running"),
    }
}

fn threat_db_json(state: &AppState) -> Value {
    let db = state.engine.db();
    json!({
        "version": db.version(),
        "trust": format!("{:?}", db.trust),
        "rules": db.payload.rules.len(),
        "hashes": db.payload.hashes.len(),
        "revoked_rules": db.payload.revoked_rules.len(),
        "revoked_hashes": db.payload.revoked_hashes.len(),
        "empty": db.is_empty(),
        "note": if db.is_empty() {
            "No hash reputation feed is installed; verdicts rely on local rules and heuristics."
        } else {
            "Signed content loaded."
        }
    })
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

fn start_scan(state: &AppState, body: &[u8]) -> ApiResponse {
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return bad_request(format!("invalid JSON body: {e}")),
    };
    let Some(raw_path) = v["path"].as_str() else {
        return bad_request("field `path` is required");
    };
    let profile = v["profile"].as_str().unwrap_or("quick").to_string();
    if !matches!(profile.as_str(), "quick" | "full" | "deep" | "custom") {
        return bad_request("profile must be one of: quick, full, deep, custom");
    }
    let quarantine_malicious = v["quarantine_malicious"].as_bool().unwrap_or(false);
    if quarantine_malicious {
        let alert_only = match state.store.lock() {
            Ok(s) => s.settings.alert_only,
            Err(_) => return err(500, "settings lock poisoned"),
        };
        if alert_only {
            return err(
                409,
                "automatic quarantine is disabled by settings.alert_only; turn it off or use POST /api/v1/quarantine",
            );
        }
    }
    let target = match std::fs::canonicalize(raw_path) {
        Ok(p) => p,
        Err(e) => return bad_request(format!("cannot access `{raw_path}`: {e}")),
    };
    if !target.exists() {
        return bad_request(format!("`{}` does not exist", target.display()));
    }

    let (job_id, cancel) = state.jobs.create(&target.display().to_string(), &profile);
    let engine = state.engine.clone();
    let jobs = state.jobs.clone();
    let store = state.store.clone();
    let vault = state.vault.clone();
    let id = job_id.clone();
    let scan_target = target.clone();
    let limits = default_limits(&profile);

    std::thread::spawn(move || {
        jobs.update(&id, |j| j.state = JobState::Running);
        let mut scanner = Scanner::new(engine.as_ref(), limits);
        scanner.cancel = Some(cancel);
        let progress_jobs = jobs.clone();
        let progress_id = id.clone();
        scanner.progress = Some(std::sync::Arc::new(
            move |summary: &litric_core::scan::ScanSummary| {
                progress_jobs.update(&progress_id, |job| {
                    job.summary = Some(summary.clone());
                });
            },
        ));

        let summary = scanner.scan_path(&scan_target);
        let cancelled = summary.cancelled;
        let files_scanned = summary.files_scanned;
        let malicious = summary.malicious;
        let suspicious = summary.suspicious;
        let unknown = summary.unknown;
        let duration_ms = summary.duration.as_millis() as u64;
        // A cancelled scan is incomplete evidence; do not move files from it.
        let quarantine = if quarantine_malicious && !cancelled {
            Some(litric_core::scan_quarantine::quarantine_malicious(
                &summary,
                vault.as_ref(),
            ))
        } else {
            None
        };

        jobs.update(&id, |job| {
            job.state = if cancelled {
                JobState::Cancelled
            } else {
                JobState::Completed
            };
            job.finished_unix = Some(now_unix());
            job.summary = Some(summary);
            job.quarantine = quarantine;
        });

        if let Ok(mut st) = store.lock() {
            let _ = st.record(HistoryEntry {
                job_id: id.clone(),
                target: scan_target.display().to_string(),
                finished_unix: now_unix(),
                files_scanned,
                malicious,
                suspicious,
                unknown,
                cancelled,
            });
        }
        let _ = duration_ms;
    });

    accepted(json!({ "job_id": job_id, "state": "queued", "target": target.display().to_string() }))
}

fn cancel_scan(state: &AppState, id: &str) -> ApiResponse {
    let Some(job) = state.jobs.get(id) else {
        return not_found(format!("no scan job `{id}`"));
    };
    if job.state.is_terminal() {
        return err(409, format!("job `{id}` already finished ({})", job.state.as_str()));
    }
    if state.jobs.cancel(id) {
        accepted(json!({ "job_id": id, "state": "cancelling" }))
    } else {
        err(409, format!("job `{id}` cannot be cancelled"))
    }
}

fn job_json(job: &Job) -> Value {
    let mut out = json!({
        "job_id": job.id,
        "target": job.target,
        "profile": job.profile,
        "state": job.state.as_str(),
        "progress_pct": job.progress_pct(),
        "created_unix": job.created_unix,
        "finished_unix": job.finished_unix,
        "error": job.error,
    });
    if let Some(s) = &job.summary {
        out["files_scanned"] = json!(s.files_scanned);
        out["clean"] = json!(s.clean);
        out["unknown"] = json!(s.unknown);
        out["suspicious"] = json!(s.suspicious);
        out["malicious"] = json!(s.malicious);
        out["unreadable"] = json!(s.unreadable);
        out["skipped"] = json!(s.skipped);
        out["skipped_too_large"] = json!(s.skipped_too_large);
        out["skipped_budget"] = json!(s.skipped_budget);
        out["truncated"] = json!(s.truncated);
        out["cancelled"] = json!(s.cancelled);
        out["bytes_scanned"] = json!(s.bytes_scanned);
        out["duration_ms"] = json!(s.duration.as_millis() as u64);
        out["files_per_second"] = json!(s.files_per_second());
        out["mb_per_second"] = json!(s.mb_per_second());
        out["detections"] = json!(s
            .detections
            .iter()
            .take(200)
            .map(|d| json!({
                "path": d.path.display().to_string(),
                "verdict": d.verdict.as_str(),
                "score": d.score,
                "threat": d.threat_name,
                "sha256": d.sha256,
            }))
            .collect::<Vec<_>>());
    }
    if let Some(q) = &job.quarantine {
        out["quarantined"] = json!(q.quarantined);
        out["quarantine_failures"] = json!(q.failures);
        out["quarantine"] = json!({
            "malicious_seen": q.malicious_seen,
            "quarantined": q.quarantined,
            "failures": q.failures,
            "entries": q.entries.iter().take(200).map(|m| json!({
                "id": m.id,
                "path": m.original_path,
                "sha256": m.sha256,
                "threat": m.threat_name,
                "original_removed": m.original_removed,
            })).collect::<Vec<_>>(),
            "entries_truncated": q.entries.len() > 200,
            "errors": q.errors,
        });
    }
    out
}

fn analyze(state: &AppState, body: &[u8]) -> ApiResponse {
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return bad_request(format!("invalid JSON body: {e}")),
    };
    let Some(raw) = v["path"].as_str() else {
        return bad_request("field `path` is required");
    };
    let path = match std::fs::canonicalize(raw) {
        Ok(p) => p,
        Err(e) => return bad_request(format!("cannot access `{raw}`: {e}")),
    };
    if !path.is_file() {
        return bad_request("`path` must be a regular file; use /scan for directories");
    }
    let limits = ScanLimits::default();
    let scanner = Scanner::new(state.engine.as_ref(), limits);
    match scanner.analyze_file(&path) {
        Ok((report, truncated)) => ok(json!({
            "name": report.name,
            "path": path.display().to_string(),
            "sha256": report.sha256.to_hex(),
            "size": report.size,
            "format": report.format,
            "extension": report.ext,
            "verdict": report.verdict.as_str(),
            "score": report.score,
            "confidence": report.confidence,
            "threat": report.threat_name,
            "family": report.family,
            "mitre": report.mitre,
            "truncated": truncated,
            "signals": report.signals.iter().map(|s| json!({
                "id": s.id,
                "weight": s.weight,
                "confidence": s.confidence.as_str(),
                "title": s.title,
                "detail": s.detail,
                "mitre": s.mitre,
            })).collect::<Vec<_>>(),
            "rules": report.rules.iter().map(|m| json!({
                "name": m.name,
                "severity": m.severity.as_str(),
                "description": m.description,
                "matched_strings": m.matched_strings,
            })).collect::<Vec<_>>(),
            "notes": report.notes,
        })),
        Err(e) => err(500, format!("analysis failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// SafeOS
// ---------------------------------------------------------------------------

/// Honest SafeOS capability report. No platform agent exists in this build, so
/// every Windows-only backend reports unavailable rather than "assumed fine".
fn safeos_status(state: &AppState) -> Value {
    let facts = state
        .host_facts
        .lock()
        .ok()
        .and_then(|f| f.clone())
        .unwrap_or_else(HostFacts::unknown);
    let readiness = Readiness::evaluate(&facts);
    json!({
        "state": if facts.known { "facts_reported" } else { "unavailable" },
        "readiness": readiness_json(),
        "host_facts_known": facts.known,
        "platform_agent": if facts.known {
            "host facts received"
        } else {
            "no host facts received; run `litric-agent` on Windows"
        },
        "host_facts": if facts.known {
            json!({
                "windows_edition": facts.windows_edition,
                "windows_build": facts.windows_build,
                "virtualization_enabled": facts.virtualization_enabled,
                "hyperv_feature_present": facts.hyperv_feature_present,
                "sandbox_feature_present": facts.sandbox_feature_present,
                "total_ram_mb": facts.total_ram_mb,
                "free_disk_mb": facts.free_disk_mb,
                "logical_cpus": facts.logical_cpus,
                "existing_nat_networks": facts.existing_nat_networks,
                "nat_query_ok": facts.nat_query_ok,
                "wsl_switches": facts.wsl_switches,
                "docker_switches": facts.docker_switches,
            })
        } else {
            Value::Null
        },
        // `host_supported` is what the Windows host can do. `available` is what
        // this build can actually launch; it stays false until a launcher exists.
        "backends": backend_status(&facts)
            .iter()
            .map(|b| {
                let host_supported = b.available;
                let usable = host_supported && litric_safeos::sandbox::LAUNCH_IMPLEMENTED;
                json!({
                    "kind": b.kind,
                    "available": usable,
                    "host_supported": host_supported,
                    "reason": if host_supported && !usable {
                        format!("{}; the launcher is not implemented in this build", b.reason)
                    } else {
                        b.reason.clone()
                    },
                    "requires_windows": b.requires_windows,
                })
            })
            .collect::<Vec<_>>(),
        "blockers": readiness
            .blockers
            .iter()
            .map(|b| json!({
                "component": b.component,
                "reason": b.reason,
                "remediation": b.remediation,
            }))
            .collect::<Vec<_>>(),
        // What the resource governor would allocate right now, from the same
        // facts the launch gate uses. It is a decision, not a measurement.
        "resource_governor": {
            "max_heavy_sessions": litric_safeos::governor::MAX_HEAVY_SESSIONS,
            "windows_sandbox": resource_decision(&facts, litric_safeos::governor::Backend::WindowsSandbox),
            "hyperv_managed": resource_decision(&facts, litric_safeos::governor::Backend::HyperV),
        },
        "windows_sandbox_launch_implemented": litric_safeos::sandbox::LAUNCH_IMPLEMENTED,
        "windows_sandbox_launch_verified": litric_safeos::sandbox::LAUNCH_VERIFIED_ON_WINDOWS,
        "hyperv_backend_implemented": false,
        "network_gateway_implemented": false,
    })
}

/// Governor decision for one backend, evaluated with no session running.
fn resource_decision(
    facts: &HostFacts,
    backend: litric_safeos::governor::Backend,
) -> Value {
    litric_safeos::governor::decide(
        facts,
        &litric_safeos::governor::ResourceRequest::new(
            backend,
            litric_safeos::model::ExecutionLevel::Unknown,
        ),
    )
    .to_json()
}

/// Accepts a read-only host report from `litric-agent`.
fn safeos_host_facts(state: &AppState, body: &[u8]) -> ApiResponse {
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return bad_request(format!("invalid JSON body: {e}")),
    };
    let facts = HostFacts::from_json(&v);
    if !facts.known {
        return bad_request("host report must set known=true");
    }
    if facts.windows_edition.trim().is_empty() {
        return bad_request("host report must include windows_edition");
    }
    if facts.windows_build == 0 {
        return bad_request("host report must include windows_build");
    }
    if facts.total_ram_mb == 0 {
        return bad_request("host report must include total_ram_mb");
    }
    if facts.existing_nat_networks > 64 {
        return bad_request("existing_nat_networks looks implausible; refusing the report");
    }
    if facts.logical_cpus > 1024 {
        return bad_request("logical_cpus looks implausible; refusing the report");
    }
    match state.host_facts.lock() {
        Ok(mut slot) => *slot = Some(facts),
        Err(e) => return err(500, format!("host facts lock poisoned: {e}")),
    }
    ok(safeos_status(state))
}

/// Classifies an application and returns the fail-closed execution decision.
fn safeos_assess(state: &AppState, body: &[u8]) -> ApiResponse {
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return bad_request(format!("invalid JSON body: {e}")),
    };
    let Some(raw) = v["path"].as_str() else {
        return bad_request("field `path` is required");
    };
    let path = match std::fs::canonicalize(raw) {
        Ok(p) => p,
        Err(e) => return bad_request(format!("cannot access `{raw}`: {e}")),
    };
    if !path.is_file() {
        return bad_request("`path` must be a regular file");
    }

    let scanner = Scanner::new(state.engine.as_ref(), ScanLimits::default());
    let report = match scanner.analyze_file(&path) {
        Ok((report, _truncated)) => report,
        Err(e) => return err(500, format!("analysis failed: {e}")),
    };

    let hash_trust = match state.engine.db().lookup(&report.sha256) {
        Some(entry) => match entry.kind {
            EntryKind::Malicious => HashTrust::Malicious,
            EntryKind::Pua => HashTrust::Pua,
            EntryKind::Trusted => HashTrust::Allowlisted,
        },
        None => HashTrust::Unknown,
    };

    let signature_trust = state.signature_verifier.verify(&path);
    let signature_chain_valid = signature_trust.is_valid();
    let facts = ApplicationFacts {
        verdict: report.verdict.as_str().to_string(),
        score: report.score,
        confidence: report.confidence,
        // A valid chain is proof that a signature exists even when the parser's
        // certificate summary is partial. Otherwise use the structural evidence.
        signature_present: report
            .pe
            .as_ref()
            .map(|p| !p.signers.is_empty())
            .unwrap_or(false)
            || signature_chain_valid,
        signature_chain_valid,
        hash_trust,
    };
    let assessment = assess(&facts);
    let decision = decide(assessment.level, &BackendSet::none());
    let host_facts = state
        .host_facts
        .lock()
        .ok()
        .and_then(|f| f.clone())
        .unwrap_or_else(HostFacts::unknown);
    let readiness = Readiness::evaluate(&host_facts);

    ok(json!({
        "path": path.display().to_string(),
        "sha256": report.sha256.to_hex(),
        "verdict": report.verdict.as_str(),
        "score": report.score,
        "signature_chain_valid": signature_chain_valid,
        "level": assessment.level.number(),
        "level_name": assessment.level.as_str(),
        "confidence": assessment.confidence,
        "rationale": assessment.rationale,
        "evidence": assessment.evidence,
        "action": decision.action.as_str(),
        "reasons": decision.reasons,
        "remediation": decision.remediation,
        "isolation_available": false,
        "system_readiness": {
            "production_ready": false,
            "sandbox_guest_runtime": "UNPROVEN",
            "host_facts_known": host_facts.known,
            "blockers": readiness
                .blockers
                .iter()
                .map(|b| json!({
                    "component": b.component,
                    "reason": b.reason,
                    "remediation": b.remediation,
                }))
                .collect::<Vec<_>>(),
        },
        "note": "no isolation backend is present in this build; the decision is fail-closed",
    }))
}

/// Prepares and, on Windows builds, starts a disposable sandbox session.
///
/// `prepare` always runs first: without reported facts and a usable sandbox
/// feature the request is refused with 409, and no process is created.
fn safeos_launch(state: &AppState, body: &[u8], query: &str) -> ApiResponse {
    use litric_safeos::sandbox::{launch, prepare, LaunchError};

    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return bad_request(format!("invalid JSON body: {e}")),
    };
    let Some(raw) = v["path"].as_str() else {
        return bad_request("field `path` is required");
    };
    // Pass the raw path through: `prepare` rejects drive roots and user profiles
    // before access, then canonicalises and requires a regular file.
    let path = PathBuf::from(raw);
    let facts = state
        .host_facts
        .lock()
        .ok()
        .and_then(|f| f.clone())
        .unwrap_or_else(HostFacts::unknown);
    let wait = query.split('&').any(|kv| kv == "wait=true");
    let prepared = match prepare(&facts, &path, &state.data_dir.join("safeos")) {
        Ok(p) => p,
        Err(LaunchError::NotReady(reasons)) => {
            return err(
                409,
                format!("sandbox is not ready: {}", reasons.join("; ")),
            )
        }
        Err(e) => return err(400, e.to_string()),
    };
    match launch(&prepared, wait) {
        Ok(outcome) => ok(json!({
            "config_path": outcome.config_path.display().to_string(),
            "command": outcome.command,
            "pid": outcome.pid,
            "exit_code": outcome.exit_code,
            "waited": wait,
            "launch_verified": litric_safeos::sandbox::LAUNCH_VERIFIED_ON_WINDOWS,
            "note": "Windows Sandbox is a disposable, offline, interactive session; it does not \
                     protect the host from a sandbox escape, and closing the window ends the session",
        })),
        Err(LaunchError::NotWindows) => err(
            501,
            "Windows Sandbox launch requires a Windows build; this daemon cannot launch it",
        ),
        Err(LaunchError::Spawn(m)) => err(500, format!("sandbox launch failed: {m}")),
        Err(e) => err(400, e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

fn quarantine_add(state: &AppState, body: &[u8]) -> ApiResponse {
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return bad_request(format!("invalid JSON body: {e}")),
    };
    let Some(raw) = v["path"].as_str() else {
        return bad_request("field `path` is required");
    };
    let threat = v["threat"].as_str().unwrap_or("User.Request");
    // Safety first: an API call copies the sample and leaves the original in
    // place unless the caller explicitly asks to remove it. A UI bug or a
    // malformed request must never be able to delete a file on its own.
    let copy_only = v["copy_only"].as_bool().unwrap_or(true);

    let path = match std::fs::canonicalize(raw) {
        Ok(p) => p,
        Err(e) => return bad_request(format!("cannot access `{raw}`: {e}")),
    };
    if !path.is_file() {
        return bad_request("only regular files can be quarantined");
    }
    match state
        .vault
        .quarantine_file(&path, threat, None, 100, copy_only)
    {
        Ok(meta) => accepted(json!({
            "id": meta.id,
            "sha256": meta.sha256,
            "size": meta.size,
            "original_removed": meta.original_removed,
            "threat": meta.threat_name,
        })),
        Err(e) => err(500, format!("quarantine failed: {e}")),
    }
}

fn quarantine_restore(state: &AppState, id: &str, body: &[u8]) -> ApiResponse {
    let dest = if body.is_empty() {
        None
    } else {
        match serde_json::from_slice::<Value>(body) {
            Ok(v) => v["dest"].as_str().map(PathBuf::from),
            Err(e) => return bad_request(format!("invalid JSON body: {e}")),
        }
    };
    match state.vault.restore(id, dest.as_deref()) {
        Ok(path) => ok(json!({ "restored_to": path.display().to_string() })),
        Err(e) => vault_error(e),
    }
}

/// Maps vault failures to stable HTTP statuses. Integrity/conflict are 409, not
/// a generic 500, because they are actionable and must not look like a crash.
fn vault_error(e: VaultError) -> ApiResponse {
    match e {
        VaultError::NotFound(m) => not_found(m),
        VaultError::Conflict(m) => err(409, m),
        VaultError::IntegrityMismatch { .. }
        | VaultError::SourceChanged { .. }
        | VaultError::Authentication => {
            err(409, format!("vault integrity check failed: {e}"))
        }
        VaultError::SafetyRefused(m) => err(403, m),
        VaultError::Corrupt(m) => err(409, format!("vault entry corrupt: {m}")),
        VaultError::Io(_) => err(500, format!("vault I/O failed: {e}")),
    }
}

/// Purging destroys evidence. It requires an explicit `confirm=true`, so a UI bug
/// cannot silently erase the user's quarantine.
fn quarantine_purge(state: &AppState, id: &str, query: &str, body: &[u8]) -> ApiResponse {
    let mut confirmed = query.split('&').any(|p| p == "confirm=true");
    if !confirmed && !body.is_empty() {
        if let Ok(v) = serde_json::from_slice::<Value>(body) {
            confirmed = v["confirm"].as_bool().unwrap_or(false);
        }
    }
    if !confirmed {
        return bad_request("purge is irreversible: pass confirm=true to proceed");
    }
    match state.vault.purge(id) {
        Ok(()) => ok(json!({ "purged": id })),
        Err(e) => vault_error(e),
    }
}

// ---------------------------------------------------------------------------
// Settings / history
// ---------------------------------------------------------------------------

fn settings_json(state: &AppState) -> Value {
    let guard = state.store.lock();
    match guard {
        Ok(s) => json!({ "settings": s.settings }),
        Err(_) => err(500, "settings lock poisoned").body,
    }
}

fn update_settings(state: &AppState, body: &[u8]) -> ApiResponse {
    let new: Settings = match serde_json::from_slice(body) {
        Ok(s) => s,
        Err(e) => return bad_request(format!("invalid settings: {e}")),
    };
    if let Err(e) = new.validate() {
        return bad_request(e);
    }
    let mut guard = match state.store.lock() {
        Ok(g) => g,
        Err(_) => return err(500, "settings lock poisoned"),
    };
    guard.settings = new.clone();
    match guard.save_settings() {
        Ok(()) => ok(json!({ "settings": new })),
        Err(e) => err(500, format!("could not persist settings: {e}")),
    }
}

fn history_json(state: &AppState) -> Value {
    match state.store.lock() {
        Ok(s) => json!({
            "entries": s.history.iter().rev().take(50).collect::<Vec<_>>(),
        }),
        Err(_) => err(500, "history lock poisoned").body,
    }
}

// ---------------------------------------------------------------------------
// RansomShield
// ---------------------------------------------------------------------------

fn ranshield_json(state: &AppState) -> Value {
    match state.ranshield.lock() {
        Ok(shield) => {
            let cfg = shield.config();
            json!({
                "enabled": true,
                "enforcement": false,
                "enforcement_reason": "Decisions are produced and returned; applying them \
                    requires the kernel file-system sensor, which is not installed.",
                "live_feed": state.ransomware().map(|b| b.status_json()),
                "config": {
                    "window_secs": cfg.window.as_secs(),
                    "write_burst": cfg.write_burst,
                    "extension_churn": cfg.extension_churn,
                    "entropy_threshold": cfg.entropy_threshold,
                    "mass_delete": cfg.mass_delete,
                    "block_threshold": cfg.block_threshold,
                    "suspend_threshold": cfg.suspend_threshold,
                }
            })
        }
        Err(_) => err(500, "ranshield lock poisoned").body,
    }
}

fn ranshield_events(state: &AppState, body: &[u8]) -> ApiResponse {
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return bad_request(format!("invalid JSON body: {e}")),
    };
    let Some(events) = v["events"].as_array() else {
        return bad_request("field `events` must be an array");
    };
    if events.len() > 10_000 {
        return bad_request("at most 10 000 events per request");
    }

    let mut shield = match state.ranshield.lock() {
        Ok(s) => s,
        Err(_) => return err(500, "ranshield lock poisoned"),
    };

    if let Some(p) = v.get("process") {
        if let Some(pid) = p["pid"].as_u64() {
            shield.register_process(
                pid as u32,
                ProcessContext {
                    image: p["image"].as_str().unwrap_or_default().to_string(),
                    signed: p["signed"].as_bool().unwrap_or(false),
                    publisher: p["publisher"].as_str().map(|s| s.to_string()),
                    command_line: p["command_line"].as_str().unwrap_or_default().to_string(),
                },
            );
        }
    }

    let mut assessments: Vec<Value> = Vec::new();
    for ev in events {
        let Some(parsed) = parse_event(ev) else {
            continue;
        };
        let a: Assessment = shield.observe(parsed);
        assessments.push(json!({
            "pid": a.pid,
            "level": a.level.as_str(),
            "score": a.score,
            "reasons": a.reasons,
            "actions": a.actions.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
        }));
    }

    let highest = assessments
        .iter()
        .map(|a| a["score"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let level = if highest >= 100 {
        Level::Critical
    } else if highest >= 70 {
        Level::Suspicious
    } else if highest >= 40 {
        Level::Watching
    } else {
        Level::Normal
    };

    ok(json!({
        "assessments": assessments,
        "highest_score": highest,
        "level": level.as_str(),
    }))
}

fn parse_event(v: &Value) -> Option<FsEvent> {
    let kind = v["type"].as_str()?;
    let pid = v["pid"].as_u64()? as u32;
    Some(match kind {
        "write" => FsEvent::Write {
            pid,
            path: PathBuf::from(v["path"].as_str()?),
            bytes: v["bytes"].as_u64().unwrap_or(0),
            entropy: v["entropy"].as_f64().unwrap_or(0.0),
        },
        "rename" => FsEvent::Rename {
            pid,
            from: PathBuf::from(v["from"].as_str()?),
            to: PathBuf::from(v["to"].as_str()?),
        },
        "delete" => FsEvent::Delete {
            pid,
            path: PathBuf::from(v["path"].as_str()?),
        },
        "decoy" => FsEvent::DecoyTouched {
            pid,
            decoy: v["decoy"].as_str().unwrap_or("decoy").to_string(),
        },
        "backup_tamper" => FsEvent::BackupTamper {
            pid,
            command: v["command"].as_str().unwrap_or_default().to_string(),
        },
        _ => return None,
    })
}

/// Helper used by tests and the server to read the `cancel` flag state safely.
pub fn job_cancelled(flag: &std::sync::atomic::AtomicBool) -> bool {
    flag.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PlatformSignatureVerifier, SignatureTrust, SignatureVerifier};
    use litric_core::engine::EngineConfig;
    use litric_core::quarantine::QuarantineVault;
    use litric_core::rules::{parse_rule_file, RuleSet};
    use litric_core::threatdb::{
        build_signed, dev_signing_key, DbPayload, HashEntry, ThreatDb, DB_FORMAT_VERSION,
    };
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    fn test_base(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "litric-api-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn test_state_with(
        tag: &str,
        db: ThreatDb,
        verifier: Arc<dyn SignatureVerifier>,
    ) -> (std::sync::Arc<AppState>, PathBuf) {
        let base = test_base(tag);
        let rules = r#"
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
"#;
        let rs = RuleSet::compile(parse_rule_file(rules, "test").unwrap()).unwrap();
        let engine = litric_core::engine::Engine::new(rs, db, EngineConfig::default());
        let vault = QuarantineVault::open(&base.join("quarantine"), &base.join("vault.key")).unwrap();
        let state = AppState::new_with_verifier(
            engine,
            vault,
            &base.join("data"),
            "test-token".into(),
            verifier,
        )
        .unwrap();
        (state, base)
    }

    fn test_state(tag: &str) -> (std::sync::Arc<AppState>, PathBuf) {
        test_state_with(
            tag,
            ThreatDb::empty(),
            Arc::new(PlatformSignatureVerifier),
        )
    }

    fn trusted_db(bytes: &[u8]) -> ThreatDb {
        let payload = DbPayload {
            schema: DB_FORMAT_VERSION,
            db_version: 1,
            min_engine: "0.0.0".into(),
            created_unix: 0,
            hashes: vec![HashEntry {
                sha256: litric_core::hash::sha256_bytes(bytes).to_hex(),
                name: "Fixture.Trusted".into(),
                family: Some("Fixture".into()),
                severity: Some("trusted".into()),
                kind: EntryKind::Trusted,
                source: Some("unit test".into()),
                license: Some("CC0".into()),
            }],
            ..Default::default()
        };
        let (payload_bytes, manifest_bytes) = build_signed(&payload, &dev_signing_key()).unwrap();
        ThreatDb::verify_loaded(
            &payload_bytes,
            &manifest_bytes,
            &[],
            true,
            litric_core::ENGINE_VERSION,
        )
        .expect("test database")
    }

    #[test]
    fn status_never_claims_protection() {
        let (state, base) = test_state("status");
        let r = dispatch(&state, "GET", "/api/v1/status", b"");
        assert_eq!(r.status, 200);
        assert_eq!(r.body["state"], "limited");
        assert_eq!(r.body["real_time_protection"], false);
        assert_eq!(r.body["capabilities"]["real_time_file_blocking"], false);
        assert_eq!(r.body["capabilities"]["on_demand_scan"], true);
        // the monitor is not attached, so the report must say so plainly
        assert_eq!(r.body["realtime"]["running"], false);
        assert_eq!(r.body["capabilities"]["realtime_file_monitor"], false);
        let _ = fs::remove_dir_all(&base);
    }

    /// End to end through the API: a real file-change notification, the real pipeline and vault,
    /// and a status that flips only while the monitor is actually alive.
    #[test]
    fn status_reports_user_mode_realtime_only_while_the_monitor_runs() {
        let (state, base) = test_state("realtime");
        assert_eq!(
            dispatch(&state, "GET", "/api/v1/realtime/events", b"").status,
            503,
            "no monitor attached yet"
        );

        let watch = base.join("watched");
        fs::create_dir_all(&watch).unwrap();
        let rules = r#"
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
"#;
        let rs = RuleSet::compile(parse_rule_file(rules, "test").unwrap()).unwrap();
        let engine =
            litric_core::engine::Engine::new(rs, ThreatDb::empty(), EngineConfig::default());
        let mut cfg = litric_monitor::MonitorConfig::new(vec![watch.clone()]);
        cfg.debounce = std::time::Duration::from_millis(250);
        cfg.log_path = Some(state.data_dir.join("realtime-events.jsonl"));
        cfg.exclude.push(state.data_dir.clone());
        let monitor = litric_monitor::Monitor::start(
            Arc::new(litric_pipeline::Pipeline::new(engine)),
            state.vault.clone(),
            cfg,
        )
        .unwrap();
        state.set_realtime(Arc::new(monitor));

        let sample = watch.join("invoice.com");
        fs::write(
            &sample,
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();
        let started = std::time::Instant::now();
        while state.vault.list().is_empty() && started.elapsed() < std::time::Duration::from_secs(15) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(state.vault.list().len(), 1, "EICAR was not quarantined in real time");
        assert!(!sample.exists(), "the original must be gone after the verified vault write");

        let r = dispatch(&state, "GET", "/api/v1/status", b"");
        assert_eq!(r.body["real_time_protection"], true, "{}", r.to_json());
        assert_eq!(r.body["state"], "realtime_user_mode", "{}", r.to_json());
        assert_eq!(r.body["capabilities"]["realtime_file_monitor"], true);
        // still no blocking, no kernel sensor: those must not flip
        assert_eq!(r.body["capabilities"]["real_time_file_blocking"], false);
        assert_eq!(r.body["capabilities"]["kernel_sensor"], false);
        assert_eq!(r.body["realtime"]["stats"]["quarantined"], 1);
        assert_eq!(r.body["quarantine_entries"], 1);

        let ev = dispatch(&state, "GET", "/api/v1/realtime/events?limit=10", b"");
        assert_eq!(ev.status, 200);
        assert!(
            ev.body["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["event"] == "quarantined"),
            "{}",
            ev.to_json()
        );

        state.realtime().unwrap().shutdown();
        let r = dispatch(&state, "GET", "/api/v1/status", b"");
        assert_eq!(r.body["real_time_protection"], false, "a stopped monitor is not protection");
        assert_eq!(r.body["state"], "limited");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_requested_but_failed_monitor_shows_its_error_instead_of_a_green_state() {
        let (state, base) = test_state("realtime-error");
        state.set_realtime_error("no watchable directories".into());
        let r = dispatch(&state, "GET", "/api/v1/status", b"");
        assert_eq!(r.body["real_time_protection"], false);
        assert_eq!(r.body["state"], "limited");
        assert_eq!(r.body["realtime"]["error"], "no watchable directories");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn scan_job_runs_and_reports_detection() {
        let (state, base) = test_state("scan");
        // Fixtures live in their own directory: the state directory also holds the
        // vault key and settings, which are files and would be scanned too.
        let target = base.join("target");
        fs::create_dir_all(&target).unwrap();
        fs::write(
            target.join("eicar.com"),
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();
        fs::write(target.join("notes.txt"), b"harmless\n").unwrap();

        let body = serde_json::to_vec(&json!({ "path": target.display().to_string(), "profile": "quick" }))
            .unwrap();
        let r = dispatch(&state, "POST", "/api/v1/scan", &body);
        assert_eq!(r.status, 202, "body: {}", r.to_json());
        let id = r.body["job_id"].as_str().unwrap().to_string();

        let mut final_state = String::new();
        for _ in 0..200 {
            let poll = dispatch(&state, "GET", &format!("/api/v1/scans/{id}"), b"");
            final_state = poll.body["state"].as_str().unwrap_or("").to_string();
            if final_state == "completed" || final_state == "failed" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert_eq!(final_state, "completed");
        let poll = dispatch(&state, "GET", &format!("/api/v1/scans/{id}"), b"");
        assert_eq!(poll.body["files_scanned"], 2);
        assert_eq!(poll.body["malicious"], 1);
        assert_eq!(poll.body["unknown"], 1);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn scan_rejects_missing_path() {
        let (state, base) = test_state("missing");
        let body = serde_json::to_vec(&json!({ "path": "/definitely/not/here" })).unwrap();
        let r = dispatch(&state, "POST", "/api/v1/scan", &body);
        assert_eq!(r.status, 400);
        let _ = fs::remove_dir_all(&base);
    }

    fn wait_for_job(state: &AppState, id: &str) -> Value {
        for _ in 0..400 {
            let poll = dispatch(state, "GET", &format!("/api/v1/scans/{id}"), b"");
            let status = poll.body["state"].as_str().unwrap_or("");
            if status == "completed" || status == "failed" || status == "cancelled" {
                return poll.body;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("scan job did not reach a terminal state");
    }

    #[test]
    fn scan_auto_quarantines_only_malicious_and_is_repeatable() {
        let (state, base) = test_state_with(
            "autoq",
            trusted_db(b"trusted clean fixture"),
            Arc::new(PlatformSignatureVerifier),
        );
        let target = base.join("target");
        fs::create_dir_all(target.join("nested")).unwrap();
        let bad = target.join("nested/eicar.com");
        let clean = target.join("clean.txt");
        let unknown = target.join("notes.txt");
        fs::write(
            &bad,
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();
        fs::write(&clean, b"trusted clean fixture").unwrap();
        fs::write(&unknown, b"unknown but harmless fixture").unwrap();

        let body = serde_json::to_vec(&json!({
            "path": target.display().to_string(),
            "profile": "quick",
            "quarantine_malicious": true
        }))
        .unwrap();
        let r = dispatch(&state, "POST", "/api/v1/scan", &body);
        assert_eq!(r.status, 202, "{}", r.to_json());
        let id = r.body["job_id"].as_str().unwrap().to_string();
        let job = wait_for_job(&state, &id);
        assert_eq!(job["state"], "completed", "{job}");
        assert_eq!(job["malicious"], 1, "{job}");
        assert_eq!(job["clean"], 1, "{job}");
        assert_eq!(job["unknown"], 1, "{job}");
        assert_eq!(job["quarantined"], 1, "{job}");
        assert_eq!(job["quarantine_failures"], 0, "{job}");
        assert!(!bad.exists(), "malicious file must move");
        assert_eq!(fs::read(&clean).unwrap(), b"trusted clean fixture");
        assert_eq!(fs::read(&unknown).unwrap(), b"unknown but harmless fixture");
        assert_eq!(state.vault.list().len(), 1);

        // Second run: the moved file is gone. It must complete with no crash
        // and must not touch the retained files.
        let r = dispatch(&state, "POST", "/api/v1/scan", &body);
        assert_eq!(r.status, 202, "{}", r.to_json());
        let id = r.body["job_id"].as_str().unwrap().to_string();
        let job = wait_for_job(&state, &id);
        assert_eq!(job["state"], "completed", "{job}");
        assert_eq!(job["files_scanned"], 2, "{job}");
        assert_eq!(job["malicious"], 0, "{job}");
        assert_eq!(job["quarantine"]["failures"], 0, "{job}");
        assert_eq!(fs::read(&clean).unwrap(), b"trusted clean fixture");
        assert_eq!(fs::read(&unknown).unwrap(), b"unknown but harmless fixture");
        assert_eq!(state.vault.list().len(), 1);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn quarantine_add_list_restore() {
        let (state, base) = test_state("quarantine");
        let sample = base.join("bad.bin");
        fs::write(&sample, b"malicious bytes").unwrap();

        let body = serde_json::to_vec(&json!({
            "path": sample.display().to_string(),
            "copy_only": false
        }))
        .unwrap();
        let r = dispatch(&state, "POST", "/api/v1/quarantine", &body);
        assert_eq!(r.status, 202, "{}", r.to_json());
        let id = r.body["id"].as_str().unwrap().to_string();
        assert!(!sample.exists());

        let list = dispatch(&state, "GET", "/api/v1/quarantine", b"");
        assert_eq!(list.body["entries"].as_array().unwrap().len(), 1);

        let dest = base.join("restored.bin");
        let rbody = serde_json::to_vec(&json!({ "dest": dest.display().to_string() })).unwrap();
        let r = dispatch(&state, "POST", &format!("/api/v1/quarantine/{id}/restore"), &rbody);
        assert_eq!(r.status, 200, "{}", r.to_json());
        assert_eq!(fs::read(&dest).unwrap(), b"malicious bytes");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn quarantine_api_defaults_to_copy_and_never_deletes_the_original() {
        let (state, base) = test_state("qcopy");
        let sample = base.join("user-data.bin");
        fs::write(&sample, b"irreplaceable user bytes").unwrap();

        let body = serde_json::to_vec(&json!({ "path": sample.display().to_string() })).unwrap();
        let r = dispatch(&state, "POST", "/api/v1/quarantine", &body);
        assert_eq!(r.status, 202, "{}", r.to_json());
        assert_eq!(r.body["original_removed"], false, "{}", r.to_json());
        assert_eq!(
            fs::read(&sample).unwrap(),
            b"irreplaceable user bytes",
            "a request without copy_only:false must not remove the source"
        );
        assert_eq!(state.vault.list().len(), 1, "the verified copy is still evidence");
        let _ = fs::remove_dir_all(&base);
    }

    struct DigestBoundVerifier {
        trusted_sha256: String,
    }

    impl SignatureVerifier for DigestBoundVerifier {
        fn verify(&self, path: &Path) -> SignatureTrust {
            let ok = fs::read(path)
                .map(|bytes| {
                    litric_core::hash::sha256_bytes(&bytes).to_hex() == self.trusted_sha256
                })
                .unwrap_or(false);
            if ok {
                SignatureTrust::Valid
            } else {
                SignatureTrust::Invalid
            }
        }
    }

    #[test]
    fn safeos_assess_trusts_an_allowlisted_chain_valid_entry() {
        let trusted = b"trusted fixture bytes";
        let digest = litric_core::hash::sha256_bytes(trusted).to_hex();
        let (state, base) = test_state_with(
            "trusted",
            trusted_db(trusted),
            Arc::new(DigestBoundVerifier {
                trusted_sha256: digest,
            }),
        );
        let sample = base.join("trusted.bin");
        fs::write(&sample, trusted).unwrap();
        let body = serde_json::to_vec(&json!({ "path": sample.display().to_string() })).unwrap();
        let r = dispatch(&state, "POST", "/api/v1/safeos/assess", &body);
        assert_eq!(r.status, 200, "{}", r.to_json());
        assert_eq!(r.body["signature_chain_valid"], true, "{}", r.to_json());
        assert_eq!(r.body["level_name"], "trusted", "{}", r.to_json());
        assert_eq!(r.body["action"], "run_on_host", "{}", r.to_json());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn safeos_assess_does_not_trust_tampered_or_unsigned_input() {
        let trusted = b"trusted fixture bytes";
        let digest = litric_core::hash::sha256_bytes(trusted).to_hex();
        let (state, base) = test_state_with(
            "tampered",
            trusted_db(trusted),
            Arc::new(DigestBoundVerifier {
                trusted_sha256: digest,
            }),
        );
        let sample = base.join("tampered.bin");
        fs::write(&sample, b"tampered fixture bytes").unwrap();
        let body = serde_json::to_vec(&json!({ "path": sample.display().to_string() })).unwrap();
        let r = dispatch(&state, "POST", "/api/v1/safeos/assess", &body);
        assert_eq!(r.status, 200, "{}", r.to_json());
        assert_eq!(r.body["signature_chain_valid"], false, "{}", r.to_json());
        assert_ne!(r.body["level_name"], "trusted", "{}", r.to_json());
        let _ = fs::remove_dir_all(&base);

        let (unsigned_state, unsigned_base) = test_state("unsigned");
        let unsigned = unsigned_base.join("unsigned.bin");
        fs::write(&unsigned, b"unsigned fixture bytes").unwrap();
        let body = serde_json::to_vec(&json!({ "path": unsigned.display().to_string() })).unwrap();
        let r = dispatch(
            &unsigned_state,
            "POST",
            "/api/v1/safeos/assess",
            &body,
        );
        assert_eq!(r.status, 200, "{}", r.to_json());
        assert_eq!(r.body["signature_chain_valid"], false, "{}", r.to_json());
        assert_ne!(r.body["level_name"], "trusted", "{}", r.to_json());
        let _ = fs::remove_dir_all(&unsigned_base);

        // Allowlisting alone must not grant trust when the platform verifier
        // cannot validate a chain.
        let (allowlisted_state, allowlisted_base) = test_state_with(
            "allowlisted-unsigned",
            trusted_db(trusted),
            Arc::new(PlatformSignatureVerifier),
        );
        let allowlisted = allowlisted_base.join("allowlisted.bin");
        fs::write(&allowlisted, trusted).unwrap();
        let body = serde_json::to_vec(&json!({ "path": allowlisted.display().to_string() })).unwrap();
        let r = dispatch(
            &allowlisted_state,
            "POST",
            "/api/v1/safeos/assess",
            &body,
        );
        assert_eq!(r.status, 200, "{}", r.to_json());
        assert_eq!(r.body["signature_chain_valid"], false, "{}", r.to_json());
        assert_ne!(r.body["level_name"], "trusted", "{}", r.to_json());
        let _ = fs::remove_dir_all(&allowlisted_base);
    }

    #[test]
    fn safeos_assess_surfaces_lifecycle_expired_build() {
        let (state, base) = test_state("expired-build");
        {
            let mut slot = state.host_facts.lock().unwrap();
            *slot = Some(HostFacts {
                known: true,
                windows_edition: "Windows 11 Pro".into(),
                windows_build: 26_100,
                virtualization_enabled: true,
                hyperv_feature_present: true,
                sandbox_feature_present: true,
                total_ram_mb: 16 * 1024,
                free_disk_mb: 100 * 1024,
                logical_cpus: 8,
                existing_nat_networks: 0,
                nat_query_ok: true,
                wsl_switches: 1,
                docker_switches: 1,
            });
        }
        let sample = base.join("notes.txt");
        fs::write(&sample, b"just notes\n").unwrap();
        let body = serde_json::to_vec(&json!({ "path": sample.display().to_string() })).unwrap();
        let r = dispatch(&state, "POST", "/api/v1/safeos/assess", &body);
        assert_eq!(r.status, 200, "{}", r.to_json());
        let blockers = r.body["system_readiness"]["blockers"]
            .as_array()
            .expect("blockers");
        let build = blockers
            .iter()
            .find(|b| b["component"] == "windows_build")
            .expect("windows_build blocker");
        assert!(build["reason"].as_str().unwrap().contains("24H2"));
        assert!(build["reason"].as_str().unwrap().contains("end of support"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn readiness_gate_refuses_to_claim_ready() {
        let (state, base) = test_state("readiness");
        let r = dispatch(&state, "GET", "/api/v1/readiness", b"");
        assert_eq!(r.status, 503, "{}", r.to_json());
        assert_eq!(r.body["production_ready"], false);
        let caps = r.body["capabilities"].as_object().unwrap();
        assert_eq!(
            caps["safeos_sandbox_guest_runtime"]["state"],
            "UNPROVEN"
        );
        assert!(matches!(
            caps["safeos_sandbox_launch"]["state"].as_str(),
            Some("UNPROVEN") | Some("BLOCKED")
        ));
        let tested = [
            "on_demand_scan",
            "quarantine",
            "safeos_risk_assessment",
            "safeos_fail_closed_policy",
            "safeos_sandbox_config",
            "test_suite_windows_execution",
            "quarantine_windows_filesystem_semantics",
        ];
        for (id, cap) in caps {
            if cap["state"] == "READY" {
                assert!(tested.contains(&id.as_str()), "unproven READY: {id}");
            }
        }

        assert_eq!(caps["test_suite_windows_execution"]["state"], "READY");
        assert_eq!(
            caps["quarantine_windows_filesystem_semantics"]["state"],
            "READY"
        );
        assert_eq!(
            r.body["test_evidence"]["windows_suite_execution"],
            "READY"
        );
        assert!(
            r.body["test_evidence"]["windows_excluded_tests"]
                .as_array()
                .map(|t| t.is_empty())
                .unwrap_or(false),
            "the Windows-only suite must not exclude tests"
        );

        let status = dispatch(&state, "GET", "/api/v1/status", b"");
        assert_eq!(status.body["readiness"]["production_ready"], false);
        let health = dispatch(&state, "GET", "/api/v1/health", b"");
        assert_eq!(health.body["protection_ready"], false);

        let sample = base.join("plain.txt");
        fs::write(&sample, b"hello").unwrap();
        let body = serde_json::to_vec(&json!({ "path": sample.display().to_string() })).unwrap();
        let assess = dispatch(&state, "POST", "/api/v1/safeos/assess", &body);
        assert_eq!(assess.status, 200, "{}", assess.to_json());
        assert_eq!(assess.body["system_readiness"]["production_ready"], false);
        assert_eq!(
            assess.body["system_readiness"]["sandbox_guest_runtime"],
            "UNPROVEN"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn quarantine_http_errors_are_actionable() {
        let (state, base) = test_state("qerrors");
        let sample = base.join("sample.bin");
        fs::write(&sample, b"sample").unwrap();
        let body = serde_json::to_vec(&json!({ "path": sample.display().to_string() })).unwrap();
        let add = dispatch(&state, "POST", "/api/v1/quarantine", &body);
        assert_eq!(add.status, 202, "{}", add.to_json());
        let id = add.body["id"].as_str().unwrap().to_string();

        let occupied = base.join("keep.bin");
        fs::write(&occupied, b"keep").unwrap();
        let body = serde_json::to_vec(&json!({ "dest": occupied.display().to_string() })).unwrap();
        let r = dispatch(
            &state,
            "POST",
            &format!("/api/v1/quarantine/{id}/restore"),
            &body,
        );
        assert_eq!(r.status, 409, "{}", r.to_json());
        assert!(r.body["error"]
            .as_str()
            .unwrap_or("")
            .contains("refusing to overwrite"));
        assert_eq!(fs::read(&occupied).unwrap(), b"keep");

        let r = dispatch(
            &state,
            "DELETE",
            &format!("/api/v1/quarantine/{id}?confirm=true"),
            b"",
        );
        assert_eq!(r.status, 200, "{}", r.to_json());
        let r = dispatch(
            &state,
            "POST",
            &format!("/api/v1/quarantine/{id}/restore"),
            b"{}",
        );
        assert_eq!(r.status, 404, "{}", r.to_json());
        assert!(r.body["error"]
            .as_str()
            .unwrap_or("")
            .contains("no quarantine entry"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn purge_requires_confirmation() {
        let (state, base) = test_state("purge");
        let sample = base.join("x.bin");
        fs::write(&sample, b"x").unwrap();
        let body = serde_json::to_vec(&json!({ "path": sample.display().to_string() })).unwrap();
        let r = dispatch(&state, "POST", "/api/v1/quarantine", &body);
        let id = r.body["id"].as_str().unwrap().to_string();

        let denied = dispatch(&state, "DELETE", &format!("/api/v1/quarantine/{id}"), b"");
        assert_eq!(denied.status, 400);
        let allowed = dispatch(
            &state,
            "DELETE",
            &format!("/api/v1/quarantine/{id}?confirm=true"),
            b"",
        );
        assert_eq!(allowed.status, 200);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn settings_are_persisted() {
        let (state, base) = test_state("settings");
        let body = serde_json::to_vec(&json!({ "eco_mode": true, "retention_days": 5 })).unwrap();
        let r = dispatch(&state, "PUT", "/api/v1/settings", &body);
        assert_eq!(r.status, 200, "{}", r.to_json());
        assert_eq!(r.body["settings"]["eco_mode"], true);

        let reloaded = litric_service_store_reload(&base);
        assert!(reloaded.settings.eco_mode);
        assert_eq!(reloaded.settings.retention_days, 5);
        let _ = fs::remove_dir_all(&base);
    }

    fn litric_service_store_reload(base: &std::path::Path) -> crate::store::Store {
        crate::store::Store::open(&base.join("data")).unwrap()
    }

    #[test]
    fn ranshield_decoy_ingestion_is_critical() {
        let (state, base) = test_state("ranshield");
        let body = serde_json::to_vec(&json!({
            "process": { "pid": 4242, "image": "C:\\Temp\\evil.exe", "signed": false },
            "events": [
                { "type": "decoy", "pid": 4242, "decoy": "decoy-0-1" }
            ]
        }))
        .unwrap();
        let r = dispatch(&state, "POST", "/api/v1/ranshield/events", &body);
        assert_eq!(r.status, 200, "{}", r.to_json());
        assert_eq!(r.body["level"], "critical");
        assert!(r.body["highest_score"].as_u64().unwrap() >= 100);
        let actions = r.body["assessments"][0]["actions"].as_array().unwrap();
        assert!(actions.iter().any(|a| a == "suspend-process"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn unknown_route_is_404() {
        let (state, base) = test_state("route");
        let r = dispatch(&state, "GET", "/api/v1/nope", b"");
        assert_eq!(r.status, 404);
        let _ = fs::remove_dir_all(&base);
    }
}
