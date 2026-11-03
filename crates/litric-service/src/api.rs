//! HTTP routing and handlers for the Litric local API.
//!
//! `dispatch` is a pure function of (state, method, url, body). That keeps the
//! whole API testable without sockets, and means authentication/transport bugs
//! cannot hide inside business logic.

use std::path::PathBuf;
use std::sync::atomic::Ordering;

use litric_core::ranshield::{Assessment, FsEvent, Level, ProcessContext};
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
        ("GET", ["api", "v1", "ranshield"]) => ok(ranshield_json(state)),
        ("POST", ["api", "v1", "ranshield", "events"]) => ranshield_events(state, body),
        ("GET", ["api", "v1", "safeos", "status"]) => ok(safeos_status()),
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
        "threat_database": true,
        "behavioural_ransomware_engine": true,
        "archive_recursion": false,
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
        "safeos_windows_sandbox_launch": false,
        "safeos_hyperv_backend": false,
        "safeos_network_gateway": false
    })
}

fn health_json(state: &AppState) -> Value {
    let (jobs_known, jobs_running) = state.jobs.counts();
    json!({
        "status": "ok",
        "product": "Litric Defender",
        "engine_version": litric_core::ENGINE_VERSION,
        "uptime_seconds": state.started.elapsed().as_secs(),
        "jobs_known": jobs_known,
        "jobs_running": jobs_running,
    })
}

fn status_json(state: &AppState) -> Value {
    let cap = capabilities();
    let realtime_active = cap["real_time_file_blocking"].as_bool().unwrap_or(false);
    let latest = state.jobs.list().into_iter().next();
    let (jobs_known, jobs_running) = state.jobs.counts();
    let quarantined = state.vault.list().len();
    let history_len = state.store.lock().map(|s| s.history.len()).unwrap_or(0);

    json!({
        "product": "Litric Defender",
        "engine": litric_core::ENGINE_NAME,
        "engine_version": litric_core::ENGINE_VERSION,
        "state": if realtime_active { "protected" } else { "limited" },
        "state_reason": if realtime_active {
            "All configured protection components are running."
        } else {
            "On-demand scanning, quarantine and behavioural analysis are active. \
             Real-time blocking is NOT active: it requires a Microsoft-signed kernel \
             file-system sensor, which this build does not include. Litric is not \
             replacing Microsoft Defender on this host."
        },
        "real_time_protection": realtime_active,
        "realtime_requested_by_user": state.realtime_requested,
        "capabilities": cap,
        "rules_loaded": state.engine.rules().len(),
        "threat_database": threat_db_json(state),
        "quarantine_entries": quarantined,
        "history_entries": history_len,
        "jobs": { "known": jobs_known, "running": jobs_running },
        "last_scan": latest.map(|j| job_json(&j)),
        "uptime_seconds": state.started.elapsed().as_secs(),
    })
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

        jobs.update(&id, |job| {
            job.state = if cancelled {
                JobState::Cancelled
            } else {
                JobState::Completed
            };
            job.finished_unix = Some(now_unix());
            job.summary = Some(summary);
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
fn safeos_status() -> Value {
    let facts = HostFacts::unknown();
    let readiness = Readiness::evaluate(&facts);
    json!({
        "state": "unavailable",
        "host_facts_known": facts.known,
        "platform_agent": "not implemented: no Windows platform agent reports host facts",
        "backends": backend_status(&facts)
            .iter()
            .map(|b| json!({
                "kind": b.kind,
                "available": b.available,
                "reason": b.reason,
                "requires_windows": b.requires_windows,
            }))
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
        "windows_sandbox_launch_implemented": litric_safeos::sandbox::LAUNCH_IMPLEMENTED,
        "hyperv_backend_implemented": false,
        "network_gateway_implemented": false,
    })
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

    let facts = ApplicationFacts {
        verdict: report.verdict.as_str().to_string(),
        score: report.score,
        confidence: report.confidence,
        signature_present: report
            .pe
            .as_ref()
            .map(|p| !p.signers.is_empty())
            .unwrap_or(false),
        // Chain validation requires WinVerifyTrust and is not implemented here.
        signature_chain_valid: false,
        hash_trust,
    };
    let assessment = assess(&facts);
    let decision = decide(assessment.level, &BackendSet::none());

    ok(json!({
        "path": path.display().to_string(),
        "sha256": report.sha256.to_hex(),
        "verdict": report.verdict.as_str(),
        "score": report.score,
        "level": assessment.level.number(),
        "level_name": assessment.level.as_str(),
        "confidence": assessment.confidence,
        "rationale": assessment.rationale,
        "evidence": assessment.evidence,
        "action": decision.action.as_str(),
        "reasons": decision.reasons,
        "remediation": decision.remediation,
        "isolation_available": false,
        "note": "no isolation backend is present in this build; the decision is fail-closed",
    }))
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
    let copy_only = v["copy_only"].as_bool().unwrap_or(false);

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
        Err(e) => err(500, format!("restore failed: {e}")),
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
        Err(e) => err(500, format!("purge failed: {e}")),
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
    use litric_core::engine::EngineConfig;
    use litric_core::quarantine::QuarantineVault;
    use litric_core::rules::{parse_rule_file, RuleSet};
    use litric_core::threatdb::ThreatDb;
    use std::fs;

    fn test_state(tag: &str) -> (std::sync::Arc<AppState>, PathBuf) {
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
        let engine = litric_core::engine::Engine::new(rs, ThreatDb::empty(), EngineConfig::default());
        let vault = QuarantineVault::open(&base.join("quarantine"), &base.join("vault.key")).unwrap();
        let state = AppState::new(engine, vault, &base.join("data"), "test-token".into()).unwrap();
        (state, base)
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

    #[test]
    fn quarantine_add_list_restore() {
        let (state, base) = test_state("quarantine");
        let sample = base.join("bad.bin");
        fs::write(&sample, b"malicious bytes").unwrap();

        let body = serde_json::to_vec(&json!({ "path": sample.display().to_string() })).unwrap();
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
