//! Thin HTTP client for the Litric daemon (`litricd`).
//!
//! Design rules:
//!
//! * **No fallback.** If the daemon is unreachable or the token is missing or
//!   rejected, the client returns an actionable error. It never silently scans
//!   in-process instead.
//! * **No business logic.** The daemon decides verdicts; this module formats
//!   them. Rendering is separated from transport so the wording of terminal
//!   states (limited / cancelled / failed) is unit-testable.
//! * **Bounded.** Connect timeout, read timeout, and a hard response cap.

use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

/// Maximum response size accepted from the daemon (8 MiB).
const MAX_RESPONSE: u64 = 8 * 1024 * 1024;

/// Why a client call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Nothing is listening at the configured address.
    NotRunning,
    /// The token file is missing/unreadable, or the daemon rejected the token.
    Unauthorized,
    /// The daemon answered with a 4xx/5xx status.
    Rejected,
    /// The daemon sent something that is not valid HTTP/JSON.
    Protocol,
    /// Transport failure other than "not listening".
    Io,
}

/// A client failure with a message written for the person at the terminal.
#[derive(Debug)]
pub struct ClientError {
    pub kind: ErrorKind,
    pub message: String,
}

impl ClientError {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        ClientError {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ClientError {}

/// Connection settings for the daemon.
#[derive(Debug, Clone)]
pub struct Client {
    addr: String,
    token: String,
    token_path: PathBuf,
}

impl Client {
    pub fn new(addr: impl Into<String>, token: impl Into<String>, token_path: PathBuf) -> Self {
        Client {
            addr: addr.into(),
            token: token.into(),
            token_path,
        }
    }

    /// Resolves the address and token from flags, environment, then defaults.
    ///
    /// A missing token is an error, not a reason to run the engine locally: the
    /// operator needs to know the service is not set up.
    pub fn discover(addr: Option<&str>, token_file: Option<&Path>) -> Result<Self, ClientError> {
        let addr = addr
            .map(|s| s.to_string())
            .or_else(|| std::env::var("LITRIC_ADDR").ok())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "127.0.0.1:8787".to_string());

        let token_path = token_file
            .map(|p| p.to_path_buf())
            .or_else(|| std::env::var("LITRIC_TOKEN_FILE").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("litric-data").join("api.token"));

        let raw = std::fs::read_to_string(&token_path).map_err(|e| {
            ClientError::new(
                ErrorKind::Unauthorized,
                format!(
                    "cannot read the API token at {}: {e}\n\
                     The Litric daemon creates this file when it starts. Start it with:\n  \
                     litricd serve --data-dir ./litric-data\n\
                     or point the client at the right file with --token-file <path> \
                     (or LITRIC_TOKEN_FILE).",
                    token_path.display()
                ),
            )
        })?;
        let token = raw.trim().to_string();
        if token.len() < 16 {
            return Err(ClientError::new(
                ErrorKind::Unauthorized,
                format!(
                    "the API token file {} looks empty or truncated.\n\
                     Regenerate it with: litricd token --token-file {}",
                    token_path.display(),
                    token_path.display()
                ),
            ));
        }
        Ok(Client {
            addr,
            token,
            token_path,
        })
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn token_path(&self) -> &Path {
        &self.token_path
    }

    // --- API surface -----------------------------------------------------

    pub fn status(&self) -> Result<Value, ClientError> {
        self.request("GET", "/api/v1/status", None)
    }

    pub fn health(&self) -> Result<Value, ClientError> {
        self.request("GET", "/api/v1/health", None)
    }

    pub fn analyze(&self, path: &str) -> Result<Value, ClientError> {
        self.post("/api/v1/analyze", &json!({ "path": path }))
    }

    pub fn start_scan(&self, path: &str, profile: &str) -> Result<Value, ClientError> {
        self.post(
            "/api/v1/scan",
            &json!({ "path": path, "profile": profile }),
        )
    }

    pub fn scan_job(&self, id: &str) -> Result<Value, ClientError> {
        self.request("GET", &format!("/api/v1/scans/{id}"), None)
    }

    pub fn cancel_scan(&self, id: &str) -> Result<Value, ClientError> {
        self.post(&format!("/api/v1/scans/{id}/cancel"), &json!({}))
    }

    pub fn quarantine_list(&self) -> Result<Value, ClientError> {
        self.request("GET", "/api/v1/quarantine", None)
    }

    pub fn quarantine_add(&self, path: &str, threat: &str) -> Result<Value, ClientError> {
        self.post(
            "/api/v1/quarantine",
            &json!({ "path": path, "threat": threat }),
        )
    }

    pub fn quarantine_restore(
        &self,
        id: &str,
        dest: Option<&Path>,
    ) -> Result<Value, ClientError> {
        let body = match dest {
            Some(d) => json!({ "dest": d.display().to_string() }),
            None => json!({}),
        };
        self.post(&format!("/api/v1/quarantine/{id}/restore"), &body)
    }

    pub fn quarantine_verify(&self) -> Result<Value, ClientError> {
        self.request("GET", "/api/v1/quarantine/verify", None)
    }

    pub fn quarantine_purge(&self, id: &str) -> Result<Value, ClientError> {
        self.request(
            "DELETE",
            &format!("/api/v1/quarantine/{id}?confirm=true"),
            None,
        )
    }

    pub fn ranshield_state(&self) -> Result<Value, ClientError> {
        self.request("GET", "/api/v1/ranshield", None)
    }

    pub fn safeos_status(&self) -> Result<Value, ClientError> {
        self.request("GET", "/api/v1/safeos/status", None)
    }

    pub fn safeos_assess(&self, path: &str) -> Result<Value, ClientError> {
        self.post("/api/v1/safeos/assess", &json!({ "path": path }))
    }

    pub fn safeos_launch(&self, path: &str, wait: bool) -> Result<Value, ClientError> {
        self.post(
            &format!("/api/v1/safeos/launch?wait={wait}"),
            &json!({ "path": path }),
        )
    }

    // --- transport -------------------------------------------------------

    fn post(&self, path: &str, body: &Value) -> Result<Value, ClientError> {
        self.request("POST", path, Some(body.to_string()))
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<Value, ClientError> {
        let body = body.unwrap_or_default();
        let stream = self.connect()?;
        let mut stream = stream;

        let request = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Authorization: Bearer {token}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            host = self.addr,
            token = self.token,
            len = body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| ClientError::new(ErrorKind::Io, format!("failed to send request: {e}")))?;

        let mut raw = Vec::new();
        let mut limited = stream.take(MAX_RESPONSE);
        limited
            .read_to_end(&mut raw)
            .map_err(|e| ClientError::new(ErrorKind::Io, format!("failed to read response: {e}")))?;

        let (code, text) = parse_response(&raw)?;
        if code == 401 {
            return Err(ClientError::new(
                ErrorKind::Unauthorized,
                format!(
                    "the daemon at {} rejected the API token from {}.\n\
                     The token does not match the running daemon. Read the current one with:\n  \
                     litricd token --token-file {}\n\
                     or restart the daemon and pass the matching --token-file.",
                    self.addr,
                    self.token_path.display(),
                    self.token_path.display()
                ),
            ));
        }
        if !(200..300).contains(&code) {
            let detail = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| text.chars().take(300).collect());
            return Err(ClientError::new(
                ErrorKind::Rejected,
                format!("daemon rejected {method} {path} (HTTP {code}): {detail}"),
            ));
        }
        serde_json::from_str(&text).map_err(|e| {
            ClientError::new(
                ErrorKind::Protocol,
                format!("daemon returned invalid JSON ({e}); is {path} really a litricd API?"),
            )
        })
    }

    fn connect(&self) -> Result<TcpStream, ClientError> {
        let addrs = self.addr.to_socket_addrs().map_err(|e| {
            ClientError::new(
                ErrorKind::Io,
                format!("`{}` is not a valid host:port pair: {e}", self.addr),
            )
        })?;
        let mut last: Option<std::io::Error> = None;
        for sa in addrs {
            match TcpStream::connect_timeout(&sa, Duration::from_secs(5)) {
                Ok(stream) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
                    return Ok(stream);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(ClientError::new(
            ErrorKind::NotRunning,
            format!(
                "cannot reach the Litric daemon at {}: {}\n\
                 Nothing is listening there. Start the service with:\n  \
                 litricd serve --addr {} --data-dir ./litric-data\n\
                 Then retry. To scan without a daemon, pass --local (standalone mode).",
                self.addr,
                last.map(|e| e.to_string())
                    .unwrap_or_else(|| "no addresses resolved".into()),
                self.addr
            ),
        ))
    }
}

/// Parses an HTTP/1.1 response into (status code, body text).
pub fn parse_response(raw: &[u8]) -> Result<(u16, String), ClientError> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            ClientError::new(
                ErrorKind::Protocol,
                "daemon returned a malformed HTTP response (no header terminator)",
            )
        })?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let body_raw = &raw[split + 4..];

    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| {
            ClientError::new(
                ErrorKind::Protocol,
                format!("daemon returned an unparsable status line: `{status_line}`"),
            )
        })?;

    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim();
            if key == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
            if key == "content-length" {
                content_length = value.parse().ok();
            }
        }
    }

    let body = if chunked {
        decode_chunked(body_raw)
    } else if let Some(n) = content_length {
        body_raw[..n.min(body_raw.len())].to_vec()
    } else {
        body_raw.to_vec()
    };
    Ok((code, String::from_utf8_lossy(&body).to_string()))
}

fn decode_chunked(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(line_end) = data.windows(2).position(|w| w == b"\r\n") {
        let size_line = String::from_utf8_lossy(&data[..line_end]).to_string();
        let size_hex = size_line.split(';').next().unwrap_or("0").trim();
        let size = usize::from_str_radix(size_hex, 16).unwrap_or(0);
        data = &data[line_end + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            out.extend_from_slice(data);
            break;
        }
        out.extend_from_slice(&data[..size]);
        data = data.get(size + 2..).unwrap_or(&[]);
    }
    out
}

// ---------------------------------------------------------------------------
// Rendering. Kept separate from transport so terminal states are testable.
// ---------------------------------------------------------------------------

/// Human-readable status. Never prints "protected" unless the daemon says so.
pub fn render_status(v: &Value) -> String {
    let mut s = String::new();
    let state = v["state"].as_str().unwrap_or("unknown");
    let realtime = v["real_time_protection"].as_bool().unwrap_or(false);
    s.push_str(&format!(
        "{} {} (engine {})\n",
        v["product"].as_str().unwrap_or("Litric Defender"),
        v["engine_version"].as_str().unwrap_or("?"),
        v["engine_version"].as_str().unwrap_or("?")
    ));
    s.push_str(&format!("state        : {state}\n"));
    if realtime {
        s.push_str("real-time    : ACTIVE\n");
    } else {
        s.push_str("real-time    : NOT ACTIVE\n");
    }
    if let Some(reason) = v["state_reason"].as_str() {
        for line in wrap(reason, 66) {
            s.push_str(&format!("reason       : {line}\n"));
        }
    }
    s.push_str(&format!(
        "rules        : {}\n",
        v["rules_loaded"].as_u64().unwrap_or(0)
    ));
    let db = &v["threat_database"];
    s.push_str(&format!(
        "threat db    : v{} ({}), {} hashes\n",
        db["version"].as_u64().unwrap_or(0),
        db["trust"].as_str().unwrap_or("unknown"),
        db["hashes"].as_u64().unwrap_or(0)
    ));
    s.push_str(&format!(
        "quarantine   : {} entr{}\n",
        v["quarantine_entries"].as_u64().unwrap_or(0),
        if v["quarantine_entries"].as_u64().unwrap_or(0) == 1 {
            "y"
        } else {
            "ies"
        }
    ));
    if let Some(jobs) = v.get("jobs") {
        s.push_str(&format!(
            "jobs         : {} known, {} running\n",
            jobs["known"].as_u64().unwrap_or(0),
            jobs["running"].as_u64().unwrap_or(0)
        ));
    }
    if let Some(caps) = v["capabilities"].as_object() {
        let mut entries: Vec<(&String, &Value)> = caps.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let unavailable: Vec<String> = entries
            .iter()
            .filter(|(_, v)| v.as_bool() == Some(false))
            .map(|(k, _)| (*k).clone())
            .collect();
        if !unavailable.is_empty() {
            s.push_str(&format!(
                "not available: {}\n",
                unavailable.join(", ")
            ));
        }
    }
    s
}

/// Human-readable job state. `cancelled` and `failed` are stated plainly.
pub fn render_job(v: &Value) -> String {
    let id = v["job_id"].as_str().unwrap_or("?");
    let state = v["state"].as_str().unwrap_or("unknown");
    let files = v["files_scanned"].as_u64().unwrap_or(0);
    let mut s = String::new();
    match state {
        "completed" => {
            s.push_str(&format!(
                "scan {id}: completed — {files} file(s) in {} ms\n",
                v["duration_ms"].as_u64().unwrap_or(0)
            ));
            s.push_str(&format!(
                "  clean {}  unknown {}  suspicious {}  malicious {}\n",
                v["clean"].as_u64().unwrap_or(0),
                v["unknown"].as_u64().unwrap_or(0),
                v["suspicious"].as_u64().unwrap_or(0),
                v["malicious"].as_u64().unwrap_or(0)
            ));
            let skipped = v["skipped"].as_u64().unwrap_or(0);
            let unreadable = v["unreadable"].as_u64().unwrap_or(0);
            if skipped > 0 || unreadable > 0 {
                s.push_str(&format!(
                    "  skipped {skipped}  unreadable {unreadable}\n"
                ));
            }
        }
        "cancelled" => {
            s.push_str(&format!(
                "scan {id}: CANCELLED — {files} file(s) were inspected before cancellation\n"
            ));
        }
        "failed" => {
            s.push_str(&format!(
                "scan {id}: FAILED — {}\n",
                v["error"].as_str().unwrap_or("the daemon did not report a reason")
            ));
        }
        other => {
            s.push_str(&format!("scan {id}: {other} — {files} file(s) so far\n"));
        }
    }
    if let Some(detections) = v["detections"].as_array() {
        for d in detections {
            s.push_str(&format!(
                "  [{:>10}] {}  ({})\n",
                d["verdict"].as_str().unwrap_or("?").to_uppercase(),
                d["path"].as_str().unwrap_or("?"),
                d["threat"].as_str().unwrap_or("unclassified")
            ));
        }
    }
    if files > 0 && v["unknown"].as_u64().unwrap_or(0) > 0 {
        s.push_str(&format!(
            "  note: {} file(s) are UNKNOWN, not clean\n",
            v["unknown"].as_u64().unwrap_or(0)
        ));
    }
    s
}

pub fn render_quarantine(v: &Value) -> String {
    let entries = v["entries"].as_array();
    match entries {
        None => "quarantine: daemon did not return an entry list\n".to_string(),
        Some(list) if list.is_empty() => "quarantine is empty\n".to_string(),
        Some(list) => {
            let mut s = format!("{} quarantined object(s)\n", list.len());
            for e in list {
                s.push_str(&format!(
                    "  {}  {:<28} {}  ({} bytes)\n",
                    e["id"].as_str().unwrap_or("?"),
                    e["threat_name"].as_str().unwrap_or("-"),
                    e["original_path"].as_str().unwrap_or("?"),
                    e["size"].as_u64().unwrap_or(0)
                ));
                s.push_str(&format!(
                    "      sha256 {}\n",
                    e["sha256"].as_str().unwrap_or("?")
                ));
            }
            s
        }
    }
}

pub fn render_analysis(v: &Value) -> String {
    let mut s = String::new();
    s.push_str(&format!("file        : {}\n", v["path"].as_str().unwrap_or("?")));
    s.push_str(&format!("sha256      : {}\n", v["sha256"].as_str().unwrap_or("?")));
    s.push_str(&format!(
        "content     : {} (extension .{})\n",
        v["format"].as_str().unwrap_or("?"),
        v["extension"].as_str().unwrap_or("")
    ));
    s.push_str(&format!(
        "verdict     : {} (score {}/100, confidence {:.2})\n",
        v["verdict"].as_str().unwrap_or("unknown").to_uppercase(),
        v["score"].as_u64().unwrap_or(0),
        v["confidence"].as_f64().unwrap_or(0.0)
    ));
    if let Some(t) = v["threat"].as_str() {
        s.push_str(&format!("threat      : {t}\n"));
    }
    if let Some(f) = v["family"].as_str() {
        s.push_str(&format!("family      : {f}\n"));
    }
    if let Some(mitre) = v["mitre"].as_array() {
        if !mitre.is_empty() {
            let ids: Vec<&str> = mitre.iter().filter_map(|m| m.as_str()).collect();
            s.push_str(&format!("mitre       : {}\n", ids.join(", ")));
        }
    }
    if let Some(signals) = v["signals"].as_array() {
        if !signals.is_empty() {
            s.push_str("evidence:\n");
            for sig in signals {
                s.push_str(&format!(
                    "  [{:>3}] {}\n        {}\n",
                    sig["weight"].as_u64().unwrap_or(0),
                    sig["title"].as_str().unwrap_or("?"),
                    sig["detail"].as_str().unwrap_or("")
                ));
            }
        }
    }
    if let Some(rules) = v["rules"].as_array() {
        for r in rules {
            s.push_str(&format!(
                "matched rule: {} [{}] {}\n",
                r["name"].as_str().unwrap_or("?"),
                r["severity"].as_str().unwrap_or("?"),
                r["description"].as_str().unwrap_or("")
            ));
        }
    }
    for note in v["notes"].as_array().into_iter().flatten() {
        if let Some(n) = note.as_str() {
            s.push_str(&format!("note        : {n}\n"));
        }
    }
    s
}

pub fn render_safeos_status(v: &Value) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "state        : {}\n",
        v["state"].as_str().unwrap_or("unknown")
    ));
    s.push_str(&format!(
        "host facts   : {}\n",
        if v["host_facts_known"].as_bool().unwrap_or(false) {
            format!(
                "{} build {}",
                v["host_facts"]["windows_edition"].as_str().unwrap_or("?"),
                v["host_facts"]["windows_build"].as_u64().unwrap_or(0)
            )
        } else {
            "NOT COLLECTED (run litric-agent on Windows)".to_string()
        }
    ));
    if let Some(backends) = v["backends"].as_array() {
        s.push_str("backends:\n");
        for b in backends {
            s.push_str(&format!(
                "  {:<18} {:<12} host supports: {:<3} ({})\n",
                b["kind"].as_str().unwrap_or("?"),
                if b["available"].as_bool().unwrap_or(false) {
                    "available"
                } else {
                    "UNAVAILABLE"
                },
                if b["host_supported"].as_bool().unwrap_or(false) {
                    "yes"
                } else {
                    "no"
                },
                b["reason"].as_str().unwrap_or("")
            ));
        }
    }
    if let Some(blockers) = v["blockers"].as_array() {
        for b in blockers {
            s.push_str(&format!(
                "blocker      : {} — {}\n",
                b["component"].as_str().unwrap_or("?"),
                b["reason"].as_str().unwrap_or("")
            ));
            if let Some(r) = b["remediation"].as_str() {
                s.push_str(&format!("               fix: {r}\n"));
            }
        }
    }
    s.push_str(&format!(
        "sandbox launch: {}\n",
        if v["windows_sandbox_launch_implemented"].as_bool().unwrap_or(false) {
            "implemented"
        } else {
            "NOT IMPLEMENTED (configuration only)"
        }
    ));
    s
}

pub fn render_safeos_assessment(v: &Value) -> String {
    let mut s = String::new();
    s.push_str(&format!("file        : {}\n", v["path"].as_str().unwrap_or("?")));
    s.push_str(&format!(
        "level       : {} ({})  confidence {:.2}\n",
        v["level"].as_u64().unwrap_or(0),
        v["level_name"].as_str().unwrap_or("unknown"),
        v["confidence"].as_f64().unwrap_or(0.0)
    ));
    s.push_str(&format!(
        "verdict     : {} (score {})\n",
        v["verdict"].as_str().unwrap_or("unknown"),
        v["score"].as_u64().unwrap_or(0)
    ));
    s.push_str(&format!(
        "action      : {}\n",
        v["action"].as_str().unwrap_or("deny")
    ));
    s.push_str(&format!(
        "rationale   : {}\n",
        v["rationale"].as_str().unwrap_or("")
    ));
    for r in v["reasons"].as_array().into_iter().flatten() {
        if let Some(r) = r.as_str() {
            s.push_str(&format!("reason      : {r}\n"));
        }
    }
    for e in v["evidence"].as_array().into_iter().flatten() {
        if let Some(e) = e.as_str() {
            s.push_str(&format!("evidence    : {e}\n"));
        }
    }
    if let Some(r) = v["remediation"].as_str() {
        s.push_str(&format!("remediation : {r}\n"));
    }
    s
}

pub fn render_safeos_launch(v: &Value) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "sandbox      : started (pid {})\n",
        v["pid"].as_u64().unwrap_or(0)
    ));
    s.push_str(&format!(
        "config       : {}\n",
        v["config_path"].as_str().unwrap_or("?")
    ));
    s.push_str(&format!(
        "command      : {}\n",
        v["command"].as_str().unwrap_or("?")
    ));
    if let Some(code) = v["exit_code"].as_i64() {
        s.push_str(&format!("exit code    : {code}\n"));
    }
    s.push_str(&format!(
        "verified     : {}\n",
        if v["launch_verified"].as_bool().unwrap_or(false) {
            "yes (checked on this host)"
        } else {
            "NO — manual checklist not completed yet"
        }
    ));
    if let Some(note) = v["note"].as_str() {
        s.push_str(&format!("note         : {note}\n"));
    }
    s
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if line.len() + word.len() + 1 > width && !line.is_empty() {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
        // Content-Length 15 covers the JSON exactly.
        let (code, body) = parse_response(raw).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, "{\"status\":\"ok\"}");
    }

    #[test]
    fn parses_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1}\r\n0\r\n\r\n";
        let (code, body) = parse_response(raw).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, "{\"a\":1}");
    }

    #[test]
    fn rejects_malformed_response() {
        let e = parse_response(b"garbage without headers").unwrap_err();
        assert_eq!(e.kind, ErrorKind::Protocol);
    }

    #[test]
    fn status_rendering_never_invents_protection() {
        let v = json!({
            "product": "Litric Defender",
            "engine_version": "0.1.0",
            "state": "limited",
            "real_time_protection": false,
            "state_reason": "Real-time blocking is NOT active.",
            "rules_loaded": 15,
            "threat_database": { "version": 0, "trust": "Unsigned", "hashes": 0 },
            "quarantine_entries": 0,
            "jobs": { "known": 0, "running": 0 },
            "capabilities": { "on_demand_scan": true, "real_time_file_blocking": false }
        });
        let text = render_status(&v);
        assert!(text.contains("limited"));
        assert!(text.contains("NOT ACTIVE"));
        assert!(!text.contains("ACTIVE\n") | text.contains("NOT ACTIVE"));
        assert!(text.contains("real_time_file_blocking"));
        assert!(!text.contains("state        : protected"));
    }

    #[test]
    fn cancelled_and_failed_are_stated_plainly() {
        let cancelled = json!({
            "job_id": "scan-1", "state": "cancelled", "files_scanned": 42,
            "detections": []
        });
        let text = render_job(&cancelled);
        assert!(text.contains("CANCELLED"));
        assert!(text.contains("42"));

        let failed = json!({
            "job_id": "scan-2", "state": "failed", "files_scanned": 0, "error": "disk vanished"
        });
        let text = render_job(&failed);
        assert!(text.contains("FAILED"));
        assert!(text.contains("disk vanished"));
    }

    #[test]
    fn completed_job_lists_detections() {
        let v = json!({
            "job_id": "scan-3",
            "state": "completed",
            "files_scanned": 3,
            "clean": 0, "unknown": 1, "suspicious": 0, "malicious": 2,
            "duration_ms": 12, "skipped": 0, "unreadable": 0,
            "detections": [
                { "verdict": "malicious", "path": "/tmp/eicar.com", "threat": "Test.EICAR" }
            ]
        });
        let text = render_job(&v);
        assert!(text.contains("completed"));
        assert!(text.contains("malicious 2"));
        assert!(text.contains("Test.EICAR"));
        assert!(text.contains("UNKNOWN, not clean"));
    }

    #[test]
    fn quarantine_rendering_handles_empty_and_entries() {
        assert!(render_quarantine(&json!({"entries": []})).contains("empty"));
        let text = render_quarantine(&json!({"entries": [{
            "id": "abc", "threat_name": "Test.EICAR", "original_path": "/tmp/x",
            "size": 68, "sha256": "aa"
        }]}));
        assert!(text.contains("abc"));
        assert!(text.contains("Test.EICAR"));
    }

    #[test]
    fn missing_token_file_is_actionable() {
        let addr = Some("127.0.0.1:1");
        let path = PathBuf::from("/nonexistent/litric/api.token");
        let e = Client::discover(addr, Some(&path)).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Unauthorized);
        assert!(e.message.contains("cannot read the API token"));
        assert!(e.message.contains("litricd serve"));
    }
}
