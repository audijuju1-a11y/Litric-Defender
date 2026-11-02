//! HTTP transport: loopback-only listener, bearer authentication, bounded bodies.
//!
//! The transport is intentionally boring: a small HTTP server on 127.0.0.1 with a
//! single bearer token. No TLS (loopback), no cookies, no CORS, no sessions.

use std::io::Read;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tiny_http::{Header, Response, Server, StatusCode};

use crate::{api, token_matches, AppState};

/// Maximum accepted request body.
pub const MAX_BODY: usize = 1024 * 1024;

/// Handle to a running API server.
pub struct ServerHandle {
    pub addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl ServerHandle {
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::SeqCst)
    }
}

/// Starts the API server on `addr` (for example `127.0.0.1:8787`).
pub fn serve(
    state: Arc<AppState>,
    addr: &str,
) -> Result<ServerHandle, Box<dyn std::error::Error + Send + Sync>> {
    let server = Server::http(addr)?;
    let bound = server
        .server_addr()
        .to_ip()
        .ok_or("listener address is not an IP address")?;
    if !bound.ip().is_loopback() {
        return Err(format!(
            "refusing to bind {bound}: the Litric control API is loopback-only"
        )
        .into());
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    std::thread::Builder::new()
        .name("litric-api".into())
        .spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match server.recv_timeout(Duration::from_millis(200)) {
                    Ok(Some(request)) => handle(&state, request),
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        })?;

    Ok(ServerHandle { addr: bound, shutdown })
}

fn handle(state: &Arc<AppState>, mut request: tiny_http::Request) {
    // 1. Peer must be loopback.
    if let Some(remote) = request.remote_addr() {
        if !remote.ip().is_loopback() {
            respond(request, 403, json!({ "error": "loopback clients only" }));
            return;
        }
    }
    let method = format!("{}", request.method());
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();

    // 2. Bearer token, except for the health probe.
    let authorized = if path == "/api/v1/health" {
        true
    } else {
        request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
            .map(|t| token_matches(&state.token, t))
            .unwrap_or(false)
    };
    if !authorized {
        respond(
            request,
            401,
            json!({ "error": "missing or invalid bearer token" }),
        );
        return;
    }

    // 3. Bounded body.
    let mut body = Vec::new();
    {
        // `as_reader` yields `&mut dyn Read`, which is unsized; borrow the local
        // binding instead so the `Read` blanket impl for `&mut R` applies.
        let mut reader = request.as_reader();
        let mut limited = (&mut reader).take((MAX_BODY + 1) as u64);
        if limited.read_to_end(&mut body).is_err() {
            respond(request, 400, json!({ "error": "could not read request body" }));
            return;
        }
    }
    if body.len() > MAX_BODY {
        respond(request, 413, json!({ "error": "request body too large" }));
        return;
    }

    // 4. Dispatch.
    let response = api::dispatch(state, &method, &url, &body);
    respond(request, response.status, response.body);
}

fn respond(request: tiny_http::Request, status: u16, body: Value) {
    let text = body.to_string();
    let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("static header");
    let no_store = Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..])
        .expect("static header");
    let response = Response::from_string(text)
        .with_status_code(StatusCode(status))
        .with_header(content_type)
        .with_header(no_store);
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::*;
    use litric_core::engine::{Engine, EngineConfig};
    use litric_core::quarantine::QuarantineVault;
    use litric_core::rules::RuleSet;
    use litric_core::threatdb::ThreatDb;
    use std::io::Write;
    use std::net::TcpStream;
    use std::path::PathBuf;

    fn state(tag: &str) -> (Arc<AppState>, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "litric-srv-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let engine = Engine::new(RuleSet::empty(), ThreatDb::empty(), EngineConfig::default());
        let vault =
            QuarantineVault::open(&base.join("q"), &base.join("vault.key")).unwrap();
        let st = AppState::new(engine, vault, &base.join("data"), "secret-token-123".into())
            .unwrap();
        (st, base)
    }

    fn request(addr: SocketAddr, path: &str, token: Option<&str>) -> String {
        let mut stream = TcpStream::connect(addr).expect("connect");
        let auth = token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn rejects_missing_token_and_accepts_valid_one() {
        let (st, base) = state("auth");
        let handle = serve(st, "127.0.0.1:0").expect("server starts");
        assert!(handle.is_running());

        let unauth = request(handle.addr, "/api/v1/status", None);
        assert!(unauth.starts_with("HTTP/1.1 401"), "got: {unauth}");

        let wrong = request(handle.addr, "/api/v1/status", Some("nope"));
        assert!(wrong.starts_with("HTTP/1.1 401"), "got: {wrong}");

        let good = request(handle.addr, "/api/v1/status", Some("secret-token-123"));
        assert!(good.starts_with("HTTP/1.1 200"), "got: {good}");
        assert!(good.contains("\"state\":\"limited\""));

        // Health is intentionally unauthenticated for readiness probes.
        let health = request(handle.addr, "/api/v1/health", None);
        assert!(health.starts_with("HTTP/1.1 200"), "got: {health}");

        handle.shutdown();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn refuses_non_loopback_bind() {
        let (st, base) = state("bind");
        let result = serve(st, "0.0.0.0:0");
        assert!(result.is_err(), "binding to 0.0.0.0 must be refused");
        let _ = std::fs::remove_dir_all(&base);
    }
}
