//! The two MCP transports: stdio (newline-delimited JSON-RPC; Claude Code, Hermes, OpenClaw) and
//! streamable HTTP (one endpoint; POST answers with `application/json`, GET is 405 because this server
//! never pushes, DELETE ends a session). Blocking threads, no async runtime.
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tiny_http::{Header, Method, Response, StatusCode};

use crate::mcp::{Server, Session, SUPPORTED};

/// Serve MCP over stdin/stdout until stdin closes. Tool calls run on their own threads (a paid call
/// can wait for a funding confirmation) while pings and lists are answered at once.
pub fn serve_stdio(server: Arc<Server>) {
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let sess = Arc::new(Mutex::new(Session::default()));
    let send = |out: &Mutex<std::io::Stdout>, v: &Value| {
        let mut o = out.lock().unwrap_or_else(|p| p.into_inner());
        let _ = writeln!(o, "{}", serde_json::to_string(v).unwrap_or_default());
        let _ = o.flush();
    };
    let mut workers = vec![];
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = xbt402::json::parse(&line) else { continue };
        if Server::is_slow(&msg) {
            // the session as it is when the call arrives (an initialize read later must not count)
            let mut s = sess.lock().unwrap_or_else(|p| p.into_inner()).clone();
            let (server, out) = (server.clone(), out.clone());
            workers.push(std::thread::spawn(move || {
                if let Some(r) = server.handle(&mut s, &msg) {
                    send(&out, &r);
                }
            }));
            workers.retain(|w| !w.is_finished());
        } else {
            let mut s = sess.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(r) = server.handle(&mut s, &msg) {
                send(&out, &r);
            }
        }
    }
    for w in workers {
        let _ = w.join();
    }
}

/// The readiness probe behind `GET /readyz`: ready or not, and a JSON status.
pub type ReadyFn = Arc<dyn Fn() -> (bool, Value) + Send + Sync>;

/// Settings of the HTTP transport.
#[derive(Clone)]
pub struct HttpConfig {
    /// `host:port` to listen on (loopback unless `allow_remote`).
    pub addr: String,
    /// The MCP endpoint path (default `/mcp`).
    pub path: String,
    /// When set, every request needs `Authorization: Bearer <token>`.
    pub token: Option<String>,
    /// When set, the token is this file, read on every request and never written: the UI owns it and
    /// rotates it on its Agents page, so a rotation takes effect at once, with no restart (AGP-042). An
    /// unreadable or empty file refuses every request (it never falls back to `token`). The MCP has no
    /// rotation endpoint: a bearer token must not be able to replace itself.
    pub token_file: Option<PathBuf>,
    pub allow_remote: bool,
    /// A path prefix a reverse proxy keeps (`XBT_BASE_PATH`): `<base>/mcp`, `<base>/healthz`. Requests
    /// without it are served too, for proxies that strip it.
    pub base: String,
    /// `GET /readyz`; `None`: ready whenever the process serves.
    pub ready: Option<ReadyFn>,
}

impl HttpConfig {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into(), path: "/mcp".into(), token: None, token_file: None, allow_remote: false, base: String::new(), ready: None }
    }
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConfig").field("addr", &self.addr).field("path", &self.path).field("token", &self.token.as_ref().map(|_| "<set>"))
            .field("allow_remote", &self.allow_remote).field("base", &self.base).finish()
    }
}

const MAX_SESSIONS: usize = 256;
const MAX_BODY: usize = 1 << 20;

fn is_loopback_host(h: &str) -> bool {
    let host = if let Some(rest) = h.strip_prefix('[') { rest.split(']').next().unwrap_or("") } else { h.split(':').next().unwrap_or("") };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn header<'a>(req: &'a tiny_http::Request, name: &str) -> Option<&'a str> {
    req.headers().iter().find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name)).map(|h| h.value.as_str())
}

fn hdr(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("ascii header")
}

fn reply(req: tiny_http::Request, status: u16, body: String, extra: &[(&str, String)]) {
    let mut r = Response::from_string(body).with_status_code(StatusCode(status));
    r.add_header(hdr("Content-Type", "application/json"));
    for (k, v) in extra {
        r.add_header(hdr(k, v));
    }
    let _ = req.respond(r);
}

fn rpc_error(code: i64, msg: &str) -> String {
    serde_json::json!({"jsonrpc": "2.0", "id": null, "error": {"code": code, "message": msg}}).to_string()
}

fn new_session_id() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("OS randomness");
    hex::encode(b)
}

/// Constant-time comparison for the bearer token.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The token in force: the token file when there is one (fail closed: `Err` when it cannot be read),
/// else the configured value.
fn live_token(cfg: &HttpConfig) -> Result<Option<String>, String> {
    let Some(p) = &cfg.token_file else { return Ok(cfg.token.clone()) };
    read_token_file(p).map(Some)
}

/// Read the token file: a regular file (not a symlink), no bits for others, not empty.
pub fn read_token_file(p: &std::path::Path) -> Result<String, String> {
    let md = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if !md.file_type().is_file() {
        return Err(format!("{}: not a regular file", p.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if md.permissions().mode() & 0o007 != 0 {
            return Err(format!("{}: readable by others; refused", p.display()));
        }
    }
    let t = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?.trim().to_string();
    if t.is_empty() {
        return Err(format!("{}: empty", p.display()));
    }
    Ok(t)
}

type Sessions = Arc<Mutex<HashMap<String, (Session, std::time::Instant)>>>;

fn handle_http(server: &Server, cfg: &HttpConfig, sessions: &Sessions, mut req: tiny_http::Request) {
    let raw = req.url().split('?').next().unwrap_or("").to_string();
    let path = xbt_svc::proxy::strip_base(&raw, &cfg.base).unwrap_or(raw);
    // health probes (Docker HEALTHCHECK, Umbrel, StartOS): no token, no session, nothing secret
    if matches!(path.as_str(), "/healthz" | "/readyz") && matches!(req.method(), Method::Get | Method::Head) {
        if path == "/healthz" {
            return reply(req, 200, serde_json::json!({"ok": true, "service": "xbt-wallet-mcp"}).to_string(), &[]);
        }
        let (ok, status) = cfg.ready.as_ref().map(|f| f()).unwrap_or((true, serde_json::json!({})));
        let mut body = serde_json::json!({"ok": ok, "service": "xbt-wallet-mcp"});
        if let (Some(b), Value::Object(m)) = (body.as_object_mut(), status) {
            b.extend(m);
        }
        body["ok"] = ok.into();
        return reply(req, if ok { 200 } else { 503 }, body.to_string(), &[]);
    }
    if path != cfg.path {
        return reply(req, 404, rpc_error(-32600, "Not found"), &[]);
    }
    // DNS rebinding: a browser page elsewhere must not reach a loopback wallet
    if let Some(o) = header(&req, "Origin") {
        let host = o.split("://").nth(1).unwrap_or("");
        if !cfg.allow_remote && !is_loopback_host(host) {
            return reply(req, 403, rpc_error(-32600, "Forbidden origin"), &[]);
        }
    }
    let want = match live_token(cfg) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("xbt-wallet-mcp: bearer token: {e}");
            return reply(req, 503, rpc_error(-32603, "the bearer token is unavailable"), &[]);
        }
    };
    if let Some(t) = want {
        let got = header(&req, "Authorization").and_then(|a| a.strip_prefix("Bearer ")).unwrap_or("");
        if !same(got, &t) {
            return reply(req, 401, rpc_error(-32600, "Unauthorized"), &[("WWW-Authenticate", "Bearer".into())]);
        }
    }
    if let Some(v) = header(&req, "MCP-Protocol-Version").map(str::to_string) {
        if !SUPPORTED.contains(&v.as_str()) {
            return reply(req, 400, rpc_error(-32600, &format!("Unsupported protocol version: {v}")), &[]);
        }
    }
    let sid = header(&req, "Mcp-Session-Id").map(str::to_string);
    match req.method() {
        Method::Get => return reply(req, 405, rpc_error(-32600, "Method not allowed: this server sends no server-initiated messages"),
                                    &[("Allow", "POST, DELETE".into())]),
        Method::Delete => {
            let gone = sid.as_ref().is_some_and(|s| sessions.lock().unwrap_or_else(|p| p.into_inner()).remove(s).is_some());
            return reply(req, if gone { 200 } else { 404 }, String::new(), &[]);
        }
        Method::Post => {}
        _ => return reply(req, 405, rpc_error(-32600, "Method not allowed"), &[("Allow", "POST, DELETE".into())]),
    }
    let mut body = Vec::new();
    if std::io::Read::read_to_end(&mut std::io::Read::take(req.as_reader(), MAX_BODY as u64 + 1), &mut body).is_err() || body.len() > MAX_BODY {
        return reply(req, 413, rpc_error(-32600, "Request too large"), &[]);
    }
    let Ok(msg) = xbt402::json::parse_slice(&body) else {
        return reply(req, 400, rpc_error(-32700, "Parse error"), &[]);
    };
    if !msg.is_object() {
        return reply(req, 400, rpc_error(-32600, "Invalid Request: one JSON-RPC message per POST"), &[]);
    }
    let is_init = msg.get("method").and_then(Value::as_str) == Some("initialize");
    let (mut sess, sid) = if is_init {
        (Session::default(), new_session_id())
    } else {
        let Some(sid) = sid else { return reply(req, 400, rpc_error(-32600, "Bad Request: Mcp-Session-Id header is required"), &[]) };
        let g = sessions.lock().unwrap_or_else(|p| p.into_inner());
        let Some((s, _)) = g.get(&sid) else { return reply(req, 404, rpc_error(-32600, "Session not found"), &[]) };
        (s.clone(), sid)
    };
    let out = server.handle(&mut sess, &msg);
    if is_init && sess.initialized {
        let mut g = sessions.lock().unwrap_or_else(|p| p.into_inner());
        if g.len() >= MAX_SESSIONS {
            if let Some(old) = g.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| k.clone()) {
                g.remove(&old);
            }
        }
        g.insert(sid.clone(), (sess, std::time::Instant::now()));
    }
    let extra = [("Mcp-Session-Id", sid)];
    match out {
        Some(r) => reply(req, 200, r.to_string(), &extra),
        None => reply(req, 202, String::new(), &extra),
    }
}

/// Serve MCP over streamable HTTP until the process ends; one thread per request.
pub fn serve_http(server: Arc<Server>, cfg: HttpConfig) -> Result<(), String> {
    let host = cfg.addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(&cfg.addr);
    if !cfg.allow_remote && !is_loopback_host(host) {
        return Err(format!("{}: not a loopback address (pass --http-allow-remote with XBT_MCP_HTTP_TOKEN to listen elsewhere)", cfg.addr));
    }
    if cfg.allow_remote && !matches!(live_token(&cfg), Ok(Some(_))) {
        return Err("--http-allow-remote needs XBT_MCP_HTTP_TOKEN".into());
    }
    let http = tiny_http::Server::http(&cfg.addr).map_err(|e| format!("{}: {e}", cfg.addr))?;
    eprintln!("xbt-wallet-mcp: streamable HTTP on http://{}{}{} (health: /healthz, /readyz)", cfg.addr, xbt_svc::proxy::normalize_base(&cfg.base), cfg.path);
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let cfg = Arc::new(cfg);
    for req in http.incoming_requests() {
        let (server, cfg, sessions) = (server.clone(), cfg.clone(), sessions.clone());
        std::thread::spawn(move || handle_http(&server, &cfg, &sessions, req));
    }
    Ok(())
}
