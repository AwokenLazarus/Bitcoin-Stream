//! The HTTP server: tiny_http on a few threads, requests reduced to [`Req`], answers as [`Resp`]
//! with the security headers on every response.
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use crate::app::App;

pub const MAX_BODY: usize = 256 * 1024;

pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; \
                       form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

#[derive(Debug, Default, Clone)]
pub struct Req {
    pub method: String,
    /// The path below the base path, starting with `/` (`/`, `/approvals`, ...).
    pub path: String,
    pub query: HashMap<String, String>,
    /// Lower-case names.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub peer: String,
}

impl Req {
    pub fn header(&self, k: &str) -> &str {
        self.headers.get(k).map(String::as_str).unwrap_or("")
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        self.header("cookie").split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
    }

    pub fn form(&self) -> HashMap<String, String> {
        parse_qs(&String::from_utf8_lossy(&self.body))
    }
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn html(status: u16, body: String) -> Self {
        Self { status, headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())], body: body.into_bytes() }
    }

    pub fn text(status: u16, ctype: &str, body: impl Into<Vec<u8>>) -> Self {
        Self { status, headers: vec![("Content-Type".into(), ctype.into())], body: body.into() }
    }

    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self::text(status, "application/json", v.to_string())
    }

    /// 303 to a relative location (`./approvals`).
    pub fn redirect(to: &str) -> Self {
        Self { status: 303, headers: vec![("Location".into(), to.into())], body: vec![] }
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}

fn hexval(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match (hexval(b[i + 1]), hexval(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push(h * 16 + l);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_qs(s: &str) -> HashMap<String, String> {
    s.split('&').filter(|p| !p.is_empty()).map(|p| {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        (url_decode(k), url_decode(v))
    }).collect()
}

/// Strip the base path; `None` when the path is outside it.
pub fn strip_base(path: &str, base: &str) -> Option<String> {
    if base == "/" {
        return Some(path.to_string());
    }
    let b = base.trim_end_matches('/');
    if path == b {
        return Some(String::new()); // the bare prefix: redirected to "prefix/"
    }
    path.strip_prefix(b).filter(|r| r.starts_with('/')).map(str::to_string).or_else(|| Some(path.to_string()))
}

pub fn security_headers(r: &mut Resp) {
    for (k, v) in [("Content-Security-Policy", CSP), ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"),
                   ("Referrer-Policy", "no-referrer"), ("Cross-Origin-Opener-Policy", "same-origin"),
                   ("Cross-Origin-Resource-Policy", "same-origin"), ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()")] {
        r.headers.push((k.into(), v.into()));
    }
    if !r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Cache-Control")) {
        r.headers.push(("Cache-Control".into(), "no-store".into()));
    }
}

fn serve_one(app: &App, mut rq: tiny_http::Request) {
    let peer = rq.remote_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let url = rq.url().to_string();
    let (raw_path, q) = url.split_once('?').unwrap_or((&url, ""));
    let mut headers = HashMap::new();
    for h in rq.headers() {
        headers.insert(h.field.as_str().as_str().to_ascii_lowercase(), h.value.as_str().to_string());
    }
    let mut body = Vec::new();
    let too_big = rq.body_length().is_some_and(|n| n > MAX_BODY) || {
        let _ = rq.as_reader().take(MAX_BODY as u64 + 1).read_to_end(&mut body);
        body.len() > MAX_BODY
    };
    let mut resp = if too_big {
        Resp::text(413, "text/plain", "request too large")
    } else {
        let req = Req { method: rq.method().as_str().to_uppercase(), path: raw_path.to_string(), query: parse_qs(q), headers, body, peer };
        app.handle(req)
    };
    security_headers(&mut resp);
    let mut out = tiny_http::Response::from_data(resp.body).with_status_code(resp.status);
    for (k, v) in resp.headers {
        if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            out.add_header(h);
        }
    }
    let _ = rq.respond(out);
}

/// A running server (tests); stops when dropped.
pub struct Running {
    pub addr: std::net::SocketAddr,
    server: Arc<tiny_http::Server>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

pub fn spawn(app: Arc<App>) -> Result<Running, String> {
    let server = Arc::new(tiny_http::Server::http(&app.cfg.bind).map_err(|e| format!("bind {}: {e}", app.cfg.bind))?);
    let addr = server.server_addr().to_ip().ok_or("not an IP listener")?;
    for _ in 0..app.cfg.threads.max(1) {
        let (s, a) = (server.clone(), app.clone());
        std::thread::spawn(move || {
            while let Ok(rq) = s.recv() {
                serve_one(&a, rq);
            }
        });
    }
    Ok(Running { addr, server })
}
