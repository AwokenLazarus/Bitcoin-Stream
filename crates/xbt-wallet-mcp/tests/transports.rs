//! The binary over both transports, in front of a recording mock signer (B2's socket protocol):
//! the tool surface, the forbidden tools, key material, signer errors, and streamable HTTP's
//! sessions, status codes, origin check and bearer token.
#![cfg(unix)]
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use xbt_wallet_mcp::mcp::{FORBIDDEN, TOOL_NAMES};

const BIN: &str = env!("CARGO_BIN_EXE_xbt-wallet-mcp");
const WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

/// A signer that records every request and answers with key-bearing probe results.
fn mock_signer(dir: &Path) -> (PathBuf, Arc<Mutex<Vec<Value>>>) {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let seen = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut line = String::new();
            BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            s2.lock().unwrap().push(req.clone());
            let resp = if req["params"]["to"] == "err" {
                json!({"id": 1, "error": {"message": "boom"}})
            } else {
                json!({"id": 1, "result": {"method": req["method"], "params": req["params"], "hot_privkey": "aa", "note": WIF,
                                           "untrusted_provider_response": {"body": WIF}}})
            };
            let _ = c.write_all(format!("{resp}\n").as_bytes());
        }
    });
    (sock, seen)
}

fn init_msg(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "initialize",
           "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
}

struct Stdio_ {
    child: Child,
    out: BufReader<std::process::ChildStdout>,
}

impl Stdio_ {
    fn start(sock: &Path) -> Self {
        let mut child = Command::new(BIN).env_clear().env("B2_SIGNER_SOCK", sock).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(Stdio::null()).spawn().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Self { child, out }
    }

    fn send(&mut self, m: &Value) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{m}").unwrap();
    }

    fn ask(&mut self, m: Value) -> Value {
        self.send(&m);
        let mut line = String::new();
        self.out.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn call(&mut self, id: u64, name: &str, args: Value) -> Value {
        self.ask(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}}))["result"].clone()
    }
}

#[test]
fn stdio_surface_safety_and_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, seen) = mock_signer(dir.path());
    let mut s = Stdio_::start(&sock);
    let init = s.ask(init_msg(1));
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "xbt-agent-wallet");
    s.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    let tools = s.ask(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let names: Vec<&str> = tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, TOOL_NAMES);
    for f in FORBIDDEN {
        assert!(!names.contains(&f));
        let r = s.call(3, f, json!({}));
        assert_eq!(r, json!({"content": [{"type": "text", "text": format!("Unknown tool: {f}")}], "isError": true}));
    }
    // a call: forwarded with its defaults, key-named fields dropped, key-shaped strings redacted,
    // the provider's untrusted body kept verbatim
    let r = s.call(4, "xbt402_pay", json!({"url": "http://x/y", "max_sats": "7"}));
    assert_eq!(r["isError"], false);
    let text = r["content"][0]["text"].as_str().unwrap();
    assert_eq!(r["structuredContent"]["result"], text);
    let v: Value = serde_json::from_str(text).unwrap();
    assert!(v.get("hot_privkey").is_none());
    assert_eq!(v["note"], "[redacted]");
    assert_eq!(v["untrusted_provider_response"]["body"], WIF);
    assert_eq!(v["params"], json!({"url": "http://x/y", "method": "GET", "body": "", "max_sats": 7}));
    assert_eq!(seen.lock().unwrap().last().unwrap()["method"], "xbt402_pay");
    // a signer error reaches the model only as B2's generic line
    let r = s.call(5, "pay", json!({"to": "err", "amount_xbt": 1}));
    assert_eq!(r["content"][0]["text"], "Error executing tool pay");
    assert_eq!(r["isError"], true);
    // a validation error never reaches the signer
    let n = seen.lock().unwrap().len();
    let r = s.call(6, "history", json!({"limit": 5.5}));
    assert!(r["content"][0]["text"].as_str().unwrap().starts_with("Error executing tool history: 1 validation error for historyArguments"));
    assert_eq!(seen.lock().unwrap().len(), n);
    drop(s.child.stdin.take());
    let _ = s.child.wait();
}

struct Http {
    child: Child,
    base: String,
}

impl Drop for Http {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn http(sock: &Path, port: u16, token: Option<&str>) -> Http {
    let mut cmd = Command::new(BIN);
    cmd.env_clear().env("B2_SIGNER_SOCK", sock).args(["--http", &format!("127.0.0.1:{port}")]).stdout(Stdio::null()).stderr(Stdio::null());
    if let Some(t) = token {
        cmd.env("XBT_MCP_HTTP_TOKEN", t);
    }
    let child = cmd.spawn().unwrap();
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Http { child, base: format!("http://127.0.0.1:{port}/mcp") }
}

/// (status, Mcp-Session-Id, body)
fn req(method: &str, url: &str, body: Option<&Value>, headers: &[(&str, &str)]) -> (u16, Option<String>, String) {
    let mut r = ureq::request(method, url).set("Accept", "application/json, text/event-stream");
    for (k, v) in headers {
        r = r.set(k, v);
    }
    let resp = match body {
        Some(b) => r.set("Content-Type", "application/json").send_string(&b.to_string()),
        None => r.call(),
    };
    let resp = match resp {
        Ok(x) => x,
        Err(ureq::Error::Status(_, x)) => x,
        Err(e) => panic!("{e}"),
    };
    let (st, sid) = (resp.status(), resp.header("Mcp-Session-Id").map(str::to_string));
    let mut s = String::new();
    resp.into_reader().read_to_string(&mut s).unwrap();
    (st, sid, s)
}

// ports: AGP-030's range 33500-33599
#[test]
fn streamable_http_sessions_and_guards() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _) = mock_signer(dir.path());
    let h = http(&sock, 33591, None);
    // AGP-063 X1: no token configured: one is generated next to the signer socket, and required
    let tok = std::fs::read_to_string(dir.path().join("mcp-http-token")).unwrap().trim().to_string();
    let auth = format!("Bearer {tok}");
    let a = ("Authorization", auth.as_str());
    assert_eq!(req("POST", &h.base, Some(&init_msg(1)), &[]).0, 401);
    let (st, sid, body) = req("POST", &h.base, Some(&init_msg(1)), &[a]);
    assert_eq!(st, 200);
    let sid = sid.expect("session id");
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["result"]["serverInfo"]["name"], "xbt-agent-wallet");
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    assert_eq!(req("POST", &h.base, Some(&list), &[a]).0, 400); // no session
    assert_eq!(req("POST", &h.base, Some(&list), &[a, ("Mcp-Session-Id", "nope")]).0, 404);
    let (st, _, body) = req("POST", &h.base, Some(&list), &[a, ("Mcp-Session-Id", &sid), ("MCP-Protocol-Version", "2025-06-18")]);
    assert_eq!(st, 200);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["result"]["tools"].as_array().unwrap().len(), 10);
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    assert_eq!(req("POST", &h.base, Some(&note), &[a, ("Mcp-Session-Id", &sid)]).0, 202);
    let call = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "balance", "arguments": {}}});
    let (st, _, body) = req("POST", &h.base, Some(&call), &[a, ("Mcp-Session-Id", &sid)]);
    assert_eq!(st, 200);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["result"]["isError"], false);
    assert_eq!(req("POST", &h.base, Some(&list), &[a, ("Mcp-Session-Id", &sid), ("MCP-Protocol-Version", "1999-01-01")]).0, 400);
    assert_eq!(req("POST", &h.base, Some(&list), &[a, ("Mcp-Session-Id", &sid), ("Origin", "https://evil.example")]).0, 403);
    assert_eq!(req("POST", &h.base, Some(&list), &[a, ("Mcp-Session-Id", &sid), ("Origin", "http://localhost:3000")]).0, 200);
    assert_eq!(req("GET", &h.base, None, &[a, ("Mcp-Session-Id", &sid)]).0, 405);
    assert_eq!(req("POST", &h.base.replace("/mcp", "/other"), Some(&list), &[a]).0, 404);
    assert_eq!(req("DELETE", &h.base, None, &[a, ("Mcp-Session-Id", &sid)]).0, 200);
    assert_eq!(req("POST", &h.base, Some(&list), &[a, ("Mcp-Session-Id", &sid)]).0, 404);

    let t = http(&sock, 33592, Some("s3cret"));
    assert_eq!(req("POST", &t.base, Some(&init_msg(1)), &[]).0, 401);
    assert_eq!(req("POST", &t.base, Some(&init_msg(1)), &[("Authorization", "Bearer wrong!")]).0, 401);
    assert_eq!(req("POST", &t.base, Some(&init_msg(1)), &[("Authorization", "Bearer s3cret")]).0, 200);
}

// ports: AGP-063's range 29060-29069 (outside the ephemeral range)
#[test]
fn x1_the_generated_token_is_private_and_origin_is_checked_with_allow_remote() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (sock, _) = mock_signer(dir.path());
    let h = http(&sock, 29060, None);
    let p = dir.path().join("mcp-http-token");
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    let tok = std::fs::read_to_string(&p).unwrap().trim().to_string();
    assert_eq!(tok.len(), 64);
    assert_eq!(req("POST", &h.base, Some(&init_msg(1)), &[]).0, 401, "loopback is no authentication");
    drop(h);
    let h = http(&sock, 29061, None);
    let auth = format!("Bearer {tok}");
    assert_eq!(req("POST", &h.base, Some(&init_msg(1)), &[("Authorization", &auth)]).0, 200, "the same token after a restart");
    // a remote listener still refuses a browser page from elsewhere (a DNS rebinding: Origin = Host)
    let mut cmd = Command::new(BIN);
    cmd.env_clear().env("B2_SIGNER_SOCK", &sock).env("XBT_MCP_HTTP_TOKEN", "s3cret").args(["--http", "127.0.0.1:29062", "--http-allow-remote"])
        .stdout(Stdio::null()).stderr(Stdio::null());
    let r = Http { child: cmd.spawn().unwrap(), base: "http://127.0.0.1:29062/mcp".into() };
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", 29062)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let b = ("Authorization", "Bearer s3cret");
    assert_eq!(req("POST", &r.base, Some(&init_msg(1)), &[b, ("Origin", "http://rebind.example:29062")]).0, 403);
    assert_eq!(req("POST", &r.base, Some(&init_msg(1)), &[b, ("Origin", "http://127.0.0.1:29062")]).0, 200);
}

#[test]
fn x1_the_local_payer_checks_the_allowlist_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, seen) = mock_signer(dir.path());
    let target = std::net::TcpListener::bind("127.0.0.1:29063").unwrap();
    target.set_nonblocking(true).unwrap();
    let mut child = Command::new(BIN).env_clear().env("B2_SIGNER_SOCK", &sock).env("XBT_MCP_PAYER", "local").env("XBT_MCP_NETWORK", "regtest")
        .env("XBT_MCP_LEDGER", dir.path().join("payer.jsonl")).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    let mut s = Stdio_ { child, out };
    s.ask(init_msg(1));
    let r = s.call(2, "xbt402_pay", json!({"url": "http://127.0.0.1:29063/internal", "max_sats": 5}));
    let v: Value = serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!((v["verdict"].as_str(), v["rule"].as_str()), (Some("deny"), Some("allowlist")), "{v}");
    assert!(matches!(target.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock), "the probe never left");
    assert!(seen.lock().unwrap().iter().any(|q| q["method"] == "policy_get"));
    drop(s.child.stdin.take());
    let _ = s.child.wait();
}

#[test]
fn http_refuses_non_loopback_without_token() {
    let out = Command::new(BIN).env_clear().args(["--http", "0.0.0.0:33593"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a loopback address"));
    let out = Command::new(BIN).env_clear().args(["--http", "0.0.0.0:33593", "--http-allow-remote"]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("needs XBT_MCP_HTTP_TOKEN"));
}

/// A tool call sent before initialize is refused even when initialize follows at once (the call runs
/// on its own thread; it must see the session as it was when the call arrived).
#[test]
fn stdio_call_before_initialize_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, seen) = mock_signer(dir.path());
    for _ in 0..20 {
        let mut s = Stdio_::start(&sock);
        s.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "balance", "arguments": {}}}));
        s.send(&init_msg(2));
        let mut got = std::collections::HashMap::new();
        for _ in 0..2 {
            let mut line = String::new();
            s.out.read_line(&mut line).unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            got.insert(v["id"].as_u64().unwrap(), v);
        }
        assert_eq!(got[&1]["error"]["code"], -32602, "{}", got[&1]);
        drop(s.child.stdin.take());
        let _ = s.child.wait();
    }
    assert!(seen.lock().unwrap().is_empty());
}

/// AGP-038 container mode: XBT_DATA_DIR, a non-loopback listener with a generated token, a base path,
/// /healthz and /readyz following the signer's readiness file. Port 33740 (AGP-038's 33700-33799).
#[test]
fn data_dir_mode_health_token_and_base_path() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (sock, _) = mock_signer(dir.path());
    let data = dir.path().join("data");
    let child = Command::new(BIN).env_clear().env("XBT_DATA_DIR", &data).env("B2_SIGNER_SOCK", &sock).env("XBT_BASE_PATH", "/w/")
        .env("XBT_MCP_HTTP", "0.0.0.0:33740").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let h = Http { child, base: "http://127.0.0.1:33740".into() };
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", 33740)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let tok_path = data.join("mcp/secrets/mcp-http-token");
    let token = std::fs::read_to_string(&tok_path).unwrap();
    assert_eq!(token.len(), 64);
    assert_eq!(std::fs::metadata(&tok_path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(data.join("mcp/secrets")).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(req("GET", &format!("{}/healthz", h.base), None, &[]).0, 200);
    assert_eq!(req("GET", &format!("{}/w/healthz", h.base), None, &[]).0, 200);
    // the signer answers, but its readiness file is missing: not ready
    let (st, _, body) = req("GET", &format!("{}/w/readyz", h.base), None, &[]);
    assert_eq!(st, 503, "{body}");
    let ready = data.join("run/signer/ready.json");
    std::fs::create_dir_all(ready.parent().unwrap()).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    std::fs::write(&ready, json!({"ok": false, "ts": now}).to_string()).unwrap();
    assert_eq!(req("GET", &format!("{}/readyz", h.base), None, &[]).0, 503);
    std::fs::write(&ready, json!({"ok": true, "ts": now}).to_string()).unwrap();
    let (st, _, body) = req("GET", &format!("{}/readyz", h.base), None, &[]);
    assert_eq!(st, 200, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["signer"]["reachable"], true);
    std::fs::write(&ready, json!({"ok": true, "ts": now - 3600.0}).to_string()).unwrap();
    assert_eq!(req("GET", &format!("{}/readyz", h.base), None, &[]).0, 503); // stale
    // MCP itself: the token, under the base path and without it (a proxy that strips it)
    let auth = format!("Bearer {token}");
    assert_eq!(req("POST", &format!("{}/w/mcp", h.base), Some(&init_msg(1)), &[]).0, 401);
    assert_eq!(req("POST", &format!("{}/w/mcp", h.base), Some(&init_msg(1)), &[("Authorization", &auth)]).0, 200);
    assert_eq!(req("POST", &format!("{}/mcp", h.base), Some(&init_msg(1)), &[("Authorization", &auth)]).0, 200);
    // production mode (a data dir) refuses the token as a plain env value
    let out = Command::new(BIN).env_clear().env("XBT_DATA_DIR", &data).env("XBT_MCP_HTTP_TOKEN", "x")
        .env("XBT_MCP_HTTP", "127.0.0.1:33741").env("B2_SIGNER_SOCK", &sock).output().unwrap();
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("refused in production mode"));
}

/// (status, every response header as "name: value" lines, body): to prove a token never leaks.
fn req_all(method: &str, url: &str, body: Option<&Value>, headers: &[(&str, &str)]) -> (u16, String, String) {
    let mut r = ureq::request(method, url).set("Accept", "application/json, text/event-stream");
    for (k, v) in headers {
        r = r.set(k, v);
    }
    let resp = match body {
        Some(b) => r.set("Content-Type", "application/json").send_string(&b.to_string()),
        None => r.call(),
    };
    let resp = match resp {
        Ok(x) => x,
        Err(ureq::Error::Status(_, x)) => x,
        Err(e) => panic!("{e}"),
    };
    let hdrs = resp.headers_names().iter().map(|n| format!("{n}: {}", resp.header(n).unwrap_or(""))).collect::<Vec<_>>().join("\n");
    let st = resp.status();
    let mut s = String::new();
    resp.into_reader().read_to_string(&mut s).unwrap();
    (st, hdrs, s)
}

/// AGP-042: on a box the UI owns the token (run/ui/mcp-http-token, 0640) and the MCP only reads it, on
/// every request. The owner's rotation (the UI replacing the file, xbt_svc::replace_secret_file, as the
/// Agents page does) cuts the old token off at once. The MCP has no rotation endpoint for a bearer token
/// to call, and the new token never appears in any MCP response. Ports: AGP-042's 34200-34299.
#[test]
fn ui_owned_token_rotation_cannot_be_done_or_seen_by_an_agent() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (sock, _) = mock_signer(dir.path());
    let data = dir.path().join("data");
    let tok_path = data.join("run/ui/mcp-http-token");
    std::fs::create_dir_all(tok_path.parent().unwrap()).unwrap();
    let old = "0a".repeat(32);
    xbt_svc::replace_secret_file(&tok_path, format!("{old}\n").as_bytes(), 0o640).unwrap();
    // no XBT_MCP_HTTP_TOKEN_FILE: the data dir's run/ui/mcp-http-token is found on its own
    let child = Command::new(BIN).env_clear().env("XBT_DATA_DIR", &data).env("B2_SIGNER_SOCK", &sock)
        .env("XBT_MCP_HTTP", "0.0.0.0:34201").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let h = Http { child, base: "http://127.0.0.1:34201".into() };
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", 34201)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!data.join("mcp/secrets/mcp-http-token").exists(), "no second token of the MCP's own");
    let mcp = format!("{}/mcp", h.base);
    let old_auth = format!("Bearer {old}");
    let (st, sid, _) = req("POST", &mcp, Some(&init_msg(1)), &[("Authorization", &old_auth)]);
    assert_eq!(st, 200);
    let sid = sid.unwrap();

    // the owner rotates (the UI's write): the old token is refused on the very next request,
    // new sessions and the session it already had alike
    let new = "5b".repeat(32);
    xbt_svc::replace_secret_file(&tok_path, format!("{new}\n").as_bytes(), 0o640).unwrap();
    assert_eq!(std::fs::metadata(&tok_path).unwrap().permissions().mode() & 0o777, 0o640, "group-readable, never world");
    assert_eq!(req("POST", &mcp, Some(&init_msg(2)), &[("Authorization", &old_auth)]).0, 401);
    let list = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"});
    assert_eq!(req("POST", &mcp, Some(&list), &[("Authorization", &old_auth), ("Mcp-Session-Id", &sid)]).0, 401);

    // an agent holding the old token (or the new one) cannot rotate: there is no endpoint, whatever it sends
    let mut seen = vec![];
    for auth in [&old_auth, &format!("Bearer {new}")] {
        for (m, url) in [("POST", format!("{}/rotate-token", h.base)), ("POST", format!("{}/mcp/rotate-token", h.base)),
                         ("PUT", mcp.clone()), ("GET", format!("{}/rotate-token", h.base))] {
            let r = req_all(m, &url, None, &[("Authorization", auth), ("X-XBT-Rotate", "owner")]);
            assert!(r.0 == 401 || r.0 == 404 || r.0 == 405, "{m} {url}: {r:?}");
            seen.push(r);
        }
    }
    assert_eq!(std::fs::read_to_string(&tok_path).unwrap().trim(), new, "the token file is unchanged");

    // the new token works; nothing the MCP answers (bodies or headers, tools included) holds it
    let new_auth = format!("Bearer {new}");
    let r = req_all("POST", &mcp, Some(&init_msg(4)), &[("Authorization", &new_auth)]);
    assert_eq!(r.0, 200, "{r:?}");
    let sid2 = r.1.lines().find_map(|l| l.strip_prefix("mcp-session-id: ").or_else(|| l.strip_prefix("Mcp-Session-Id: "))).unwrap().to_string();
    seen.push(r);
    let sh = [("Authorization", new_auth.as_str()), ("Mcp-Session-Id", sid2.as_str())];
    seen.push(req_all("POST", &mcp, Some(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})), &sh));
    seen.push(req_all("POST", &mcp, Some(&list), &sh));
    let tools: Value = serde_json::from_str(&seen.last().unwrap().2).unwrap();
    let names: Vec<&str> = tools["result"]["tools"].as_array().unwrap().iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(!names.is_empty() && names.iter().all(|n| !n.contains("rotate") && !n.contains("token")), "{names:?}");
    for t in &names {
        seen.push(req_all("POST", &mcp, Some(&json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": t, "arguments": {}}})), &sh));
    }
    for p in ["/healthz", "/readyz"] {
        seen.push(req_all("GET", &format!("{}{p}", h.base), None, &[]));
    }
    for (st, hdrs, body) in &seen {
        assert!(!hdrs.contains(&new) && !body.contains(&new) && !hdrs.contains(&old) && !body.contains(&old), "{st} {hdrs} {body}");
    }

    // fail closed: a missing or world-readable file refuses everything; it never falls back
    std::fs::set_permissions(&tok_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(req("POST", &mcp, Some(&init_msg(5)), &[("Authorization", &new_auth)]).0, 503);
    std::fs::remove_file(&tok_path).unwrap();
    assert_eq!(req("POST", &mcp, Some(&init_msg(6)), &[("Authorization", &new_auth)]).0, 503);
    assert_eq!(req("POST", &mcp, Some(&init_msg(7)), &[]).0, 503);
}
