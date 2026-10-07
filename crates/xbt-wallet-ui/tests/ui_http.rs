//! AGP-039: the web UI over real HTTP against a regtest signer (the signer suite's rig: the Rust
//! signer on a fake pruned regtest node with the Rust xbt402 provider in process, served on its socket).
//!
//! Auth (first run, login, throttle, sessions, logout), CSRF, the security headers, proxy base paths,
//! and every action: approve (xbt402 grant and pay), deny, the policy editor (the signer's errors, a
//! signed change applied live, JSON mode), human-key enrolment and rotation, sweep, rotation, backup,
//! anchor, close and refund, the pages, the hub probe, and an over-threshold `xbt402_pay` through the
//! MCP that waits, is approved in the UI and is paid.
#[path = "../../xbt-signer/tests/common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use xbt_signer::approval::{backup_message, canonical_message, human_key_message, policy_message, rotate_message, sweep_message};
use xbt_wallet_ui::app::App;
use xbt_wallet_ui::config::Config;

/// A signer on its socket plus the UI in front of it.
struct Box_ {
    rig: Rig,
    _sock: xbt_signer::server::Running,
    app: Arc<App>,
    _srv: xbt_wallet_ui::server::Running,
    base: String,
    data: tempfile::TempDir,
}

fn start(policy_extra: Value, witness: bool, tweak: impl FnOnce(&mut Config)) -> Box_ {
    let rig = Rig::new(policy_extra, witness);
    let sock_path = rig.dir.path().join("signer.sock");
    let sock = xbt_signer::server::spawn(rig.s.clone(), &sock_path, false).unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_test(sock_path, data.path().join("ui"), "127.0.0.1:0");
    tweak(&mut cfg);
    let app = App::new(cfg).unwrap();
    let srv = xbt_wallet_ui::server::spawn(app.clone()).unwrap();
    let base = format!("http://{}", srv.addr);
    Box_ { rig, _sock: sock, app, _srv: srv, base, data }
}

struct R {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

impl R {
    fn location(&self) -> &str {
        self.headers.get("location").map(String::as_str).unwrap_or("")
    }
}

/// A browser: one cookie, no redirects followed.
struct B {
    base: String,
    cookie: String,
    agent: ureq::Agent,
}

fn field(html: &str, name: &str) -> String {
    let pat = format!("name=\"{name}\" value=\"");
    let i = html.find(&pat).unwrap_or_else(|| panic!("no field {name} in page"));
    let rest = &html[i + pat.len()..];
    unescape(&rest[..rest.find('"').unwrap()])
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

impl B {
    fn new(base: &str) -> Self {
        Self { base: base.into(), cookie: String::new(), agent: ureq::AgentBuilder::new().redirects(0).build() }
    }

    fn send(&mut self, method: &str, path: &str, body: Option<&str>, extra: &[(&str, &str)]) -> R {
        let mut rq = self.agent.request(method, &format!("{}{path}", self.base));
        if !self.cookie.is_empty() {
            rq = rq.set("Cookie", &self.cookie);
        }
        for (k, v) in extra {
            rq = rq.set(k, v);
        }
        let resp = match body {
            Some(b) => rq.set("Content-Type", "application/x-www-form-urlencoded").send_string(b),
            None => rq.call(),
        };
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => panic!("{method} {path}: {e}"),
        };
        let mut headers = HashMap::new();
        for n in resp.headers_names() {
            headers.insert(n.to_ascii_lowercase(), resp.all(&n).join("\n"));
        }
        if let Some(c) = headers.get("set-cookie") {
            let v = c.split(';').next().unwrap().to_string();
            self.cookie = if v.ends_with('=') { String::new() } else { v };
        }
        R { status: resp.status(), headers, body: resp.into_string().unwrap_or_default() }
    }

    fn get(&mut self, path: &str) -> R {
        self.send("GET", path, None, &[])
    }

    fn post(&mut self, path: &str, form: &[(&str, &str)]) -> R {
        let body = form.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&");
        self.send("POST", path, Some(&body), &[])
    }

    /// POST with the CSRF token of `page`.
    fn act(&mut self, page: &str, path: &str, form: &[(&str, &str)]) -> R {
        let csrf = field(&self.get(page).body, "csrf");
        let mut f = vec![("csrf", csrf.as_str())];
        f.extend_from_slice(form);
        self.post(path, &f)
    }

    /// The flash on the page a POST redirected to.
    fn flash_after(&mut self, r: &R) -> String {
        assert_eq!(r.status, 303, "{}", r.body);
        let to = r.location().trim_start_matches('.').to_string();
        let page = self.get(&to).body;
        let i = page.find("class=\"flash").map(|i| &page[i..]).unwrap_or("");
        let text = &i[i.find('>').map(|x| x + 1).unwrap_or(0)..];
        unescape(&text[..text.find("</div>").unwrap_or(0)])
    }
}

const PW: &str = "a long box password";

fn logged_in(b: &Box_) -> B {
    let mut br = B::new(&b.base);
    let code = std::fs::read_to_string(b.data.path().join("ui/setup-code")).unwrap();
    let r = br.post("/setup-password", &[("code", code.trim()), ("password", PW), ("password2", PW)]);
    assert_eq!(r.status, 303, "{}", r.body);
    br
}

fn sig(m: &[u8]) -> String {
    sign_human(m)
}

// --- auth, sessions, CSRF, headers -------------------------------------------------------------------

#[test]
fn first_run_needs_the_setup_code_then_the_password_and_logins_are_throttled() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = B::new(&bx.base);
    assert_eq!(br.get("/healthz").status, 200);
    assert_eq!(br.get("/readyz").body, "{\"ok\":true,\"signer\":\"reachable\"}");
    let r = br.get("/");
    assert!(r.body.contains("Setup code"), "first run asks for the setup code");
    let r = br.get("/approvals");
    assert_eq!((r.status, r.location()), (303, "./setup-password"));
    let r = br.post("/setup-password", &[("code", "000000000000"), ("password", PW), ("password2", PW)]);
    assert!(r.body.contains("wrong setup code"));
    let code = std::fs::read_to_string(bx.data.path().join("ui/setup-code")).unwrap();
    let r = br.post("/setup-password", &[("code", code.trim()), ("password", "short"), ("password2", "short")]);
    assert!(r.body.contains("at least 10 characters"));
    let r = br.post("/setup-password", &[("code", code.trim()), ("password", PW), ("password2", PW)]);
    assert_eq!((r.status, r.location()), (303, "./setup"));
    let c = r.headers["set-cookie"].clone();
    assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Path=/"), "{c}");
    assert!(!bx.data.path().join("ui/setup-code").exists(), "the setup code is spent");
    let h = std::fs::read_to_string(bx.data.path().join("ui/password.scrypt")).unwrap();
    assert!(h.starts_with("scrypt$15$8$1$") && !h.contains(PW));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(bx.data.path().join("ui/password.scrypt")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(br.get("/setup").status, 200);
    // log out: the session is gone
    let r = br.act("/", "/logout", &[]);
    assert_eq!(r.location(), "./login");
    br.cookie.clear();
    assert_eq!(br.get("/").location(), "./login");
    assert_eq!(br.get("/api/pending").status, 401);
    // wrong passwords, then the throttle refuses even the right one
    for _ in 0..5 {
        assert_eq!(br.post("/login", &[("password", "nope nope nope")]).status, 401);
    }
    let r = br.post("/login", &[("password", PW)]);
    assert!(r.body.contains("too many failed logins"), "{}", r.body);
    // a stolen old cookie does not work
    let mut other = B::new(&bx.base);
    other.cookie = "xbtui=00".into();
    assert_eq!(other.get("/").location(), "./login");
}

#[test]
fn a_platform_password_sessions_expire_and_csrf_is_required() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |c| c.password = Some("platform password".into()));
    assert!(!bx.data.path().join("ui/setup-code").exists(), "no setup code with a platform password");
    let mut br = B::new(&bx.base);
    assert_eq!(br.get("/").location(), "./login");
    assert_eq!(br.post("/login", &[("password", "platform password")]).location(), "./");
    let page = br.get("/approvals");
    assert_eq!(page.status, 200);
    // security headers on every response
    for (k, want) in [("content-security-policy", "default-src 'none'; script-src 'self'"), ("x-frame-options", "DENY"),
                      ("x-content-type-options", "nosniff"), ("referrer-policy", "no-referrer"), ("cache-control", "no-store")] {
        assert!(page.headers.get(k).is_some_and(|v| v.contains(want)), "{k}: {:?}", page.headers.get(k));
    }
    // no absolute URLs and nothing from elsewhere
    for p in ["/", "/approvals", "/policy", "/channels", "/signatures", "/keys", "/hub", "/setup"] {
        let html = br.get(p).body;
        for bad in ["href=\"/", "src=\"/", "action=\"/", "http://", "https://"] {
            if bad.starts_with("http") {
                assert!(!html.contains(&format!("href=\"{bad}")) && !html.contains(&format!("src=\"{bad}")) && !html.contains(&format!("action=\"{bad}")),
                        "{p} has an absolute {bad} link");
            } else {
                assert!(!html.contains(bad), "{p} has a root-relative URL {bad}");
            }
        }
    }
    // CSRF: none, wrong, another session's, cross-site
    let r = br.post("/deny", &[("token", "x")]);
    assert_eq!(r.status, 403);
    let r = br.post("/deny", &[("csrf", "00"), ("token", "x")]);
    assert_eq!(r.status, 403);
    let mut other = B::new(&bx.base);
    other.post("/login", &[("password", "platform password")]);
    let foreign = field(&other.get("/").body, "csrf");
    assert_eq!(br.post("/deny", &[("csrf", &foreign), ("token", "x")]).status, 403);
    let mine = field(&br.get("/").body, "csrf");
    let body = format!("csrf={mine}&token=x");
    assert_eq!(br.send("POST", "/deny", Some(&body), &[("Sec-Fetch-Site", "cross-site")]).status, 403);
    assert_eq!(br.send("POST", "/deny", Some(&body), &[("Sec-Fetch-Site", "same-origin")]).status, 303);
    // the static assets
    let js = br.get("/ui.js");
    assert_eq!(js.status, 200);
    assert!(js.headers["content-type"].starts_with("text/javascript"));
}

#[test]
fn sessions_expire_when_idle() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |c| {
        c.password = Some("platform password".into());
        c.session_idle = Duration::from_millis(1500);
    });
    let mut br = B::new(&bx.base);
    assert_eq!(br.post("/login", &[("password", "platform password")]).location(), "./");
    assert_eq!(br.get("/keys").status, 200);
    std::thread::sleep(Duration::from_millis(1700));
    assert_eq!(br.get("/keys").location(), "./login");
}

#[test]
fn behind_a_proxy_prefix_and_the_peer_allowlist() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |c| {
        c.base_path = "/apps/wallet/".into();
        c.setup_open = true;
    });
    let mut br = B::new(&bx.base);
    assert_eq!(br.get("/apps/wallet").location(), "./wallet/");
    let r = br.post("/apps/wallet/setup-password", &[("password", PW), ("password2", PW)]);
    assert_eq!(r.status, 303, "the open setup needs no code: {}", r.body);
    assert!(r.headers["set-cookie"].contains("Path=/apps/wallet/"));
    assert_eq!(br.get("/apps/wallet/approvals").status, 200);
    assert_eq!(br.get("/approvals").status, 200, "a proxy that strips the prefix works too");
    // X-Forwarded-Proto https: a Secure cookie
    let mut b2 = B::new(&bx.base);
    let r = b2.send("POST", "/apps/wallet/login", Some(&format!("password={}", enc(PW))), &[("X-Forwarded-Proto", "https")]);
    assert!(r.headers["set-cookie"].contains("; Secure"));
    drop(bx);
    let bx = start(json!({}), false, |c| c.allow_ips = vec!["10.9.".into()]);
    assert_eq!(B::new(&bx.base).get("/").status, 403, "only the configured peers");
}

// --- actions against the signer -----------------------------------------------------------------------

#[test]
fn approve_an_xbt402_call_in_the_ui_and_the_agent_s_retry_pays_and_deny_drops_one() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    bx.rig.fund_hot(1, 12_000);
    let mut br = logged_in(&bx);
    let r = bx.rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 1000}));
    assert_eq!(r["verdict"], "needs_human");
    assert_eq!(br.get("/api/pending").body, "{\"pending\":1}");
    let page = br.get("/approvals").body;
    assert!(page.contains(URL) && page.contains("1,000 sats"), "the queue shows the call and amount");
    let token = field(&page, "token");
    let (dest, amount, exp) = (field(&page, "dest"), field(&page, "amount_sats"), field(&page, "expiry"));
    assert_eq!((dest.as_str(), amount.as_str()), (PROVIDER, "1000"));
    // the message shown for another device is exactly the signer's
    let m = canonical_message(&token, &dest, 1000, exp.parse().unwrap());
    assert!(page.contains(&hex::encode(&m)));
    // a bad signature is refused by the signer
    let r = br.act("/approvals", "/approve", &[("token", &token), ("dest", &dest), ("amount_sats", "1000"), ("expiry", &exp), ("signature", &sig(b"x"))]);
    assert!(br.flash_after(&r).contains("approval_sig"));
    // the signature pasted from another device
    let r = br.act("/approvals", "/approve", &[("token", &token), ("dest", &dest), ("amount_sats", "1000"), ("expiry", &exp),
                                               ("signature", ""), ("signature_ext", &sig(&m))]);
    let f = br.flash_after(&r);
    assert!(f.starts_with("Approved. The agent's call to"), "{f}");
    assert!(br.get("/approvals").body.contains("Approved: paid when the agent"));
    // the agent's same call pays under the grant (a block for the new channel first)
    assert_eq!(bx.rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 1000}))["verdict"], "pending");
    bx.rig.chain.mine(1);
    let paid = bx.rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 1000}));
    assert_eq!((paid["verdict"].as_str(), paid["approved"].as_bool()), (Some("allow"), Some(true)), "{paid}");
    assert!(!br.get("/approvals").body.contains(&token));
    // deny another
    let r2 = bx.rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 1000}));
    let t2 = r2["approval_token"].as_str().unwrap();
    let r = br.act("/approvals", "/deny", &[("token", t2), ("reason", "too much")]);
    assert_eq!(br.flash_after(&r), "Denied.");
    assert_eq!(bx.rig.call("approval_status", json!({"token": t2}))["state"], "denied");
    let hist = bx.rig.call("history", json!({"limit": 100}))["events"].to_string();
    assert!(hist.contains("too much"));
}

#[test]
fn approve_a_pay_token_pays_at_once() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let payto = hex::encode(xbt_primitives::ecdsa::pubkey(&secret("provider payTo")));
    let bx = start(json!({"counterparties": {PROVIDER: {"pay_to": payto}}}), false, |_| {});
    bx.rig.fund_hot(1, 12_000);
    let mut br = logged_in(&bx);
    let r = bx.rig.call("pay", json!({"to": PROVIDER, "amount_sats": 1000, "memo": "invoice 7"}));
    let page = br.get("/approvals").body;
    assert!(page.contains("invoice 7") && page.contains("paid as soon as you approve"));
    let m = canonical_message(r["approval_token"].as_str().unwrap(), PROVIDER, 1000, r["approval_expires"].as_i64().unwrap());
    let r = br.act("/approvals", "/approve", &[("token", r["approval_token"].as_str().unwrap()), ("dest", PROVIDER), ("amount_sats", "1000"),
                                               ("expiry", &r["approval_expires"].to_string()), ("signature", &sig(&m))]);
    let f = br.flash_after(&r);
    assert!(f.starts_with("Approved and paid: 1000 sats to") && f.contains("channel"), "{f}");
}

#[test]
fn the_policy_editor_shows_the_signer_s_errors_and_applies_a_signed_change_live() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    let page = br.get("/policy").body;
    assert!(page.contains("name=\"f_human_threshold_sats\" value=\"1000\""));
    // an invalid value: the page lists exactly what the signer's validator says
    let csrf = field(&page, "csrf");
    let mut form: Vec<(String, String)> = vec![("csrf".into(), csrf.clone()), ("mode".into(), "form".into())];
    for k in ["max_per_tx_sats", "daily_budget_sats", "weekly_budget_sats", "per_counterparty_cap_sats", "human_threshold_sats", "approval_ttl_s",
              "split_window_s", "velocity_max", "velocity_window_s", "channel_expiry_blocks", "refund_margin_blocks", "close_fee_max_sats",
              "open_wait_s", "open_retry_s", "hot_balance_cap_sats", "anchor_interval_s", "treasury_csv"] {
        let v = field(&page, &format!("f_{k}"));
        form.push((format!("f_{k}"), v));
    }
    form.push(("f_refund_enabled".into(), "1".into()));
    form.push(("f_allowlist".into(), PROVIDER.into()));
    let post = |br: &mut B, f: &[(String, String)]| br.post("/policy", &f.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>());
    let mut bad = form.clone();
    bad.iter_mut().find(|(k, _)| k == "f_max_per_tx_sats").unwrap().1 = "lots".into();
    let r = post(&mut br, &bad);
    let mut raw = bx.rig.call("policy_get", json!({}))["policy"].clone();
    raw["max_per_tx_sats"] = "lots".into();
    let want = bx.rig.call("policy_validate", json!({"policy": raw}))["errors"][0].as_str().unwrap().to_string();
    assert_eq!(want, "policy.json max_per_tx_sats: not an integer");
    assert!(r.body.contains(&want), "the UI shows the signer's own error");
    let mut bad = form.clone();
    bad.iter_mut().find(|(k, _)| k == "f_approval_ttl_s").unwrap().1 = "0".into();
    assert!(post(&mut br, &bad).body.contains("policy.json approval_ttl_s: must be &gt; 0 (got 0)"));
    // a valid change: preview (diff + the exact text), sign what is shown, apply
    let mut good = form.clone();
    good.iter_mut().find(|(k, _)| k == "f_human_threshold_sats").unwrap().1 = "5000".into();
    good.push(("f_hubs".into(), "http://127.0.0.1:33899 5000 1000".into()));
    good.push(("f_route_max_lock_sats".into(), "2000".into()));
    good.push(("f_route_daily_budget_sats".into(), "3000".into()));
    let prev = post(&mut br, &good).body;
    assert!(prev.contains("<code>human_threshold_sats</code>") && prev.contains("Sign and apply"), "{prev}");
    let text = field(&prev, "text");
    let (sha, exp) = (field(&prev, "prev_sha256"), field(&prev, "expiry"));
    let shown = &prev[prev.find("<pre class=\"signed-text\">").unwrap() + 25..];
    assert_eq!(unescape(&shown[..shown.find("</pre>").unwrap()]), text, "what is shown is what is signed");
    let m = policy_message(&sha, exp.parse().unwrap(), &text);
    assert!(prev.contains(&hex::encode(&m)));
    let r = br.post("/policy-apply", &[("csrf", &csrf), ("text", &text), ("prev_sha256", &sha), ("expiry", &exp), ("signature", &sig(b"wrong"))]);
    assert!(br.flash_after(&r).contains("human_sig"));
    let r = br.post("/policy-apply", &[("csrf", &csrf), ("text", &text), ("prev_sha256", &sha), ("expiry", &exp), ("signature", &sig(&m))]);
    assert_eq!(br.flash_after(&r), "Policy applied; it is in force now.");
    assert_eq!(bx.rig.s.config().human_threshold_sats, 5000);
    assert_eq!(bx.rig.call("routing_status", json!({}))["policy"]["enabled"], true, "routing is live too");
    // JSON mode, with a restart-only key
    let cur = bx.rig.call("policy_get", json!({}));
    let mut p = cur["policy"].clone();
    p["open_wait_s"] = 30.into();
    let prev = br.post("/policy", &[("csrf", &csrf), ("mode", "json"), ("json", &p.to_string())]).body;
    assert!(prev.contains("after restart"));
    let (text, sha, exp) = (field(&prev, "text"), field(&prev, "prev_sha256"), field(&prev, "expiry"));
    let r = br.post("/policy-apply", &[("csrf", &csrf), ("text", &text), ("prev_sha256", &sha), ("expiry", &exp),
                                        ("signature", &sig(&policy_message(&sha, exp.parse().unwrap(), &text)))]);
    assert!(br.flash_after(&r).contains("take effect when the signer restarts: open_wait_s"));
    assert!(br.get("/policy").body.contains("waiting for a signer restart: open_wait_s"));
    assert!(br.post("/policy", &[("csrf", &csrf), ("mode", "json"), ("json", "{nope")]).body.contains("policy.json: key must be a string"));
    // the template
    assert!(br.get("/policy?template=starter").body.contains("name=\"f_max_per_tx_sats\" value=\"100000\""));
}

#[test]
fn enrol_and_replace_the_human_key_then_sweep_rotate_backup_and_anchor() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({"human_pubkey": ""}), true, |_| {});
    bx.rig.fund_hot(1, 20_000);
    let mut br = logged_in(&bx);
    let setup = br.get("/setup").body;
    assert!(setup.contains("id=\"keygen\"") && setup.contains("./human-key-enroll"));
    assert!(br.get("/").body.contains("No approval key is enrolled"));
    let pubhex = hex::encode(human().verifying_key().to_bytes());
    let r = br.act("/setup", "/human-key-enroll", &[("pubkey", &pubhex)]);
    assert_eq!(br.flash_after(&r), "Approval key enrolled.");
    let r = br.act("/setup", "/human-key-enroll", &[("pubkey", &pubhex)]);
    assert!(br.flash_after(&r).contains("already enrolled"));
    let keys = br.get("/keys").body;
    assert!(keys.contains(&format!("data-enrolled=\"{pubhex}\"")));
    // sweep 5,000 sats to an outside address
    let hot = field(&keys, "hot_address");
    let exp = field(&keys, "expiry").parse::<i64>().unwrap();
    let to = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let r = br.act("/keys", "/sweep", &[("to", to), ("amount_sats", "5000"), ("expiry", &exp.to_string()), ("signature", &sig(&sweep_message(&hot, to, 5000, exp)))]);
    let f = br.flash_after(&r);
    assert!(f.starts_with("Swept 5000 sats to"), "{f}");
    // rotate
    let r = br.act("/keys", "/rotate", &[("expiry", &exp.to_string()), ("signature", &sig(&rotate_message(&hot, exp)))]);
    let f = br.flash_after(&r);
    assert!(f.starts_with("Hot key rotated"), "{f}");
    // backup: a JSON download
    let keys = br.get("/keys").body;
    let hot = field(&keys, "hot_address");
    let csrf = field(&keys, "csrf");
    let r = br.post("/backup", &[("csrf", &csrf), ("expiry", &exp.to_string()), ("backup_pass", "correct horse battery"), ("backup_pass2", "different"),
                                 ("signature", &sig(&backup_message(&hot, exp)))]);
    assert!(br.flash_after(&r).contains("differ"));
    let r = br.post("/backup", &[("csrf", &csrf), ("expiry", &exp.to_string()), ("backup_pass", "correct horse battery"), ("backup_pass2", "correct horse battery"),
                                 ("signature", &sig(&backup_message(&hot, exp)))]);
    assert_eq!(r.status, 200);
    assert!(r.headers["content-disposition"].starts_with("attachment; filename=\"xbt-wallet-backup-"));
    let doc: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(doc["format"], "xbt-agentwallet-backup-v1");
    assert!(br.get("/setup").body.contains("A backup was exported."));
    // replace the human key: signed by the old one
    let new = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let new_hex = hex::encode(new.verifying_key().to_bytes());
    let r = br.act("/keys", "/human-key-rotate", &[("old_pub", &pubhex), ("pubkey", &new_hex), ("expiry", &exp.to_string()),
                                                   ("signature", &sig(&human_key_message(&pubhex, &new_hex, exp)))]);
    assert!(br.flash_after(&r).starts_with("The new approval key is enrolled"));
    assert_eq!(hex::encode(bx.rig.s.human_key()), new_hex);
    // the signature log and the anchor
    let r = br.act("/signatures", "/anchor-now", &[]);
    assert_eq!(br.flash_after(&r), "Anchored.");
    let s = br.get("/signatures").body;
    assert!(s.contains("chain intact, matches the anchor"), "{s}");
    assert!(s.contains("human:sweep_signature") && s.contains("human:rotate_signature"));
}

#[test]
fn channels_show_the_close_report_and_refund_eta_and_close_and_refund_act() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    bx.rig.fund_hot(1, 12_000);
    let chan = bx.rig.open()["chan"].as_str().unwrap().to_string();
    let mut br = logged_in(&bx);
    let page = br.get("/channels").body;
    assert!(page.contains(&chan) && page.contains(">open<") && page.contains("if not closed"), "refund ETA shown");
    // refund before expiry: the signer refuses
    let r = br.act("/channels", "/channel-refund", &[("counterparty", PROVIDER)]);
    let f = br.flash_after(&r);
    assert!(!f.starts_with("Refund broadcast"), "{f}");
    let r = br.act("/channels", "/channel-close", &[("counterparty", PROVIDER)]);
    let f = br.flash_after(&r);
    assert!(f.starts_with("Closed: txid") && f.ends_with("close report ok."), "{f}");
    let page = br.get("/channels").body;
    assert!(page.contains(">closed<") && page.contains("Close report") && page.contains("provider cum"), "{page}");
    let ov = br.get("/").body;
    assert!(ov.contains("Recent activity") && ov.contains("Closed</dt><dd>1"));
}

#[test]
fn the_hub_page_probes_this_box_s_hub() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let hub = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let hub_addr = hub.server_addr().to_ip().unwrap();
    std::thread::spawn(move || {
        while let Ok(rq) = hub.recv() {
            let (code, body) = match rq.url() {
                "/healthz" => (200, "{\"ok\":true,\"role\":\"hub\"}"),
                "/readyz" => (200, "{\"ok\":true,\"wallet\":{\"name\":\"hub\",\"loaded\":true,\"receive_address\":\"bcrt1qhubrecv\",\"balance_sats\":0},\"tor\":\"http://hubtest.onion\"}"),
                _ => (404, "no"),
            };
            let _ = rq.respond(tiny_http::Response::from_string(body).with_status_code(code));
        }
    });
    let bx = start(json!({"routing": {"hubs": {PROVIDER: {"max_fee_ppm": 5000, "max_fee_base_msat": 2000}}, "max_lock_sats": 2000,
                                      "daily_budget_sats": 3000}}), false, |c| c.hub_url = Some(format!("http://{hub_addr}")));
    let mut br = logged_in(&bx);
    let page = br.get("/hub").body;
    assert!(page.contains("<span class=\"tag ok\">on</span>") && page.contains("5000 ppm"), "{page}");
    assert!(page.contains("&quot;role&quot;:&quot;hub&quot;"), "the hub's /healthz is shown");
    assert!(page.contains("id=\"hub-receive\">bcrt1qhubrecv") && page.contains("id=\"hub-tor\">http://hubtest.onion"), "{page}");
    assert!(!page.contains("XBT Compute"), "no cmp tile unless configured");
}

#[test]
fn the_agents_page_shows_the_mcp_endpoint_and_token_only_after_login() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let tdir = tempfile::tempdir().unwrap();
    let tok = tdir.path().join("mcp-http-token");
    let bx = start(json!({}), false, |c| {
        c.mcp_urls = vec!["http://umbrel.local:33510/mcp".into()];
        c.mcp_token_file = tok.clone();
    });
    let mut anon = B::new(&bx.base);
    let r = anon.get("/agents");
    assert_eq!(r.status, 303, "login first");
    let mut br = logged_in(&bx);
    let page = br.get("/agents").body;
    assert!(page.contains("http://umbrel.local:33510/mcp") && page.contains("No token here yet"), "{page}");
    // as xbt-init leaves it on a box: 0640, the MCP reads it by group
    xbt_svc::replace_secret_file(&tok, format!("{}\n", "ab".repeat(32)).as_bytes(), 0o640).unwrap();
    let page = br.get("/agents").body;
    assert!(page.contains(&"ab".repeat(32)) && page.contains("Bearer ") && page.contains("<details>"), "{page}");
    assert!(page.contains("aria-current=\"page\">Agents") && page.contains("Rotate the token"), "{page}");
    // AGP-042: the real MCP HTTP transport, reading the same file (the UI never calls it to rotate)
    let wallet = std::sync::Arc::new(xbt_wallet_mcp::wallet::Wallet::new(tdir.path().join("no-signer.sock"),
                                                                          xbt_wallet_mcp::wallet::PayerMode::Signer));
    let mut cfg = xbt_wallet_mcp::transport::HttpConfig::new("127.0.0.1:34202");
    cfg.token_file = Some(tok.clone());
    let server = std::sync::Arc::new(xbt_wallet_mcp::mcp::Server::new(wallet));
    std::thread::spawn(move || xbt_wallet_mcp::transport::serve_http(server, cfg));
    let mcp_init = |t: &str| {
        for _ in 0..100 {
            let r = ureq::post("http://127.0.0.1:34202/mcp").set("Accept", "application/json, text/event-stream")
                .set("Authorization", &format!("Bearer {t}"))
                .send_string(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26",
                                     "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}).to_string());
            match r {
                Ok(x) => return x.status(),
                Err(ureq::Error::Status(c, _)) => return c,
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        panic!("mcp not listening")
    };
    assert_eq!(mcp_init(&"ab".repeat(32)), 200);
    // no confirmation box: nothing changes
    let r = br.act("/agents", "/rotate-token", &[]);
    assert!(br.flash_after(&r).contains("tick the box"));
    assert_eq!(std::fs::read_to_string(&tok).unwrap().trim(), "ab".repeat(32));
    let r = br.act("/agents", "/rotate-token", &[("confirm", "1")]);
    let flash = br.flash_after(&r);
    assert!(flash.contains("Agent token rotated"), "{flash}");
    // the old token is refused on the next request; the new one (shown only on this page) works
    assert_eq!(mcp_init(&"ab".repeat(32)), 401);
    let page = br.get("/agents").body;
    let new = regex_token(&page);
    assert!(new.len() == 64 && new != "ab".repeat(32));
    assert_eq!(std::fs::read_to_string(&tok).unwrap().trim(), new);
    assert_eq!(mcp_init(&new), 200);
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&tok).unwrap().permissions().mode() & 0o777, 0o640, "the mode is kept: group, never others");
    }
    let left: Vec<_> = std::fs::read_dir(tdir.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    assert!(left.iter().all(|n| !n.contains(".tmp")), "{left:?}");
}

fn regex_token(page: &str) -> String {
    let i = page.find("<code id=\"mcp-token\">").expect("token on page");
    let rest = &page[i + "<code id=\"mcp-token\">".len()..];
    rest[..rest.find("</code>").unwrap()].to_string()
}

#[test]
fn xbt_compute_status_tile_and_link_when_configured() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let cmp = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let cmp_addr = cmp.server_addr().to_ip().unwrap();
    std::thread::spawn(move || {
        while let Ok(rq) = cmp.recv() {
            let body = "{\"ok\":true,\"role\":\"node-host\",\"node_sync_pct\":99.7,\"services\":{\"hub\":\"up\"}}";
            let _ = rq.respond(tiny_http::Response::from_string(body));
        }
    });
    let bx = start(json!({}), false, |c| {
        c.cmp_status_url = Some(format!("http://{cmp_addr}/readyz"));
        c.cmp_url = Some("http://umbrel.local:3900/".into());
    });
    let mut br = logged_in(&bx);
    for p in ["/", "/hub"] {
        let page = br.get(p).body;
        assert!(page.contains("id=\"cmp-status\"") && page.contains(">up</span>") && page.contains("node_sync_pct") && page.contains("99.7"), "{p}: {page}");
        assert!(page.contains("href=\"http://umbrel.local:3900/\" target=\"_blank\" rel=\"noopener noreferrer\""));
    }
    drop(bx);
    let bx = start(json!({}), false, |c| c.cmp_status_url = Some("http://127.0.0.1:1/readyz".into()));
    let mut br = logged_in(&bx);
    assert!(br.get("/").body.contains("unreachable"), "a down cmp shows as unreachable, the page still renders");
}

// --- the MCP waits, the UI approves, the call is paid ---------------------------------------------------

#[test]
fn an_over_threshold_xbt402_pay_through_the_mcp_waits_for_the_ui_approval_then_is_paid() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    bx.rig.fund_hot(1, 12_000);
    let sock = bx.app.cfg.signer_sock.clone();
    let mut wallet = xbt_wallet_mcp::wallet::Wallet::new(sock, xbt_wallet_mcp::wallet::PayerMode::Signer);
    wallet.approval_wait = Duration::from_secs(30);
    let agent = std::thread::spawn(move || {
        let mut args = serde_json::Map::new();
        args.insert("url".into(), URL.into());
        args.insert("method".into(), "GET".into());
        args.insert("body".into(), "".into());
        args.insert("max_sats".into(), 1000.into());
        wallet.call_tool("xbt402_pay", args)
    });
    // the human sees it in the UI and approves it there
    let mut br = logged_in(&bx);
    let mut page = String::new();
    for _ in 0..50 {
        page = br.get("/approvals").body;
        if page.contains("name=\"token\"") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let (token, exp) = (field(&page, "token"), field(&page, "expiry"));
    let m = canonical_message(&token, PROVIDER, 1000, exp.parse().unwrap());
    let r = br.act("/approvals", "/approve", &[("token", &token), ("dest", PROVIDER), ("amount_sats", "1000"), ("expiry", &exp), ("signature", &sig(&m))]);
    assert!(br.flash_after(&r).starts_with("Approved."));
    // the new channel's funding needs a block (regtest)
    std::thread::sleep(Duration::from_millis(1500));
    bx.rig.chain.mine(1);
    let out = agent.join().unwrap().expect("the tool call");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["verdict"], "allow", "{v}");
    assert_eq!(v["approved"], true);
    assert_eq!(v["waited_for_human"], true);
    assert!(v["charged_sats"].as_i64().unwrap() > 0);
    assert_eq!(bx.rig.call("approval_status", json!({"token": token}))["state"], "used");
}

#[test]
fn without_a_wait_the_mcp_answers_needs_human_at_once_and_a_deny_ends_a_wait() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let sock = bx.app.cfg.signer_sock.clone();
    let args = || {
        let mut a = serde_json::Map::new();
        a.insert("url".into(), URL.into());
        a.insert("max_sats".into(), 1000.into());
        a
    };
    let w0 = xbt_wallet_mcp::wallet::Wallet::new(sock.clone(), xbt_wallet_mcp::wallet::PayerMode::Signer);
    let v: Value = serde_json::from_str(&w0.call_tool("xbt402_pay", args()).unwrap()).unwrap();
    assert_eq!(v["verdict"], "needs_human");
    assert!(v.get("approval_state").is_none(), "B2's answer, unchanged");
    let mut w = xbt_wallet_mcp::wallet::Wallet::new(sock, xbt_wallet_mcp::wallet::PayerMode::Signer);
    w.approval_wait = Duration::from_secs(30);
    let t = std::thread::spawn(move || w.call_tool("xbt402_pay", args()));
    let mut br = logged_in(&bx);
    let mut tokens = vec![];
    for _ in 0..50 {
        let q = bx.rig.call("approvals", json!({}));
        tokens = q["approvals"].as_array().unwrap().iter().filter(|a| a["state"] == "pending").map(|a| a["token"].as_str().unwrap().to_string()).collect();
        if tokens.len() == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    for t in &tokens {
        br.act("/approvals", "/deny", &[("token", t)]);
    }
    let v: Value = serde_json::from_str(&t.join().unwrap().unwrap()).unwrap();
    assert_eq!((v["verdict"].as_str(), v["approval_state"].as_str()), (Some("needs_human"), Some("denied")), "{v}");
}
