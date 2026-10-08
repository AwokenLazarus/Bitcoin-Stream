//! The routes and pages.
//!
//! Reads go straight to the signer socket. Every change is a POST with the session's CSRF token.
//! The ones that raise what the wallet may spend or move keys (approve, policy, human key, sweep,
//! rotation, backup) also carry the human's ed25519 signature, made in the browser by `ui.js` (or
//! pasted from another device); the signer verifies it, so this process cannot forge them.
use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::auth::Auth;
use crate::config::Config;
use crate::html::{esc, escv, int, json_block, kv, page, sats, short, txt, utc, Nav};
use crate::link::SignerLink;
use crate::server::{strip_base, Req, Resp};
use crate::{msg, now};

pub const COOKIE: &str = "xbtui";
/// How long a signed form stays valid.
pub const SIGN_WINDOW_S: i64 = 600;

pub struct App {
    pub cfg: Config,
    pub auth: Auth,
    pub signer: SignerLink,
}

/// What a human who signs on another device needs.
enum Ext {
    /// The exact bytes.
    Bytes(Vec<u8>),
    /// The fields are typed on this page: the message's lines, described.
    Lines(String),
    /// Only this browser can do it (the new key is made here).
    Browser,
}

impl Ext {
    fn html(&self) -> String {
        let paste = "<textarea name=\"signature_ext\" rows=\"2\" placeholder=\"128 hex characters\"></textarea>";
        match self {
            Ext::Bytes(m) => format!("<details><summary>Sign on another device</summary><p>Sign these bytes (hex) with your ed25519 approval key, \
                                      e.g. <code>xbt-wallet-ui sign --key KEYFILE --message-hex HEX</code>, and paste the signature:</p>\
                                      <pre class=\"hex\">{}</pre>{paste}</details>", hex::encode(m)),
            Ext::Lines(l) => format!("<details><summary>Sign on another device</summary><p>The message is these lines joined by a newline \
                                      (<code>xbt-wallet-ui sign --key KEYFILE --message-hex HEX</code> signs its hex):</p><pre>{}</pre>{paste}</details>", esc(l)),
            Ext::Browser => String::new(),
        }
    }
}

/// One request's session.
struct Ctx {
    sid: String,
    csrf: String,
    flash: Option<(bool, String)>,
}

const INT_KEYS: [(&str, &str, &str); 17] = [
    ("max_per_tx_sats", "Largest single payment (sats)", "budgets"),
    ("daily_budget_sats", "Daily budget (sats, rolling 24 h)", "budgets"),
    ("weekly_budget_sats", "Weekly budget (sats, rolling 7 days)", "budgets"),
    ("per_counterparty_cap_sats", "Per-counterparty cap (sats per 7 days; also a new channel's size)", "budgets"),
    ("human_threshold_sats", "Human approval at or above (sats)", "human"),
    ("approval_ttl_s", "An approval request expires after (s)", "human"),
    ("split_window_s", "Split-payment window (s): smaller payments to one destination that add up are counted together", "human"),
    ("velocity_max", "At most this many payments…", "velocity"),
    ("velocity_window_s", "…per this many seconds", "velocity"),
    ("channel_expiry_blocks", "Channel expiry (blocks)", "channels"),
    ("refund_margin_blocks", "Refund this many blocks before expiry (restart)", "channels"),
    ("close_fee_max_sats", "Refuse a provider's close fee above (sats, restart)", "channels"),
    ("open_wait_s", "Wait for a new channel's funding (s, restart)", "channels"),
    ("open_retry_s", "Retry a pending open every (s)", "channels"),
    ("hot_balance_cap_sats", "Hot key balance cap (sats; 0 = none; above it, a human sweep)", "hot"),
    ("anchor_interval_s", "Anchor the signature log every (s, restart)", "anchor"),
    ("treasury_csv", "Treasury CSV (blocks; B2 field, unused by the Rust signer)", "anchor"),
];

/// A conservative first policy (the setup wizard's template; `xbt-wallet-mcp/policy.example.json`'s limits).
pub fn starter_policy() -> Value {
    json!({"allowlist": [], "counterparties": {}, "max_per_tx_sats": 100000, "daily_budget_sats": 200000, "weekly_budget_sats": 500000,
           "per_counterparty_cap_sats": 100000, "velocity_max": 60, "velocity_window_s": 3600, "human_threshold_sats": 50000,
           "split_window_s": 600, "approval_ttl_s": 900, "channel_expiry_blocks": 1008, "refund_enabled": true, "refund_margin_blocks": 6,
           "hot_balance_cap_sats": 1500000, "anchor_interval_s": 300, "open_wait_s": 45, "open_retry_s": 60, "close_fee_max_sats": 2000,
           "routing": {}})
}

fn state_of(c: &Value) -> &'static str {
    if c.get("refund_txid").is_some_and(|v| !v.is_null()) {
        "refunded"
    } else {
        match c.get("state").and_then(Value::as_str) {
            Some("open") => "open",
            Some("pending") => "pending",
            Some("closed") => "closed",
            _ => "other",
        }
    }
}

/// The signer did it: no deny, no `ok: false`, no error.
fn ok_of(r: &Value) -> bool {
    r.is_object() && !matches!(r.get("verdict").and_then(Value::as_str), Some("deny") | Some("needs_human"))
        && r.get("ok") != Some(&Value::Bool(false)) && r.get("error").map_or(true, Value::is_null)
}

fn reason_of(r: &Value) -> String {
    for k in ["reason", "error"] {
        if let Some(s) = r.get(k).and_then(Value::as_str) {
            return format!("{}{s}", r.get("rule").and_then(Value::as_str).map(|x| format!("{x}: ")).unwrap_or_default());
        }
    }
    r.to_string()
}

impl App {
    pub fn new(cfg: Config) -> Result<Arc<Self>, String> {
        let auth = Auth::open(&cfg.data_dir, cfg.password.as_deref(), cfg.setup_open, cfg.session_idle, cfg.session_max)?;
        let signer = SignerLink::new(cfg.signer_sock.clone(), std::time::Duration::from_secs(90));
        Ok(Arc::new(Self { cfg, auth, signer }))
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.signer.call(method, params)
    }

    fn cookie(&self, req: &Req, sid: &str, max_age: i64) -> String {
        let secure = self.cfg.secure_cookie.unwrap_or_else(|| req.header("x-forwarded-proto").eq_ignore_ascii_case("https"));
        format!("{COOKIE}={sid}; Path={}; HttpOnly; SameSite=Strict; Max-Age={max_age}{}", self.cfg.base_path, if secure { "; Secure" } else { "" })
    }

    fn peer_allowed(&self, peer: &str) -> bool {
        self.cfg.allow_ips.is_empty() || self.cfg.allow_ips.iter().any(|p| peer == p || (p.ends_with('.') || p.ends_with(':')) && peer.starts_with(p.as_str()))
    }

    pub fn handle(&self, mut req: Req) -> Resp {
        if !self.peer_allowed(&req.peer) {
            return Resp::text(403, "text/plain", "forbidden");
        }
        if !host_allowed(req.header("host"), &self.cfg.allowed_hosts) {
            return Resp::text(421, "text/plain", "unknown Host: add it to XBT_UI_ALLOWED_HOSTS");
        }
        let Some(path) = strip_base(&req.path, &self.cfg.base_path) else { return Resp::text(404, "text/plain", "not found") };
        if path.is_empty() {
            let last = self.cfg.base_path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            return Resp::redirect(&format!("./{last}/"));
        }
        req.path = path;
        let get = req.method == "GET" || req.method == "HEAD";
        let post = req.method == "POST";
        if !get && !post {
            return Resp::text(405, "text/plain", "method not allowed");
        }
        match (get, req.path.as_str()) {
            (true, "/ui.js") => return Resp::text(200, "text/javascript; charset=utf-8", crate::UI_JS).header("Cache-Control", "public, max-age=86400"),
            (true, "/ui.css") => return Resp::text(200, "text/css; charset=utf-8", crate::UI_CSS).header("Cache-Control", "public, max-age=86400"),
            (true, "/healthz") => return Resp::json(200, &json!({"ok": true})),
            (true, "/readyz") => {
                let up = self.call("health", json!({})).is_ok();
                return Resp::json(if up { 200 } else { 503 }, &json!({"ok": up, "signer": if up { "reachable" } else { "unreachable" }}));
            }
            _ => {}
        }
        // a POST from another site is refused before anything else (the CSRF token is the second check)
        if post && req.header("sec-fetch-site").eq_ignore_ascii_case("cross-site") {
            return Resp::text(403, "text/plain", "cross-site request refused");
        }
        let origin = req.header("origin");
        if post && !origin.is_empty() && !origin_allowed(origin, &self.cfg.allowed_hosts) {
            return Resp::text(403, "text/plain", "cross-origin request refused");
        }
        if !self.auth.has_password() {
            return self.setup_password(&req);
        }
        match req.path.as_str() {
            "/login" => return self.login(&req),
            "/setup-password" => return Resp::redirect("./login"),
            _ => {}
        }
        let sid = req.cookie(COOKIE).unwrap_or_default();
        let Some((csrf, flash)) = self.auth.with_session(&sid, |s| (s.csrf.clone(), s.flash.take())) else {
            if req.path.starts_with("/api/") {
                return Resp::json(401, &json!({"error": "login required"}));
            }
            return Resp::redirect("./login");
        };
        let ctx = Ctx { sid, csrf, flash };
        if post {
            let form = req.form();
            if !self.auth.check_csrf(&ctx.sid, form.get("csrf").map(String::as_str).unwrap_or("")) {
                return Resp::text(403, "text/plain", "missing or wrong CSRF token: reload the page");
            }
            return self.post(&req, &ctx, &form);
        }
        match req.path.as_str() {
            "/" => self.overview(&ctx),
            "/approvals" => self.approvals(&ctx),
            "/policy" => self.policy_page(&ctx, req.query.get("template").map(|t| t == "starter").unwrap_or(false)),
            "/channels" => self.channels(&ctx),
            "/signatures" => self.signatures(&ctx),
            "/keys" => self.keys(&ctx),
            "/agents" => self.agents(&ctx),
            "/hub" => self.hub(&ctx),
            "/setup" => self.setup(&ctx),
            "/api/pending" => Resp::json(200, &json!({"pending": self.pending_count()})),
            _ => Resp::html(404, self.render("Not found", &ctx, "<p>No such page. <a href=\"./\">Overview</a></p>")),
        }
    }

    fn flash(&self, ctx: &Ctx, ok: bool, m: impl Into<String>) {
        let m = m.into();
        self.auth.with_session(&ctx.sid, |s| s.flash = Some((ok, m)));
    }

    fn pending_count(&self) -> usize {
        self.call("approvals", json!({})).ok().and_then(|v| v.get("approvals").and_then(Value::as_array).cloned())
            .map(|a| a.iter().filter(|x| x["state"] == "pending").count()).unwrap_or(0)
    }

    fn render(&self, title: &str, ctx: &Ctx, body: &str) -> String {
        let nav = Nav { active: title, csrf: &ctx.csrf, pending: self.pending_count(), logged_in: true };
        page(title, &nav, ctx.flash.clone(), body)
    }

    fn page(&self, title: &str, ctx: &Ctx, body: String) -> Resp {
        Resp::html(200, self.render(title, ctx, &body))
    }

    fn csrf_input(ctx: &Ctx) -> String {
        format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", esc(&ctx.csrf))
    }

    fn error_box(e: &str) -> String {
        format!("<div class=\"flash bad\">{}</div>", esc(e))
    }

    /// A form the human signs: `kind` picks the message in ui.js (built there from these fields).
    #[allow(clippy::too_many_arguments)]
    fn signed_form(&self, ctx: &Ctx, action: &str, kind: &str, human: &str, hidden: &[(&str, String)], visible: &str, button: &str,
                   message: Ext) -> String {
        let mut h = String::new();
        for (k, v) in hidden {
            h.push_str(&format!("<input type=\"hidden\" name=\"{}\" value=\"{}\">", esc(k), esc(v)));
        }
        format!("<form method=\"post\" action=\"{action}\" data-sign=\"{kind}\" data-human=\"{}\" class=\"signed\">{}{h}{visible}\
                 <input type=\"hidden\" name=\"signature\" value=\"\">\
                 <div class=\"row\"><input class=\"pin\" type=\"password\" autocomplete=\"off\" inputmode=\"text\" placeholder=\"Key passphrase\" aria-label=\"Key passphrase\">\
                 <button type=\"submit\">{}</button></div><p class=\"sign-msg\" aria-live=\"polite\"></p>\
                 {}</form>",
                esc(human), Self::csrf_input(ctx), esc(button), message.html())
    }

    fn human_pub(&self) -> String {
        self.call("keystore_status", json!({})).ok().and_then(|v| v.get("human_pubkey").and_then(Value::as_str).map(str::to_string)).unwrap_or_default()
    }

    // --- login and first run ------------------------------------------------------------------------

    fn bare(&self, title: &str, flash: Option<(bool, String)>, body: &str) -> String {
        page(title, &Nav { active: "", csrf: "", pending: 0, logged_in: false }, flash, body)
    }

    fn setup_password(&self, req: &Req) -> Resp {
        let code_field = if self.auth.needs_setup_code() {
            "<label>Setup code <small>(printed in the app's log at first start, and in the file <code>setup-code</code> in the UI's data directory)</small>\
             <input name=\"code\" autocomplete=\"off\" required></label>"
        } else {
            ""
        };
        let form = |flash: Option<(bool, String)>| {
            Resp::html(200, self.bare("First run", flash, &format!(
                "<p>Choose the password for this wallet's web UI. Anyone with it can see the wallet and deny requests; \
                 raising limits or approving payments also needs your approval key.</p>\
                 <form method=\"post\" action=\"./setup-password\" class=\"card\">{code_field}\
                 <label>New password (at least {} characters)<input type=\"password\" name=\"password\" autocomplete=\"new-password\" required></label>\
                 <label>Again<input type=\"password\" name=\"password2\" autocomplete=\"new-password\" required></label>\
                 <button>Set password</button></form>", crate::auth::MIN_PASSWORD)))
        };
        if req.method != "POST" || req.path != "/setup-password" {
            if req.path != "/setup-password" && req.path != "/" {
                return Resp::redirect("./setup-password");
            }
            return form(None);
        }
        let f = req.form();
        let pw = f.get("password").cloned().unwrap_or_default();
        if Some(&pw) != f.get("password2") {
            return form(Some((false, "the passwords differ".into())));
        }
        match self.auth.set_initial(f.get("code").map(String::as_str).unwrap_or(""), &pw) {
            Err(e) => form(Some((false, e))),
            Ok(()) => {
                let sid = self.auth.new_session();
                self.auth.with_session(&sid, |s| s.flash = Some((true, "Password set. Next: your approval key.".into())));
                Resp::redirect("./setup").header("Set-Cookie", &self.cookie(req, &sid, self.cfg.session_max.as_secs() as i64))
            }
        }
    }

    fn login(&self, req: &Req) -> Resp {
        let form = |flash: Option<(bool, String)>, status: u16| {
            Resp::html(status, self.bare("Log in", flash, "<form method=\"post\" action=\"./login\" class=\"card\">\
                <label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" autofocus required></label>\
                <button>Log in</button></form>"))
        };
        if req.method != "POST" {
            return form(None, 200);
        }
        match self.auth.login(req.form().get("password").map(String::as_str).unwrap_or("")) {
            Err(e) => form(Some((false, e)), 401),
            Ok(sid) => Resp::redirect("./").header("Set-Cookie", &self.cookie(req, &sid, self.cfg.session_max.as_secs() as i64)),
        }
    }

    // --- POST actions -------------------------------------------------------------------------------

    fn post(&self, req: &Req, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
        let sig = || { let s = g("signature"); if s.is_empty() { g("signature_ext") } else { s } };
        let i = |k: &str| g(k).parse::<i64>().unwrap_or(0);
        let back = |to: &str, r: Result<Value, String>, ok_text: &dyn Fn(&Value) -> String| -> Resp {
            match r {
                Ok(v) if ok_of(&v) => self.flash(ctx, true, ok_text(&v)),
                Ok(v) => self.flash(ctx, false, reason_of(&v)),
                Err(e) => self.flash(ctx, false, e),
            }
            Resp::redirect(to)
        };
        match req.path.as_str() {
            "/logout" => {
                self.auth.logout(&ctx.sid);
                Resp::redirect("./login").header("Set-Cookie", &self.cookie(req, "", 0))
            }
            "/approve" => back("./approvals", self.call("approve", json!({"token": g("token"), "dest": g("dest"), "amount_sats": i("amount_sats"),
                                                                          "expiry": i("expiry"), "signature": sig()})), &|v| {
                if v["granted"] == true {
                    format!("Approved. The agent's call to {} will be paid (at most {} sats) when it arrives; approvals expire at {}.",
                            txt(v.get("url")), int(v.get("amount_sats")), utc(int(v.get("expires"))))
                } else {
                    format!("Approved and paid: {} sats to {} ({}{}).", int(v.get("amount_sats")), txt(v.get("dest")), txt(v.get("rail")),
                            v.get("txid").or(v.get("chan")).map(|t| format!(" {}", txt(Some(t)))).unwrap_or_default())
                }
            }),
            "/deny" => back("./approvals", self.call("deny_approval", json!({"token": g("token"), "reason": g("reason"), "expiry": i("expiry"), "signature": sig()})),
                            &|_| "Denied.".into()),
            "/policy" => self.policy_preview(ctx, f),
            // browsers submit line breaks as CRLF; the signed text is LF only (JSON escapes a CR inside a string)
            "/policy-apply" => back("./policy", self.call("policy_set", json!({"text": f.get("text").map(|t| t.replace("\r\n", "\n")).unwrap_or_default(),
                                                                              "prev_sha256": g("prev_sha256"), "expiry": i("expiry"), "signature": sig()})), &|v| {
                let pr = v.get("pending_restart").and_then(Value::as_array).map(|a| a.iter().map(|x| txt(Some(x))).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                if pr.is_empty() { "Policy applied; it is in force now.".into() } else { format!("Policy applied. These take effect when the signer restarts: {pr}.") }
            }),
            "/human-key-enroll" => back("./setup", self.call("human_key_enroll", json!({"pubkey": g("pubkey"), "code": g("code")})), &|_| "Approval key enrolled.".into()),
            "/human-key-rotate" => back("./keys", self.call("human_key_rotate", json!({"pubkey": g("pubkey"), "expiry": i("expiry"), "signature": sig()})),
                                        &|_| "The new approval key is enrolled; the old one no longer approves anything.".into()),
            "/sweep" => back("./keys", self.call("sweep_hot", json!({"to": g("to"), "amount_sats": i("amount_sats"), "expiry": i("expiry"), "signature": sig()})),
                             &|v| format!("Swept {} sats to {} (txid {}).", int(v.get("swept_sats")), txt(v.get("to")), txt(v.get("txid")))),
            "/rotate" => back("./keys", self.call("rotate_hot_key_signed", json!({"expiry": i("expiry"), "signature": sig()})),
                              &|v| format!("Hot key rotated: new address {}.", txt(v.get("new_address")))),
            "/rotate-token" => {
                if g("confirm") != "1" {
                    self.flash(ctx, false, "tick the box to rotate the agent token");
                    return Resp::redirect("./agents");
                }
                match self.rotate_mcp_token() {
                    Ok(_) => self.flash(ctx, true, "Agent token rotated. Give your agents the new token from this page."),
                    Err(e) => self.flash(ctx, false, e),
                }
                Resp::redirect("./agents")
            }
            "/anchor-now" => back("./signatures", self.call("anchor_now", json!({"reason": "operator:ui"})), &|_| "Anchored.".into()),
            "/channel-close" => back("./channels", self.call("close_channel", json!({"counterparty": g("counterparty")})),
                                     &|v| format!("Closed: txid {}, close report {}.", txt(v.get("txid")), txt(v.pointer("/close_report/status")))),
            "/channel-refund" => back("./channels", self.call("xbt402_refund", json!({"counterparty": g("counterparty")})),
                                      &|v| format!("Refund broadcast: {}.", txt(v.get("txid").or(v.get("refund_txid"))))),
            "/backup" => {
                if f.get("backup_pass") != f.get("backup_pass2") {
                    self.flash(ctx, false, "the backup passphrases differ");
                    return Resp::redirect("./keys");
                }
                match self.call("backup_export", json!({"expiry": i("expiry"), "signature": sig(), "backup_pass": f.get("backup_pass").cloned().unwrap_or_default()})) {
                    Ok(v) if ok_of(&v) => Resp::text(200, "application/json", txt(v.get("backup_json")))
                        .header("Content-Disposition", &format!("attachment; filename=\"xbt-wallet-backup-{}.json\"", now())),
                    Ok(v) => { self.flash(ctx, false, reason_of(&v)); Resp::redirect("./keys") }
                    Err(e) => { self.flash(ctx, false, e); Resp::redirect("./keys") }
                }
            }
            _ => Resp::text(404, "text/plain", "not found"),
        }
    }

    // --- overview -----------------------------------------------------------------------------------

    fn overview(&self, ctx: &Ctx) -> Resp {
        let health = match self.call("health", json!({})) {
            Ok(h) => h,
            Err(e) => return self.page("Overview", ctx, Self::error_box(&e)),
        };
        let mut b = String::new();
        let bal = self.call("balance", json!({})).unwrap_or(json!({}));
        let hot = bal.get("hot").cloned().unwrap_or(json!({}));
        let approvals = self.call("approvals", json!({})).unwrap_or(json!({}));
        let pend: Vec<&Value> = approvals["approvals"].as_array().map(|a| a.iter().filter(|x| x["state"] == "pending").collect()).unwrap_or_default();
        if !pend.is_empty() {
            b.push_str(&format!("<div class=\"flash warn\"><a href=\"./approvals\">{} payment{} wait{} for your approval.</a></div>",
                                pend.len(), if pend.len() == 1 { "" } else { "s" }, if pend.len() == 1 { "s" } else { "" }));
        }
        if approvals["human_key"] == false {
            b.push_str("<div class=\"flash warn\">No approval key is enrolled yet: <a href=\"./setup\">finish the setup</a>.</div>");
        }
        if hot["hot_over_cap"] == true {
            b.push_str("<div class=\"flash warn\">The hot key is over its balance cap: new channels are refused until you <a href=\"./keys\">sweep</a> the excess.</div>");
        }
        b.push_str("<section class=\"grid\"><div class=\"card\"><h2>Balances</h2>");
        b.push_str(&kv(&[("Node wallet (confirmed)", sats(int(bal.get("trusted_sats")))), ("Node wallet (pending)", sats(int(bal.get("untrusted_pending_sats")))),
                         ("Hot key", sats(int(hot.get("hot_sats")))),
                         ("Hot key cap", if int(hot.get("hot_cap_sats")) > 0 { sats(int(hot.get("hot_cap_sats"))) } else { "none".into() }),
                         ("Hot key status", if hot["hot_over_cap"] == true { "<span class=\"tag bad\">over cap</span>".into() } else { "<span class=\"tag ok\">within cap</span>".into() }),
                         ("Keys encrypted at rest", if hot["hot_encrypted"] == true { "yes".into() } else { "<span class=\"tag bad\">no</span>".into() })]));
        b.push_str("</div>");
        let chans = bal.get("channels").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for c in &chans {
            *counts.entry(state_of(c)).or_default() += 1;
        }
        let locked: i64 = chans.iter().filter(|c| state_of(c) == "open").map(|c| int(c.get("residual_sats"))).sum();
        b.push_str("<div class=\"card\"><h2>Channels</h2>");
        b.push_str(&kv(&[("Open", counts.get("open").copied().unwrap_or(0).to_string()), ("Pending", counts.get("pending").copied().unwrap_or(0).to_string()),
                         ("Closed", counts.get("closed").copied().unwrap_or(0).to_string()), ("Refunded", counts.get("refunded").copied().unwrap_or(0).to_string()),
                         ("Unspent in open channels", sats(locked))]));
        b.push_str("<p><a href=\"./channels\">Channels →</a></p></div>");
        let anchor = self.call("anchor_status", json!({})).unwrap_or(json!({}));
        b.push_str("<div class=\"card\"><h2>Signature log</h2>");
        b.push_str(&kv(&[("Anchor witness", if anchor["enabled"] == true { "enabled".into() } else { "<span class=\"tag warn\">not configured</span>".into() }),
                         ("Log lines", escv(anchor.get("log_lines"))), ("Not yet anchored", escv(anchor.get("unanchored_lines"))),
                         ("Last anchor", utc(int(anchor.get("anchored_at")))),
                         ("Last error", if anchor["last_error"].as_str().is_some_and(|s| !s.is_empty()) { format!("<span class=\"tag bad\">{}</span>", escv(anchor.get("last_error"))) } else { "none".into() })]));
        b.push_str("<p><a href=\"./signatures\">Signatures →</a></p></div>");
        if let Some(t) = self.cmp_tile() {
            b.push_str(&t);
        }
        b.push_str("<div class=\"card\"><h2>Signer</h2>");
        b.push_str(&kv(&[("Chain", escv(health.get("chain"))), ("Implementation", escv(health.get("implementation"))),
                         ("Node wallet", escv(health.get("wallet"))), ("Regtest mining", escv(health.get("mining")))]));
        b.push_str("</div></section>");
        if let Ok(h) = self.call("history", json!({"limit": 15})) {
            b.push_str("<h2>Recent activity</h2><div class=\"scroll\"><table><thead><tr><th>When</th><th>Event</th><th>Destination</th><th>Amount</th><th>Detail</th></tr></thead><tbody>");
            for e in h["events"].as_array().cloned().unwrap_or_default().iter().rev() {
                let what = match e["type"].as_str() {
                    Some("decision") => format!("decision: {}", txt(e.get("verdict"))),
                    Some(t) => t.replace('_', " "),
                    None => String::new(),
                };
                let amt = e.get("amount_sats").map(|a| sats(int(Some(a)))).unwrap_or_default();
                b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{amt}</td><td>{}</td></tr>", utc(int(e.get("ts"))), esc(&what),
                                    esc(&short(&txt(e.get("dest")), 40)), esc(&short(&txt(e.get("reason").or(e.get("txid"))), 80))));
            }
            b.push_str("</tbody></table></div>");
        }
        self.page("Overview", ctx, b)
    }

    // --- approvals ----------------------------------------------------------------------------------

    fn approvals(&self, ctx: &Ctx) -> Resp {
        let q = match self.call("approvals", json!({})) {
            Ok(q) => q,
            Err(e) => return self.page("Approvals", ctx, Self::error_box(&e)),
        };
        let human = self.human_pub();
        let mut b = String::from("<p>Payments at or above the human threshold wait here. Approving signs \
            <em>exactly</em> the token, destination, amount and expiry shown, with the approval key in this browser; the signer checks the signature.</p>");
        let rows = q["approvals"].as_array().cloned().unwrap_or_default();
        if rows.is_empty() {
            b.push_str("<p class=\"empty\">Nothing waits for you.</p>");
        }
        for a in rows {
            let token = txt(a.get("token"));
            let dest = txt(a.get("dest"));
            let amount = int(a.get("amount_sats"));
            let exp = int(a.get("expires"));
            let kind = txt(a.get("kind"));
            let state = txt(a.get("state"));
            b.push_str(&format!("<article class=\"card approval {}\"><h2>{}</h2>", esc(&state), sats(amount)));
            let mut rows = vec![("To", format!("<code>{}</code>", esc(&dest)))];
            if kind == "xbt402" {
                rows.push(("Paid call", format!("{} <code>{}</code> (at most this amount)", escv(a.get("method")), escv(a.get("url")))));
            } else {
                rows.push(("Kind", "payment (paid as soon as you approve)".into()));
            }
            rows.push(("Agent's memo", escv(a.get("memo"))));
            rows.push(("Requested", utc(int(a.get("ts")))));
            rows.push(("Expires", format!("{} · <span data-expires=\"{exp}\"></span>", utc(exp))));
            rows.push(("Token", format!("<code>{}</code>", esc(&token))));
            b.push_str(&kv(&rows));
            match state.as_str() {
                "pending" => {
                    let hidden = [("token", token.clone()), ("dest", dest.clone()), ("amount_sats", amount.to_string()), ("expiry", exp.to_string())];
                    b.push_str(&self.signed_form(ctx, "./approve", "approve", &human, &hidden, "", "Approve", Ext::Bytes(msg::approve(&token, &dest, amount, exp))));
                    let sexp = now() + SIGN_WINDOW_S;
                    b.push_str(&self.signed_form(ctx, "./deny", "deny", &human, &[("token", token.clone()), ("expiry", sexp.to_string())],
                        "<input name=\"reason\" placeholder=\"Reason (optional)\" maxlength=\"200\">", "Deny", Ext::Bytes(msg::deny(&token, sexp))));
                }
                "approved" => {
                    let sexp = now() + SIGN_WINDOW_S;
                    b.push_str("<p class=\"tag ok\">Approved: paid when the agent's call arrives.</p>");
                    b.push_str(&self.signed_form(ctx, "./deny", "deny", &human, &[("token", token.clone()), ("expiry", sexp.to_string()), ("reason", "revoked".into())],
                        "", "Revoke", Ext::Bytes(msg::deny(&token, sexp))));
                }
                _ => b.push_str(&format!("<p class=\"tag\">Expired.</p><form method=\"post\" action=\"./deny\">{}<input type=\"hidden\" name=\"token\" value=\"{}\">\
                    <input type=\"hidden\" name=\"reason\" value=\"expired\"><button>Dismiss</button></form>", Self::csrf_input(ctx), esc(&token))),
            }
            b.push_str("</article>");
        }
        self.page("Approvals", ctx, b)
    }

    // --- policy -------------------------------------------------------------------------------------

    /// `eff`: the signer's values in force (defaults included), shown where policy.json leaves a key out.
    fn policy_form(&self, ctx: &Ctx, p: &Value, eff: &Value, errors: &[String], warnings: &[String]) -> String {
        let mut b = String::new();
        if !errors.is_empty() {
            b.push_str("<div class=\"flash bad\"><p>The signer refuses this policy:</p><ul>");
            for e in errors {
                b.push_str(&format!("<li>{}</li>", esc(e)));
            }
            b.push_str("</ul></div>");
        }
        if !warnings.is_empty() {
            b.push_str("<div class=\"flash warn\"><ul>");
            for w in warnings {
                b.push_str(&format!("<li>{}</li>", esc(w)));
            }
            b.push_str("</ul></div>");
        }
        b.push_str(&format!("<form method=\"post\" action=\"./policy\" class=\"policy\">{}<input type=\"hidden\" name=\"mode\" value=\"form\">", Self::csrf_input(ctx)));
        let groups = [("budgets", "Budgets"), ("human", "Human approval"), ("velocity", "Velocity"), ("channels", "Channels and refunds"),
                      ("hot", "Hot key"), ("anchor", "Signature log")];
        for (g, title) in groups {
            b.push_str(&format!("<fieldset><legend>{title}</legend>"));
            for (k, label, grp) in INT_KEYS {
                if grp == g {
                    b.push_str(&format!("<label>{}<input name=\"f_{k}\" value=\"{}\" inputmode=\"numeric\"></label>", esc(label), escv(p.get(k).or(eff.get(k)))));
                }
            }
            if g == "channels" {
                let on = p.get("refund_enabled").or(eff.get("refund_enabled")).map(|v| v != &Value::Bool(false)).unwrap_or(true);
                b.push_str(&format!("<label class=\"check\"><input type=\"checkbox\" name=\"f_refund_enabled\" value=\"1\"{}> Refund expired channels to the hot key automatically</label>",
                                    if on { " checked" } else { "" }));
            }
            if g == "anchor" {
                b.push_str(&format!("<label class=\"check\"><input type=\"checkbox\" name=\"f_anchor_required\" value=\"1\"{}> Refuse to start without the anchor witness (restart)</label>",
                                    if p.get("anchor_required").or(eff.get("anchor_required")) == Some(&Value::Bool(true)) { " checked" } else { "" }));
            }
            b.push_str("</fieldset>");
        }
        let allow = p.get("allowlist").and_then(Value::as_array).map(|a| a.iter().map(|x| txt(Some(x))).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        let cps = p.get("counterparties").and_then(Value::as_object).map(|m| m.iter().map(|(k, v)| format!("{k} {}", txt(v.get("pay_to")))).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        let routing = p.get("routing").cloned().unwrap_or(json!({}));
        let hubs = routing.get("hubs").and_then(Value::as_object).map(|m| m.iter().map(|(k, v)| format!("{k} {} {}", int(v.get("max_fee_ppm")), int(v.get("max_fee_base_msat")))).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        b.push_str(&format!("<fieldset><legend>Destinations</legend>\
            <label>Allowlist: the only destinations the agent may pay (one per line: an xbt402 origin such as <code>https://api.example.net</code>, or an address)\
            <textarea name=\"f_allowlist\" rows=\"4\">{}</textarea></label>\
            <label>Counterparties for direct channel payments (one per line: <code>origin payTo-pubkey-hex</code>)<textarea name=\"f_counterparties\" rows=\"3\">{}</textarea></label></fieldset>\
            <fieldset><legend>Routing through hubs</legend>\
            <label>Hubs (one per line: <code>origin max_fee_ppm max_fee_base_msat</code>)<textarea name=\"f_hubs\" rows=\"2\">{}</textarea></label>\
            <label>Largest routed lock (sats)<input name=\"f_route_max_lock_sats\" value=\"{}\" inputmode=\"numeric\"></label>\
            <label>Routed budget per 24 h (sats)<input name=\"f_route_daily_budget_sats\" value=\"{}\" inputmode=\"numeric\"></label></fieldset>\
            <p><button>Review the change</button> <a href=\"./policy?template=starter\">Start from the conservative template</a></p></form>",
            esc(&allow), esc(&cps), esc(&hubs), escv(routing.get("max_lock_sats")), escv(routing.get("daily_budget_sats"))));
        b.push_str(&format!("<details><summary>Edit policy.json directly</summary><form method=\"post\" action=\"./policy\">{}\
            <input type=\"hidden\" name=\"mode\" value=\"json\"><textarea name=\"json\" rows=\"20\" class=\"mono\">{}</textarea>\
            <button>Review the change</button></form></details>", Self::csrf_input(ctx), esc(&serde_json::to_string_pretty(p).unwrap_or_default())));
        b
    }

    fn policy_page(&self, ctx: &Ctx, template: bool) -> Resp {
        let cur = match self.call("policy_get", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Policy", ctx, Self::error_box(&e)),
        };
        let mut b = String::from("<p>The rules the signer applies to every payment the agent asks for. A change takes effect \
            once you sign it with your approval key; the agent cannot change them.</p>");
        let pr = cur["pending_restart"].as_array().cloned().unwrap_or_default();
        if !pr.is_empty() {
            b.push_str(&format!("<div class=\"flash warn\">Signed but waiting for a signer restart: {}.</div>",
                                esc(&pr.iter().map(|x| txt(Some(x))).collect::<Vec<_>>().join(", "))));
        }
        let mut p = cur["policy"].clone();
        if template {
            let keep = p.clone();
            p = starter_policy();
            for k in ["allowlist", "counterparties", "routing", "human_pubkey"] {
                if let Some(v) = keep.get(k) {
                    p[k] = v.clone();
                }
            }
            b.push_str("<div class=\"flash ok\">The conservative template is filled in below (your allowlist, counterparties and routing are kept). Review, then sign.</div>");
        }
        let errs: Vec<String> = cur["errors"].as_array().map(|a| a.iter().map(|x| txt(Some(x))).collect()).unwrap_or_default();
        let warns: Vec<String> = cur["warnings"].as_array().map(|a| a.iter().map(|x| txt(Some(x))).collect()).unwrap_or_default();
        b.push_str(&self.policy_form(ctx, &p, &cur["effective"], &errs, &warns));
        b.push_str(&format!("<p class=\"small\">policy.json SHA-256 <code>{}</code></p>", escv(cur.get("sha256"))));
        self.page("Policy", ctx, b)
    }

    /// The form's fields on top of the current policy (unknown keys are kept).
    fn proposed_from_form(cur: &Value, f: &HashMap<String, String>) -> Value {
        let mut p = cur.as_object().cloned().unwrap_or_default();
        let num = |s: &str| -> Value { s.trim().parse::<i64>().map(Value::from).unwrap_or_else(|_| Value::from(s.trim())) };
        for (k, _, _) in INT_KEYS {
            if let Some(v) = f.get(&format!("f_{k}")) {
                p.insert(k.into(), num(v));
            }
        }
        p.insert("refund_enabled".into(), Value::Bool(f.contains_key("f_refund_enabled")));
        p.insert("anchor_required".into(), Value::Bool(f.contains_key("f_anchor_required")));
        let lines = |k: &str| -> Vec<String> { f.get(k).map(|v| v.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()).unwrap_or_default() };
        p.insert("allowlist".into(), Value::from(lines("f_allowlist")));
        let old_cp = cur.get("counterparties").and_then(Value::as_object).cloned().unwrap_or_default();
        let mut cps = Map::new();
        for l in lines("f_counterparties") {
            let mut it = l.split_whitespace();
            let (Some(origin), pay_to) = (it.next(), it.next().unwrap_or("")) else { continue };
            let mut e = old_cp.get(origin).and_then(Value::as_object).cloned().unwrap_or_default();
            e.insert("pay_to".into(), pay_to.into());
            cps.insert(origin.into(), Value::Object(e));
        }
        p.insert("counterparties".into(), Value::Object(cps));
        let mut routing = cur.get("routing").and_then(Value::as_object).cloned().unwrap_or_default();
        let mut hubs = Map::new();
        for l in lines("f_hubs") {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if let Some(h) = parts.first() {
                hubs.insert(h.to_string(), json!({"max_fee_ppm": num(parts.get(1).unwrap_or(&"0")), "max_fee_base_msat": num(parts.get(2).unwrap_or(&"0"))}));
            }
        }
        routing.insert("hubs".into(), Value::Object(hubs));
        for (fk, k) in [("f_route_max_lock_sats", "max_lock_sats"), ("f_route_daily_budget_sats", "daily_budget_sats")] {
            match f.get(fk).map(|v| v.trim()) {
                Some("") | None => { routing.remove(k); }
                Some(v) => { routing.insert(k.into(), num(v)); }
            }
        }
        if routing.get("hubs").and_then(Value::as_object).is_some_and(|h| h.is_empty()) && routing.len() == 1 {
            routing.clear();
        }
        p.insert("routing".into(), Value::Object(routing));
        Value::Object(p)
    }

    fn policy_preview(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let cur = match self.call("policy_get", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Policy", ctx, Self::error_box(&e)),
        };
        let proposed = if f.get("mode").map(String::as_str) == Some("json") {
            match serde_json::from_str::<Value>(f.get("json").map(String::as_str).unwrap_or("")) {
                Ok(v) => v,
                Err(e) => {
                    let body = self.policy_form(ctx, &cur["policy"], &cur["effective"], &[format!("policy.json: {e}")], &[]);
                    return self.page("Policy", ctx, body);
                }
            }
        } else {
            Self::proposed_from_form(&cur["policy"], f)
        };
        let prep = match self.call("policy_prepare", json!({"policy": proposed})) {
            Ok(v) => v,
            Err(e) => return self.page("Policy", ctx, Self::error_box(&e)),
        };
        let strs = |k: &str| -> Vec<String> { prep[k].as_array().map(|a| a.iter().map(|x| txt(Some(x))).collect()).unwrap_or_default() };
        if prep["ok"] != true {
            let body = self.policy_form(ctx, &proposed, &cur["effective"], &strs("errors"), &strs("warnings"));
            return self.page("Policy", ctx, body);
        }
        let mut b = String::from("<p>Check the change, then sign it with your approval key. The signer writes exactly the text below.</p>");
        let diff = prep["diff"].as_array().cloned().unwrap_or_default();
        if diff.is_empty() {
            b.push_str("<p class=\"empty\">No change.</p>");
        } else {
            b.push_str("<div class=\"scroll\"><table><thead><tr><th>Setting</th><th>Now</th><th>New</th><th></th></tr></thead><tbody>");
            for d in &diff {
                b.push_str(&format!("<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>", escv(d.get("key")),
                                    esc(&short(&d.get("old").map(|v| v.to_string()).unwrap_or_else(|| "(none)".into()), 200)),
                                    esc(&short(&d.get("new").map(|v| v.to_string()).unwrap_or_else(|| "(none)".into()), 200)),
                                    if d["restart"] == true { "<span class=\"tag warn\">after restart</span>" } else { "" }));
            }
            b.push_str("</tbody></table></div>");
        }
        let w = strs("warnings");
        if !w.is_empty() {
            b.push_str("<div class=\"flash warn\"><ul>");
            for x in w {
                b.push_str(&format!("<li>{}</li>", esc(&x)));
            }
            b.push_str("</ul></div>");
        }
        if prep["human_key"] != true {
            b.push_str("<div class=\"flash bad\">No approval key is enrolled: <a href=\"./setup\">set one up</a> before you can sign a policy.</div>");
        }
        let text = txt(prep.get("text"));
        let prev = txt(prep.get("prev_sha256"));
        let exp = int(prep.get("expiry"));
        let visible = format!("<details open><summary>The policy you sign</summary><pre class=\"signed-text\">{}</pre></details>", esc(&text));
        b.push_str(&self.signed_form(ctx, "./policy-apply", "policy", &self.human_pub(),
                                     &[("text", text.clone()), ("prev_sha256", prev.clone()), ("expiry", exp.to_string())], &visible,
                                     "Sign and apply", Ext::Bytes(msg::policy(&prev, exp, &text))));
        b.push_str("<p><a href=\"./policy\">Cancel</a></p>");
        self.page("Policy", ctx, b)
    }

    // --- channels -----------------------------------------------------------------------------------

    fn channels(&self, ctx: &Ctx) -> Resp {
        let ch = match self.call("channels", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Channels", ctx, Self::error_box(&e)),
        };
        let reps = self.call("channel_reports", json!({})).unwrap_or(json!({}));
        let height = int(ch.get("height"));
        let margin = int(reps.get("refund_margin_blocks"));
        let mut b = format!("<p>Spillman channels the wallet paid through. Tip height {height}. An open channel the provider never closes \
                             is refunded to the hot key {margin} blocks before its expiry (about 10 minutes a block).</p>");
        let list = ch["channels"].as_array().cloned().unwrap_or_default();
        if list.is_empty() {
            b.push_str("<p class=\"empty\">No channels yet.</p>");
        }
        for c in list.iter().rev() {
            let st = state_of(c);
            let chan = txt(c.get("chan"));
            let dest = txt(c.get("dest"));
            let expiry = int(c.get("expiry"));
            b.push_str(&format!("<article class=\"card chan\"><h2><span class=\"tag {}\">{st}</span> {}</h2>", if st == "open" { "ok" } else { "" },
                                esc(&txt(c.get("origin")).chars().next().map(|_| txt(c.get("origin"))).unwrap_or(dest.clone()))));
            let mut rows = vec![("Channel", format!("<code>{}</code>", esc(&chan))), ("Capacity", sats(int(c.get("cap_sats")))),
                                ("Paid (signed state)", sats(int(c.get("used_sats")))), ("Unspent", sats(int(c.get("residual_sats")))),
                                ("Expiry", format!("block {expiry}"))];
            if st == "open" || st == "pending" {
                let left = expiry - margin - height;
                rows.push(("Refund", if left > 0 { format!("in {left} blocks (≈ {} h) if not closed", (left * 10 + 59) / 60) }
                                     else { "due now (the watcher refunds it)".into() }));
            }
            for (k, label) in [("funding_txid", "Funding"), ("closed_txid", "Close"), ("refund_txid", "Refund tx")] {
                if let Some(t) = c.get(k).and_then(Value::as_str) {
                    rows.push((label, format!("<code>{}</code>", esc(t))));
                }
            }
            if let Some(e) = c.get("open_error").and_then(Value::as_str) {
                rows.push(("Open", esc(e)));
            }
            if let Some(cc) = c.get("close_change").and_then(Value::as_str) {
                rows.push(("Close change", esc(cc)));
            }
            if let Some(r) = reps.pointer(&format!("/reports/{}", chan.replace('~', "~0").replace('/', "~1"))) {
                let rep = &r["report"];
                let mut t = format!("<span class=\"tag {}\">{}</span> provider cum {}, unpaid {} msat", if rep["status"] == "ok" { "ok" } else { "bad" },
                                    escv(rep.get("status")), escv(rep.get("cum")), escv(rep.get("unpaid_msat")));
                if rep.get("payee_fee").is_some() {
                    t.push_str(&format!(", payeeFee {} (the provider's own close fee), payeeNet {}", escv(rep.get("payee_fee")), escv(rep.get("payee_net"))));
                }
                rows.push(("Close report", t));
            }
            b.push_str(&kv(&rows));
            if st == "open" {
                let key = if txt(c.get("origin")).is_empty() { dest.clone() } else { txt(c.get("origin")) };
                b.push_str(&format!("<div class=\"row\"><form method=\"post\" action=\"./channel-close\">{}<input type=\"hidden\" name=\"counterparty\" value=\"{}\">\
                    <button>Close cooperatively</button></form><form method=\"post\" action=\"./channel-refund\">{}<input type=\"hidden\" name=\"counterparty\" value=\"{}\">\
                    <button class=\"danger\"{}>Refund (after expiry)</button></form></div>", Self::csrf_input(ctx), esc(&key), Self::csrf_input(ctx), esc(&key),
                    if height >= expiry { "" } else { " disabled" }));
            }
            b.push_str("</article>");
        }
        self.page("Channels", ctx, b)
    }

    // --- signatures ---------------------------------------------------------------------------------

    fn signatures(&self, ctx: &Ctx) -> Resp {
        let s = match self.call("signatures", json!({"limit": 200})) {
            Ok(v) => v,
            Err(e) => return self.page("Signatures", ctx, Self::error_box(&e)),
        };
        let a = &s["anchor"];
        let mut b = String::from("<p>Every signature the signer made, hash-chained, and the chain's head anchored with the witness \
            (a separate process under another user): a rewritten log fails the check below.</p>");
        let chain_ok = s["chain_ok"] == true;
        b.push_str(&kv(&[
            ("Log check", if chain_ok { "<span class=\"tag ok\">chain intact, matches the anchor</span>".into() }
                          else { format!("<span class=\"tag bad\">FAILED</span> {}", esc(&s["chain"].to_string())) }),
            ("Anchor witness", if a["enabled"] == true { "enabled".into() } else { "<span class=\"tag warn\">not configured</span>".into() }),
            ("Anchored lines", escv(a.get("anchored_n"))), ("Log lines", escv(a.get("log_lines"))),
            ("Not yet anchored", escv(a.get("unanchored_lines"))), ("Last anchor", utc(int(a.get("anchored_at")))),
            ("Anchored head", format!("<code>{}</code>", esc(&short(&txt(a.get("anchored_head")), 20)))),
        ]));
        if let Some(e) = s.get("chain").and_then(|c| c.get("anchor_error")).or(s.get("anchor_error")) {
            b.push_str(&Self::error_box(&txt(Some(e))));
        }
        b.push_str(&format!("<form method=\"post\" action=\"./anchor-now\">{}<button>Anchor now</button></form>", Self::csrf_input(ctx)));
        b.push_str("<div class=\"scroll\"><table><thead><tr><th>When</th><th>Kind</th><th>Authorised by</th><th>Method</th><th>Destination</th><th>Signature hash</th></tr></thead><tbody>");
        for e in s["signatures"].as_array().cloned().unwrap_or_default().iter().rev() {
            b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>", utc(int(e.get("ts"))),
                                escv(e.get("kind")), escv(e.get("rule")), escv(e.get("method")), esc(&short(&txt(e.get("dest")), 40)),
                                esc(&short(&txt(e.get("sig_sha256")), 16))));
        }
        b.push_str("</tbody></table></div>");
        self.page("Signatures", ctx, b)
    }

    // --- keys ---------------------------------------------------------------------------------------

    fn keygen_block(&self, ctx: &Ctx, enroll: bool) -> String {
        let enroll_form = if enroll {
            format!("<form method=\"post\" action=\"./human-key-enroll\" id=\"enroll-form\" hidden>{}<input type=\"hidden\" name=\"pubkey\" value=\"\">\
                     <label>Enrolment code<input name=\"code\" class=\"mono\" autocomplete=\"off\" required placeholder=\"XXXX-XXXX-XXXX\"></label>\
                     <p class=\"hint\">The signer prints a one-time code in its log while no key is enrolled (Umbrel: the app's log; StartOS: Logs; \
                     a server: the signer's stderr or <code>.run/enroll-code</code>).</p>\
                     <button>Enrol this public key with the signer</button></form>", Self::csrf_input(ctx))
        } else {
            String::new()
        };
        format!("<div id=\"keygen\" class=\"card\"><h3>An approval key in this browser</h3>\
            <p>The key is made here and never sent to the box; only its public half is. It is kept in this browser's storage, \
            encrypted under a passphrase. Write the backup down: it is the only copy.</p>\
            <p><button type=\"button\" id=\"keygen-new\">Make a new key</button></p>\
            <details><summary>…or restore a key from its backup</summary><input id=\"keygen-import-hex\" class=\"mono\" placeholder=\"64 hex characters\" autocomplete=\"off\">\
            <button type=\"button\" id=\"keygen-import\">Use this key</button></details>\
            <div id=\"keygen-step2\" hidden><p>Backup (keep it offline):</p><pre id=\"keygen-backup\" class=\"hex\"></pre>\
            <label>Type its last 8 characters<input id=\"keygen-confirm\" autocomplete=\"off\"></label>\
            <label>Passphrase for this browser (at least 12 characters, not only digits or a repeated pattern)\
            <input id=\"keygen-pin\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\"></label>\
            <p id=\"keygen-strength\" class=\"hint\" aria-live=\"polite\">At least 12 characters, not only digits, not a repeated pattern.</p>\
            <label>Passphrase again<input id=\"keygen-pin2\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\"></label>\
            <button type=\"button\" id=\"keygen-save\">Save the key in this browser</button></div>\
            <p id=\"keygen-msg\" class=\"msg\" aria-live=\"polite\"></p>{enroll_form}\
            <p><button type=\"button\" id=\"keygen-forget\" class=\"link\">Remove the key from this browser</button></p></div>")
    }

    fn keys(&self, ctx: &Ctx) -> Resp {
        let ks = match self.call("keystore_status", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Keys", ctx, Self::error_box(&e)),
        };
        let human = txt(ks.get("human_pubkey"));
        let hot = &ks["hot"];
        let hot_addr = txt(hot.get("hot_address"));
        let exp = now() + SIGN_WINDOW_S;
        let mut b = format!("<section class=\"card\" id=\"human-key-state\" data-enrolled=\"{}\"><h2>Your approval key</h2>", esc(&human));
        b.push_str(&kv(&[("Enrolled public key", if human.is_empty() { "<span class=\"tag bad\">none</span>".into() } else { format!("<code>{}</code>", esc(&human)) })]));
        b.push_str("<p id=\"browser-key\" class=\"msg\"></p>");
        if human.is_empty() {
            b.push_str(&self.keygen_block(ctx, true));
        } else {
            b.push_str("<details><summary>Put the enrolled key in this browser (from its backup)</summary>");
            b.push_str(&self.keygen_block(ctx, false));
            b.push_str("</details><details><summary>Replace the approval key</summary><p>A new key is made in this browser, and the \
                current one signs the handover. The new key is kept under the same passphrase; write its backup down from the key page afterwards.</p>");
            b.push_str(&self.signed_form(ctx, "./human-key-rotate", "human-key", &human, &[("old_pub", human.clone()), ("pubkey", String::new()),
                                         ("expiry", exp.to_string())], "", "Make a new key and hand over", Ext::Browser));
            b.push_str("</details>");
        }
        b.push_str("</section>");
        b.push_str("<section class=\"card\"><h2>Hot key</h2>");
        b.push_str(&kv(&[("Address", format!("<code>{}</code>", esc(&hot_addr))), ("Balance", sats(int(hot.get("hot_sats")))),
                         ("Cap", if int(hot.get("hot_cap_sats")) > 0 { sats(int(hot.get("hot_cap_sats"))) } else { "none".into() }),
                         ("Retired keys", escv(hot.get("hot_retired_keys")))]));
        b.push_str("<h3>Sweep to your own wallet</h3>");
        b.push_str(&self.signed_form(ctx, "./sweep", "sweep", &human, &[("hot_address", hot_addr.clone()), ("expiry", exp.to_string())],
            "<label>To address<input name=\"to\" class=\"mono\" autocomplete=\"off\" required></label>\
             <label>Amount (sats)<input name=\"amount_sats\" inputmode=\"numeric\" required></label>",
            "Sign and sweep",
            Ext::Lines(format!("xbt-agentwallet-hot-sweep-v1\n{hot_addr}\n<to address>\n<amount in sats>\n{exp}"))));
        b.push_str("<h3>Rotate the hot key</h3><p>A new hot key; the coins on the old one move to it.</p>");
        b.push_str(&self.signed_form(ctx, "./rotate", "rotate", &human, &[("hot_address", hot_addr.clone()), ("expiry", exp.to_string())], "",
                                     "Sign and rotate", Ext::Bytes(msg::rotate(&hot_addr, exp))));
        b.push_str("</section>");
        b.push_str("<section class=\"card\"><h2>Wrapping key and backup</h2>");
        b.push_str(&kv(&[("Keys encrypted at rest", if ks["encrypted"] == true { "yes".into() } else { "<span class=\"tag bad\">no (test mode)</span>".into() }),
                         ("Wrapping key", match ks["kdf"].as_str() { Some("keyfile") => "a key file".into(), Some("scrypt") => "a passphrase".into(), _ => "none".into() }),
                         ("Key file", escv(ks.get("keyfile"))),
                         ("Key file mode", match ks["keyfile_mode"].as_str() { Some("600") | Some("400") => format!("{} <span class=\"tag ok\">private</span>", escv(ks.get("keyfile_mode"))),
                                                                             Some(m) => format!("{} <span class=\"tag bad\">readable by others</span>", esc(m)), None => "-".into() })]));
        b.push_str("<p>The backup holds the policy, the sealed keys, the channel book and the logs, plus the wrapping key sealed under the \
                    passphrase you choose here. Without that passphrase it opens nothing.</p>");
        b.push_str(&self.signed_form(ctx, "./backup", "backup", &human, &[("hot_address", hot_addr.clone()), ("expiry", exp.to_string())],
            "<label>Backup passphrase (at least 12 characters)<input name=\"backup_pass\" type=\"password\" autocomplete=\"new-password\" required></label>\
             <label>Again<input name=\"backup_pass2\" type=\"password\" autocomplete=\"new-password\" required></label>",
            "Sign and download the backup", Ext::Bytes(msg::backup(&hot_addr, exp))));
        b.push_str("</section>");
        self.page("Keys", ctx, b)
    }

    // --- hub and setup ------------------------------------------------------------------------------

    /// How an agent connects: the MCP endpoint and its bearer token (AGP-040). A box has no terminal, so
    /// this page is where the owner gets them. The token lets an agent pay allowlisted services within the
    /// policy and below the human threshold; it cannot approve, change the policy or move keys.
    fn agents(&self, ctx: &Ctx) -> Resp {
        let mut b = String::from("<section class=\"card\"><h2>Connect an agent</h2>\
            <p>Agents talk to the wallet's MCP server over HTTP with a bearer token. They can pay the services your policy allows, \
            within its budgets and below the human threshold. They cannot approve payments, change the policy or move keys.</p>");
        let urls = &self.cfg.mcp_urls;
        if urls.is_empty() {
            b.push_str("<p>No MCP address is configured for this page (<code>XBT_UI_MCP_URL</code>). The MCP server listens on port 33510 at <code>/mcp</code>.</p>");
        } else {
            b.push_str("<p>MCP endpoint:</p><ul>");
            for u in urls {
                b.push_str(&format!("<li><code>{}</code></li>", esc(u)));
            }
            b.push_str("</ul>");
        }
        let token = std::fs::read_to_string(&self.cfg.mcp_token_file).ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
        match token {
            None => b.push_str(&format!("<p>No token here yet (<code>{}</code>). The box's installer copies it from the MCP server on start.</p>",
                                        esc(&self.cfg.mcp_token_file.display().to_string()))),
            Some(t) => {
                let url = urls.first().cloned().unwrap_or_else(|| "http://<this box>:33510/mcp".into());
                let snippet = json!({"mcpServers": {"xbt-wallet": {"type": "http", "url": url, "headers": {"Authorization": format!("Bearer {t}")}}}});
                b.push_str(&format!("<details><summary>Show the bearer token</summary><p><code id=\"mcp-token\">{}</code></p>\
                                     <p>An MCP client configuration:</p>{}</details>\
                                     <p class=\"msg\">Treat the token like a card with a spending limit: anyone who holds it can pay what your policy allows.</p>",
                                    esc(&t), json_block(&snippet)));
                b.push_str(&format!("<form method=\"post\" action=\"./rotate-token\" class=\"stack\">{}<p>If the token leaked, replace it here. \
                    Every agent loses access until you give it the new one. No terminal and no app restart.</p>\
                    <label><input type=\"checkbox\" name=\"confirm\" value=\"1\" required> I will give my agents the new token</label>\
                    <button type=\"submit\">Rotate the token</button></form>", Self::csrf_input(ctx)));
            }
        }
        b.push_str("</section>");
        self.page("Agents", ctx, b)
    }

    /// Replace the MCP bearer token (AGP-042). The UI owns the token file and the MCP only reads it, on
    /// every request, so the old token stops working at once. The MCP is never asked: rotation must not be
    /// reachable with the token it replaces, and the new token goes nowhere but this file and this page.
    fn rotate_mcp_token(&self) -> Result<(), String> {
        let p = &self.cfg.mcp_token_file;
        let md = std::fs::symlink_metadata(p).map_err(|e| format!("read token: {e}"))?;
        if !md.file_type().is_file() {
            return Err("the token file is not a regular file".into());
        }
        // keep the mode xbt-init gave it (0640 on a box: the MCP reads it by group), never a bit for others
        let mode = mode_bits(&md) & 0o640;
        let new = hex::encode(crate::random_bytes::<32>());
        xbt_svc::replace_secret_file(p, format!("{new}\n").as_bytes(), mode | 0o600).map_err(|e| format!("{}: {e}", p.display()))
    }

    fn hub(&self, ctx: &Ctx) -> Resp {
        let mut b = String::new();
        match self.call("routing_status", json!({})) {
            Err(e) => b.push_str(&Self::error_box(&e)),
            Ok(r) => {
                let pol = &r["policy"];
                b.push_str("<section class=\"card\"><h2>Paying through hubs</h2>");
                b.push_str(&kv(&[("Routing", if pol["enabled"] == true { "<span class=\"tag ok\">on</span>".into() } else { "off (no hubs in the policy)".into() }),
                                 ("Adaptor", escv(r.get("adaptor"))), ("Routed in the last 24 h", sats(int(r.get("spent_24h_sats")))),
                                 ("24 h routed budget", sats(int(pol.get("daily_budget_sats")))), ("Largest lock", sats(int(pol.get("max_lock_sats"))))]));
                if let Some(h) = pol.get("hubs").and_then(Value::as_object) {
                    b.push_str("<ul>");
                    for (k, v) in h {
                        b.push_str(&format!("<li><code>{}</code>: at most {} ppm + {} msat</li>", esc(k), escv(v.get("max_fee_ppm")), escv(v.get("max_fee_base_msat"))));
                    }
                    b.push_str("</ul>");
                }
                let pend = r["pending"].as_array().cloned().unwrap_or_default();
                b.push_str(&format!("<p>Pending locks: {}</p>", pend.len()));
                if !pend.is_empty() {
                    b.push_str(&json_block(&Value::Array(pend)));
                }
                b.push_str("</section>");
            }
        }
        if let Some(t) = self.cmp_tile() {
            b.push_str(&t);
        }
        b.push_str("<section class=\"card\"><h2>This box's hub</h2>");
        match &self.cfg.hub_url {
            None => b.push_str("<p>No hub is configured for this box (<code>XBT_UI_HUB_URL</code>).</p>"),
            Some(u) => {
                let probe = |path: &str| http_get(&format!("{u}{path}"));
                b.push_str(&format!("<p><code>{}</code></p>", esc(u)));
                match probe("/readyz") {
                    Ok((st, body)) => {
                        if let Ok(v) = serde_json::from_str::<Value>(&body) {
                            if let Some(addr) = v.pointer("/wallet/receive_address").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                                let bal = v.pointer("/wallet/balance_sats").and_then(Value::as_u64).unwrap_or(0);
                                b.push_str(&format!("<section class=\"card\" id=\"hub-funding\"><h3>Fund the hub</h3>\
                                    <p>Send XBT to this address. The hub created the node wallet named <code>{}</code> for you; no terminal.</p>\
                                    <p>Receive address: <code id=\"hub-receive\">{}</code></p><p>Balance: {}</p>",
                                    esc(v.pointer("/wallet/name").and_then(Value::as_str).unwrap_or("hub")), esc(addr), sats(bal as i64)));
                                if let Some(onion) = v.get("tor").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                                    b.push_str(&format!("<p>Tor: <code id=\"hub-tor\">{}</code></p>", esc(onion)));
                                }
                                b.push_str("</section>");
                            }
                        }
                        b.push_str(&format!("<p><span class=\"tag {}\">{st}</span> <code>/readyz</code></p><pre class=\"json\">{}</pre>",
                                            if st == 200 { "ok" } else { "bad" }, esc(&short(&body, 2000))));
                    }
                    Err(e) => b.push_str(&format!("<p><span class=\"tag bad\">unreachable</span> <code>/readyz</code>: {}</p>", esc(&e))),
                }
                for path in ["/healthz", "/x402/supported"] {
                    match probe(path) {
                        Ok((st, body)) => b.push_str(&format!("<p><span class=\"tag {}\">{st}</span> <code>{path}</code></p><pre class=\"json\">{}</pre>",
                                                              if st == 200 { "ok" } else { "bad" }, esc(&short(&body, 2000)))),
                        Err(e) => b.push_str(&format!("<p><span class=\"tag bad\">unreachable</span> <code>{path}</code>: {}</p>", esc(&e))),
                    }
                }
            }
        }
        b.push_str("</section>");
        self.page("Hub", ctx, b)
    }

    /// xbt-compute's node/hub (cmp-lead): a link to its status page and, when a status URL is set, a
    /// compact tile from its JSON (CONTRACT §U: `/healthz`, `/readyz`, JSON status with node sync %).
    /// The JSON has no fixed schema yet, so the tile shows the common fields and folds the rest.
    fn cmp_tile(&self) -> Option<String> {
        if self.cfg.cmp_url.is_none() && self.cfg.cmp_status_url.is_none() {
            return None;
        }
        let mut b = String::from("<div class=\"card\" id=\"cmp-status\"><h2>XBT Compute</h2>");
        if let Some(u) = &self.cfg.cmp_status_url {
            match http_get(u) {
                Ok((st, body)) => {
                    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                    let up = st == 200 && v.get("ok") != Some(&Value::Bool(false)) && v.get("ready") != Some(&Value::Bool(false));
                    let rows = vec![("Status", format!("<span class=\"tag {}\">{}</span> HTTP {st}", if up { "ok" } else { "bad" }, if up { "up" } else { "not ready" }))];
                    let mut extra: Vec<(String, String)> = vec![];
                    if let Some(m) = v.as_object() {
                        for (k, x) in m {
                            let kl = k.to_ascii_lowercase();
                            if (kl.contains("sync") || ["role", "version", "chain", "height", "ready", "ok", "mode", "hub"].contains(&kl.as_str())) && !x.is_object() && !x.is_array() {
                                extra.push((k.clone(), esc(&short(&txt(Some(x)), 80))));
                            }
                        }
                    }
                    let mut html = kv(&rows);
                    if !extra.is_empty() {
                        html.push_str(&kv(&extra.iter().map(|(k, v)| (k.as_str(), v.clone())).collect::<Vec<_>>()));
                    }
                    b.push_str(&html);
                    if !v.is_null() {
                        b.push_str(&format!("<details><summary>Status JSON</summary>{}</details>", json_block(&v)));
                    }
                }
                Err(e) => b.push_str(&format!("<p><span class=\"tag bad\">unreachable</span> {}</p>", esc(&e))),
            }
        }
        if let Some(l) = &self.cfg.cmp_url {
            b.push_str(&format!("<p><a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">Node and hub status →</a></p>", esc(l)));
        }
        b.push_str("</div>");
        Some(b)
    }

    fn setup(&self, ctx: &Ctx) -> Resp {
        let ks = match self.call("keystore_status", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Setup", ctx, Self::error_box(&e)),
        };
        let pol = self.call("policy_get", json!({})).unwrap_or(json!({}));
        let hist = self.call("history", json!({"limit": 5000})).unwrap_or(json!({}));
        let events = hist["events"].as_array().cloned().unwrap_or_default();
        let seen = |t: &str| events.iter().any(|e| e["type"] == t);
        let human = txt(ks.get("human_pubkey"));
        let allow_n = pol["policy"]["allowlist"].as_array().map(|a| a.len()).unwrap_or(0);
        let step = |done: bool, title: &str, body: String| {
            format!("<li class=\"step {}\"><h2>{} {}</h2>{body}</li>", if done { "done" } else { "todo" }, if done { "✓" } else { "○" }, esc(title))
        };
        let mut b = String::from("<p>Four steps. The wallet is safe to leave running after each one; nothing is paid until your policy allows it.</p><ol class=\"steps\">");
        b.push_str(&step(true, "UI password", "<p>Set. Sessions end after 15 minutes idle.</p>".into()));
        let key_body = if human.is_empty() {
            format!("<section id=\"human-key-state\" data-enrolled=\"\"><p id=\"browser-key\" class=\"msg\"></p>{}</section>", self.keygen_block(ctx, true))
        } else {
            format!("<section id=\"human-key-state\" data-enrolled=\"{}\"><p>Enrolled: <code>{}</code></p><p id=\"browser-key\" class=\"msg\"></p>\
                     <p><a href=\"./keys\">Manage keys →</a></p></section>", esc(&human), esc(&human))
        };
        b.push_str(&step(!human.is_empty(), "Your approval key", key_body));
        b.push_str(&step(seen("policy_change"), "Your policy",
            format!("<p>{} destination{} allowed now. Start from the conservative template, add the services your agent may pay, and sign it.</p>\
                     <p><a href=\"./policy?template=starter\">Open the template →</a></p>", allow_n, if allow_n == 1 { "" } else { "s" })));
        let enc = ks["encrypted"] == true;
        b.push_str(&step(enc && seen("backup_export"), "Wrapping key and backup",
            format!("<p>The signer's keys are {} at rest{}. {}</p><p><a href=\"./keys\">Download an encrypted backup →</a></p>",
                    if enc { "encrypted" } else { "<strong>not</strong> encrypted" },
                    match ks["kdf"].as_str() { Some("keyfile") => " with a key file", Some("scrypt") => " with a passphrase", _ => "" },
                    if seen("backup_export") { "A backup was exported." } else { "No backup exported yet." })));
        b.push_str("</ol>");
        self.page("Setup", ctx, b)
    }
}

#[cfg(unix)]
fn mode_bits(md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_bits(_: &std::fs::Metadata) -> u32 {
    0o600
}

/// A plain-HTTP GET with a short timeout (the hub is on the box's own network).
pub fn http_get(url: &str) -> Result<(u16, String), String> {
    use std::io::{Read, Write};
    let rest = url.strip_prefix("http://").ok_or("only http:// hub URLs are probed")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&if hostport.contains(':') { hostport.to_string() } else { format!("{hostport}:80") })
        .map_err(|e| e.to_string())?.next().ok_or("no address")?;
    let t = std::time::Duration::from_secs(3);
    let mut s = std::net::TcpStream::connect_timeout(&addr, t).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(t)).ok();
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: {hostport}\r\nConnection: close\r\n\r\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.take(64 * 1024).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    Ok((status, body))
}

/// AGP-063 W4: a Host this UI answers to. An absent one (no browser sends none), an IP literal, a
/// single-label name (`localhost`, a container name behind the box's proxy), `*.local`,
/// `*.localhost`, `*.onion`, or one of `XBT_UI_ALLOWED_HOSTS`. Any other name points a public DNS
/// name at this box's address: a rebinding page that would read the UI.
pub fn host_allowed(host: &str, allowed: &[String]) -> bool {
    let h = host.trim().to_ascii_lowercase();
    if h.is_empty() || allowed.iter().any(|a| a == "*") {
        return true;
    }
    let name = match h.strip_prefix('[') {
        Some(r) => return r.split(']').next().is_some_and(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok()),
        None => h.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(n, _)| n).unwrap_or(&h),
    };
    let name = name.trim_end_matches('.');
    name.parse::<std::net::IpAddr>().is_ok() || !name.contains('.') || [".local", ".localhost", ".onion"].iter().any(|t| name.ends_with(t))
        || allowed.iter().any(|a| a == name)
}

/// A POST's `Origin`: its host must be one [`host_allowed`] accepts. `null` counts as absent: this
/// UI's own pages send it (`Referrer-Policy: no-referrer`), and any page can, so the Host check
/// is what refuses a rebinding; the CSRF token and SameSite cookie refuse the rest.
pub fn origin_allowed(origin: &str, allowed: &[String]) -> bool {
    let o = origin.trim();
    if o == "null" {
        return true;
    }
    let rest = o.strip_prefix("http://").or_else(|| o.strip_prefix("https://"));
    rest.is_some_and(|r| !r.is_empty() && !r.contains('/') && host_allowed(r, allowed))
}
