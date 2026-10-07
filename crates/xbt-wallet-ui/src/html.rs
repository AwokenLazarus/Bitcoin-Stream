//! Escaping, the page layout and value formatting. Every URL is relative (`./x`), so the UI works
//! under any proxy prefix and on an .onion; nothing is loaded from elsewhere.
use serde_json::Value;

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// A JSON value as display text (strings unquoted).
pub fn txt(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
    }
}

pub fn escv(v: Option<&Value>) -> String {
    esc(&txt(v))
}

pub fn int(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Number(n)) => n.as_i64().unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

fn group3(n: u64) -> String {
    let s = n.to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            o.push(',');
        }
        o.push(c);
    }
    o
}

/// `150,000 sats (0.00150000 XBT)`.
pub fn sats(n: i64) -> String {
    let sign = if n < 0 { "-" } else { "" };
    let a = n.unsigned_abs();
    format!("{sign}{} sats <span class=\"xbt\">({sign}{}.{:08} XBT)</span>", group3(a), a / 100_000_000, a % 100_000_000)
}

/// UTC `YYYY-MM-DD HH:MM:SS` from Unix seconds.
pub fn utc(t: i64) -> String {
    if t <= 0 {
        return "-".into();
    }
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // civil_from_days (H. Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", secs / 3600, secs % 3600 / 60, secs % 60)
}

pub fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

pub struct Nav<'a> {
    pub active: &'a str,
    pub csrf: &'a str,
    pub pending: usize,
    pub logged_in: bool,
}

const PAGES: [(&str, &str); 9] = [("./", "Overview"), ("./approvals", "Approvals"), ("./policy", "Policy"), ("./channels", "Channels"),
                                  ("./signatures", "Signatures"), ("./keys", "Keys"), ("./agents", "Agents"), ("./hub", "Hub"), ("./setup", "Setup")];

pub fn page(title: &str, nav: &Nav, flash: Option<(bool, String)>, body: &str) -> String {
    let mut links = String::new();
    if nav.logged_in {
        for (href, name) in PAGES {
            let cur = if name == nav.active { " aria-current=\"page\"" } else { "" };
            let badge = if name == "Approvals" {
                format!(" <span id=\"pending-badge\" class=\"badge\"{}>{}</span>", if nav.pending == 0 { " hidden" } else { "" },
                        if nav.pending == 0 { String::new() } else { nav.pending.to_string() })
            } else {
                String::new()
            };
            links.push_str(&format!("<a href=\"{href}\"{cur}>{name}{badge}</a>"));
        }
        links.push_str(&format!("<form method=\"post\" action=\"./logout\" class=\"inline\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                                 <button class=\"link\">Log out</button></form>", esc(nav.csrf)));
    }
    let flash = flash.map(|(ok, m)| format!("<div class=\"flash {}\" role=\"status\">{}</div>", if ok { "ok" } else { "bad" }, esc(&m))).unwrap_or_default();
    format!("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <meta name=\"referrer\" content=\"no-referrer\"><link rel=\"icon\" href=\"data:,\"><title>{} · XBT Agent Wallet</title>\
             <link rel=\"stylesheet\" href=\"./ui.css?v={}\"></head><body>\
             <header><div class=\"brand\">XBT Agent Wallet</div><nav>{links}</nav></header>\
             <main>{flash}<h1>{}</h1>{body}</main>\
             <footer>Keys stay in the signer; your approval key stays in your browser.</footer>\
             <script src=\"./ui.js?v={}\"></script></body></html>\n",
            esc(title), asset_version(crate::UI_CSS), esc(title), asset_version(crate::UI_JS))
}

/// A short content hash for cache busting.
pub fn asset_version(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(s.as_bytes())[..6])
}

pub fn kv(rows: &[(&str, String)]) -> String {
    let mut o = String::from("<dl class=\"kv\">");
    for (k, v) in rows {
        o.push_str(&format!("<dt>{}</dt><dd>{v}</dd>", esc(k)));
    }
    o.push_str("</dl>");
    o
}

/// The JSON a signer returned, for a details box.
pub fn json_block(v: &Value) -> String {
    format!("<pre class=\"json\">{}</pre>", esc(&serde_json::to_string_pretty(v).unwrap_or_default()))
}
