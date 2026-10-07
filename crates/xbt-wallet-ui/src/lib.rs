//! xbt-wallet-ui (AGP-039): the agent wallet's web UI for a box with no terminal (Umbrel, StartOS).
//!
//! A separate process that talks only to the signer's socket, like the MCP server. It renders plain
//! HTML on the server; the only script, `assets/ui.js`, holds the human's ed25519 key in the browser
//! and signs there, so approvals keep B2's human-key property: the box never holds the approving key.
//!
//! * [`config`]: environment and data directory.
//! * [`auth`]: the login (scrypt), sessions, CSRF tokens, the login throttle.
//! * [`link`]: the signer socket client.
//! * [`msg`]: the signed message formats (the same bytes as `xbt_signer::approval` and `ui.js`).
//! * [`html`]: escaping, the page layout, formatting.
//! * [`app`]: the routes and pages; [`server`]: the HTTP server.
pub mod app;
pub mod auth;
pub mod config;
pub mod html;
pub mod link;
pub mod msg;
pub mod server;

pub const UI_JS: &str = include_str!("../assets/ui.js");
pub const UI_CSS: &str = include_str!("../assets/ui.css");

/// OS randomness.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}

/// Seconds since the epoch.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Constant-time equality for secrets of public length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
