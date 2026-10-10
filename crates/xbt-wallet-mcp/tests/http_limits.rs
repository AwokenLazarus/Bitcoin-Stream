//! AGP-072 (review T1): the MCP's streamable HTTP transport survives slow and endless heads and
//! bodies. Real sockets on 127.0.0.1; no signer is needed for `/healthz` or for a body that never arrives.
#[path = "../../xbt-svc/tests/common/slowloris.rs"]
mod slowloris;

use std::net::TcpListener;
use std::sync::Arc;

use xbt_wallet_mcp::mcp::Server;
use xbt_wallet_mcp::transport::{serve_listener, HttpConfig};
use xbt_wallet_mcp::wallet::{PayerMode, Wallet};

const OK: &str = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
const SLOW: &str = "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer t0ken\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n";

/// The transport on a port the OS picks and keeps bound.
fn start() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let mut cfg = HttpConfig::new(addr.clone());
    cfg.token = Some("t0ken".into());
    let server = Arc::new(Server::new(Arc::new(Wallet::new(
        "/nonexistent/signer.sock".into(),
        PayerMode::Signer,
    ))));
    serve_listener(server, cfg, l).unwrap();
    addr
}

#[test]
fn slow_bodies_do_not_stall_the_mcp() {
    slowloris::slow_bodies_do_not_stall_and_are_cut_off(&start(), OK, SLOW, 8);
}

#[test]
fn slow_heads_do_not_stall_the_mcp_and_are_cut_off() {
    slowloris::slow_heads_do_not_stall_and_are_cut_off(&start(), OK);
}

#[test]
fn an_endless_header_line_is_refused_by_the_mcp() {
    slowloris::an_endless_header_line_is_refused(&start(), OK);
}
