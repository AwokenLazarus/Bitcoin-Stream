//! AGP-072 (review T1): the UI's HTTP server survives slow and endless heads and bodies. Real
//! sockets on 127.0.0.1; no signer is needed for `/healthz` or for a body that never arrives.
#[path = "../../xbt-svc/tests/common/slowloris.rs"]
mod slowloris;

use xbt_wallet_ui::app::App;
use xbt_wallet_ui::config::Config;
use xbt_wallet_ui::server::Running;

const OK: &str = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
const SLOW: &str = "POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100000\r\n\r\n";

fn start() -> (Running, String, tempfile::TempDir) {
    let d = tempfile::tempdir().unwrap();
    let app = App::new(Config::for_test(
        d.path().join("no-signer.sock"),
        d.path().join("ui"),
        "127.0.0.1:0",
    ))
    .unwrap();
    let srv = xbt_wallet_ui::server::spawn(app).unwrap();
    let addr = srv.addr.to_string();
    (srv, addr, d)
}

#[test]
fn slow_bodies_do_not_stall_the_ui() {
    let (_srv, addr, _d) = start();
    slowloris::slow_bodies_do_not_stall_and_are_cut_off(&addr, OK, SLOW, 8);
}

#[test]
fn slow_heads_do_not_stall_the_ui_and_are_cut_off() {
    let (_srv, addr, _d) = start();
    slowloris::slow_heads_do_not_stall_and_are_cut_off(&addr, OK);
}

#[test]
fn an_endless_header_line_is_refused_by_the_ui() {
    let (_srv, addr, _d) = start();
    slowloris::an_endless_header_line_is_refused(&addr, OK);
}
