//! AGP-072 (review T1): both relay listeners survive slow and endless heads and bodies. Real sockets
//! on 127.0.0.1.
#[path = "../../xbt-svc/tests/common/slowloris.rs"]
mod slowloris;

use std::sync::Arc;
use std::time::Duration;

use xbt_work_relay::{serve, Config, Relay, Running, Store, BLOB_LEN};

const OK: &str = "GET /healthz HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n";
const LOOKUP: &str = "3f1c0d7e5a2b4c6d8e9f00112233445566778899aabbccddeeff001122334455";

fn start() -> Running {
    let r = Arc::new(Relay::new(
        Config {
            rate: 0.0,
            ..Config::default()
        },
        Store::memory(10, 0),
    ));
    serve(
        r,
        "127.0.0.1:0",
        Some("127.0.0.1:0"),
        2,
        Duration::from_secs(3600),
    )
    .unwrap()
}

fn slow() -> String {
    format!("PUT /{LOOKUP} HTTP/1.1\r\nHost: h\r\nContent-Length: {BLOB_LEN}\r\n\r\n")
}

#[test]
fn slow_bodies_do_not_stall_the_public_listener() {
    let run = start();
    slowloris::slow_bodies_do_not_stall_and_are_cut_off(&run.public.to_string(), OK, &slow(), 8);
}

#[test]
fn slow_bodies_do_not_stall_the_push_listener() {
    let run = start();
    slowloris::slow_bodies_do_not_stall_and_are_cut_off(
        &run.push.unwrap().to_string(),
        OK,
        &slow(),
        8,
    );
}

#[test]
fn slow_heads_do_not_stall_the_public_listener_and_are_cut_off() {
    let run = start();
    slowloris::slow_heads_do_not_stall_and_are_cut_off(&run.public.to_string(), OK);
}

#[test]
fn slow_heads_do_not_stall_the_push_listener_and_are_cut_off() {
    let run = start();
    slowloris::slow_heads_do_not_stall_and_are_cut_off(&run.push.unwrap().to_string(), OK);
}

#[test]
fn an_endless_header_line_is_refused_by_both_listeners() {
    let run = start();
    slowloris::an_endless_header_line_is_refused(&run.public.to_string(), OK);
    slowloris::an_endless_header_line_is_refused(&run.push.unwrap().to_string(), OK);
}
