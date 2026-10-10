//! AGP-072: the shared bounded server's edges over real sockets: HEAD and 204 carry no body, a
//! handler cannot inject headers or keep a handler slot, Expect: 100-continue, 413 before the body, the
//! peer is the socket's, and a stopped server takes no more connections.
#[path = "common/slowloris.rs"]
mod slowloris;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use xbt_svc::http::{serve, Handler, Request, Response, Running};

struct T;

impl Handler for T {
    fn body_limit(&self, _method: &str, target: &str) -> usize {
        if target == "/small" {
            4
        } else {
            1 << 16
        }
    }

    fn handle(&self, req: Request) -> Response {
        match req.path() {
            "/panic" => panic!("handler bug"),
            "/empty" => Response::new(204, vec![("X-A".into(), "1".into())], b"ignored".to_vec()),
            "/inject" => Response::new(
                200,
                vec![
                    ("X-Evil".into(), "a\r\nSet-Cookie: x=1".into()),
                    ("Content-Length".into(), "1".into()),
                    ("Connection".into(), "keep-alive".into()),
                    ("X-Ok".into(), "yes".into()),
                ],
                b"body".to_vec(),
            ),
            "/peer" => Response::text(
                200,
                "text/plain",
                req.peer.map(|a| a.ip().to_string()).unwrap_or_default(),
            ),
            _ => Response::text(
                200,
                "text/plain",
                format!(
                    "{} {} {}",
                    req.method,
                    req.target,
                    String::from_utf8_lossy(&req.body)
                ),
            ),
        }
    }
}

fn start() -> (Running, String) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let run = serve(Arc::new(T), l, 2).unwrap();
    let addr = run.addr.to_string();
    (run, addr)
}

fn raw(addr: &str, req: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).to_string()
}

#[test]
fn head_and_204_carry_no_body() {
    let (_run, a) = start();
    let r = raw(&a, b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n");
    assert!(
        r.starts_with("HTTP/1.1 200 OK\r\n")
            && r.contains("Content-Length: 8\r\n")
            && r.ends_with("\r\n\r\n"),
        "{r}"
    );
    let r = raw(&a, b"GET /empty HTTP/1.1\r\nHost: h\r\n\r\n");
    assert!(
        r.starts_with("HTTP/1.1 204 No Content\r\n")
            && r.contains("X-A: 1\r\n")
            && !r.contains("Content-Length")
            && r.ends_with("\r\n\r\n"),
        "{r}"
    );
}

#[test]
fn a_handler_cannot_inject_headers_or_set_framing() {
    let (_run, a) = start();
    let r = raw(&a, b"GET /inject HTTP/1.1\r\nHost: h\r\n\r\n");
    assert!(
        !r.contains("Set-Cookie") && !r.contains("X-Evil") && !r.contains("keep-alive"),
        "{r}"
    );
    assert!(
        r.contains("X-Ok: yes\r\n")
            && r.contains("Content-Length: 4\r\n")
            && r.contains("Connection: close\r\n")
            && r.ends_with("\r\n\r\nbody"),
        "{r}"
    );
}

#[test]
fn a_panicking_handler_costs_its_request_not_a_slot() {
    let (_run, a) = start();
    for _ in 0..4 {
        assert!(raw(&a, b"GET /panic HTTP/1.1\r\nHost: h\r\n\r\n").starts_with("HTTP/1.1 500"));
    }
    assert!(
        raw(&a, b"GET /ok HTTP/1.1\r\nHost: h\r\n\r\n").starts_with("HTTP/1.1 200"),
        "both handler slots were given back"
    );
}

#[test]
fn bodies_need_one_content_length_under_the_limit() {
    let (_run, a) = start();
    assert!(raw(
        &a,
        b"POST /e HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"
    )
    .ends_with("POST /e abc"));
    // refused before a body byte is read: nothing is sent after the head
    assert!(raw(
        &a,
        b"POST /small HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n"
    )
    .starts_with("HTTP/1.1 413"));
    assert!(raw(
        &a,
        b"POST /e HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc"
    )
    .starts_with("HTTP/1.1 400"));
    assert!(raw(
        &a,
        b"POST /e HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    )
    .starts_with("HTTP/1.1 501"));
    let mut s = TcpStream::connect(&a).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(
        b"POST /e HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n",
    )
    .unwrap();
    let mut buf = [0u8; 25];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"HTTP/1.1 100 Continue\r\n\r\n");
    s.write_all(b"hi").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.ends_with("POST /e hi"), "{out}");
}

#[test]
fn the_peer_is_the_socket_s() {
    let (_run, a) = start();
    assert!(raw(
        &a,
        b"GET /peer HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n"
    )
    .ends_with("\r\n\r\n127.0.0.1"));
}

#[test]
fn a_stopped_server_takes_no_more_requests() {
    let (run, a) = start();
    assert!(raw(&a, b"GET /ok HTTP/1.1\r\nHost: h\r\n\r\n").starts_with("HTTP/1.1 200"));
    run.stopper().stop();
    for t in run.threads {
        t.join().unwrap();
    }
    assert!(TcpStream::connect(&a).is_err(), "the listener is closed");
}

#[test]
fn the_shared_slowloris_checks_pass_on_the_bare_server() {
    let (_run, a) = start();
    const OK: &str = "GET /ok HTTP/1.1\r\nHost: h\r\n\r\n";
    slowloris::an_endless_header_line_is_refused(&a, OK);
}

/// Connections that sent half a head and wait: each holds a connection slot until the head deadline.
fn hold(addr: &str, n: usize) -> Vec<TcpStream> {
    (0..n)
        .map(|_| {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /x HTTP/1.1\r\nHost: h\r\n").unwrap();
            s
        })
        .collect()
}

/// AGP-081 (review T1): the connection cap was one global number, so one address holding every slot
/// kept every other client at 503. An address gets at most `Limits::per_address` of them.
#[test]
fn one_address_cannot_hold_every_connection() {
    let limits = xbt_svc::http::Limits::default();
    assert!(limits.per_address > 0 && limits.per_address < limits.connections);
    // dual-stack where the host has IPv6: a 127.0.0.1 client and a ::1 client are two addresses
    let (l, v6) = match TcpListener::bind("[::]:0") {
        Ok(l) => {
            let v6 = TcpStream::connect(("::1", l.local_addr().unwrap().port())).is_ok();
            (l, v6)
        }
        Err(_) => (TcpListener::bind("127.0.0.1:0").unwrap(), false),
    };
    let run = serve(Arc::new(T), l, 2).unwrap();
    let port = run.addr.port();
    let v4 = format!("127.0.0.1:{port}");
    std::thread::sleep(Duration::from_millis(100)); // the probe connection above is gone
    let held = hold(&v4, limits.connections);
    std::thread::sleep(Duration::from_millis(300));
    // the address is at its cap: its next connection is refused, with slots still free
    let r = raw(&v4, b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    assert!(
        r.starts_with("HTTP/1.1 503 "),
        "one address took more than its share: {r:?}"
    );
    if v6 {
        let r = raw(
            &format!("[::1]:{port}"),
            b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        assert!(
            r.starts_with("HTTP/1.1 200 OK\r\n"),
            "another address was shut out by one address's connections: {r:?}"
        );
    } else {
        eprintln!(
            "no IPv6 loopback here: the second-address half ran only as the unit test in http.rs"
        );
    }
    // its slots come back when its connections end
    drop(held);
    std::thread::sleep(Duration::from_millis(300));
    let r = raw(&v4, b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r:?}");
    run.stopper().stop();
}

/// AGP-081 (review T2): a request target with a `#` is refused before any handler sees it.
#[test]
fn a_target_with_a_fragment_is_refused() {
    let (_run, a) = start();
    for t in ["/x#y", "/x?a=1#y", "/#", "#"] {
        let r = raw(
            &a,
            format!("GET {t} HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes(),
        );
        assert!(r.starts_with("HTTP/1.1 400 "), "{t}: {r:?}");
    }
    assert!(raw(&a, b"GET /x?a=%23 HTTP/1.1\r\nHost: h\r\n\r\n").starts_with("HTTP/1.1 200 OK\r\n"));
}
