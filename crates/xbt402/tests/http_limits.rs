//! AGP-068 T1/T3: the HTTP server survives slow and oversized clients, and the payer's transport
//! never returns a truncated body as a good one. Real sockets on 127.0.0.1.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use xbt402::client::Transport;
use xbt402::http::{serve_listener, HttpService, UreqTransport};
use xbt402::provider::{HttpResponse, PEER_HEADER};

struct Echo;

impl HttpService for Echo {
    fn body_limit(&self, _path: &str) -> usize {
        1 << 20
    }
    fn serve(
        &self,
        method: &str,
        path: &str,
        _headers: &[(String, String)],
        body: &[u8],
        url: &str,
    ) -> HttpResponse {
        HttpResponse::new(
            200,
            vec![("X-Url".into(), url.into())],
            format!("{method} {path} {}", body.len()).into_bytes(),
        )
    }
}

/// The server on a port the OS picks and keeps bound (no fixed port, no rebind race).
fn start(threads: usize) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    serve_listener(Arc::new(Echo), l, threads).unwrap();
    addr
}

/// One request on a fresh connection; the status line and body, or None if nothing came back in `wait`.
fn get(addr: &str, wait: Duration) -> Option<String> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(wait)).unwrap();
    s.write_all(b"GET /ok HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).to_string();
    text.starts_with("HTTP/1.1 200").then_some(text)
}

#[test]
fn slow_bodies_do_not_stall_the_server() {
    let addr = start(4);
    // more connections than workers, each promising a body it never sends (tiny_http read bodies
    // up to 1 KiB on its connection thread and larger ones on the workers)
    let slow: Vec<TcpStream> = (0..8)
        .map(|_| {
            let mut s = TcpStream::connect(&addr).unwrap();
            s.write_all(b"POST /slow HTTP/1.1\r\nHost: h\r\nContent-Length: 100000\r\n\r\n")
                .unwrap();
            s
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    let t = Instant::now();
    let r = get(&addr, Duration::from_secs(3));
    assert!(
        r.is_some(),
        "a normal request stalled behind {} slow bodies ({:?})",
        slow.len(),
        t.elapsed()
    );
    drop(slow);
}

#[test]
fn slow_heads_do_not_stall_the_server_and_are_cut_off() {
    let addr = start(4);
    let mut slow: Vec<TcpStream> = (0..32)
        .map(|_| {
            let mut s = TcpStream::connect(&addr).unwrap();
            s.write_all(b"GET /slow HTTP/1.1\r\nHost: h\r\nX-Drip: ")
                .unwrap();
            s
        })
        .collect();
    assert!(
        get(&addr, Duration::from_secs(3)).is_some(),
        "a normal request stalled behind slow heads"
    );
    // a head that never ends is cut off at the head deadline (10 s by default), not held forever
    let s = &mut slow[0];
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let t = Instant::now();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    assert!(
        t.elapsed() < Duration::from_secs(15),
        "a slow head held its connection for {:?}",
        t.elapsed()
    );
}

#[test]
fn an_endless_header_line_is_refused() {
    let addr = start(4);
    let mut s = TcpStream::connect(&addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: h\r\nX-Long: ");
    let chunk = vec![b'a'; 64 * 1024];
    let mut sent = 0usize;
    // the server must answer 431 and close long before 4 MiB of one header line
    while sent < 4 << 20 {
        if s.write_all(&chunk).is_err() {
            break;
        }
        sent += chunk.len();
    }
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.starts_with("HTTP/1.1 431"),
        "after {sent} bytes of one header line: {:?}",
        &text[..text.len().min(80)]
    );
    assert!(get(&addr, Duration::from_secs(3)).is_some());
}

/// A raw server answering every connection with `head` then `body`, then closing.
fn raw_server(head: String, body: Arc<Vec<u8>>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let (head, body) = (head.clone(), body.clone());
            std::thread::spawn(move || {
                let mut req = [0u8; 4096];
                let _ = s.read(&mut req);
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(&body);
            });
        }
    });
    addr
}

#[test]
fn an_oversized_response_is_an_error_not_a_truncated_body() {
    let n = (64 << 20) + 1;
    let addr = raw_server(
        format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n"),
        Arc::new(vec![b'x'; n]),
    );
    let r = UreqTransport::default().request("GET", &format!("http://{addr}/big"), b"", &[]);
    assert!(
        r.is_err(),
        "a {n}-byte body came back as Ok with {} bytes",
        r.map(|r| r.body.len()).unwrap_or(0)
    );
}

#[test]
fn a_body_cut_short_is_an_error() {
    let addr = raw_server(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".into(),
        Arc::new(vec![b'x'; 50]),
    );
    let r = UreqTransport::default().request("GET", &format!("http://{addr}/short"), b"", &[]);
    assert!(
        r.is_err(),
        "50 of 100 bytes came back as Ok with {} bytes",
        r.map(|r| r.body.len()).unwrap_or(0)
    );
}

struct Peers;

impl HttpService for Peers {
    fn body_limit(&self, _path: &str) -> usize {
        1 << 10
    }
    fn serve(&self, _method: &str, _path: &str, headers: &[(String, String)], _body: &[u8], _url: &str) -> HttpResponse {
        let peers: Vec<&str> = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(PEER_HEADER)).map(|(_, v)| v.as_str()).collect();
        HttpResponse::new(200, vec![], peers.join(",").into_bytes())
    }
}

#[test]
fn the_peer_header_is_the_socket_peer_never_the_clients() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    serve_listener(Arc::new(Peers), l, 2).unwrap();
    let mut s = TcpStream::connect(&addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(format!("GET /admin/x HTTP/1.1\r\nHost: h\r\n{PEER_HEADER}: 203.0.113.9\r\nx-xbt402-peer: 203.0.113.10\r\nConnection: close\r\n\r\n").as_bytes())
        .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with("\r\n\r\n127.0.0.1"), "only the socket's peer address reaches the service: {text}");
}

/// AGP-080 X1: an allowlisted origin that answers 302 does not send the payer anywhere. The
/// redirect comes back as the answer, and the host it names is never asked.
#[test]
fn x1_a_redirect_is_not_followed() {
    let elsewhere = TcpListener::bind("127.0.0.1:0").unwrap();
    elsewhere.set_nonblocking(true).unwrap();
    let target = format!("http://{}/stolen", elsewhere.local_addr().unwrap());
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = origin.local_addr().unwrap().to_string();
    let t2 = target.clone();
    let server = std::thread::spawn(move || {
        let (mut s, _) = origin.accept().unwrap();
        let mut buf = [0u8; 2048];
        let _ = s.read(&mut buf);
        s.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {t2}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    });
    let r = xbt402::http::UreqTransport::default().request("GET", &format!("http://{addr}/paid"), b"", &[("PAYMENT-SIGNATURE".into(), "x".into())]).unwrap();
    server.join().unwrap();
    assert_eq!(r.status, 302, "the redirect is the answer");
    assert_eq!(r.header("Location"), Some(target.as_str()));
    std::thread::sleep(Duration::from_millis(200));
    assert!(elsewhere.accept().is_err(), "the host the redirect names was asked");
}
