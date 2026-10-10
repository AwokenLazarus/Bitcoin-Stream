//! The AGP-068 slowloris checks (xbt402 `tests/http_limits.rs`) as functions, so every HTTP server we
//! ship runs the same ones (AGP-072). `ok` is one complete request the server answers with a 2xx;
//! `slow` is a request head with a Content-Length the server accepts and whose body never comes.
//! The limits are [`xbt_svc::http::Limits::default`]: head deadline 10 s, body deadline 30 s.
#![allow(dead_code)]
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// The answer to `ok` on a fresh connection, or None if no 2xx came back within `wait`.
pub fn get_ok(addr: &str, ok: &str, wait: Duration) -> Option<String> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(wait)).ok()?;
    s.write_all(ok.as_bytes()).ok()?;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).to_string();
    text.starts_with("HTTP/1.1 2").then_some(text)
}

/// Wait for the server to close `s`; how long that took from `since`.
fn closed_after(s: &mut TcpStream, since: Instant, wait: Duration) -> Duration {
    s.set_read_timeout(Some(wait)).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    since.elapsed()
}

/// `conns` connections (more than the server has workers) each promise a body and never send it:
/// a normal request still gets through, and the server drops a slow body at its body deadline.
pub fn slow_bodies_do_not_stall_and_are_cut_off(addr: &str, ok: &str, slow: &str, conns: usize) {
    let t0 = Instant::now();
    let mut held: Vec<TcpStream> = (0..conns)
        .map(|_| {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(slow.as_bytes()).unwrap();
            s
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    let t = Instant::now();
    assert!(
        get_ok(addr, ok, Duration::from_secs(3)).is_some(),
        "a normal request stalled behind {conns} slow bodies ({:?})",
        t.elapsed()
    );
    let took = closed_after(&mut held[0], t0, Duration::from_secs(60));
    assert!(
        took < Duration::from_secs(40),
        "a body that never came held its connection for {took:?}"
    );
}

/// 32 heads that never end: a normal request still gets through, and the server drops a slow head
/// at its head deadline.
pub fn slow_heads_do_not_stall_and_are_cut_off(addr: &str, ok: &str) {
    let t0 = Instant::now();
    let mut held: Vec<TcpStream> = (0..32)
        .map(|_| {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /slow HTTP/1.1\r\nHost: h\r\nX-Drip: ")
                .unwrap();
            s
        })
        .collect();
    assert!(
        get_ok(addr, ok, Duration::from_secs(3)).is_some(),
        "a normal request stalled behind slow heads"
    );
    let took = closed_after(&mut held[0], t0, Duration::from_secs(20));
    assert!(
        took < Duration::from_secs(15),
        "a slow head held its connection for {took:?}"
    );
}

/// One header line that never ends is refused with 431 long before 4 MiB, and the server still serves.
pub fn an_endless_header_line_is_refused(addr: &str, ok: &str) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: h\r\nX-Long: ");
    let chunk = vec![b'a'; 64 * 1024];
    let mut sent = 0usize;
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
    assert!(get_ok(addr, ok, Duration::from_secs(3)).is_some());
}
