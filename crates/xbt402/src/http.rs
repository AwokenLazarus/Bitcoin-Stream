//! HTTP transports: a blocking client for the payer (feature `http-client`, ureq) and a small
//! threaded server around [`Provider::serve`] (feature `http-server`, std::net).
#[cfg(feature = "http-client")]
pub use client::UreqTransport;
#[cfg(feature = "http-server")]
pub use server::{serve_http, serve_listener, serve_service, HttpService};

#[cfg(feature = "http-client")]
mod client {
    use std::io::Read;
    use std::time::Duration;

    use crate::client::Transport;
    use crate::error::{ChannelError, Result};
    use crate::provider::HttpResponse;

    /// Responses above this are refused (a provider cannot make the payer buffer without bound).
    const MAX_RESPONSE: u64 = 64 << 20;

    pub struct UreqTransport {
        agent: ureq::Agent,
    }

    impl Default for UreqTransport {
        fn default() -> Self {
            Self { agent: ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).redirects(0).build() }
        }
    }

    impl Transport for UreqTransport {
        fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
            let mut req = self.agent.request(method, url);
            for (k, v) in headers {
                req = req.set(k, v);
            }
            let resp = match if body.is_empty() && method == "GET" { req.call() } else { req.send_bytes(body) } {
                Ok(r) => r,
                Err(ureq::Error::Status(_, r)) => r,
                Err(e) => return Err(ChannelError::new("transport_error", e.to_string())),
            };
            let status = resp.status();
            let headers: Vec<(String, String)> = resp.headers_names().into_iter()
                .filter_map(|n| resp.header(&n).map(|v| (n.to_ascii_uppercase(), v.to_string()))).collect();
            // A body over the cap, or one cut short of its Content-Length, is an error. `take` used
            // to stop at the cap and return Ok, so the payer booked a truncated answer as the one it
            // paid for (Guida T3).
            let declared = resp.header("Content-Length").and_then(|s| s.parse::<u64>().ok());
            if declared.is_some_and(|n| n > MAX_RESPONSE) {
                return Err(ChannelError::new("response_too_large", format!("response is {} bytes; the cap is {MAX_RESPONSE}", declared.unwrap_or(0))));
            }
            let mut out = Vec::new();
            resp.into_reader().take(MAX_RESPONSE + 1).read_to_end(&mut out).map_err(|e| ChannelError::new("transport_error", e.to_string()))?;
            if out.len() as u64 > MAX_RESPONSE {
                return Err(ChannelError::new("response_too_large", format!("response exceeds {MAX_RESPONSE} bytes")));
            }
            if declared.is_some_and(|n| out.len() as u64 != n) {
                return Err(ChannelError::new("response_truncated", format!("response body is {} of {} bytes", out.len(), declared.unwrap_or(0))));
            }
            Ok(HttpResponse::new(status, headers, out))
        }
    }
}

#[cfg(feature = "http-server")]
mod server {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use crate::hub::RouteHub;
    use crate::provider::{HttpResponse, Provider, PEER_HEADER};

    /// A header that never finishes is cut here (Guida T1). The slow-head test allows 15 s.
    const HEAD_DEADLINE: Duration = Duration::from_secs(10);
    /// A body that never arrives occupies a connection slot, not a worker, and only until this.
    const BODY_DEADLINE: Duration = Duration::from_secs(30);
    /// One header line. An endless line is 431 well before it can fill memory.
    const MAX_HEADER_LINE: usize = 8 * 1024;
    const MAX_HEADERS: usize = 32 * 1024;
    /// Slowloris connections accepted at once, above the worker count, so a few of them cannot
    /// fill the pool that runs [`HttpService::serve`].
    const MAX_CONNECTIONS: usize = 64;

    /// Anything served over HTTP by [`serve_service`]: a provider, or a routing hub.
    pub trait HttpService: Send + Sync {
        fn body_limit(&self, path: &str) -> usize;
        fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse;
    }

    impl HttpService for Provider {
        fn body_limit(&self, path: &str) -> usize {
            Provider::body_limit(self, path, None)
        }

        fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
            Provider::serve(self, method, path, headers, body, url, None)
        }
    }

    impl HttpService for RouteHub {
        fn body_limit(&self, path: &str) -> usize {
            RouteHub::body_limit(self, path, None)
        }

        fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
            RouteHub::serve(self, method, path, headers, body, url, None)
        }
    }

    enum Fail {
        Timeout,
        Line,
        Eof,
    }

    fn reason(status: u16) -> &'static str {
        match status {
            200 => "OK",
            400 => "Bad Request",
            402 => "Payment Required",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            413 => "Payload Too Large",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            503 => "Service Unavailable",
            _ => "OK",
        }
    }

    fn write_all(sock: &mut TcpStream, bytes: &[u8]) -> bool {
        let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
        sock.write_all(bytes).is_ok()
    }

    fn write_raw(sock: &mut TcpStream, status: u16, headers: &[(String, String)], body: &[u8]) {
        let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("connection") {
                continue;
            }
            if k.bytes().any(|c| matches!(c, b'\r' | b'\n' | 0)) || v.bytes().any(|c| matches!(c, b'\r' | b'\n' | 0)) {
                continue;
            }
            head.push_str(k);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
        head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
        if write_all(sock, head.as_bytes()) {
            let _ = write_all(sock, body);
        }
        let _ = sock.shutdown(Shutdown::Both);
    }

    fn write_msg(sock: &mut TcpStream, status: u16, body: &[u8]) {
        write_raw(sock, status, &[], body);
    }

    /// Read until `\r\n\r\n`, refusing a line or a block over the caps, and a head past the deadline.
    fn read_head(sock: &mut TcpStream) -> Result<Vec<u8>, Fail> {
        let deadline = Instant::now() + HEAD_DEADLINE;
        let mut buf = Vec::new();
        let mut line = 0usize;
        let mut tmp = [0u8; 1024];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Fail::Timeout);
            }
            if sock.set_read_timeout(Some(left)).is_err() {
                return Err(Fail::Eof);
            }
            match sock.read(&mut tmp) {
                Ok(0) => return Err(Fail::Eof),
                Ok(n) => {
                    for &b in &tmp[..n] {
                        buf.push(b);
                        if buf.len() > MAX_HEADERS {
                            return Err(Fail::Line);
                        }
                        if b == b'\n' {
                            line = 0;
                        } else {
                            line += 1;
                            if line > MAX_HEADER_LINE {
                                return Err(Fail::Line);
                            }
                        }
                    }
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        return Ok(buf);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(Fail::Timeout);
                }
                Err(_) => return Err(Fail::Eof),
            }
        }
    }

    fn read_exact(sock: &mut TcpStream, n: usize, already: &[u8]) -> Result<Vec<u8>, Fail> {
        let mut out = already.to_vec();
        if out.len() >= n {
            out.truncate(n);
            return Ok(out);
        }
        let deadline = Instant::now() + BODY_DEADLINE;
        let mut tmp = [0u8; 8192];
        while out.len() < n {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Fail::Timeout);
            }
            if sock.set_read_timeout(Some(left)).is_err() {
                return Err(Fail::Eof);
            }
            match sock.read(&mut tmp) {
                Ok(0) => return Err(Fail::Eof),
                Ok(k) => {
                    let need = n - out.len();
                    out.extend_from_slice(&tmp[..k.min(need)]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(Fail::Timeout);
                }
                Err(_) => return Err(Fail::Eof),
            }
        }
        Ok(out)
    }

    struct Parsed {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    fn header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    /// The request target, so the body cap is the service's for that path before the body is read.
    fn request_target(buf: &[u8]) -> Option<String> {
        let end = header_end(buf)?;
        let line = buf[..end].split(|&b| b == b'\n').next()?;
        let line = std::str::from_utf8(line.strip_suffix(b"\r").unwrap_or(line)).ok()?;
        let target = line.split(' ').nth(1)?;
        (!target.is_empty()).then(|| target.to_string())
    }

    fn parse(buf: &[u8], limit: usize, sock: &mut TcpStream) -> Result<Parsed, (u16, &'static [u8])> {
        let end = header_end(buf).ok_or((400, &b"bad headers"[..]))?;
        let head = &buf[..end];
        let rest = &buf[end + 4..];
        let mut lines = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
        let req = lines.next().ok_or((400, &b"bad request"[..]))?;
        let req = std::str::from_utf8(req).map_err(|_| (400, &b"bad request"[..]))?;
        let mut parts = req.split(' ');
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        if method.is_empty() || path.is_empty() {
            return Err((400, b"bad request"));
        }
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let line = std::str::from_utf8(line).map_err(|_| (400, &b"bad headers"[..]))?;
            let Some((k, v)) = line.split_once(':') else { return Err((400, b"bad headers")) };
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
        if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Transfer-Encoding")) {
            return Err((501, b"transfer-encoding not supported"));
        }
        if headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).count() > 1 {
            return Err((400, b"duplicate PAYMENT-SIGNATURE"));
        }
        let lengths: Vec<_> = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length")).map(|(_, v)| v.clone()).collect();
        let n = if lengths.is_empty() {
            0usize
        } else if lengths.len() == 1 {
            let s = &lengths[0];
            if !s.bytes().all(|c| c.is_ascii_digit()) {
                return Err((400, b"bad content-length"));
            }
            match s.parse::<usize>() {
                Ok(n) if n > limit => return Err((413, b"bad content-length")),
                Ok(n) => n,
                Err(_) => return Err((400, b"bad content-length")),
            }
        } else {
            return Err((400, b"bad content-length"));
        };
        let body = if n == 0 {
            Vec::new()
        } else {
            let expect = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("Expect") && v.eq_ignore_ascii_case("100-continue"));
            if expect && rest.is_empty() && !write_all(sock, b"HTTP/1.1 100 Continue\r\n\r\n") {
                return Err((400, b"bad body"));
            }
            read_exact(sock, n, rest).map_err(|_| (400, &b"bad body"[..]))?
        };
        Ok(Parsed { method, path, headers, body })
    }

    fn public_url(headers: &[(String, String)], path: &str) -> String {
        let host = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.as_str()).unwrap_or("");
        let https = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-forwarded-proto") && v.trim().eq_ignore_ascii_case("https"));
        format!("{}://{host}{path}", if https { "https" } else { "http" })
    }

    struct Job {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        url: String,
        done: mpsc::SyncSender<HttpResponse>,
    }

    /// Serve `provider` on `addr` with `threads` workers. Content-Length bodies only (a chunked
    /// body is refused, as the reference does), bounded by the provider's body limit.
    ///
    /// Headers and bodies are read on a connection thread (capped at [`MAX_CONNECTIONS`]) with a
    /// deadline, then handed to one of `threads` workers for [`HttpService::serve`]. A slow body
    /// therefore cannot occupy every worker. Public deployments still belong behind a reverse
    /// proxy: it terminates TLS, sets `X-Forwarded-Proto` and `Host` to the name the payer used,
    /// and is the limit in front of this process.
    pub fn serve_http(provider: Arc<Provider>, addr: &str, threads: usize) -> std::io::Result<Vec<JoinHandle<()>>> {
        serve_service(provider, addr, threads)
    }

    /// Serve any [`HttpService`] (a [`RouteHub`] blocks a worker while it waits for a provider's
    /// reveal, so give a hub a few more threads than it has concurrent clients).
    pub fn serve_service(provider: Arc<dyn HttpService>, addr: &str, threads: usize) -> std::io::Result<Vec<JoinHandle<()>>> {
        serve_listener(provider, TcpListener::bind(addr)?, threads)
    }

    /// [`serve_service`] on a listener the caller bound (port 0 included: no window in which
    /// another process can take the port).
    pub fn serve_listener(provider: Arc<dyn HttpService>, listener: TcpListener, threads: usize) -> std::io::Result<Vec<JoinHandle<()>>> {
        let threads = threads.max(1);
        let (tx, rx) = mpsc::sync_channel::<Job>(threads);
        let rx = Arc::new(std::sync::Mutex::new(rx));
        let mut hs = vec![];
        for _ in 0..threads {
            let (rx, provider) = (rx.clone(), provider.clone());
            hs.push(std::thread::spawn(move || {
                loop {
                    let job = {
                        let guard = rx.lock().unwrap_or_else(|p| p.into_inner());
                        guard.recv()
                    };
                    let Ok(job) = job else { break };
                    // a panicking handler costs its request, not a worker for good
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        provider.serve(&job.method, &job.path, &job.headers, &job.body, &job.url)
                    }))
                    .unwrap_or_else(|_| HttpResponse::new(500, vec![], b"handler panicked".to_vec()));
                    let _ = job.done.send(r);
                }
            }));
        }
        let open = Arc::new(AtomicUsize::new(0));
        let tx_acc = tx;
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { continue };
                if open.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    write_msg(&mut sock, 503, b"too many connections");
                    continue;
                }
                open.fetch_add(1, Ordering::Relaxed);
                let (tx, open, provider) = (tx_acc.clone(), open.clone(), provider.clone());
                std::thread::spawn(move || {
                    struct Slot(Arc<AtomicUsize>);
                    impl Drop for Slot {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                    let _slot = Slot(open);
                    let head = match read_head(&mut sock) {
                        Ok(b) => b,
                        Err(Fail::Line) => {
                            write_msg(&mut sock, 431, b"header too large");
                            return;
                        }
                        Err(Fail::Timeout) => {
                            write_msg(&mut sock, 408, b"header timeout");
                            return;
                        }
                        Err(Fail::Eof) => return,
                    };
                    let limit = request_target(&head).map(|p| provider.body_limit(&p)).unwrap_or(1 << 20);
                    let parsed = match parse(&head, limit, &mut sock) {
                        Ok(p) => p,
                        Err((status, body)) => {
                            write_msg(&mut sock, status, body);
                            return;
                        }
                    };
                    let (done_tx, done_rx) = mpsc::sync_channel(1);
                    let mut headers = parsed.headers;
                    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(PEER_HEADER));
                    if let Ok(a) = sock.peer_addr() {
                        headers.push((PEER_HEADER.to_string(), a.ip().to_string()));
                    }
                    let url = public_url(&headers, &parsed.path);
                    let job = Job { method: parsed.method, path: parsed.path, headers, body: parsed.body, url, done: done_tx };
                    if tx.send(job).is_err() {
                        write_msg(&mut sock, 500, b"server stopped");
                        return;
                    }
                    match done_rx.recv() {
                        Ok(r) => write_raw(&mut sock, r.status, &r.headers, &r.body),
                        Err(_) => write_msg(&mut sock, 500, b"worker gone"),
                    }
                });
            }
        });
        Ok(hs)
    }
}
