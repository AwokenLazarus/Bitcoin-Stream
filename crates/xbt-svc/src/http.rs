//! The bounded HTTP/1.1 server every XBT service listens with (review T1: AGP-068 in xbt402, AGP-072
//! for the UI, the MCP and the relay). std::net and threads, no async runtime, no dependency.
//!
//! A connection thread (at most [`Limits::connections`] at once, and [`Limits::per_address`] of them
//! from one client address) reads the head under a line cap, a
//! head cap and an absolute deadline, then a Content-Length body under the handler's limit and its
//! own deadline. Only then does it wait for one of `threads` handler slots to run
//! [`Handler::handle`], so a slow or endless client holds a connection slot until its deadline, and
//! never a handler slot. One request per connection (`Connection: close`); chunked request bodies are 501.
//! A public deployment still belongs behind a reverse proxy that terminates TLS.
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The caps and deadlines. [`Limits::default`] is what every shipped server uses.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// One header line, request line included. An endless line is 431 long before it fills memory.
    pub line: usize,
    /// The whole head.
    pub head: usize,
    /// From accept to the end of the head; past it, 408.
    pub head_deadline: Duration,
    /// From the end of the head to the end of the body; past it, 408.
    pub body_deadline: Duration,
    /// Connections open at once; above it, 503 and close.
    pub connections: usize,
    /// Connections open at once from one client address ([`AddrKey`]); above it, 503 and close
    /// (AGP-081, review T1: with only the global cap one address held every slot). 0: no cap per
    /// address, for a server whose only peer is its reverse proxy.
    pub per_address: usize,
}

/// Sets [`Limits::per_address`] for the servers a process starts with [`serve`].
pub const PER_ADDRESS_ENV: &str = "XBT_HTTP_MAX_PER_ADDRESS";

impl Default for Limits {
    fn default() -> Self {
        Self {
            line: 8 * 1024,
            head: 32 * 1024,
            head_deadline: Duration::from_secs(10),
            body_deadline: Duration::from_secs(30),
            connections: 64,
            per_address: 48,
        }
    }
}

impl Limits {
    /// The default limits with [`PER_ADDRESS_ENV`] applied: a whole number, 0 for no cap per
    /// address. Anything else is an error, not the default.
    pub fn from_env() -> io::Result<Self> {
        let mut l = Self::default();
        if let Some(v) = std::env::var_os(PER_ADDRESS_ENV) {
            let bad = || {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{PER_ADDRESS_ENV} must be a whole number (0: no cap per address)"),
                )
            };
            l.per_address = v
                .to_str()
                .ok_or_else(bad)?
                .trim()
                .parse()
                .map_err(|_| bad())?;
        }
        Ok(l)
    }
}

/// A complete request: the head and its whole body.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// As sent (`GET`, `post`, ...).
    pub method: String,
    /// The request target as sent: path and query.
    pub target: String,
    /// In order, names as sent.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The socket's peer (never a header).
    pub peer: Option<SocketAddr>,
}

impl Request {
    /// The first header called `name` (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The target without its query.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// `Content-Length`, `Connection` and `Transfer-Encoding` are the server's; a handler's copies
    /// are dropped, as is any header holding CR, LF or NUL.
    pub headers: Vec<(String, String)>,
    /// Not sent for `HEAD` (its length still is), 1xx, 204 and 304.
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    pub fn text(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self::new(
            status,
            vec![("Content-Type".into(), content_type.into())],
            body.into(),
        )
    }
}

/// What a server serves.
pub trait Handler: Send + Sync {
    /// The largest body accepted for this request line. A larger Content-Length is 413 before any
    /// body byte is read.
    fn body_limit(&self, method: &str, target: &str) -> usize;
    fn handle(&self, req: Request) -> Response;
}

/// Stops a server: no new connections; the open ones are served to the end.
#[derive(Clone, Debug)]
pub struct Stop {
    flag: Arc<AtomicBool>,
    addr: SocketAddr,
}

impl Stop {
    pub fn stop(&self) {
        if self.flag.swap(true, Ordering::SeqCst) {
            return;
        }
        // wake the accept loop; an unspecified bind address is reached on loopback
        let mut a = self.addr;
        if a.ip().is_unspecified() {
            a.set_ip(if a.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            });
        }
        let _ = TcpStream::connect_timeout(&a, Duration::from_secs(1));
    }
}

/// A running server. Dropping it does not stop it: use [`Running::stopper`].
#[derive(Debug)]
pub struct Running {
    pub addr: SocketAddr,
    /// The accept thread: it ends after [`Stop::stop`].
    pub threads: Vec<JoinHandle<()>>,
    stop: Stop,
}

impl Running {
    pub fn stopper(&self) -> Stop {
        self.stop.clone()
    }
}

/// [`serve_with`] the default [`Limits`], [`PER_ADDRESS_ENV`] applied.
pub fn serve(
    handler: Arc<dyn Handler>,
    listener: TcpListener,
    threads: usize,
) -> io::Result<Running> {
    serve_with(handler, listener, threads, Limits::from_env()?)
}

/// Serve `handler` on `listener` (bound by the caller, port 0 included: no window in which another
/// process can take the port), running at most `threads` handlers at once.
pub fn serve_with(
    handler: Arc<dyn Handler>,
    listener: TcpListener,
    threads: usize,
    limits: Limits,
) -> io::Result<Running> {
    let addr = listener.local_addr()?;
    let gate = Arc::new(Gate {
        busy: Mutex::new(0),
        free: Condvar::new(),
        max: threads.max(1),
    });
    let stop = Stop {
        flag: Arc::new(AtomicBool::new(false)),
        addr,
    };
    let flag = stop.flag.clone();
    let accept = std::thread::Builder::new()
        .name("http-accept".into())
        .spawn(move || accept(listener, handler, gate, limits, &flag))?;
    Ok(Running {
        addr,
        threads: vec![accept],
        stop,
    })
}

/// At most `max` handlers at once; the rest wait in their connection slot.
struct Gate {
    busy: Mutex<usize>,
    free: Condvar,
    max: usize,
}

struct Pass<'a>(&'a Gate);

impl Gate {
    fn enter(&self) -> Pass<'_> {
        let mut busy = self.busy.lock().unwrap_or_else(|p| p.into_inner());
        while *busy >= self.max {
            busy = self.free.wait(busy).unwrap_or_else(|p| p.into_inner());
        }
        *busy += 1;
        Pass(self)
    }
}

impl Drop for Pass<'_> {
    fn drop(&mut self) {
        *self.0.busy.lock().unwrap_or_else(|p| p.into_inner()) -= 1;
        self.0.free.notify_one();
    }
}

/// What counts as one client address: an IPv4 address (an IPv4-mapped IPv6 address is its IPv4
/// address), or an IPv6 /64, since one host is usually handed the whole prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddrKey {
    V4(Ipv4Addr),
    V6Prefix(u64),
}

impl AddrKey {
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(a) => Self::V4(a),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(m) => Self::V4(m),
                None => Self::V6Prefix((u128::from(a) >> 64) as u64),
            },
        }
    }
}

/// Open connections per client address. A connection whose peer the socket cannot name counts
/// under `None`, as one address. The map never holds more entries than there are open connections.
struct PerAddress {
    max: usize,
    open: Mutex<HashMap<Option<AddrKey>, usize>>,
}

impl PerAddress {
    /// Count one more connection for `key`, unless it is at the cap.
    fn admit(&self, key: Option<AddrKey>) -> bool {
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let n = open.entry(key).or_insert(0);
        if self.max > 0 && *n >= self.max {
            return false;
        }
        *n += 1;
        true
    }

    fn release(&self, key: Option<AddrKey>) {
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = open.get_mut(&key) {
            *n -= 1;
            if *n == 0 {
                open.remove(&key);
            }
        }
    }
}

/// Releases a connection slot, and its address's, when its connection ends, however it ends.
struct Slot {
    open: Arc<AtomicUsize>,
    per: Arc<PerAddress>,
    key: Option<AddrKey>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.open.fetch_sub(1, Ordering::SeqCst);
        self.per.release(self.key);
    }
}

/// An idle connection thread waits this long for its next connection, then ends.
const IDLE: Duration = Duration::from_secs(60);

type Conn = (TcpStream, Slot);

/// Connection threads are kept for reuse: the accept loop queues a connection for an idle one, or
/// starts one while fewer than [`Limits::connections`] are alive. The queue never holds more than
/// the open connections, which are capped.
struct Pool {
    handler: Arc<dyn Handler>,
    gate: Arc<Gate>,
    limits: Limits,
    state: Mutex<PoolState>,
    ready: Condvar,
}

#[derive(Default)]
struct PoolState {
    queue: VecDeque<Conn>,
    idle: usize,
    alive: usize,
}

impl Pool {
    fn lock(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Queue `conn` for an idle thread, or start a thread for it.
    fn dispatch(self: &Arc<Self>, conn: Conn) {
        let mut st = self.lock();
        if st.idle > st.queue.len() || st.alive >= self.limits.connections {
            // an idle thread takes it; failing that, a busy one does when it finishes (the open
            // connections, this one included, are at most `connections`, so one is not busy)
            st.queue.push_back(conn);
            drop(st);
            self.ready.notify_one();
            return;
        }
        st.alive += 1;
        drop(st);
        let p = self.clone();
        // a failed spawn drops the closure: the connection closes and its slot is returned
        if std::thread::Builder::new()
            .name("http-conn".into())
            .spawn(move || p.run(conn))
            .is_err()
        {
            self.lock().alive -= 1;
        }
    }

    fn run(&self, first: Conn) {
        let mut next = Some(first);
        while let Some((sock, slot)) = next.take() {
            connection(sock, &*self.handler, &self.gate, &self.limits);
            drop(slot);
            next = self.wait();
        }
    }

    /// The next queued connection, or None (and this thread counted out) after [`IDLE`].
    fn wait(&self) -> Option<Conn> {
        let deadline = Instant::now() + IDLE;
        let mut st = self.lock();
        st.idle += 1;
        loop {
            if let Some(c) = st.queue.pop_front() {
                st.idle -= 1;
                return Some(c);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                st.idle -= 1;
                st.alive -= 1;
                return None;
            }
            st = self
                .ready
                .wait_timeout(st, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }
}

fn accept(
    listener: TcpListener,
    handler: Arc<dyn Handler>,
    gate: Arc<Gate>,
    limits: Limits,
    stop: &AtomicBool,
) {
    let open = Arc::new(AtomicUsize::new(0));
    let per = Arc::new(PerAddress {
        max: limits.per_address,
        open: Mutex::new(HashMap::new()),
    });
    let pool = Arc::new(Pool {
        handler,
        gate,
        limits,
        state: Mutex::new(PoolState::default()),
        ready: Condvar::new(),
    });
    for conn in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let mut sock = match conn {
            Ok(s) => s,
            Err(_) => {
                // out of file descriptors and the like: do not spin
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        if open.load(Ordering::SeqCst) >= limits.connections {
            write_error(&mut sock, 503, "too many connections");
            continue;
        }
        let key = sock.peer_addr().ok().map(|a| AddrKey::of(a.ip()));
        if !per.admit(key) {
            write_error(&mut sock, 503, "too many connections from this address");
            continue;
        }
        open.fetch_add(1, Ordering::SeqCst);
        let slot = Slot {
            open: open.clone(),
            per: per.clone(),
            key,
        };
        pool.dispatch((sock, slot));
    }
}

fn connection(mut sock: TcpStream, handler: &dyn Handler, gate: &Gate, limits: &Limits) {
    let peer = sock.peer_addr().ok();
    let (head, rest) = match read_head(&mut sock, limits) {
        Ok(h) => h,
        Err(Fail::Large) => return write_error(&mut sock, 431, "header too large"),
        Err(Fail::Timeout) => return write_error(&mut sock, 408, "header timeout"),
        Err(Fail::Gone) => return,
    };
    let mut req = match parse_head(&head) {
        Ok(r) => r,
        Err((status, msg)) => return write_error(&mut sock, status, msg),
    };
    let n = match content_length(&req.headers, handler.body_limit(&req.method, &req.target)) {
        Ok(n) => n,
        Err((status, msg)) => return write_error(&mut sock, status, msg),
    };
    if n > 0 {
        let expect = req.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("Expect") && v.eq_ignore_ascii_case("100-continue")
        });
        if expect && rest.is_empty() && !write_all(&mut sock, b"HTTP/1.1 100 Continue\r\n\r\n") {
            return;
        }
        match read_body(&mut sock, n, rest, limits.body_deadline) {
            Ok(b) => req.body = b,
            Err(Fail::Timeout) => return write_error(&mut sock, 408, "body timeout"),
            Err(_) => return,
        }
    }
    req.peer = peer;
    let head_only = req.method.eq_ignore_ascii_case("HEAD");
    let r = {
        let _pass = gate.enter();
        // a panicking handler costs its request, and its slot is given back
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler.handle(req)))
            .unwrap_or_else(|_| Response::text(500, "text/plain", "handler panicked"))
    };
    write_response(&mut sock, &r, head_only);
}

enum Fail {
    Timeout,
    Large,
    Gone,
}

fn timed_read(sock: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<usize, Fail> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Fail::Timeout);
    }
    sock.set_read_timeout(Some(left)).map_err(|_| Fail::Gone)?;
    match sock.read(buf) {
        Ok(0) => Err(Fail::Gone),
        Ok(n) => Ok(n),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            Err(Fail::Timeout)
        }
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(0),
        Err(_) => Err(Fail::Gone),
    }
}

/// Read to the end of the head: (head without its blank line, the body bytes read with it).
fn read_head(sock: &mut TcpStream, limits: &Limits) -> Result<(Vec<u8>, Vec<u8>), Fail> {
    let deadline = Instant::now() + limits.head_deadline;
    let mut buf = Vec::with_capacity(1024);
    let mut line = 0usize;
    let mut tmp = [0u8; 2048];
    loop {
        let n = timed_read(sock, &mut tmp, deadline)?;
        let from = buf.len().saturating_sub(3);
        for &b in &tmp[..n] {
            if b == b'\n' {
                line = 0;
            } else {
                line += 1;
                if line > limits.line {
                    return Err(Fail::Large);
                }
            }
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = from + i;
            if end > limits.head {
                return Err(Fail::Large);
            }
            let rest = buf.split_off(end + 4);
            buf.truncate(end);
            return Ok((buf, rest));
        }
        if buf.len() > limits.head {
            return Err(Fail::Large);
        }
    }
}

fn read_body(
    sock: &mut TcpStream,
    n: usize,
    mut out: Vec<u8>,
    wait: Duration,
) -> Result<Vec<u8>, Fail> {
    out.truncate(n);
    out.reserve_exact(n - out.len());
    let deadline = Instant::now() + wait;
    let mut tmp = [0u8; 8192];
    while out.len() < n {
        let k = timed_read(sock, &mut tmp, deadline)?;
        out.extend_from_slice(&tmp[..k.min(n - out.len())]);
    }
    Ok(out)
}

type Refusal = (u16, &'static str);

fn parse_head(head: &[u8]) -> Result<Request, Refusal> {
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let first = lines
        .next()
        .and_then(|l| std::str::from_utf8(l).ok())
        .ok_or((400, "bad request"))?;
    let mut parts = first.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if method.is_empty() || target.is_empty() {
        return Err((400, "bad request"));
    }
    if target.contains('#') {
        // no client sends a fragment; a payment's request binding does not cover one (AGP-081, review T2)
        return Err((400, "request target with a fragment"));
    }
    let mut headers = Vec::new();
    for line in lines {
        let line = std::str::from_utf8(line).map_err(|_| (400, "bad headers"))?;
        let Some((k, v)) = line.split_once(':') else {
            return Err((400, "bad headers"));
        };
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    Ok(Request {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        body: vec![],
        peer: None,
    })
}

/// The body length: Content-Length only, one of them, digits only, at most `limit`.
fn content_length(headers: &[(String, String)], limit: usize) -> Result<usize, Refusal> {
    if headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("Transfer-Encoding"))
    {
        return Err((501, "transfer-encoding not supported"));
    }
    let lengths: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .map(|(_, v)| v.as_str())
        .collect();
    let s = match lengths.as_slice() {
        [] => return Ok(0),
        [s] => *s,
        _ => return Err((400, "bad content-length")),
    };
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err((400, "bad content-length"));
    }
    match s.parse::<usize>() {
        Ok(n) if n <= limit => Ok(n),
        Ok(_) => Err((413, "request too large")),
        Err(_) => Err((400, "bad content-length")),
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        507 => "Insufficient Storage",
        _ => "Status",
    }
}

fn write_all(sock: &mut TcpStream, bytes: &[u8]) -> bool {
    let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
    sock.write_all(bytes).is_ok()
}

fn write_response(sock: &mut TcpStream, r: &Response, head_only: bool) {
    let mut head = format!("HTTP/1.1 {} {}\r\n", r.status, reason(r.status));
    for (k, v) in &r.headers {
        if ["content-length", "connection", "transfer-encoding"]
            .iter()
            .any(|h| k.eq_ignore_ascii_case(h))
        {
            continue;
        }
        let bad = |s: &str| s.bytes().any(|c| matches!(c, b'\r' | b'\n' | 0));
        if k.is_empty() || bad(k) || bad(v) {
            continue;
        }
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    let bodiless = matches!(r.status, 100..=199 | 204 | 304);
    if !bodiless {
        head.push_str(&format!("Content-Length: {}\r\n", r.body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");
    let mut out = head.into_bytes();
    if !bodiless && !head_only {
        out.extend_from_slice(&r.body);
    }
    let _ = write_all(sock, &out);
    let _ = sock.shutdown(Shutdown::Both);
}

fn write_error(sock: &mut TcpStream, status: u16, msg: &str) {
    let headers = vec![
        ("Content-Type".into(), "text/plain; charset=utf-8".into()),
        ("Cache-Control".into(), "no-store".into()),
        ("X-Content-Type-Options".into(), "nosniff".into()),
    ];
    write_response(
        sock,
        &Response::new(status, headers, format!("{msg}\n").into_bytes()),
        false,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_is_one_decimal_number_under_the_limit() {
        let h = |v: &[&str]| {
            v.iter()
                .map(|v| ("Content-Length".to_string(), v.to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(content_length(&[], 10), Ok(0));
        assert_eq!(content_length(&h(&["7"]), 10), Ok(7));
        assert_eq!(content_length(&h(&["10"]), 10), Ok(10));
        assert_eq!(content_length(&h(&["11"]), 10).unwrap_err().0, 413);
        for bad in [
            &["+1"][..],
            &["-1"],
            &["1 "],
            &[""],
            &["0x1"],
            &["1", "1"],
            &["99999999999999999999999"],
        ] {
            assert_eq!(content_length(&h(bad), 10).unwrap_err().0, 400, "{bad:?}");
        }
        let te = vec![("transfer-encoding".to_string(), "chunked".to_string())];
        assert_eq!(content_length(&te, 10).unwrap_err().0, 501);
    }

    #[test]
    fn heads_parse_and_bad_ones_are_400() {
        let r = parse_head(b"POST /a?b=1 HTTP/1.1\r\nHost: x\r\nX-A:  v \r\nx-a: w").unwrap();
        assert_eq!(
            (r.method.as_str(), r.target.as_str(), r.path()),
            ("POST", "/a?b=1", "/a")
        );
        assert_eq!(r.header("x-a"), Some("v"));
        assert_eq!(r.headers.len(), 3);
        for bad in [
            &b""[..],
            b"GET",
            b"GET  HTTP/1.1",
            b"GET / HTTP/1.1\r\nno colon",
            b"GET / HTTP/1.1\r\nX: \xff",
            b"GET /a#b HTTP/1.1",
        ] {
            assert_eq!(
                parse_head(bad).unwrap_err().0,
                400,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn one_address_is_an_ipv4_address_or_an_ipv6_slash_64() {
        let k = |s: &str| AddrKey::of(s.parse().unwrap());
        assert_eq!(k("::ffff:192.0.2.7"), k("192.0.2.7"));
        assert_ne!(k("192.0.2.7"), k("192.0.2.8"));
        assert_eq!(k("2001:db8:1:2::1"), k("2001:db8:1:2:ffff:ffff:ffff:ffff"));
        assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
        assert_ne!(k("::1"), k("127.0.0.1"));
    }

    #[test]
    fn an_address_at_its_cap_is_refused_and_no_other_is() {
        let per = PerAddress {
            max: 2,
            open: Mutex::new(HashMap::new()),
        };
        let (a, b) = (
            Some(AddrKey::of("192.0.2.7".parse().unwrap())),
            Some(AddrKey::of("2001:db8::1".parse().unwrap())),
        );
        assert!(per.admit(a) && per.admit(a) && !per.admit(a));
        assert!(per.admit(b) && per.admit(None) && per.admit(None) && !per.admit(None));
        per.release(a);
        assert!(per.admit(a) && !per.admit(a));
        for k in [a, a, b, None, None] {
            per.release(k);
        }
        assert!(
            per.open.lock().unwrap().is_empty(),
            "a closed connection leaves no entry"
        );
        let off = PerAddress {
            max: 0,
            open: Mutex::new(HashMap::new()),
        };
        assert!((0..1000).all(|_| off.admit(a)), "0 is no cap per address");
    }
}
