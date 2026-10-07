//! The signer's and the witness's local socket, portably.
//!
//! An endpoint is a filesystem path (a Unix-domain socket, B2's protocol; Unix only) or
//! `tcp://127.0.0.1:PORT` (every platform, loopback only). A Unix socket is access-controlled by its
//! file mode (0600); a loopback TCP port is reachable by every local user, so on platforms without
//! Unix sockets in std (Windows) the signer's host must be single-user or firewalled per user.
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

/// A connected byte stream.
pub enum Stream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

/// A bound listener.
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixListener),
}

fn tcp_addr(ep: &str) -> Option<&str> {
    ep.strip_prefix("tcp://")
}

fn loopback_only(addr: &str) -> io::Result<()> {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    if matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "the signer socket listens on loopback only"))
    }
}

impl Stream {
    pub fn connect(ep: &Path) -> io::Result<Self> {
        let s = ep.to_string_lossy();
        if let Some(a) = tcp_addr(&s) {
            return TcpStream::connect(a).map(Stream::Tcp);
        }
        #[cfg(unix)]
        {
            std::os::unix::net::UnixStream::connect(ep).map(Stream::Unix)
        }
        #[cfg(not(unix))]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Unix sockets are not available here: use tcp://127.0.0.1:PORT"))
        }
    }

    pub fn set_timeouts(&self, t: Option<Duration>) {
        match self {
            Stream::Tcp(s) => {
                let _ = s.set_read_timeout(t);
                let _ = s.set_write_timeout(t);
            }
            #[cfg(unix)]
            Stream::Unix(s) => {
                let _ = s.set_read_timeout(t);
                let _ = s.set_write_timeout(t);
            }
        }
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Stream::Tcp(s) => s.try_clone().map(Stream::Tcp),
            #[cfg(unix)]
            Stream::Unix(s) => s.try_clone().map(Stream::Unix),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(b),
            #[cfg(unix)]
            Stream::Unix(s) => s.read(b),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(b),
            #[cfg(unix)]
            Stream::Unix(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.flush(),
            #[cfg(unix)]
            Stream::Unix(s) => s.flush(),
        }
    }
}

impl Listener {
    /// Bind `ep`; a stale socket file is replaced, and a Unix socket gets `mode`.
    pub fn bind(ep: &Path, mode: u32) -> io::Result<Self> {
        let s = ep.to_string_lossy();
        if let Some(a) = tcp_addr(&s) {
            loopback_only(a)?;
            return TcpListener::bind(a).map(Listener::Tcp);
        }
        #[cfg(unix)]
        {
            if ep.exists() {
                std::fs::remove_file(ep)?;
            }
            if let Some(p) = ep.parent() {
                std::fs::create_dir_all(p)?;
            }
            let l = std::os::unix::net::UnixListener::bind(ep)?;
            crate::fsx::set_mode(ep, mode)?;
            Ok(Listener::Unix(l))
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
            Err(io::Error::new(io::ErrorKind::Unsupported, "Unix sockets are not available here: use tcp://127.0.0.1:PORT"))
        }
    }

    pub fn accept(&self) -> io::Result<Stream> {
        match self {
            Listener::Tcp(l) => l.accept().map(|(s, _)| Stream::Tcp(s)),
            #[cfg(unix)]
            Listener::Unix(l) => l.accept().map(|(s, _)| Stream::Unix(s)),
        }
    }
}
