//! The signer socket (B2's protocol: one newline-delimited JSON request per connection): a Unix
//! socket path, or `tcp://127.0.0.1:PORT`.
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct SignerLink {
    pub sock: PathBuf,
    pub timeout: Duration,
}

trait Conn: Read + Write {}
impl<T: Read + Write> Conn for T {}

impl SignerLink {
    pub fn new(sock: PathBuf, timeout: Duration) -> Self {
        Self { sock, timeout }
    }

    fn connect(&self) -> std::io::Result<Box<dyn Conn>> {
        let s = self.sock.to_string_lossy();
        if let Some(a) = s.strip_prefix("tcp://") {
            let c = std::net::TcpStream::connect(a)?;
            c.set_read_timeout(Some(self.timeout))?;
            c.set_write_timeout(Some(self.timeout))?;
            return Ok(Box::new(c));
        }
        #[cfg(unix)]
        {
            let c = std::os::unix::net::UnixStream::connect(&self.sock)?;
            c.set_read_timeout(Some(self.timeout))?;
            c.set_write_timeout(Some(self.timeout))?;
            Ok(Box::new(c))
        }
        #[cfg(not(unix))]
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "use tcp://127.0.0.1:PORT for the signer socket"))
    }

    /// The signer's result, or its error message (or why it could not be reached).
    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let io = |e: std::io::Error| format!("the signer at {} is unreachable: {e}", self.sock.display());
        let mut c = self.connect().map_err(io)?;
        let line = serde_json::to_string(&json!({"id": 1, "method": method, "params": params})).map_err(|e| e.to_string())?;
        c.write_all(format!("{line}\n").as_bytes()).map_err(io)?;
        let mut out = String::new();
        BufReader::new(c).read_line(&mut out).map_err(io)?;
        let resp: Value = serde_json::from_str(out.trim()).map_err(|e| format!("the signer's answer is not JSON: {e}"))?;
        if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(e.get("message").and_then(Value::as_str).unwrap_or("error").to_string());
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }
}
