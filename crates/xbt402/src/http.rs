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
            // paid for (review T3).
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
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread::JoinHandle;

    use xbt_svc::http::{Handler, Request, Response};

    use crate::hub::RouteHub;
    use crate::provider::{HttpResponse, Provider, PEER_HEADER};

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

    fn public_url(headers: &[(String, String)], path: &str) -> String {
        let host = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.as_str()).unwrap_or("");
        let https = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-forwarded-proto") && v.trim().eq_ignore_ascii_case("https"));
        format!("{}://{host}{path}", if https { "https" } else { "http" })
    }

    /// An [`HttpService`] on the shared bounded server: the peer header comes from the socket and
    /// never from the client, and the URL a payment binds is rebuilt from `Host`.
    struct Service(Arc<dyn HttpService>);

    impl Handler for Service {
        fn body_limit(&self, _method: &str, target: &str) -> usize {
            self.0.body_limit(target)
        }

        fn handle(&self, req: Request) -> Response {
            if req.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).count() > 1 {
                return Response::text(400, "text/plain", "duplicate PAYMENT-SIGNATURE");
            }
            let mut headers = req.headers;
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case(PEER_HEADER));
            if let Some(a) = req.peer {
                headers.push((PEER_HEADER.to_string(), a.ip().to_string()));
            }
            let url = public_url(&headers, &req.target);
            let r = self.0.serve(&req.method, &req.target, &headers, &req.body, &url);
            Response::new(r.status, r.headers, r.body)
        }
    }

    /// Serve `provider` on `addr` with at most `threads` calls at once, on [`xbt_svc::http`]: Content-Length
    /// bodies only (a chunked body is refused, as the reference does), bounded by the provider's
    /// body limit, read with a deadline on a connection thread so a slow body cannot occupy a
    /// handler slot. Public deployments still belong behind a reverse proxy: it terminates TLS, sets
    /// `X-Forwarded-Proto` and `Host` to the name the payer used, and is the limit in front of this
    /// process.
    pub fn serve_http(provider: Arc<Provider>, addr: &str, threads: usize) -> std::io::Result<Vec<JoinHandle<()>>> {
        serve_service(provider, addr, threads)
    }

    /// Serve any [`HttpService`] (a [`RouteHub`] holds a handler slot while it waits for a provider's
    /// reveal, so give a hub a few more threads than it has concurrent clients).
    pub fn serve_service(provider: Arc<dyn HttpService>, addr: &str, threads: usize) -> std::io::Result<Vec<JoinHandle<()>>> {
        serve_listener(provider, TcpListener::bind(addr)?, threads)
    }

    /// [`serve_service`] on a listener the caller bound (port 0 included: no window in which
    /// another process can take the port).
    pub fn serve_listener(provider: Arc<dyn HttpService>, listener: TcpListener, threads: usize) -> std::io::Result<Vec<JoinHandle<()>>> {
        Ok(xbt_svc::http::serve(Arc::new(Service(provider)), listener, threads)?.threads)
    }
}
