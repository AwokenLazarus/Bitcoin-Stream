//! HTTP transports: a blocking client for the payer (feature `http-client`, ureq) and a small
//! threaded server around [`Provider::serve`] (feature `http-server`, tiny_http).
#[cfg(feature = "http-client")]
pub use client::UreqTransport;
#[cfg(feature = "http-server")]
pub use server::{serve_http, serve_service, HttpService};

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
            let mut out = Vec::new();
            resp.into_reader().take(MAX_RESPONSE).read_to_end(&mut out).map_err(|e| ChannelError::new("transport_error", e.to_string()))?;
            Ok(HttpResponse::new(status, headers, out))
        }
    }
}

#[cfg(feature = "http-server")]
mod server {
    use std::io::Read;
    use std::sync::Arc;
    use std::thread::JoinHandle;

    use crate::hub::RouteHub;
    use crate::provider::{HttpResponse, Provider};

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

    fn respond(req: tiny_http::Request, r: HttpResponse) {
        let mut resp = tiny_http::Response::from_data(r.body).with_status_code(r.status);
        for (k, v) in r.headers {
            if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                resp.add_header(h);
            }
        }
        let _ = req.respond(resp);
    }

    /// Serve `provider` on `addr` with `threads` workers. Content-Length bodies only (a chunked
    /// body is refused, as the reference does), bounded by the provider's body limit.
    pub fn serve_http(provider: Arc<Provider>, addr: &str, threads: usize) -> std::io::Result<Vec<JoinHandle<()>>> {
        serve_service(provider, addr, threads)
    }

    /// Serve any [`HttpService`] (a [`RouteHub`] blocks a worker while it waits for a provider's
    /// reveal, so give a hub a few more threads than it has concurrent clients).
    pub fn serve_service(provider: Arc<dyn HttpService>, addr: &str, threads: usize) -> std::io::Result<Vec<JoinHandle<()>>> {
        let server = Arc::new(tiny_http::Server::http(addr).map_err(|e| std::io::Error::other(e.to_string()))?);
        let mut hs = vec![];
        for _ in 0..threads.max(1) {
            let (server, provider) = (server.clone(), provider.clone());
            hs.push(std::thread::spawn(move || {
                for mut req in server.incoming_requests() {
                    let url = req.url().to_string();
                    let headers: Vec<(String, String)> =
                        req.headers().iter().map(|h| (h.field.as_str().as_str().to_string(), h.value.as_str().to_string())).collect();
                    if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Transfer-Encoding")) {
                        respond(req, HttpResponse::new(501, vec![], b"transfer-encoding not supported".to_vec()));
                        continue;
                    }
                    if headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).count() > 1 {
                        respond(req, HttpResponse::new(400, vec![], b"duplicate PAYMENT-SIGNATURE".to_vec()));
                        continue;
                    }
                    let limit = provider.body_limit(&url);
                    if req.body_length().unwrap_or(0) > limit {
                        respond(req, HttpResponse::new(413, vec![], b"bad content-length".to_vec()));
                        continue;
                    }
                    let mut body = Vec::new();
                    if req.as_reader().take(limit as u64 + 1).read_to_end(&mut body).is_err() {
                        respond(req, HttpResponse::new(400, vec![], b"bad body".to_vec()));
                        continue;
                    }
                    let host = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Host")).map(|(_, v)| v.clone()).unwrap_or_default();
                    let method = req.method().to_string();
                    let r = provider.serve(&method, &url, &headers, &body, &format!("http://{host}{url}"));
                    respond(req, r);
                }
            }));
        }
        Ok(hs)
    }
}
