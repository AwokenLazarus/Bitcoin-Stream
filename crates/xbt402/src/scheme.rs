//! Other x402 schemes beside `xbt-channel` (AGP-032). A [`Provider`](crate::provider::Provider)
//! can offer a second scheme in the same 402 and serve calls paid with it
//! ([`Provider::with_scheme`](crate::provider::Provider::with_scheme)); a
//! [`Client`](crate::client::Client) can pay with one when a 402 offers it
//! ([`Client::with_payer`](crate::client::Client::with_payer)). The two schemes are independent:
//! a payload of one never touches the other's state. The `xbt-work` crate implements both sides.
use serde_json::Value;

use crate::client::Transport;
use crate::error::Result;
use crate::provider::HttpResponse;

/// The provider side of another scheme.
pub trait ProviderScheme: Send + Sync {
    /// The `scheme` string of its PaymentRequirements.
    fn scheme(&self) -> &str;
    /// Its PaymentRequirements for a call the provider prices at `price_sats`, listed after the
    /// `xbt-channel` offer in an unpaid 402; None: not offered for this call.
    fn requirements(&self, method: &str, path: &str, price_sats: u64) -> Option<Value>;
    /// Its own control endpoints (for `xbt-work`, invoice issuance): Some(response) when `path` is one.
    fn control(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> Option<HttpResponse>;
    /// Check a decoded PAYMENT-SIGNATURE whose `accepted.scheme` is this scheme and debit the call
    /// before the handler runs. Err: the PaymentRequired document of the refusal (sent as a 402).
    fn authorize(&self, payment: &Value, method: &str, path: &str, body: &[u8], price_sats: u64, url: &str)
                 -> std::result::Result<Box<dyn SchemeCharge>, Value>;
}

/// A debited call, settled once the handler has answered.
pub trait SchemeCharge: Send {
    /// Settle with the handler's status (at or above 500 is not charged): the SettlementResponse
    /// that goes back in PAYMENT-RESPONSE.
    fn settle(self: Box<Self>, status: u16) -> Value;
}

/// The payer side of another scheme. Preferred over `xbt-channel` whenever a 402 offers it.
pub trait SchemePayer: Send + Sync {
    fn scheme(&self) -> &str;
    /// PAYMENT-SIGNATURE headers for a call to `origin` sent before any 402, when this payer has
    /// a session there; None otherwise.
    fn upfront(&self, origin: &str, method: &str, path: &str, body: &[u8]) -> Result<Option<Vec<(String, String)>>>;
    /// Answer a 402 that offers this scheme (`accepted`, from the PaymentRequired `pr`): the
    /// headers to send the call again with.
    #[allow(clippy::too_many_arguments)]
    fn answer(&self, t: &dyn Transport, origin: &str, accepted: &Value, pr: &Value, method: &str, path: &str, body: &[u8])
              -> Result<Vec<(String, String)>>;
    /// Check the decoded PAYMENT-RESPONSE of a call this payer paid.
    fn check(&self, origin: &str, resp: &Value, method: &str, path: &str, body: &[u8]) -> Result<()>;
}
