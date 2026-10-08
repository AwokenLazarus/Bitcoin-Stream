//! Request binding (spec §8.2): `auth` ties one payment payload to one request, one receipt state
//! and a fresh per-invoice counter `n`, under the invoice's `authKey` that only the payer and the
//! provider hold (the gateway operator and the Prime see the invoice, not the key).
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::GResult;
use crate::grammar::check_invoice;

pub const AUTH_TAG: &str = "xbt-work/auth";

/// `hex(SHA256(method | target | body))`: xbt402's v1 request digest, which `xbt-channel` replaced
/// with the length-prefixed, origin-bound v2 (AGP-068). xbt-work keeps v1 because its published
/// vectors (XBT-053) do; moving it is the scheme owner's change.
pub use xbt402::wire::request_digest_v1 as request_digest;

/// `hex(HMAC-SHA256(authKey, "xbt-work/auth|" invoice "|" n "|" seq "|" cum_work "|" req))`.
pub fn auth_tag(auth_key: &[u8], invoice: &str, n: u64, seq: u64, cum_work: u64, req: &str) -> GResult<String> {
    check_invoice(invoice)?;
    let mut m = Hmac::<Sha256>::new_from_slice(auth_key).expect("HMAC takes any key length");
    m.update(format!("{AUTH_TAG}|{invoice}|{n}|{seq}|{cum_work}|{req}").as_bytes());
    Ok(hex::encode(m.finalize().into_bytes()))
}

/// Constant-time comparison of two hex tags.
pub fn tag_eq(a: &str, b: &str) -> bool {
    xbt402::wire::auth_eq(a, b)
}
