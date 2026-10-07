//! The field grammars of the scheme (spec §2, §4): canonical unsigned integers, invoice
//! identifiers, identities, bech32 canonicalisation, invoice encoding and the two username forms.
//! Every signed line is built only from values that passed these checks, so no field can carry a
//! `|` and one signature has exactly one reading (§5.1, §12.1).
use serde_json::Value;

use crate::error::{GrammarError, GResult};

pub const U32: u64 = u32::MAX as u64;
pub const U64: u64 = u64::MAX;

/// Strict unsigned integer (receipts.py `_uint`): a JSON integer, or its canonical decimal string
/// (no sign, no leading zero, no separators), at most `hi`. Booleans, floats (`3.0`), negative
/// and larger values are refused.
pub fn uint(v: Option<&Value>, hi: u64, name: &str) -> GResult<u64> {
    let n = match v {
        Some(Value::String(s)) => {
            if !canonical_decimal(s) {
                return Err(GrammarError::new(format!("{name}: not a canonical decimal")));
            }
            s.parse::<u64>().map_err(|_| GrammarError::new(format!("{name}: out of range")))?
        }
        Some(Value::Number(n)) if !n.is_f64() => n.as_u64().ok_or_else(|| GrammarError::new(format!("{name}: out of range")))?,
        // a big integer read by xbt402::json::parse is above u64 by construction
        Some(v @ Value::Object(_)) if xbt402::json::as_big_int(v).is_some() => {
            return Err(GrammarError::new(format!("{name}: out of range")))
        }
        _ => return Err(GrammarError::new(format!("{name}: not an integer"))),
    };
    if n > hi {
        return Err(GrammarError::new(format!("{name}: out of range")));
    }
    Ok(n)
}

/// [`uint`] over text, as a signed line spells it.
pub fn uint_text(s: &str, hi: u64, name: &str) -> GResult<u64> {
    uint(Some(&Value::String(s.to_string())), hi, name)
}

/// `0|[1-9][0-9]*`.
pub fn canonical_decimal(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.iter().all(u8::is_ascii_digit) && (b.len() == 1 || b[0] != b'0')
}

/// §4.1: 8 to 64 characters of `[0-9A-Za-z_-]`.
pub fn valid_invoice(inv: &str) -> bool {
    (8..=64).contains(&inv.len()) && inv.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// §4.2: 1 to 90 characters of `[0-9A-Za-z]`.
pub fn valid_identity(ident: &str) -> bool {
    (1..=90).contains(&ident.len()) && ident.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// `^[0-9a-f]{64}$`: a block hash in a window statement or deferral line.
pub fn valid_block_hash(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn check_invoice(inv: &str) -> GResult<&str> {
    if valid_invoice(inv) { Ok(inv) } else { Err(GrammarError::new("invoice: 8-64 of [0-9A-Za-z_-]")) }
}

pub fn check_identity(ident: &str) -> GResult<&str> {
    if valid_identity(ident) { Ok(ident) } else { Err(GrammarError::new("identity: 1-90 of [0-9A-Za-z]")) }
}

/// A JSON value that must be a string passing `check` (a non-string fails `check` too).
pub(crate) fn text(v: Option<&Value>, check: fn(&str) -> GResult<&str>) -> GResult<&str> {
    let s = v.and_then(Value::as_str).unwrap_or("");
    check(s)?;
    Ok(s)
}

const B32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// BIP173/BIP350 checksum (either constant) over a single-case string: receipts.py
/// `_bech32_valid`, rule for rule (no length or hrp-range checks beyond its own).
pub fn bech32_valid(s: &str) -> bool {
    if !s.is_ascii() {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    if lower != s && s.to_ascii_uppercase() != s {
        return false;
    }
    let Some(sep) = lower.rfind('1') else { return false };
    let (hrp, data) = (&lower[..sep], &lower[sep + 1..]);
    if hrp.is_empty() || data.len() < 6 {
        return false;
    }
    let mut vals: Vec<u32> = hrp.bytes().map(|c| (c >> 5) as u32).collect();
    vals.push(0);
    vals.extend(hrp.bytes().map(|c| (c & 31) as u32));
    for c in data.bytes() {
        match B32.iter().position(|&x| x == c) {
            Some(i) => vals.push(i as u32),
            None => return false,
        }
    }
    let mut chk: u32 = 1;
    for v in vals {
        let top = chk >> 25;
        chk = ((chk & 0x1FF_FFFF) << 5) ^ v;
        for (i, g) in [0x3B6A_57B2u32, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3].iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk == 1 || chk == 0x2BC8_30A3
}

/// §4.2: bech32/bech32m addresses are case-insensitive and lower-cased; anything else is compared
/// byte for byte.
pub fn canonical_identity(ident: &str) -> String {
    if bech32_valid(ident) { ident.to_ascii_lowercase() } else { ident.to_string() }
}

/// §4.1: an invoice identifier is 128 random bits as 26 lowercase RFC 4648 base32 characters,
/// no padding.
pub fn new_invoice(rand16: &[u8; 16]) -> String {
    const A: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut out, mut acc, mut bits) = (String::with_capacity(26), 0u32, 0u32);
    for &b in rand16 {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// A fresh invoice identifier from the OS CSPRNG.
pub fn random_invoice() -> String {
    let mut r = [0u8; 16];
    getrandom::getrandom(&mut r).expect("OS randomness");
    new_invoice(&r)
}

/// Python's `str.strip()` whitespace (Unicode White_Space plus the ASCII separators 0x1c-0x1f).
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// A parsed stratum username (§4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Username {
    /// Canonical identity (§4.2).
    pub identity: String,
    /// The invoice, or None (a candidate outside the grammar is no invoice).
    pub invoice: Option<String>,
    pub worker: String,
}

/// §4.3: `<identity>.pw-<invoice>[.<worker>]` or `<identity>~<invoice>[.<worker>]`. The identity
/// is the text before the first `.` or `~`; a `pw-` anywhere else is not an invoice.
pub fn parse_username(username: &str) -> Username {
    let u = username.trim_matches(py_space);
    let cut = u.find(['.', '~']).unwrap_or(u.len());
    let (ident, rest) = (&u[..cut], &u[cut..]);
    let split = |s: &str| -> (Option<String>, String) {
        let (tag, worker) = s.split_once('.').unwrap_or((s, ""));
        (valid_invoice(tag).then(|| tag.to_string()), worker.to_string())
    };
    let (invoice, worker) = if let Some(r) = rest.strip_prefix('~') {
        split(r)
    } else if let Some(r) = rest.strip_prefix(".pw-") {
        split(r)
    } else if let Some(r) = rest.strip_prefix('.') {
        (None, r.to_string())
    } else {
        (None, String::new())
    };
    Username { identity: canonical_identity(ident), invoice, worker }
}

/// The two encodings a provider hands a payer: (`<identity>~<invoice>.<worker>`,
/// `<identity>.pw-<invoice>`), as receipts.py `usernames`.
pub fn usernames(identity: &str, invoice: &str, worker: &str) -> GResult<(String, String)> {
    check_identity(identity)?;
    check_invoice(invoice)?;
    Ok((format!("{identity}~{invoice}.{worker}"), format!("{identity}.pw-{invoice}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn uints_are_strict() {
        assert_eq!(uint(Some(&json!(7)), U64, "x").unwrap(), 7);
        assert_eq!(uint(Some(&json!("0")), U64, "x").unwrap(), 0);
        assert_eq!(uint(Some(&json!("18446744073709551615")), U64, "x").unwrap(), u64::MAX);
        for bad in [json!(3.0), json!(-1), json!("03"), json!(true), json!("1|0"), json!(""), json!("+1"), json!(null)] {
            assert!(uint(Some(&bad), U64, "x").is_err(), "{bad}");
        }
        assert!(uint(Some(&json!(4294967296u64)), U32, "x").is_err());
        let big = xbt402::json::parse("18446744073709551616").unwrap();
        assert!(uint(Some(&big), U64, "x").is_err());
        assert!(uint(None, U64, "x").is_err());
    }

    #[test]
    fn invoice_encoding() {
        assert_eq!(new_invoice(&[0u8; 16]), "aaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(new_invoice(&[0xff; 16]), "77777777777777777777777774");
        assert_eq!(random_invoice().len(), 26);
        assert!(valid_invoice(&random_invoice()));
    }

    #[test]
    fn usernames_parse() {
        let p = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let u = parse_username(&format!("{}.pw-abcdefgh.RIG", p.to_uppercase()));
        assert_eq!((u.identity.as_str(), u.invoice.as_deref(), u.worker.as_str()), (p, Some("abcdefgh"), "RIG"));
        let u = parse_username(&format!("{p}.rig1.pw-abcdefgh"));
        assert_eq!((u.invoice, u.worker.as_str()), (None, "rig1.pw-abcdefgh"));
        let u = parse_username(&format!("  {p}~abcdefgh.x.y  "));
        assert_eq!((u.invoice.as_deref(), u.worker.as_str()), (Some("abcdefgh"), "x.y"));
        assert_eq!(parse_username(&format!("{p}~short.r")).invoice, None);
        // a non-bech32 identity stays byte-exact
        assert_eq!(parse_username("SomeThing.pw-abcdefgh").identity, "SomeThing");
    }
}
