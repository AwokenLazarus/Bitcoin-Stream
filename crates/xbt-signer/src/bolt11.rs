//! BOLT 11 invoices, decoded and checked here (AGP-048), not taken from the Lightning node.
//!
//! The `rail=ln` payer reads the payee, the amount, the payment hash, the expiry, the description
//! (hash) and the feature bits from the invoice itself and verifies the payee's signature, so the
//! policy decision never rests on what the LN node says the invoice means. The node's own decode
//! (`DecodePayReq`) is then compared field by field ([`crate::ln`]).
//!
//! XBT-LN keeps Bitcoin's `lnbc` / `lnbcrt` prefixes and genesis chain hash; the only thing that
//! separates its invoices from SHA-256 Lightning's is the compulsory feature bit 512
//! (`option_blake2b`, AGP-047 §3). [`Invoice::has_feature`] exposes it; the caller refuses without it.
use sha2::{Digest, Sha256};
use xbt_primitives::secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use xbt_primitives::secp256k1::{Message, PublicKey, Secp256k1};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/// `option_blake2b`: compulsory on every XBT-LN invoice (the odd bit is its optional form).
pub const FEATURE_BLAKE2B: usize = 512;
/// BOLT 11 defaults when the invoice omits `x` / `c`.
pub const DEFAULT_EXPIRY_S: u64 = 3600;
pub const DEFAULT_MIN_FINAL_CLTV: u64 = 18;
/// Invoices longer than this are refused before any work (BOLT 11 has no limit; LND caps at 7089).
pub const MAX_LEN: usize = 7089;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// The currency prefix after `ln`: `bc` (mainnet, XBT and BTC alike), `bcrt`, `tb`, `tbs`.
    pub currency: String,
    /// `None`: an "any amount" invoice.
    pub amount_msat: Option<u64>,
    pub timestamp: u64,
    pub payment_hash: [u8; 32],
    pub payment_secret: Option<[u8; 32]>,
    pub description: Option<String>,
    pub description_hash: Option<[u8; 32]>,
    /// The payee's node id: the `n` field, or recovered from the signature.
    pub payee: [u8; 33],
    pub expiry_s: u64,
    pub min_final_cltv: u64,
    /// Feature bits set (the `9` field), ascending.
    pub features: Vec<usize>,
    /// Route hints (`r` fields) present.
    pub route_hints: usize,
}

impl Invoice {
    pub fn has_feature(&self, bit: usize) -> bool {
        self.features.contains(&bit)
    }

    pub fn payee_hex(&self) -> String {
        hex::encode(self.payee)
    }

    pub fn payment_hash_hex(&self) -> String {
        hex::encode(self.payment_hash)
    }

    /// The amount in whole sats, rounded up (a sub-sat invoice costs the next sat against a budget).
    pub fn amount_sats_ceil(&self) -> Option<u64> {
        self.amount_msat.map(|m| m.div_ceil(1000))
    }

    /// When the invoice stops being payable (unix seconds).
    pub fn expires_at(&self) -> u64 {
        self.timestamp.saturating_add(self.expiry_s)
    }
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(*v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.iter().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.iter().map(|c| c & 31));
    v
}

/// Bech32 (not bech32m) with no length limit: `(hrp, 5-bit words without the checksum)`.
pub fn bech32_decode(s: &str) -> Result<(String, Vec<u8>), String> {
    if s.len() > MAX_LEN {
        return Err(format!("invoice is {} characters (limit {MAX_LEN})", s.len()));
    }
    if s.bytes().any(|c| c.is_ascii_lowercase()) && s.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err("mixed-case invoice".into());
    }
    let s = s.to_ascii_lowercase();
    let pos = s.rfind('1').ok_or("no bech32 separator")?;
    if pos < 1 || pos + 7 > s.len() {
        return Err("bad bech32 separator position".into());
    }
    let hrp = &s[..pos];
    if hrp.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err("bad character in the prefix".into());
    }
    let mut data = Vec::with_capacity(s.len() - pos - 1);
    for c in s[pos + 1..].bytes() {
        let v = CHARSET.iter().position(|x| *x == c).ok_or_else(|| format!("bad bech32 character {:?}", c as char))?;
        data.push(v as u8);
    }
    let mut chk = hrp_expand(hrp.as_bytes());
    chk.extend(&data);
    if polymod(&chk) != 1 {
        return Err("bad bech32 checksum".into());
    }
    data.truncate(data.len() - 6);
    Ok((hrp.to_string(), data))
}

/// 5-bit words to bytes; `pad` keeps a final partial byte (zero-filled), as the signed data does.
fn to_bytes(words: &[u8], pad: bool) -> Vec<u8> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::with_capacity(words.len() * 5 / 8 + 1));
    for w in words {
        acc = (acc << 5) | u32::from(*w);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if pad && bits > 0 {
        out.push((acc << (8 - bits)) as u8);
    }
    out
}

fn to_int(words: &[u8]) -> Result<u64, String> {
    if words.len() > 12 {
        return Err("integer field too long".into());
    }
    Ok(words.iter().fold(0u64, |a, w| (a << 5) | u64::from(*w)))
}

/// `ln` + currency + optional amount: `(currency, amount_msat)`.
fn parse_hrp(hrp: &str) -> Result<(String, Option<u64>), String> {
    let rest = hrp.strip_prefix("ln").ok_or("not a Lightning invoice (no ln prefix)")?;
    // longest first: bcrt before bc, tbs before tb
    let currency = ["bcrt", "bc", "tbs", "tb"].into_iter().find(|c| rest.starts_with(c))
        .ok_or_else(|| format!("unknown invoice currency in {hrp:?}"))?;
    let amt = &rest[currency.len()..];
    if amt.is_empty() {
        return Ok((currency.into(), None));
    }
    let (digits, mult) = match amt.as_bytes()[amt.len() - 1] {
        c @ (b'm' | b'u' | b'n' | b'p') => (&amt[..amt.len() - 1], Some(c)),
        _ => (amt, None),
    };
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(format!("bad invoice amount {amt:?}"));
    }
    let n: u128 = digits.parse().map_err(|_| format!("bad invoice amount {amt:?}"))?;
    // 1 BTC = 10^11 msat
    let msat: u128 = match mult {
        None => n * 100_000_000_000,
        Some(b'm') => n * 100_000_000,
        Some(b'u') => n * 100_000,
        Some(b'n') => n * 100,
        _ => {
            if n % 10 != 0 {
                return Err("a pico amount must be a whole number of msat".into());
            }
            n / 10
        }
    };
    let msat = u64::try_from(msat).map_err(|_| "invoice amount overflows".to_string())?;
    if msat == 0 {
        return Err("zero invoice amount".into());
    }
    Ok((currency.into(), Some(msat)))
}

fn arr32(b: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(b).ok()
}

/// Decode a BOLT 11 invoice and verify its signature. Any malformed part is an error; unknown
/// fields are skipped as BOLT 11 says.
pub fn decode(invoice: &str) -> Result<Invoice, String> {
    let s = invoice.trim();
    let s = s.strip_prefix("lightning:").or_else(|| s.strip_prefix("LIGHTNING:")).unwrap_or(s);
    let (hrp, data) = bech32_decode(s)?;
    let (currency, amount_msat) = parse_hrp(&hrp)?;
    if data.len() < 7 + 104 {
        return Err("invoice too short".into());
    }
    let (body, sig_words) = data.split_at(data.len() - 104);
    let timestamp = to_int(&body[..7])?;
    let (mut payment_hash, mut payment_secret, mut description, mut description_hash) = (None, None, None, None);
    let (mut payee_n, mut expiry_s, mut min_final_cltv, mut features, mut route_hints) = (None, None, None, Vec::new(), 0usize);
    let mut i = 7;
    while i < body.len() {
        if i + 3 > body.len() {
            return Err("truncated tagged field".into());
        }
        let tag = body[i];
        let len = (usize::from(body[i + 1]) << 5) | usize::from(body[i + 2]);
        let start = i + 3;
        let end = start + len;
        if end > body.len() {
            return Err("tagged field runs past the end".into());
        }
        let f = &body[start..end];
        match tag {
            // p: the payment hash (only a 52-word field counts; the first one wins)
            1 if len == 52 && payment_hash.is_none() => payment_hash = arr32(&to_bytes(f, false)[..32]),
            16 if len == 52 && payment_secret.is_none() => payment_secret = arr32(&to_bytes(f, false)[..32]),
            13 if description.is_none() => {
                description = Some(String::from_utf8(to_bytes(f, false)).map_err(|_| "description is not UTF-8".to_string())?);
            }
            23 if len == 52 && description_hash.is_none() => description_hash = arr32(&to_bytes(f, false)[..32]),
            19 if len == 53 && payee_n.is_none() => payee_n = <[u8; 33]>::try_from(&to_bytes(f, false)[..33]).ok(),
            6 if expiry_s.is_none() => expiry_s = Some(to_int(f)?),
            24 if min_final_cltv.is_none() => min_final_cltv = Some(to_int(f)?),
            5 => {
                features = (0..len * 5).filter(|b| (f[len - 1 - b / 5] >> (b % 5)) & 1 == 1).collect();
            }
            3 => route_hints += 1,
            _ => {}
        }
        i = end;
    }
    let payment_hash = payment_hash.ok_or("invoice has no payment hash")?;
    if description.is_none() && description_hash.is_none() {
        return Err("invoice has neither a description nor a description hash".into());
    }
    // the signature: 64 bytes + a recovery id, over SHA-256(hrp bytes || body words as bytes, padded)
    let sig = to_bytes(sig_words, false);
    let mut pre = hrp.as_bytes().to_vec();
    pre.extend(to_bytes(body, true));
    let msg = Message::from_digest(Sha256::digest(&pre).into());
    let secp = Secp256k1::verification_only();
    let recid = RecoveryId::from_i32(i32::from(sig[64])).map_err(|_| "bad signature recovery id".to_string())?;
    let rsig = RecoverableSignature::from_compact(&sig[..64], recid).map_err(|_| "bad invoice signature".to_string())?;
    let recovered = secp.recover_ecdsa(&msg, &rsig).map_err(|_| "invoice signature does not recover a key".to_string())?;
    let payee = match payee_n {
        Some(n) => {
            let pk = PublicKey::from_slice(&n).map_err(|_| "the invoice's payee (n) is not a public key".to_string())?;
            let mut plain = Signature::from_compact(&sig[..64]).map_err(|_| "bad invoice signature".to_string())?;
            plain.normalize_s();
            secp.verify_ecdsa(&msg, &plain, &pk).map_err(|_| "the invoice is not signed by its payee (n)".to_string())?;
            n
        }
        None => recovered.serialize(),
    };
    Ok(Invoice { currency, amount_msat, timestamp, payment_hash, payment_secret, description, description_hash, payee,
                 expiry_s: expiry_s.unwrap_or(DEFAULT_EXPIRY_S), min_final_cltv: min_final_cltv.unwrap_or(DEFAULT_MIN_FINAL_CLTV),
                 features, route_hints })
}

/// The invoice currency this chain's invoices use (XBT keeps Bitcoin's prefixes, AGP-047 §3).
pub fn currency_for_chain(chain: &str) -> Option<&'static str> {
    match chain {
        "main" => Some("bc"),
        "regtest" => Some("bcrt"),
        "test" | "testnet4" => Some("tb"),
        "signet" => Some("tbs"),
        _ => None,
    }
}

/// Test support: build and sign an invoice (the encoder the decoder is checked against).
#[doc(hidden)]
pub mod encode {
    use super::*;
    use xbt_primitives::secp256k1::SecretKey;

    fn from_bytes(b: &[u8]) -> Vec<u8> {
        let (mut acc, mut bits, mut out) = (0u32, 0u32, vec![]);
        for x in b {
            acc = (acc << 8) | u32::from(*x);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(((acc >> bits) & 31) as u8);
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(((acc << (5 - bits)) & 31) as u8);
        }
        out
    }

    fn int_words(mut n: u64, min: usize) -> Vec<u8> {
        let mut w = vec![];
        while n > 0 {
            w.push((n & 31) as u8);
            n >>= 5;
        }
        while w.len() < min {
            w.push(0);
        }
        w.reverse();
        w
    }

    fn field(tag: u8, words: Vec<u8>) -> Vec<u8> {
        let mut f = vec![tag, (words.len() >> 5) as u8, (words.len() & 31) as u8];
        f.extend(words);
        f
    }

    /// What to put in a test invoice.
    pub struct Spec<'a> {
        pub hrp: &'a str,
        pub timestamp: u64,
        pub payment_hash: [u8; 32],
        pub description: Option<&'a str>,
        pub description_hash: Option<[u8; 32]>,
        pub expiry_s: Option<u64>,
        pub features: &'a [usize],
        pub include_payee: bool,
    }

    pub fn invoice(spec: &Spec, key: &SecretKey) -> String {
        let mut body = int_words(spec.timestamp, 7);
        body.extend(field(1, from_bytes(&spec.payment_hash)));
        body.extend(field(16, from_bytes(&[7u8; 32])));
        if let Some(d) = spec.description {
            body.extend(field(13, from_bytes(d.as_bytes())));
        }
        if let Some(h) = spec.description_hash {
            body.extend(field(23, from_bytes(&h)));
        }
        if let Some(x) = spec.expiry_s {
            body.extend(field(6, int_words(x, 1)));
        }
        if !spec.features.is_empty() {
            let top = spec.features.iter().max().copied().unwrap_or(0);
            let mut w = vec![0u8; top / 5 + 1];
            let n = w.len();
            for b in spec.features {
                w[n - 1 - b / 5] |= 1 << (b % 5);
            }
            body.extend(field(5, w));
        }
        let secp = Secp256k1::new();
        if spec.include_payee {
            body.extend(field(19, from_bytes(&PublicKey::from_secret_key(&secp, key).serialize())));
        }
        let mut pre = spec.hrp.as_bytes().to_vec();
        pre.extend(to_bytes(&body, true));
        let msg = Message::from_digest(Sha256::digest(&pre).into());
        let (rid, sig) = secp.sign_ecdsa_recoverable(&msg, key).serialize_compact();
        let mut sb = sig.to_vec();
        sb.push(rid.to_i32() as u8);
        body.extend(from_bytes(&sb));
        let mut chk = hrp_expand(spec.hrp.as_bytes());
        chk.extend(&body);
        chk.extend([0u8; 6]);
        let pm = polymod(&chk) ^ 1;
        body.extend((0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8));
        let mut s = format!("{}1", spec.hrp);
        s.extend(body.iter().map(|w| CHARSET[usize::from(*w)] as char));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::encode::{invoice, Spec};
    use super::*;
    use xbt_primitives::secp256k1::SecretKey;

    fn key() -> SecretKey {
        SecretKey::from_slice(&[0x11; 32]).unwrap()
    }

    fn spec<'a>(hrp: &'a str, features: &'a [usize]) -> Spec<'a> {
        Spec { hrp, timestamp: 1_790_000_000, payment_hash: [9u8; 32], description: Some("coffee"), description_hash: None,
               expiry_s: Some(600), features, include_payee: false }
    }

    #[test]
    fn round_trip_recovers_the_payee_and_bit_512() {
        let inv = invoice(&spec("lnbcrt25u", &[8, 14, 17, 512]), &key());
        let d = decode(&inv).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &key()).serialize();
        assert_eq!(d.payee, pk);
        assert_eq!(d.currency, "bcrt");
        assert_eq!(d.amount_msat, Some(2_500_000));
        assert_eq!(d.amount_sats_ceil(), Some(2_500));
        assert_eq!(d.payment_hash, [9u8; 32]);
        assert_eq!(d.expiry_s, 600);
        assert_eq!(d.description.as_deref(), Some("coffee"));
        assert!(d.has_feature(FEATURE_BLAKE2B));
        assert_eq!(d.features, vec![8, 14, 17, 512]);
        // uppercase and a lightning: URI decode the same
        assert_eq!(decode(&format!("lightning:{}", inv.to_uppercase())).unwrap(), d);
        // with n: verified, same payee
        let mut s = spec("lnbcrt25u", &[512]);
        s.include_payee = true;
        assert_eq!(decode(&invoice(&s, &key())).unwrap().payee, pk);
    }

    #[test]
    fn no_512_is_visible() {
        let d = decode(&invoice(&spec("lnbc10n", &[8, 14, 17]), &key())).unwrap();
        assert!(!d.has_feature(FEATURE_BLAKE2B));
        assert_eq!(d.amount_msat, Some(1_000));
        assert_eq!(d.currency, "bc");
    }

    #[test]
    fn amounts() {
        assert_eq!(parse_hrp("lnbc").unwrap(), ("bc".into(), None));
        assert_eq!(parse_hrp("lnbc1").unwrap().1, Some(100_000_000_000));
        assert_eq!(parse_hrp("lnbc2500u").unwrap().1, Some(250_000_000));
        assert_eq!(parse_hrp("lnbcrt1m").unwrap(), ("bcrt".into(), Some(100_000_000)));
        assert_eq!(parse_hrp("lntb10p").unwrap().1, Some(1));
        assert!(parse_hrp("lnbc15p").is_err());
        assert!(parse_hrp("lnbc0u").is_err());
        assert!(parse_hrp("lnbc01u").is_err());
        assert!(parse_hrp("lnblakert1u").is_err());
        assert!(parse_hrp("lnxyz").is_err());
    }

    #[test]
    fn tampering_is_refused_or_changes_the_payee() {
        let inv = invoice(&spec("lnbcrt25u", &[512]), &key());
        // a flipped character breaks the checksum
        let mut b = inv.clone().into_bytes();
        let k = b.len() - 20;
        b[k] = if b[k] == b'q' { b'p' } else { b'q' };
        assert!(decode(std::str::from_utf8(&b).unwrap()).unwrap_err().contains("checksum"));
        // re-signed amount by another key: a different payee, never the original one
        let other = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let forged = invoice(&spec("lnbcrt1m", &[512]), &other);
        assert_ne!(decode(&forged).unwrap().payee, decode(&inv).unwrap().payee);
        // n says one key, the signature is another's: refused
        let mut s = spec("lnbcrt25u", &[512]);
        s.include_payee = true;
        let good = invoice(&s, &key());
        let bad = invoice(&s, &other);
        let (_, gw) = bech32_decode(&good).unwrap();
        let (_, bw) = bech32_decode(&bad).unwrap();
        // splice the signature of `bad` (signed by other, n = other) onto `good`'s fields (n = key)
        let mut spliced = gw[..gw.len() - 104].to_vec();
        spliced.extend(&bw[bw.len() - 104..]);
        let mut chk = hrp_expand(b"lnbcrt25u");
        chk.extend(&spliced);
        chk.extend([0u8; 6]);
        let pm = polymod(&chk) ^ 1;
        spliced.extend((0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8));
        let s2 = format!("lnbcrt25u1{}", spliced.iter().map(|w| CHARSET[usize::from(*w)] as char).collect::<String>());
        assert!(decode(&s2).unwrap_err().contains("not signed by its payee"));
    }

    #[test]
    fn needs_hash_and_description() {
        let mut s = spec("lnbcrt25u", &[512]);
        s.description = None;
        assert!(decode(&invoice(&s, &key())).unwrap_err().contains("description"));
        s.description_hash = Some([5u8; 32]);
        assert_eq!(decode(&invoice(&s, &key())).unwrap().description_hash, Some([5u8; 32]));
        assert!(decode("lnbcrt1qqqqqq").is_err());
        assert!(decode(&"x".repeat(MAX_LEN + 1)).is_err());
    }
}
