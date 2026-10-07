//! AGP-049: what the LN node's macaroon allows, read from the macaroon itself (the v2 binary format
//! and LND's identifier), so `ln_status` can show it and `ln_pay` can refuse an over-broad one on
//! mainnet. Nothing here verifies the macaroon's HMAC: that is the LN node's job, and the signer does
//! not hold the root key.
//!
//! LND's `ipaddr` / `iprange` caveats are checked against the **gRPC** peer address. LND's REST
//! gateway is an in-process gRPC client that dials `127.0.0.1` (lnd.go, `restProxyDest`), so over
//! REST every call arrives from loopback: a caveat locked to the signer's own address makes every REST
//! call fail ("macaroon locked to different IP address"), and `ipaddr 127.0.0.1` passes any REST
//! caller. An IP caveat binds only gRPC callers; for this REST client the restriction is the REST
//! listener's own address (`restlisten` on a private interface) or a firewall. Shown on the lab
//! (`scripts/ln_rail_regtest.sh`, S12).
use serde_json::{json, Value};

/// What `rail=ln` needs, and nothing else (the README's baked macaroon).
pub const NEEDED_OPS: [&str; 4] = ["info:read", "offchain:read", "offchain:write", "onchain:read"];

/// Permissions that let a holder move funds on chain, sign arbitrary data or mint new macaroons:
/// refused on mainnet.
pub const DANGEROUS_OPS: [&str; 4] = ["onchain:write", "macaroon:generate", "macaroon:write", "signer:generate"];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Macaroon {
    pub location: String,
    pub identifier: Vec<u8>,
    /// First-party caveat conditions (`ipaddr 1.2.3.4`, `time-before 2026-…`, `lnd-custom …`).
    pub caveats: Vec<String>,
    /// `entity:action`, from LND's identifier (empty if the identifier is not LND's).
    pub ops: Vec<String>,
}

fn uvarint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let c = *b.get(*pos)?;
        *pos += 1;
        v |= ((c & 0x7f) as u64) << shift;
        if c & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// One v2 field: `(type, data)`, or `None` at the end-of-section marker (a zero byte).
fn field<'a>(b: &'a [u8], pos: &mut usize) -> Result<Option<(u64, &'a [u8])>, String> {
    let t = uvarint(b, pos).ok_or("truncated field type")?;
    if t == 0 {
        return Ok(None);
    }
    let n = uvarint(b, pos).ok_or("truncated field length")? as usize;
    let end = pos.checked_add(n).filter(|e| *e <= b.len()).ok_or("field past the end")?;
    let d = &b[*pos..end];
    *pos = end;
    Ok(Some((t, d)))
}

/// A protobuf length-delimited walk: `(field number, bytes)` for every wire-type-2 field; other wire
/// types are skipped.
fn proto_fields(b: &[u8]) -> Vec<(u64, &[u8])> {
    let mut out = vec![];
    let mut pos = 0;
    while pos < b.len() {
        let Some(key) = uvarint(b, &mut pos) else { break };
        match key & 7 {
            0 => {
                if uvarint(b, &mut pos).is_none() {
                    break;
                }
            }
            1 => pos += 8,
            5 => pos += 4,
            2 => {
                let Some(n) = uvarint(b, &mut pos) else { break };
                let Some(end) = pos.checked_add(n as usize).filter(|e| *e <= b.len()) else { break };
                out.push((key >> 3, &b[pos..end]));
                pos = end;
            }
            _ => break,
        }
    }
    out
}

/// LND's identifier: a version byte (3), then `MacaroonId { nonce = 1; storageId = 2; repeated Op ops = 3 }`
/// with `Op { entity = 1; repeated actions = 2 }`.
fn lnd_ops(id: &[u8]) -> Vec<String> {
    if id.first() != Some(&3) {
        return vec![];
    }
    let mut ops = vec![];
    for (f, op) in proto_fields(&id[1..]) {
        if f != 3 {
            continue;
        }
        let parts = proto_fields(op);
        let entity = parts.iter().find(|(n, _)| *n == 1).map(|(_, e)| String::from_utf8_lossy(e).to_string()).unwrap_or_default();
        for (_, a) in parts.iter().filter(|(n, _)| *n == 2) {
            ops.push(format!("{entity}:{}", String::from_utf8_lossy(a)));
        }
    }
    ops.sort();
    ops.dedup();
    ops
}

/// Parse a v2 binary macaroon (what LND writes to `*.macaroon`).
pub fn parse(b: &[u8]) -> Result<Macaroon, String> {
    if b.first() != Some(&2) {
        return Err("not a v2 binary macaroon".into());
    }
    let mut pos = 1;
    let mut m = Macaroon::default();
    while let Some((t, d)) = field(b, &mut pos)? {
        match t {
            1 => m.location = String::from_utf8_lossy(d).into(),
            2 => m.identifier = d.to_vec(),
            _ => {}
        }
    }
    loop {
        if b.get(pos) == Some(&0) {
            pos += 1;
            break;
        }
        if pos >= b.len() {
            return Err("truncated caveats".into());
        }
        let (mut id, mut third_party) = (Vec::new(), false);
        while let Some((t, d)) = field(b, &mut pos)? {
            match t {
                2 => id = d.to_vec(),
                4 => third_party = true,
                _ => {}
            }
        }
        m.caveats.push(if third_party { format!("third-party {}", hex::encode(&id)) } else { String::from_utf8_lossy(&id).into() });
    }
    match field(b, &mut pos)? {
        Some((6, _)) => {}
        _ => return Err("no signature".into()),
    }
    m.ops = lnd_ops(&m.identifier);
    Ok(m)
}

impl Macaroon {
    /// The caveat's argument for a condition name (`ipaddr`, `iprange`, `time-before`).
    pub fn caveat(&self, cond: &str) -> Option<String> {
        self.caveats.iter().find_map(|c| c.strip_prefix(cond).and_then(|r| r.strip_prefix(' ')).map(str::to_string))
    }

    pub fn excess_ops(&self) -> Vec<String> {
        self.ops.iter().filter(|o| !NEEDED_OPS.contains(&o.as_str())).cloned().collect()
    }

    pub fn dangerous_ops(&self) -> Vec<String> {
        self.ops.iter().filter(|o| DANGEROUS_OPS.contains(&o.as_str()) || o.ends_with(":*")).cloned().collect()
    }

    /// For `ln_status`: the permissions and caveats, with what each means for a REST client.
    pub fn report(&self) -> Value {
        let ip = self.caveat("ipaddr").or_else(|| self.caveat("iprange"));
        let ip_note = match &ip {
            None => "no IP caveat: the macaroon works from any address that reaches the REST listener".to_string(),
            Some(a) if a == "127.0.0.1" || a == "::1" || a.starts_with("127.") => {
                format!("IP caveat {a}: LND's REST gateway dials gRPC from 127.0.0.1, so this passes every REST caller; \
                         restrict the REST listener (restlisten) or firewall it")
            }
            Some(a) => format!("IP caveat {a}: over REST LND sees 127.0.0.1, so REST calls fail unless {a} covers loopback"),
        };
        json!({"ops": self.ops, "excess_ops": self.excess_ops(), "dangerous_ops": self.dangerous_ops(), "caveats": self.caveats,
               "ip_caveat": ip, "ip_note": ip_note, "time_before": self.caveat("time-before")})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(out: &mut Vec<u8>, t: u8, d: &[u8]) {
        out.push(t);
        out.push(d.len() as u8);
        out.extend_from_slice(d);
    }

    fn proto(field: u8, d: &[u8]) -> Vec<u8> {
        let mut v = vec![(field << 3) | 2, d.len() as u8];
        v.extend_from_slice(d);
        v
    }

    /// A macaroon as LND bakes it: v2, identifier version 3 + MacaroonId, first-party caveats.
    pub fn lnd_macaroon(ops: &[(&str, &[&str])], caveats: &[&str]) -> Vec<u8> {
        let mut id = vec![3u8];
        id.extend(proto(1, &[7; 16]));
        id.extend(proto(2, b"0"));
        for (e, acts) in ops {
            let mut op = proto(1, e.as_bytes());
            for a in *acts {
                op.extend(proto(2, a.as_bytes()));
            }
            id.extend(proto(3, &op));
        }
        let mut m = vec![2u8];
        put(&mut m, 1, b"lnd");
        put(&mut m, 2, &id);
        m.push(0);
        for c in caveats {
            put(&mut m, 2, c.as_bytes());
            m.push(0);
        }
        m.push(0);
        put(&mut m, 6, &[9; 32]);
        m
    }

    #[test]
    fn reads_lnd_ops_and_caveats() {
        let b = lnd_macaroon(&[("info", &["read"]), ("offchain", &["read", "write"]), ("onchain", &["read"])], &["ipaddr 127.0.0.1"]);
        let m = parse(&b).unwrap();
        assert_eq!(m.location, "lnd");
        assert_eq!(m.ops, vec!["info:read", "offchain:read", "offchain:write", "onchain:read"]);
        assert_eq!(m.caveat("ipaddr").as_deref(), Some("127.0.0.1"));
        assert!(m.excess_ops().is_empty() && m.dangerous_ops().is_empty());
        assert!(m.report()["ip_note"].as_str().unwrap().contains("passes every REST caller"));
        let admin = parse(&lnd_macaroon(&[("onchain", &["read", "write"]), ("macaroon", &["generate"])], &[])).unwrap();
        assert_eq!(admin.dangerous_ops(), vec!["macaroon:generate", "onchain:write"]);
        assert!(admin.report()["ip_note"].as_str().unwrap().starts_with("no IP caveat"));
        let locked = parse(&lnd_macaroon(&[("info", &["read"])], &["ipaddr 172.18.0.1", "time-before 2030-01-01T00:00:00Z"])).unwrap();
        assert!(locked.report()["ip_note"].as_str().unwrap().contains("REST calls fail"));
        assert_eq!(locked.caveat("time-before").as_deref(), Some("2030-01-01T00:00:00Z"));
    }

    #[test]
    fn refuses_garbage() {
        assert!(parse(b"").is_err());
        assert!(parse(&[1, 2, 3]).is_err());
        let mut b = lnd_macaroon(&[("info", &["read"])], &[]);
        b.truncate(b.len() - 10);
        assert!(parse(&b).is_err());
    }
}
