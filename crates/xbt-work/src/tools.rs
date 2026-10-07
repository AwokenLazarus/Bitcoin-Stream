//! Helpers for the interop binaries (feature `tools`): the node's view of the chain (network id,
//! the epoch's nBits, pool coinbases) and the Prime's window statements, fed to the audit.
use serde_json::{json, Value};
use xbt402::client::Transport;
use xbt402::rpc::Rpc;
use xbt_primitives::network::network_id;

use crate::audit::{window_from_doc, SignedDeferral, SignedWindow};
use crate::error::{Result, WorkError};

/// `--name value` from argv.
pub fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

pub fn flag(name: &str) -> bool {
    std::env::args().any(|x| x == name)
}

pub fn rpc(port: &str, cookie: &str) -> Result<Rpc> {
    Ok(Rpc::from_cookie(&format!("http://127.0.0.1:{port}"), std::path::Path::new(cookie))?)
}

/// The CAIP-2 network of the node's chain (the first BLAKE2b block, 101 on regtest).
pub fn network(rpc: &Rpc) -> Result<String> {
    let h = rpc.call("getblockhash", json!([101]))?;
    Ok(network_id(h.as_str().ok_or_else(|| WorkError::new("node", "getblockhash"))?))
}

/// The tip's compact target (the epoch's `bits`).
pub fn tip_bits(rpc: &Rpc) -> Result<u32> {
    let best = rpc.call("getbestblockhash", json!([]))?;
    let hdr = rpc.call("getblockheader", json!([best]))?;
    u32::from_str_radix(hdr["bits"].as_str().unwrap_or(""), 16).map_err(|_| WorkError::new("node", "bits"))
}

pub fn block_count(rpc: &Rpc) -> Result<u32> {
    Ok(rpc.call("getblockcount", json!([]))?.as_u64().unwrap_or(0) as u32)
}

/// A block's coinbase: (block hash, total value V in sats, [(address, sats)]).
pub type Coinbase = (String, u64, Vec<(String, u64)>);

pub fn coinbase(rpc: &Rpc, height: u32) -> Result<Coinbase> {
    let hash = rpc.call("getblockhash", json!([height]))?;
    let blk = rpc.call("getblock", json!([hash, 2]))?;
    let mut total = 0u64;
    let mut outs = vec![];
    for o in blk["tx"][0]["vout"].as_array().into_iter().flatten() {
        let sats = (o["value"].as_f64().unwrap_or(0.0) * 1e8).round() as u64;
        total += sats;
        outs.push((o["scriptPubKey"]["address"].as_str().unwrap_or("").to_string(), sats));
    }
    Ok((hash.as_str().unwrap_or("").to_string(), total, outs))
}

/// What a coinbase pays `identity` (bech32 compared lower-case).
pub fn paid_to(outs: &[(String, u64)], identity: &str) -> u64 {
    outs.iter().filter(|(a, _)| a.eq_ignore_ascii_case(identity)).map(|(_, s)| *s).sum()
}

/// The Prime's statement for a pool block (`GET <window_url>?height=H`), or None when it has none.
pub fn window(t: &dyn Transport, window_url: &str, height: u32) -> Result<Option<(SignedWindow, Vec<SignedDeferral>, Value)>> {
    let r = t.request("GET", &format!("{window_url}?height={height}"), b"", &[])?;
    if r.status != 200 {
        return Ok(None);
    }
    let doc = xbt402::json::parse_slice(&r.body).map_err(|_| WorkError::new("prime", "window statement is not JSON"))?;
    let (w, d) = window_from_doc(&doc).map_err(|e| WorkError::new("prime", e.0))?;
    Ok(Some((w, d, doc)))
}
