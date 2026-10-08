//! Helpers for the interop binaries (feature `tools`): the node's view of the chain (network id,
//! the epoch's nBits, pool coinbases) and the Prime's window statements, fed to the audit.
use serde_json::{json, Value};
use xbt402::client::Transport;
use xbt402::rpc::Rpc;
use xbt_primitives::network::network_id;

use crate::audit::{window_from_doc, PrimeTerms, SignedDeferral, SignedWindow};
use crate::chain::{ChainBlock, Maturity};
use crate::error::{Result, WorkError};

/// `--name value` from argv.
pub fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

pub fn flag(name: &str) -> bool {
    std::env::args().any(|x| x == name)
}

/// `--flag value`, else the env variable.
pub fn opt(flag: &str, var: &str) -> Option<String> {
    arg(flag).or_else(|| std::env::var(var).ok().filter(|v| !v.trim().is_empty()))
}

fn opt_num<T: std::str::FromStr>(flag: &str, var: &str) -> Result<Option<T>> {
    opt(flag, var).map(|v| v.trim().parse().map_err(|_| WorkError::new("bad_config", format!("{flag} / {var}: not a number: {v}")))).transpose()
}

/// The Prime's pool terms (AGP-065) from `--prime-window`, `--prime-window-min-work`,
/// `--window-tolerance-bps`, `--prime-fee-bps`, `--prime-min-payout` or their `XBT_WORK_*` env
/// variables; primed's defaults for any not given.
pub fn prime_terms() -> Result<PrimeTerms> {
    let d = PrimeTerms::default();
    Ok(PrimeTerms { window: opt_num("--prime-window", "XBT_WORK_PRIME_WINDOW")?.unwrap_or(d.window),
                    window_min_work: opt_num("--prime-window-min-work", "XBT_WORK_PRIME_WINDOW_MIN_WORK")?.unwrap_or(d.window_min_work),
                    window_tolerance_bps: opt_num("--window-tolerance-bps", "XBT_WORK_WINDOW_TOLERANCE_BPS")?.unwrap_or(d.window_tolerance_bps),
                    fee_bps: opt_num("--prime-fee-bps", "XBT_WORK_PRIME_FEE_BPS")?.unwrap_or(d.fee_bps),
                    max_min_payout: opt_num("--prime-min-payout", "XBT_WORK_PRIME_MIN_PAYOUT")?.unwrap_or(d.max_min_payout) })
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
    rpc.call("getblockcount", json!([]))?.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| WorkError::new("node", "getblockcount"))
}

pub fn block_hash(rpc: &Rpc, height: u32) -> Result<String> {
    rpc.call("getblockhash", json!([height]))?.as_str().map(str::to_string).ok_or_else(|| WorkError::new("node", "getblockhash"))
}

/// A block's coinbase: (block hash, total value V in sats, [(address, sats)]).
pub type Coinbase = (String, u64, Vec<(String, u64)>);

pub fn coinbase(rpc: &Rpc, height: u32) -> Result<Coinbase> {
    let hash = block_hash(rpc, height)?;
    let blk = rpc.call("getblock", json!([hash, 2]))?;
    let (total, outs) = coinbase_outputs(&blk)?;
    Ok((hash, total, outs))
}

fn coinbase_outputs(blk: &Value) -> Result<(u64, Vec<(String, u64)>)> {
    let vout = blk["tx"][0]["vout"].as_array().ok_or_else(|| WorkError::new("node", "getblock: no coinbase outputs"))?;
    let mut total = 0u64;
    let mut outs = vec![];
    for o in vout {
        let btc = o["value"].as_f64().ok_or_else(|| WorkError::new("node", "getblock: output value"))?;
        let sats = (btc * 1e8).round() as u64;
        total = total.saturating_add(sats);
        // an output with no address (OP_RETURN, the witness commitment) pays no identity
        outs.push((o["scriptPubKey"]["address"].as_str().unwrap_or("").to_string(), sats));
    }
    Ok((total, outs))
}

fn bits_of(v: &Value) -> Result<u32> {
    u32::from_str_radix(v["bits"].as_str().unwrap_or(""), 16).map_err(|_| WorkError::new("node", "bits"))
}

/// The block at `height` as the provider's node has it, with what its coinbase pays `identity`.
pub fn chain_block(rpc: &Rpc, height: u32, identity: &str) -> Result<ChainBlock> {
    let hash = block_hash(rpc, height)?;
    let blk = rpc.call("getblock", json!([hash, 2]))?;
    let (value_sats, outs) = coinbase_outputs(&blk)?;
    let bits = bits_of(&blk)?;
    let prev_bits = match blk["previousblockhash"].as_str() {
        Some(p) => bits_of(&rpc.call("getblockheader", json!([p]))?)?,
        None => bits,
    };
    Ok(ChainBlock { height, hash, value_sats, paid_sats: paid_to(&outs, identity), bits, prev_bits })
}

/// The node's coinbase maturity (Knots `getdeploymentinfo`).
pub fn maturity(rpc: &Rpc) -> Result<Maturity> {
    Maturity::from_deployments(&rpc.call("getdeploymentinfo", json!([]))?)
}

/// What a coinbase pays `identity` (bech32 compared lower-case).
pub fn paid_to(outs: &[(String, u64)], identity: &str) -> u64 {
    outs.iter().filter(|(a, _)| a.eq_ignore_ascii_case(identity)).map(|(_, s)| *s).sum()
}

/// The Prime's statement for a pool block (`GET <window_url>?height=H`): None when the Prime
/// answers 404 (it has none for that height); any other status is an error, never "none"
/// (Guida P4: an unreachable Prime must not look like a block with nothing to audit).
pub fn window(t: &dyn Transport, window_url: &str, height: u32) -> Result<Option<(SignedWindow, Vec<SignedDeferral>, Value)>> {
    let r = t.request("GET", &format!("{window_url}?height={height}"), b"", &[])?;
    match r.status {
        200 => {}
        404 => return Ok(None),
        s => return Err(WorkError::new("prime", format!("window statement for {height}: HTTP {s}"))),
    }
    let doc = xbt402::json::parse_slice(&r.body).map_err(|_| WorkError::new("prime", "window statement is not JSON"))?;
    let (w, d) = window_from_doc(&doc).map_err(|e| WorkError::new("prime", e.0))?;
    Ok(Some((w, d, doc)))
}
