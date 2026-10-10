//! Coinbase audit (spec §10): signed window statements, signed deferral lines (carry, including
//! XBT-NTA `unattested` payees), the provider's bound, the pass/fail rule, transferable fraud
//! proofs, and the ledger of carry owed.
//!
//! ```text
//! xbt-work-window/1|<prime_id>|<height>|<block_hash>|<window_start>|<window_work>|<min_payout>|<fee_bps>
//! xbt-work-deferral/1|<prime_id>|<height>|<block_hash>|<identity>|<deferred_sats>|<reason>
//! L_H        = Σ work of intervals with lo > window_start and hi < H
//! expected_H = ⌊ V_H · (10⁴ − fee_bps) · L_H / (10⁴ · window_work) ⌋
//! pass  ⇔  expected_H < min_payout  ∨  paid_H + deferred_H + 1 ≥ expected_H
//! ```
//!
//! AGP-065 (review P1, P3): `window_work`, `fee_bps` and `min_payout` are the Prime's numbers, so the
//! provider holds each to a bound it sets itself ([`AuditBounds`], from the Prime's published
//! [`PrimeTerms`] and the chain's difficulty) before the rule runs, and the statement must name the
//! block the provider's node has at that height ([`ChainBlock`]). A third party checks a fraud proof
//! under the same bounds.
use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use ruint::aliases::{U256, U512};
use serde_json::Value;
use xbt402::json::obj;

use crate::book::{Interval, ReceiptBook};
use crate::chain::ChainBlock;
use crate::error::{fail, GResult, GrammarError, Result};
use crate::grammar::{check_identity, uint_text, valid_block_hash, U32, U64};
use crate::pricing::{bits_to_target, diff1_target};
use crate::receipt::{sig64, verify, PrimeKey, Signed, WorkReceipt};

pub const WINDOW_TAG: &str = "xbt-work-window/1";
pub const DEFERRAL_TAG: &str = "xbt-work-deferral/1";
pub const DEFERRAL_REASONS: [&str; 3] = ["unattested", "over-budget", "below-minimum"];
pub const FRAUD_KIND: &str = "xbt-work-fraud/1";
/// One satoshi of rounding per output (§10.3).
pub const TOLERANCE: u64 = 1;

/// §10.1: the Prime's statement of the window a pool block's coinbase split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowStatement {
    pub prime_id: u32,
    pub height: u32,
    /// 64 lowercase hex.
    pub block_hash: String,
    /// Every share credited above this height is wholly inside the window.
    pub window_start: u32,
    /// The split's own divisor (at least the window target W).
    pub window_work: u64,
    /// Outputs below this are deferred as carry.
    pub min_payout: u64,
    /// Pool fee on the invoice path.
    pub fee_bps: u32,
}

impl WindowStatement {
    pub fn message(&self) -> GResult<String> {
        if !valid_block_hash(&self.block_hash) {
            return Err(GrammarError::new("block_hash"));
        }
        if self.fee_bps > 10_000 {
            return Err(GrammarError::new("fee_bps: out of range"));
        }
        Ok(format!("{WINDOW_TAG}|{}|{}|{}|{}|{}|{}|{}", self.prime_id, self.height, self.block_hash, self.window_start,
                   self.window_work, self.min_payout, self.fee_bps))
    }

    /// Strict parse of a statement line (canonical integers, the line rebuilt must be identical).
    pub fn parse(line: &str) -> GResult<Self> {
        let f: Vec<&str> = line.split('|').collect();
        if f.len() != 8 || f[0] != WINDOW_TAG {
            return Err(GrammarError::new("window statement line"));
        }
        let w = Self { prime_id: uint_text(f[1], U32, "prime_id")? as u32, height: uint_text(f[2], U32, "height")? as u32,
                       block_hash: f[3].into(), window_start: uint_text(f[4], U32, "window_start")? as u32,
                       window_work: uint_text(f[5], U64, "window_work")?, min_payout: uint_text(f[6], U64, "min_payout")?,
                       fee_bps: uint_text(f[7], 10_000, "fee_bps")? as u32 };
        if w.message()? != line {
            return Err(GrammarError::new("window statement is not canonical"));
        }
        Ok(w)
    }
}

/// §10.1: a signed statement that the block at (height, block_hash) deferred `sats` of `identity`'s
/// earned share to carry. Under XBT-NTA the reason is `unattested`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferral {
    pub prime_id: u32,
    pub height: u32,
    pub block_hash: String,
    pub identity: String,
    pub sats: u64,
    pub reason: String,
}

impl Deferral {
    pub fn message(&self) -> GResult<String> {
        if !valid_block_hash(&self.block_hash) {
            return Err(GrammarError::new("block_hash"));
        }
        if !DEFERRAL_REASONS.contains(&self.reason.as_str()) {
            return Err(GrammarError::new("reason"));
        }
        check_identity(&self.identity)?;
        Ok(format!("{DEFERRAL_TAG}|{}|{}|{}|{}|{}|{}", self.prime_id, self.height, self.block_hash, self.identity, self.sats, self.reason))
    }

    pub fn parse(line: &str) -> GResult<Self> {
        let f: Vec<&str> = line.split('|').collect();
        if f.len() != 7 || f[0] != DEFERRAL_TAG {
            return Err(GrammarError::new("deferral line"));
        }
        let d = Self { prime_id: uint_text(f[1], U32, "prime_id")? as u32, height: uint_text(f[2], U32, "height")? as u32,
                       block_hash: f[3].into(), identity: f[4].into(), sats: uint_text(f[5], U64, "sats")?, reason: f[6].into() };
        if d.message()? != line {
            return Err(GrammarError::new("deferral line is not canonical"));
        }
        Ok(d)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedWindow {
    pub stmt: WindowStatement,
    pub sig: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDeferral {
    pub d: Deferral,
    pub sig: [u8; 64],
}

impl SignedWindow {
    pub fn line_doc(&self) -> Value {
        obj([("message", self.stmt.message().unwrap_or_default().into()), ("sig", hex::encode(self.sig).into())])
    }

    pub fn verify(&self, pk: &VerifyingKey) -> bool {
        self.stmt.message().is_ok_and(|m| verify(pk, &m, &self.sig))
    }

    /// `{message, sig, ...}` as a Prime serves it.
    pub fn from_doc(d: &Value) -> GResult<Self> {
        Ok(Self { stmt: WindowStatement::parse(d.get("message").and_then(Value::as_str).unwrap_or(""))?, sig: sig64(d.get("sig"))? })
    }
}

impl SignedDeferral {
    pub fn line_doc(&self) -> Value {
        obj([("message", self.d.message().unwrap_or_default().into()), ("sig", hex::encode(self.sig).into())])
    }

    pub fn verify(&self, pk: &VerifyingKey) -> bool {
        self.d.message().is_ok_and(|m| verify(pk, &m, &self.sig))
    }

    pub fn from_doc(d: &Value) -> GResult<Self> {
        Ok(Self { d: Deferral::parse(d.get("message").and_then(Value::as_str).unwrap_or(""))?, sig: sig64(d.get("sig"))? })
    }
}

/// A Prime's statement document (`GET /window?height=H`): `{message, sig, deferred: [{message,
/// sig, ...}]}`. Deferral lines that do not parse are dropped here (they are not the Prime's word,
/// §10.3); the ones that parse are still checked against the key and the block by the audit.
pub fn window_from_doc(d: &Value) -> GResult<(SignedWindow, Vec<SignedDeferral>)> {
    let w = SignedWindow::from_doc(d)?;
    let lines = d.get("deferred").and_then(Value::as_array).into_iter().flatten().filter_map(|x| SignedDeferral::from_doc(x).ok()).collect();
    Ok((w, lines))
}

impl PrimeKey {
    pub fn sign_window(&self, stmt: &WindowStatement) -> GResult<SignedWindow> {
        Ok(SignedWindow { stmt: stmt.clone(), sig: self.sign_raw(stmt.message()?.as_bytes()) })
    }

    pub fn sign_deferral(&self, d: &Deferral) -> GResult<SignedDeferral> {
        Ok(SignedDeferral { d: d.clone(), sig: self.sign_raw(d.message()?.as_bytes()) })
    }
}

/// §10.3: sats `deferred` owes `identity` for the block of `w`. A line counts only if it verifies
/// under the Prime key and names w's prime_id, height and block_hash and this identity. Returns
/// the total and the lines that counted (`{message, sig}`).
pub fn deferred_sats(pk: &VerifyingKey, w: &WindowStatement, identity: &str, deferred: &[SignedDeferral]) -> (u64, Vec<Value>) {
    let (mut total, mut used) = (0u64, vec![]);
    for sd in deferred {
        let d = &sd.d;
        if (d.prime_id, d.height, d.block_hash.as_str(), d.identity.as_str()) != (w.prime_id, w.height, w.block_hash.as_str(), identity) {
            continue;
        }
        if !sd.verify(pk) {
            continue;
        }
        total = total.saturating_add(d.sats);
        used.push(sd.line_doc());
    }
    (total, used)
}

/// §10.2 `L_H`: receipted work certainly in the window of the block at `height`.
pub fn window_work_bound(intervals: &[Interval], height: u32, window_start: u32) -> u64 {
    intervals.iter().filter(|(lo, hi, _)| *lo > window_start && *hi < height).fold(0u64, |a, (_, _, w)| a.saturating_add(*w))
}

/// `⌊ V · (10⁴ − fee_bps) · L / (10⁴ · window_work) ⌋`.
pub fn expected_sats(coinbase_value_sats: u64, fee_bps: u32, proven_work: u64, window_work: u64) -> Result<u64> {
    if window_work == 0 || fee_bps > 10_000 {
        return fail("bad_window", "window_work is zero or fee_bps above 10000");
    }
    let num = U256::from(coinbase_value_sats) * U256::from(10_000 - fee_bps) * U256::from(proven_work);
    let q = num / (U256::from(10_000u64) * U256::from(window_work));
    // the provider's share of V can never exceed V
    Ok(u64::try_from(q).unwrap_or(u64::MAX))
}

/// §10.4 third-party bound: for each (identity, invoice) the highest `cum_work` of a receipt whose
/// whole span `[first_height, last_height]` lies in `(window_start, height)`.
pub fn receipts_bound<'a>(receipts: impl IntoIterator<Item = &'a WorkReceipt>, w: &WindowStatement) -> u64 {
    let mut best: HashMap<(&str, &str), u64> = HashMap::new();
    for r in receipts {
        if r.first_height > w.window_start && r.last_height < w.height {
            let e = best.entry((r.identity.as_str(), r.invoice.as_str())).or_insert(0);
            *e = (*e).max(r.cum_work);
        }
    }
    best.values().fold(0u64, |a, b| a.saturating_add(*b))
}

/// The Prime's published pool terms, pinned in the provider's configuration (AGP-065, review P1). They
/// bound what any window statement may claim; a statement never moves them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimeTerms {
    /// primed `window`: the window target is this many times the network difficulty, in work units.
    pub window: u32,
    /// primed `window-min-work`: the Prime's floor on the window target (regtest needs one).
    pub window_min_work: u64,
    /// Slack over the target: a TIDES window holds up to one share row more than its target, and a
    /// Prime may size it from the parent's difficulty for one block after a retarget (both counted).
    pub window_tolerance_bps: u32,
    /// The pool fee on the invoice path the Prime advertises (what the provider prices with, §13.7).
    pub fee_bps: u32,
    /// The Prime's advertised `min-payout`: a statement may name less, never more.
    pub max_min_payout: u64,
}

impl Default for PrimeTerms {
    /// primed's defaults (window 8, no floor, fee 0, min-payout 546) with 5% slack.
    fn default() -> Self {
        Self { window: 8, window_min_work: 0, window_tolerance_bps: 500, fee_bps: 0, max_min_payout: 546 }
    }
}

impl PrimeTerms {
    /// The window target at `bits`: `max(⌈window · T₁ / T(bits)⌉, window_min_work)`.
    pub fn window_target(&self, bits: u32) -> Result<u64> {
        let t = (U512::from(self.window) * diff1_target()).div_ceil(bits_to_target(bits)?);
        Ok(u64::try_from(t).unwrap_or(u64::MAX).max(self.window_min_work))
    }

    /// The bounds for the coinbase of `block`: the larger target of its own and its parent's
    /// difficulty, plus the slack.
    pub fn bounds(&self, block: &ChainBlock) -> Result<AuditBounds> {
        if self.window_tolerance_bps > 10_000 || self.fee_bps > 10_000 {
            return fail("bad_config", "window_tolerance_bps and fee_bps are at most 10000");
        }
        let target = self.window_target(block.bits)?.max(self.window_target(block.prev_bits)?);
        let max = (U256::from(target) * U256::from(10_000 + self.window_tolerance_bps)).div_ceil(U256::from(10_000u64));
        Ok(AuditBounds { max_window_work: u64::try_from(max).unwrap_or(u64::MAX), fee_bps: self.fee_bps, max_min_payout: self.max_min_payout })
    }
}

/// What a statement for one block may claim (AGP-065). The audit uses `min(statement, bound)` for each:
/// a larger `window_work` or `fee_bps` would shrink `expected`, a larger `min_payout` would excuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditBounds {
    pub max_window_work: u64,
    pub fee_bps: u32,
    pub max_min_payout: u64,
}

impl AuditBounds {
    /// No bound: the v1 draft rule, the statement's numbers as they are. The conformance vectors
    /// use it; a provider never should.
    pub const STATEMENT_ONLY: Self = Self { max_window_work: u64::MAX, fee_bps: 10_000, max_min_payout: u64::MAX };

    /// (window_work, fee_bps, min_payout) the rule runs with, and whether any was cut down.
    pub fn apply(&self, w: &WindowStatement) -> (u64, u32, u64, bool) {
        let (ww, fee, mp) = (w.window_work.min(self.max_window_work), w.fee_bps.min(self.fee_bps), w.min_payout.min(self.max_min_payout));
        (ww, fee, mp, (ww, fee, mp) != (w.window_work, w.fee_bps, w.min_payout))
    }

    pub fn to_json(&self) -> Value {
        obj([("maxWindowWork", self.max_window_work.into()), ("feeBps", self.fee_bps.into()), ("maxMinPayout", self.max_min_payout.into())])
    }
}

/// The verdict on one coinbase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditOutcome {
    pub ok: bool,
    pub expected_sats: u64,
    pub paid_sats: u64,
    pub deferred_sats: u64,
    /// A pass under the `min_payout` clause that the coinbase did not pay: owed as carry, as the
    /// Prime's window carries it (counted in the carry ledger, AGP-065).
    pub below_min_sats: u64,
    pub proven_work: u64,
    /// The `window_work`, `fee_bps` and `min_payout` the rule ran with (the statement's, bounded).
    pub window_work: u64,
    pub fee_bps: u32,
    pub min_payout: u64,
    /// Whether the bounds cut any of the statement's numbers down.
    pub bounded: bool,
    /// The §10.4 fraud proof when the coinbase fails.
    pub proof: Option<Value>,
}

/// §10.3 for the provider holding `book`: the coinbase of `block` (from the provider's own node),
/// with the statement `sw` and the deferral lines it published, under `bounds`. The statement must
/// verify under the pinned key (`bad_window_sig`) and name `block`'s height and hash (`wrong_block`).
pub fn audit_block(book: &ReceiptBook, sw: &SignedWindow, block: &ChainBlock, bounds: &AuditBounds, deferred: &[SignedDeferral]) -> Result<AuditOutcome> {
    let w = &sw.stmt;
    if !sw.verify(&book.prime_pubkey) {
        return fail("bad_window_sig", "window statement not signed by the pinned Prime key");
    }
    if w.prime_id != book.prime_id {
        return fail("wrong_prime", "window statement from another Prime");
    }
    if (w.height, w.block_hash.as_str()) != (block.height, block.hash.as_str()) {
        return fail("wrong_block", format!("the statement names {} at {}, the chain has {} at {}", w.block_hash, w.height, block.hash, block.height));
    }
    let (ww, fee, mp, bounded) = bounds.apply(w);
    let (value, paid) = (block.value_sats, block.paid_sats);
    let l = window_work_bound(&book.intervals, w.height, w.window_start);
    let expected = expected_sats(value, fee, l, ww)?;
    let (owed, lines) = deferred_sats(&book.prime_pubkey, w, &book.identity, deferred);
    let covered = paid.saturating_add(owed).saturating_add(TOLERANCE);
    let ok = expected < mp || covered >= expected;
    let proof = (!ok).then(|| {
        let mut p = obj([("kind", FRAUD_KIND.into()), ("identity", book.identity.clone().into()), ("height", w.height.into()),
                         ("blockHash", w.block_hash.clone().into()), ("coinbaseValueSats", value.into()),
                         ("paidSats", paid.into()), ("expectedSats", expected.into()), ("windowWork", ww.into()),
                         ("provenWork", l.into()), ("window", sw.line_doc()),
                         ("receipts", book.proof_receipts(w.window_start, w.height).into_iter().map(Signed::line_doc).collect::<Vec<_>>().into())]);
        if !lines.is_empty() {
            p["deferredSats"] = owed.into();
            p["deferred"] = lines.into();
        }
        if bounded {
            p["bounds"] = bounds.to_json();
        }
        p
    });
    let below_min_sats = if ok && covered < expected { expected - paid.saturating_add(owed) } else { 0 };
    Ok(AuditOutcome { ok, expected_sats: expected, paid_sats: paid, deferred_sats: owed, below_min_sats, proven_work: l, window_work: ww,
                      fee_bps: fee, min_payout: mp, bounded, proof })
}

/// Check a §10.4 fraud proof from its signed contents alone, given the Prime key, the block (from
/// the checker's own node: height, hash, `V` and what the coinbase paid the identity) and the
/// bounds of the Prime's published terms for that block. True when the proof convicts the Prime.
pub fn check_fraud_proof(proof: &Value, pk: &VerifyingKey, block: &ChainBlock, bounds: &AuditBounds) -> bool {
    (|| -> Option<bool> {
        let identity = proof.get("identity")?.as_str()?;
        let sw = SignedWindow::from_doc(proof.get("window")?).ok()?;
        if !sw.verify(pk) {
            return Some(false);
        }
        let w = &sw.stmt;
        if (w.height, w.block_hash.as_str()) != (block.height, block.hash.as_str()) {
            return Some(false);
        }
        let (ww, fee, mp, _) = bounds.apply(w);
        let mut receipts = vec![];
        for rc in proof.get("receipts")?.as_array()? {
            let r = WorkReceipt::parse_line(rc.get("message")?.as_str()?).ok()?;
            if !verify(pk, rc.get("message")?.as_str()?, &sig64(rc.get("sig")).ok()?) || r.identity != identity || r.prime_id != w.prime_id {
                return Some(false);
            }
            receipts.push(r);
        }
        let expected = expected_sats(block.value_sats, fee, receipts_bound(&receipts, w), ww).ok()?;
        // every deferral line the statement published for the identity counts with paid; a proof
        // that leaves one out is refuted by the Prime producing it
        let mut owed = 0u64;
        for dl in proof.get("deferred").and_then(Value::as_array).into_iter().flatten() {
            let sd = SignedDeferral::from_doc(dl).ok()?;
            let d = &sd.d;
            if !sd.verify(pk) || (d.prime_id, d.height, d.block_hash.as_str(), d.identity.as_str()) != (w.prime_id, w.height, w.block_hash.as_str(), identity) {
                return Some(false);
            }
            owed = owed.saturating_add(d.sats);
        }
        Some(proof.get("blockHash")?.as_str()? == w.block_hash && expected >= mp
             && block.paid_sats.saturating_add(owed).saturating_add(TOLERANCE) < expected)
    })().unwrap_or(false)
}

/// The carry a Prime owes the provider (§10.3): the sum of its signed deferral lines and of the
/// unpaid shares it excused as below `min_payout` (AGP-065), less what later coinbases paid above
/// `expected` (released carry). Treat it as unaudited credit (§13.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CarryLedger {
    pub deferred_total: u64,
    pub released_total: u64,
    /// (height, expected, paid, deferred) per audited block, in audit order.
    pub blocks: Vec<(u32, u64, u64, u64)>,
}

impl CarryLedger {
    /// Record a block's verdict. A block audited again replaces its earlier entry.
    pub fn record(&mut self, height: u32, o: &AuditOutcome) {
        let owed = o.deferred_sats.saturating_add(o.below_min_sats);
        let entry = (height, o.expected_sats, o.paid_sats, owed);
        self.forget(height);
        self.blocks.push(entry);
        self.deferred_total = self.deferred_total.saturating_add(owed);
        self.released_total = self.released_total.saturating_add(o.paid_sats.saturating_sub(o.expected_sats));
    }

    /// Drop a block's verdict (it was re-audited, or a reorg took it out of the chain).
    pub fn forget(&mut self, height: u32) {
        if let Some(i) = self.blocks.iter().position(|b| b.0 == height) {
            let (_, e, p, d) = self.blocks.remove(i);
            self.deferred_total = self.deferred_total.saturating_sub(d);
            self.released_total = self.released_total.saturating_sub(p.saturating_sub(e));
        }
    }

    /// Carry still owed.
    pub fn owed(&self) -> u64 {
        self.deferred_total.saturating_sub(self.released_total)
    }

    /// Whether owed carry grew over each of the last `n` audited blocks (with at least `n` blocks
    /// seen): the signal to stop accepting a Prime's receipts while the provider attests every tip.
    pub fn keeps_growing(&self, n: usize) -> bool {
        if n == 0 || self.blocks.len() < n {
            return false;
        }
        self.blocks[self.blocks.len() - n..].iter().all(|(_, e, p, d)| *d > p.saturating_sub(*e))
    }

    pub fn to_json(&self) -> Value {
        obj([("owedSats", self.owed().into()), ("deferredSats", self.deferred_total.into()), ("releasedSats", self.released_total.into())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    #[test]
    fn lines_round_trip_and_refuse_injection() {
        let w = WindowStatement { prime_id: 70, height: 1013, block_hash: "ab".repeat(32), window_start: 981, window_work: 8_000_000,
                                  min_payout: 546, fee_bps: 0 };
        assert_eq!(WindowStatement::parse(&w.message().unwrap()).unwrap(), w);
        let d = Deferral { prime_id: 70, height: 1013, block_hash: "ab".repeat(32), identity: P.into(), sats: 5, reason: "unattested".into() };
        assert_eq!(Deferral::parse(&d.message().unwrap()).unwrap(), d);
        assert!(Deferral { reason: "other".into(), ..d.clone() }.message().is_err());
        assert!(Deferral { identity: "a|b".into(), ..d.clone() }.message().is_err());
        assert!(WindowStatement::parse("xbt-work-window/1|70|1013|x|981|8|546|0").is_err());
        assert!(WindowStatement::parse(&w.message().unwrap().replace("|546|", "|0546|")).is_err());
    }

    #[test]
    fn carry_ledger() {
        let mut c = CarryLedger::default();
        let o = |e, p, d| AuditOutcome { ok: true, expected_sats: e, paid_sats: p, deferred_sats: d, below_min_sats: 0, proven_work: 0, window_work: 1,
                                         fee_bps: 0, min_payout: 0, bounded: false, proof: None };
        c.record(10, &o(100, 0, 100));
        c.record(11, &o(100, 0, 100));
        assert!(c.keeps_growing(2));
        c.record(12, &o(100, 250, 0));
        assert_eq!(c.owed(), 50);
        assert!(!c.keeps_growing(2));
        // auditing a block again replaces it
        c.record(12, &o(100, 300, 0));
        assert_eq!((c.owed(), c.blocks.len()), (0, 3));
        // an excused below-min share is owed like a deferral; a reorged block is forgotten
        c.record(13, &AuditOutcome { below_min_sats: 400, ..o(400, 0, 0) });
        assert_eq!(c.owed(), 400);
        c.forget(13);
        assert_eq!((c.owed(), c.blocks.len()), (0, 3));
    }

    #[test]
    fn terms_bound_the_window() {
        let t = PrimeTerms::default();
        // difficulty 1: target 8 work units, 5% slack rounds up to 9
        let b = |bits, prev_bits| ChainBlock { height: 2, hash: "00".repeat(32), value_sats: 0, paid_sats: 0, bits, prev_bits };
        assert_eq!(t.bounds(&b(0x1d00ffff, 0x1d00ffff)).unwrap().max_window_work, 9);
        // a retarget: the larger of the block's and the parent's difficulty
        assert_eq!(t.bounds(&b(0x1d00ffff, 0x1c7fff80)).unwrap().max_window_work, 17);
        // regtest: the floor
        let r = PrimeTerms { window_min_work: 64, ..t };
        assert_eq!(r.bounds(&b(0x207fffff, 0x207fffff)).unwrap().max_window_work, 68);
        assert!(PrimeTerms { fee_bps: 10_001, ..t }.bounds(&b(0x1d00ffff, 0x1d00ffff)).is_err());
        let w = WindowStatement { prime_id: 70, height: 2, block_hash: "00".repeat(32), window_start: 1, window_work: 100, min_payout: 1000, fee_bps: 30 };
        let bd = AuditBounds { max_window_work: 9, fee_bps: 0, max_min_payout: 546 };
        assert_eq!(bd.apply(&w), (9, 0, 546, true));
        assert_eq!(AuditBounds::STATEMENT_ONLY.apply(&w), (100, 30, 1000, false));
    }
}
