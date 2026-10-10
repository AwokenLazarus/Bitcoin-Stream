//! The provider's receipt book (spec §9.1 steps 6-8, §10.2): verifies receipts under the pinned
//! Prime key, credits only the increase over the best receipt it holds per invoice, keeps
//! conflicting receipts as an equivocation fraud proof, and remembers the height interval of every
//! credited increase for the coinbase audit. A port of receipts.py `Provider.accept`, rule for rule.
//!
//! §13.1 caps (AGP-043): with [`CreditCaps`] set, a receipt's increase is credited only as far as the
//! caps on *unaudited* credit allow, per invoice and in total. The rest is **held**: receipted by the
//! Prime, kept in the book, but not spendable. Each credited increase stays unaudited until a coinbase
//! audit that passes at a height above it ([`ReceiptBook::audited`]), which then credits held work
//! ([`ReceiptBook::release_held`]). The audit intervals record every receipted increase whether it is
//! credited or held: the Prime signed for all of it, so the audit bound never depends on the caps.
//! Without caps nothing is held and the book behaves exactly as the reference.
//!
//! AGP-065 (review P2): a pass releases only the credit its bound counted. Each receipted increase is
//! a [`Span`]; an audit at `H` with window start `ws` covers a span only when `ws < lo` and `hi < H`
//! (the spans `L_H` sums). A span with `lo ≤ ws` is **skipped**: the window moved past it, so no
//! audit will ever count it. Skipped credit is forgiven up to [`CreditCaps::skipped`] in total and
//! counts against `total` beyond that, for good. A reorg puts the spans an orphaned audit resolved
//! back to open ([`ReceiptBook::uncover`]).
use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use indexmap::IndexMap;
use serde_json::Value;
use xbt402::json::obj;

use crate::error::{fail, Result, WorkError};
use crate::receipt::{sig64, Signed, WorkReceipt};

/// Two receipts the Prime key signed that cannot both be true (§9.1 step 7, §10.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation {
    pub a: Signed,
    pub b: Signed,
    pub why: String,
}

impl Equivocation {
    pub fn to_json(&self) -> Value {
        obj([("why", self.why.clone().into()), ("a", self.a.line_doc()), ("b", self.b.line_doc())])
    }

    /// Anyone holding the Prime key can check it: both lines verify, name one (identity, invoice),
    /// and have one seq with different states or a cumulative state that fell as seq rose.
    pub fn check(&self, pubkey: &VerifyingKey) -> bool {
        let (a, b) = (&self.a.receipt, &self.b.receipt);
        if !self.a.verify(pubkey) || !self.b.verify(pubkey) || (a.prime_id, &a.identity, &a.invoice) != (b.prime_id, &b.identity, &b.invoice) {
            return false;
        }
        (a.seq == b.seq && a != b)
            || (a.seq < b.seq && (b.cum_work < a.cum_work || b.shares < a.shares || b.last_height < a.last_height))
            || (b.seq < a.seq && (a.cum_work < b.cum_work || a.shares < b.shares || a.last_height < b.last_height))
    }
}

/// A credited increase: `work` units whose shares all lie in heights `[lo, hi]` (§5.3 rule 2).
pub type Interval = (u32, u32, u64);

/// §13.1: limits on credit extended before an audit covers it, in work units. `None`: no limit.
/// Providers SHOULD set both to about one window's value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CreditCaps {
    /// Unaudited credit of one invoice.
    pub per_invoice: Option<u64>,
    /// Unaudited credit across all invoices.
    pub total: Option<u64>,
    /// Credit no audit can cover any more (skipped) that is forgiven, in total; skipped credit
    /// beyond it counts as unaudited (against `total`) for good. `u64::MAX`: all of it is
    /// forgiven, as AGP-043 did.
    pub skipped: u64,
}

impl CreditCaps {
    pub fn is_none(&self) -> bool {
        self.per_invoice.is_none() && self.total.is_none()
    }
}

/// Where a receipted increase stands with the audits; the height is the audited block that put it
/// there (a reorg of that block reopens it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    Open,
    Covered(u32),
    Skipped(u32),
}

/// One receipted increase of one invoice: `work` units in heights `[lo, hi]`, `credited` of them
/// turned into credit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub invoice: String,
    pub lo: u32,
    pub hi: u32,
    pub work: u64,
    pub credited: u64,
    pub coverage: Coverage,
}

/// One invoice's open credit, all open credit and the skipped credit, from which the caps' room
/// follows (kept current while [`ReceiptBook::credit`] walks the spans, so the walk is one pass).
struct Tally {
    open: u64,
    open_all: u64,
    skipped: u64,
}

impl Tally {
    fn unaudited_all(&self, caps: &CreditCaps) -> u64 {
        self.open_all.saturating_add(self.skipped.saturating_sub(caps.skipped))
    }

    fn total_room(&self, caps: &CreditCaps) -> u64 {
        caps.total.map_or(u64::MAX, |c| c.saturating_sub(self.unaudited_all(caps)))
    }

    fn room(&self, caps: &CreditCaps) -> u64 {
        caps.per_invoice.map_or(u64::MAX, |c| c.saturating_sub(self.open)).min(self.total_room(caps))
    }

    /// How much skipped work may still be credited.
    fn skipped_room(&self, caps: &CreditCaps) -> u64 {
        caps.skipped.saturating_sub(self.skipped).saturating_add(self.total_room(caps))
    }
}

/// The receipts a provider holds for one identity under one Prime key.
#[derive(Debug, Clone)]
pub struct ReceiptBook {
    pub identity: String,
    pub prime_pubkey: VerifyingKey,
    pub prime_id: u32,
    /// invoice -> the highest-seq receipt held (insertion order is kept: fraud proofs list them so).
    pub last: IndexMap<String, Signed>,
    by_seq: HashMap<(String, u64), Signed>,
    /// invoice -> cum_work already turned into credit.
    pub credited: HashMap<String, u64>,
    pub intervals: Vec<Interval>,
    pub fraud: Vec<Equivocation>,
    /// The receipted increases not yet settled ([`ReceiptBook::settle`]), in receipt order.
    pub spans: Vec<Span>,
    /// Skipped credit of spans already settled.
    pub settled_skipped: u64,
    /// The caps in force (configuration, not state).
    pub caps: CreditCaps,
    /// Set: no new credit at all (the carry rules of §10.3/§13.1), with the reason's short code.
    pub frozen: Option<String>,
}

impl ReceiptBook {
    pub fn new(identity: &str, prime_pubkey: VerifyingKey, prime_id: u32) -> Self {
        Self { identity: identity.into(), prime_pubkey, prime_id, last: IndexMap::new(), by_seq: HashMap::new(),
               credited: HashMap::new(), intervals: vec![], fraud: vec![], spans: vec![], settled_skipped: 0,
               caps: CreditCaps::default(), frozen: None }
    }

    fn open_credit(&self, invoice: Option<&str>) -> u64 {
        self.spans.iter().filter(|s| s.coverage == Coverage::Open && invoice.is_none_or(|v| v == s.invoice))
            .fold(0u64, |a, s| a.saturating_add(s.credited))
    }

    /// Credit no audit can cover any more.
    pub fn skipped_work(&self) -> u64 {
        self.spans.iter().filter(|s| matches!(s.coverage, Coverage::Skipped(_))).fold(self.settled_skipped, |a, s| a.saturating_add(s.credited))
    }

    /// Unaudited credit of `invoice` (None: across all invoices, with the skipped credit beyond
    /// [`CreditCaps::skipped`]).
    pub fn unaudited_work(&self, invoice: Option<&str>) -> u64 {
        match invoice {
            Some(_) => self.open_credit(invoice),
            None => self.open_credit(None).saturating_add(self.skipped_work().saturating_sub(self.caps.skipped)),
        }
    }

    /// Work the best receipt of `invoice` carries beyond what was credited (held by the caps).
    pub fn held(&self, invoice: &str) -> u64 {
        let best = self.last.get(invoice).map(|s| s.receipt.cum_work).unwrap_or(0);
        best.saturating_sub(self.credited.get(invoice).copied().unwrap_or(0))
    }

    /// Held work across all invoices.
    pub fn held_total(&self) -> u64 {
        self.last.keys().fold(0u64, |a, k| a.saturating_add(self.held(k)))
    }

    /// Whether any work was receipted for `invoice` (credited or held).
    pub fn funded(&self, invoice: &str) -> bool {
        self.last.get(invoice).is_some_and(|s| s.receipt.cum_work > 0) || self.credited.get(invoice).copied().unwrap_or(0) > 0
    }

    /// How much more `invoice` may be credited now.
    pub fn room(&self, invoice: &str) -> u64 {
        if self.frozen.is_some() {
            return 0;
        }
        self.tally(invoice).room(&self.caps)
    }

    fn tally(&self, invoice: &str) -> Tally {
        Tally { open: self.open_credit(Some(invoice)), open_all: self.open_credit(None), skipped: self.skipped_work() }
    }

    /// The coinbase at `height` was audited under a statement with window start `window_start`: the
    /// open spans with `lo ≤ window_start` are skipped, and if it `passed`, the open spans its bound
    /// counted (`window_start < lo`, `hi < height`) are covered. Returns the credit covered.
    pub fn audited(&mut self, height: u32, window_start: u32, passed: bool) -> u64 {
        let mut covered = 0u64;
        for s in self.spans.iter_mut().filter(|s| s.coverage == Coverage::Open) {
            if s.lo <= window_start {
                s.coverage = Coverage::Skipped(height);
            } else if passed && s.hi < height {
                s.coverage = Coverage::Covered(height);
                covered = covered.saturating_add(s.credited);
            }
        }
        covered
    }

    /// The audited block at `height` left the chain: the spans its audit resolved are open again.
    /// Returns the credit that is unaudited again.
    pub fn uncover(&mut self, height: u32) -> u64 {
        let mut back = 0u64;
        for s in self.spans.iter_mut().filter(|s| matches!(s.coverage, Coverage::Covered(h) | Coverage::Skipped(h) if h == height)) {
            s.coverage = Coverage::Open;
            back = back.saturating_add(s.credited);
        }
        back
    }

    /// Forget what no reorg will reopen: fully credited spans an audit at or below `height`
    /// resolved, the receipts (other than the best) and intervals at or below `window_start`, which
    /// no later window counts. Call it with an audited block deeper than any expected reorg.
    pub fn settle(&mut self, height: u32, window_start: u32) {
        let mut skipped = 0u64;
        self.spans.retain(|s| {
            let done = s.credited == s.work && matches!(s.coverage, Coverage::Covered(h) | Coverage::Skipped(h) if h <= height);
            if done && matches!(s.coverage, Coverage::Skipped(_)) {
                skipped = skipped.saturating_add(s.credited);
            }
            !done
        });
        self.settled_skipped = self.settled_skipped.saturating_add(skipped);
        let last = &self.last;
        self.by_seq.retain(|(inv, seq), s| s.receipt.first_height > window_start || last.get(inv).is_some_and(|l| l.receipt.seq == *seq));
        self.intervals.retain(|(lo, _, _)| *lo > window_start);
    }

    /// Credit `invoice`'s held work as far as the caps allow; returns the work credited. Covered
    /// spans are credited in full, open ones within [`ReceiptBook::room`], skipped ones within the
    /// skipped allowance.
    fn credit(&mut self, invoice: &str) -> u64 {
        if self.frozen.is_some() {
            return 0;
        }
        let mut t = self.tally(invoice);
        let mut granted = 0u64;
        for s in self.spans.iter_mut().filter(|s| s.invoice == invoice) {
            let want = s.work.saturating_sub(s.credited);
            let g = match s.coverage {
                Coverage::Covered(_) => want,
                Coverage::Open => want.min(t.room(&self.caps)),
                Coverage::Skipped(_) => want.min(t.skipped_room(&self.caps)),
            };
            match s.coverage {
                Coverage::Open => {
                    t.open = t.open.saturating_add(g);
                    t.open_all = t.open_all.saturating_add(g);
                }
                Coverage::Skipped(_) => t.skipped = t.skipped.saturating_add(g),
                Coverage::Covered(_) => {}
            }
            s.credited += g;
            granted = granted.saturating_add(g);
        }
        if granted > 0 {
            let c = self.credited.entry(invoice.to_string()).or_insert(0);
            *c = c.saturating_add(granted);
        }
        granted
    }

    /// Credit whatever the caps now allow of every invoice's held work: (invoice, credited).
    pub fn release_held(&mut self) -> Vec<(String, u64)> {
        let invs: Vec<String> = self.last.keys().filter(|k| self.held(k) > 0).cloned().collect();
        invs.into_iter().map(|k| {
            let g = self.credit(&k);
            (k, g)
        }).filter(|(_, g)| *g > 0).collect()
    }

    /// Verify a receipt presented for `invoice`; return the newly credited work (0 for a replay).
    pub fn accept(&mut self, s: &Signed, invoice: &str) -> Result<u64> {
        let r = &s.receipt;
        if r.identity != self.identity {
            return fail("wrong_identity", "receipt pays another identity");
        }
        if r.prime_id != self.prime_id {
            return fail("wrong_prime", "");
        }
        if r.invoice != invoice {
            return fail("wrong_invoice", "receipt is for another invoice");
        }
        if !s.verify(&self.prime_pubkey) {
            return fail("bad_sig", "not signed by the pinned Prime key");
        }
        let key = (invoice.to_string(), r.seq);
        if let Some(twin) = self.by_seq.get(&key) {
            if twin.receipt != *r {
                self.fraud.push(Equivocation { a: twin.clone(), b: s.clone(), why: "equivocation: two receipts, one seq".into() });
                return fail("equivocation", "two receipts with one seq");
            }
        }
        self.by_seq.insert(key, s.clone());
        let prev = self.last.get(invoice).cloned();
        if let Some(prev) = &prev {
            let p = &prev.receipt;
            if r.seq > p.seq && (r.cum_work < p.cum_work || r.shares < p.shares || r.last_height < p.last_height) {
                self.fraud.push(Equivocation { a: prev.clone(), b: s.clone(), why: "cumulative state went backwards".into() });
                return fail("equivocation", "cumulative state went backwards");
            }
            if r.seq < p.seq && (r.cum_work > p.cum_work || r.shares > p.shares) {
                self.fraud.push(Equivocation { a: s.clone(), b: prev.clone(), why: "cumulative state went backwards".into() });
                return fail("equivocation", "cumulative state went backwards");
            }
            if r.seq < p.seq {
                return Ok(0);
            }
            if r.seq == p.seq {
                // the receipt held already (a replay): credits only work the caps held back
                return Ok(self.credit(invoice));
            }
        }
        if r.seq == 0 {
            return Ok(0);
        }
        // the audit interval: all the work this receipt adds, credited or held
        let lo = match &prev {
            Some(p) if p.receipt.seq != 0 => p.receipt.last_height,
            _ => r.first_height,
        };
        let added = r.cum_work.saturating_sub(prev.as_ref().map_or(0, |p| p.receipt.cum_work));
        if added > 0 {
            self.intervals.push((lo, r.last_height, added));
            self.spans.push(Span { invoice: invoice.to_string(), lo, hi: r.last_height, work: added, credited: 0, coverage: Coverage::Open });
        }
        self.last.insert(invoice.to_string(), s.clone());
        Ok(self.credit(invoice))
    }

    /// The receipts a §10.4 fraud proof for the block at `height` carries: per invoice, the latest
    /// receipt held and, when its span does not lie inside `(window_start, height)`, the held
    /// receipt of that invoice with the most work whose span does (the one that brackets the
    /// window), placed before it. A third party can only count whole in-span receipts.
    pub fn proof_receipts(&self, window_start: u32, height: u32) -> Vec<&Signed> {
        let inside = |s: &Signed| s.receipt.first_height > window_start && s.receipt.last_height < height;
        let mut out = vec![];
        for (inv, last) in &self.last {
            if !inside(last) {
                let best = self.by_seq.iter().filter(|((i, _), s)| i == inv && inside(s)).map(|(_, s)| s)
                    .max_by_key(|s| (s.receipt.cum_work, s.receipt.seq));
                out.extend(best);
            }
            out.push(last);
        }
        out
    }

    /// The best receipt held for `invoice`.
    pub fn best(&self, invoice: &str) -> Option<&Signed> {
        self.last.get(invoice)
    }

    /// Everything a restart needs (the receipts are signed, so reloading re-verifies them).
    pub fn to_json(&self) -> Value {
        let last: Vec<Value> = self.last.values().map(Signed::to_doc).collect();
        let iv: Vec<Value> = self.intervals.iter().map(|(lo, hi, w)| Value::from(vec![Value::from(*lo), Value::from(*hi), Value::from(*w)])).collect();
        let cr: serde_json::Map<String, Value> = self.last.keys().map(|k| (k.clone(), self.credited.get(k).copied().unwrap_or(0).into())).collect();
        let sp: Vec<Value> = self.spans.iter().map(|s| {
            let (state, h) = match s.coverage { Coverage::Open => ("open", 0), Coverage::Covered(h) => ("covered", h), Coverage::Skipped(h) => ("skipped", h) };
            Value::from(vec![Value::from(s.invoice.clone()), s.lo.into(), s.hi.into(), s.work.into(), s.credited.into(), state.into(), h.into()])
        }).collect();
        let mut held: Vec<&Signed> = self.by_seq.values().filter(|s| self.last.get(&s.receipt.invoice).is_none_or(|l| l.receipt.seq != s.receipt.seq)).collect();
        held.sort_by(|a, b| (&a.receipt.invoice, a.receipt.seq).cmp(&(&b.receipt.invoice, b.receipt.seq)));
        obj([("last", last.into()), ("credited", Value::Object(cr)), ("intervals", iv.into()),
             ("fraud", self.fraud.iter().map(Equivocation::to_json).collect::<Vec<_>>().into()),
             ("spans", sp.into()), ("settledSkipped", self.settled_skipped.into()),
             ("receipts", held.into_iter().map(Signed::line_doc).collect::<Vec<_>>().into())])
    }

    /// Restore [`ReceiptBook::to_json`]. Every held receipt must still verify.
    pub fn load(&mut self, v: &Value) -> Result<()> {
        let bad = |w: &str| WorkError::new("bad_state", w.to_string());
        for d in v.get("last").and_then(Value::as_array).into_iter().flatten() {
            let s = Signed::from_doc(d).map_err(|e| bad(&e.0))?;
            if !s.verify(&self.prime_pubkey) || s.receipt.identity != self.identity {
                return Err(bad("held receipt does not verify"));
            }
            self.by_seq.insert((s.receipt.invoice.clone(), s.receipt.seq), s.clone());
            self.last.insert(s.receipt.invoice.clone(), s);
        }
        for (k, c) in v.get("credited").and_then(Value::as_object).into_iter().flatten() {
            self.credited.insert(k.clone(), c.as_u64().ok_or_else(|| bad("credited"))?);
        }
        for i in v.get("intervals").and_then(Value::as_array).into_iter().flatten() {
            let f = |j: usize| i.get(j).and_then(Value::as_u64).ok_or_else(|| bad("interval"));
            self.intervals.push((f(0)? as u32, f(1)? as u32, f(2)?));
        }
        let n32 = |x: u64, w: &str| u32::try_from(x).map_err(|_| bad(w));
        for d in v.get("receipts").and_then(Value::as_array).into_iter().flatten() {
            let msg = d.get("message").and_then(Value::as_str).ok_or_else(|| bad("receipt"))?;
            let s = Signed { receipt: WorkReceipt::parse_line(msg).map_err(|e| bad(&e.0))?, sig: sig64(d.get("sig")).map_err(|e| bad(&e.0))? };
            if !s.verify(&self.prime_pubkey) || s.receipt.identity != self.identity {
                return Err(bad("held receipt does not verify"));
            }
            self.by_seq.insert((s.receipt.invoice.clone(), s.receipt.seq), s);
        }
        if let Some(spans) = v.get("spans") {
            for s in spans.as_array().ok_or_else(|| bad("spans"))? {
                let f = |j: usize| s.get(j).and_then(Value::as_u64).ok_or_else(|| bad("span"));
                let h = n32(f(6)?, "span")?;
                let coverage = match s.get(5).and_then(Value::as_str) {
                    Some("open") => Coverage::Open,
                    Some("covered") => Coverage::Covered(h),
                    Some("skipped") => Coverage::Skipped(h),
                    _ => return Err(bad("span")),
                };
                let invoice = s.get(0).and_then(Value::as_str).ok_or_else(|| bad("span"))?.to_string();
                self.spans.push(Span { invoice, lo: n32(f(1)?, "span")?, hi: n32(f(2)?, "span")?, work: f(3)?, credited: f(4)?, coverage });
            }
            self.settled_skipped = v.get("settledSkipped").and_then(Value::as_u64).ok_or_else(|| bad("settledSkipped"))?;
        } else {
            // AGP-043 state: per invoice, what no pass covered (`unaudited`) stays open over the
            // best receipt's span, the rest of its credit counts as covered
            let mut open: HashMap<String, u64> = HashMap::new();
            for u in v.get("unaudited").and_then(Value::as_array).into_iter().flatten() {
                let inv = u.get(0).and_then(Value::as_str).ok_or_else(|| bad("unaudited"))?;
                let w = u.get(2).and_then(Value::as_u64).ok_or_else(|| bad("unaudited"))?;
                *open.entry(inv.to_string()).or_insert(0) += w;
            }
            for (inv, best) in &self.last {
                let (lo, hi, cum) = (best.receipt.first_height, best.receipt.last_height, best.receipt.cum_work);
                let credited = self.credited.get(inv).copied().unwrap_or(0).min(cum);
                let unaudited = open.get(inv).copied().unwrap_or(0).min(credited);
                let span = |work, credited, coverage| Span { invoice: inv.clone(), lo, hi, work, credited, coverage };
                if credited > unaudited {
                    self.spans.push(span(credited - unaudited, credited - unaudited, Coverage::Covered(0)));
                }
                if cum > credited - unaudited {
                    self.spans.push(span(cum - (credited - unaudited), unaudited, Coverage::Open));
                }
            }
        }
        for e in v.get("fraud").and_then(Value::as_array).into_iter().flatten() {
            let line = |k: &str| -> Result<Signed> {
                let d = e.get(k).ok_or_else(|| bad("fraud"))?;
                let r = WorkReceipt::parse_line(d.get("message").and_then(Value::as_str).unwrap_or("")).map_err(|e| bad(&e.0))?;
                Ok(Signed { receipt: r, sig: sig64(d.get("sig")).map_err(|e| bad(&e.0))? })
            };
            self.fraud.push(Equivocation { a: line("a")?, b: line("b")?, why: e.get("why").and_then(Value::as_str).unwrap_or("").into() });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::PrimeKey;

    const P: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const I: &str = "vfer2e5e75t4tv7in42lakx6i4";

    fn r(seq: u64, cum: u64, first: u32, last: u32) -> WorkReceipt {
        WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 4, ..WorkReceipt::zero(70, P, I) }
    }

    #[test]
    fn deltas_replays_equivocation_and_reload() {
        let k = PrimeKey::from_seed(70, &[1u8; 32]);
        let mut b = ReceiptBook::new(P, k.pubkey(), 70);
        assert_eq!(b.accept(&k.sign(&r(3, 12, 101, 102)).unwrap(), I).unwrap(), 12);
        assert_eq!(b.accept(&k.sign(&r(7, 28, 101, 104)).unwrap(), I).unwrap(), 16);
        assert_eq!(b.accept(&k.sign(&r(3, 12, 101, 102)).unwrap(), I).unwrap(), 0);
        assert_eq!(b.intervals, vec![(101, 102, 12), (102, 104, 16)]);
        let e = b.accept(&k.sign(&r(7, 56, 101, 104)).unwrap(), I).unwrap_err();
        assert_eq!(e.code, "equivocation");
        assert!(b.fraud[0].check(&k.pubkey()));
        let e = b.accept(&k.sign(&r(9, 20, 101, 105)).unwrap(), I).unwrap_err();
        assert_eq!(e.code, "equivocation");
        assert!(b.fraud[1].check(&k.pubkey()));
        let other = PrimeKey::from_seed(70, &[2u8; 32]);
        assert_eq!(b.accept(&other.sign(&r(8, 40, 101, 105)).unwrap(), I).unwrap_err().code, "bad_sig");
        let mut c = ReceiptBook::new(P, k.pubkey(), 70);
        c.load(&b.to_json()).unwrap();
        assert_eq!((c.intervals.clone(), c.credited.clone(), c.fraud.len()), (b.intervals.clone(), b.credited.clone(), 2));
        assert_eq!(c.accept(&k.sign(&r(8, 30, 101, 105)).unwrap(), I).unwrap(), 2);
    }

    const J: &str = "vfer2e5e75t4tv7in42lakx6i5";

    fn rj(seq: u64, cum: u64, first: u32, last: u32) -> WorkReceipt {
        WorkReceipt { invoice: J.into(), ..r(seq, cum, first, last) }
    }

    #[test]
    fn caps_hold_unaudited_credit_until_an_audit_passes() {
        let k = PrimeKey::from_seed(70, &[1u8; 32]);
        let mut b = ReceiptBook::new(P, k.pubkey(), 70);
        b.caps = CreditCaps { per_invoice: Some(20), total: Some(30), skipped: 0 };
        // invoice I: 12 fits, then 16 more of which only 8 fit under the per-invoice cap
        assert_eq!(b.accept(&k.sign(&r(3, 12, 101, 102)).unwrap(), I).unwrap(), 12);
        let s7 = k.sign(&r(7, 28, 101, 104)).unwrap();
        assert_eq!(b.accept(&s7, I).unwrap(), 8);
        assert_eq!((b.credited[I], b.held(I), b.unaudited_work(Some(I))), (20, 8, 20));
        // a replay credits nothing more while the cap is full
        assert_eq!(b.accept(&s7, I).unwrap(), 0);
        // invoice J: the total cap (30) leaves room for 10 of its 15
        assert_eq!(b.accept(&k.sign(&rj(2, 15, 103, 104)).unwrap(), J).unwrap(), 10);
        assert_eq!((b.unaudited_work(None), b.held_total(), b.room(J)), (30, 13, 0));
        assert!(b.funded(J));
        // the audit intervals hold all the receipted work, credited or not
        assert_eq!(b.intervals, vec![(101, 102, 12), (102, 104, 16), (103, 104, 15)]);
        // an audit at 104 covers only the credits whose shares are all below it
        assert_eq!(b.audited(104, 100, true), 12);
        assert_eq!(b.unaudited_work(None), 18);
        // a later receipt of I: 12 more receipted; room for 12 under the invoice cap, 8 stay held
        assert_eq!(b.accept(&k.sign(&r(9, 40, 101, 106)).unwrap(), I).unwrap(), 12);
        assert_eq!(*b.intervals.last().unwrap(), (104, 106, 12));
        assert_eq!(b.held(I), 8);
        // everything below 107 audited: held work flows again, as far as the caps allow
        b.audited(107, 100, true);
        assert_eq!(b.release_held(), vec![(I.to_string(), 8), (J.to_string(), 5)]);
        assert_eq!((b.held_total(), b.credited[I], b.credited[J]), (0, 40, 15));
        // frozen (the carry rules): no new credit at all
        b.frozen = Some("carry_cap".into());
        assert_eq!(b.accept(&k.sign(&r(10, 44, 101, 107)).unwrap(), I).unwrap(), 0);
        assert_eq!(b.held(I), 4);
        // state round trip keeps held and unaudited work
        let mut c = ReceiptBook::new(P, k.pubkey(), 70);
        c.load(&b.to_json()).unwrap();
        assert_eq!((c.spans.clone(), c.held(I), c.credited[I]), (b.spans.clone(), 4, 40));
        assert_eq!(c.accept(&k.sign(&r(10, 44, 101, 107)).unwrap(), I).unwrap(), 4);
        assert_eq!(c.intervals, b.intervals);
    }

    /// review P2: a pass releases only what its bound counted; the rest is skipped, forgiven up to the
    /// allowance, and a reorg reopens what an orphaned audit resolved.
    #[test]
    fn a_pass_covers_only_the_spans_its_bound_counts() {
        let k = PrimeKey::from_seed(70, &[1u8; 32]);
        let mut b = ReceiptBook::new(P, k.pubkey(), 70);
        b.caps = CreditCaps { per_invoice: Some(100), total: Some(100), skipped: 10 };
        assert_eq!(b.accept(&k.sign(&r(1, 30, 101, 103)).unwrap(), I).unwrap(), 30);
        assert_eq!(b.accept(&k.sign(&r(2, 50, 101, 106)).unwrap(), I).unwrap(), 20);
        // the window starts at 102: span (101, 103) is outside it, (103, 106) is not below 106
        assert_eq!(b.audited(106, 102, true), 0);
        assert_eq!(b.spans.iter().map(|s| s.coverage).collect::<Vec<_>>(), vec![Coverage::Skipped(106), Coverage::Open]);
        // 30 skipped, 10 forgiven: 20 still count against the total, with the 20 open
        assert_eq!((b.skipped_work(), b.unaudited_work(None), b.unaudited_work(Some(I))), (30, 40, 20));
        assert_eq!(b.audited(107, 102, true), 20);
        assert_eq!(b.unaudited_work(None), 20);
        // the block at 107 is orphaned: its span is open again
        assert_eq!(b.uncover(107), 20);
        assert_eq!(b.unaudited_work(None), 40);
        assert_eq!(b.audited(107, 102, true), 20);
        // settled: forgotten, the skipped credit kept as a total; the best receipt stays
        b.settle(107, 103);
        assert!(b.spans.is_empty());
        assert_eq!((b.skipped_work(), b.unaudited_work(None), b.intervals.len()), (30, 20, 0));
        let mut c = ReceiptBook::new(P, k.pubkey(), 70);
        c.caps = b.caps;
        c.load(&b.to_json()).unwrap();
        assert_eq!((c.skipped_work(), c.unaudited_work(None), c.best(I).map(|s| s.receipt.seq)), (30, 20, Some(2)));
    }

    #[test]
    fn earlier_receipts_survive_a_restart_and_agp043_state_migrates() {
        let k = PrimeKey::from_seed(70, &[1u8; 32]);
        let mut b = ReceiptBook::new(P, k.pubkey(), 70);
        b.accept(&k.sign(&r(3, 12, 101, 102)).unwrap(), I).unwrap();
        b.accept(&k.sign(&r(7, 28, 101, 104)).unwrap(), I).unwrap();
        let mut c = ReceiptBook::new(P, k.pubkey(), 70);
        c.load(&b.to_json()).unwrap();
        // the seq-3 twin is still known after the restart
        assert_eq!(c.accept(&k.sign(&r(3, 13, 101, 102)).unwrap(), I).unwrap_err().code, "equivocation");
        assert_eq!(c.proof_receipts(100, 104).len(), 2);
        // AGP-043 state: credited 28 of which 8 unaudited
        let mut v = b.to_json();
        v.as_object_mut().unwrap().remove("spans");
        v["unaudited"] = serde_json::json!([[I, 104, 8]]);
        let mut d = ReceiptBook::new(P, k.pubkey(), 70);
        d.load(&v).unwrap();
        assert_eq!((d.unaudited_work(None), d.held(I)), (8, 0));
    }

    #[test]
    fn no_caps_is_the_reference_behaviour() {
        let k = PrimeKey::from_seed(70, &[1u8; 32]);
        let (mut a, mut b) = (ReceiptBook::new(P, k.pubkey(), 70), ReceiptBook::new(P, k.pubkey(), 70));
        b.caps = CreditCaps { per_invoice: Some(u64::MAX), total: None, skipped: 0 };
        for (seq, cum, lo, hi) in [(1, 4, 101, 101), (1, 4, 101, 101), (4, 9, 101, 103), (2, 5, 101, 102), (6, 30, 101, 110)] {
            let s = k.sign(&r(seq, cum, lo, hi)).unwrap();
            assert_eq!(a.accept(&s, I).ok(), b.accept(&s, I).ok());
        }
        assert_eq!((a.intervals.clone(), a.credited.clone(), a.held_total()), (b.intervals.clone(), b.credited.clone(), 0));
    }
}
