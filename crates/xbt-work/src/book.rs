//! The provider's receipt book (spec §9.1 steps 6-8, §10.2): verifies receipts under the pinned
//! Prime key, credits only the increase over the best receipt it holds per invoice, keeps
//! conflicting receipts as an equivocation fraud proof, and remembers the height interval of every
//! credited increase for the coinbase audit. A port of receipts.py `Provider.accept`, rule for rule.
//!
//! §13.1 caps (AGP-043): with [`CreditCaps`] set, a receipt's increase is credited only as far as the
//! caps on *unaudited* credit allow, per invoice and in total. The rest is **held**: receipted by the
//! Prime, kept in the book, but not spendable, and credited once the caps have room again
//! ([`ReceiptBook::release_held`]). The audit intervals record every receipted increase whether it is
//! credited or held: the Prime signed for all of it, so the audit bound never depends on the caps.
//! Without caps nothing is held and the book behaves exactly as the reference.
//!
//! AGP-079 (closure audit, P1): credit leaves the caps only as far as coinbases paid for it. The
//! provider's audit turns what a pool block's coinbase paid the identity (read from its own node)
//! into work units at its own price and records it here ([`ReceiptBook::pay`]). Credit is kept in
//! the order it was granted ([`ReceiptBook::credits`]) and the paid-for work covers the oldest
//! first; what is left is the unaudited credit the caps count. No number a Prime signs (a window
//! start, a deferral line, `min_payout`, whether a block has a statement at all) moves it. A reorg
//! takes the block's payment out again ([`ReceiptBook::uncover`]). This replaces the AGP-065 spans
//! (`Open`, `Covered`, `Skipped`), under which one passing audit released everything its bound
//! counted, whatever the coinbase paid.
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
}

impl CreditCaps {
    pub fn is_none(&self) -> bool {
        self.per_invoice.is_none() && self.total.is_none()
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
    /// Credit not yet settled ([`ReceiptBook::settle`]), in the order it was granted: (invoice,
    /// work). Paid-for work covers the oldest first.
    pub credits: Vec<(String, u64)>,
    /// Work the coinbase of each audited block paid for, (height, work), lowest height first.
    pub cover: Vec<(u32, u64)>,
    /// Paid-for work of settled blocks that no credit has used yet.
    pub cover_settled: u64,
    /// Payments of blocks at or below this height are settled and final: auditing such a block
    /// again never counts its payment a second time.
    pub settled_through: u32,
    /// The caps in force (configuration, not state).
    pub caps: CreditCaps,
    /// Set: no new credit at all (the carry rules of §10.3/§13.1), with the reason's short code.
    pub frozen: Option<String>,
}

impl ReceiptBook {
    pub fn new(identity: &str, prime_pubkey: VerifyingKey, prime_id: u32) -> Self {
        Self { identity: identity.into(), prime_pubkey, prime_id, last: IndexMap::new(), by_seq: HashMap::new(),
               credited: HashMap::new(), intervals: vec![], fraud: vec![], credits: vec![], cover: vec![], cover_settled: 0, settled_through: 0,
               caps: CreditCaps::default(), frozen: None }
    }

    /// Work the audited coinbases paid for.
    pub fn paid_work(&self) -> u128 {
        self.cover.iter().fold(u128::from(self.cover_settled), |a, (_, w)| a + u128::from(*w))
    }

    fn granted(&self) -> u128 {
        self.credits.iter().fold(0u128, |a, (_, w)| a + u128::from(*w))
    }

    /// Credit no coinbase has paid for yet: of `invoice`, or across all invoices (None). Payments
    /// cover the oldest credit first, so the unpaid credit is the newest.
    pub fn unaudited_work(&self, invoice: Option<&str>) -> u64 {
        let unpaid = u64::try_from(self.granted().saturating_sub(self.paid_work())).unwrap_or(u64::MAX);
        let Some(invoice) = invoice else { return unpaid };
        let (mut left, mut mine) = (unpaid, 0u64);
        for (inv, w) in self.credits.iter().rev() {
            if left == 0 {
                break;
            }
            let part = (*w).min(left);
            if inv == invoice {
                mine = mine.saturating_add(part);
            }
            left -= part;
        }
        mine
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

    /// How much more `invoice` may be credited now: paid-for work no credit has used, plus what
    /// the caps leave.
    pub fn room(&self, invoice: &str) -> u64 {
        if self.frozen.is_some() {
            return 0;
        }
        let surplus = u64::try_from(self.paid_work().saturating_sub(self.granted())).unwrap_or(u64::MAX);
        let per_invoice = self.caps.per_invoice.map_or(u64::MAX, |c| c.saturating_sub(self.unaudited_work(Some(invoice))));
        let total = self.caps.total.map_or(u64::MAX, |c| c.saturating_sub(self.unaudited_work(None)));
        surplus.saturating_add(per_invoice.min(total))
    }

    /// The coinbase at `height` passed its audit and paid for `work` units (0: it paid for none, or
    /// failed). Replaces what was recorded for that height; a block at or below
    /// [`ReceiptBook::settled_through`] is settled and changes nothing. Returns the credit it newly covers.
    pub fn pay(&mut self, height: u32, work: u64) -> u64 {
        if height <= self.settled_through {
            return 0;
        }
        let before = self.unaudited_work(None);
        self.cover.retain(|(h, _)| *h != height);
        if work > 0 {
            let at = self.cover.partition_point(|(h, _)| *h < height);
            self.cover.insert(at, (height, work));
        }
        before.saturating_sub(self.unaudited_work(None))
    }

    /// The audited block at `height` left the chain: what its coinbase paid for no longer counts.
    /// Returns the credit that is unaudited again.
    pub fn uncover(&mut self, height: u32) -> u64 {
        let before = self.unaudited_work(None);
        self.cover.retain(|(h, _)| *h != height);
        self.unaudited_work(None).saturating_sub(before)
    }

    /// Forget what no reorg will reopen: the payments of blocks at or below `height` and the
    /// oldest credit they cover, and the receipts (other than the best) and intervals at or below
    /// `window_start`, which no later window counts. Call it with an audited block deeper than any
    /// expected reorg. Unpaid credit is never forgotten.
    pub fn settle(&mut self, height: u32, window_start: u32) {
        self.settled_through = self.settled_through.max(height);
        let mut deep = u128::from(self.cover_settled);
        self.cover.retain(|(h, w)| {
            let settled = *h <= height;
            if settled {
                deep += u128::from(*w);
            }
            !settled
        });
        let mut done = 0;
        for (_, w) in self.credits.iter_mut() {
            let part = u128::from(*w).min(deep);
            deep -= part;
            // part <= *w, a u64
            *w -= part as u64;
            if *w > 0 {
                break;
            }
            done += 1;
        }
        self.credits.drain(..done);
        self.cover_settled = u64::try_from(deep).unwrap_or(u64::MAX);
        let last = &self.last;
        self.by_seq.retain(|(inv, seq), s| s.receipt.first_height > window_start || last.get(inv).is_some_and(|l| l.receipt.seq == *seq));
        self.intervals.retain(|(lo, _, _)| *lo > window_start);
    }

    /// Credit `invoice`'s held work as far as [`ReceiptBook::room`] allows; returns the work credited.
    fn credit(&mut self, invoice: &str) -> u64 {
        let granted = self.held(invoice).min(self.room(invoice));
        if granted == 0 {
            return 0;
        }
        match self.credits.last_mut() {
            Some((inv, w)) if inv == invoice => *w = w.saturating_add(granted),
            _ => self.credits.push((invoice.to_string(), granted)),
        }
        let c = self.credited.entry(invoice.to_string()).or_insert(0);
        *c = c.saturating_add(granted);
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
        let credits: Vec<Value> = self.credits.iter().map(|(inv, w)| Value::from(vec![Value::from(inv.clone()), Value::from(*w)])).collect();
        let cover: Vec<Value> = self.cover.iter().map(|(h, w)| Value::from(vec![Value::from(*h), Value::from(*w)])).collect();
        let mut held: Vec<&Signed> = self.by_seq.values().filter(|s| self.last.get(&s.receipt.invoice).is_none_or(|l| l.receipt.seq != s.receipt.seq)).collect();
        held.sort_by(|a, b| (&a.receipt.invoice, a.receipt.seq).cmp(&(&b.receipt.invoice, b.receipt.seq)));
        obj([("last", last.into()), ("credited", Value::Object(cr)), ("intervals", iv.into()),
             ("fraud", self.fraud.iter().map(Equivocation::to_json).collect::<Vec<_>>().into()),
             ("credits", credits.into()), ("cover", cover.into()), ("coverSettled", self.cover_settled.into()),
             ("settledThrough", self.settled_through.into()),
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
        if let Some(credits) = v.get("credits") {
            for c in credits.as_array().ok_or_else(|| bad("credits"))? {
                let inv = c.get(0).and_then(Value::as_str).ok_or_else(|| bad("credit"))?;
                self.credits.push((inv.to_string(), c.get(1).and_then(Value::as_u64).ok_or_else(|| bad("credit"))?));
            }
            for c in v.get("cover").and_then(Value::as_array).ok_or_else(|| bad("cover"))? {
                let f = |j: usize| c.get(j).and_then(Value::as_u64).ok_or_else(|| bad("cover"));
                self.cover.push((n32(f(0)?, "cover")?, f(1)?));
            }
            self.cover.sort_by_key(|(h, _)| *h);
            self.cover_settled = v.get("coverSettled").and_then(Value::as_u64).ok_or_else(|| bad("coverSettled"))?;
            self.settled_through = n32(v.get("settledThrough").and_then(Value::as_u64).ok_or_else(|| bad("settledThrough"))?, "settledThrough")?;
        } else if let Some(spans) = v.get("spans") {
            // AGP-065 state: what an audit covered counts as paid for and is settled; open and
            // skipped credit (none of it forgiven any more) is unpaid, the settled skipped first
            let settled = v.get("settledSkipped").and_then(Value::as_u64).ok_or_else(|| bad("settledSkipped"))?;
            if settled > 0 {
                self.credits.push((String::new(), settled));
            }
            for s in spans.as_array().ok_or_else(|| bad("spans"))? {
                let invoice = s.get(0).and_then(Value::as_str).ok_or_else(|| bad("span"))?;
                let credited = s.get(4).and_then(Value::as_u64).ok_or_else(|| bad("span"))?;
                match s.get(5).and_then(Value::as_str) {
                    Some("covered") => {}
                    Some("open" | "skipped") if credited > 0 => self.credits.push((invoice.to_string(), credited)),
                    Some("open" | "skipped") => {}
                    _ => return Err(bad("span")),
                }
            }
        } else {
            // AGP-043 state: per invoice, what no pass covered (`unaudited`) is unpaid
            for u in v.get("unaudited").and_then(Value::as_array).into_iter().flatten() {
                let inv = u.get(0).and_then(Value::as_str).ok_or_else(|| bad("unaudited"))?;
                let w = u.get(2).and_then(Value::as_u64).ok_or_else(|| bad("unaudited"))?;
                let w = w.min(self.credited.get(inv).copied().unwrap_or(0));
                if w > 0 {
                    self.credits.push((inv.to_string(), w));
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
    fn caps_hold_unpaid_credit_until_a_coinbase_pays_for_it() {
        let k = PrimeKey::from_seed(70, &[1u8; 32]);
        let mut b = ReceiptBook::new(P, k.pubkey(), 70);
        b.caps = CreditCaps { per_invoice: Some(20), total: Some(30) };
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
        // the coinbase at 104 paid for 12 units: they cover the oldest credit, I's
        assert_eq!(b.pay(104, 12), 12);
        assert_eq!((b.unaudited_work(None), b.unaudited_work(Some(I)), b.unaudited_work(Some(J))), (18, 8, 10));
        // a later receipt of I: 12 more receipted; room for 12 under both caps, 8 stay held
        assert_eq!(b.accept(&k.sign(&r(9, 40, 101, 106)).unwrap(), I).unwrap(), 12);
        assert_eq!(*b.intervals.last().unwrap(), (104, 106, 12));
        assert_eq!(b.held(I), 8);
        // the coinbase at 107 pays for the rest: held work flows again, as far as the caps allow
        assert_eq!(b.pay(107, 30), 30);
        assert_eq!(b.release_held(), vec![(I.to_string(), 8), (J.to_string(), 5)]);
        assert_eq!((b.held_total(), b.credited[I], b.credited[J]), (0, 40, 15));
        // frozen (the carry rules): no new credit at all
        b.frozen = Some("carry_cap".into());
        assert_eq!(b.accept(&k.sign(&r(10, 44, 101, 107)).unwrap(), I).unwrap(), 0);
        assert_eq!(b.held(I), 4);
        // state round trip keeps held and unaudited work
        let mut c = ReceiptBook::new(P, k.pubkey(), 70);
        c.load(&b.to_json()).unwrap();
        assert_eq!((c.credits.clone(), c.cover.clone(), c.held(I), c.credited[I]), (b.credits.clone(), b.cover.clone(), 4, 40));
        assert_eq!(c.accept(&k.sign(&r(10, 44, 101, 107)).unwrap(), I).unwrap(), 4);
        assert_eq!(c.intervals, b.intervals);
    }

    /// AGP-079: only what a coinbase paid for leaves the caps; a re-audit replaces a block's payment,
    /// a reorg takes it back, more than was credited is room, and settling forgets no unpaid credit.
    #[test]
    fn payments_cover_the_oldest_credit_and_a_reorg_takes_them_back() {
        let k = PrimeKey::from_seed(70, &[1u8; 32]);
        let mut b = ReceiptBook::new(P, k.pubkey(), 70);
        b.caps = CreditCaps { per_invoice: Some(100), total: Some(100) };
        assert_eq!(b.accept(&k.sign(&r(1, 30, 101, 103)).unwrap(), I).unwrap(), 30);
        assert_eq!(b.accept(&k.sign(&r(2, 50, 101, 106)).unwrap(), I).unwrap(), 20);
        // a pass that paid nothing covers nothing
        assert_eq!((b.pay(106, 0), b.unaudited_work(None)), (0, 50));
        assert_eq!((b.pay(107, 20), b.unaudited_work(None)), (20, 30));
        // the block at 107 is orphaned: its payment is gone
        assert_eq!((b.uncover(107), b.unaudited_work(None)), (20, 50));
        b.pay(107, 20);
        // audited again with more paid: replaced, not added
        assert_eq!((b.pay(107, 25), b.unaudited_work(None)), (5, 25));
        // paid for more than was credited: the surplus is room beyond the caps
        assert_eq!((b.pay(108, 40), b.unaudited_work(None), b.room(I)), (25, 0, 115));
        // settling 107 forgets its payment and the 25 units of credit it covered, nothing unpaid
        b.settle(107, 103);
        assert_eq!((b.credits.clone(), b.cover.clone(), b.intervals.len()), (vec![(I.to_string(), 25)], vec![(108, 40)], 0));
        b.uncover(108);
        assert_eq!(b.unaudited_work(None), 25, "settled credit a reorg left unpaid is still counted");
        b.pay(108, 40);
        b.settle(108, 103);
        assert_eq!((b.credits.len(), b.cover.len(), b.cover_settled, b.room(I)), (0, 0, 15, 115));
        // a settled block audited again is not paid for twice
        assert_eq!((b.pay(107, 25), b.pay(108, 40), b.cover.len(), b.room(I)), (0, 0, 0, 115));
        let mut c = ReceiptBook::new(P, k.pubkey(), 70);
        c.caps = b.caps;
        c.load(&b.to_json()).unwrap();
        assert_eq!((c.cover_settled, c.settled_through, c.unaudited_work(None), c.room(I), c.best(I).map(|s| s.receipt.seq)), (15, 108, 0, 115, Some(2)));
    }

    /// AGP-079, against a model over 1,200 random steps (receipts on three invoices, payments,
    /// re-audits, reorgs, settling, a restart): unaudited credit is exactly the credit granted less
    /// the work paid for, the invoices' shares add up to it, no grant takes it over a cap, and
    /// settling or reloading changes none of it.
    #[test]
    fn unaudited_credit_is_credit_granted_less_work_paid_for() {
        let k = PrimeKey::from_seed(70, &[1u8; 32]);
        let invoices = [I, J, "vfer2e5e75t4tv7in42lakx6i6"];
        let caps = CreditCaps { per_invoice: Some(400), total: Some(900) };
        let mut b = ReceiptBook::new(P, k.pubkey(), 70);
        b.caps = caps;
        // xorshift64: a fixed seed, so a failure reproduces
        let mut x = 0x9e37_79b9_7f4a_7c15_u64;
        let mut rnd = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        let (mut seq, mut cum) = ([0u64; 3], [0u64; 3]);
        let (mut granted, mut settled_paid, mut tip) = (0u128, 0u128, 100u32);
        let mut paid: std::collections::BTreeMap<u32, u64> = Default::default();
        for step in 0..1_200 {
            let before = (b.unaudited_work(None), invoices.map(|i| b.unaudited_work(Some(i))));
            match rnd(10) {
                0..=4 => {
                    let i = rnd(3) as usize;
                    seq[i] += 1;
                    cum[i] += 1 + rnd(120);
                    let r = WorkReceipt { invoice: invoices[i].into(), ..r(seq[i], cum[i], 101, tip) };
                    let g = b.accept(&k.sign(&r).unwrap(), invoices[i]).unwrap();
                    granted += u128::from(g);
                    if g > 0 {
                        assert!(b.unaudited_work(None) <= caps.total.unwrap().max(before.0), "step {step}: a grant went over the total cap");
                        assert!(b.unaudited_work(Some(invoices[i])) <= caps.per_invoice.unwrap().max(before.1[i]), "step {step}: over the invoice cap");
                    }
                }
                5 | 6 => {
                    // a new block, or one audited again (a settled one changes nothing)
                    let h = if rnd(3) == 0 { tip.saturating_sub(rnd(30) as u32) } else { tip + 1 };
                    tip = tip.max(h);
                    let w = rnd(4) * rnd(150);
                    let covered = b.pay(h, w);
                    if h > b.settled_through {
                        paid.remove(&h);
                        if w > 0 {
                            paid.insert(h, w);
                        }
                    }
                    assert!(covered <= before.0, "step {step}");
                    granted += b.release_held().iter().map(|(_, g)| u128::from(*g)).sum::<u128>();
                }
                7 => {
                    let h = tip.saturating_sub(rnd(10) as u32);
                    b.uncover(h);
                    if h > b.settled_through {
                        paid.remove(&h);
                    }
                }
                8 => {
                    let h = tip.saturating_sub(10 + rnd(20) as u32);
                    let moved: Vec<u32> = paid.range(..=h).map(|(h, _)| *h).collect();
                    for m in moved {
                        settled_paid += u128::from(paid.remove(&m).unwrap());
                    }
                    // every receipt starts at 101: all but each invoice's best are forgotten
                    b.settle(h, 101);
                    assert_eq!((b.unaudited_work(None), invoices.map(|i| b.unaudited_work(Some(i)))), before, "step {step}: settling moved credit");
                }
                _ => {
                    let mut c = ReceiptBook::new(P, k.pubkey(), 70);
                    c.caps = caps;
                    c.load(&b.to_json()).unwrap();
                    assert_eq!((c.unaudited_work(None), invoices.map(|i| c.unaudited_work(Some(i))), invoices.map(|i| c.room(i))),
                               (before.0, before.1, invoices.map(|i| b.room(i))), "step {step}: a restart moved credit");
                    b = c;
                }
            }
            let paid_for = settled_paid + paid.values().map(|w| u128::from(*w)).sum::<u128>();
            assert_eq!(u128::from(b.unaudited_work(None)), granted.saturating_sub(paid_for), "step {step}");
            assert_eq!(invoices.iter().map(|i| b.unaudited_work(Some(i))).sum::<u64>(), b.unaudited_work(None), "step {step}");
            assert_eq!(b.credited.values().map(|c| u128::from(*c)).sum::<u128>(), granted, "step {step}");
        }
        assert!(granted > 5_000 && settled_paid > 0, "the walk granted {granted} and settled {settled_paid}");
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
        for key in ["credits", "cover", "coverSettled"] {
            v.as_object_mut().unwrap().remove(key);
        }
        let mut v43 = v.clone();
        v43["unaudited"] = serde_json::json!([[I, 104, 8]]);
        let mut d = ReceiptBook::new(P, k.pubkey(), 70);
        d.load(&v43).unwrap();
        assert_eq!((d.unaudited_work(None), d.held(I)), (8, 0));
        // AGP-065 state: covered spans are paid for; open and skipped credit is unpaid, none forgiven
        v["spans"] = serde_json::json!([[I, 101, 102, 12, 12, "covered", 104], [I, 102, 104, 16, 16, "open", 0]]);
        v["settledSkipped"] = 3.into();
        let mut e = ReceiptBook::new(P, k.pubkey(), 70);
        e.load(&v).unwrap();
        assert_eq!((e.unaudited_work(None), e.unaudited_work(Some(I)), e.held(I)), (19, 16, 0));
    }

    #[test]
    fn no_caps_is_the_reference_behaviour() {
        let k = PrimeKey::from_seed(70, &[1u8; 32]);
        let (mut a, mut b) = (ReceiptBook::new(P, k.pubkey(), 70), ReceiptBook::new(P, k.pubkey(), 70));
        b.caps = CreditCaps { per_invoice: Some(u64::MAX), total: None };
        for (seq, cum, lo, hi) in [(1, 4, 101, 101), (1, 4, 101, 101), (4, 9, 101, 103), (2, 5, 101, 102), (6, 30, 101, 110)] {
            let s = k.sign(&r(seq, cum, lo, hi)).unwrap();
            assert_eq!(a.accept(&s, I).ok(), b.accept(&s, I).ok());
        }
        assert_eq!((a.intervals.clone(), a.credited.clone(), a.held_total()), (b.intervals.clone(), b.credited.clone(), 0));
    }
}
