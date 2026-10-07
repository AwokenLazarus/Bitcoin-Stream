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
    /// Credited increases no passing audit covers yet: (invoice, hi, work).
    pub unaudited: Vec<(String, u32, u64)>,
    /// The caps in force (configuration, not state).
    pub caps: CreditCaps,
    /// Set: no new credit at all (the carry rules of §10.3/§13.1), with the reason's short code.
    pub frozen: Option<String>,
}

impl ReceiptBook {
    pub fn new(identity: &str, prime_pubkey: VerifyingKey, prime_id: u32) -> Self {
        Self { identity: identity.into(), prime_pubkey, prime_id, last: IndexMap::new(), by_seq: HashMap::new(),
               credited: HashMap::new(), intervals: vec![], fraud: vec![], unaudited: vec![],
               caps: CreditCaps::default(), frozen: None }
    }

    /// Unaudited credit of `invoice` (None: across all invoices).
    pub fn unaudited_work(&self, invoice: Option<&str>) -> u64 {
        self.unaudited.iter().filter(|(i, _, _)| invoice.map_or(true, |v| v == i)).fold(0u64, |a, (_, _, w)| a.saturating_add(*w))
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
        let per = self.caps.per_invoice.map_or(u64::MAX, |c| c.saturating_sub(self.unaudited_work(Some(invoice))));
        let tot = self.caps.total.map_or(u64::MAX, |c| c.saturating_sub(self.unaudited_work(None)));
        per.min(tot)
    }

    /// A coinbase at `height` passed its audit: every credit recorded so far with shares below it is
    /// covered. Returns the work released from the caps.
    pub fn audited(&mut self, height: u32) -> u64 {
        let before = self.unaudited_work(None);
        self.unaudited.retain(|(_, hi, _)| *hi >= height);
        before - self.unaudited_work(None)
    }

    /// Credit `invoice`'s held work as far as the caps allow; returns the work credited. The credit
    /// stays unaudited until an audit passes above the best receipt's last share.
    fn credit(&mut self, invoice: &str) -> u64 {
        let before = *self.credited.entry(invoice.to_string()).or_insert(0);
        let Some((cum, hi)) = self.last.get(invoice).map(|s| (s.receipt.cum_work, s.receipt.last_height)) else { return 0 };
        let grant = cum.saturating_sub(before).min(self.room(invoice));
        if grant > 0 {
            self.unaudited.push((invoice.to_string(), hi, grant));
            self.credited.insert(invoice.to_string(), before + grant);
        }
        grant
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
        let ua: Vec<Value> = self.unaudited.iter().map(|(i, hi, w)| Value::from(vec![Value::from(i.clone()), Value::from(*hi), Value::from(*w)])).collect();
        obj([("last", last.into()), ("credited", Value::Object(cr)), ("intervals", iv.into()),
             ("fraud", self.fraud.iter().map(Equivocation::to_json).collect::<Vec<_>>().into()),
             ("unaudited", ua.into())])
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
        for u in v.get("unaudited").and_then(Value::as_array).into_iter().flatten() {
            let inv = u.get(0).and_then(Value::as_str).ok_or_else(|| bad("unaudited"))?;
            let f = |j: usize| u.get(j).and_then(Value::as_u64).ok_or_else(|| bad("unaudited"));
            self.unaudited.push((inv.to_string(), f(1)? as u32, f(2)?));
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
        // an audit at 104 covers only the credits whose shares are all below it
        assert_eq!(b.audited(104), 12);
        assert_eq!(b.unaudited_work(None), 18);
        // a later receipt of I: 12 more receipted; room for 12 under the invoice cap, 8 stay held
        assert_eq!(b.accept(&k.sign(&r(9, 40, 101, 106)).unwrap(), I).unwrap(), 12);
        assert_eq!(*b.intervals.last().unwrap(), (104, 106, 12));
        assert_eq!(b.held(I), 8);
        // everything below 107 audited: held work flows again, as far as the caps allow
        b.audited(107);
        assert_eq!(b.release_held(), vec![(I.to_string(), 8), (J.to_string(), 5)]);
        assert_eq!((b.held_total(), b.credited[I], b.credited[J]), (0, 40, 15));
        // frozen (the carry rules): no new credit at all
        b.frozen = Some("carry_cap".into());
        assert_eq!(b.accept(&k.sign(&r(10, 44, 101, 107)).unwrap(), I).unwrap(), 0);
        assert_eq!(b.held(I), 4);
        // state round trip keeps held and unaudited work
        let mut c = ReceiptBook::new(P, k.pubkey(), 70);
        c.load(&b.to_json()).unwrap();
        assert_eq!((c.unaudited.clone(), c.held(I), c.credited[I]), (b.unaudited.clone(), 4, 40));
        assert_eq!(c.accept(&k.sign(&r(10, 44, 101, 107)).unwrap(), I).unwrap(), 4);
        assert_eq!(c.intervals, b.intervals);
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
