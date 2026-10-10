//! `rail=ln` pays BOLT 12 offers (AGP-082): `ln_pay` takes an `lno1...` offer as well as a BOLT 11
//! invoice, under the same policy, booking, fee limit, exposure cap and halt rules ([`crate::ln`]).
//!
//! The offer is the stable name, so the policy destination is `ln-offer:<offer id>` (the SHA-256 of
//! the offer's fields, which Lightning Fork and Core Lightning report too). In order, before anything
//! is paid:
//!
//! 1. the offer, decoded here ([`crate::bolt12`]): **feature bit 512**, a chain this node is on (an
//!    offer that names no chain names Bitcoin's genesis, which only mainnet shares), not expired, an
//!    amount (its own, or the caller's `amount_sats` when it has none), the caller's description if
//!    given, the caller's `max_sats`;
//! 2. the LN node's chain identity and macaroon, the exposure cap, the watchtowers, as for BOLT 11;
//! 3. the channels: the node's `PayOffer` takes no set of outgoing channels, so the payment is refused
//!    unless **every** channel of the node passes the guards and the funding proof;
//! 4. B2's policy on `ln-offer:<offer id>` and the amount plus the fee limit, known before any invoice
//!    exists; over the human threshold the approval is for the offer and that amount;
//! 5. only then the invoice: the node fetches it (`FetchInvoice`, `offchain:read`), and the signer
//!    decodes the `lni1...` itself, verifies the issuer's signature, checks it against the offer (bit
//!    512, chain, the offer's own fields repeated, the issuer, the amount asked, expiry, time locks)
//!    and against the node's summary of it, field by field. The signer never asks the node to decode
//!    (`invoices:read`), so the mainnet macaroon keeps its four permissions;
//! 6. the key that signed: recorded with the offer the first time (`ln_offers.json`), and an invoice
//!    for that offer signed by another key is refused from then on.
//!
//! Invoices asked of one offer are limited per hour like the sends (`ln.max_sends_per_hour`): each
//! request is an onion message the node sends, whether or not its invoice is then paid.
//!
//! The fetched invoice is written down before it is paid, and it is the invoice that is paid
//! (`PayOffer` with `invoice`), never the offer: paying the offer again would fetch a second invoice,
//! and a retry that settled beside the first would pay twice. A later `ln_pay` of the same offer for
//! the same amount pays the stored invoice while it is unpaid and not expiring, and fetches a new one
//! only after that one settled.
//!
//! Not shipped here: payer identity. Lightning Fork signs every invoice request with a fresh key, so
//! two payments of one offer carry two `invreq_payer_id`s; each is recorded with its payment and
//! names that payment only.
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::bolt12::{self, Invoice, InvoiceTerms, Offer};
use crate::ln::{bytes_hex, htlc_locks, u64_of, write_json, LnBackend, LnPolicy, LnRoutes, LnSent, OfferPayRequest};
use crate::policy::{Payment, Verdict};
use crate::pyjson::{py_int, str_or_empty, ts_value};
use crate::signer::{deny, with, Signer};
use crate::{err, node, sigaudit, Result};

/// The policy destination of an offer.
pub fn offer_dest(o: &Offer) -> String {
    format!("ln-offer:{}", o.id_hex())
}

/// Which BOLT 12 string this is by its prefix (`lno`, `lni` or `lnr`), if any.
pub fn bolt12_kind(s: &str) -> Option<&'static str> {
    let head = s.trim_start().get(..4)?.to_ascii_lowercase();
    ["lno", "lni", "lnr"].into_iter().find(|k| head.starts_with(k) && head.ends_with('1'))
}

/// The node's `FetchInvoiceResponse` must say what the invoice it returned says.
pub fn cross_check(o: &Offer, inv: &Invoice, resp: &Value) -> std::result::Result<(), String> {
    let info = resp.get("invoice").unwrap_or(&Value::Null);
    let mut bad = vec![];
    if bytes_hex(resp.get("offer_id")) != o.id_hex() {
        bad.push("offer_id");
    }
    if bytes_hex(info.get("payment_hash")) != inv.payment_hash_hex() {
        bad.push("payment_hash");
    }
    if u64_of(info.get("amount_msat")) != inv.amount_msat {
        bad.push("amount_msat");
    }
    if bytes_hex(info.get("node_id")) != hex::encode(inv.node_id) {
        bad.push("node_id");
    }
    if bytes_hex(info.get("payer_id")) != hex::encode(inv.payer_id) {
        bad.push("payer_id");
    }
    if u64_of(info.get("created_at")) != inv.created_at {
        bad.push("created_at");
    }
    // an invoice that leaves the expiry out is reported as 0
    if !matches!(u64_of(info.get("relative_expiry")), 0 if inv.relative_expiry == bolt12::DEFAULT_RELATIVE_EXPIRY_S)
        && u64_of(info.get("relative_expiry")) != inv.relative_expiry {
        bad.push("relative_expiry");
    }
    if info.get("signature_valid") != Some(&Value::Bool(true)) {
        bad.push("signature_valid");
    }
    if bad.is_empty() { Ok(()) } else { Err(format!("the LN node describes the invoice differently: {}", bad.join(", "))) }
}

/// `ln_offers.json`, beside the payment book: offer id → what the wallet knows of the offer: the key
/// that signed its first invoice (`node_id`) and the last invoice fetched for it (`last_invoice`).
struct OfferStore {
    path: PathBuf,
}

impl OfferStore {
    /// A store that is there but cannot be read is an error, never "no offer known": the recorded
    /// signer is a check.
    fn read(&self) -> Result<Map<String, Value>> {
        match std::fs::read_to_string(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Map::new()),
            Err(e) => Err(err("ln_offer_store", format!("ln_offers.json cannot be read: {e}"))),
            Ok(t) => serde_json::from_str::<Value>(&t).ok().and_then(|v| v.get("offers").and_then(Value::as_object).cloned())
                .ok_or_else(|| err("ln_offer_store", "ln_offers.json is not the offer record")),
        }
    }

    fn get(&self, id: &str) -> Result<Option<Value>> {
        Ok(self.read()?.get(id).cloned())
    }

    fn merge(&self, id: &str, fields: Value) -> Result<()> {
        let mut m = self.read()?;
        let rec = m.remove(id).unwrap_or_else(|| json!({}));
        m.insert(id.into(), with(rec, fields));
        write_json(&self.path, &json!({"offers": m})).map_err(|e| err("ln_offer_store", e.msg))
    }
}

impl Signer {
    fn ln_offers(&self) -> OfferStore {
        OfferStore { path: self.ln_book.path.with_file_name("ln_offers.json") }
    }

    /// A human-approved, unused, unexpired ln grant for exactly this offer and amount.
    fn find_ln_offer_grant(&self, dest: &str, amount: i64, offer_id: &str) -> Option<String> {
        let now = self.engine.now() as i64;
        self.engine.store.approvals().ok()?.into_iter().find(|(_, a)| {
            a.get("kind").and_then(Value::as_str) == Some("ln") && a.get("approved") == Some(&Value::Bool(true))
                && a.get("used") != Some(&Value::Bool(true)) && py_int(a.get("expires")).unwrap_or(0) >= now
                && a.get("dest").and_then(Value::as_str) == Some(dest) && py_int(a.get("amount_sats")) == Some(amount)
                && a.get("offer_id").and_then(Value::as_str) == Some(offer_id)
        }).map(|(t, _)| t)
    }

    /// The block 0 hash of the chain our own node follows, in wire order: the chain an offer must name.
    fn ln_genesis(&self) -> Option<[u8; 32]> {
        let mut b = hex::decode(node::block_hash(&*self.node, 0).ok()?).ok()?;
        b.reverse();
        <[u8; 32]>::try_from(b).ok()
    }

    /// The last invoice fetched for this offer, if it can still be paid for this amount: unpaid, checked
    /// again against the offer, not expiring. Paying it again is how a failed payment is retried.
    fn ln_stored_invoice(&self, o: &Offer, known: Option<&Value>, terms: &InvoiceTerms) -> Option<(String, Invoice)> {
        let s = known?.get("last_invoice")?.get("invoice")?.as_str()?;
        let inv = bolt12::decode_invoice(s).ok()?;
        bolt12::check_invoice(o, &inv, terms).ok()?;
        let state = self.ln_book.get(&inv.payment_hash_hex()).and_then(|r| r.get("state").and_then(Value::as_str).map(str::to_string));
        (state.as_deref() != Some("settled")).then(|| (s.to_string(), inv))
    }

    /// `ln_pay` of a BOLT 12 offer: every check, the fetched invoice written down, the write-ahead
    /// booking, then the node pays that invoice.
    pub(crate) fn ln_pay_offer_locked(&self, p: &Value, offer: &str, max_sats: i64, ln: Arc<dyn LnBackend>, pol: &LnPolicy) -> Value {
        let offer = offer.trim();
        let o = match bolt12::decode_offer(offer) {
            Ok(o) => o,
            Err(e) => return self.ln_refuse("ln_offer", &format!("not a valid BOLT 12 offer: {e}"), "", ""),
        };
        let (dest, id) = (offer_dest(&o), o.id_hex());
        let now = self.engine.now();
        let Some(genesis) = self.ln_genesis() else {
            return self.ln_refuse("ln_chain", "our own node did not give its block 0 hash, which is the chain an offer must name", &dest, "");
        };
        if let Err((rule, why)) = bolt12::check_offer(&o, &genesis, now) {
            return self.ln_refuse(&rule, &why, &dest, "");
        }
        let description = str_or_empty(p.get("description"));
        if !description.is_empty() {
            if o.description.as_deref() != Some(description.as_str()) {
                return self.ln_refuse("ln_description", "the offer's description does not match the description given", &dest, "");
            }
        } else if pol.require_description {
            return self.ln_refuse("ln_description", "policy ln.require_description: pass the offer's description", &dest, "");
        }
        // amount_sats: only for an offer that names no amount (0 or absent: not given)
        let asked = match p.get("amount_sats").filter(|v| !v.is_null()).map(|v| py_int(Some(v))) {
            None | Some(Some(0)) => None,
            Some(Some(n)) if n > 0 => Some((n as u64).saturating_mul(1000)),
            Some(_) => return deny("amount", "amount_sats must be a positive integer (the amount to pay an offer that names none)"),
        };
        let amount_msat = match bolt12::offer_amount_msat(&o, asked) {
            Ok(a) => a,
            Err((rule, why)) => return self.ln_refuse(&rule, &why, &dest, ""),
        };
        let Ok(amount) = i64::try_from(amount_msat.div_ceil(1000)) else {
            return self.ln_refuse("ln_amount", "the amount is out of range", &dest, "");
        };
        // the node reads a fee limit of 0 as its own default, so the limit is at least 1 sat
        let fee_limit = pol.fee_limit_sats(amount).max(1);
        let total = amount.saturating_add(fee_limit);
        if total > max_sats {
            return self.ln_refuse("max_sats", &format!("offer {amount} + fee limit {fee_limit} = {total} sats is above max_sats {max_sats}"), &dest, "");
        }
        // anything a crash or a timeout left in flight is settled or released first
        self.ln_reconcile_locked();
        if let Some((h, _)) = self.ln_book.in_flight().first() {
            return self.ln_refuse("ln_in_flight", &format!("another LN payment ({h}) is still in flight"), &dest, "");
        }
        if pol.max_sends_per_hour > 0 && self.ln_book.sends_since(now - 3600.0) as i64 >= pol.max_sends_per_hour {
            return self.ln_refuse("ln_rate_limit", &format!("already {} payments sent to the LN node in the last hour (ln.max_sends_per_hour)",
                                                            pol.max_sends_per_hour), &dest, "");
        }
        let chain_ok = match self.ln_node_checks(&*ln, pol, &dest, "") {
            Ok(v) => v,
            Err(d) => return d,
        };
        let LnRoutes { chans, exposure, warnings, .. } = match self.ln_route_checks(&*ln, pol, &dest, "", true) {
            Ok(r) => r,
            Err(d) => return d,
        };
        // the policy, on the offer and what it will cost at most: decided before any invoice is asked for
        let pay = Payment::new(&dest, total, &format!("ln offer {id}"));
        let grant = self.find_ln_offer_grant(&dest, total, &id);
        let d = match self.engine.evaluate(&pay, grant.is_some()) {
            Ok(d) => d,
            Err(e) => return deny("ln", e.msg),
        };
        let facts = json!({"rail": "ln", "offer_id": id, "invoice_sats": amount, "fee_limit_sats": fee_limit});
        if d.verdict == Verdict::NeedsHuman {
            if let Some(t) = &d.approval_token {
                let _ = self.engine.store.update_approval(t, &json!({"kind": "ln", "offer_id": id, "offer": offer}));
            }
        }
        if !d.allowed() {
            return with(with(d.as_value(), facts), json!({"charged_sats": 0}));
        }
        let book = self.ln_book.all();
        let locks = htlc_locks(&chans, &|h: &str| {
            book.get(h).and_then(|r| r.get("state")).and_then(Value::as_str).is_some_and(|s| s == "sending" || s == "settled")
        });
        let room = d.residual_daily_sats.min(d.residual_weekly_sats);
        if locks.unbooked_sats > 0 && total + locks.unbooked_sats > room {
            return with(self.ln_refuse("ln_htlc_lock", &format!(
                "{} sats are locked in HTLCs the wallet did not send (until height {}); with this payment's {total} that exceeds the {room} sats left \
                 in the budgets", locks.unbooked_sats, locks.until_height), &dest, ""), json!({"htlc_locks": locks.list}));
        }
        // the invoice: the one already fetched for this offer and amount while it is unpaid, else a new one
        let store = self.ln_offers();
        let known = match store.get(&id) {
            Ok(k) => k,
            Err(e) => return self.ln_refuse("ln_offer_store", &e.msg, &dest, ""),
        };
        let terms = InvoiceTerms { amount_msat, genesis: &genesis, now, min_expiry_s: pol.min_expiry_s, max_cltv_blocks: pol.max_cltv_blocks };
        let (lni, inv, fetched) = match self.ln_stored_invoice(&o, known.as_ref(), &terms) {
            Some((s, inv)) => (s, inv, false),
            None => {
                // each FetchInvoice has the node send an onion message: bounded per offer, as the sends are
                let mut asked: Vec<f64> = known.as_ref().and_then(|k| k.get("fetch_ts")).and_then(Value::as_array).into_iter().flatten()
                    .filter_map(Value::as_f64).filter(|t| *t >= now - 3600.0).collect();
                if pol.max_sends_per_hour > 0 && asked.len() as i64 >= pol.max_sends_per_hour {
                    return self.ln_refuse("ln_rate_limit", &format!("already {} invoices asked for this offer in the last hour (ln.max_sends_per_hour)",
                                                                    pol.max_sends_per_hour), &dest, "");
                }
                asked.push(now);
                if let Err(e) = store.merge(&id, json!({"fetch_ts": asked})) {
                    return self.ln_refuse("ln_offer_store", &e.msg, &dest, "");
                }
                // an offer with an amount is asked for that amount by leaving it out
                let resp = match ln.fetch_invoice(offer, if o.amount.is_some() { 0 } else { amount_msat }, pol.timeout_s.max(1)) {
                    Ok(r) => r,
                    Err(e) => return self.ln_refuse("ln_fetch_invoice", &format!("no invoice for the offer: {}", e.msg), &dest, ""),
                };
                let s = str_or_empty(resp.get("bolt12")).trim().to_string();
                let inv = match bolt12::decode_invoice(&s) {
                    Ok(i) => i,
                    Err(e) => return self.ln_refuse("ln_invoice", &format!("the LN node's invoice for the offer is not a valid BOLT 12 invoice: {e}"), &dest, ""),
                };
                let hash = inv.payment_hash_hex();
                if let Err((rule, why)) = bolt12::check_invoice(&o, &inv, &terms) {
                    return self.ln_refuse(&rule, &why, &dest, &hash);
                }
                if let Err(why) = cross_check(&o, &inv, &resp) {
                    return self.ln_refuse("ln_decode_mismatch", &why, &dest, &hash);
                }
                (s, inv, true)
            }
        };
        let (hash, signer, payer) = (inv.payment_hash_hex(), hex::encode(inv.node_id), hex::encode(inv.payer_id));
        // the key that signed the offer's first invoice signs them all
        let first = known.as_ref().and_then(|k| k.get("node_id")).and_then(Value::as_str).map(str::to_string);
        if let Some(first) = first.as_deref().filter(|f| *f != signer) {
            return self.ln_refuse("ln_offer_signer", &format!(
                "this invoice for the offer is signed by {signer}; its first was signed by {first}. Refused: the owner removes the offer from \
                 ln_offers.json to accept a new signer"), &dest, &hash);
        }
        match self.ln_book.get(&hash).as_ref().and_then(|r| r.get("state")).and_then(Value::as_str) {
            Some("settled") => return self.ln_refuse("ln_duplicate", "the LN node returned an invoice that is already paid", &dest, &hash),
            Some("sending") => return self.ln_refuse("ln_in_flight", "this invoice's payment is still in flight", &dest, &hash),
            _ => {}
        }
        // written down before it is paid: a retry pays this invoice, and never fetches beside it
        if fetched || first.is_none() {
            let mut fields = json!({"last_invoice": {"invoice": lni, "payment_hash": hash, "amount_msat": amount_msat, "payer_id": payer,
                                                     "fetched_ts": ts_value(now)}});
            if first.is_none() {
                fields = with(fields, json!({"node_id": signer, "first_seen_ts": ts_value(now)}));
            }
            if let Err(e) = store.merge(&id, fields) {
                return self.ln_refuse("ln_offer_store", &e.msg, &dest, &hash);
            }
        }
        sigaudit::set_rule(&if grant.is_some() { "human:approval_signature".to_string() } else { format!("policy:{}", d.rule) });
        // write-ahead: the worst case is booked before the node is asked to pay
        let rec = json!({"state": "sending", "dest": dest, "invoice": lni, "amount_msat": amount_msat, "fee_limit_sats": fee_limit, "booked_sats": total,
                         "ts": ts_value(now), "approval_token": grant, "offer_id": id, "offer": offer, "payer_id": payer, "node_id": signer});
        if let Err(e) = self.ln_book.put(&hash, rec) {
            return deny("ln", e.msg);
        }
        if let Err(e) = self.engine.commit(&pay, &format!("ln:{hash}")) {
            let _ = self.ln_book.update(&hash, json!({"state": "failed", "failure": "ledger"}));
            return deny("ln", e.msg);
        }
        let req = OfferPayRequest { invoice: lni, fee_limit_msat: (fee_limit as u64).saturating_mul(1000), timeout_s: pol.timeout_s.max(1) };
        // an answer for another payment is no answer: the node's record of this hash decides
        let sent = ln.pay_offer(&req).and_then(|pmt| {
            if str_or_empty(pmt.get("payment_hash")).eq_ignore_ascii_case(&hash) { Ok(pmt) } else { Err(err("ln_backend", "the LN node answered for another payment")) }
        });
        self.ln_sent(&*ln, &hash, sent, LnSent { decision: d.as_value(), grant, total, warnings,
                                                 facts: json!({"chain_check": chain_ok, "fee_limit_sats": fee_limit, "invoice_sats": amount,
                                                               "exposure": exposure, "offer_id": id, "payer_id": payer,
                                                               "invoice_reused": !fetched}) })
    }
}
