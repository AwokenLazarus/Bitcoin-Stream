//! The provider rail (spec §4.5, §7, §9): an `xbt-work` offer beside `xbt-channel` in the xbt402
//! [`Provider`](xbt402::provider::Provider) ([`Provider::with_scheme`](xbt402::provider::Provider::with_scheme)).
//!
//! * `POST /x402/xbt-work/invoice` issues invoices (128-bit base32 id, a fresh `authKey`, both
//!   usernames), bounded and expiring while unfunded.
//! * A PAYMENT-SIGNATURE naming `xbt-work` is checked in the §9.1 order (scheme/network/payTo,
//!   grammar, identity and Prime, invoice, `auth` and a fresh `n`, the Ed25519 signature,
//!   equivocation, delta credit, balance), debited and recorded durably before the handler runs,
//!   released if the handler answers ≥ 500, and answered with the `SettlementResponse` of §9.3.
//! * [`WorkProvider::refresh`] pulls the latest receipts through the blinded relay (§11.1), and
//!   [`WorkProvider::audit`] checks a pool coinbase against the book (§10), with the carry ledger.
//! * §13.1 credit caps (AGP-043, [`WorkConfig::caps`]): unaudited credit is capped per invoice and in
//!   total; work beyond the caps is held and credited after the next passing audit. The carry the
//!   Prime owes counts too: above [`WorkConfig::max_owed_carry_sats`], or when it
//!   [keeps growing](crate::audit::CarryLedger::keeps_growing) over
//!   [`WorkConfig::carry_growth_blocks`] audited blocks, no new credit is extended until carry is
//!   released. A call the held work would have paid is refused with `credit_cap`, `carry_cap` or
//!   `carry_growing` (and the balances in `work`), never with a silent loss: the receipts stay held.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use xbt402::client::Transport;
use xbt402::json::{dumps, obj};
use xbt402::provider::HttpResponse;
use xbt402::scheme::{ProviderScheme, SchemeCharge};
use xbt402::wire::settlement_response;

use crate::audit::{audit_block, AuditOutcome, CarryLedger, SignedDeferral, SignedWindow};
use crate::auth::{auth_tag, request_digest, tag_eq};
use crate::book::{CreditCaps, ReceiptBook};
use crate::error::{fail, Result, WorkError};
use crate::grammar::{canonical_identity, random_invoice, uint, valid_identity, U64};
use crate::pricing::Pricing;
use crate::receipt::{pubkey_from_hex, sig64, Signed, WorkReceipt};
use crate::{ASSET, INVOICE_PATH, SCHEME};

/// How a call's price in sats becomes its `amount` in work units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Amount {
    /// Every call costs this many work units.
    Fixed(u64),
    /// §6.2 exact pricing of the call's sats price at the current epoch (`price_sats` is replaced
    /// by the call's price); `extra.pricing` is published.
    Priced(Pricing),
}

/// Provider settings.
#[derive(Debug, Clone)]
pub struct WorkConfig {
    /// CAIP-2 network id, as the xbt-channel offer.
    pub network: String,
    /// The payout identity (canonicalised here), `payTo`.
    pub identity: String,
    pub prime_id: u32,
    /// The pinned Prime key as advertised (`primed pubkey` output; the first 32 bytes sign).
    pub prime_pubkey_hex: String,
    /// `extra.receiptUrl`: the Prime's direct receipt query (or the relay).
    pub receipt_url: String,
    /// The blinded relay the provider pulls from and names in invoices (`relayUrl`).
    pub relay_url: Option<String>,
    pub amount: Amount,
    /// The price (sats) an invoice document quotes `amount` for.
    pub invoice_price_sats: u64,
    pub invoice_ttl_secs: u64,
    pub max_unfunded: usize,
    pub max_timeout_secs: u64,
    /// Where the book is kept (recorded before each handler runs). None: memory only.
    pub state_path: Option<PathBuf>,
    /// §13.1: caps on unaudited credit, in work units (about one window's value each).
    pub caps: CreditCaps,
    /// §10.3/§13.1: owed carry above this (sats) stops new credit until carry is released.
    pub max_owed_carry_sats: Option<u64>,
    /// §10.3: owed carry grew over each of the last N audited blocks: stop new credit (set it when the
    /// provider attests every tip, so growth means the Prime is not paying).
    pub carry_growth_blocks: Option<usize>,
    /// The chain enforces payee attestation (§13.8): the identity must be a key-path P2TR address.
    pub nta: bool,
}

impl WorkConfig {
    pub fn new(network: &str, identity: &str, prime_id: u32, prime_pubkey_hex: &str, receipt_url: &str) -> Self {
        Self { network: network.into(), identity: canonical_identity(identity), prime_id, prime_pubkey_hex: prime_pubkey_hex.into(),
               receipt_url: receipt_url.into(), relay_url: None, amount: Amount::Fixed(1), invoice_price_sats: 0,
               invoice_ttl_secs: 3600, max_unfunded: 10_000, max_timeout_secs: 3600, state_path: None, caps: CreditCaps::default(),
               max_owed_carry_sats: None, carry_growth_blocks: None, nta: false }
    }
}

#[derive(Debug, Clone)]
struct Invoice {
    key: [u8; 32],
    /// Highest `n` accepted (consumed even when the call is then refused).
    n: u64,
    spent: u64,
    expires_at: u64,
    retired: bool,
}

struct State {
    invoices: HashMap<String, Invoice>,
    book: ReceiptBook,
    carry: CarryLedger,
    audits: Vec<Value>,
    /// Set once the Prime key equivocated or failed an audit: its receipts are no longer accepted
    /// (§9.1 step 7, §13.1).
    distrust: Option<(String, String)>,
}

/// The `xbt-work` rail of a provider.
pub struct WorkProvider {
    pub cfg: WorkConfig,
    pubkey: VerifyingKey,
    /// The pricing rule in force (`cfg.amount` at start, then each epoch's).
    rule: Mutex<Amount>,
    state: Mutex<State>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}

impl WorkProvider {
    pub fn new(cfg: WorkConfig) -> Result<Self> {
        if !valid_identity(&cfg.identity) {
            return fail("bad_config", "identity outside the grammar (§4.2)");
        }
        if cfg.nta {
            // §13.8 rule 1: any other script cannot be a payee; the Prime could only carry its share forever
            let spk = xbt_primitives::address::address_to_spk(&cfg.identity, None).unwrap_or_default();
            if !crate::nta::is_payee_script(&spk) {
                return fail("bad_config", "the identity is not a key-path P2TR address: it cannot be paid under payee attestation (§13.8)");
            }
        }
        let pubkey = pubkey_from_hex(&cfg.prime_pubkey_hex).map_err(|e| WorkError::new("bad_config", e.0))?;
        let mut book = ReceiptBook::new(&cfg.identity, pubkey, cfg.prime_id);
        book.caps = cfg.caps;
        let wp = Self { pubkey, rule: Mutex::new(cfg.amount.clone()), state: Mutex::new(State { invoices: HashMap::new(), book, carry: CarryLedger::default(), audits: vec![], distrust: None }), cfg };
        wp.load()?;
        wp.carry_rules(&mut wp.lock());
        Ok(wp)
    }

    /// §10.3/§13.1: freeze new credit while the owed carry is over its cap or keeps growing.
    fn carry_rules(&self, st: &mut State) {
        st.book.frozen = if self.cfg.max_owed_carry_sats.is_some_and(|m| st.carry.owed() > m) {
            Some("carry_cap".into())
        } else if self.cfg.carry_growth_blocks.is_some_and(|n| st.carry.keeps_growing(n)) {
            Some("carry_growing".into())
        } else {
            None
        };
    }

    /// Change the caps (e.g. re-derived from sats at a new epoch). Held work the new caps allow is
    /// credited at once.
    pub fn set_caps(&self, caps: CreditCaps) -> Result<Vec<(String, u64)>> {
        let mut st = self.lock();
        st.book.caps = caps;
        let r = st.book.release_held();
        self.save(&st)?;
        Ok(r)
    }

    /// (unaudited, held) work: credit no audit covers yet, and receipted work the caps hold back.
    pub fn exposure(&self) -> (u64, u64) {
        let st = self.lock();
        (st.book.unaudited_work(None), st.book.held_total())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn prime_pubkey(&self) -> &VerifyingKey {
        &self.pubkey
    }

    /// The advertised key: the 32-byte Ed25519 key in hex.
    pub fn prime_pubkey_hex(&self) -> String {
        hex::encode(self.pubkey.as_bytes())
    }

    /// A new epoch (§6.3): re-price new 402s at `bits` and `block_value_sats`. Balances are kept
    /// in work units and never revalued. Returns whether the price inputs changed.
    pub fn set_epoch(&self, bits: u32, block_value_sats: u64) -> bool {
        let mut r = self.rule.lock().unwrap_or_else(|p| p.into_inner());
        match &mut *r {
            Amount::Priced(p) if (p.bits, p.block_value_sats) != (bits, block_value_sats) => {
                p.bits = bits;
                p.block_value_sats = block_value_sats;
                true
            }
            _ => false,
        }
    }

    /// The pricing rule in force.
    pub fn rule(&self) -> Amount {
        self.rule.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Work units a call priced `price_sats` costs.
    pub fn amount(&self, price_sats: u64) -> Result<u64> {
        match &self.rule() {
            Amount::Fixed(n) => Ok((*n).max(1)),
            Amount::Priced(p) => Pricing { price_sats, ..p.clone() }.amount(),
        }
    }

    /// The §7 PaymentRequirements for `amount` work units.
    pub fn requirements_for(&self, amount: u64, price_sats: u64) -> Value {
        let mut extra = obj([("invoiceUrl", INVOICE_PATH.into()), ("primeId", self.cfg.prime_id.into()),
                             ("primePubkey", self.prime_pubkey_hex().into()), ("receiptUrl", self.cfg.receipt_url.clone().into()),
                             ("usernameForms", Value::from(vec!["pw", "tilde"])), ("invoiceTtlSeconds", self.cfg.invoice_ttl_secs.into())]);
        if let Amount::Priced(p) = &self.rule() {
            extra["pricing"] = Pricing { price_sats, ..p.clone() }.to_json();
        }
        obj([("scheme", SCHEME.into()), ("network", self.cfg.network.clone().into()), ("amount", amount.to_string().into()),
             ("asset", ASSET.into()), ("payTo", self.cfg.identity.clone().into()), ("maxTimeoutSeconds", self.cfg.max_timeout_secs.into()),
             ("extra", extra)])
    }

    fn refusal(&self, url: &str, amount: u64, price_sats: u64, code: &str, work: Option<Value>) -> Value {
        let mut v = obj([("x402Version", 2.into()), ("error", code.into()), ("resource", obj([("url", url.into())])),
                         ("accepts", Value::from(vec![self.requirements_for(amount, price_sats)]))]);
        if let Some(w) = work {
            v["work"] = w;
        }
        v
    }

    /// §4.5: issue an invoice. `too_many_invoices` beyond the bound of unfunded ones.
    pub fn issue_invoice(&self) -> Result<Value> {
        let amount = self.amount(self.cfg.invoice_price_sats)?;
        let (inv, key, exp) = {
            let mut st = self.lock();
            let t = now();
            let State { invoices, book, .. } = &mut *st;
            invoices.retain(|k, v| book.funded(k) || v.expires_at >= t);
            let unfunded = invoices.keys().filter(|k| !book.funded(k)).count();
            if unfunded >= self.cfg.max_unfunded {
                return fail("too_many_invoices", "");
            }
            let inv = random_invoice();
            let (key, exp) = (random32(), t + self.cfg.invoice_ttl_secs);
            invoices.insert(inv.clone(), Invoice { key, n: 0, spent: 0, expires_at: exp, retired: false });
            self.save(&st)?;
            (inv, key, exp)
        };
        let id = &self.cfg.identity;
        let mut doc = obj([("invoice", inv.clone().into()), ("identity", id.clone().into()), ("network", self.cfg.network.clone().into()),
                           ("username", format!("{id}.pw-{inv}.<worker>").into()), ("usernameAlt", format!("{id}~{inv}.<worker>").into()),
                           ("authKey", hex::encode(key).into()), ("amount", amount.to_string().into()), ("primeId", self.cfg.prime_id.into()),
                           ("primePubkey", self.prime_pubkey_hex().into()), ("expiresAt", exp.into()),
                           ("receiptUrl", format!("{}?identity={id}&invoice={inv}", self.cfg.receipt_url).into())]);
        if let Some(r) = &self.cfg.relay_url {
            doc["relayUrl"] = r.clone().into();
        }
        Ok(doc)
    }

    /// Retire an invoice: its balance can no longer be spent (§9.1 step 4).
    pub fn retire(&self, invoice: &str) -> Result<()> {
        let mut st = self.lock();
        if let Some(i) = st.invoices.get_mut(invoice) {
            i.retired = true;
        }
        self.save(&st)
    }

    /// (credited, spent) of an invoice.
    pub fn balance(&self, invoice: &str) -> Option<(u64, u64)> {
        let st = self.lock();
        let i = st.invoices.get(invoice)?;
        Some((st.book.credited.get(invoice).copied().unwrap_or(0), i.spent))
    }

    /// The live invoices (funded, or unfunded and not expired).
    pub fn invoices(&self) -> Vec<String> {
        let st = self.lock();
        let t = now();
        let mut v: Vec<String> = st.invoices.iter().filter(|(k, i)| !i.retired && (st.book.credited.contains_key(*k) || st.book.funded(k) || i.expires_at >= t))
            .map(|(k, _)| k.clone()).collect();
        v.sort();
        v
    }

    /// A copy of the receipt book.
    pub fn book(&self) -> ReceiptBook {
        self.lock().book.clone()
    }

    /// Offer a receipt to the book (from the relay, the Prime, or a payer): the newly credited work.
    pub fn accept(&self, s: &Signed) -> Result<u64> {
        let mut st = self.lock();
        if !st.invoices.contains_key(&s.receipt.invoice) {
            return fail("unknown_invoice", "not an invoice this provider issued");
        }
        let r = st.book.accept(s, &s.receipt.invoice.clone());
        self.save(&st)?;
        r
    }

    /// Pull the latest receipt of every live invoice through the blinded relay (§11.1) and credit
    /// it: returns (invoice, newly credited work) for each receipt that verified.
    pub fn refresh(&self, t: &dyn Transport) -> Vec<(String, Result<u64>)> {
        let Some(relay) = self.cfg.relay_url.clone() else { return vec![] };
        let mut out = vec![];
        for inv in self.invoices() {
            let r = crate::relay::fetch(t, &relay, &self.cfg.identity, &inv).and_then(|doc| match doc {
                None => Ok(0),
                Some(d) => {
                    let s = Signed::from_doc(&d).map_err(WorkError::from)?;
                    if s.receipt.invoice != inv {
                        return fail("wrong_invoice", "relay blob holds another invoice");
                    }
                    self.accept(&s)
                }
            });
            out.push((inv, r));
        }
        out
    }

    /// §10.3 for one pool coinbase: records the verdict (and the carry it defers or releases). Auditing
    /// a block again (more receipts, the statement's lines fetched again) replaces its earlier verdict
    /// and carry, so nothing is counted twice. A pass covers every credit with shares below the block
    /// (§13.1): held work is credited as far as the caps then allow.
    pub fn audit(&self, sw: &SignedWindow, deferred: &[SignedDeferral], coinbase_value_sats: u64, paid_sats: u64) -> Result<AuditOutcome> {
        let mut st = self.lock();
        let o = audit_block(&st.book, sw, coinbase_value_sats, paid_sats, deferred)?;
        st.carry.record(sw.stmt.height, &o);
        let mut released = 0;
        if !o.ok && st.distrust.is_none() {
            st.distrust = Some(("wrong_prime".into(), format!("the Prime's coinbase at height {} failed the audit", sw.stmt.height)));
        }
        self.carry_rules(&mut st);
        if o.ok {
            released = st.book.audited(sw.stmt.height);
            st.book.release_held();
        }
        let mut rec = obj([("height", sw.stmt.height.into()), ("blockHash", sw.stmt.block_hash.clone().into()), ("ok", o.ok.into()),
                           ("expectedSats", o.expected_sats.into()), ("paidSats", paid_sats.into()), ("deferredSats", o.deferred_sats.into()),
                           ("provenWork", o.proven_work.into()), ("coveredWork", released.into()),
                           ("owedCarrySats", st.carry.owed().into())]);
        if let Some(p) = &o.proof {
            rec["proof"] = p.clone();
        }
        let (h, hash) = (u64::from(sw.stmt.height), sw.stmt.block_hash.as_str());
        st.audits.retain(|a| !(a.get("height").and_then(Value::as_u64) == Some(h) && a.get("blockHash").and_then(Value::as_str) == Some(hash)));
        st.audits.push(rec);
        self.save(&st)?;
        Ok(o)
    }

    pub fn carry(&self) -> CarryLedger {
        self.lock().carry.clone()
    }

    /// Audit log, equivocations and carry, as JSON.
    pub fn report(&self) -> Value {
        let st = self.lock();
        let caps = |c: Option<u64>| c.map(Value::from).unwrap_or(Value::Null);
        let credit = obj([("unauditedWork", st.book.unaudited_work(None).into()), ("heldWork", st.book.held_total().into()),
                          ("capInvoiceWork", caps(st.book.caps.per_invoice)), ("capTotalWork", caps(st.book.caps.total)),
                          ("maxOwedCarrySats", caps(self.cfg.max_owed_carry_sats)),
                          ("frozen", st.book.frozen.clone().map(Value::from).unwrap_or(Value::Null))]);
        obj([("audits", st.audits.clone().into()), ("carry", st.carry.to_json()), ("credit", credit),
             ("distrust", st.distrust.as_ref().map(|(c, m)| obj([("code", c.clone().into()), ("why", m.clone().into())])).unwrap_or(Value::Null)),
             ("equivocations", st.book.fraud.iter().map(|e| e.to_json()).collect::<Vec<_>>().into()),
             ("intervals", st.book.to_json()["intervals"].clone())])
    }

    // --- durable state ------------------------------------------------------------------------

    fn save(&self, st: &State) -> Result<()> {
        let Some(path) = &self.cfg.state_path else { return Ok(()) };
        let inv: serde_json::Map<String, Value> = st.invoices.iter().map(|(k, i)| {
            (k.clone(), obj([("key", hex::encode(i.key).into()), ("n", i.n.into()), ("spent", i.spent.into()),
                             ("expiresAt", i.expires_at.into()), ("retired", i.retired.into())]))
        }).collect();
        let doc = obj([("version", 1.into()), ("identity", self.cfg.identity.clone().into()), ("invoices", Value::Object(inv)),
                       ("book", st.book.to_json()), ("audits", st.audits.clone().into()),
                       ("carry", obj([("deferred", st.carry.deferred_total.into()), ("released", st.carry.released_total.into()),
                                      ("blocks", st.carry.blocks.iter().map(|(h, e, p, d)| Value::from(vec![Value::from(*h), Value::from(*e), Value::from(*p), Value::from(*d)])).collect::<Vec<_>>().into())])),
                       ("distrust", st.distrust.as_ref().map(|(c, m)| Value::from(vec![c.clone(), m.clone()])).unwrap_or(Value::Null))]);
        crate::fsx::write_private(path, dumps(&doc).as_bytes()).map_err(|e| WorkError::new("state_io", e.to_string()))
    }

    fn load(&self) -> Result<()> {
        let Some(path) = &self.cfg.state_path else { return Ok(()) };
        let Ok(raw) = std::fs::read(path) else { return Ok(()) };
        let bad = |w: &str| WorkError::new("bad_state", w.to_string());
        let v = xbt402::json::parse_slice(&raw).map_err(|_| bad("not JSON"))?;
        if v.get("identity").and_then(Value::as_str) != Some(self.cfg.identity.as_str()) {
            return Err(bad("state is for another identity"));
        }
        let mut st = self.lock();
        for (k, i) in v.get("invoices").and_then(Value::as_object).into_iter().flatten() {
            let key: [u8; 32] = i.get("key").and_then(Value::as_str).and_then(|h| hex::decode(h).ok()).and_then(|b| b.try_into().ok())
                .ok_or_else(|| bad("invoice key"))?;
            let u = |f: &str| i.get(f).and_then(Value::as_u64).ok_or_else(|| bad(f));
            st.invoices.insert(k.clone(), Invoice { key, n: u("n")?, spent: u("spent")?, expires_at: u("expiresAt")?,
                                                   retired: i.get("retired").and_then(Value::as_bool).unwrap_or(false) });
        }
        if let Some(b) = v.get("book") {
            st.book.load(b)?;
        }
        st.audits = v.get("audits").and_then(Value::as_array).cloned().unwrap_or_default();
        st.carry.deferred_total = v.pointer("/carry/deferred").and_then(Value::as_u64).unwrap_or(0);
        st.carry.released_total = v.pointer("/carry/released").and_then(Value::as_u64).unwrap_or(0);
        for b in v.pointer("/carry/blocks").and_then(Value::as_array).into_iter().flatten() {
            let f = |j: usize| b.get(j).and_then(Value::as_u64).ok_or_else(|| bad("carry block"));
            st.carry.blocks.push((f(0)? as u32, f(1)?, f(2)?, f(3)?));
        }
        st.distrust = v.get("distrust").and_then(Value::as_array).and_then(|a| Some((a.first()?.as_str()?.to_string(), a.get(1)?.as_str()?.to_string())));
        Ok(())
    }

    // --- §9.1 ----------------------------------------------------------------------------------

    /// The checks of §9.1 and the debit of §9.2 step 1. Err: (short code, `work` detail).
    fn check_and_debit(&self, pp: &Value, method: &str, path: &str, body: &[u8], amount: u64)
                       -> std::result::Result<WorkCharge, (String, Option<Value>)> {
        let refuse = |c: &str| Err((c.to_string(), None));
        // 1. version, scheme, network, payTo
        let acc = pp.get("accepted").filter(|a| a.is_object());
        let s = |v: Option<&Value>, k: &str| v.and_then(|a| a.get(k)).and_then(Value::as_str).map(str::to_string);
        if pp.get("x402Version").and_then(Value::as_u64) != Some(2) || s(acc, "scheme").as_deref() != Some(SCHEME)
            || s(acc, "network").as_deref() != Some(self.cfg.network.as_str()) || s(acc, "payTo").as_deref() != Some(self.cfg.identity.as_str())
        {
            return refuse("unsupported_scheme_or_network");
        }
        // 2. every field in its grammar, sig 64 bytes of hex, n an integer, auth a string
        let pl = pp.get("payload").filter(|p| p.is_object());
        let parsed = (|| -> Option<(WorkReceipt, [u8; 64], u64, String)> {
            let pl = pl?;
            let r = WorkReceipt::from_doc(pl.get("receipt")?).ok()?;
            Some((r, sig64(pl.get("sig")).ok()?, uint(pl.get("n"), U64, "n").ok()?, pl.get("auth")?.as_str()?.to_string()))
        })();
        let Some((r, sig, n, auth)) = parsed else { return refuse("bad_payload") };
        // 3. identity and Prime
        if r.identity != self.cfg.identity {
            return refuse("wrong_identity");
        }
        if r.prime_id != self.cfg.prime_id {
            return refuse("wrong_prime");
        }
        let mut st = self.lock();
        let t = now();
        let State { invoices, book, .. } = &mut *st;
        // 4. issued here, not expired (unfunded), not retired
        let funded = book.funded(&r.invoice);
        let Some(inv) = invoices.get_mut(&r.invoice).filter(|i| !i.retired && (funded || i.expires_at >= t)) else {
            return refuse("unknown_invoice");
        };
        // 5. auth over this request and receipt state, n fresh; n is consumed from here on
        let req = request_digest(method, path, body);
        let want = auth_tag(&inv.key, &r.invoice, n, r.seq, r.cum_work, &req).unwrap_or_default();
        if !tag_eq(&want, &auth) || n <= inv.n {
            return refuse("bad_auth");
        }
        inv.n = n;
        // a Prime key that equivocated or failed an audit is no longer trusted
        if let Some((code, _)) = &st.distrust {
            let code = code.clone();
            let _ = self.save(&st);
            return Err((code, None));
        }
        let State { invoices, book, distrust, .. } = &mut *st;
        // 6-8. signature, equivocation, delta credit
        let invoice = r.invoice.clone();
        let delta = match book.accept(&Signed { receipt: r, sig }, &invoice) {
            Ok(d) => d,
            Err(e) => {
                if e.code == "equivocation" {
                    *distrust = Some(("equivocation".into(), e.msg.clone()));
                }
                let _ = self.save(&st);
                let code = if e.code == "wrong_invoice" { "unknown_invoice".to_string() } else { e.code };
                return Err((code, None));
            }
        };
        let credited = book.credited.get(&invoice).copied().unwrap_or(0);
        let seq = book.best(&invoice).map(|b| b.receipt.seq).unwrap_or(0);
        let inv = invoices.get_mut(&invoice).expect("checked above");
        // 9. billing
        if credited.saturating_sub(inv.spent) < amount {
            let held = book.held(&invoice);
            let mut work = obj([("invoice", invoice.clone().into()), ("creditedWork", credited.to_string().into()),
                                ("spentWork", inv.spent.to_string().into())]);
            // §13.1: receipted work the caps hold back would have paid: say why, and what is held
            let code = if held > 0 {
                work["heldWork"] = held.to_string().into();
                work["unauditedWork"] = book.unaudited_work(Some(&invoice)).to_string().into();
                work["unauditedTotalWork"] = book.unaudited_work(None).to_string().into();
                if let Some(c) = book.caps.per_invoice {
                    work["capInvoiceWork"] = c.to_string().into();
                }
                if let Some(c) = book.caps.total {
                    work["capTotalWork"] = c.to_string().into();
                }
                book.frozen.clone().unwrap_or_else(|| "credit_cap".into())
            } else {
                "insufficient_work".into()
            };
            let _ = self.save(&st);
            return Err((code, Some(work)));
        }
        inv.spent += amount;
        let spent = inv.spent;
        // recorded before the handler runs (§9.2 step 1); a failed write refuses the call
        if self.save(&st).is_err() {
            let inv = st.invoices.get_mut(&invoice).expect("checked above");
            inv.spent -= amount;
            return Err(("state_io".into(), None));
        }
        Ok(WorkCharge { invoice, amount, delta, credited, spent, seq, n, req, network: self.cfg.network.clone(), provider: None })
    }
}

/// A debited call, settled after the handler (§9.2, §9.3).
pub struct WorkCharge {
    invoice: String,
    amount: u64,
    delta: u64,
    credited: u64,
    spent: u64,
    seq: u64,
    n: u64,
    req: String,
    network: String,
    provider: Option<std::sync::Arc<WorkProvider>>,
}

impl WorkCharge {
    fn response(&self, charged: u64, spent: u64, success: bool) -> Value {
        let receipt = obj([("scheme", SCHEME.into()), ("invoice", self.invoice.clone().into()), ("seq", self.seq.into()), ("n", self.n.into()),
                           ("newlyCreditedWork", self.delta.to_string().into()), ("creditedWork", self.credited.to_string().into()),
                           ("spentWork", spent.to_string().into()), ("balanceWork", self.credited.saturating_sub(spent).to_string().into()),
                           ("charged", charged.to_string().into()), ("req", self.req.clone().into())]);
        settlement_response(&receipt, &self.network, &self.invoice, success)
    }
}

impl SchemeCharge for WorkCharge {
    fn settle(self: Box<Self>, status: u16) -> Value {
        if status >= 500 {
            // not charged: release the debit
            let spent = match &self.provider {
                Some(p) => {
                    let mut st = p.lock();
                    let s = st.invoices.get_mut(&self.invoice).map(|i| {
                        i.spent = i.spent.saturating_sub(self.amount);
                        i.spent
                    });
                    let _ = p.save(&st);
                    s.unwrap_or(self.spent - self.amount)
                }
                None => self.spent - self.amount,
            };
            return self.response(0, spent, false);
        }
        self.response(self.amount, self.spent, status < 400)
    }
}

/// The scheme as an xbt402 Provider sees it. Wrap the rail in an `Arc` to share it with the
/// relay-refresh and audit loops.
pub struct WorkScheme(pub std::sync::Arc<WorkProvider>);

impl ProviderScheme for WorkScheme {
    fn scheme(&self) -> &str {
        SCHEME
    }

    fn requirements(&self, _method: &str, _path: &str, price_sats: u64) -> Option<Value> {
        self.0.amount(price_sats).ok().map(|a| self.0.requirements_for(a, price_sats))
    }

    fn control(&self, method: &str, path: &str, _headers: &[(String, String)], _body: &[u8]) -> Option<HttpResponse> {
        if path.split('?').next() != Some(INVOICE_PATH) {
            return None;
        }
        let json = |status: u16, v: &Value| HttpResponse::new(status, vec![("Content-Type".into(), "application/json".into()),
                                                                           ("Cache-Control".into(), "no-store".into())], dumps(v));
        if method != "POST" && method != "GET" {
            return Some(HttpResponse::new(405, vec![], b"method not allowed".to_vec()));
        }
        Some(match self.0.issue_invoice() {
            Ok(doc) => json(200, &doc),
            Err(e) if e.code == "too_many_invoices" => json(429, &obj([("error", "too_many_invoices".into())])),
            Err(e) => json(500, &obj([("error", e.code.into())])),
        })
    }

    fn authorize(&self, payment: &Value, method: &str, path: &str, body: &[u8], price_sats: u64, url: &str)
                 -> std::result::Result<Box<dyn SchemeCharge>, Value> {
        let amount = match self.0.amount(price_sats) {
            Ok(a) => a,
            Err(_) => return Err(self.0.refusal(url, 1, price_sats, "bad_pricing", None)),
        };
        match self.0.check_and_debit(payment, method, path, body, amount) {
            Ok(mut c) => {
                c.provider = Some(self.0.clone());
                Ok(Box::new(c))
            }
            Err((code, work)) => Err(self.0.refusal(url, amount, price_sats, &code, work)),
        }
    }
}
