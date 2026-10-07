//! AGP-053: make-before-break ch2 rollover (a port of B1 `tests/security/test_agp053_make_before_break.py`),
//! in process: [`MemChain`] + [`MemNet`]. The hub opens the rollover's next ch2 at once, unconfirmed,
//! where the provider takes it (the child of its own confirmed hub-bound channel, below a cap and
//! before the parent's close margin), so routing to that provider never pauses for a block.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::{self, Sc};
use xbt402::channel::{ChannelParams, FeePayer};
use xbt402::funding::FundingPolicy;
use xbt402::hub::{HubConfig, OutChannel, RouteHub, ROLLOVER_GONE};
use xbt402::ledger::{ChannelState, Ledger};
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::*;
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402::wire::{hub_channel_message, OPEN_PATH};
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::address::segwit_address;
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";
const ORIGIN: &str = "http://p0.test";

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp053-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    prov: Arc<Provider>,
    pay: Arc<RoutePayer>,
    sh: Arc<Shard>,
    _dir: TempDir,
}

/// One provider (settle_multiple 2, 40 sat a call, `zc_max` its zero-conf cap), a hub (`zc` its
/// zero_conf_rollover), a payer with ch1 open.
fn world(zc_max: Option<u64>, zc: bool) -> W {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let mut hc = HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500,
                                              "delta": 36, "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000,
                                              "close_margin": 36,
                                              "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap();
    hc.zero_conf_rollover = zc;
    let hub = Arc::new(RouteHub::new(chain.clone(), chain.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                     sk(0x4B4B), NET, Some(&dir.0.join("hub")), hc).unwrap());
    net.add(HUB, hub.clone());
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.settle_multiple = 2;
    cfg.height_ttl = Duration::ZERO;
    cfg.route_close_fee_payer = FeePayer::Payee;
    cfg.rollover_zero_conf_max = zc_max;
    let ledger = Ledger::open(&dir.0.join("prov.jsonl")).unwrap();
    let prov = Arc::new(Provider::new(chain.clone(), adaptor::random_secret(), cfg, ledger, Box::new(|_, _| 1000),
                                      Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap());
    prov.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", 40 * AMSAT_PER_SAT) });
    net.add(ORIGIN, prov.clone());
    hub.connect(ORIGIN, None, None).unwrap();
    chain.confirm_all();
    hub.watch_tick();
    let mut pc = RoutePayerConfig::new(NET);
    pc.expiry_blocks = 8_000;
    let c = chain.clone();
    let pay = Arc::new(RoutePayer::new(HUB, pc, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                       Box::new(move || Ok(c.height()))));
    pay.open().unwrap();
    let sh = pay.shard(&format!("{ORIGIN}/v1/chunk"), "POST").unwrap();
    W { chain, net, hub, prov, pay, sh, _dir: dir }
}

impl W {
    fn oc(&self) -> OutChannel {
        self.hub.out_channels()[ORIGIN].clone()
    }

    fn lock(&self, calls: usize) -> Value {
        for _ in 0..calls {
            let r = self.pay.call(&self.sh, "POST", br#"{"tokens":1}"#).unwrap();
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        }
        self.pay.lock(&self.sh).unwrap().unwrap()
    }

    /// Stream to the provider's threshold and let the watcher roll ch2 over: (parent, child).
    fn roll(&self) -> (OutChannel, OutChannel) {
        let parent = self.oc();
        assert_eq!(self.lock(50)["status"], "paid");
        let acts = self.hub.watch_tick();
        assert!(acts.iter().any(|a| a["event"] == "ch2_rollover"), "{acts:?}");
        (parent, self.oc())
    }

    fn child_st(&self, child: &OutChannel) -> ChannelState {
        self.prov.channel_state(&child.params.channel_id()).unwrap()
    }

    fn hub_refused(&self, code: &str) -> u64 {
        self.hub.stats.lock().unwrap().refused.get(code).copied().unwrap_or(0)
    }

    fn set_hub_zc(&self, k: &str, v: Value) {
        self.hub.with_out(|b| {
            b.chans.get_mut(ORIGIN).unwrap().zero_conf.insert(k.into(), v);
        });
    }

    fn events(&self, kind: &str) -> Vec<Value> {
        self.hub.events.lock().unwrap().iter().filter(|e| e["event"] == kind).cloned().collect()
    }
}

fn evs(acts: &[Value]) -> Vec<String> {
    acts.iter().map(|a| a["event"].as_str().unwrap_or("").to_string()).collect()
}

#[test]
fn child_is_open_at_once_and_routing_never_pauses() {
    let w = world(None, true);
    let (parent, child) = w.roll();
    assert_eq!(child.state, "open");
    assert_eq!(child.rolled_from, parent.params.channel_id());
    assert_eq!(Value::Object(child.zero_conf.clone()),
               json!({"parent": parent.params.channel_id(), "maxCum": 2 * 2 * 600, "until": parent.params.expiry - 36, "confirmed": false}));
    let zc = w.child_st(&child).extra["zero_conf"].clone();
    assert_eq!((zc["parent"].clone(), zc["maxCum"].clone(), zc["confirmed"].clone()), (json!(parent.params.channel_id()), json!(2400), json!(false)));
    assert!(w.events("ch2_open").iter().any(|e| e["chan"] == child.params.channel_id().as_str() && e["zeroConf"] == 2400));
    for _ in 0..3 {
        assert_eq!(w.lock(5)["status"], "paid"); // no block: over the unconfirmed child
    }
    assert!(w.child_st(&child).best_cum > 0);
    assert!(w.hub.stats.lock().unwrap().refused.is_empty());
    assert!(w.hub.routing_extra().unwrap()["providers"].as_array().unwrap().contains(&json!(ORIGIN)));
    w.chain.confirm_all();
    assert!(evs(&w.hub.watch_tick()).contains(&"ch2_zero_conf_confirmed".to_string()));
    w.prov.close_due().unwrap();
    assert_eq!(w.child_st(&child).extra["zero_conf"]["confirmed"], true);
    assert_eq!(w.lock(5)["status"], "paid");
}

#[test]
fn child_is_not_rolled_over_before_it_confirms() {
    let w = world(None, true);
    let (_, child) = w.roll();
    assert_eq!(w.lock(20)["status"], "paid"); // 800 sat on the child
    w.hub.with_out(|b| b.chans.get_mut(ORIGIN).unwrap().signed = 2_000); // past the provider's threshold
    assert!(!evs(&w.hub.watch_tick()).contains(&"ch2_rollover".to_string()));
    let e = w.hub.rollover(&w.oc()).unwrap_err(); // and the provider would refuse it
    assert_eq!(e.code, "unconfirmed");
    assert!(w.oc().next.is_empty());
    let best = w.child_st(&child).best_cum;
    w.hub.with_out(|b| b.chans.get_mut(ORIGIN).unwrap().signed = best);
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.oc().zero_conf["confirmed"], true);
}

#[test]
fn hub_caps_the_child_below_the_providers_zero_conf_max() {
    let w = world(None, true);
    w.roll();
    let n_lock = w.net.count(ROUTE_LOCK_PATH);
    let r = w.lock(70); // 2,800 sat > the 2,400 cap
    assert_eq!(r["error"], "route_blocked", "{r}");
    assert_eq!(w.net.count(ROUTE_LOCK_PATH), n_lock, "the hub sent a lock past the provider's cap");
    assert!(w.oc().pending.is_empty());
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.lock(1)["status"], "paid"); // confirmed: no cap
}

#[test]
fn provider_enforces_its_cap_and_margin_itself() {
    let w = world(None, true);
    let (_, child) = w.roll();
    w.set_hub_zc("maxCum", json!(1_000_000_000u64)); // a hub that ignores the cap
    let r = w.lock(70);
    assert_eq!(r["error"], "route_failed", "{r}");
    assert_eq!(w.hub_refused("zero_conf_cap"), 1);
    // at the parent's close margin the provider takes nothing more on the unconfirmed child (here
    // parent and child expire together, so the margin is moved rather than the tip)
    let h = w.chain.height();
    w.prov.with_state(&child.params.channel_id(), |st| {
        let mut zc = st.extra["zero_conf"].clone();
        zc["until"] = h.into();
        st.extra.insert("zero_conf".into(), zc);
    }).unwrap();
    w.set_hub_zc("until", json!(1_000_000_000u64));
    assert_eq!(w.lock(1)["error"], "route_failed");
    assert_eq!(w.hub_refused("unconfirmed"), 1);
}

#[test]
fn hub_stops_at_the_parents_close_margin() {
    let w = world(None, true);
    w.roll();
    w.set_hub_zc("until", json!(w.chain.height()));
    let r = w.lock(5);
    assert_eq!(r["error"], "route_blocked", "{r}");
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.lock(5)["status"], "paid");
}

#[test]
fn reorg_across_the_switch() {
    let w = world(None, true);
    let (parent, child) = w.roll();
    assert_eq!(w.lock(5)["status"], "paid");
    w.chain.confirm_all();
    w.hub.watch_tick();
    w.prov.close_due().unwrap();
    assert_eq!(w.oc().zero_conf["confirmed"], true);
    // the block with the rollover is reorged out: back in the mempool, the parent unspent in blocks
    w.chain.unconfirm(&child.params.funding_txid());
    assert!(evs(&w.hub.watch_tick()).contains(&"ch2_zero_conf_reorg".to_string()));
    assert_eq!(w.oc().zero_conf["confirmed"], false);
    w.prov.close_due().unwrap();
    let st = w.child_st(&child);
    assert_eq!((st.extra["zero_conf"]["confirmed"].clone(), st.suspended), (json!(false), false));
    assert_eq!(w.lock(5)["status"], "paid"); // under the cap again, still routing
    // the parent itself reorged out: the child is no longer taken, by either side
    w.chain.unconfirm(&parent.params.funding_txid());
    w.prov.close_due().unwrap();
    assert!(w.child_st(&child).suspended);
    let r = w.lock(5);
    assert_eq!(r["error"], "route_failed", "{r}");
    assert_eq!(w.hub_refused("unconfirmed"), 1);
}

#[test]
fn vanished_rollover_blocks_until_it_is_back() {
    let w = world(None, true);
    let (_, child) = w.roll();
    let txid = child.params.funding_txid();
    w.chain.evict(&txid); // it left every mempool
    assert!(evs(&w.hub.watch_tick()).contains(&"ch2_rollover_vanished".to_string()));
    let c = w.oc();
    assert_eq!((c.state.as_str(), c.blocked.as_str(), c.final_), ("open", ROLLOVER_GONE, false));
    assert_eq!(w.lock(5)["error"], "route_blocked");
    w.prov.close_due().unwrap(); // the provider sends its rollover again
    assert!(w.chain.raw(&txid).is_some());
    assert!(evs(&w.hub.watch_tick()).contains(&"ch2_rollover_back".to_string()));
    assert_eq!(w.oc().blocked, "");
    w.prov.close_due().unwrap();
    assert_eq!(w.lock(5)["status"], "paid");
}

#[test]
fn replaced_rollover_drops_the_child() {
    let w = world(None, true);
    let (parent, child) = w.roll();
    assert_eq!(w.lock(5)["status"], "paid");
    w.chain.evict(&child.params.funding_txid());
    let close = w.prov.best_close_hex(&parent.params.channel_id()).unwrap(); // the provider closes the parent instead
    let spender = xbt402::funding::ChainBackend::send_raw_transaction(w.chain.as_ref(), &close).unwrap();
    w.chain.confirm_all();
    let acts = w.hub.watch_tick();
    let ev = acts.iter().find(|a| a["event"] == "ch2_rollover_replaced").expect("replaced").clone();
    assert_eq!((ev["spender"].clone(), ev["parent"].clone()), (json!(spender), json!(parent.params.channel_id())));
    let c = w.oc();
    assert_eq!((c.state.as_str(), c.final_), ("dropped", true));
    assert_eq!(w.lock(5)["error"], "route_blocked");
    assert!(!w.hub.routing_extra().unwrap()["providers"].as_array().unwrap().contains(&json!(ORIGIN)));
    w.hub.connect(ORIGIN, None, None).unwrap(); // a new ch2 for that payTo
    assert_eq!(w.oc().state, "funded");
}

#[test]
fn lost_rollover_reply_child_opened_by_the_watcher() {
    let w = world(None, true);
    let parent = w.oc();
    assert_eq!(w.lock(50)["status"], "paid");
    w.net.set_drop(ORIGIN, Some(Box::new(|_, p| p == ROLLOVER_PATH)));
    w.hub.watch_tick(); // broadcast by the provider, answer lost
    w.net.set_drop(ORIGIN, None);
    w.hub.watch_tick(); // the watcher finishes the rollover
    let child = w.oc();
    assert_eq!((child.state.as_str(), child.rolled_from.as_str()), ("funded", parent.params.channel_id().as_str()));
    let acts = w.hub.watch_tick(); // and opens it unconfirmed
    assert!(acts.contains(&json!({"event": "ch2_open", "provider": ORIGIN, "zeroConf": true})), "{acts:?}");
    assert_eq!(w.oc().state, "open");
    assert_eq!(w.lock(5)["status"], "paid");
}

/// A hub-signed /open request for `p` (funded), bound to the hub key `hub`.
fn open_req(p: &ChannelParams, hub: &SecretKey) -> Value {
    json!({"x402Version": 2, "network": NET,
           "channel": {"txid": p.funding_txid(), "vout": p.funding_vout(), "capacity": p.capacity, "expiry": p.expiry,
                       "payerPub": hex::encode(p.payer_pub), "payerSpk": hex::encode(&p.payer_spk), "redeemScript": hex::encode(p.script()),
                       "closeFeePayer": "payee"},
           "hub": {"payTo": hex::encode(ecdsa::pubkey(hub)), "sig": hex::encode(ecdsa::sign(hub, &hub_channel_message(&p.channel_id())))}})
}

#[test]
fn unrelated_unconfirmed_channel_is_refused() {
    let w = world(None, true);
    let pay_to = hex::decode(w.prov.pay_to()).unwrap();
    let p = ChannelParams::derive(&pay_to, &ecdsa::pubkey(&sk(77)), w.chain.height() + 1000, 600, None, NET, FeePayer::Payee).unwrap();
    let (txid, vout) = w.chain.fund_with(&segwit_address("bcrt", &p.spk()).unwrap(), 50_000, 0).unwrap();
    let p = p.with_funding(&txid, vout, 50_000).unwrap();
    assert_eq!(w.prov.open(&open_req(&p, &sk(0x4B4B))).unwrap_err().code, "unconfirmed");
}

#[test]
fn child_is_taken_only_under_the_parents_hub() {
    let w = world(None, false);
    let (_, child) = w.roll();
    assert_eq!(child.state, "funded"); // hub off: break-before-make
    assert_eq!(w.prov.open(&open_req(&child.params, &sk(0x5151))).unwrap_err().code, "unconfirmed");
    let r = w.prov.open(&open_req(&child.params, &sk(0x4B4B))).unwrap();
    assert_eq!(r["zeroConf"]["maxCum"], "2400");
    assert_eq!(r["confirmations"], 0);
}

#[test]
fn break_before_make_when_the_provider_wants_confirmations() {
    let w = world(Some(0), true);
    let (_, child) = w.roll();
    assert_eq!((child.state.as_str(), child.zero_conf.is_empty()), ("funded", true));
    assert_eq!(w.lock(5)["error"], "route_blocked"); // the pre-AGP-053 gap
    let n_open = w.net.count(OPEN_PATH);
    w.hub.watch_tick(); // tried once a block, not again
    assert_eq!(w.net.count(OPEN_PATH), n_open);
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!((w.oc().state.as_str(), w.oc().zero_conf.is_empty()), ("open", true));
    assert_eq!(w.lock(5)["status"], "paid");
}

#[test]
fn hub_config_off_is_break_before_make() {
    let w = world(None, false);
    let n_open = w.net.count(OPEN_PATH);
    let (_, child) = w.roll();
    assert_eq!(child.state, "funded");
    assert_eq!(w.net.count(OPEN_PATH), n_open);
    assert!(HubConfig::from_json(&json!({"zero_conf_rollover": "yes"})).is_err());
    assert!(!HubConfig::from_json(&json!({"zero_conf_rollover": false})).unwrap().zero_conf_rollover);
}
