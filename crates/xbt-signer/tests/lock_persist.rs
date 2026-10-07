//! AGP-055: the lock path writes only what changed, and a crash at any durable step of a lock loses
//! nothing signed (mirrors B2 `tests/test_agp055_lock_persist.py`).
//!
//! Every write, fsync, rename and truncate of a routed lock (`xbt402_sign_state_adaptor` +
//! `xbt402_resolve_lock` on a full signer: sealed keys, signature log, policy engine) is made the
//! last thing the process does, in turn, both cleanly and with the write torn in half
//! ([`xbt_signer::fsx::probe`]). The signer is then started again from its files and checked.
mod common;

use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

use common::*;
use serde_json::{json, Value};
use xbt402::adaptor;
use xbt_primitives::secp256k1::{Scalar, SecretKey};
use xbt_signer::fsx::probe;
use xbt_signer::sigaudit::check_chain;

fn routing_rig() -> Rig {
    let routing = json!({"routing": {"hubs": {PROVIDER: {"max_fee_ppm": 5000, "max_fee_base_msat": 2000}}, "max_lock_sats": 2000,
                                     "daily_budget_sats": 3000}});
    let rig = Rig::build(routing, false, "regtest", None);
    rig.fund_hot(1, 12_000);
    rig.open();
    rig
}

/// Pre-sign one lock; `Ok((its answer, the secret t + r that resolves it))` or the signer's denial.
fn lock(rig: &Rig, chan: &str, cum: i64, amount: i64, fee: i64, id: &str) -> Result<(Value, String), Value> {
    let t = secret(&format!("t-{id}-{cum}"));
    let r = rig.call("xbt402_sign_state_adaptor", json!({"chan": chan, "cum": cum, "point": hex::encode(adaptor::enc(&adaptor::point_of(&t))),
                                                         "route": {"hub": PROVIDER, "amount": amount, "fee": fee, "lockId": id}}));
    if r.get("adaptor").is_none() {
        return Err(r);
    }
    let tweak = SecretKey::from_slice(&hex::decode(r["tweak"].as_str().unwrap()).unwrap()).unwrap();
    let y = hex::encode(t.add_tweak(&Scalar::from(tweak)).unwrap().secret_bytes());
    Ok((r, y))
}

fn resolve(rig: &Rig, chan: &str, y: &str) {
    let r = rig.call("xbt402_resolve_lock", json!({"chan": chan, "secret": y}));
    assert!(r["t"].is_string(), "{r}");
}

fn spent(rig: &Rig) -> i64 {
    rig.call("routing_status", json!({}))["spent_24h_sats"].as_i64().unwrap()
}

fn lock_rows(rig: &Rig) -> usize {
    rig.s.engine.store.payments().unwrap().iter().filter(|p| p.txid.starts_with("lock:")).count()
}

const CUM0: i64 = 1_146;
const CUM1: i64 = 1_446;
const CUM2: i64 = 1_646;

/// A wallet with one resolved lock; the next lock dies at `step`. `Some(durable steps)` when the
/// lock finished instead.
fn one(step: u64, torn: bool) -> Option<probe::Counts> {
    let tag = format!("step {step} torn={torn}");
    let mut rig = routing_rig();
    let chan = rig.s.book.get(PROVIDER).unwrap().chan;
    let (first, y0) = lock(&rig, &chan, CUM0, 594, 6, "L0").unwrap();
    resolve(&rig, &chan, &y0);
    let (spent0, rows0) = (spent(&rig), lock_rows(&rig));
    assert_eq!((spent0, rows0), (600, 1));

    let mut out: Option<(Value, String)> = None;
    probe::crash_at(step, torn);
    let died = catch_unwind(AssertUnwindSafe(|| {
        out = Some(lock(&rig, &chan, CUM1, 295, 5, "L1").unwrap());
        resolve(&rig, &chan, &out.as_ref().unwrap().1);
    }));
    let counts = probe::counts();
    probe::reset();
    let finished = match died {
        Ok(()) => true,
        Err(e) if e.is::<probe::Crash>() => false,
        Err(e) => resume_unwind(e),
    };

    rig.restart().unwrap_or_else(|e| panic!("{tag}: the signer does not start: {}: {}", e.code, e.msg)); // every file loads
    let sig_log = rig.root.join(".run/signatures.jsonl");
    assert_eq!(check_chain(&sig_log, None)["ok"], true, "{tag}");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let pending = rec.has_pending_lock();
    if let Some((o, _)) = &out {
        // a pre-signature left: its record is durable
        assert!(rec.used_sats == CUM1 || rec.pending_lock["pre"] == o["adaptor"], "{tag}");
    }
    if pending {
        // a pending lock is whole, and logged; never a second pre-signature for its state
        let lk = &rec.pending_lock;
        assert_eq!((lk["cum"].as_i64(), rec.used_sats), (Some(CUM1), CUM0), "{tag}");
        let pt = |k: &str| xbt_primitives::secp256k1::PublicKey::from_slice(&hex::decode(lk[k].as_str().unwrap()).unwrap()).unwrap();
        let r = SecretKey::from_slice(&hex::decode(lk["r"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(pt("T").combine(&adaptor::point_of(&r)).unwrap(), pt("T1"), "{tag}");
        assert!(rig.sigs().iter().any(|x| x["kind"] == "adaptor_presig" && x["cum"] == CUM1), "{tag}");
        assert_eq!(lock(&rig, &chan, CUM1, 295, 5, "again").unwrap_err()["rule"], "lock_outstanding", "{tag}");
    } else if rec.used_sats != CUM1 {
        assert_eq!(rec.used_sats, CUM0, "{tag}: nothing happened");
    }
    if finished {
        assert_eq!((rec.used_sats, pending), (CUM1, false), "{tag}");
    }
    // a resolve that reached disk is booked exactly once in both budgets, whether the rows were
    // written before the crash or by the restart; nothing else is booked
    let want = if rec.used_sats == CUM1 { (300, 1) } else { (0, 0) };
    assert_eq!((spent(&rig) - spent0, lock_rows(&rig) - rows0), want, "{tag}");
    rig.restart().unwrap();
    assert_eq!((rig.s.routing.recovered_bookings, spent(&rig) - spent0, lock_rows(&rig) - rows0), (0, want.0, want.1), "{tag}: a second start books nothing more");

    // the wallet goes on: finish or give up the lock; no nonce and no tweak is used twice
    let mut pres = vec![first];
    if pending {
        match &out {
            Some((_, y)) => resolve(&rig, &chan, y),
            None => assert_eq!(rig.call("xbt402_void_lock", json!({"chan": chan}))["voided"], true, "{tag}"), // on disk, but it never left
        }
        pres.push(json!({"adaptor": rec.pending_lock["pre"], "tweak": rec.pending_lock["r"]}));
    }
    let (next, y2) = lock(&rig, &chan, CUM2, 196, 4, "L2").unwrap_or_else(|d| panic!("{tag}: {d}"));
    resolve(&rig, &chan, &y2);
    pres.push(next);
    pres.extend(out.map(|(o, _)| o));
    let mut seen = std::collections::HashSet::new();
    for p in &pres {
        seen.insert((p["adaptor"]["R1"].as_str().unwrap().to_string(), p["tweak"].as_str().unwrap().to_string()));
    }
    let (nonces, tweaks): (std::collections::HashSet<_>, std::collections::HashSet<_>) = seen.iter().cloned().unzip();
    assert_eq!((nonces.len(), tweaks.len()), (seen.len(), seen.len()), "{tag}");
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, CUM2, "{tag}");
    assert_eq!(check_chain(&sig_log, None)["ok"], true, "{tag}");
    finished.then_some(counts)
}

#[test]
fn crash_at_every_durable_step_of_a_lock() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    for torn in [false, true] {
        let mut step = 0;
        let total = loop {
            if let Some(c) = one(step, torn) {
                break c;
            }
            step += 1;
        };
        assert_eq!(step, total.steps, "every durable step of the lock was the last one once");
        // 9 fsyncs: signature log 1, policy audit 2, channel records 2 x (file + directory), spend
        // row 1, ledger row 1. 2 renames: the records, twice. The keys file: never.
        assert_eq!((total.syncs, total.renames, total.writes), (9, 2, 7), "torn={torn}");
    }
}

/// The keys file, the approvals file and every row already in the logs stay as they are: a lock
/// writes the records, and one line each to the signature log, the audit log, the spend log and the ledger.
#[test]
fn a_lock_appends_and_rewrites_only_the_records() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = routing_rig();
    let chan = rig.s.book.get(PROVIDER).unwrap().chan;
    let (_, y) = lock(&rig, &chan, CUM0, 594, 6, "L0").unwrap();
    resolve(&rig, &chan, &y);
    let run = rig.root.join(".run");
    let read = |f: &str| std::fs::read(run.join(f)).unwrap();
    let names = ["channel_keys.json", "ledger.json", "routing.json", "ledger.payments.jsonl", "signatures.jsonl", "audit.jsonl", "channels.json"];
    let before: Vec<Vec<u8>> = names.iter().map(|f| read(f)).collect();
    let (_, y) = lock(&rig, &chan, CUM1, 295, 5, "L1").unwrap();
    resolve(&rig, &chan, &y);
    for (f, old) in names.iter().zip(&before) {
        let now = read(f);
        match *f {
            "channel_keys.json" | "ledger.json" => assert_eq!(&now, old, "{f} is not rewritten by a lock"),
            "channels.json" => assert_ne!(&now, old),
            _ => {
                assert!(now.starts_with(old) && now.len() > old.len(), "{f} is appended to");
                let added = now[old.len()..].iter().filter(|&&b| b == b'\n').count();
                assert_eq!(added, if *f == "audit.jsonl" { 2 } else { 1 }, "{f}: lines added by one lock");
            }
        }
    }
}

/// A crash mid-append left a signature line without its newline; the next record must not be glued
/// onto it (the chain check then failed on the damaged line).
#[test]
fn a_torn_signature_line_is_cut_at_start_and_the_chain_holds() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = routing_rig();
    let log = rig.root.join(".run/signatures.jsonl");
    let whole = std::fs::read(&log).unwrap();
    std::fs::write(&log, [whole.as_slice(), b"{\"kind\":\"adaptor_presig\",\"chan\":\"ab"].concat()).unwrap();
    rig.restart().unwrap();
    assert_eq!(std::fs::read(&log).unwrap(), whole, "the torn tail is cut at start");
    let chan = rig.s.book.get(PROVIDER).unwrap().chan;
    lock(&rig, &chan, CUM0, 594, 6, "L0").unwrap();
    assert_eq!(check_chain(&log, None)["ok"], true);
}
