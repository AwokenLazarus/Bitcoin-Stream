#!/usr/bin/env python3
"""AGP-027: vectors from the Python B2 signer (agp-next2 b4f2fe5) for the Rust port.

  vectors/b2_policy.json   the policy decision table: every case is (policy.json, a committed ledger,
                           a payment, human, now) and B2's decision (verdict, rule, reason, residuals,
                           whether an approval token was issued and its expiry); plus normalize_dest,
                           sats_from_xbt, the ed25519 approval messages and sanitize
  vectors/b2_custody.json  files made by B2's own code under a known wrapping key file and a known
                           passphrase: sealed blobs, hot.json (current + retired), hot_utxos.json,
                           channel_keys.json + channels.json, a signature log and its witness store,
                           and (AGP-055) a routed wallet: spend log, ledger + payments log, records.
                           The Rust signer must open all of them (tests/custody_compat.rs)

    B2=~/xbt-rnd/b2 B1_ROOT=~/xbt-rnd/b1 python scripts/gen_b2_signer_vectors.py
    (or XBT402_B1, which is copied into B1_ROOT when B1_ROOT is unset)
(needs `cryptography`; the xbt-063 venv has it). Deterministic except for the random parts of
sealing (salts, nonces) and signatures, which the Rust side only opens and verifies.
"""
import json
import os
import random
import sys
import tempfile
from pathlib import Path

B2 = Path(os.environ.get("B2", Path.home() / "xbt-rnd" / "b2"))
sys.path.insert(0, str(B2))
if not os.environ.get("B1_ROOT", "").strip():
    xbt_b1 = os.environ.get("XBT402_B1", "").strip()
    if xbt_b1:
        os.environ["B1_ROOT"] = xbt_b1

from agentwallet import approval  # noqa: E402
import importlib  # noqa: E402
import agentwallet.sanitize  # noqa: E402,F401
san = sys.modules["agentwallet.sanitize"]
from agentwallet.policy import AuditLog, Payment, PolicyConfig, PolicyEngine, PolicyStore, normalize_dest  # noqa: E402
from agentwallet.signer import sats_from_xbt  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "vectors"
NOW = 1_790_000_000.0
A, B, C = "http://127.0.0.1:33210", "https://api.example:8443", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


def decide(cfg_raw, ledger, pay, human):
    with tempfile.TemporaryDirectory() as d:
        store = PolicyStore(Path(d) / "ledger.json")
        for e in ledger:
            from agentwallet.policy import LedgerEntry
            store.commit(LedgerEntry(dest=e["dest"], amount_sats=e["amount_sats"], ts=NOW - e["age_s"], txid="t", memo=""))
        eng = PolicyEngine(PolicyConfig.from_dict(cfg_raw), store, AuditLog(Path(d) / "audit.jsonl"), clock=lambda: NOW)
        dd = eng.evaluate(Payment(dest=pay["dest"], amount_sats=pay["amount_sats"], memo="m"), human=human).as_dict()
        dd["approval_token"] = dd["approval_token"] is not None
        return dd


def policy_cases():
    rnd = random.Random(27)
    cases = []
    runbook = {"allowlist": [A], "max_per_tx_sats": 1000, "daily_budget_sats": 6000, "weekly_budget_sats": 6000,
               "per_counterparty_cap_sats": 9400, "velocity_max": 20, "velocity_window_s": 3600, "human_threshold_sats": 1000,
               "split_window_s": 0}
    defaults = {"allowlist": [A, B, C.upper()]}
    tight = {"allowlist": [A + "/some/path", B, C], "max_per_tx_sats": "5000", "daily_budget_sats": 20000, "weekly_budget_sats": 30000,
             "per_counterparty_cap_sats": 12000, "velocity_max": 4, "velocity_window_s": 600, "human_threshold_sats": 3000,
             "split_window_s": 300, "approval_ttl_s": 120}
    configs = {"runbook": runbook, "defaults": defaults, "tight": tight}
    dests = [A, A + "/v1/infer?x=1", B, C, C.upper(), "  " + C + "  ", "http://evil.example", "", "https://", "not a url"]
    amounts = [-5, 0, 1, 499, 500, 546, 999, 1000, 1001, 2999, 3000, 4999, 5000, 5001, 9400, 10_000_000, 10_000_001]
    ages = [0, 30, 299, 301, 599, 601, 3599, 3601, 86_399, 86_401, 604_799, 604_801]
    for i in range(600):
        name = rnd.choice(sorted(configs))
        cfg = configs[name]
        ledger = [{"dest": rnd.choice([A, B, C]), "amount_sats": rnd.choice([100, 500, 1000, 2500, 4000]), "age_s": rnd.choice(ages)}
                  for _ in range(rnd.choice([0, 0, 1, 2, 3, 5, 8, 12]))]
        allowed = [normalize_dest(x) for x in cfg["allowlist"]]
        dest = rnd.choice(allowed + [x.upper() if x.startswith("bc") else x + "/p" for x in allowed]) if rnd.random() < 0.75 else rnd.choice(dests)
        pay = {"dest": dest, "amount_sats": rnd.choice(amounts)}
        human = rnd.random() < 0.25
        cases.append({"id": f"r{i}", "config": name, "ledger": ledger, "payment": pay, "human": human,
                      "expect": decide(cfg, ledger, pay, human)})
    # hand-made edges: every rule at its boundary
    edges = [
        ("runbook", [], {"dest": A, "amount_sats": 500}, False),
        ("runbook", [{"dest": A, "amount_sats": 500, "age_s": 10}] * 11, {"dest": A, "amount_sats": 500}, False),
        ("runbook", [{"dest": A, "amount_sats": 500, "age_s": 10}] * 12, {"dest": A, "amount_sats": 500}, False),
        ("runbook", [{"dest": A, "amount_sats": 1, "age_s": 1}] * 20, {"dest": A, "amount_sats": 1}, False),
        ("runbook", [], {"dest": A, "amount_sats": 1000}, False),
        ("runbook", [], {"dest": A, "amount_sats": 1000}, True),
        ("tight", [{"dest": B, "amount_sats": 2000, "age_s": 100}], {"dest": B, "amount_sats": 1000}, False),
        ("tight", [{"dest": B, "amount_sats": 2000, "age_s": 100}], {"dest": B, "amount_sats": 1000}, True),
        ("tight", [{"dest": B, "amount_sats": 4000, "age_s": 100}], {"dest": B, "amount_sats": 1001}, True),
        ("tight", [{"dest": C, "amount_sats": 4000, "age_s": 400}] * 3, {"dest": C, "amount_sats": 1}, False),
        ("tight", [{"dest": C, "amount_sats": 4000, "age_s": 90_000}] * 7, {"dest": C, "amount_sats": 2500}, False),
        ("tight", [{"dest": B, "amount_sats": 4000, "age_s": 400}] * 3, {"dest": B, "amount_sats": 1}, False),
        ("tight", [{"dest": B, "amount_sats": 4000, "age_s": 400}] * 3, {"dest": B, "amount_sats": 1}, True),
        ("tight", [{"dest": B, "amount_sats": 4000, "age_s": 90_000}, {"dest": B, "amount_sats": 4000, "age_s": 400},
                   {"dest": B, "amount_sats": 3000, "age_s": 500}], {"dest": B + "/x", "amount_sats": 1001}, False),
        ("runbook", [{"dest": A, "amount_sats": 1000, "age_s": 5}] * 9 + [{"dest": A, "amount_sats": 400, "age_s": 5}], {"dest": A, "amount_sats": 500}, False),
        ("defaults", [], {"dest": C.upper(), "amount_sats": 10_000_000}, False),
        ("defaults", [], {"dest": C, "amount_sats": 10_000_000}, True),
    ]
    for j, (name, ledger, pay, human) in enumerate(edges):
        cases.append({"id": f"e{j}", "config": name, "ledger": ledger, "payment": pay, "human": human,
                      "expect": decide(configs[name], ledger, pay, human)})
    return configs, cases


def main():
    configs, cases = policy_cases()
    norm = [[d, normalize_dest(d)] for d in ["", "  ", "BCRT1QABC", " bc1QX ", "tb1Q", "http://h:1/x?y#z", "https://h", "https:///x",
                                               "HTTP://h/x", "http://u@h:9", "http://h?q", "ftp://h/x", "x"]]
    def sx(v):
        try:
            return sats_from_xbt(v)
        except ValueError:
            return None  # B2 raises: the request fails
    sats = [[v, sx(v)] for v in ["0", "1", "0.00000546", "0.1", "1.5", "0.123456789", "-1", "12", ".5",
                                 0, 1, 0.5, 1e-05, 2.00000001, "abc", "1.x",
                                 0.00001, "1e-05", 0.00000001, 21e6]]
    msgs = {
        "approve": approval.canonical_message("tok-_A1", C, 5000, 1790000900).hex(),
        "recover": approval.recover_message(C, 1790000900).hex(),
        "sweep": approval.sweep_message(C, "bcrt1qmike", 5200, 1790000900).hex(),
    }
    priv = bytes(range(32))
    pub = approval.Ed25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        approval.Encoding.Raw, approval.PublicFormat.Raw) if hasattr(approval, "Ed25519PrivateKey") else None
    sig = approval.sign(priv, bytes.fromhex(msgs["sweep"]))
    wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    sanitize_in = {"txid": "ab" * 32, "hot_secret": "x", "nested": [{"passphrase": 1, "ok": wif}, "xprv" + "a" * 30 + " tail"],
                   "Cookie": 1, "wifi": 2, san.UNTRUSTED_KEY: {"body": wif, "secret": 1}, "ok": "K" + "1" * 51}
    doc = {"generator": "scripts/gen_b2_signer_vectors.py", "b2": os.popen(f"git -C {B2} rev-parse --short HEAD").read().strip(),
           "now": NOW, "configs": configs, "cases": cases, "normalize_dest": norm, "sats_from_xbt": sats, "messages": msgs,
           "ed25519": {"pub": pub.hex() if pub else "", "sweep_sig": sig.hex()},
           "sanitize": {"in": sanitize_in, "out": san.sanitize(sanitize_in)}}
    (OUT / "b2_policy.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"b2_policy.json: {len(cases)} policy cases")
    custody()


def routed(ks):
    """AGP-055: a wallet directory after routed locks, written by B2's own code: lock L1 resolved and
    booked (spend row, ledger row), L2 resolved in the record but not booked (the crash window between
    the two: the next start books it), L3 pending (written ahead). The Rust signer must open it, book
    L2 once, and resolve L3 (tests/custody_compat.rs). Times are fixed in 2100 so that the rows stay
    inside the 7 day spend window however old this file gets."""
    import time
    from agentwallet.channels import ChannelBook
    from agentwallet.policy import AuditLog, PolicyConfig, PolicyEngine, PolicyStore
    from agentwallet.routing import RoutePolicy, RouteSigner, adaptor_mod
    from xbt402.channel import ChannelParams
    from xbt402 import ecc
    from xbt402.x402_channel import network_id
    A = adaptor_mod()
    hub = "http://127.0.0.1:33211"
    clock, real = [4_102_444_800.0], time.time
    time.time = lambda: clock[0]
    try:
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            book = ChannelBook(d / "channels.json", d / "channel_keys.json", keystore=ks)
            p = ChannelParams.derive(ecc.pubkey(778).hex(), ecc.pubkey(4343).hex(), 7734, 600, "0014" + "ab" * 20,
                                     network=network_id("%064x" % 101))
            p.funding_txid, p.funding_vout, p.capacity = "44" * 32, 0, 100_600
            book.add_funded(hub, secret=4343, params=p, origin=hub, cap_sats=p.max_amount)
            cfg = PolicyConfig(allowlist=frozenset({hub}), velocity_max=100)
            engine = PolicyEngine(cfg, PolicyStore(d / "ledger.json"), AuditLog(d / "audit.jsonl"), clock=lambda: clock[0])
            policy = {"hubs": {hub: {"max_fee_ppm": 5000, "max_fee_base_msat": 2000}}, "max_lock_sats": 20_000,
                      "daily_budget_sats": 50_000}
            rs = RouteSigner(book, RoutePolicy.from_dict(policy), state_path=d / "routing.json", engine=engine)

            def lock(cum, t, lock_id):
                clock[0] += 1
                o = rs.sign_state_adaptor(p.channel_id, cum, A.enc(A.point_of(t)).hex(),
                                          {"hub": hub, "amount": cum - book.get(hub).used_sats - 1, "fee": 1, "lockId": lock_id})
                clock[0] += 1
                return o, "%064x" % ((t + int(o["tweak"], 16)) % A.N)
            _, y1 = lock(1_000, 1111, "L1")
            rs.resolve_lock(p.channel_id, y1)
            _, y2 = lock(1_500, 2222, "L2")
            book.resolve_lock(hub, y2)                    # on disk, and the process dies before its rows
            o3, y3 = lock(1_800, 3333, "L3")
            return {"hub": hub, "chan": p.channel_id, "payer_pub": p.payer_pub, "routing_policy": policy,
                    "channels.json": json.loads((d / "channels.json").read_text()),
                    "channel_keys.json": json.loads((d / "channel_keys.json").read_text()),
                    "routing.json": (d / "routing.json").read_text(),
                    "ledger.json": json.loads((d / "ledger.json").read_text()),
                    "ledger.payments.jsonl": (d / "ledger.payments.jsonl").read_text(),
                    "booked": {"key": "lock:%s:1000" % p.channel_id, "amount": 1000},
                    "unbooked": {"key": "lock:%s:1500" % p.channel_id, "amount": 500},
                    "pending": {"cum": 1800, "amount": 300, "adaptor": o3["adaptor"], "secret": y3, "t": "%064x" % 3333}}
    finally:
        time.time = real


def custody():
    """Files B2 wrote, under a known key file (32 x 0x42) and passphrase."""
    from agentwallet import anchor, keystore, sigaudit
    from agentwallet.channels import ChannelBook
    from agentwallet.hot import HotWallet
    sys.path.insert(0, os.environ["B1_ROOT"])
    from xbt402.channel import ChannelParams
    from xbt402 import ecc
    out = {}
    key = bytes([0x42]) * 32
    ks, kp = keystore.KeyStore(key=key), keystore.KeyStore(passphrase=b"b2 passphrase")
    out["blobs"] = {"keyfile": ks.seal(b"hello rust", "b2/test"), "passphrase": kp.seal(b"hello rust", "b2/test")}
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        hw = HotWallet(d / "hot.json", rpc=None, hrp="bcrt", keystore=ks)
        first = hw.address
        hw._retired.append(hw._current)
        hw._current = type(hw._current)(123456789, "bcrt")
        hw._retired[0].retired_at = 1790000000.25
        hw._persist()
        hw.notice_utxo("11" * 32, 1, 12000, hw.spk.hex())
        hw.notice_utxo("22" * 32, 0, 700, hw._retired[0].spk.hex())
        out["hot"] = {"hot.json": json.loads((d / "hot.json").read_text()), "hot_utxos.json": json.loads((d / "hot_utxos.json").read_text()),
                      "current_address": hw.address, "retired_address": first, "hot_sats": hw.balance_sats()}
        book = ChannelBook(d / "channels.json", d / "channel_keys.json", keystore=ks)
        payee = ecc.pubkey(777).hex()
        secret, payer_pub = 4242, ecc.pubkey(4242).hex()
        from xbt402.x402_channel import network_id
        p = ChannelParams.derive(payee, payer_pub, 7734, 600, hw.spk.hex(), network=network_id("%064x" % 101))
        p.funding_txid, p.funding_vout, p.capacity = "33" * 32, 0, 10000
        book.add_pending("http://127.0.0.1:33210", secret=secret, params=p, origin="http://127.0.0.1:33210", cap_sats=9400,
                         open_height=6720, open_url="http://127.0.0.1:33210/x402/xbt-channel/open", network=network_id("%064x" % 101),
                         min_conf=1, funding_hex="")
        book.mark_open("http://127.0.0.1:33210")
        book.increment("http://127.0.0.1:33210", 500)
        out["channels"] = {"channels.json": json.loads((d / "channels.json").read_text()),
                           "channel_keys.json": json.loads((d / "channel_keys.json").read_text()),
                           "chan": p.channel_id, "state_sig_cum": 546, "state_tx_sighash": p.sighash(p.state_tx(546)).hex(),
                           "payer_pub": payer_pub}
        log = sigaudit.SigAudit(d / "signatures.jsonl")
        with sigaudit.context(method="xbt402_pay", rule="method:xbt402_pay"):
            sigaudit.set_rule("policy:ok")
            log.record("channel_state", sig=b"\x30" * 70, chan=p.channel_id, dest="http://127.0.0.1:33210", cum=546, sighash="0x21")
            log.record("funding", sig=b"\x31" * 71, txid="33" * 32, amount_sats=11400)
        store = anchor.AnchorStore(d / "anchor")
        lines = log.raw_lines()
        import hashlib
        r = store.submit(len(lines), hashlib.sha256(lines[-1]).hexdigest(), [x.decode() for x in lines], "signer_start")
        log.record("close_auth", sig=b"\x32" * 70, chan=p.channel_id, dest="http://127.0.0.1:33210", cum=546)
        out["log"] = {"signatures.jsonl": (d / "signatures.jsonl").read_text(), "anchors.jsonl": (d / "anchor" / "anchors.jsonl").read_text(),
                      "submit": r}
    out["routed"] = routed(ks)
    out["keyfile_hex"] = key.hex()
    out["passphrase"] = "b2 passphrase"
    (OUT / "b2_custody.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print("b2_custody.json: blobs, hot, channels, log")


if __name__ == "__main__":
    main()
