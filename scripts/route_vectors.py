#!/usr/bin/env python3
"""xbt402 routing vectors from the Python reference (B1 agp-023 `xbt402/adaptor.py`, `route.py`),
and an independent checker for a vector file whoever emitted it (AGP-026).

    route_vectors.py gen  OUT.json     # the reference file (B1 as the library), deterministic
    route_vectors.py check FILE.json   # B1 re-verifies every value in FILE (e.g. the Rust-emitted one)

Everything random in the protocol is fixed here: keys are sha256(tag) mod n, and the adaptor nonces
(k, w) are injected into B1's presign by replacing its `secrets.randbelow` for that one call (the
blinding factors it draws do not change the output). The Rust emitter (`xbt402-route-vectors`)
builds the same file from the Rust crates; conformance.sh diffs the two byte for byte and runs
`check` on the Rust one.

Sections:
  adaptor  pre-signatures (5 cases), completions, extraction, pre-verify refusals
  route    FeeQuote + the fee carry, PriceQuote (an amsat price above 2^64) + quoteId, invoices,
           a signed ROUTE-STATE, session key, call/lock auth, route_ok and next_cum tables, hub binding
  lock     one routed lock over both hops on fixed channels: ch1 (payer-pays) and ch2 (payee-pays,
           hub-bound), the client's POST /x402/route payload and body, the hub's POST
           /x402/xbt-channel/lock payload and body, both completions, t read back off ch2's close
"""
import hashlib
import json
import os
import sys

B1 = os.environ.get("XBT402_B1", os.path.expanduser("~/xbt-rnd/b1-agp-023"))
sys.path.insert(0, B1)

from xbt402 import adaptor, ecc  # noqa: E402
from xbt402.channel import ChannelParams, Payee, channel_auth_key, channel_payee_secret  # noqa: E402
from xbt402.route import (FeeQuote, Invoice, PriceQuote, call_auth, fee_due, hub_channel_message,  # noqa: E402
                          lock_auth, next_cum, route_ok, session_key, state_sign, state_verify)
from xbt402.x402_channel import request_auth, request_digest  # noqa: E402

N = ecc.N
NET = "bip122:0000000000000000000000000000beef"


def key(tag: str) -> int:
    return int.from_bytes(hashlib.sha256(tag.encode()).digest(), "big") % N


def h32(tag: str) -> bytes:
    return hashlib.sha256(tag.encode()).digest()


def pub(x: int) -> str:
    return ecc.pubkey(x).hex()


class _Nonces:
    """randbelow for one presign: k - 1, a blind, a blind, w - 1 (in B1's call order)."""

    def __init__(self, k: int, w: int):
        self.q = [k - 1, 12345, 67890, w - 1]

    def randbelow(self, n):
        return self.q.pop(0)


def presign_fixed(x: int, z: bytes, Y, k: int, w: int) -> adaptor.PreSig:
    real = adaptor.secrets
    adaptor.secrets = _Nonces(k, w)
    try:
        return adaptor.presign(x, z, Y)
    finally:
        adaptor.secrets = real


def adaptor_section() -> list:
    out = []
    for i in range(5):
        x, y = key(f"adaptor/x/{i}"), key(f"adaptor/y/{i}")
        k, w = key(f"adaptor/k/{i}"), key(f"adaptor/w/{i}")
        z = h32(f"adaptor/z/{i}")
        Y = adaptor.point_of(y)
        pre = presign_fixed(x, z, Y, k, w)
        sig = adaptor.adapt(pre, y)
        out.append({"x": f"{x:064x}", "X": pub(x), "z": z.hex(), "y": f"{y:064x}", "Y": adaptor.enc(Y).hex(),
                    "k": f"{k:064x}", "w": f"{w:064x}", "presig": pre.to_json(),
                    "preverify": adaptor.preverify(bytes.fromhex(pub(x)), z, Y, pre),
                    "preverifyOtherDigest": adaptor.preverify(bytes.fromhex(pub(x)), h32("other"), Y, pre),
                    "preverifyOtherPoint": adaptor.preverify(bytes.fromhex(pub(x)), z, adaptor.point_of(key("other")), pre),
                    "sig": sig.hex(), "sigVerifies": ecc.verify(bytes.fromhex(pub(x)), z, sig),
                    "extracted": f"{adaptor.extract(pre, sig + bytes([0x21]), Y):064x}",
                    "bogusDer": pre.bogus_der().hex(), "bogusVerifies": ecc.verify(bytes.fromhex(pub(x)), z, pre.bogus_der())})
    return out


def route_section() -> dict:
    hub, prov, client = key("route/hub"), key("route/provider"), key("route/client")
    q = FeeQuote(pub(hub), NET, 100, 2000, 20000, 500, 144, 2, 1727500001, 1727500000, 1727500600).sign(hub)
    carry, units, paid = [], 0, 0
    for d in (3, 3, 3, 1, 250, 20000, 7, 1, 1, 999):
        f, units = fee_due(q, d, units, paid)
        paid += f
        carry.append({"d": d, "fee": f, "units": str(units), "paid": paid})
    pq = PriceQuote(pub(prov), NET, "/v1/chunk", 813 * 10 ** 18 + 123_456_789, "call", 1727500002, 1727500000,
                    1727503600).sign(prov)
    inv_any = Invoice(pub(prov), NET, "0f" * 16, "ab" * 12, pub(key("route/t")), 1727500015.125, "any").sign(prov)
    inv_hubs = Invoice(pub(prov), NET, "0f" * 16, "cd" * 12, pub(key("route/t2")), 1727500016.5, [pub(hub)]).sign(prov)
    st = {"session": "0f" * 16, "seq": 12, "calls": 12, "chargeAmsat": str(813 * 10 ** 18 + 123_456_789),
          "accruedAmsat": str(12 * (813 * 10 ** 18 + 123_456_789)), "paidSat": 9, "quote": pq.quote_id(),
          "lastLock": {"lockId": "ab" * 12, "amount": 9, "secret": f"{key('route/t'):064x}"},
          "invoice": {k: v for k, v in inv_hubs.__dict__.items()}}
    signed_state = state_sign(prov, st)
    sk = session_key(client, bytes.fromhex(pub(prov)))
    assert sk == session_key(prov, bytes.fromhex(pub(client)))
    req = request_digest("POST", "/v1/chunk", b'{"tokens":1}')
    return {
        "hub": pub(hub), "provider": pub(prov), "client": pub(client),
        "feeQuote": q.__dict__, "feeQuoteVerifies": q.verify(), "feeCarry": carry,
        "priceQuote": pq.__dict__, "priceQuoteId": pq.quote_id(), "priceQuoteVerifies": pq.verify(),
        "invoiceAny": inv_any.__dict__, "invoiceHubs": inv_hubs.__dict__,
        "routeState": signed_state, "routeStateVerifies": state_verify(pub(prov), signed_state),
        "sessionKey": sk.hex(),
        "callAuth": {"session": "0f" * 16, "seq": 7, "req": req, "auth": call_auth(sk, "0f" * 16, 7, req)},
        "lockAuth": {"session": "0f" * 16, "lockId": "ab" * 12, "amount": 37, "point": pub(key("route/t")).upper(),
                     "hub": pub(hub), "auth": lock_auth(sk, "0f" * 16, "ab" * 12, 37, pub(key("route/t")).upper(), pub(hub))},
        "hubBinding": {"chan": "22" * 32 + ":1", "sig": ecc.sign(hub, hub_channel_message("22" * 32 + ":1")).hex()},
        "routeOk": [[tip, i, o, m, d, route_ok(tip, i, o, m, d)] for tip, i, o, m, d in
                    ((100, 9000, 5000, 144, 144), (100, 5000, 5000, 144, 144), (4857, 9000, 5000, 144, 144),
                     (4856, 9000, 5000, 144, 144), (100, 5288, 5000, 144, 144), (100, 5287, 5000, 144, 144))],
        "nextCum": [[r, a, fl, next_cum(r, a, fl)] for r, a, fl in ((0, 5, 546), (0, 5, 1146), (2000, 37, 1146), (540, 6, 546))],
    }


def lock_section() -> dict:
    client, hub, prov = key("lock/client"), key("lock/hub"), key("lock/provider")
    ch2key = key("lock/hub-ch2")
    t, r = key("lock/t"), key("lock/r")
    T = adaptor.point_of(t)
    T1 = adaptor.add(T, adaptor.point_of(r))
    p1 = ChannelParams.derive(pub(hub), pub(client), 9000, 600, network=NET)
    p1.funding_txid, p1.funding_vout, p1.capacity = "11" * 32, 0, 200000
    p2 = ChannelParams.derive(pub(prov), pub(ch2key), 8000, 600, network=NET, close_fee_payer="payee")
    p2.funding_txid, p2.funding_vout, p2.capacity = "22" * 32, 1, 150000
    q = FeeQuote(pub(hub), NET, 100, 2000, 20000, 500, 144, 2, 1727500001, 1727500000, 1727500600).sign(hub)
    d = 37
    f, units = fee_due(q, d, 0, 0)
    routed1, routed2 = 1000, 2000
    cum1 = next_cum(routed1, d + f, p1.min_amount)
    cum2 = next_cum(routed2, d, p2.min_amount)
    pre1 = presign_fixed(client, p1.sighash(p1.state_tx(cum1)), T1, key("lock/k1"), key("lock/w1"))
    pre2 = presign_fixed(ch2key, p2.sighash(p2.state_tx(cum2)), T, key("lock/k2"), key("lock/w2"))
    session, lock_id = "5e" * 16, "1d" * 12
    sk = session_key(key("lock/route-client"), bytes.fromhex(pub(prov)))
    inv = Invoice(pub(prov), NET, session, lock_id, adaptor.enc(T).hex(), 1727500015.125, "any").sign(prov)
    la = lock_auth(sk, session, lock_id, d, adaptor.enc(T).hex(), pub(hub))
    route = {"provider": "http://127.0.0.1:33111", "payTo": pub(prov), "network": NET, "amount": d,
             "point": adaptor.enc(T).hex(), "fee": f, "feeQuote": q.__dict__, "invoice": inv.__dict__, "session": session,
             "lockId": lock_id, "lockAuth": la, "tweak": f"{r:064x}"}
    body1 = json.dumps({"route": route}).encode()
    pl1 = {"chan": p1.channel_id, "seq": 5, "cum": str(cum1), "adaptor": pre1.to_json(), "point": adaptor.enc(T1).hex()}
    pl1["auth"] = request_auth(channel_auth_key(client, bytes.fromhex(p1.payee_pub)), pl1["chan"], pl1["seq"], pl1["cum"],
                               None, request_digest("POST", "/x402/route", body1))
    rt2 = {"session": session, "lockId": lock_id, "amount": d, "lockAuth": la, "hub": pub(hub)}
    body2 = json.dumps({"route": rt2}).encode()
    pl2 = {"chan": p2.channel_id, "seq": 3, "cum": str(cum2), "point": adaptor.enc(T).hex(), "adaptor": pre2.to_json()}
    pl2["auth"] = request_auth(channel_auth_key(ch2key, bytes.fromhex(p2.payee_pub)), pl2["chan"], pl2["seq"], pl2["cum"],
                               None, request_digest("POST", "/x402/xbt-channel/lock", body2))
    # the provider completes ch2 with t: a plain 0x21 state its Payee takes
    sig2 = adaptor.adapt(pre2, t) + b"\x21"
    payee2 = Payee(p2, channel_payee_secret(NET, prov, bytes.fromhex(p2.payer_pub), p2.expiry))
    payee2.accept(cum2, sig2)
    close2 = payee2.close_tx()
    t_back = adaptor.secret_from_witness(pre2, close2.inputs[0].witness, T)
    # the hub completes ch1 with t + r; the client's receipt is t = (t + r) - r
    s1 = (t + r) % N
    sig1 = adaptor.adapt(pre1, s1) + b"\x21"
    payee1 = Payee(p1, channel_payee_secret(NET, hub, bytes.fromhex(p1.payer_pub), p1.expiry))
    payee1.accept(cum1, sig1)
    answer = {"lockId": lock_id, "secret": f"{t:064x}", "cum": str(cum2), "chan": p2.channel_id, "routedSat": routed2 + d,
              "session": state_sign(prov, {"session": session, "lockId": lock_id, "amount": d, "paidSat": 9})}
    return {
        "ch1": p1.to_dict(), "ch1Id": p1.channel_id, "ch2": p2.to_dict(), "ch2Id": p2.channel_id,
        "ch1MinCum": p1.min_amount, "ch2MinCum": p2.min_amount,
        "t": f"{t:064x}", "T": adaptor.enc(T).hex(), "r": f"{r:064x}", "T1": adaptor.enc(T1).hex(),
        "d": d, "fee": f, "feeUnits": str(units), "routed1": routed1, "routed2": routed2, "cum1": cum1, "cum2": cum2,
        "ch1Sighash": p1.sighash(p1.state_tx(cum1)).hex(), "ch2Sighash": p2.sighash(p2.state_tx(cum2)).hex(),
        "routeBody": body1.decode(), "routePayload": pl1, "lockBody": body2.decode(), "lockPayload": pl2,
        "ch2Completed": sig2.hex(), "ch2Close": close2.hex(), "tFromCh2Close": f"{t_back:064x}",
        "hubSecret": f"{s1:064x}", "ch1Completed": sig1.hex(), "clientReceipt": f"{(s1 - r) % N:064x}",
        "providerAnswer": answer,
        "ch1PreverifyUnderT": adaptor.preverify(bytes.fromhex(p1.payer_pub), p1.sighash(p1.state_tx(cum1)), T, pre1),
        "ch2PreverifyV11State": adaptor.preverify(bytes.fromhex(p2.payer_pub), p2.sighash(
            ChannelParams(**{**p2.to_dict(), "close_fee_payer": "payer"}).state_tx(cum2)), T, pre2),
    }


def generate() -> dict:
    return {"about": "xbt402 hub routing vectors (AGP-026): generated by scripts/route_vectors.py from B1 "
                     "agp-023 xbt402/adaptor.py + route.py; the Rust emitter xbt402-route-vectors must match byte for byte",
            "network": NET, "adaptor": adaptor_section(), "route": route_section(), "lock": lock_section()}


def dump(v) -> str:
    return json.dumps(v, indent=1) + "\n"


# --- independent checks of a file, whoever emitted it -----------------------------------------------
def check(doc: dict) -> list:
    bad = []

    def ok(name, cond):
        if not cond:
            bad.append(name)
    for i, a in enumerate(doc["adaptor"]):
        pre = adaptor.PreSig.from_json(a["presig"])
        X, Y, z = bytes.fromhex(a["X"]), adaptor.dec(a["Y"]), bytes.fromhex(a["z"])
        ok(f"adaptor[{i}] X = x*G", pub(int(a["x"], 16)) == a["X"])
        ok(f"adaptor[{i}] preverify", adaptor.preverify(X, z, Y, pre) and a["preverify"])
        ok(f"adaptor[{i}] refusals", not a["preverifyOtherDigest"] and not a["preverifyOtherPoint"]
           and not adaptor.preverify(X, h32("other"), Y, pre))
        sig = bytes.fromhex(a["sig"])
        ok(f"adaptor[{i}] completion verifies", ecc.verify(X, z, sig) and a["sigVerifies"])
        ok(f"adaptor[{i}] completion = adapt(pre, y)", adaptor.adapt(pre, int(a["y"], 16)) == sig)
        ok(f"adaptor[{i}] extract", adaptor.extract(pre, sig, Y) == int(a["y"], 16) == int(a["extracted"], 16))
        ok(f"adaptor[{i}] bogus DER refused", not ecc.verify(X, z, bytes.fromhex(a["bogusDer"])) and not a["bogusVerifies"])
    r = doc["route"]
    q = FeeQuote.from_dict(r["feeQuote"])
    ok("route feeQuote verifies", q.verify() and q.hub == r["hub"])
    units, paid = 0, 0
    for c in r["feeCarry"]:
        f, units = fee_due(q, c["d"], units, paid)
        paid += f
        ok(f"route feeCarry d={c['d']}", (f, str(units), paid) == (c["fee"], c["units"], c["paid"]))
    pq = PriceQuote(**r["priceQuote"])
    ok("route priceQuote verifies", pq.verify() and pq.quote_id() == r["priceQuoteId"] and pq.amsatPerCall > 2 ** 64)
    for k in ("invoiceAny", "invoiceHubs"):
        ok(f"route {k} verifies", Invoice.from_dict(r[k]).verify())
    ok("route ROUTE-STATE verifies", state_verify(r["provider"], r["routeState"]))
    ca = r["callAuth"]
    ok("route callAuth", call_auth(bytes.fromhex(r["sessionKey"]), ca["session"], ca["seq"], ca["req"]) == ca["auth"])
    la = r["lockAuth"]
    ok("route lockAuth", lock_auth(bytes.fromhex(r["sessionKey"]), la["session"], la["lockId"], la["amount"], la["point"],
                                   la["hub"]) == la["auth"])
    hb = r["hubBinding"]
    ok("route hub binding", ecc.verify(bytes.fromhex(r["hub"]), hub_channel_message(hb["chan"]), bytes.fromhex(hb["sig"])))
    for row in r["routeOk"]:
        ok(f"route route_ok {row[:5]}", route_ok(*row[:5]) == row[5])
    for row in r["nextCum"]:
        ok(f"route next_cum {row[:3]}", next_cum(*row[:3]) == row[3])
    lk = doc["lock"]
    p1, p2 = ChannelParams(**lk["ch1"]), ChannelParams(**lk["ch2"])
    T, T1 = adaptor.dec(lk["T"]), adaptor.dec(lk["T1"])
    t, rr = int(lk["t"], 16), int(lk["r"], 16)
    ok("lock T = t*G, T1 = T + r*G", adaptor.point_of(t) == T and adaptor.add(T, adaptor.point_of(rr)) == T1)
    ok("lock cum1/cum2", lk["cum1"] == next_cum(lk["routed1"], lk["d"] + lk["fee"], p1.min_amount)
       and lk["cum2"] == next_cum(lk["routed2"], lk["d"], p2.min_amount) and p2.min_amount == 1146)
    pre1 = adaptor.PreSig.from_json(lk["routePayload"]["adaptor"])
    pre2 = adaptor.PreSig.from_json(lk["lockPayload"]["adaptor"])
    z1, z2 = p1.sighash(p1.state_tx(lk["cum1"])), p2.sighash(p2.state_tx(lk["cum2"]))
    ok("lock sighashes", z1.hex() == lk["ch1Sighash"] and z2.hex() == lk["ch2Sighash"])
    ok("lock ch1 pre-verifies under T1 (the hub's check 4)", adaptor.preverify(bytes.fromhex(p1.payer_pub), z1, T1, pre1))
    ok("lock ch1 does not pre-verify under T", not adaptor.preverify(bytes.fromhex(p1.payer_pub), z1, T, pre1)
       and not lk["ch1PreverifyUnderT"])
    ok("lock ch2 pre-verifies under T (the provider's check)", adaptor.preverify(bytes.fromhex(p2.payer_pub), z2, T, pre2))
    ok("lock ch2 pre-signature is for the payee-pays state only", not lk["ch2PreverifyV11State"])
    ok("lock route payload auth", lk["routePayload"]["auth"] == request_auth(
        channel_auth_key(key("lock/client"), bytes.fromhex(p1.payee_pub)), p1.channel_id, lk["routePayload"]["seq"],
        lk["routePayload"]["cum"], None, request_digest("POST", "/x402/route", lk["routeBody"].encode())))
    ok("lock hub payload auth", lk["lockPayload"]["auth"] == request_auth(
        channel_auth_key(key("lock/hub-ch2"), bytes.fromhex(p2.payee_pub)), p2.channel_id, lk["lockPayload"]["seq"],
        lk["lockPayload"]["cum"], None, request_digest("POST", "/x402/xbt-channel/lock", lk["lockBody"].encode())))
    sig2 = bytes.fromhex(lk["ch2Completed"])
    ok("lock ch2 completion is a valid 0x21 state", ecc.verify(bytes.fromhex(p2.payer_pub), z2, sig2[:-1]) and sig2[-1] == 0x21)
    from xbt402.tx import Tx
    close2 = Tx.parse(bytes.fromhex(lk["ch2Close"]))
    ok("lock t read back off ch2's close", adaptor.secret_from_witness(pre2, close2.inputs[0].witness, T) == t
       == int(lk["tFromCh2Close"], 16))
    ok("lock ch2 close pays the provider cum2 - its fee", close2.outputs[0].value == lk["cum2"] - 600
       and close2.outputs[1].value == p2.capacity - lk["cum2"])
    sig1 = bytes.fromhex(lk["ch1Completed"])
    ok("lock ch1 completion (t + r) is a valid 0x21 state", ecc.verify(bytes.fromhex(p1.payer_pub), z1, sig1[:-1])
       and int(lk["hubSecret"], 16) == (t + rr) % N and int(lk["clientReceipt"], 16) == t)
    ok("lock provider answer signed", state_verify(pub(key("lock/provider")), lk["providerAnswer"]["session"]))
    rb = json.loads(lk["routeBody"])["route"]
    ok("lock the invoice and fee quote in the route body verify", Invoice.from_dict(rb["invoice"]).verify()
       and FeeQuote.from_dict(rb["feeQuote"]).verify())
    return bad


def main(argv):
    if len(argv) == 3 and argv[1] == "gen":
        with open(argv[2], "w") as f:
            f.write(dump(generate()))
        return 0
    if len(argv) == 3 and argv[1] == "check":
        with open(argv[2]) as f:
            doc = json.load(f)
        bad = check(doc)
        n = len(doc["adaptor"]) + 1 + 1
        print(f"route vectors ({ecc.BACKEND}): {argv[2]}: {'OK' if not bad else 'FAIL'}"
              f" ({len(doc['adaptor'])} adaptor cases, route, lock)" + ("" if not bad else f": {bad}"))
        return 0 if not bad else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
