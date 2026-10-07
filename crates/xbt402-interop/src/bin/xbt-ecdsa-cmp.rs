//! The Rust half of the ECDSA cross-check with cmp's `cmp/keys.py` (AGP-035; driver
//! `scripts/cmp_keys_ecdsa.py`). One case per stdin line, `sign <secret hex> <msg hex>` or
//! `verify <pub hex> <msg hex> <sig hex>`; one answer per stdout line, `<pub hex> <sig hex>` (`-` is the empty message) (the
//! compressed pub and `xbt_primitives::ecdsa::sign(secret, sha256(msg))`, strict DER) or `1`/`0`.
use std::io::{BufRead, BufWriter, Write};

use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;

fn main() {
    let out = std::io::stdout();
    let mut out = BufWriter::new(out.lock());
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split_whitespace().collect();
        let hx = |i: usize| match f.get(i).copied() {
            Some("-") => vec![],
            x => hex::decode(x.expect("field")).expect("hex"),
        };
        match f.first().copied() {
            Some("sign") => {
                let secret: [u8; 32] = hx(1).try_into().expect("32-byte secret");
                let sk = ecdsa::secret_key(&secret).expect("secret in [1, n)");
                writeln!(out, "{} {}", hex::encode(ecdsa::pubkey(&sk)), hex::encode(ecdsa::sign(&sk, &sha256(&hx(2))))).expect("stdout");
            }
            Some("verify") => writeln!(out, "{}", u8::from(ecdsa::verify(&hx(1), &sha256(&hx(2)), &hx(3)))).expect("stdout"),
            _ => panic!("bad line: {line}"),
        }
    }
}
