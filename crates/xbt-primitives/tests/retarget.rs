//! The mainnet retarget rule against B2's Python (recorded by scripts/gen_retarget_cases.py):
//! exact CalculateNextWorkRequired at a period boundary with a known first header, the 4x
//! PermittedDifficultyTransition range without one, unchanged bits inside a period; and the
//! compact encoding.
use ruint::aliases::U256;
use serde_json::Value;
use xbt_primitives::header::{bits_to_target, target_to_bits, Allowed, ChainRules, Header};

#[test]
fn mainnet_next_bits_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/retarget_main_cases.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let rules = ChainRules::main();
    let (mut n, mut compact) = (0, 0);
    for c in v["cases"].as_array().unwrap() {
        if let Some(bits) = c.get("compact") {
            let t = bits_to_target(bits.as_u64().unwrap() as u32).unwrap();
            assert_eq!(format!("{t:064x}"), c["target"].as_str().unwrap());
            assert_eq!(target_to_bits(t) as u64, c["roundTrip"].as_u64().unwrap());
            compact += 1;
            continue;
        }
        let parent = Header { time: c["time"].as_u64().unwrap() as u32, bits: c["bits"].as_u64().unwrap() as u32,
                              height: c["height"].as_u64().unwrap() as u32, txcount: 1, ..Header::default() };
        let first = c["firstTime"].as_i64().map(|t| t.max(0) as u32);
        // Python allows a negative first time only in synthetic cases; skip those
        if c["firstTime"].as_i64().is_some_and(|t| t < 0) {
            continue;
        }
        let got = rules.next_bits(&parent, first).unwrap();
        match (got, c.get("exact"), c.get("range")) {
            (Allowed::Exact(mut g), Some(w), None) => {
                g.sort_unstable();
                let w: Vec<u32> = w.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect();
                assert_eq!(g, w, "case {c}");
            }
            (Allowed::Range(lo, hi), None, Some(r)) => {
                let p = |i: usize| U256::from_str_radix(r[i].as_str().unwrap(), 16).unwrap();
                assert_eq!((lo, hi), (p(0), p(1)), "case {c}");
            }
            (g, _, _) => panic!("shape differs for {c}: {g:?}"),
        }
        n += 1;
    }
    assert!(n >= 390 && compact == 6, "{n} retarget cases, {compact} compact cases");
}
