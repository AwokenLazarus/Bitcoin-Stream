//! The routing vectors as tests: the Rust emitter reproduces the published (B1-generated) file byte
//! for byte, the Rust checker passes it, and a tampered value fails exactly its own check.
use serde_json::Value;
use xbt402_interop::route_vectors::{check, check_count, dump_indent1, generate};
use xbt402_interop::vectors_dir;

fn published() -> (String, Value) {
    let s = std::fs::read_to_string(vectors_dir().join("xbt402_routing_vectors.json")).unwrap();
    let v = xbt402::json::parse(&s).unwrap();
    (s, v)
}

#[test]
fn rust_emits_the_published_routing_vectors_byte_for_byte() {
    let (s, _) = published();
    assert_eq!(dump_indent1(&generate()), s);
}

#[test]
fn every_routing_vector_checks() {
    let (_, v) = published();
    assert_eq!(check(&v), Vec::<String>::new());
    assert_eq!(check_count(&v), 79);
}

#[test]
fn a_tampered_presignature_or_quote_fails_its_check() {
    let (_, mut v) = published();
    let s = v["adaptor"][2]["presig"]["s1"].as_str().unwrap().to_string();
    v["adaptor"][2]["presig"]["s1"] = format!("{}{}", if &s[..1] == "0" { "1" } else { "0" }, &s[1..]).into();
    let bad = check(&v);
    assert!(!bad.is_empty() && bad.iter().all(|b| b.starts_with("adaptor[2]")), "{bad:?}");
    let (_, mut v) = published();
    v["route"]["feeQuote"]["feePpm"] = 1.into();
    assert_eq!(check(&v)[0], "route feeQuote verifies");
    let (_, mut v) = published();
    v["lock"]["ch2Completed"] = v["lock"]["ch1Completed"].clone();
    assert_eq!(check(&v), vec!["lock ch2 completion is a valid 0x21 state".to_string()]);
}
