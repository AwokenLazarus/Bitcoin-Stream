//! The conformance suite as tests, plus mutation checks: a tampered vector file must fail on
//! exactly the vector that was touched (so N/N means something).
use serde_json::Value;
use xbt402_interop::conformance::{run_all, xbt402_check};
use xbt402_interop::vectors_dir;

fn published() -> Value {
    xbt402::json::parse(&std::fs::read_to_string(vectors_dir().join("xbt402_vectors.json")).unwrap()).unwrap()
}

#[test]
fn every_published_vector_is_byte_identical() {
    let groups = run_all(&vectors_dir());
    let total: usize = groups.iter().map(|g| g.total).sum();
    for g in &groups {
        assert!(g.ok(), "{}: {}/{} {:?}", g.name, g.passed, g.total, g.failures);
    }
    assert_eq!(groups[0].total, 54, "check_vectors.py counts 54 xbt402 vectors");
    assert_eq!(groups[1].total, 166);
    assert_eq!(total, 253);
}

fn failing(v: &Value) -> Vec<String> {
    xbt402_check(v, "tampered").failures.iter().map(|f| f.split(':').next().unwrap().to_string()).collect()
}

#[test]
fn a_tampered_signature_fails_its_vector() {
    let mut v = published();
    let s = v["state"]["states"][1]["payerSig"].as_str().unwrap().to_string();
    let flipped = format!("{}{}", &s[..10], if &s[10..11] == "0" { "1" } else { "0" }) + &s[11..];
    v["state"]["states"][1]["payerSig"] = flipped.into();
    assert_eq!(failing(&v), vec!["state.states[1]"]);
}

#[test]
fn a_tampered_header_fails_its_step() {
    let mut v = published();
    let h = v["roundtrip"]["steps"][0]["PAYMENT-REQUIRED"].as_str().unwrap().replace('e', "f");
    v["roundtrip"]["steps"][0]["PAYMENT-REQUIRED"] = h.into();
    assert_eq!(failing(&v), vec!["roundtrip.steps[0]"]);
}

#[test]
fn a_wrong_refusal_code_fails() {
    let mut v = published();
    v["state"]["invalid"][1]["error"] = "bad_sig".into();       // the reference refuses it with bad_sighash
    assert_eq!(failing(&v), vec!["state.invalid[1]"]);
    let mut v = published();
    v["payeePays"]["invalid"][1]["error"] = "bad_sig".into();   // below the least state: bad_amount
    assert_eq!(failing(&v), vec!["payeePays.invalid[1]"]);
}

#[test]
fn a_net_close_report_fails_the_close_vector() {
    // AGP-029: the pre-fix report (cum = the payee's net output, the fee counted as unpaid)
    let mut v = published();
    for (k, val) in [("cum", "900"), ("unpaidMsat", "600000")] {
        v["payeePays"]["close"]["response"][k] = val.into();
    }
    assert_eq!(failing(&v), vec!["payeePays.close"]);
    let mut v = published();
    v["payeePays"]["close"]["settle"]["response"]["amount"] = "900".into();
    assert_eq!(failing(&v), vec!["payeePays.close"]);
}

#[test]
fn a_section_field_fails_the_whole_section() {
    let mut v = published();
    v["payeePays"]["params"]["close_fee"] = 601.into();
    let f = failing(&v);
    assert!(f.len() >= 13 && f.iter().all(|u| u.starts_with("payeePays")), "{f:?}");
}
