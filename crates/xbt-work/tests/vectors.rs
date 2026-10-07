//! Conformance with XBT-053's published vectors (agp-011, pinned in `vectors/xbt_work_vectors.json`):
//! the Rust emitter rebuilds the file byte for byte, and every section and independent check
//! passes; an altered vector is caught.
use xbt_work::vectors::{check, generate, to_file};

fn pinned() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/xbt_work_vectors.json")).expect("pinned vectors")
}

#[test]
fn rust_emits_the_published_file_byte_for_byte() {
    assert!(to_file(&generate()) == pinned(), "Rust-emitted vectors differ from the published file");
}

#[test]
fn every_published_vector_checks() {
    let rows = check(&xbt402::json::parse(&pinned()).unwrap());
    let total: usize = rows.iter().map(|r| r.checks).sum();
    let fails: Vec<&String> = rows.iter().flat_map(|r| &r.failures).collect();
    assert!(fails.is_empty(), "{fails:?}");
    assert_eq!(total, 91);
}

#[test]
fn an_altered_vector_fails() {
    let v = xbt402::json::parse(&pinned()).unwrap();
    for (ptr, val) in [("/receipts/1/sig", serde_json::json!("00".repeat(64))), ("/pricing/0/workUnits", serde_json::json!(1822)),
                       ("/audit/fraud/paidSats", serde_json::json!(1)), ("/relay/blob", serde_json::json!("00")),
                       ("/usernames/7/invoice", serde_json::json!("vfer2e5e75t4tv7in42lakx6i4"))] {
        let mut w = v.clone();
        *w.pointer_mut(ptr).unwrap() = val;
        assert!(check(&w).iter().any(|r| !r.failures.is_empty()), "{ptr} altered but every check passed");
    }
}
