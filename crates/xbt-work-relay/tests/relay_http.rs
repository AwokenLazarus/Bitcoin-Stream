//! The relay over real HTTP with the xbt-work relay client: a Prime-signed receipt sealed, pushed on
//! the push listener, fetched through the public one, opened and verified; the public side is
//! read-only, lists nothing, sends no-store, and the blob hides the identity and the invoice.
use std::sync::Arc;
use std::time::Duration;

use xbt402::client::Transport;
use xbt402::http::UreqTransport;
use xbt_work::receipt::{PrimeKey, Signed, WorkReceipt};
use xbt_work::relay;
use xbt_work_relay::{serve, Config, Relay, Store, BLOB_LEN};

const ID: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const INV: &str = "vfer2e5e75t4tv7in42lakx6i4";

#[test]
fn prime_push_payer_fetch_over_http() {
    let d = tempfile::tempdir().unwrap();
    let cfg = Config { rate: 0.0, push_token: Some("tok".into()), ..Config::default() };
    let r = Arc::new(Relay::new(cfg, Store::disk(d.path().join("blobs"), 100, 86_400).unwrap()));
    let run = serve(r.clone(), "127.0.0.1:0", Some("127.0.0.1:0"), 2, Duration::from_secs(3600)).unwrap();
    let (public, push) = (format!("http://{}", run.public), format!("http://{}", run.push.unwrap()));
    let t = UreqTransport::default();

    // nothing yet
    assert_eq!(relay::fetch(&t, &public, ID, INV).unwrap(), None);

    // the Prime signs a receipt and pushes the sealed document
    let k = PrimeKey::from_seed(70, &[7u8; 32]);
    let rc = WorkReceipt { seq: 2, cum_work: 9, shares: 2, first_height: 111, last_height: 112, difficulty: 4, ..WorkReceipt::zero(70, ID, INV) };
    let s = k.sign(&rc).unwrap();
    let doc = xbt402::json::dumps(&s.to_doc());
    let blob = relay::seal(doc.as_bytes(), ID, INV, None).unwrap();
    assert_eq!(blob.len(), BLOB_LEN);
    let lk = relay::lookup(ID, INV);
    let auth = vec![("Authorization".to_string(), "Bearer tok".to_string())];
    assert_eq!(t.request("PUT", &format!("{push}/{lk}"), &blob, &[]).unwrap().status, 401);
    assert_eq!(t.request("PUT", &format!("{push}/{lk}"), &blob[..100], &auth).unwrap().status, 400);
    assert_eq!(t.request("PUT", &format!("{public}/{lk}"), &blob, &auth).unwrap().status, 405);
    assert_eq!(t.request("PUT", &format!("{push}/{lk}"), &blob, &auth).unwrap().status, 204);

    // the payer (or the provider) fetches, opens, verifies
    let got = relay::fetch(&t, &public, ID, INV).unwrap().expect("entry");
    let back = Signed::from_doc(&got).unwrap();
    assert!(back.verify(&k.pubkey()));
    assert_eq!(back.receipt, rc);
    let raw = t.request("GET", &format!("{public}/work-receipts/v1/{lk}"), b"", &[]).unwrap();
    assert_eq!(raw.status, 200);
    assert_eq!(raw.body, blob);
    let h = |n: &str| raw.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone());
    assert_eq!(h("Cache-Control").as_deref(), Some("no-store"));
    assert!(!String::from_utf8_lossy(&raw.body).contains(ID) && !String::from_utf8_lossy(&raw.body).contains(INV));
    // another pair cannot open it; the relay lists nothing
    assert!(relay::open(&raw.body, ID, "vfer2e5e75t4tv7in42lakx6i5").is_err());
    for p in ["/", "/work-receipts/v1/", "/list", "/keys"] {
        assert_eq!(t.request("GET", &format!("{public}{p}"), b"", &[]).unwrap().status, 404, "{p}");
    }
    assert_eq!(t.request("GET", &format!("{public}/healthz"), b"", &[]).unwrap().status, 200);
    assert_eq!(t.request("GET", &format!("{public}/readyz"), b"", &[]).unwrap().status, 200);
    // it is on disk: a new relay over the same directory serves it
    let r2 = Relay::new(Config::default(), Store::disk(d.path().join("blobs"), 100, 86_400).unwrap());
    assert_eq!(r2.store.len(), 1);
    assert_eq!(r2.public("GET", &format!("/{lk}"), &[], None).body, blob);
}
