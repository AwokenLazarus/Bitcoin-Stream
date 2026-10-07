//! The README's example policy is one the signer accepts.
#[test]
fn example_policy_parses_in_the_signer() {
    let v: serde_json::Value = serde_json::from_str(include_str!("../policy.example.json")).unwrap();
    let p = xbt_signer::policy::PolicyConfig::from_value(&v).unwrap();
    assert_eq!(p.daily_budget_sats, 200_000);
    assert_eq!(p.human_threshold_sats, 150_000);
    assert!(p.anchor_required);
    assert!(p.routing.get("hubs").is_some_and(|h| h.is_object()));
}
