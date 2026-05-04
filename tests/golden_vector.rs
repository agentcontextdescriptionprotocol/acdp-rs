//! Integration tests against the ACDP spec's golden vectors.
//!
//! All expected values come from:
//!   schemas/conformance/sig-001-ed25519-golden.json
//!   schemas/conformance/can-001-jcs-vector.json

use acdp::{
    crypto::{
        canonicalize_value, compute_content_hash, derive_lineage_id, verify_ed25519, SigningKey,
    },
    types::{AgentDid, ContentHash, ContextType, CtxId, Visibility},
};
use serde_json::json;

const TEST_SEED: [u8; 32] = [0u8; 32];
const TEST_PUB_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
const EXPECTED_CONTENT_HASH: &str =
    "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5";
const EXPECTED_SIGNATURE_B64: &str =
    "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ==";
const EXPECTED_LINEAGE_ID: &str =
    "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a";

/// ProducerContent for the golden vector (no registry-assigned or integrity fields).
fn golden_producer_content() -> serde_json::Value {
    json!({
        "version": 1,
        "supersedes": null,
        "agent_id": "did:web:agents.example.com:test-producer",
        "contributors": [],
        "title": "Golden test vector — minimal first version",
        "type": "data_snapshot",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public"
    })
}

#[test]
fn canonical_form_matches_spec() {
    let pc = golden_producer_content();
    let canonical = canonicalize_value(&pc);
    let got = std::str::from_utf8(&canonical).unwrap();
    let expected = r#"{"agent_id":"did:web:agents.example.com:test-producer","contributors":[],"data_refs":[],"derived_from":[],"supersedes":null,"title":"Golden test vector — minimal first version","type":"data_snapshot","version":1,"visibility":"public"}"#;
    assert_eq!(got, expected, "JCS canonical form mismatch");
}

#[test]
fn content_hash_matches_spec() {
    let pc = golden_producer_content();
    let hash = compute_content_hash(&pc).unwrap();
    assert_eq!(hash.as_str(), EXPECTED_CONTENT_HASH);
}

#[test]
fn signature_matches_spec() {
    let key = SigningKey::from_bytes(&TEST_SEED);
    let hash = ContentHash(EXPECTED_CONTENT_HASH.into());
    let sig = key.sign_content_hash(&hash);
    assert_eq!(sig, EXPECTED_SIGNATURE_B64);
}

#[test]
fn signature_verifies() {
    let pub_bytes: [u8; 32] = hex::decode(TEST_PUB_HEX).unwrap().try_into().unwrap();
    verify_ed25519(&pub_bytes, EXPECTED_SIGNATURE_B64, EXPECTED_CONTENT_HASH).unwrap();
}

#[test]
fn lineage_id_matches_spec() {
    let ctx = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
    let lid = derive_lineage_id(&ctx);
    assert_eq!(lid.as_str(), EXPECTED_LINEAGE_ID);
}

#[test]
fn full_producer_round_trip() {
    use acdp::producer::Producer;

    let key = SigningKey::from_bytes(&TEST_SEED);
    let prod = Producer::new(
        key,
        AgentDid::new("did:web:agents.example.com:test-producer"),
        "did:web:agents.example.com:test-producer#key-1",
    );

    let req = prod
        .publish_request()
        .title("Golden test vector — minimal first version")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();

    assert_eq!(req.content_hash.as_str(), EXPECTED_CONTENT_HASH);
    assert_eq!(req.signature.value, EXPECTED_SIGNATURE_B64);
    assert_eq!(req.signature.algorithm, "ed25519");
}

#[test]
fn jcs_negative_zero() {
    // can-001 conformance vector: -0.0 MUST become 0
    let v = json!({"values": [42, -7, 0, 1.1, 1.5, -0.0_f64]});
    let out = canonicalize_value(&v);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(!s.contains("-0"), "negative zero leaked: {s}");
    assert!(s.contains("\"values\":[42,-7,0,1.1,1.5,0]"), "got: {s}");
}

#[test]
fn jcs_key_sort() {
    let v = json!({"z": 1, "a": 2, "m": 3});
    let out = canonicalize_value(&v);
    assert_eq!(out, b"{\"a\":2,\"m\":3,\"z\":1}");
}

#[test]
fn exclusion_set_invariant() {
    // Adding excluded fields must not change content_hash
    let base = golden_producer_content();
    let h1 = compute_content_hash(&base).unwrap();

    let mut with_excluded = base.as_object().unwrap().clone();
    with_excluded.insert("ctx_id".into(), json!("acdp://reg/uid"));
    with_excluded.insert("lineage_id".into(), json!("lin:sha256:aabb"));
    with_excluded.insert("created_at".into(), json!("2026-01-01T00:00:00.000Z"));
    with_excluded.insert("origin_registry".into(), json!("reg"));
    with_excluded.insert("content_hash".into(), json!("sha256:0000"));
    with_excluded.insert(
        "signature".into(),
        json!({"algorithm":"ed25519","key_id":"k","value":"v"}),
    );

    let h2 = compute_content_hash(&serde_json::Value::Object(with_excluded)).unwrap();
    assert_eq!(h1, h2, "excluded fields must not affect content_hash");
}
