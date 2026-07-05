//! Field-transfer guard for `Body::from_publish_request` (IMP-02).
//!
//! Three store backends materialize `PublishRequest → Body` through the
//! shared constructor (this repo's `InMemoryStore` plus the registry's
//! Postgres and SQLite backends). This test makes a missed field mapping
//! a test failure instead of a silent data-loss bug: it builds a request
//! with **every** producer field populated, materializes a `Body`, and
//! asserts that every key the request serializes is present in the body
//! with an identical value.
//!
//! If you add a field to `PublishRequest` and this test fails, map the
//! field in `Body::from_publish_request` (crates/acdp-types/src/body.rs)
//! — do not weaken the test.

use acdp::crypto::SigningKey;
use acdp::producer::Producer;
use acdp::types::body::{Body, DataPeriod};
use acdp::types::{AgentDid, ContextType, CtxId, LineageId, Visibility};
use chrono::{TimeZone, Utc};

#[test]
fn every_publish_request_field_transfers_to_the_body() {
    let producer = Producer::new(
        SigningKey::from_bytes(&[7u8; 32]),
        AgentDid::new("did:web:agents.example.com:guard"),
        "did:web:agents.example.com:guard#key-1",
    );

    // Populate EVERY producer-controlled field. Optional fields use
    // `skip_serializing_if`, so an unset field would be invisible to the
    // JSON comparison below — full population is what makes the guard
    // exhaustive.
    let start = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2026, 1, 31, 0, 0, 0).unwrap();
    let req = producer
        .publish_request()
        .title("field-transfer guard")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Restricted)
        .audience(vec![AgentDid::new("did:web:consumers.example.com:auditor")])
        .description("exhaustively populated request")
        .summary("guard summary")
        .tags(vec!["guard", "imp-02"])
        .domain("testing")
        .contributors(vec![AgentDid::new("did:web:agents.example.com:helper")])
        .expires_at(Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap())
        .data_period(DataPeriod { start, end })
        .metadata(serde_json::json!({"k": "v", "n": 1}))
        .schema_uri("https://schemas.example.com/guard/v1")
        .build()
        .expect("valid request");

    let req_json = serde_json::to_value(&req).expect("request serializes");
    let req_map = req_json.as_object().expect("request is an object");

    let body = Body::from_publish_request(
        &req,
        CtxId("acdp://registry.example.com/contexts/00000000-0000-4000-8000-000000000000".into()),
        LineageId(
            "lin:sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        ),
        "registry.example.com",
        Utc::now(),
    );
    let body_json = serde_json::to_value(&body).expect("body serializes");
    let body_map = body_json.as_object().expect("body is an object");

    // Every serialized request key must appear in the body, verbatim.
    // (The publish schema is closed, so this covers the entire producer
    // surface; registry-assigned fields are extra keys on the body side
    // and intentionally not compared.)
    let mut missing = Vec::new();
    for (key, req_value) in req_map {
        match body_map.get(key) {
            Some(body_value) if body_value == req_value => {}
            Some(body_value) => missing.push(format!(
                "field '{key}' altered in transfer: request={req_value} body={body_value}"
            )),
            None => missing.push(format!(
                "field '{key}' present on PublishRequest but NOT mapped by \
                 Body::from_publish_request — map it in crates/acdp-types/src/body.rs"
            )),
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));

    // Registry-assigned fields are set from the arguments…
    assert_eq!(body.origin_registry, "registry.example.com");
    // …and created_at is ms-truncated by the constructor (RFC-ACDP-0001
    // §5.3), so nanosecond remainders never reach the stored body.
    assert_eq!(body.created_at.timestamp_subsec_nanos() % 1_000_000, 0);
}
