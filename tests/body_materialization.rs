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
use acdp::types::anchor::AnchorEntry;
use acdp::types::body::{Body, DataPeriod};
use acdp::types::primitives::ContentHash;
use acdp::types::{AgentDid, ContextType, CtxId, LineageId, PublishRequest, Visibility};
use chrono::{TimeZone, Utc};

/// Assert every key the request serializes appears verbatim on the body.
/// Shared by the full-population and supersession guards.
fn assert_all_request_fields_transfer(req: &PublishRequest, body: &Body) {
    let req_json = serde_json::to_value(req).expect("request serializes");
    let req_map = req_json.as_object().expect("request is an object");
    let body_json = serde_json::to_value(body).expect("body serializes");
    let body_map = body_json.as_object().expect("body is an object");

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
}

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
        .anchors(vec![AnchorEntry {
            scheme: "macp.commitment".into(),
            content_hash: ContentHash::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
            uri: Some("https://example.com/commitments/guard".into()),
            extensions: Default::default(),
        }])
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

    assert_all_request_fields_transfer(&req, &body);

    // Registry-assigned fields are set from the arguments…
    assert_eq!(body.origin_registry, "registry.example.com");
    // …and created_at is ms-truncated by the constructor (RFC-ACDP-0001
    // §5.3), so nanosecond remainders never reach the stored body.
    assert_eq!(body.created_at.timestamp_subsec_nanos() % 1_000_000, 0);
}

/// The inverse guard: a minimally-populated request must NOT gain
/// optional fields in the body. Because optional fields use
/// `skip_serializing_if = "Option::is_none"`, an unset field must be
/// *absent* from the body JSON — a materializer that invented a default
/// (e.g. `data_period: Some(default)`) would change the canonical form
/// and break sig-001. This catches that regression.
#[test]
fn unset_optional_fields_are_absent_from_the_body() {
    let producer = Producer::new(
        SigningKey::from_bytes(&[8u8; 32]),
        AgentDid::new("did:web:agents.example.com:minimal"),
        "did:web:agents.example.com:minimal#key-1",
    );
    // Only the required fields; every optional field left unset.
    let req = producer
        .publish_request()
        .title("minimal")
        .context_type(ContextType::DataSnapshot)
        .build()
        .expect("valid request");

    let body = Body::from_publish_request(
        &req,
        CtxId("acdp://registry.example.com/00000000-0000-4000-8000-000000000000".into()),
        LineageId(
            "lin:sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        ),
        "registry.example.com",
        Utc::now(),
    );
    let body_json = serde_json::to_value(&body).expect("body serializes");
    let body_map = body_json.as_object().expect("body is an object");

    for key in [
        "audience",
        "description",
        "summary",
        "tags",
        "domain",
        "expires_at",
        "data_period",
        "metadata",
        "schema_uri",
        "anchors",
    ] {
        assert!(
            !body_map.contains_key(key),
            "unset optional field '{key}' must be ABSENT from the body JSON, \
             not materialized to a default (would change the canonical form)"
        );
    }
}

/// Supersession (v2+) guard: a superseding request carries `supersedes`
/// and `version`, plus the registry-assigned `lineage_id` must transfer
/// verbatim. RFC-ACDP-0003 §3.1.
#[test]
fn supersession_v2_fields_transfer_to_the_body() {
    let producer = Producer::new(
        SigningKey::from_bytes(&[9u8; 32]),
        AgentDid::new("did:web:agents.example.com:super"),
        "did:web:agents.example.com:super#key-1",
    );
    let previous = CtxId("acdp://registry.example.com/00000000-0000-4000-8000-000000000001".into());
    let lineage = LineageId(
        "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
    );

    let req = producer
        .supersede(previous.clone())
        .expected_lineage_id(lineage.clone())
        .version(2)
        .title("v2 supersedes v1")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("valid v2 request");
    assert_eq!(req.version, 2);
    assert_eq!(req.supersedes.as_ref(), Some(&previous));

    let ctx_id = CtxId("acdp://registry.example.com/00000000-0000-4000-8000-000000000002".into());
    let body = Body::from_publish_request(
        &req,
        ctx_id.clone(),
        lineage.clone(),
        "registry.example.com",
        Utc::now(),
    );

    assert_all_request_fields_transfer(&req, &body);
    assert_eq!(body.version, 2);
    assert_eq!(body.supersedes.as_ref(), Some(&previous));

    // Registry-assigned identity fields round-trip verbatim from the
    // constructor arguments.
    assert_eq!(body.ctx_id, ctx_id);
    assert_eq!(body.lineage_id, lineage);
    assert_eq!(body.origin_registry, "registry.example.com");
}
