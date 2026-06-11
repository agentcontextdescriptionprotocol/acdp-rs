//! Example: publish a first version, then supersede it with a v2.
//!
//! Run with: `cargo run --example supersession`
//!
//! Supersession (RFC-ACDP-0003) is how a producer issues a *new version*
//! of a context while keeping a verifiable lineage back to the original.
//! The two rules the builder enforces are:
//!
//!   * **v1** — `supersedes` MUST be null, `version` MUST be 1, and
//!     `lineage_id` MUST NOT be set.
//!   * **v2+** — `supersedes` points at the previous `ctx_id`, `version`
//!     is `previous.version + 1`, and `lineage_id` MAY be carried so the
//!     registry can check it against the deterministically-derived value.
//!
//! `lineage_id` is derived once, from the *first* version's `ctx_id`
//! (`derive_lineage_id`), and every later version in the chain repeats it
//! unchanged — that shared id is what ties the chain together.
//!
//! This example runs fully offline: it builds a v1 request, simulates the
//! registry assigning a `ctx_id` + `lineage_id` (the part you would
//! normally get back from `RegistryClient::publish` + `retrieve`), then
//! uses `Producer::supersede_body` to roll a v2.

use acdp::{
    crypto::{derive_lineage_id, SigningKey},
    producer::Producer,
    types::{AgentDid, Body, ContextType, CtxId, DataRef, DataRefType, Visibility},
};

fn main() {
    // ── 1. Producer ─────────────────────────────────────────────────────────
    let key = SigningKey::generate();
    let agent_id = AgentDid::new("did:web:agents.example.com:my-agent");
    let key_id = "did:web:agents.example.com:my-agent#key-1";
    let producer = Producer::new(key, agent_id, key_id);

    // ── 2. Build and "publish" version 1 ────────────────────────────────────
    let v1 = producer
        .publish_request()
        .title("Q1 2026 revenue snapshot")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .summary("Preliminary Q1 2026 revenue, pending audit.")
        .data_refs(vec![DataRef::uri(
            DataRefType::PrimaryResult,
            "https://data.example.com/revenue/q1-2026.parquet",
        )])
        .domain("finance")
        .tags(vec!["finance", "revenue", "q1-2026"])
        .build()
        .expect("v1 build failed");

    println!("── version 1 (as submitted) ─────────────────────────────");
    println!("version:      {}", v1.version);
    println!("supersedes:   {:?}", v1.supersedes);
    println!("content_hash: {}", v1.content_hash);

    // ── 3. Simulate the registry response ───────────────────────────────────
    // After a successful publish the registry assigns a `ctx_id`, derives
    // the `lineage_id` from it, and returns the stored `Body`. We rebuild
    // that Body locally so the example needs no network.
    let v1_ctx_id = CtxId::parse(format!(
        "acdp://registry.example.com/{}",
        "11111111-1111-4111-8111-111111111111"
    ))
    .expect("ctx_id");
    let lineage_id = derive_lineage_id(&v1_ctx_id);

    let mut v1_value = serde_json::to_value(&v1).expect("serialize v1");
    let obj = v1_value.as_object_mut().unwrap();
    obj.insert("ctx_id".into(), serde_json::json!(v1_ctx_id.as_str()));
    obj.insert("lineage_id".into(), serde_json::json!(lineage_id.as_str()));
    obj.insert(
        "origin_registry".into(),
        serde_json::json!("registry.example.com"),
    );
    obj.insert(
        "created_at".into(),
        serde_json::json!("2026-04-16T10:30:15.123Z"),
    );
    let v1_body: Body = serde_json::from_value(v1_value).expect("v1 Body");

    println!("\n── registry assigned ────────────────────────────────────");
    println!("ctx_id:     {}", v1_body.ctx_id.as_str());
    println!("lineage_id: {}", v1_body.lineage_id.as_str());

    // ── 4. Supersede with version 2 ─────────────────────────────────────────
    // Two entry points exist:
    //   * `supersede_body(&body)` — blank slate; pre-fills supersedes,
    //     version, and expected_lineage_id only. You re-supply title,
    //     context_type, and every other field.
    //   * `new_version_from(&body)` — used here; additionally carries over
    //     every producer-controlled field (title, type, tags, domain, …)
    //     so you override only what actually changed.
    let v2 = producer
        .new_version_from(&v1_body)
        .summary("Final Q1 2026 revenue, audit complete.")
        .data_refs(vec![DataRef::uri(
            DataRefType::PrimaryResult,
            "https://data.example.com/revenue/q1-2026-final.parquet",
        )])
        .build()
        .expect("v2 build failed");

    println!("\n── version 2 (supersession) ─────────────────────────────");
    println!("version:      {}", v2.version);
    println!("supersedes:   {}", v2.supersedes.as_ref().unwrap().as_str());
    println!(
        "lineage_id:   {}",
        v2.lineage_id
            .as_ref()
            .map(|l| l.as_str())
            .unwrap_or("<none>")
    );
    println!("content_hash: {}", v2.content_hash);

    // ── 5. The chain is consistent ──────────────────────────────────────────
    assert_eq!(v2.version, 2);
    assert_eq!(v2.supersedes.as_ref().unwrap(), &v1_body.ctx_id);
    assert_eq!(v2.lineage_id.as_ref().unwrap(), &v1_body.lineage_id);
    assert_ne!(v1.content_hash, v2.content_hash, "new content → new hash");
    println!("\n✓ v2 supersedes v1, lineage_id preserved, content_hash changed");
}
