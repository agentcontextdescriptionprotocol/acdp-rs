//! Example: retrieve and verify a context.
//!
//! Run with: `cargo run --example consumer --features client`
//!
//! Two paths are shown:
//!
//! 1. **Recommended (network):** `VerifiedContext::fetch_report` runs
//!    retrieve + schema + hash + DID + signature + per-DataRef recording in
//!    one call, returning a structured `VerificationReport`. See the
//!    commented sketch at the top of `main` for the call shape.
//! 2. **Offline (this example):** for the sig-001 golden vector we bypass the
//!    network and exercise the underlying primitives directly. Useful for
//!    understanding what `fetch_report` does internally.

use acdp::{
    crypto::{compute_content_hash, verify_ed25519},
    types::ContentHash,
};
use serde_json::json;

fn main() {
    // ── Recommended production call (network path) ──────────────────────────
    //
    // ```rust,no_run
    // use acdp::client::{RegistryClient, VerificationPolicy, VerifiedContext};
    // use acdp::did::WebResolver;
    // use acdp::types::CtxId;
    //
    // async fn fetch_one(registry_url: &str, ctx_id: CtxId) -> anyhow::Result<()> {
    //     let client   = RegistryClient::new(registry_url)?;
    //     let resolver = WebResolver::new();
    //     let policy   = VerificationPolicy::default();
    //
    //     let (verified, report) =
    //         VerifiedContext::fetch_report(&client, &resolver, &ctx_id, &policy).await?;
    //
    //     // `report` is a structured diagnostic — see VerificationReport.
    //     assert!(report.schema_ok && report.body_hash_ok && report.signature_ok);
    //     println!("✓ {}", verified.body().title);
    //     Ok(())
    // }
    // ```

    // ── Offline replay against the sig-001 golden vector ────────────────────
    // The body below is a literal copy of what a registry would return
    // for `GET /contexts/<ctx_id>`. In production this comes from the
    // network via `RegistryClient::retrieve`.
    let body_json = json!({
        "version": 1,
        "supersedes": null,
        "agent_id": "did:web:agents.example.com:test-producer",
        "contributors": [],
        "title": "Golden test vector — minimal first version",
        "type": "data_snapshot",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public",
        // Registry-assigned fields. `origin_registry` is the bare DNS
        // hostname per the body schema — NOT a `did:web:` URI
        // (capabilities.registry_did carries the did:web form).
        "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
        "lineage_id": "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
        "origin_registry": "registry.example.com",
        "created_at": "2026-04-16T10:30:15.123Z",
        // Integrity fields
        "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
        "signature": {
            "algorithm": "ed25519",
            "key_id": "did:web:agents.example.com:test-producer#key-1",
            "value": "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
        }
    });

    // ── Step 1: parse + structural validation ───────────────────────────────
    //
    // In production, `validate_body` is called by
    // `VerifiedContext::fetch_with_policy` (when
    // `policy.validate_body_schema = true`, the default). It catches
    // protocol-invalid bodies (oversize fields, did:agent agent_id,
    // inverted data_period, etc.) before paying the SHA-256 + DID
    // resolution cost.
    let body: acdp::types::Body =
        serde_json::from_value(body_json.clone()).expect("body must deserialize");
    acdp::validation::validate_body(&body).expect("validate_body");
    println!("✓ Body structurally valid");

    // ── Step 2: recompute content_hash ──────────────────────────────────────
    let recomputed = compute_content_hash(&body_json).expect("hash failed");
    let stored = ContentHash(body_json["content_hash"].as_str().unwrap().to_string());
    assert_eq!(recomputed, stored, "content_hash mismatch!");
    println!("✓ content_hash matches: {}", recomputed);

    // ── Step 3: verify Ed25519 signature ────────────────────────────────────
    //
    // In production this key is resolved from the producer's
    // `did:web` document via `WebResolver`. Here we hardcode the
    // sig-001 fixture's test public key so the example runs offline.
    let pub_hex = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    let pub_bytes: [u8; 32] = hex::decode(pub_hex).unwrap().try_into().unwrap();
    let sig_b64 = body_json["signature"]["value"].as_str().unwrap();
    verify_ed25519(&pub_bytes, sig_b64, stored.as_str()).expect("signature verification failed");
    println!("✓ Ed25519 signature verified");

    println!(
        "✓ Context is authentic — authored by: {}",
        body_json["agent_id"].as_str().unwrap()
    );
    println!("  Title:   {}", body_json["title"].as_str().unwrap());
    println!("  ctx_id:  {}", body_json["ctx_id"].as_str().unwrap());
}
