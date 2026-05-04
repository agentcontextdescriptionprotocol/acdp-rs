//! Example: retrieve and verify a context.
//!
//! Run with: `cargo run --example consumer --features client`
//!
//! This example verifies the golden test vector locally (no HTTP needed).

use acdp::{
    crypto::{compute_content_hash, verify_ed25519},
    types::ContentHash,
};
use serde_json::json;

fn main() {
    // Simulate a retrieved context (in production this comes from the registry)
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
        // Registry-assigned fields
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

    // ── Step 1: recompute content_hash ───────────────────────────────────────
    let recomputed = compute_content_hash(&body_json).expect("hash failed");
    let stored = ContentHash(body_json["content_hash"].as_str().unwrap().to_string());
    assert_eq!(recomputed, stored, "content_hash mismatch!");
    println!("✓ content_hash matches: {}", recomputed);

    // ── Step 2: verify signature (using the known test public key) ───────────
    // In production you would resolve the producer's DID document first.
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
