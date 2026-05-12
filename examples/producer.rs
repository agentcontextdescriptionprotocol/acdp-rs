//! Example: build and sign a publish request.
//!
//! Run with: `cargo run --example producer`

use acdp::{
    crypto::SigningKey,
    producer::Producer,
    types::{AgentDid, ContextType, DataRef, DataRefType, Visibility},
};

fn main() {
    // ── 1. Create a signing key ─────────────────────────────────────────────
    // In production, load from secure storage (HSM, env var, …). The
    // example uses `SigningKey::generate()` so that this binary
    // exercises a real OS-entropy keypair and the run is repeatable in
    // CI without committing a private seed.
    let key = SigningKey::generate();

    // ── 2. Create a producer ────────────────────────────────────────────────
    let agent_id = AgentDid::new("did:web:agents.example.com:my-agent");
    let key_id = "did:web:agents.example.com:my-agent#key-1";
    let producer = Producer::new(key, agent_id, key_id);

    // ── 3. Build a publish request ──────────────────────────────────────────
    let request = producer
        .publish_request()
        .title("Q1 2026 revenue snapshot")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .description("Quarterly revenue figures aggregated by region.")
        .tags(vec!["finance", "revenue", "q1-2026"])
        .domain("finance")
        .data_refs(vec![DataRef::uri(
            DataRefType::PrimaryResult,
            "https://data.example.com/revenue/q1-2026.parquet",
        )])
        .summary("Quarterly revenue snapshot for Q1 2026.")
        .metadata(serde_json::json!({
            "quarter": "Q1-2026",
            "currency": "USD"
        }))
        .build()
        .expect("build failed");

    // ── 4. Inspect the result ───────────────────────────────────────────────
    println!("content_hash:  {}", request.content_hash);
    println!("signature alg: {}", request.signature.algorithm);
    println!("key_id:        {}", request.signature.key_id);
    println!("sig (b64):     {}…", &request.signature.value[..20]);

    // Serialize to JSON (what you would POST to the registry)
    let json = serde_json::to_string_pretty(&request).unwrap();
    println!("\nPublish request JSON:\n{json}");
}
