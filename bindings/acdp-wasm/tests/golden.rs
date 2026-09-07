//! Golden-vector parity for the `acdp-wasm` verifier surface.
//!
//! Runs the canonical spec fixtures `sig-001` (Ed25519 content-hash +
//! signature) and `wit-001` (witness cosignature) through the SAME pure
//! `core` functions the `wasm-bindgen` exports wrap, and asserts they
//! reproduce the pinned golden values byte-for-byte. This is the wasm
//! member of the binding-family parity guarantee: the Python
//! (`bindings/acdp-py`) and Node (`bindings/acdp-node`) suites pin the
//! identical `sig-001` / `wit-001` constants, so a green run here proves
//! the wasm surface matches them (and the Rust core) exactly.
//!
//! The functions under test are target-independent pure Rust, so this
//! runs as an ordinary NATIVE `cargo test` — no browser engine needed.
//! The `wasm32-unknown-unknown` build itself is proven by the CI job and
//! by `cargo build --target wasm32-unknown-unknown`.
//!
//! Fixtures are located via `ACDP_SPEC_DIR` (falling back to a sibling
//! checkout) and the test SKIPS gracefully when neither is available —
//! matching the root `tests/conformance.rs` convention.

use std::path::{Path, PathBuf};

use acdp_wasm::core;

/// Locate the ACDP spec checkout: `ACDP_SPEC_DIR` first, then any
/// ancestor's sibling `agentcontextdistributionprotocol` directory
/// (this crate sits two levels below the repo root at
/// `bindings/acdp-wasm`, so the search walks up).
fn spec_root() -> Option<PathBuf> {
    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for ancestor in manifest_dir.ancestors() {
        let candidate = ancestor.join("agentcontextdistributionprotocol");
        if candidate.join("schemas/conformance").exists() {
            return Some(candidate);
        }
    }
    None
}

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

fn verdict_valid(json: &str) -> bool {
    let v: serde_json::Value = serde_json::from_str(json).expect("verdict must be JSON");
    v.get("valid").and_then(|b| b.as_bool()).unwrap_or(false)
}

/// sig-001: recompute `content_hash` over the golden publish-request
/// body and verify the Ed25519 signature over the ASCII
/// `"sha256:<hex>"` string — the two byte-exact checks a browser
/// consumer performs on a `did:web` producer's context.
#[test]
fn sig_001_content_hash_and_signature() {
    let Some(root) = spec_root() else {
        eprintln!("skipping sig-001: no ACDP spec checkout (set ACDP_SPEC_DIR)");
        return;
    };
    let fixture = read_json(&root.join("schemas/conformance/sig-001-ed25519-golden.json"));
    let keypair = &fixture["test_keypair"];
    let pub_b64 = keypair["public_key_base64"]
        .as_str()
        .expect("public_key_base64");
    let vector = &fixture["vectors"][0];
    let expected = &vector["expected"];
    let body = &expected["publish_request_body"];
    let content_hash = expected["content_hash"].as_str().expect("content_hash");
    let sig_b64 = expected["signature_value_base64"]
        .as_str()
        .expect("signature_value_base64");

    // 1. content_hash recomputation over the RAW wire body.
    let body_json = serde_json::to_string(body).unwrap();
    let verdict = core::verify_content_hash_json(&body_json, content_hash)
        .expect("content_hash verify must not error on golden input");
    assert!(
        verdict_valid(&verdict),
        "sig-001 content_hash must verify, got {verdict}"
    );

    // 2. Ed25519 signature over the ASCII content_hash string.
    let verdict = core::verify_signature_ed25519(pub_b64, sig_b64, content_hash)
        .expect("signature verify must not error on golden input");
    assert!(
        verdict_valid(&verdict),
        "sig-001 signature must verify, got {verdict}"
    );

    // Negative control: the same key over a tampered hash must NOT verify
    // (proves the wrapper is really checking, not always-true).
    let tampered = content_hash.replace("f170", "0000");
    let verdict = core::verify_signature_ed25519(pub_b64, sig_b64, &tampered)
        .expect("negative control must not error");
    assert!(
        !verdict_valid(&verdict),
        "sig-001 signature over a tampered hash must FAIL"
    );
}

/// wit-001: re-mint the witness cosignature over the log-001 checkpoint
/// subset with the witness test seed and assert byte-for-byte equality
/// with the pinned golden `log_cosignature` (the sig-001-equivalent for
/// the witness layer). Then round-trip it through offline verification.
#[test]
fn wit_001_cosignature_mint_and_verify() {
    let Some(root) = spec_root() else {
        eprintln!("skipping wit-001: no ACDP spec checkout (set ACDP_SPEC_DIR)");
        return;
    };
    let fixture = read_json(&root.join("schemas/conformance/wit-001-cosignature-golden.json"));
    let keypair = &fixture["witness_test_keypair"];
    let seed_hex = keypair["private_seed_hex"]
        .as_str()
        .expect("private_seed_hex");
    let witness_pub_hex = keypair["public_key_hex"].as_str().expect("public_key_hex");
    let vector = &fixture["vectors"][0];
    let unsigned = &vector["cosignature_unsigned"];
    let witness_id = unsigned["witness_id"].as_str().expect("witness_id");
    let witnessed_checkpoint = &unsigned["witnessed_checkpoint"];
    let witnessed_at = unsigned["witnessed_at"].as_str().expect("witnessed_at");
    let expected_cosig = &vector["expected"]["log_cosignature"];

    // 1. Deterministic re-mint reproduces the golden cosignature exactly.
    let checkpoint_json = serde_json::to_string(witnessed_checkpoint).unwrap();
    let minted =
        core::build_witness_cosignature_json(&checkpoint_json, witness_id, seed_hex, witnessed_at)
            .expect("witness cosignature mint must succeed on golden input");
    let minted_value: serde_json::Value = serde_json::from_str(&minted).unwrap();
    assert_eq!(
        &minted_value, expected_cosig,
        "wit-001 re-mint must reproduce the golden cosignature byte-for-byte"
    );

    // 2. The minted cosignature verifies against the witness's resolved
    //    key for a consumer holding the (full) log-001 checkpoint (§8).
    let witness_doc = witness_did_doc(witness_id, witness_pub_hex);
    let full_checkpoint = full_log_checkpoint(witnessed_checkpoint);
    // A consumer clock a few seconds after witnessed_at (fixture-pinned).
    let verdict = core::verify_witness_cosignature_json(
        &minted,
        &witness_doc,
        &full_checkpoint,
        Some("2026-07-04T12:00:10.000Z"),
        None,
    )
    .expect("witness verify must not error on golden input");
    assert!(
        verdict_valid(&verdict),
        "wit-001 cosignature must verify, got {verdict}"
    );
}

/// A minimal witness DID document carrying the witness key in both
/// `verificationMethod` and `assertionMethod` (RFC-ACDP-0015 §9) —
/// byte-shape-identical to the one the py/node suites build.
fn witness_did_doc(did: &str, pub_hex: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let key_id = format!("{did}#witness-key-1");
    let x = URL_SAFE_NO_PAD.encode(hex::decode(pub_hex).unwrap());
    serde_json::json!({
        "id": did,
        "verificationMethod": [{
            "id": key_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
        }],
        "assertionMethod": [key_id],
    })
    .to_string()
}

/// Expand the witnessed-checkpoint subset into a full (unsigned-here)
/// RFC-ACDP-0012 checkpoint the consumer is assumed to hold. Only the
/// `{log_id, tree_size, root_hash}` binding tuple is checked by §8 step
/// 4, so a placeholder signature suffices for the binding round-trip.
fn full_log_checkpoint(witnessed: &serde_json::Value) -> String {
    serde_json::json!({
        "checkpoint_version": "acdp-log/1",
        "log_id": witnessed["log_id"],
        "tree_size": witnessed["tree_size"],
        "root_hash": witnessed["root_hash"],
        "timestamp": witnessed["timestamp"],
        "signature": {
            "algorithm": "ed25519",
            "key_id": "did:web:registry.example.com#receipt-key-1",
            "value": "o5rJmVE+1w/f7xAvW2P4vHA9FqWcMpS0crUPkMUZKSrBhrCVt/jyS+PCgnHNsNpmr+N+sR9I9qbqQ/Y0ZfOrDQ==",
        },
    })
    .to_string()
}

// ── rcpt-001 (RFC-ACDP-0010 §8 registry receipts) ────────────────────────
//
// Hardcoded (not loaded from `ACDP_SPEC_DIR`) to mirror the py/node
// `RCPT001`/`RCPT_001` fixtures exactly — a receipt over the sig-001
// content_hash, minted by a registry whose Ed25519 receipt key has seed
// `[0x11u8; 32]`, binding the fp-001 producer-key fingerprint. These
// tests exercise `core::verify_receipt_json` directly, giving this
// binding real receipt coverage under an ordinary native `cargo test`
// (F2: the wasm-bindgen `verifyReceipt` export previously had none from
// any target).

const RCPT_001_JSON: &str = r#"{
  "registry_did": "did:web:registry.example.com",
  "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
  "lineage_id": "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
  "origin_registry": "registry.example.com",
  "created_at": "2026-04-16T10:30:15.123Z",
  "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
  "key_fingerprint": "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
  "signature": {
    "algorithm": "ed25519",
    "key_id": "did:web:registry.example.com#receipt-key-1",
    "value": "vBgQKmn17pHXXY95C07BBeconmjDIdYIvxN5B+YXrQ7tIzFsDNsh1TglzgxOyPUp8lwTz7zwMNiK+Sn5whveDg=="
  }
}"#;

const RCPT_001_REGISTRY_KEY_B64: &str = "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=";
const RCPT_001_CTX_ID: &str = "acdp://registry.example.com/12345678-1234-4321-8123-123456781234";
const RCPT_001_CONTENT_HASH: &str =
    "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5";
const RCPT_001_FINGERPRINT: &str =
    "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070";

/// The sig-001 body `RCPT_001_JSON` attests, assembled from sig-001's
/// `producer_content`/`publish_request_body` plus its
/// `registry_assigned` block (schemas/conformance/sig-001*.json:49-54)
/// — `rcpt-001-receipt-golden.json` ships no paired body. `supersedes`
/// is included as `null` (not omitted): `Body` has no
/// `#[serde(default)]` on that field, so the key MUST be present even
/// when null. Callers may override individual fields to build a
/// mismatch fixture.
fn rcpt_001_body_json(lineage_id: &str, origin_registry: &str, created_at: &str) -> String {
    format!(
        r#"{{
  "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
  "lineage_id": "{lineage_id}",
  "origin_registry": "{origin_registry}",
  "created_at": "{created_at}",
  "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
  "signature": {{
    "algorithm": "ed25519",
    "key_id": "did:web:agents.example.com:test-producer#key-1",
    "value": "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
  }},
  "version": 1,
  "supersedes": null,
  "agent_id": "did:web:agents.example.com:test-producer",
  "contributors": [],
  "title": "Golden test vector — minimal first version",
  "type": "data_snapshot",
  "data_refs": [],
  "derived_from": [],
  "visibility": "public"
}}"#
    )
}

fn rcpt_001_body() -> String {
    rcpt_001_body_json(
        "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
        "registry.example.com",
        "2026-04-16T10:30:15.123Z",
    )
}

#[test]
fn rcpt_001_receipt_verifies() {
    let verdict = core::verify_receipt_json(
        RCPT_001_JSON,
        &rcpt_001_body(),
        RCPT_001_REGISTRY_KEY_B64,
        RCPT_001_CTX_ID,
        RCPT_001_CONTENT_HASH,
        RCPT_001_FINGERPRINT,
    )
    .expect("verify_receipt_json must not error on golden input");
    assert!(
        verdict_valid(&verdict),
        "rcpt-001 must verify, got {verdict}"
    );
}

#[test]
fn rcpt_001_rejects_body_lineage_id_mismatch() {
    // §8 step 3 body binding: the receipt's `lineage_id` MUST equal the
    // accompanying body's `lineage_id`. A mismatch is a verification
    // OUTCOME (a fail verdict), never a host-input `Err`.
    let mismatched_body = rcpt_001_body_json(
        &format!("lin:sha256:{}", "a".repeat(64)),
        "registry.example.com",
        "2026-04-16T10:30:15.123Z",
    );
    let verdict = core::verify_receipt_json(
        RCPT_001_JSON,
        &mismatched_body,
        RCPT_001_REGISTRY_KEY_B64,
        RCPT_001_CTX_ID,
        RCPT_001_CONTENT_HASH,
        RCPT_001_FINGERPRINT,
    )
    .expect("a body-binding mismatch is a verdict, not an error");
    assert!(!verdict_valid(&verdict), "lineage_id mismatch must FAIL");
    assert!(
        verdict.to_lowercase().contains("lineage_id"),
        "verdict should name the mismatched field, got {verdict}"
    );
}

#[test]
fn rcpt_001_rejects_body_origin_registry_mismatch() {
    // §8 step 3 body binding: the receipt's `origin_registry` MUST
    // equal the accompanying body's `origin_registry`.
    let mismatched_body = rcpt_001_body_json(
        "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
        "other.example.com",
        "2026-04-16T10:30:15.123Z",
    );
    let verdict = core::verify_receipt_json(
        RCPT_001_JSON,
        &mismatched_body,
        RCPT_001_REGISTRY_KEY_B64,
        RCPT_001_CTX_ID,
        RCPT_001_CONTENT_HASH,
        RCPT_001_FINGERPRINT,
    )
    .expect("a body-binding mismatch is a verdict, not an error");
    assert!(
        !verdict_valid(&verdict),
        "origin_registry mismatch must FAIL"
    );
    assert!(
        verdict.to_lowercase().contains("origin_registry"),
        "verdict should name the mismatched field, got {verdict}"
    );
}

#[test]
fn rcpt_001_rejects_body_created_at_mismatch() {
    // §8 step 3 body binding: the receipt's `created_at` MUST equal the
    // accompanying body's `created_at`.
    let mismatched_body = rcpt_001_body_json(
        "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
        "registry.example.com",
        "2026-04-16T10:30:15.124Z",
    );
    let verdict = core::verify_receipt_json(
        RCPT_001_JSON,
        &mismatched_body,
        RCPT_001_REGISTRY_KEY_B64,
        RCPT_001_CTX_ID,
        RCPT_001_CONTENT_HASH,
        RCPT_001_FINGERPRINT,
    )
    .expect("a body-binding mismatch is a verdict, not an error");
    assert!(!verdict_valid(&verdict), "created_at mismatch must FAIL");
    assert!(
        verdict.to_lowercase().contains("created_at"),
        "verdict should name the mismatched field, got {verdict}"
    );
}

#[test]
fn rcpt_001_rejects_malformed_body_json() {
    // A malformed `body_json` is a HOST-input error (`Err`), distinct
    // from a `cross_check_body` mismatch (a `{"valid": false, ...}`
    // verdict).
    let err = core::verify_receipt_json(
        RCPT_001_JSON,
        "not json",
        RCPT_001_REGISTRY_KEY_B64,
        RCPT_001_CTX_ID,
        RCPT_001_CONTENT_HASH,
        RCPT_001_FINGERPRINT,
    )
    .expect_err("malformed body_json must be a host-input Err, not Ok(verdict)");
    assert!(
        err.to_lowercase().contains("body"),
        "error should name the body as the malformed input, got {err}"
    );
}
