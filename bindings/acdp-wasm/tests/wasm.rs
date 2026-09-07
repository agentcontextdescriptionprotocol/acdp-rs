//! Real-engine smoke test for the `#[wasm_bindgen]` exports.
//!
//! Runs the actual exported wrappers (not the pure `core` functions) in a
//! genuine wasm engine to prove the FFI surface links and executes —
//! complementing the native `golden.rs` byte-for-byte parity test, which
//! covers the pure core across every method. Uses the PUBLIC sig-001
//! test-vector constants inline (a browser/WASI wasm module cannot read
//! fixture files), so this needs no `ACDP_SPEC_DIR`.
//!
//! Compiled ONLY for wasm32 — under a native `cargo test` this whole file
//! is configured out, so it never interferes with the host build. Run it
//! with:
//!
//! ```bash
//! wasm-pack test --node bindings/acdp-wasm
//! ```
#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

// sig-001 golden vector (publicly-known TEST keypair — private seed is 32
// zero bytes; NEVER production material).
const PUB_KEY_B64: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
const CONTENT_HASH: &str =
    "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5";
const SIG_B64: &str =
    "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ==";
const BODY_JSON: &str = r#"{
  "version": 1,
  "supersedes": null,
  "agent_id": "did:web:agents.example.com:test-producer",
  "contributors": [],
  "title": "Golden test vector — minimal first version",
  "type": "data_snapshot",
  "data_refs": [],
  "derived_from": [],
  "visibility": "public",
  "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
  "signature": {
    "algorithm": "ed25519",
    "key_id": "did:web:agents.example.com:test-producer#key-1",
    "value": "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
  }
}"#;

fn is_valid(verdict: &str) -> bool {
    let v: serde_json::Value = serde_json::from_str(verdict).unwrap();
    v["valid"].as_bool().unwrap_or(false)
}

#[wasm_bindgen_test]
fn sig_001_content_hash_verifies_in_wasm() {
    let verdict = acdp_wasm::verify_content_hash(BODY_JSON, CONTENT_HASH)
        .expect("content_hash export must not throw on golden input");
    assert!(is_valid(&verdict), "content_hash must verify: {verdict}");
}

#[wasm_bindgen_test]
fn sig_001_signature_verifies_in_wasm() {
    let verdict = acdp_wasm::verify_signature_ed25519(PUB_KEY_B64, SIG_B64, CONTENT_HASH)
        .expect("signature export must not throw on golden input");
    assert!(is_valid(&verdict), "signature must verify: {verdict}");

    // Negative control: a tampered hash must NOT verify.
    let tampered = CONTENT_HASH.replace("f170", "0000");
    let verdict = acdp_wasm::verify_signature_ed25519(PUB_KEY_B64, SIG_B64, &tampered)
        .expect("negative control must not throw");
    assert!(!is_valid(&verdict), "tampered signature must FAIL");
}

// ── verifyCtxIdBinding (RFC-ACDP-0006 §4.1 step 7) ───────────────────────────

const CTX: &str = "acdp://registry.example.com/12345678-1234-4321-8123-123456781234";
const OTHER_CTX_UUID: &str = "acdp://registry.example.com/00000000-0000-4000-8000-000000000000";
const OTHER_CTX_AUTHORITY: &str = "acdp://other.example.com/12345678-1234-4321-8123-123456781234";
// Mirrors the core `verify_ctx_id_binding` fixture: only the last three
// UUID hex chars are uppercase.
const UPPERCASE_UUID_CTX: &str = "acdp://registry.example.com/00000000-0000-4000-8000-000000000AAA";

/// A full retrieval-shape `Body` (registry-assigned fields included) with
/// the given `ctx_id` — `verifyCtxIdBinding` only reads `ctx_id`, so the
/// content_hash/signature need not be mutually consistent here.
fn body_with_ctx_id(ctx_id: &str) -> String {
    format!(
        r#"{{
  "ctx_id": "{ctx_id}",
  "lineage_id": "lin:sha256:{}",
  "origin_registry": "registry.example.com",
  "created_at": "2026-01-01T00:00:00.000Z",
  "version": 1,
  "supersedes": null,
  "agent_id": "did:web:agents.example.com:test-producer",
  "contributors": [],
  "title": "Golden test vector — minimal first version",
  "type": "data_snapshot",
  "data_refs": [],
  "derived_from": [],
  "visibility": "public",
  "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
  "signature": {{
    "algorithm": "ed25519",
    "key_id": "did:web:agents.example.com:test-producer#key-1",
    "value": "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
  }}
}}"#,
        "a".repeat(64)
    )
}

#[wasm_bindgen_test]
fn verify_ctx_id_matching_ids_ok_in_wasm() {
    // Positive control for every failure case below.
    let body = body_with_ctx_id(CTX);
    let verdict = acdp_wasm::verify_ctx_id_binding(&body, CTX)
        .expect("verifyCtxIdBinding must not throw on matching ids");
    assert!(is_valid(&verdict), "matching ctx_id must verify: {verdict}");
}

#[wasm_bindgen_test]
fn verify_ctx_id_rejects_uuid_only_mismatch_in_wasm() {
    let body = body_with_ctx_id(CTX);
    let verdict = acdp_wasm::verify_ctx_id_binding(&body, OTHER_CTX_UUID)
        .expect("a mismatch is a verdict, not a throw");
    assert!(!is_valid(&verdict), "UUID-only mismatch must FAIL");
}

#[wasm_bindgen_test]
fn verify_ctx_id_rejects_authority_only_mismatch_in_wasm() {
    // A mismatch differing only in the authority (not the UUID) must
    // also be rejected.
    let body = body_with_ctx_id(CTX);
    let verdict = acdp_wasm::verify_ctx_id_binding(&body, OTHER_CTX_AUTHORITY)
        .expect("a mismatch is a verdict, not a throw");
    assert!(!is_valid(&verdict), "authority-only mismatch must FAIL");
}

#[wasm_bindgen_test]
fn verify_ctx_id_throws_on_malformed_expected_in_wasm() {
    // `expected_ctx_id` is host input (mirrors `verify_content_hash`'s
    // `expected_hash` and `verify_receipt`'s `expected_ctx_id`), so a
    // malformed value is pre-parsed and throws — NOT a fail verdict.
    let body = body_with_ctx_id(CTX);
    assert!(
        acdp_wasm::verify_ctx_id_binding(&body, "not-a-ctx-id").is_err(),
        "malformed expected_ctx_id must throw, not return a fail verdict"
    );
}

#[wasm_bindgen_test]
fn verify_ctx_id_rejects_uppercase_uuid_on_served_side_in_wasm() {
    // Uppercase-UUID rejection must be enforced on the served side too,
    // not just the expected side.
    let body = body_with_ctx_id(UPPERCASE_UUID_CTX);
    let verdict = acdp_wasm::verify_ctx_id_binding(&body, CTX)
        .expect("malformed served ctx_id is a fail verdict");
    assert!(!is_valid(&verdict), "uppercase served UUID must FAIL");
}

#[wasm_bindgen_test]
fn verify_ctx_id_throws_on_uppercase_uuid_on_expected_side_in_wasm() {
    // Same host-input reasoning as the malformed-expected case above:
    // an uppercase-UUID `expected_ctx_id` fails `CtxId::parse` and must
    // throw, not return a fail verdict.
    let body = body_with_ctx_id(CTX);
    assert!(
        acdp_wasm::verify_ctx_id_binding(&body, UPPERCASE_UUID_CTX).is_err(),
        "uppercase expected UUID must throw, not return a fail verdict"
    );
}

#[wasm_bindgen_test]
fn verify_ctx_id_rejects_malformed_body_json_in_wasm() {
    // Malformed body JSON is malformed HOST input — this one throws.
    assert!(acdp_wasm::verify_ctx_id_binding("not json", CTX).is_err());
}

// ── verifyReceipt (RFC-ACDP-0010 §8 registry receipts) ───────────────────
//
// The real-engine complement to golden.rs's native `verify_receipt_json`
// coverage: proves the `#[wasm_bindgen(js_name = verifyReceipt)]` export
// itself links and executes in a genuine wasm engine. rcpt-001 fixture
// values mirror the py/node `RCPT001`/`RCPT_001` constants exactly.

const RCPT_001_RECEIPT_JSON: &str = r#"{
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

/// The sig-001 body `RCPT_001_RECEIPT_JSON` attests (assembled from
/// `producer_content` + `registry_assigned`, mirroring golden.rs's
/// `rcpt_001_body_json`), with `lineage_id`/`origin_registry`/
/// `created_at` overridable to build a mismatch fixture.
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

#[wasm_bindgen_test]
fn rcpt_001_receipt_verifies_in_wasm() {
    let verdict = acdp_wasm::verify_receipt(
        RCPT_001_RECEIPT_JSON,
        &rcpt_001_body(),
        RCPT_001_REGISTRY_KEY_B64,
        RCPT_001_CTX_ID,
        RCPT_001_CONTENT_HASH,
        RCPT_001_FINGERPRINT,
    )
    .expect("verifyReceipt must not throw on golden input");
    assert!(is_valid(&verdict), "rcpt-001 must verify: {verdict}");
}

#[wasm_bindgen_test]
fn rcpt_001_rejects_body_lineage_id_mismatch_in_wasm() {
    let mismatched_body = rcpt_001_body_json(
        &format!("lin:sha256:{}", "a".repeat(64)),
        "registry.example.com",
        "2026-04-16T10:30:15.123Z",
    );
    let verdict = acdp_wasm::verify_receipt(
        RCPT_001_RECEIPT_JSON,
        &mismatched_body,
        RCPT_001_REGISTRY_KEY_B64,
        RCPT_001_CTX_ID,
        RCPT_001_CONTENT_HASH,
        RCPT_001_FINGERPRINT,
    )
    .expect("a body-binding mismatch is a verdict, not a throw");
    assert!(!is_valid(&verdict), "lineage_id mismatch must FAIL");
}

#[wasm_bindgen_test]
fn rcpt_001_rejects_body_origin_registry_mismatch_in_wasm() {
    let mismatched_body = rcpt_001_body_json(
        "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
        "other.example.com",
        "2026-04-16T10:30:15.123Z",
    );
    let verdict = acdp_wasm::verify_receipt(
        RCPT_001_RECEIPT_JSON,
        &mismatched_body,
        RCPT_001_REGISTRY_KEY_B64,
        RCPT_001_CTX_ID,
        RCPT_001_CONTENT_HASH,
        RCPT_001_FINGERPRINT,
    )
    .expect("a body-binding mismatch is a verdict, not a throw");
    assert!(!is_valid(&verdict), "origin_registry mismatch must FAIL");
}

#[wasm_bindgen_test]
fn rcpt_001_rejects_body_created_at_mismatch_in_wasm() {
    let mismatched_body = rcpt_001_body_json(
        "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
        "registry.example.com",
        "2026-04-16T10:30:15.124Z",
    );
    let verdict = acdp_wasm::verify_receipt(
        RCPT_001_RECEIPT_JSON,
        &mismatched_body,
        RCPT_001_REGISTRY_KEY_B64,
        RCPT_001_CTX_ID,
        RCPT_001_CONTENT_HASH,
        RCPT_001_FINGERPRINT,
    )
    .expect("a body-binding mismatch is a verdict, not a throw");
    assert!(!is_valid(&verdict), "created_at mismatch must FAIL");
}

#[wasm_bindgen_test]
fn rcpt_001_rejects_malformed_body_json_in_wasm() {
    // A malformed body_json is malformed HOST input — this one throws,
    // distinct from a cross_check_body mismatch verdict.
    assert!(acdp_wasm::verify_receipt(
        RCPT_001_RECEIPT_JSON,
        "not json",
        RCPT_001_REGISTRY_KEY_B64,
        RCPT_001_CTX_ID,
        RCPT_001_CONTENT_HASH,
        RCPT_001_FINGERPRINT,
    )
    .is_err());
}
