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
