//! `AcdpVerifier` — consumer-side content_hash and signature verification.
//!
//! All methods are static. DID resolution is intentionally NOT done here
//! — that requires async HTTP and belongs in the host language (or the
//! Rust `client` feature called from native code). This binding exposes
//! the pure-crypto checks every consumer needs:
//!
//! * `verify_content_hash` — recompute `sha256(JCS(producer_content))`
//!   and compare against the body's stored `content_hash`.
//! * `verify_signature` — Ed25519 verify against an already-known
//!   public key, useful once the host has resolved the producer's DID.
//! * `verify_body_offline` / `verify_publish_request_offline` — full
//!   verification for `did:key` producers (ACDP 0.2), where the key is
//!   the identity and no resolution is needed at all.
//! * `canonical_preimage` / `explain_hash_mismatch` — hash-divergence
//!   diagnostics (WS-D2).
//! * `fingerprint_ed25519_b64` / `verify_receipt` — registry-receipt
//!   verification (ACDP 0.2, RFC-ACDP-0010).

use acdp::crypto::{
    canonical_preimage, explain_hash_mismatch, fingerprint_ed25519, verify_body_offline,
    verify_content_hash, verify_ecdsa_p256, verify_ed25519,
    verify_publish_request_signature_offline,
};
use acdp::types::{Body, ContentHash, CtxId, PublishRequest, RegistryReceipt};
use base64::{engine::general_purpose::STANDARD, Engine};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

/// Decode a standard-base64 raw 32-byte Ed25519 public key.
fn decode_ed25519_b64(public_key_b64: &str) -> PyResult<[u8; 32]> {
    let bytes: Vec<u8> = STANDARD
        .decode(public_key_b64)
        .map_err(|e| PyValueError::new_err(format!("invalid public_key_b64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("public key must decode to 32 bytes"))
}

/// Consumer-side verification utilities. All methods are static.
#[pyclass(name = "AcdpVerifier")]
pub struct PyAcdpVerifier;

#[pymethods]
impl PyAcdpVerifier {
    /// Verify that a body's `content_hash` matches the SHA-256 over its
    /// JCS-canonicalized producer-controlled fields.
    ///
    /// * `body_json` — the `body` object from a `FullContext` retrieval
    ///   (or the `PublishRequest` itself — both share the §5.7 layout).
    /// * `expected_hash` — the `body.content_hash` string
    ///   (`"sha256:<64-hex>"`).
    ///
    /// Returns `True` on success. Raises `RuntimeError` on mismatch or
    /// `ValueError` on malformed JSON.
    #[staticmethod]
    fn verify_content_hash(body_json: &str, expected_hash: &str) -> PyResult<bool> {
        let body: serde_json::Value = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        // Validate the hash envelope up-front so a malformed
        // `expected_hash` (wrong prefix, wrong length, uppercase hex)
        // produces a clear ValueError instead of being treated as a
        // recomputation mismatch.
        let stored = ContentHash::parse(expected_hash)
            .map_err(|e| PyValueError::new_err(format!("invalid content_hash: {e}")))?;
        verify_content_hash(&body, &stored)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(format!("content_hash mismatch: {e}")))
    }

    /// Verify an Ed25519 signature over a `content_hash` string.
    ///
    /// The signing input per RFC-ACDP-0001 §5.8 is the ASCII bytes of
    /// the full `"sha256:<hex>"` string — NOT the raw 32-byte digest.
    /// This wrapper forwards exactly the same bytes
    /// `acdp::crypto::verify_ed25519` expects.
    ///
    /// * `pub_key_b64` — standard base64 (padded) of the 32-byte raw
    ///   Ed25519 public key (same format as
    ///   `AcdpProducer.public_key_b64`).
    /// * `sig_b64` — the `body.signature.value` field from the wire
    ///   format.
    /// * `content_hash` — the `body.content_hash` string.
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed
    /// base64 input or `RuntimeError` on a verification failure.
    #[staticmethod]
    fn verify_signature(pub_key_b64: &str, sig_b64: &str, content_hash: &str) -> PyResult<bool> {
        let pub_bytes: Vec<u8> = STANDARD
            .decode(pub_key_b64)
            .map_err(|e| PyValueError::new_err(format!("invalid pub_key_b64: {e}")))?;
        let arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("public key must decode to 32 bytes"))?;
        verify_ed25519(&arr, sig_b64, content_hash)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(format!("signature invalid: {e}")))
    }

    /// Verify an ECDSA-P256 signature over a `content_hash` string.
    ///
    /// The counterpart to [`AcdpP256Producer`] signing. The signing input
    /// per RFC-ACDP-0001 §5.8 is the ASCII bytes of the full
    /// `"sha256:<hex>"` string — NOT the raw 32-byte digest. The wire
    /// signature is IEEE 1363 `r‖s` (64 bytes, base64), NOT DER.
    ///
    /// * `pub_key_sec1_b64` — standard base64 of the 65-byte
    ///   SEC1-uncompressed public key (`0x04 || x || y`), the same format
    ///   as `AcdpP256Producer.public_key_sec1_b64`.
    /// * `sig_b64` — the `body.signature.value` field from the wire
    ///   format (88-char base64 of the 64-byte `r‖s`).
    /// * `content_hash` — the `body.content_hash` string.
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed
    /// base64 input or `RuntimeError` on a verification failure.
    ///
    /// [`AcdpP256Producer`]: crate::producer::PyAcdpP256Producer
    #[staticmethod]
    fn verify_signature_p256(
        pub_key_sec1_b64: &str,
        sig_b64: &str,
        content_hash: &str,
    ) -> PyResult<bool> {
        let pub_bytes: Vec<u8> = STANDARD
            .decode(pub_key_sec1_b64)
            .map_err(|e| PyValueError::new_err(format!("invalid pub_key_sec1_b64: {e}")))?;
        verify_ecdsa_p256(&pub_bytes, sig_b64, content_hash)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(format!("signature invalid: {e}")))
    }

    /// Fully verify a `did:key` body offline (ACDP 0.2) — structural
    /// validation, `content_hash` recomputation, key_id/agent_id
    /// consistency, and signature verification against the key embedded
    /// in the DID itself. No resolution, no network, no key argument.
    ///
    /// * `body_json` — the `body` object from a `FullContext` retrieval.
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed JSON
    /// or `RuntimeError` on any verification failure (including a
    /// non-`did:key` producer — `did:web` bodies need DID resolution,
    /// which stays in the host language by design).
    #[staticmethod]
    fn verify_body_offline(body_json: &str) -> PyResult<bool> {
        let body: Body = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        verify_body_offline(&body)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Fully verify a `did:key` PublishRequest offline (ACDP 0.2):
    /// recompute and check `content_hash`, then verify the signature
    /// against the key embedded in the producer's `did:key` DID.
    ///
    /// * `request_json` — the wire PublishRequest JSON (e.g. the output
    ///   of `AcdpProducer.build_publish_request` on a did:key producer).
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed JSON
    /// or `RuntimeError` on hash mismatch, key/agent inconsistency, a
    /// non-`did:key` producer, or a bad signature.
    #[staticmethod]
    fn verify_publish_request_offline(request_json: &str) -> PyResult<bool> {
        let req: PublishRequest = serde_json::from_str(request_json)
            .map_err(|e| PyValueError::new_err(format!("invalid request JSON: {e}")))?;
        // The offline signature check assumes the content_hash was
        // independently recomputed — do that first, over the raw wire
        // object (so unknown fields participate, mirroring the core).
        let value: serde_json::Value = serde_json::from_str(request_json)
            .map_err(|e| PyValueError::new_err(format!("invalid request JSON: {e}")))?;
        verify_content_hash(&value, &req.content_hash)
            .map_err(|e| PyRuntimeError::new_err(format!("content_hash mismatch: {e}")))?;
        verify_publish_request_signature_offline(&req)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Diagnose a `content_hash` mismatch by probing the known
    /// divergence patterns (`acdp_version` omitted vs explicit,
    /// null-vs-absent optionals, sub-millisecond timestamps — WS-D2).
    /// Returns a human-readable report; this is tooling for chasing
    /// "the hash that won't reproduce", never a verification verdict.
    ///
    /// * `body_json` — the body (or PublishRequest) JSON object.
    /// * `expected_hash` — the hash the counterparty computed
    ///   (`"sha256:<64-hex>"`).
    #[staticmethod]
    fn explain_hash_mismatch(body_json: &str, expected_hash: &str) -> PyResult<String> {
        let body: serde_json::Value = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        let expected = ContentHash::parse(expected_hash)
            .map_err(|e| PyValueError::new_err(format!("invalid content_hash: {e}")))?;
        explain_hash_mismatch(&body, &expected).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// The exact JCS canonical preimage hashed for `content_hash`,
    /// returned as a string (the canonical bytes are always valid UTF-8
    /// JSON). When two SDKs disagree on a hash, diff their preimages —
    /// that localizes the divergence in a way two opaque digests never
    /// can. See also [`explain_hash_mismatch`] for an automated first
    /// pass.
    ///
    /// [`explain_hash_mismatch`]: Self::explain_hash_mismatch
    #[staticmethod]
    fn canonical_preimage(body_json: &str) -> PyResult<String> {
        let body: serde_json::Value = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        let (bytes, _hash) =
            canonical_preimage(&body).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        String::from_utf8(bytes)
            .map_err(|e| PyRuntimeError::new_err(format!("canonical bytes not UTF-8: {e}")))
    }

    /// Fingerprint a raw Ed25519 public key for receipt cross-checks
    /// (ACDP 0.2, RFC-ACDP-0010):
    /// `"sha256:" + lowercase_hex(SHA-256(raw 32-byte key))`.
    ///
    /// * `public_key_b64` — standard base64 (padded) of the 32-byte raw
    ///   key, the same format as `AcdpProducer.public_key_b64`.
    #[staticmethod]
    fn fingerprint_ed25519_b64(public_key_b64: &str) -> PyResult<String> {
        let key = decode_ed25519_b64(public_key_b64)?;
        Ok(fingerprint_ed25519(&key))
    }

    /// Verify a registry receipt (ACDP 0.2, RFC-ACDP-0010): validate the
    /// canonical millisecond byte form of `created_at`, run the offline
    /// cross-checks, then verify the registry's Ed25519 signature over
    /// the preimage hash computed from the RAW wire JSON exactly as
    /// received (never a re-serialized struct — re-serialization can
    /// normalize byte details and falsely fail an honest receipt).
    ///
    /// Resolving the registry's DID document to obtain
    /// `registry_public_key_b64` stays in the host language by design
    /// (it needs HTTP) — pair `AcdpDid.web_to_url` + `httpx` +
    /// `AcdpDidDocument.key_for_algorithm`, then pass the key here.
    ///
    /// **Two RFC-ACDP-0010 checks remain the HOST's obligation** —
    /// this binding makes no HTTP calls and never sees the accompanying
    /// body, so it cannot perform them:
    ///
    /// 1. **Serving-authority binding** — `receipt.registry_did` MUST
    ///    equal `"did:web:" + <authority>` where `<authority>` is the
    ///    authority the response was *actually fetched from*. Compare
    ///    it against your HTTP client's request URL, not against any
    ///    field inside the response.
    /// 2. **Body bindings** — the receipt's `lineage_id`,
    ///    `origin_registry`, and `created_at` MUST equal the
    ///    accompanying body's fields. And `recomputed_body_hash` MUST
    ///    be the body hash you independently RECOMPUTED (run
    ///    `AcdpVerifier.verify_content_hash` on the body first and pass
    ///    that verified hash) — never the body's echoed `content_hash`
    ///    field taken on faith.
    ///
    /// * `receipt_json` — the `registry_receipt` object from a
    ///   `FullContext` retrieval, exactly as received on the wire.
    /// * `registry_public_key_b64` — standard base64 of the registry's
    ///   raw 32-byte Ed25519 receipt key.
    /// * `expected_ctx_id` — the ctx_id the consumer requested.
    /// * `recomputed_body_hash` — the body hash the consumer recomputed
    ///   itself (`"sha256:<64-hex>"` — never the body's echoed field).
    /// * `producer_key_fingerprint` — fingerprint of the resolved
    ///   producer key (see `fingerprint_ed25519_b64`).
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed
    /// input or `RuntimeError` (carrying the core error message) on any
    /// failed cross-check or a bad signature.
    #[staticmethod]
    fn verify_receipt(
        receipt_json: &str,
        registry_public_key_b64: &str,
        expected_ctx_id: &str,
        recomputed_body_hash: &str,
        producer_key_fingerprint: &str,
    ) -> PyResult<bool> {
        let value: serde_json::Value = serde_json::from_str(receipt_json)
            .map_err(|e| PyValueError::new_err(format!("invalid receipt JSON: {e}")))?;
        // §8 step 6: reject non-canonical created_at byte forms before
        // anything else — a parsed struct would silently normalize them.
        RegistryReceipt::validate_created_at_form(&value)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let receipt = RegistryReceipt::from_value(&value)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let registry_key = decode_ed25519_b64(registry_public_key_b64)?;
        let recomputed = ContentHash::parse(recomputed_body_hash)
            .map_err(|e| PyValueError::new_err(format!("invalid content_hash: {e}")))?;
        receipt
            .cross_check(
                &CtxId(expected_ctx_id.to_string()),
                &recomputed,
                producer_key_fingerprint,
            )
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        // Normative raw-JSON rule: hash the receipt exactly as received
        // (minus `signature`), not a re-serialization of the parsed
        // struct — mirrors the Rust client's verification path.
        let raw_hash = RegistryReceipt::preimage_hash_of_value(&value)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        receipt
            .verify_signature_against_hash(&raw_hash, Some(&registry_key), None)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}
