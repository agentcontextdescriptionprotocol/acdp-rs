//! `AcdpVerifier` — consumer-side content_hash and signature verification.
//!
//! All methods are static. DID resolution is intentionally NOT done here
//! — that requires async HTTP and belongs in JS land. This binding
//! exposes the pure-crypto checks every consumer needs, including the
//! ACDP 0.2 offline path: `did:key` bodies and publish requests verify
//! with no network at all, and registry receipts verify against a
//! caller-resolved registry key.

use acdp::crypto::{
    canonical_preimage, explain_hash_mismatch, fingerprint_ed25519, verify_body_offline,
    verify_content_hash, verify_ecdsa_p256, verify_ed25519,
    verify_publish_request_signature_offline,
};
use acdp::types::{Body, ContentHash, CtxId, PublishRequest, RegistryReceipt};
use base64::{engine::general_purpose::STANDARD, Engine};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Consumer-side verification utilities. All methods are static.
#[napi]
pub struct AcdpVerifier;

#[napi]
impl AcdpVerifier {
    /// Verify that a body's `content_hash` matches the SHA-256 over
    /// its JCS-canonicalized producer-controlled fields.
    ///
    /// * `bodyJson` — the `body` object from a `FullContext` retrieval
    ///   (or the `PublishRequest` itself — both share the §5.7 layout).
    /// * `expectedHash` — the `body.content_hash` string
    ///   (`"sha256:<64-hex>"`).
    ///
    /// Returns `true` on success; throws on mismatch or bad JSON.
    #[napi]
    pub fn verify_content_hash(body_json: String, expected_hash: String) -> Result<bool> {
        let body: serde_json::Value = serde_json::from_str(&body_json)
            .map_err(|e| Error::from_reason(format!("invalid body JSON: {e}")))?;
        // Validate the hash envelope up-front so a malformed
        // `expectedHash` (wrong prefix, wrong length, uppercase hex)
        // surfaces as a clear error instead of being treated as a
        // recomputation mismatch.
        let stored = ContentHash::parse(&expected_hash)
            .map_err(|e| Error::from_reason(format!("invalid content_hash: {e}")))?;
        verify_content_hash(&body, &stored)
            .map(|_| true)
            .map_err(|e| Error::from_reason(format!("content_hash mismatch: {e}")))
    }

    /// Verify an Ed25519 signature over a `content_hash` string.
    ///
    /// The signing input per RFC-ACDP-0001 §5.8 is the ASCII bytes of
    /// the full `"sha256:<hex>"` string — NOT the raw 32-byte digest.
    ///
    /// * `pubKeyB64` — standard base64 (padded) of the 32-byte raw
    ///   Ed25519 public key (same shape as
    ///   `AcdpProducer.publicKeyB64`).
    /// * `sigB64` — the `body.signature.value` field from the wire
    ///   format.
    /// * `contentHash` — the `body.content_hash` string.
    ///
    /// Returns `true` on success; throws on failure.
    #[napi]
    pub fn verify_signature(
        pub_key_b64: String,
        sig_b64: String,
        content_hash: String,
    ) -> Result<bool> {
        let pub_bytes: Vec<u8> = STANDARD
            .decode(&pub_key_b64)
            .map_err(|e| Error::from_reason(format!("invalid pubKeyB64: {e}")))?;
        let arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| Error::from_reason("public key must decode to 32 bytes"))?;
        verify_ed25519(&arr, &sig_b64, &content_hash)
            .map(|_| true)
            .map_err(|e| Error::from_reason(format!("signature invalid: {e}")))
    }

    /// Verify an ECDSA-P256 signature over a `content_hash` string.
    ///
    /// The counterpart to `AcdpP256Producer` signing. The signing input
    /// per RFC-ACDP-0001 §5.8 is the ASCII bytes of the full
    /// `"sha256:<hex>"` string — NOT the raw 32-byte digest. The wire
    /// signature is IEEE 1363 `r‖s` (64 bytes, base64), NOT DER.
    ///
    /// * `pubKeySec1B64` — standard base64 of the 65-byte
    ///   SEC1-uncompressed public key (`0x04 || x || y`), the same shape
    ///   as `AcdpP256Producer.publicKeySec1B64`.
    /// * `sigB64` — the `body.signature.value` field from the wire
    ///   format (88-char base64 of the 64-byte `r‖s`).
    /// * `contentHash` — the `body.content_hash` string.
    ///
    /// Returns `true` on success; throws on failure.
    #[napi]
    pub fn verify_signature_p256(
        pub_key_sec1_b64: String,
        sig_b64: String,
        content_hash: String,
    ) -> Result<bool> {
        let pub_bytes: Vec<u8> = STANDARD
            .decode(&pub_key_sec1_b64)
            .map_err(|e| Error::from_reason(format!("invalid pubKeySec1B64: {e}")))?;
        verify_ecdsa_p256(&pub_bytes, &sig_b64, &content_hash)
            .map(|_| true)
            .map_err(|e| Error::from_reason(format!("signature invalid: {e}")))
    }

    /// Full offline verification of a retrieved `Body` from a `did:key`
    /// producer (ACDP 0.2) — structural validation, `content_hash`
    /// recomputation, key_id/agent_id binding, and signature check, all
    /// with no network.
    ///
    /// * `bodyJson` — the `body` object from a `FullContext` retrieval
    ///   (the registry-assigned fields must be present).
    ///
    /// Throws for `did:web` bodies — those need DID-document
    /// resolution, which stays in JS land (resolve via `AcdpDid.webToUrl`
    /// + `fetch`, then use `verifySignature`).
    ///
    /// Returns `true` on success; throws on any failure.
    #[napi]
    pub fn verify_body_offline(body_json: String) -> Result<bool> {
        let body: Body = serde_json::from_str(&body_json)
            .map_err(|e| Error::from_reason(format!("invalid body JSON: {e}")))?;
        verify_body_offline(&body)
            .map(|_| true)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Offline verification of a `PublishRequest` from a `did:key`
    /// producer (ACDP 0.2): recomputes the `content_hash` over the
    /// request's producer-controlled fields, then verifies the
    /// signature against the key embedded in the `did:key` itself.
    ///
    /// * `requestJson` — the full PublishRequest wire JSON (e.g. the
    ///   string `buildPublishRequest` returned).
    ///
    /// Throws for non-`did:key` requests — `did:web` verification needs
    /// DID resolution, which stays in JS land by design.
    ///
    /// Returns `true` on success; throws on any failure.
    #[napi]
    pub fn verify_publish_request_offline(request_json: String) -> Result<bool> {
        let value: serde_json::Value = serde_json::from_str(&request_json)
            .map_err(|e| Error::from_reason(format!("invalid request JSON: {e}")))?;
        let req: PublishRequest = serde_json::from_value(value.clone())
            .map_err(|e| Error::from_reason(format!("invalid PublishRequest: {e}")))?;
        verify_content_hash(&value, &req.content_hash)
            .map_err(|e| Error::from_reason(format!("content_hash mismatch: {e}")))?;
        verify_publish_request_signature_offline(&req)
            .map(|_| true)
            .map_err(|e| Error::from_reason(format!("signature invalid: {e}")))
    }

    /// Diagnose a `content_hash` mismatch (ACDP 0.2 divergence
    /// tooling). Probes the known cross-implementation divergence
    /// patterns — `acdp_version` omitted vs explicit, null-vs-absent
    /// optionals, sub-millisecond timestamps — and returns a
    /// human-readable report naming the matching pattern (or the
    /// recomputed hash and preimage when none matches).
    ///
    /// Never use this to *accept* a body; it is producer/SDK-author
    /// tooling for chasing "the hash that won't reproduce".
    #[napi]
    pub fn explain_hash_mismatch(body_json: String, expected_hash: String) -> Result<String> {
        let value: serde_json::Value = serde_json::from_str(&body_json)
            .map_err(|e| Error::from_reason(format!("invalid body JSON: {e}")))?;
        let expected = ContentHash::parse(&expected_hash)
            .map_err(|e| Error::from_reason(format!("invalid content_hash: {e}")))?;
        explain_hash_mismatch(&value, &expected).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// The exact JCS canonical preimage hashed for `content_hash`,
    /// returned as a UTF-8 string. When two SDKs disagree on a hash,
    /// diffing their canonical preimages localizes the divergence in a
    /// way two opaque digests never can.
    #[napi]
    pub fn canonical_preimage(body_json: String) -> Result<String> {
        let value: serde_json::Value = serde_json::from_str(&body_json)
            .map_err(|e| Error::from_reason(format!("invalid body JSON: {e}")))?;
        let (bytes, _hash) =
            canonical_preimage(&value).map_err(|e| Error::from_reason(e.to_string()))?;
        String::from_utf8(bytes)
            .map_err(|e| Error::from_reason(format!("canonical form is not UTF-8: {e}")))
    }

    /// SHA-256 fingerprint (`"sha256:<64-hex>"`) of a raw Ed25519
    /// public key, as carried in a registry receipt's
    /// `key_fingerprint` (ACDP 0.2).
    ///
    /// * `publicKeyB64` — standard base64 of the 32-byte raw key (the
    ///   same shape as `AcdpProducer.publicKeyB64` /
    ///   `ResolvedDidKey.publicKeyB64`).
    #[napi]
    pub fn fingerprint_ed25519_b64(public_key_b64: String) -> Result<String> {
        let pub_bytes: Vec<u8> = STANDARD
            .decode(&public_key_b64)
            .map_err(|e| Error::from_reason(format!("invalid publicKeyB64: {e}")))?;
        let arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| Error::from_reason("public key must decode to 32 bytes"))?;
        Ok(fingerprint_ed25519(&arr))
    }

    /// Verify a registry receipt (ACDP 0.2, RFC-ACDP-0010): the
    /// canonical `created_at` byte-form check, the offline cross-checks
    /// (`ctx_id`, recomputed body hash, producer key fingerprint,
    /// ms-truncated `created_at`, `registry_did`/`origin_registry`
    /// consistency), then the Ed25519 signature check against the
    /// registry's receipt key — with the signature preimage hashed over
    /// the **raw wire JSON** of the receipt as received (minus
    /// `signature`), never a re-serialization of the parsed struct.
    ///
    /// Resolving `registry_did` to that key is the caller's job — DID
    /// resolution stays in JS land by design (resolve the registry's
    /// DID document via `AcdpDid.webToUrl` + `fetch`, extract the key
    /// with `AcdpDidDocument.keyForAlgorithm`).
    ///
    /// **Two checks remain the HOST's obligation** — this binding makes
    /// no HTTP calls and never sees the accompanying body:
    ///
    /// 1. **Serving-authority binding** — `receipt.registry_did` MUST
    ///    equal `"did:web:" + <authority>` where `<authority>` is the
    ///    authority the response was *actually fetched from*, not
    ///    whatever the receipt claims.
    /// 2. **Body bindings** — the receipt's `lineage_id`,
    ///    `origin_registry`, and `created_at` MUST equal the
    ///    accompanying body's fields, and the `recomputedBodyHash`
    ///    argument MUST be independently recomputed from that body
    ///    (run `AcdpVerifier.verifyContentHash` first) — never the
    ///    body's echoed `content_hash` field.
    ///
    /// * `receiptJson` — the `registry_receipt` object from a
    ///   `FullContext` retrieval.
    /// * `registryPublicKeyB64` — standard base64 of the registry's
    ///   32-byte raw Ed25519 receipt key.
    /// * `expectedCtxId` — the ctx_id the caller actually requested.
    /// * `recomputedBodyHash` — the *independently recomputed* body
    ///   hash, never the body's echoed `content_hash` field.
    /// * `producerKeyFingerprint` — fingerprint of the resolved
    ///   producer key (see `fingerprintEd25519B64`).
    ///
    /// Returns `true` on success; throws with the failing check's
    /// message otherwise.
    #[napi]
    pub fn verify_receipt(
        receipt_json: String,
        registry_public_key_b64: String,
        expected_ctx_id: String,
        recomputed_body_hash: String,
        producer_key_fingerprint: String,
    ) -> Result<bool> {
        let value: serde_json::Value = serde_json::from_str(&receipt_json)
            .map_err(|e| Error::from_reason(format!("invalid receipt JSON: {e}")))?;
        // §8 step 6: the raw `created_at` bytes must already be in the
        // canonical millisecond-precision form before anything is hashed.
        RegistryReceipt::validate_created_at_form(&value)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let receipt =
            RegistryReceipt::from_value(&value).map_err(|e| Error::from_reason(e.to_string()))?;
        let body_hash = ContentHash::parse(&recomputed_body_hash)
            .map_err(|e| Error::from_reason(format!("invalid recomputedBodyHash: {e}")))?;
        receipt
            .cross_check(
                &CtxId(expected_ctx_id),
                &body_hash,
                &producer_key_fingerprint,
            )
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let pub_bytes: Vec<u8> = STANDARD
            .decode(&registry_public_key_b64)
            .map_err(|e| Error::from_reason(format!("invalid registryPublicKeyB64: {e}")))?;
        let arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| Error::from_reason("registry public key must decode to 32 bytes"))?;
        // Hash the receipt exactly as received (raw wire JSON minus
        // `signature`) — re-serializing the parsed struct could
        // normalize byte details and verify a preimage the registry
        // never signed.
        let raw_hash = RegistryReceipt::preimage_hash_of_value(&value)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        receipt
            .verify_signature_against_hash(&raw_hash, Some(&arr), None)
            .map(|_| true)
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}
