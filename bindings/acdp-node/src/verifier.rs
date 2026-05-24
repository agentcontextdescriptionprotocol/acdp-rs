//! `AcdpVerifier` — consumer-side content_hash and signature verification.
//!
//! All methods are static. DID resolution is intentionally NOT done here
//! — that requires async HTTP and belongs in JS land. This binding
//! exposes the two pure-crypto checks every consumer needs.

use acdp::crypto::{verify_content_hash, verify_ed25519};
use acdp::types::ContentHash;
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
}
