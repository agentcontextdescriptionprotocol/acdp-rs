//! `AcdpVerifier` — consumer-side content_hash and signature verification.
//!
//! All methods are static. DID resolution is intentionally NOT done here
//! — that requires async HTTP and belongs in the host language (or the
//! Rust `client` feature called from native code). This binding exposes
//! the two pure-crypto checks every consumer needs:
//!
//! * `verify_content_hash` — recompute `sha256(JCS(producer_content))`
//!   and compare against the body's stored `content_hash`.
//! * `verify_signature` — Ed25519 verify against an already-known
//!   public key, useful once the host has resolved the producer's DID.

use acdp::crypto::{verify_content_hash, verify_ecdsa_p256, verify_ed25519};
use acdp::types::ContentHash;
use base64::{engine::general_purpose::STANDARD, Engine};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

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
}
