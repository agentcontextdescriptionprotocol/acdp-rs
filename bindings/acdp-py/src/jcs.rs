//! `AcdpCanonicalizer` — RFC 8785 JSON canonicalization + content hashing.
//!
//! Exposes the crate's in-house JCS implementation
//! (`acdp::crypto::jcs`) and the SHA-256 content-hash preimage helper so
//! host code does not have to re-implement either. Both are pure and
//! synchronous; the FFI convention is JSON-string in, string out.

use acdp::crypto::try_canonicalize_value;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use sha2::{Digest, Sha256};

/// RFC 8785 canonicalization utilities. All methods are static.
#[pyclass(name = "AcdpCanonicalizer")]
pub struct PyAcdpCanonicalizer;

#[pymethods]
impl PyAcdpCanonicalizer {
    /// Canonicalize a JSON document to its RFC 8785 (JCS) form.
    ///
    /// * `json_str` — any JSON document as a string.
    ///
    /// Returns the canonical UTF-8 JSON string (sorted object keys, no
    /// whitespace, `-0.0` normalized to `0`, ECMAScript number
    /// formatting). Raises `ValueError` on malformed JSON and
    /// `RuntimeError` if the document nests past the canonicalizer's
    /// recursion ceiling.
    #[staticmethod]
    fn canonicalize(json_str: &str) -> PyResult<String> {
        let value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| PyValueError::new_err(format!("invalid JSON: {e}")))?;
        let bytes = try_canonicalize_value(&value)
            .map_err(|e| PyRuntimeError::new_err(format!("canonicalization failed: {e}")))?;
        // JCS output is UTF-8 by construction; surface a clear error if a
        // future change ever violates that rather than panicking.
        String::from_utf8(bytes)
            .map_err(|e| PyRuntimeError::new_err(format!("canonical form is not UTF-8: {e}")))
    }

    /// SHA-256 over the canonical (JCS) form of a JSON document, returned
    /// as the ACDP envelope `"sha256:<64-lowercase-hex>"`.
    ///
    /// This is the hashing primitive behind `content_hash` /
    /// `data_ref.content_hash`. It hashes the document *as given* — it
    /// does NOT strip the RFC-ACDP-0001 §5.7 exclusion set, so to
    /// recompute a body's `content_hash` the caller passes the already
    /// producer-controlled object (or uses `AcdpVerifier.verify_content_hash`).
    #[staticmethod]
    fn content_hash(json_str: &str) -> PyResult<String> {
        let value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| PyValueError::new_err(format!("invalid JSON: {e}")))?;
        let bytes = try_canonicalize_value(&value)
            .map_err(|e| PyRuntimeError::new_err(format!("canonicalization failed: {e}")))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("sha256:{}", hex::encode(digest)))
    }
}
