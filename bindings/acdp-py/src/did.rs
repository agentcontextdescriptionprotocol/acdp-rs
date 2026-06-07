//! `AcdpDid` / `AcdpDidDocument` — pure, synchronous did:web helpers.
//!
//! DID *resolution* (the async HTTPS fetch) stays in the host language —
//! it needs an HTTP client and belongs with `httpx` / `requests`. What the
//! host should NOT re-implement is the security-critical, byte-exact part:
//!
//!   * `did:web` → HTTPS URL translation (RFC-ACDP-0001 §5.11), and
//!   * DID-document parsing + verification-method key extraction with the
//!     assertionMethod authorization gate and the algorithm-downgrade
//!     defense (RFC-ACDP-0008 §3.9).
//!
//! Both wrap the core `acdp::did` types so a key the ACDP registry
//! authenticates is the same key this binding extracts — no parallel
//! hand-port to drift.
//!
//! A rejection raises [`DidResolutionError`], whose `.reason` attribute
//! carries a stable snake_case code — the same vocabulary as the Node
//! binding's `.code`: `not_did_web`, `parse_failed`, `id_mismatch`,
//! `key_not_found`, `key_not_authorized`, `alg_mismatch`,
//! `malformed_key`, `unsupported_algorithm`.

use std::collections::HashMap;

use acdp::did::{did_web_to_url, DidDocument};
use base64::{engine::general_purpose::STANDARD, Engine};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(
    acdp,
    DidResolutionError,
    PyException,
    "Raised when a did:web helper rejects input. The `.reason` attribute \
     is a stable snake_case code."
);

/// Build a [`DidResolutionError`] carrying the stable reason on `.reason`.
fn did_err(reason: &str, detail: impl Into<String>) -> PyErr {
    Python::with_gil(|py| {
        let err = DidResolutionError::new_err(detail.into());
        match err.value_bound(py).setattr("reason", reason) {
            Ok(()) => err,
            Err(set_err) => set_err,
        }
    })
}

/// Stateless did:web string helpers. All methods are static.
#[pyclass(name = "AcdpDid")]
pub struct PyAcdpDid;

#[pymethods]
impl PyAcdpDid {
    /// Translate a `did:web:…` DID to the HTTPS URL of its DID document
    /// per RFC-ACDP-0001 §5.11.
    ///
    /// * `did:web:example.com` → `https://example.com/.well-known/did.json`
    /// * `did:web:example.com:users:alice` → `https://example.com/users/alice/did.json`
    ///
    /// Raises `DidResolutionError` (`.reason == "not_did_web"`) if the
    /// input is not a `did:web` DID.
    #[staticmethod]
    fn web_to_url(did: &str) -> PyResult<String> {
        did_web_to_url(did).map_err(|e| did_err("not_did_web", e.to_string()))
    }

    /// Strip the `#fragment` from a DID URL, returning the bare DID.
    /// Returns the input unchanged when it carries no fragment.
    #[staticmethod]
    fn strip_fragment(did_url: &str) -> String {
        match did_url.split_once('#') {
            Some((base, _)) => base.to_string(),
            None => did_url.to_string(),
        }
    }
}

/// A parsed did:web DID document. Construct with `AcdpDidDocument.parse`,
/// then resolve a signing key with `key_for_algorithm`.
#[pyclass(name = "AcdpDidDocument")]
pub struct PyAcdpDidDocument {
    inner: DidDocument,
}

#[pymethods]
impl PyAcdpDidDocument {
    /// Parse a DID document and assert its `id` equals `expected_did`.
    ///
    /// Raises `DidResolutionError` with `.reason == "parse_failed"` on
    /// malformed JSON / missing `id`, or `.reason == "id_mismatch"` when
    /// `id` ≠ `expected_did`.
    #[staticmethod]
    fn parse(json_str: &str, expected_did: &str) -> PyResult<Self> {
        let doc: DidDocument = serde_json::from_str(json_str)
            .map_err(|e| did_err("parse_failed", format!("DID document parse: {e}")))?;
        if doc.id.is_empty() {
            return Err(did_err("parse_failed", "DID document missing required `id`"));
        }
        if doc.id != expected_did {
            return Err(did_err(
                "id_mismatch",
                format!(
                    "DID document id '{}' does not match requested DID '{}'",
                    doc.id, expected_did
                ),
            ));
        }
        Ok(Self { inner: doc })
    }

    /// The DID this document describes.
    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    /// Resolve a verification method to raw public-key bytes, enforcing
    /// the full consumer-side gate (method exists by exact `#fragment`;
    /// is authorized in `assertionMethod`; any declared algorithm matches
    /// `requested_alg` per RFC-ACDP-0008 §3.9; key bytes decode).
    ///
    /// Returns a dict `{"key_id", "algorithm", "public_key_b64"}` where
    /// `public_key_b64` is standard base64 of the raw key bytes (32-byte
    /// Ed25519, or 65-byte SEC1-uncompressed P-256). Raises
    /// `DidResolutionError` with the stable `.reason` on any gate failure.
    fn key_for_algorithm(
        &self,
        requested_key_id: &str,
        requested_alg: &str,
    ) -> PyResult<HashMap<String, String>> {
        if requested_alg != "ed25519" && requested_alg != "ecdsa-p256" {
            return Err(did_err(
                "unsupported_algorithm",
                format!("unsupported algorithm: {requested_alg}"),
            ));
        }

        let vm = match requested_key_id.rsplit_once('#') {
            Some((_, frag)) => self.inner.find_by_fragment(frag),
            None => self
                .inner
                .verification_methods
                .iter()
                .find(|m| m.id == requested_key_id),
        }
        .ok_or_else(|| {
            did_err(
                "key_not_found",
                format!("no verificationMethod with id '{requested_key_id}'"),
            )
        })?;

        if !self.inner.is_assertion_method(requested_key_id) {
            return Err(did_err(
                "key_not_authorized",
                format!(
                    "verificationMethod '{requested_key_id}' is not in assertionMethod \
                     (cannot sign challenges)"
                ),
            ));
        }

        if let Some(declared) = vm.declared_algorithm() {
            if declared != requested_alg {
                return Err(did_err(
                    "alg_mismatch",
                    format!(
                        "requested {requested_alg} but verificationMethod '{}' is {} ({declared})",
                        vm.id, vm.method_type
                    ),
                ));
            }
        }

        let public_key_b64 = if requested_alg == "ed25519" {
            let bytes = vm
                .ed25519_public_key_bytes()
                .map_err(|e| did_err("malformed_key", e.to_string()))?;
            STANDARD.encode(bytes)
        } else {
            let bytes = vm
                .ecdsa_p256_public_key_sec1()
                .map_err(|e| did_err("malformed_key", e.to_string()))?;
            STANDARD.encode(bytes)
        };

        let mut out = HashMap::with_capacity(3);
        out.insert("key_id".to_string(), vm.id.clone());
        out.insert("algorithm".to_string(), requested_alg.to_string());
        out.insert("public_key_b64".to_string(), public_key_b64);
        Ok(out)
    }
}
