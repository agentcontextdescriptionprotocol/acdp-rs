//! `AcdpDid` / `AcdpDidDocument` — pure, synchronous did:web helpers.
//!
//! DID *resolution* (the async HTTPS fetch) stays in the host language —
//! it needs an HTTP client and belongs with `fetch` / `undici`. What the
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
//! Errors thrown carry a stable reason on the JS `.code` property
//! (the same convention as `AcdpSsrfPolicy`): `not_did_web`,
//! `parse_failed`, `id_mismatch`, `key_not_found`, `key_not_authorized`,
//! `alg_mismatch`, `malformed_key`, and `unsupported_algorithm`.

use acdp::did::{did_web_to_url, DidDocument};
use base64::{engine::general_purpose::STANDARD, Engine};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Build a JS `Error` whose `.code` is the stable reason string.
fn err(code: &str, detail: impl Into<String>) -> Error<String> {
    Error::new(code.to_string(), detail.into())
}

/// A verification method resolved to raw public-key bytes, in the
/// base64 shape the host's pinned-key directory speaks.
#[napi(object)]
pub struct ResolvedDidKey {
    /// Verification-method id (full DID URL with `#fragment`).
    pub key_id: String,
    /// `ed25519` or `ecdsa-p256`.
    pub algorithm: String,
    /// Standard base64 of the raw key bytes:
    /// * ed25519 — 32 bytes
    /// * ecdsa-p256 — 65-byte SEC1 uncompressed (`0x04 || x || y`)
    pub public_key_b64: String,
}

/// Stateless did:web string helpers. All methods are static.
#[napi]
pub struct AcdpDid;

#[napi]
impl AcdpDid {
    /// Translate a `did:web:…` DID to the HTTPS URL of its DID document
    /// per RFC-ACDP-0001 §5.11.
    ///
    /// * `did:web:example.com` → `https://example.com/.well-known/did.json`
    /// * `did:web:example.com:users:alice` → `https://example.com/users/alice/did.json`
    ///
    /// Throws with `.code === "not_did_web"` if the input is not a
    /// `did:web` DID.
    #[napi]
    pub fn web_to_url(did: String) -> Result<String, String> {
        did_web_to_url(&did).map_err(|e| err("not_did_web", e.to_string()))
    }

    /// Strip the `#fragment` from a DID URL, returning the bare DID.
    /// Returns the input unchanged when it carries no fragment.
    #[napi]
    pub fn strip_fragment(did_url: String) -> String {
        match did_url.split_once('#') {
            Some((base, _)) => base.to_string(),
            None => did_url,
        }
    }
}

/// A parsed did:web DID document. Construct with
/// [`AcdpDidDocument::parse`], then resolve a signing key with
/// [`AcdpDidDocument::key_for_algorithm`].
#[napi]
pub struct AcdpDidDocument {
    inner: DidDocument,
}

#[napi]
impl AcdpDidDocument {
    /// Parse a DID document and assert its `id` equals `expectedDid`.
    ///
    /// `expectedDid` is the bare DID being resolved (no fragment). The
    /// `id`-match check (RFC-ACDP-0001 §9.1) stops a misconfigured or
    /// hostile server from substituting another DID's keys.
    ///
    /// Throws `.code === "parse_failed"` on malformed JSON / missing
    /// `id`, or `.code === "id_mismatch"` when `id` ≠ `expectedDid`.
    #[napi(factory)]
    pub fn parse(json_str: String, expected_did: String) -> Result<AcdpDidDocument, String> {
        let doc: DidDocument = serde_json::from_str(&json_str)
            .map_err(|e| err("parse_failed", format!("DID document parse: {e}")))?;
        if doc.id.is_empty() {
            return Err(err("parse_failed", "DID document missing required `id`"));
        }
        if doc.id != expected_did {
            return Err(err(
                "id_mismatch",
                format!(
                    "DID document id '{}' does not match requested DID '{}'",
                    doc.id, expected_did
                ),
            ));
        }
        Ok(AcdpDidDocument { inner: doc })
    }

    /// The DID this document describes.
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    /// Resolve a verification method to raw public-key bytes, enforcing
    /// the full consumer-side gate:
    ///
    /// 1. the method `requestedKeyId` (matched by `#fragment`, exact —
    ///    no loose suffix) must exist, else `.code === "key_not_found"`;
    /// 2. it must be authorized in `assertionMethod`, else
    ///    `.code === "key_not_authorized"`;
    /// 3. any algorithm the method declares (via `type`, JWK params, or
    ///    multibase multicodec prefix) must equal `requestedAlg`, else
    ///    `.code === "alg_mismatch"` (downgrade defense, RFC-ACDP-0008
    ///    §3.9);
    /// 4. the key bytes must decode for `requestedAlg`, else
    ///    `.code === "malformed_key"`.
    ///
    /// `requestedAlg` is `"ed25519"` or `"ecdsa-p256"`
    /// (`.code === "unsupported_algorithm"` otherwise). `requestedKeyId`
    /// is the full DID URL from the signature's `key_id`.
    #[napi]
    pub fn key_for_algorithm(
        &self,
        requested_key_id: String,
        requested_alg: String,
    ) -> Result<ResolvedDidKey, String> {
        if requested_alg != "ed25519" && requested_alg != "ecdsa-p256" {
            return Err(err(
                "unsupported_algorithm",
                format!("unsupported algorithm: {requested_alg}"),
            ));
        }

        // Look up by exact #fragment (the core `find_by_fragment` rejects
        // loose suffix matches); fall back to full-id equality for a
        // fragment-less key_id.
        let vm = match requested_key_id.rsplit_once('#') {
            Some((_, frag)) => self.inner.find_by_fragment(frag),
            None => self
                .inner
                .verification_methods
                .iter()
                .find(|m| m.id == requested_key_id),
        }
        .ok_or_else(|| {
            err(
                "key_not_found",
                format!("no verificationMethod with id '{requested_key_id}'"),
            )
        })?;

        if !self.inner.is_assertion_method(&requested_key_id) {
            return Err(err(
                "key_not_authorized",
                format!(
                    "verificationMethod '{requested_key_id}' is not in assertionMethod \
                     (cannot sign challenges)"
                ),
            ));
        }

        // Algorithm-downgrade defense: when the method declares an
        // algorithm, it MUST match the requested one before any key bytes
        // are touched.
        if let Some(declared) = vm.declared_algorithm() {
            if declared != requested_alg {
                return Err(err(
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
                .map_err(|e| err("malformed_key", e.to_string()))?;
            STANDARD.encode(bytes)
        } else {
            let bytes = vm
                .ecdsa_p256_public_key_sec1()
                .map_err(|e| err("malformed_key", e.to_string()))?;
            STANDARD.encode(bytes)
        };

        Ok(ResolvedDidKey {
            key_id: vm.id.clone(),
            algorithm: requested_alg,
            public_key_b64,
        })
    }
}
