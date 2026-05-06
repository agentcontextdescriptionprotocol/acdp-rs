//! Error types for the ACDP library.
//!
//! Error variants align with the wire vocabulary defined by
//! `acdp-error.schema.json` and RFC-ACDP-0007 §5. The
//! [`AcdpError::from_wire_error`] helper converts a
//! [`crate::types::WireError`] (HTTP response body shape) into a typed
//! variant.

use crate::types::primitives::ContentHash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Top-level error type.
#[derive(Debug, Error)]
pub enum AcdpError {
    // ── Cryptography ─────────────────────────────────────────────────────────
    /// JCS canonicalization failed (input not serializable).
    #[error("JCS canonicalization failed: {0}")]
    Canonicalization(String),

    /// Stored `content_hash` did not match the recomputed value
    /// (locally detected during signature verification).
    #[error("content_hash mismatch\n  stored:     {stored}\n  recomputed: {recomputed}")]
    HashMismatch {
        /// The hash claimed by the body or request.
        stored: ContentHash,
        /// The hash recomputed by the verifier.
        recomputed: ContentHash,
    },

    /// Wire code: `hash_mismatch`. The remote registry rejected a
    /// publish request because its independent hash recomputation did
    /// not match the producer-supplied `content_hash`. Distinct from
    /// the local [`AcdpError::HashMismatch`] variant: this one carries
    /// the registry's message verbatim and indicates a *producer-side*
    /// bug (most often canonicalization divergence — see RFC-ACDP-0001
    /// §5.7 and the `can-001` conformance fixture).
    #[error("registry rejected hash_mismatch: {0}")]
    RemoteHashMismatch(String),

    /// Signature verification failed or signature was malformed.
    /// Wire code: `invalid_signature`.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    // ── DID / key resolution ─────────────────────────────────────────────
    /// Wire code: `key_resolution_failed` (HTTP 400).
    #[error("key resolution failed: {0}")]
    KeyResolution(String),

    /// Wire code: `key_resolution_unreachable` (HTTP 502) — transient, may retry.
    #[error("key resolution unreachable (transient): {0}")]
    KeyResolutionUnreachable(String),

    /// Wire code: `key_not_authorized` (HTTP 403).
    #[error("key not authorized: {0}")]
    KeyNotAuthorized(String),

    // ── Input validation ─────────────────────────────────────────────────
    /// Producer body could not be parsed.
    #[error("invalid body: {0}")]
    InvalidBody(String),

    /// A required field was missing.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Schema validation failed (string length, array uniqueness, oneOf, etc).
    /// Wire code: `schema_violation`.
    #[error("schema violation: {0}")]
    SchemaViolation(String),

    /// Wire code: `payload_too_large` — request body exceeds the registry limit.
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    /// Wire code: `embedded_too_large` — a single `DataRef.embedded.content`
    /// exceeds the 64 KB cap.
    #[error("embedded data reference too large: {0}")]
    EmbeddedTooLarge(String),

    /// Wire code: `unsupported_algorithm` — the producer used a signature
    /// algorithm the registry does not accept.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Wire code: `not_implemented` — endpoint or feature not supported by
    /// this registry.
    #[error("not implemented: {0}")]
    NotImplemented(String),

    // ── Retrieval / authorization ────────────────────────────────────────
    /// Wire code: `not_found`.
    #[error("not found: {0}")]
    NotFound(String),

    /// Wire code: `not_authorized` — the caller is not permitted to access
    /// this resource.
    #[error("not authorized: {0}")]
    NotAuthorized(String),

    /// Wire code: `rate_limited`.
    #[error("rate limited: {0}")]
    RateLimited(String),

    // ── Pagination ───────────────────────────────────────────────────────
    /// Wire code: `cursor_expired`.
    #[error("search cursor expired")]
    CursorExpired,

    /// Wire code: `invalid_cursor`.
    #[error("invalid cursor: {0}")]
    InvalidCursor(String),

    // ── Publication ──────────────────────────────────────────────────────
    /// Wire code: `superseded_target`. The supersession target was rejected;
    /// the [`SupersessionReason`] disambiguates the cause.
    #[error("superseded target rejected ({reason:?}): {message}")]
    SupersededTarget {
        /// Why the target was rejected.
        reason: SupersessionReason,
        /// Human-readable message from the registry.
        message: String,
    },

    /// Wire code: `duplicate_publish` — an Idempotency-Key replay produced
    /// a different request body than the original.
    #[error("duplicate publish: {0}")]
    DuplicatePublish(String),

    // ── Cross-registry ───────────────────────────────────────────────────
    /// Wire code: `cross_registry_resolution_failed`.
    #[error("cross-registry resolution failed: {0}")]
    CrossRegistryResolutionFailed(String),

    // ── Wire / transport ─────────────────────────────────────────────────
    /// Wire code: `internal_error`.
    #[error("registry internal error: {0}")]
    RegistryInternal(String),

    /// Catch-all for `WireError` codes that have no typed variant in this
    /// version of the library. Forward-compatible: registries may emit
    /// reserved codes (`immutable_field`, `unsupported_embedding_model`)
    /// that future ACDP versions add.
    #[error("registry returned error: {0:?}")]
    Registry(crate::types::WireError),

    /// JSON (de)serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(String),

    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(String),
}

/// Sub-reason for [`AcdpError::SupersededTarget`]. Mirrors the
/// `details.reason` values defined by `acdp-error.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupersessionReason {
    /// The supersedes target context does not exist on this registry.
    NotFound,
    /// The target's lineage_id differs from the new publication's lineage.
    LineageMismatch,
    /// The new version is not exactly `previous.version + 1`.
    VersionMismatch,
    /// The target has already been superseded by a different version.
    AlreadySuperseded,
    /// The target lives on a different registry; v0.0.1 only allows
    /// same-registry supersession.
    CrossRegistrySupersessionUnsupported,
    /// The lineage walk through `supersedes` failed because an
    /// intermediate context could not be retrieved (RFC-ACDP-0001 §5.6.1).
    LineageWalkFailed,
    /// A reason this version of the library does not recognize.
    #[serde(other)]
    Other,
}

impl AcdpError {
    /// Whether this error is plausibly transient and worth retrying
    /// with the same request body (and, if applicable, the same
    /// `Idempotency-Key`).
    ///
    /// Returned by [`AcdpError::is_transient`] only for variants whose
    /// wire codes the spec marks retryable: `key_resolution_unreachable`
    /// (RFC-ACDP-0001 §5.11), `rate_limited` (RFC-ACDP-0008 §4.3),
    /// `cross_registry_resolution_failed` (RFC-ACDP-0006 §7), and
    /// `internal_error` (RFC-ACDP-0007 §5). Generic `Http` transport
    /// errors are conservatively treated as transient since they
    /// usually mean DNS or TCP-level glitches.
    ///
    /// All cryptographic, schema, and authorization errors are NOT
    /// transient: a malformed body or invalid signature will not
    /// magically validate on retry.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            AcdpError::KeyResolutionUnreachable(_)
                | AcdpError::RateLimited(_)
                | AcdpError::CrossRegistryResolutionFailed(_)
                | AcdpError::RegistryInternal(_)
                | AcdpError::Http(_)
        )
    }

    /// Map a wire-protocol [`crate::types::WireError`] into a typed
    /// [`AcdpError`].
    ///
    /// Codes the library does not yet recognize are returned as
    /// [`AcdpError::Registry`] for forward compatibility.
    pub fn from_wire_error(wire: crate::types::WireError) -> Self {
        let code = wire.error.code.as_str();
        let msg = wire.error.message.clone();

        match code {
            "invalid_signature" => AcdpError::InvalidSignature(msg),
            "hash_mismatch" => AcdpError::RemoteHashMismatch(msg),
            "schema_violation" => AcdpError::SchemaViolation(msg),
            "not_authorized" => AcdpError::NotAuthorized(msg),
            "not_found" => AcdpError::NotFound(msg),
            "rate_limited" => AcdpError::RateLimited(msg),
            "payload_too_large" => AcdpError::PayloadTooLarge(msg),
            "embedded_too_large" => AcdpError::EmbeddedTooLarge(msg),
            "key_resolution_failed" => AcdpError::KeyResolution(msg),
            "key_resolution_unreachable" => AcdpError::KeyResolutionUnreachable(msg),
            "key_not_authorized" => AcdpError::KeyNotAuthorized(msg),
            "unsupported_algorithm" => AcdpError::UnsupportedAlgorithm(msg),
            "not_implemented" => AcdpError::NotImplemented(msg),
            "cursor_expired" => AcdpError::CursorExpired,
            "invalid_cursor" => AcdpError::InvalidCursor(msg),
            "duplicate_publish" => AcdpError::DuplicatePublish(msg),
            "cross_registry_resolution_failed" => AcdpError::CrossRegistryResolutionFailed(msg),
            "internal_error" => AcdpError::RegistryInternal(msg),
            "superseded_target" => {
                let reason = wire
                    .error
                    .details
                    .as_ref()
                    .and_then(|d| d.get("reason"))
                    .and_then(|v| serde_json::from_value::<SupersessionReason>(v.clone()).ok())
                    .unwrap_or(SupersessionReason::Other);
                AcdpError::SupersededTarget {
                    reason,
                    message: msg,
                }
            }
            // Unknown / future codes pass through as the catch-all variant
            _ => AcdpError::Registry(wire),
        }
    }
}

impl From<serde_json::Error> for AcdpError {
    fn from(e: serde_json::Error) -> Self {
        AcdpError::Serialization(e.to_string())
    }
}

impl From<std::io::Error> for AcdpError {
    fn from(e: std::io::Error) -> Self {
        AcdpError::Http(format!("io error: {e}"))
    }
}

#[cfg(feature = "client")]
impl From<reqwest::Error> for AcdpError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_connect() || e.is_timeout() {
            AcdpError::Http(format!("connection failed: {e}"))
        } else {
            AcdpError::Http(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::publish::{WireError, WireErrorBody};
    use serde_json::json;

    fn wire(code: &str, message: &str, details: Option<serde_json::Value>) -> WireError {
        WireError {
            error: WireErrorBody {
                code: code.into(),
                message: message.into(),
                details,
            },
        }
    }

    #[test]
    fn all_19_wire_codes_round_trip() {
        // Test-coverage matrix entry: "All 19 error codes parse from WireError".
        // Every code enumerated by acdp-error.schema.json's enum MUST map to a
        // typed AcdpError variant (or, for `superseded_target` with details,
        // produce the right SupersessionReason).
        type Check = fn(&AcdpError) -> bool;
        let cases: &[(&str, Check)] = &[
            ("invalid_signature", |e| {
                matches!(e, AcdpError::InvalidSignature(_))
            }),
            ("hash_mismatch", |e| {
                matches!(e, AcdpError::RemoteHashMismatch(_))
            }),
            ("schema_violation", |e| {
                matches!(e, AcdpError::SchemaViolation(_))
            }),
            ("not_authorized", |e| {
                matches!(e, AcdpError::NotAuthorized(_))
            }),
            ("not_found", |e| matches!(e, AcdpError::NotFound(_))),
            ("superseded_target", |e| {
                matches!(e, AcdpError::SupersededTarget { .. })
            }),
            ("unsupported_algorithm", |e| {
                matches!(e, AcdpError::UnsupportedAlgorithm(_))
            }),
            ("rate_limited", |e| matches!(e, AcdpError::RateLimited(_))),
            ("payload_too_large", |e| {
                matches!(e, AcdpError::PayloadTooLarge(_))
            }),
            ("embedded_too_large", |e| {
                matches!(e, AcdpError::EmbeddedTooLarge(_))
            }),
            ("key_resolution_failed", |e| {
                matches!(e, AcdpError::KeyResolution(_))
            }),
            ("key_resolution_unreachable", |e| {
                matches!(e, AcdpError::KeyResolutionUnreachable(_))
            }),
            ("key_not_authorized", |e| {
                matches!(e, AcdpError::KeyNotAuthorized(_))
            }),
            ("not_implemented", |e| {
                matches!(e, AcdpError::NotImplemented(_))
            }),
            ("cursor_expired", |e| matches!(e, AcdpError::CursorExpired)),
            ("invalid_cursor", |e| {
                matches!(e, AcdpError::InvalidCursor(_))
            }),
            ("duplicate_publish", |e| {
                matches!(e, AcdpError::DuplicatePublish(_))
            }),
            ("cross_registry_resolution_failed", |e| {
                matches!(e, AcdpError::CrossRegistryResolutionFailed(_))
            }),
            ("internal_error", |e| {
                matches!(e, AcdpError::RegistryInternal(_))
            }),
        ];
        // Schema enumerates exactly 19 codes (RFC-ACDP-0007 §5).
        assert_eq!(cases.len(), 19);
        for (code, expected) in cases {
            let err = AcdpError::from_wire_error(wire(code, "msg", None));
            assert!(
                expected(&err),
                "code '{code}' did not map to its typed variant: got {err:?}"
            );
        }
    }

    #[test]
    fn superseded_target_with_reason_details() {
        let w = wire(
            "superseded_target",
            "lineage mismatch",
            Some(json!({"reason": "lineage_mismatch"})),
        );
        match AcdpError::from_wire_error(w) {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(reason, SupersessionReason::LineageMismatch);
            }
            other => panic!("expected SupersededTarget, got {other:?}"),
        }
    }

    #[test]
    fn superseded_target_without_details_falls_back_to_other() {
        let w = wire("superseded_target", "?", None);
        match AcdpError::from_wire_error(w) {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(reason, SupersessionReason::Other);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn unknown_code_passes_through_as_registry() {
        let w = wire("immutable_field", "reserved future code", None);
        assert!(matches!(
            AcdpError::from_wire_error(w),
            AcdpError::Registry(_)
        ));
    }

    /// T4 — `lineage_walk_failed` reason round-trips via WireError
    /// (RFC-ACDP-0001 §5.6.1).
    #[test]
    fn lineage_walk_failed_reason_roundtrip() {
        let w = wire(
            "superseded_target",
            "intermediate not retrievable",
            Some(json!({
                "reason": "lineage_walk_failed",
                "unreachable_ctx_id":
                    "acdp://r.example.com/12345678-1234-4321-8123-123456781234"
            })),
        );
        match AcdpError::from_wire_error(w) {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(reason, SupersessionReason::LineageWalkFailed);
            }
            other => panic!("got {other:?}"),
        }
    }

    /// `is_transient` covers the wire codes the spec marks retryable.
    #[test]
    fn is_transient_for_known_retryables() {
        assert!(AcdpError::KeyResolutionUnreachable("x".into()).is_transient());
        assert!(AcdpError::RateLimited("x".into()).is_transient());
        assert!(AcdpError::CrossRegistryResolutionFailed("x".into()).is_transient());
        assert!(AcdpError::RegistryInternal("x".into()).is_transient());
        assert!(AcdpError::Http("x".into()).is_transient());
        assert!(!AcdpError::SchemaViolation("x".into()).is_transient());
        assert!(!AcdpError::InvalidSignature("x".into()).is_transient());
        assert!(!AcdpError::NotFound("x".into()).is_transient());
    }
}
