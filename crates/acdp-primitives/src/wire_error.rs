//! Wire error envelope returned by the registry on all error responses.
//!
//! Lives in `acdp-primitives` (rather than alongside the other wire types)
//! because [`crate::error::AcdpError`] references it in its `Registry`
//! variant and in [`crate::error::AcdpError::from_wire_error`] — and
//! `AcdpError` is the foundational error type every higher crate depends
//! on.

use serde::{Deserialize, Serialize};

/// Wire error envelope returned by the registry on all error responses.
///
/// Code values match the ACDP error registry (RFC-ACDP-0007 §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    pub error: WireErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireErrorBody {
    /// Error code from the ACDP error registry.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Machine-readable details (e.g. `{"reason": "lineage_mismatch"}`).
    ///
    /// Optional in `acdp-error.schema.json` and, when present, a JSON
    /// object (`"type": "object"`) — not nullable. `de_present_object`
    /// rejects an explicit `"details": null` and any non-object value.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::de_present_object"
    )]
    pub details: Option<serde_json::Value>,
}

impl WireErrorBody {
    /// Typed accessor for `details.reason` on `superseded_target` errors.
    pub fn supersession_reason(&self) -> Option<crate::error::SupersessionReason> {
        self.details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// `details.unreachable_ctx_id` (set on `lineage_walk_failed`).
    pub fn unreachable_ctx_id(&self) -> Option<&str> {
        self.details
            .as_ref()
            .and_then(|d| d.get("unreachable_ctx_id"))
            .and_then(|v| v.as_str())
    }

    /// `details.idempotency_key` (set on `duplicate_publish`).
    pub fn idempotency_key(&self) -> Option<&str> {
        self.details
            .as_ref()
            .and_then(|d| d.get("idempotency_key"))
            .and_then(|v| v.as_str())
    }

    /// `details.original_ctx_id` (set on `duplicate_publish`).
    pub fn original_ctx_id(&self) -> Option<&str> {
        self.details
            .as_ref()
            .and_then(|d| d.get("original_ctx_id"))
            .and_then(|v| v.as_str())
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error.code, self.error.message)
    }
}
