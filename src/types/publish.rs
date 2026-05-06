use crate::types::body::{DataPeriod, Signature};
use crate::types::data_ref::DataRef;
use crate::types::primitives::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Wire-ready publish request body (`POST /contexts`).
///
/// Contains all producer-controlled fields plus `content_hash` and
/// `signature`.  Does NOT contain registry-assigned fields (`ctx_id`,
/// `lineage_id`, `origin_registry`, `created_at`).
///
/// Normally built via [`crate::producer::RequestBuilder::build`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishRequest {
    // Producer-controlled required fields
    pub version: u32,
    pub supersedes: Option<CtxId>,
    pub agent_id: AgentDid,
    pub contributors: Vec<AgentDid>,
    pub title: String,
    #[serde(rename = "type")]
    pub context_type: ContextType,
    pub data_refs: Vec<DataRef>,
    pub derived_from: Vec<CtxId>,
    pub visibility: Visibility,

    // Integrity fields (computed, not optional)
    pub content_hash: ContentHash,
    pub signature: Signature,

    // Producer-controlled optional fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<AgentDid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acdp_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Producer-supplied summary for search results (≤ 1000 chars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Optional self-verification of the lineage_id on supersession publish.
    /// Per `acdp-publish-request.schema.json` `allOf` conditional: v1
    /// publications MUST NOT include this field; v2+ MAY include it for the
    /// registry to verify against the deterministically-derived value.
    /// Excluded from ProducerContent (hash preimage) per RFC-ACDP-0001 §5.7.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_id: Option<LineageId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_period: Option<DataPeriod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_uri: Option<String>,
}

/// Successful publish response (HTTP 201).
///
/// Per `acdp-publish-response.schema.json` (additionalProperties: false),
/// the response contains exactly the five registry-assigned fields. It
/// MUST NOT echo `content_hash`, the producer's signature, or any body
/// field — the producer already submitted those and the response is for
/// retrieving the assigned identifiers.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishResponse {
    /// Registry-assigned context identifier.
    pub ctx_id: CtxId,
    /// Lineage identifier (derived from the v1 ctx_id).
    pub lineage_id: LineageId,
    /// Version of the published context (1 for first-version, prior+1 otherwise).
    pub version: u32,
    /// Registry's acceptance timestamp (millisecond precision).
    pub created_at: DateTime<Utc>,
    /// Lifecycle status. MUST be `Active` on a successful first-publish.
    pub status: Status,
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
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
