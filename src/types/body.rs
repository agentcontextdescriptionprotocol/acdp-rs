use crate::types::data_ref::DataRef;
use crate::types::primitives::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Body ─────────────────────────────────────────────────────────────────────

/// The immutable stored body of an ACDP context (RFC-ACDP-0002).
///
/// Contains producer-controlled fields (covered by the producer signature)
/// plus registry-assigned identity fields (`ctx_id`, `lineage_id`,
/// `origin_registry`, `created_at`) which rely on registry honesty in v0.0.1.
///
/// The hash/signature preimage is ProducerContent: the Body with
/// `content_hash`, `signature`, and the registry-assigned identity fields
/// removed.  See RFC-ACDP-0001 §5.7.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    // ── Registry-assigned identity fields (NOT in ProducerContent) ──────
    pub ctx_id: CtxId,
    pub lineage_id: LineageId,
    pub origin_registry: String,
    pub created_at: DateTime<Utc>,

    // ── Integrity fields (NOT in ProducerContent) ────────────────────────
    pub content_hash: ContentHash,
    pub signature: Signature,

    // ── Producer-controlled required fields ──────────────────────────────
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

    // ── Producer-controlled optional fields ──────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<AgentDid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acdp_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Producer-supplied summary for search results (≤ 1000 chars).
    /// Part of ProducerContent — included in the content_hash preimage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
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

/// Time window the underlying data covers.
///
/// Per `acdp-common.schema.json#/$defs/data_period`, both `start` and `end`
/// are required (additionalProperties: false). The schema does not compare
/// timestamps; producers SHOULD ensure `start <= end` and registries
/// SHOULD reject `start > end` as `schema_violation` at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPeriod {
    /// Inclusive start of the data period.
    pub start: DateTime<Utc>,
    /// Inclusive end of the data period.
    pub end: DateTime<Utc>,
}

/// Detached Ed25519 signature over the body's `content_hash` field value.
///
/// The `value` bytes are a signature over the ASCII bytes of the full
/// `content_hash` string (e.g. `"sha256:5f8d…"`) — NOT the raw 32-byte
/// digest.  See RFC-ACDP-0001 §5.8.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Algorithm identifier.  Only `"ed25519"` is required in v0.0.1.
    pub algorithm: String,
    /// DID URL identifying the signing key (e.g. `did:web:…#key-1`).
    pub key_id: String,
    /// Standard base64-encoded signature bytes.
    pub value: String,
}

// ── Registry state ────────────────────────────────────────────────────────────

/// Mutable, registry-derived state returned alongside the Body on retrieval.
///
/// In v0.0.1 this contains only `status`.  Future versions add lifecycle
/// events, relationships, and attestations here without modifying the Body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryState {
    pub status: Status,
}

// ── Full retrieval envelope ───────────────────────────────────────────────────

/// The full context object returned by `GET /contexts/{ctx_id}`.
///
/// `additionalProperties: true` in the schema. Future versions may add
/// top-level keys (e.g. `registry_receipt` per RFC-ACDP-0009 §2.7); this
/// struct preserves a known one explicitly and silently drops the rest
/// (consumers who need them can use a custom deserializer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullContext {
    /// Producer-signed body.
    pub body: Body,
    /// Mutable registry-derived state (status etc).
    pub registry_state: RegistryState,
    /// Optional registry receipt — reserved for RFC-ACDP-0009 §2.7. Opaque
    /// to the library; preserved verbatim if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_receipt: Option<serde_json::Value>,
}
