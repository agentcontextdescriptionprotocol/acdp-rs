use crate::types::data_ref::DataRef;
use crate::types::primitives::*;
use crate::types::serde_helpers::de_present;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Body ─────────────────────────────────────────────────────────────────────

/// The immutable stored body of an ACDP context (RFC-ACDP-0002).
///
/// Contains producer-controlled fields (covered by the producer signature)
/// plus registry-assigned identity fields (`ctx_id`, `lineage_id`,
/// `origin_registry`, `created_at`) which rely on registry honesty in v0.1.0.
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
    //
    // Optional bare-typed fields use the absent-vs-null convention
    // (RFC-ACDP-0005 §2.2.1, schema-005/006/007): an absent key is
    // tolerated, a present-but-`null` key is rejected at deserialize.
    // [`crate::types::serde_helpers::de_present`] implements this.
    // `supersedes` is the one v0.1.0 field whose schema is
    // `["string","null"]` (RFC-ACDP-0002 §3.1) — it is legitimately
    // nullable and intentionally NOT routed through `de_present`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<AgentDid>>,
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub acdp_version: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// Producer-supplied summary for search results (≤ 1000 chars).
    /// Part of ProducerContent — included in the content_hash preimage.
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub summary: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub tags: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_period: Option<DataPeriod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub schema_uri: Option<String>,

    /// Forward-compatible carry-through of unknown producer-controlled
    /// fields (e.g. v0.1's `priority`). Including these in the typed
    /// model is required for `serde_json::to_value(body)` → JCS → SHA-256
    /// to reproduce the original `content_hash`. Without `flatten`, a
    /// v0.1.0 consumer reading a v0.1 body would silently drop the new
    /// field and compute a different hash, falsely rejecting the body.
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// Time window the underlying data covers.
///
/// Per `acdp-common.schema.json#/$defs/data_period`, both `start` and `end`
/// are required (additionalProperties: false). The schema does not compare
/// timestamps; producers SHOULD ensure `start <= end` and registries
/// SHOULD reject `start > end` as `schema_violation` at runtime.
///
/// `data_period` is a CLOSED two-field wire shape and part of
/// ProducerContent — an unknown field would silently change the
/// `content_hash` preimage, so `deny_unknown_fields` rejects it
/// (RFC-ACDP-0007 §3.3.1, conformance fixture schema-009).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
///
/// The `signature` object is a CLOSED wire shape — exactly `algorithm`,
/// `key_id`, `value` (`additionalProperties: false`). Future signature
/// variants (proof chains, threshold attestations) require an explicit
/// schema bump, not field-level extensibility, so `deny_unknown_fields`
/// rejects an unknown field (RFC-ACDP-0007 §3.3.1, fixture schema-008).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Algorithm identifier.  Only `"ed25519"` is required in v0.1.0.
    pub algorithm: String,
    /// DID URL identifying the signing key (e.g. `did:web:…#key-1`).
    pub key_id: String,
    /// Standard base64-encoded signature bytes.
    pub value: String,
}

// ── Registry state ────────────────────────────────────────────────────────────

/// Mutable, registry-derived state returned alongside the Body on retrieval.
///
/// In v0.1.0 this contains only `status`. Future versions add lifecycle
/// events, relationships, and attestations here without modifying the
/// Body. Unknown fields are preserved in [`Self::extensions`] so consumers
/// can surface them to operators (RFC-ACDP-0004 §3 forward-compat).
///
/// # Reserved extension field names (RFC-ACDP-0009 §2.1)
///
/// The following keys are reserved for future RFCs. Until the relevant
/// RFC ships normative text, v0.1.0 consumers will see them in
/// [`Self::extensions`] (the `#[serde(flatten)]` map below). v0.1.0
/// producers MUST NOT emit them.
///
/// | Name              | RFC                           | Purpose                                                       |
/// |-------------------|-------------------------------|---------------------------------------------------------------|
/// | `lifecycle_events`| RFC-ACDP-0009 §2.1 (reserved) | Retraction / republication / status-change audit trail.        |
/// | `relationships`   | RFC-ACDP-0009 §2.1 (reserved) | Post-publication `builds_on` / `disputes` etc.                 |
/// | `attestations`    | RFC-ACDP-0009 §2.1 (reserved) | Third-party `reproduced` / `audit` markers.                    |
/// | `subscriptions`   | RFC-ACDP-0009 §2.1 (reserved) | Push-subscription receipts.                                    |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryState {
    pub status: Status,
    /// Forward-compatible passthrough for fields added in future versions
    /// (e.g. v0.1's `lifecycle_events`, `relationships`, `attestations`,
    /// `subscriptions` — see the type docs for the reserved set).
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

// ── Full retrieval envelope ───────────────────────────────────────────────────

/// The full context object returned by `GET /contexts/{ctx_id}`.
///
/// `acdp-context.schema.json` is `additionalProperties: true`: future
/// ACDP versions may add top-level keys without a schema bump, and
/// v0.1.0 consumers MUST tolerate unknown top-level keys. `body`,
/// `registry_state`, and the reserved `registry_receipt` are modelled
/// explicitly; any other top-level field is preserved verbatim in
/// [`Self::extensions`]. These top-level fields are NOT part of
/// `ProducerContent`, so unlike [`Body::extensions`] this carry-through
/// is a forward-compatibility contract, not a hash-stability one.
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

    /// Unknown top-level context fields, preserved per
    /// `acdp-context.schema.json` `additionalProperties: true`. Retained
    /// for forward compatibility with future ACDP versions that add
    /// top-level registry fields.
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}
