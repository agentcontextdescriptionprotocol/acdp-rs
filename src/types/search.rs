use crate::types::primitives::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Keyword search ────────────────────────────────────────────────────────────

/// Query parameters for `GET /contexts/search`.
///
/// All fields are optional; unset fields are omitted from the query string.
/// The registry defaults `status` to `active` when not supplied.
#[derive(Debug, Default, Serialize)]
pub struct SearchParams {
    /// Full-text search across title, description, domain, tags, agent_id, type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,

    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub context_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// Comma-separated tag list.  All listed tags must be present (AND).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_uri: Option<String>,

    /// Filter for contexts whose `derived_from` includes this `ctx_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<String>,

    /// RFC 3339 lower bound on `created_at`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_after: Option<String>,

    /// RFC 3339 upper bound on `created_at`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_before: Option<String>,

    /// RFC 3339 lower bound on `data_period.start`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_period_start_after: Option<String>,

    /// RFC 3339 upper bound on `data_period.end`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_period_end_before: Option<String>,

    /// RFC 3339 lower bound on `expires_at`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_after: Option<String>,

    /// RFC 3339 upper bound on `expires_at`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_before: Option<String>,

    /// Filter by lifecycle status.  Defaults to `active`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Maximum results per page (registry-capped, typically ≤ 100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Pagination cursor from a previous response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Response from `GET /contexts/search`.
///
/// Per `acdp-search-response.schema.json` (additionalProperties: false), the
/// wrapping array MUST be named `matches`. Conformant consumers MUST reject
/// responses that emit `results` or any other alternative spelling
/// (RFC-ACDP-0005 §2.2, fixture vis-003).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResponse {
    /// Lightweight projections of matching contexts.
    pub matches: Vec<SearchResult>,
    /// Estimated total — may be approximate.
    pub total_estimate: Option<u64>,
    /// Opaque pagination cursor; absent if no more results.
    pub next_cursor: Option<String>,
}

impl SearchResponse {
    /// Back-compat accessor; new code should prefer `.matches`.
    pub fn results(&self) -> &[SearchResult] {
        &self.matches
    }
}

/// A single search result — `match_summary` projection per
/// `acdp-common.schema.json#/$defs/match_summary`.
///
/// Required fields: ctx_id, lineage_id, type, agent_id, title, created_at,
/// status. Optional: summary, domain, visibility. The full description,
/// tags, etc. are NOT in this projection — fetch the full Body via the
/// registry's retrieval endpoint to access them.
///
/// `match_summary` is `additionalProperties: false`; deserialization
/// rejects unknown fields to keep the projection aligned with the schema.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResult {
    /// Context identifier.
    pub ctx_id: CtxId,
    /// Lineage this version belongs to.
    pub lineage_id: LineageId,
    /// Producer's signing DID.
    pub agent_id: AgentDid,
    /// Short human-readable title.
    pub title: String,
    /// Producer-supplied search-summary (≤ 1000 chars).
    pub summary: Option<String>,
    /// Standard or namespaced custom context type.
    #[serde(rename = "type")]
    pub context_type: ContextType,
    /// Subject-domain identifier.
    pub domain: Option<String>,
    /// Registry-assigned acceptance time.
    pub created_at: DateTime<Utc>,
    /// Lifecycle status.
    pub status: Status,
    /// Visibility level per RFC-ACDP-0005 §2.2 / RFC-ACDP-0008 §4.5
    /// disclosure rules. Registries SHOULD include `Public` for public
    /// results; for `Restricted` / `Private` results the field MUST only
    /// be present when the requester is authorized. Absence MUST NOT be
    /// interpreted as `Public`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
}

// ── Typed builder ────────────────────────────────────────────────────────────

/// Typed builder for [`SearchParams`] that accepts `DateTime<Utc>` for date
/// filters and ensures they're emitted in RFC 3339 millisecond form.
#[derive(Default)]
pub struct SearchParamsBuilder {
    inner: SearchParams,
}

use crate::time::fmt_rfc3339_ms;

impl SearchParamsBuilder {
    /// Start an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Full-text query.
    pub fn q(mut self, q: impl Into<String>) -> Self {
        self.inner.q = Some(q.into());
        self
    }

    /// Filter on `type`.
    pub fn context_type(mut self, t: impl Into<String>) -> Self {
        self.inner.context_type = Some(t.into());
        self
    }

    /// Filter on `domain`.
    pub fn domain(mut self, d: impl Into<String>) -> Self {
        self.inner.domain = Some(d.into());
        self
    }

    /// Filter on tags (comma-separated).
    pub fn tags(mut self, t: impl Into<String>) -> Self {
        self.inner.tags = Some(t.into());
        self
    }

    /// Filter on `agent_id`.
    pub fn agent_id(mut self, a: impl Into<String>) -> Self {
        self.inner.agent_id = Some(a.into());
        self
    }

    /// Filter to contexts whose `derived_from` includes this `ctx_id`.
    pub fn derived_from(mut self, c: impl Into<String>) -> Self {
        self.inner.derived_from = Some(c.into());
        self
    }

    /// Typed alternative to [`Self::derived_from`] — accepts a strongly
    /// typed [`CtxId`] so callers don't pass arbitrary strings.
    pub fn derived_from_ctx_id(mut self, c: &CtxId) -> Self {
        self.inner.derived_from = Some(c.as_str().to_string());
        self
    }

    /// Accumulate a tag. Multiple calls are joined with `,` for the
    /// AND-semantics matcher per RFC-ACDP-0005 §2.1.
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        let t: String = t.into();
        match self.inner.tags.as_mut() {
            Some(existing) if !existing.is_empty() => {
                existing.push(',');
                existing.push_str(&t);
            }
            _ => self.inner.tags = Some(t),
        }
        self
    }

    /// Lower bound on `created_at`.
    pub fn created_after(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.created_after = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Upper bound on `created_at`.
    pub fn created_before(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.created_before = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Lower bound on `data_period.start`.
    pub fn data_period_start_after(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.data_period_start_after = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Upper bound on `data_period.end`.
    pub fn data_period_end_before(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.data_period_end_before = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Lower bound on `expires_at`.
    pub fn expires_after(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.expires_after = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Upper bound on `expires_at`.
    pub fn expires_before(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.expires_before = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Status filter.
    pub fn status(mut self, s: impl Into<String>) -> Self {
        self.inner.status = Some(s.into());
        self
    }

    /// Result page size cap.
    pub fn limit(mut self, l: u32) -> Self {
        self.inner.limit = Some(l);
        self
    }

    /// Pagination cursor.
    pub fn cursor(mut self, c: impl Into<String>) -> Self {
        self.inner.cursor = Some(c.into());
        self
    }

    /// Finalize.
    pub fn build(self) -> SearchParams {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_result() -> serde_json::Value {
        serde_json::json!({
            "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
            "lineage_id": "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "agent_id": "did:web:agents.example.com:test",
            "title": "x",
            "summary": null,
            "type": "data_snapshot",
            "domain": null,
            "created_at": "2026-01-01T00:00:00.000Z",
            "status": "active",
        })
    }

    /// BUG-03 — `SearchResult` carries the `visibility` projection field.
    /// `match_summary` schema marks it optional; a registry SHOULD emit
    /// it for public results and MUST omit it for restricted/private
    /// results when the requester is unauthorized.
    #[test]
    fn deserializes_with_visibility() {
        let mut v = base_result();
        v["visibility"] = serde_json::json!("public");
        let r: SearchResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.visibility, Some(Visibility::Public));
    }

    #[test]
    fn deserializes_without_visibility() {
        let r: SearchResult = serde_json::from_value(base_result()).unwrap();
        assert_eq!(r.visibility, None, "absence must NOT be coerced to Public");
    }

    /// `match_summary` is `additionalProperties: false` — extra fields
    /// must be rejected so the projection stays aligned with the schema.
    #[test]
    fn rejects_unknown_field() {
        let mut v = base_result();
        v["surprise"] = serde_json::json!("rejected");
        let r: Result<SearchResult, _> = serde_json::from_value(v);
        assert!(r.is_err(), "unknown field must trigger deny_unknown_fields");
    }

    /// Round-trip preserves visibility.
    #[test]
    fn round_trip_with_visibility_public() {
        let mut v = base_result();
        v["visibility"] = serde_json::json!("restricted");
        let r: SearchResult = serde_json::from_value(v).unwrap();
        let back = serde_json::to_value(&r).unwrap();
        assert_eq!(back["visibility"], serde_json::json!("restricted"));
    }
}
