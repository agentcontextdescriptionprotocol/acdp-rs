//! Typed external anchors — `acdp-common.schema.json` (RFC-ACDP-0016, 0.5.0).
//!
//! An anchor is a producer-signed, content-addressed reference from an
//! ACDP body to a non-ACDP external artifact (a commitment record, a
//! sealed decision, anything identified by its own digest). It is part
//! of ProducerContent (RFC-ACDP-0001 §5.7) — included in the
//! `content_hash` preimage exactly like any other producer-controlled
//! field, with no special-casing in the hash pipeline.
//!
//! Anchors are opaque to core verification (RFC-ACDP-0016 §6): a
//! verifier that does not recognize an anchor's `scheme` MUST ignore it
//! for resolution purposes while still treating it as signed content.
//! `uri` is an advisory locator hint only — it MUST NOT be dereferenced
//! by any ACDP-level verification code path; the binding is
//! `content_hash`, never `uri`.

use acdp_primitives::primitives::ContentHash;
use serde::{Deserialize, Serialize};

/// One entry in `Body::anchors` / `PublishRequest::anchors`.
///
/// `additionalProperties: true` per RFC-ACDP-0016 §4: a future
/// anchor-scheme-specific field is automatically signed under the
/// RFC-ACDP-0001 §5.7 unknown-field rule without a schema update, so
/// unknown keys are preserved in [`Self::extensions`] rather than
/// rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnchorEntry {
    /// Dotted-namespace identifier of the external artifact's system
    /// (e.g. `macp.commitment`), pattern
    /// `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$` (the same structured-locator
    /// scheme grammar as RFC-ACDP-0002 §6.2). Opaque to core
    /// verification — an unrecognized scheme has zero effect on the
    /// body's ACDP-level verification verdict (RFC-ACDP-0016 §6).
    pub scheme: String,
    /// The external artifact's own content digest
    /// (`"sha256:" + 64 lowercase hex`) — an independent digest,
    /// unrelated to the body's own `content_hash` field. This is the
    /// anchor's genesis identity (RFC-ACDP-0016 §4, §7).
    pub content_hash: ContentHash,
    /// Optional locator hint for resolving the artifact. Advisory
    /// only: the binding is `content_hash`, not `uri`. MUST NOT be
    /// dereferenced by any ACDP-level verification code path
    /// (RFC-ACDP-0016 §6, NORMATIVE) — no code in this crate reads
    /// this field for anything but (de)serialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Forward-compatible passthrough for anchor-scheme-specific
    /// fields not yet known to this crate (RFC-ACDP-0016 §4's
    /// `additionalProperties: true`).
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}
