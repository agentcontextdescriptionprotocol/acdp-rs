//! Runtime validation against the ACDP schemas.
//!
//! The JSON schemas are the single source of truth for wire-shape constraints,
//! but JSON Schema cannot express every invariant in the ACDP RFCs. This
//! module implements the runtime checks the schema delegates to producers
//! and registries:
//!
//! - String length / array uniqueness / array size limits
//! - `data_period.start <= end`
//! - `DataRef` oneOf (location XOR embedded), URI credential rejection,
//!   structured-locator scheme pattern, embedded size cap, embedded
//!   `content` typing per encoding
//! - `metadata` runtime depth / JCS-size / property-count caps
//! - `agent_id` DID pattern + `did:web` enforcement (v0.0.1)
//! - Signature value length per algorithm
//! - Embedded `content_hash` computation and verification
//! - Identifier pattern validation (`ctx_id`, `lineage_id`, `content_hash`)
//!
//! Each function is independently usable; [`validate_publish_request`] and
//! [`validate_body`] aggregate everything for end-to-end validation.

use crate::crypto::canonicalize_value;
use crate::error::AcdpError;
use crate::types::body::Body;
use crate::types::data_ref::{DataRef, EmbeddedContent, EmbeddedEncoding, Location};
use crate::types::primitives::{
    AgentDid, ContentHash, ContextType, CtxId, LineageId, Status, Visibility,
};
use crate::types::publish::PublishRequest;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

// ── Constants from the schemas ────────────────────────────────────────────────

const MAX_TITLE_LEN: usize = 500;
const MAX_DESCRIPTION_LEN: usize = 5000;
const MAX_SUMMARY_LEN: usize = 1000;
const MAX_DOMAIN_LEN: usize = 200;
const MAX_DATA_REF_DESCRIPTION_LEN: usize = 1000;
const MAX_TAG_LEN: usize = 100;
const MAX_CONTRIBUTORS: usize = 100;
const MAX_TAGS: usize = 200;
const MAX_DERIVED_FROM: usize = 1000;
const MAX_AUDIENCE: usize = 1000;
const MAX_METADATA_PROPERTIES: usize = 100;
const MAX_METADATA_DEPTH: usize = 8;
const MAX_METADATA_JCS_BYTES: usize = 65_536;
const MAX_URI_LEN: usize = 4096;
const MAX_EMBEDDED_BYTES: usize = 65_536;
const ED25519_SIG_B64_LEN: usize = 88;
const ECDSA_P256_SIG_B64_LEN: usize = 88;

// ── Top-level entry points ───────────────────────────────────────────────────

/// Validate a complete [`PublishRequest`] against every schema constraint
/// and runtime invariant.
pub fn validate_publish_request(req: &PublishRequest) -> Result<(), AcdpError> {
    validate_title(&req.title)?;
    validate_optional_string(
        req.description.as_deref(),
        "description",
        MAX_DESCRIPTION_LEN,
    )?;
    validate_optional_string(req.summary.as_deref(), "summary", MAX_SUMMARY_LEN)?;
    validate_optional_string(req.domain.as_deref(), "domain", MAX_DOMAIN_LEN)?;

    validate_agent_did(&req.agent_id)?;
    for c in &req.contributors {
        validate_agent_did(c)?;
    }
    validate_unique_array("contributors", &req.contributors, MAX_CONTRIBUTORS)?;
    validate_unique_array("derived_from", &req.derived_from, MAX_DERIVED_FROM)?;

    if let Some(tags) = &req.tags {
        validate_tags(tags)?;
    }
    if let Some(audience) = &req.audience {
        validate_unique_array("audience", audience, MAX_AUDIENCE)?;
        for did in audience {
            validate_agent_did(did)?;
        }
    }

    validate_visibility_audience(&req.visibility, req.audience.as_deref())?;

    if let Some(dp) = &req.data_period {
        if dp.start > dp.end {
            return Err(AcdpError::SchemaViolation(
                "data_period.start must not be after data_period.end".into(),
            ));
        }
    }

    if let Some(ct) = &req.context_type.namespaced_form() {
        validate_namespaced_context_type(ct)?;
    }

    if let Some(meta) = &req.metadata {
        validate_metadata(meta)?;
    }

    for dr in &req.data_refs {
        validate_data_ref(dr)?;
    }

    validate_signature_length(&req.signature.algorithm, &req.signature.value)?;
    ContentHash::parse(req.content_hash.as_str())?;

    // Version coherence (also enforced by the builder)
    match (&req.supersedes, req.version) {
        (None, 1) => {}
        (None, v) => {
            return Err(AcdpError::SchemaViolation(format!(
                "first-version publish requires version=1, got {v}"
            )));
        }
        (Some(_), v) if v >= 2 => {}
        (Some(_), v) => {
            return Err(AcdpError::SchemaViolation(format!(
                "supersession publish requires version >= 2, got {v}"
            )));
        }
    }

    Ok(())
}

/// Validate a stored [`Body`] (retrieval-side check).
pub fn validate_body(body: &Body) -> Result<(), AcdpError> {
    validate_title(&body.title)?;
    validate_optional_string(
        body.description.as_deref(),
        "description",
        MAX_DESCRIPTION_LEN,
    )?;
    validate_optional_string(body.summary.as_deref(), "summary", MAX_SUMMARY_LEN)?;
    validate_optional_string(body.domain.as_deref(), "domain", MAX_DOMAIN_LEN)?;

    validate_agent_did(&body.agent_id)?;
    for c in &body.contributors {
        validate_agent_did(c)?;
    }
    validate_unique_array("contributors", &body.contributors, MAX_CONTRIBUTORS)?;
    validate_unique_array("derived_from", &body.derived_from, MAX_DERIVED_FROM)?;

    if let Some(tags) = &body.tags {
        validate_tags(tags)?;
    }
    if let Some(audience) = &body.audience {
        validate_unique_array("audience", audience, MAX_AUDIENCE)?;
    }
    validate_visibility_audience(&body.visibility, body.audience.as_deref())?;

    if let Some(dp) = &body.data_period {
        if dp.start > dp.end {
            return Err(AcdpError::SchemaViolation(
                "data_period.start must not be after data_period.end".into(),
            ));
        }
    }

    if let Some(meta) = &body.metadata {
        validate_metadata(meta)?;
    }

    for dr in &body.data_refs {
        validate_data_ref(dr)?;
    }

    validate_signature_length(&body.signature.algorithm, &body.signature.value)?;
    validate_identifiers(&body.ctx_id, &body.lineage_id, &body.content_hash)?;
    let _ = &body.created_at; // schema-derived; serde already enforces RFC 3339
    let _ = &body.origin_registry;

    // Avoid unused-import warnings on Status / Visibility
    let _ = std::any::type_name::<Status>();
    let _: &Visibility = &body.visibility;

    Ok(())
}

/// Validate an identifier triple — convenient for retrieval-side use.
pub fn validate_identifiers(
    ctx_id: &CtxId,
    lineage_id: &LineageId,
    content_hash: &ContentHash,
) -> Result<(), AcdpError> {
    CtxId::parse(ctx_id.as_str())?;
    LineageId::parse(lineage_id.as_str())?;
    ContentHash::parse(content_hash.as_str())?;
    Ok(())
}

// ── DataRef ──────────────────────────────────────────────────────────────────

/// Validate a single [`DataRef`] against `acdp-data-ref.schema.json` and the
/// runtime invariants the schema delegates.
pub fn validate_data_ref(dr: &DataRef) -> Result<(), AcdpError> {
    // oneOf: exactly one of location / embedded
    match (&dr.location, &dr.embedded) {
        (None, None) => {
            return Err(AcdpError::SchemaViolation(
                "DataRef requires exactly one of 'location' or 'embedded' (got neither)".into(),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(AcdpError::SchemaViolation(
                "DataRef requires exactly one of 'location' or 'embedded' (got both)".into(),
            ));
        }
        _ => {}
    }

    if let Some(desc) = &dr.description {
        if desc.len() > MAX_DATA_REF_DESCRIPTION_LEN {
            return Err(AcdpError::SchemaViolation(format!(
                "DataRef.description {} chars exceeds {} limit",
                desc.len(),
                MAX_DATA_REF_DESCRIPTION_LEN
            )));
        }
    }

    if let Some(loc) = &dr.location {
        validate_location(loc)?;
    }
    if let Some(emb) = &dr.embedded {
        validate_embedded(emb)?;
    }

    Ok(())
}

fn validate_location(loc: &Location) -> Result<(), AcdpError> {
    match loc {
        Location::Uri(uri) => validate_uri_location(uri),
        Location::Structured(map) => validate_structured_locator(map),
    }
}

fn validate_uri_location(uri: &str) -> Result<(), AcdpError> {
    if uri.len() < 3 || uri.len() > MAX_URI_LEN {
        return Err(AcdpError::SchemaViolation(format!(
            "DataRef.location URI length {} not in 3..={}",
            uri.len(),
            MAX_URI_LEN
        )));
    }
    // Scheme: ^[a-z][a-z0-9+.-]*:
    let (scheme, rest) = uri
        .split_once(':')
        .ok_or_else(|| AcdpError::SchemaViolation(format!("URI missing scheme: {uri}")))?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'))
    {
        return Err(AcdpError::SchemaViolation(format!(
            "URI scheme '{scheme}' invalid; must match [a-z][a-z0-9+.-]*"
        )));
    }
    // userinfo rejection: ^[a-z][a-z0-9+.-]*://[^/?#@]+@
    if let Some(after_slashes) = rest.strip_prefix("//") {
        if let Some(authority_end) = after_slashes.find(['/', '?', '#']) {
            let authority = &after_slashes[..authority_end];
            if authority.contains('@') {
                return Err(AcdpError::SchemaViolation(format!(
                    "URI MUST NOT contain credentials in userinfo: {uri}"
                )));
            }
        } else if after_slashes.contains('@') {
            return Err(AcdpError::SchemaViolation(format!(
                "URI MUST NOT contain credentials in userinfo: {uri}"
            )));
        }
    }
    Ok(())
}

fn validate_structured_locator(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AcdpError> {
    let scheme = map.get("scheme").and_then(|v| v.as_str()).ok_or_else(|| {
        AcdpError::SchemaViolation("structured locator missing required 'scheme'".into())
    })?;
    if !is_dotted_namespace_scheme(scheme) {
        return Err(AcdpError::SchemaViolation(format!(
            "structured locator scheme '{scheme}' must match ^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$"
        )));
    }
    Ok(())
}

fn is_dotted_namespace_scheme(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().all(|part| {
        !part.is_empty()
            && part.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

fn validate_embedded(emb: &EmbeddedContent) -> Result<(), AcdpError> {
    // utf8 / base64: content MUST be a JSON string
    match emb.encoding {
        EmbeddedEncoding::Utf8 | EmbeddedEncoding::Base64 => {
            if !emb.content.is_string() {
                return Err(AcdpError::SchemaViolation(format!(
                    "embedded {:?} content MUST be a JSON string",
                    emb.encoding
                )));
            }
        }
        EmbeddedEncoding::Json => {}
    }
    // Decoded size cap
    let decoded = embedded_decoded_bytes(emb)?;
    if decoded.len() > MAX_EMBEDDED_BYTES {
        return Err(AcdpError::EmbeddedTooLarge(format!(
            "embedded decoded size {} bytes exceeds {} limit",
            decoded.len(),
            MAX_EMBEDDED_BYTES
        )));
    }
    Ok(())
}

/// Decode an [`EmbeddedContent`] to its canonical byte form per
/// `acdp-data-ref.schema.json` `content_hash` semantics:
/// - `json`   → JCS-canonicalized bytes
/// - `utf8`   → raw UTF-8 bytes of the string
/// - `base64` → base64-decoded bytes of the string
pub fn embedded_decoded_bytes(emb: &EmbeddedContent) -> Result<Vec<u8>, AcdpError> {
    Ok(match emb.encoding {
        EmbeddedEncoding::Json => canonicalize_value(&emb.content),
        EmbeddedEncoding::Utf8 => {
            let s = emb.content.as_str().ok_or_else(|| {
                AcdpError::SchemaViolation("utf8 embedded content must be a JSON string".into())
            })?;
            s.as_bytes().to_vec()
        }
        EmbeddedEncoding::Base64 => {
            let s = emb.content.as_str().ok_or_else(|| {
                AcdpError::SchemaViolation("base64 embedded content must be a JSON string".into())
            })?;
            STANDARD
                .decode(s)
                .map_err(|e| AcdpError::SchemaViolation(format!("base64 decode failed: {e}")))?
        }
    })
}

/// Compute the SHA-256 [`ContentHash`] of decoded embedded content.
pub fn compute_embedded_hash(emb: &EmbeddedContent) -> Result<ContentHash, AcdpError> {
    let bytes = embedded_decoded_bytes(emb)?;
    let digest = Sha256::digest(&bytes);
    Ok(ContentHash(format!("sha256:{}", hex::encode(digest))))
}

/// Verify a [`DataRef`]'s declared `content_hash` against its embedded payload.
/// Does nothing if the ref has no `content_hash` or no `embedded`.
pub fn verify_embedded_hash(dr: &DataRef) -> Result<(), AcdpError> {
    let (Some(emb), Some(stored)) = (&dr.embedded, &dr.content_hash) else {
        return Ok(());
    };
    let recomputed = compute_embedded_hash(emb)?;
    if &recomputed != stored {
        return Err(AcdpError::HashMismatch {
            stored: stored.clone(),
            recomputed,
        });
    }
    Ok(())
}

// ── Metadata ─────────────────────────────────────────────────────────────────

/// Validate `metadata`'s runtime invariants per RFC-ACDP-0002 §3.3:
/// max 100 top-level properties, max 8 nesting levels, max 64 KB JCS size.
pub fn validate_metadata(value: &serde_json::Value) -> Result<(), AcdpError> {
    let obj = value
        .as_object()
        .ok_or_else(|| AcdpError::SchemaViolation("metadata must be a JSON object".into()))?;
    if obj.len() > MAX_METADATA_PROPERTIES {
        return Err(AcdpError::SchemaViolation(format!(
            "metadata has {} top-level properties, exceeds {} limit",
            obj.len(),
            MAX_METADATA_PROPERTIES
        )));
    }
    let depth = json_depth(value);
    if depth > MAX_METADATA_DEPTH {
        return Err(AcdpError::SchemaViolation(format!(
            "metadata nesting depth {depth} exceeds {MAX_METADATA_DEPTH}"
        )));
    }
    let canonical_size = canonicalize_value(value).len();
    if canonical_size > MAX_METADATA_JCS_BYTES {
        return Err(AcdpError::SchemaViolation(format!(
            "metadata JCS-canonical size {canonical_size} bytes exceeds {MAX_METADATA_JCS_BYTES}"
        )));
    }
    Ok(())
}

fn json_depth(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Array(arr) => 1 + arr.iter().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

// ── Visibility ───────────────────────────────────────────────────────────────

fn validate_visibility_audience(
    vis: &Visibility,
    audience: Option<&[AgentDid]>,
) -> Result<(), AcdpError> {
    match vis {
        Visibility::Restricted => {
            if audience.map_or(true, |a| a.is_empty()) {
                return Err(AcdpError::SchemaViolation(
                    "visibility:restricted requires a non-empty audience".into(),
                ));
            }
        }
        Visibility::Public => {
            if audience.is_some_and(|a| !a.is_empty()) {
                return Err(AcdpError::SchemaViolation(
                    "visibility:public MUST NOT include audience".into(),
                ));
            }
        }
        Visibility::Private => {}
    }
    Ok(())
}

// ── Strings & arrays ─────────────────────────────────────────────────────────

fn validate_title(title: &str) -> Result<(), AcdpError> {
    if title.is_empty() || title.chars().count() > MAX_TITLE_LEN {
        return Err(AcdpError::SchemaViolation(format!(
            "title length {} not in 1..={}",
            title.chars().count(),
            MAX_TITLE_LEN
        )));
    }
    Ok(())
}

fn validate_optional_string(s: Option<&str>, name: &str, max_len: usize) -> Result<(), AcdpError> {
    if let Some(value) = s {
        if value.chars().count() > max_len {
            return Err(AcdpError::SchemaViolation(format!(
                "{name} length {} exceeds {max_len}",
                value.chars().count()
            )));
        }
    }
    Ok(())
}

fn validate_unique_array<T: PartialEq + std::fmt::Debug>(
    name: &str,
    items: &[T],
    max: usize,
) -> Result<(), AcdpError> {
    if items.len() > max {
        return Err(AcdpError::SchemaViolation(format!(
            "{name} has {} items, exceeds {max}",
            items.len()
        )));
    }
    for (i, item) in items.iter().enumerate() {
        if items[i + 1..].iter().any(|other| other == item) {
            return Err(AcdpError::SchemaViolation(format!(
                "{name} contains duplicate entry: {item:?}"
            )));
        }
    }
    Ok(())
}

fn validate_tags(tags: &[String]) -> Result<(), AcdpError> {
    if tags.len() > MAX_TAGS {
        return Err(AcdpError::SchemaViolation(format!(
            "tags has {} entries, exceeds {}",
            tags.len(),
            MAX_TAGS
        )));
    }
    for tag in tags {
        validate_tag(tag)?;
    }
    // Uniqueness
    for (i, tag) in tags.iter().enumerate() {
        if tags[i + 1..].iter().any(|t| t == tag) {
            return Err(AcdpError::SchemaViolation(format!(
                "tags contains duplicate entry: {tag}"
            )));
        }
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), AcdpError> {
    if tag.is_empty() || tag.len() > MAX_TAG_LEN {
        return Err(AcdpError::SchemaViolation(format!(
            "tag '{tag}' length not in 1..={MAX_TAG_LEN}"
        )));
    }
    let mut chars = tag.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(AcdpError::SchemaViolation(format!(
            "tag '{tag}' first char must be alphanumeric"
        )));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) {
        return Err(AcdpError::SchemaViolation(format!(
            "tag '{tag}' must match [A-Za-z0-9][A-Za-z0-9_.-]*"
        )));
    }
    Ok(())
}

// ── DID / agent_id ───────────────────────────────────────────────────────────

fn validate_agent_did(did: &AgentDid) -> Result<(), AcdpError> {
    AgentDid::parse(did.as_str())?;
    Ok(())
}

// ── Context type ─────────────────────────────────────────────────────────────

fn validate_namespaced_context_type(value: &str) -> Result<(), AcdpError> {
    // Schema pattern: ^[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*$
    let (ns, name) = value.split_once(':').ok_or_else(|| {
        AcdpError::SchemaViolation(format!(
            "context_type '{value}' missing namespace separator"
        ))
    })?;
    if ns.is_empty()
        || !ns.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        || !ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(AcdpError::SchemaViolation(format!(
            "context_type namespace '{ns}' must match [a-z][a-z0-9_]*"
        )));
    }
    if name.is_empty()
        || !name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
    {
        return Err(AcdpError::SchemaViolation(format!(
            "context_type name '{name}' must match [a-z][a-z0-9_-]*"
        )));
    }
    Ok(())
}

trait ContextTypeExt {
    fn namespaced_form(&self) -> Option<&str>;
}

impl ContextTypeExt for ContextType {
    fn namespaced_form(&self) -> Option<&str> {
        match self {
            ContextType::Custom(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

// ── Signatures ───────────────────────────────────────────────────────────────

fn validate_signature_length(algorithm: &str, value_b64: &str) -> Result<(), AcdpError> {
    let expected = match algorithm {
        "ed25519" => Some(ED25519_SIG_B64_LEN),
        "ecdsa-p256" => Some(ECDSA_P256_SIG_B64_LEN),
        _ => None,
    };
    if let Some(n) = expected {
        if value_b64.len() != n {
            return Err(AcdpError::InvalidSignature(format!(
                "signature.value for '{algorithm}' must be {n} base64 chars, got {}",
                value_b64.len()
            )));
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::data_ref::DataRefType;
    use serde_json::json;

    fn embedded_json(v: serde_json::Value) -> EmbeddedContent {
        EmbeddedContent {
            encoding: EmbeddedEncoding::Json,
            content: v,
        }
    }

    // ── DataRef.oneOf ────────────────────────────────────────────────────────

    #[test]
    fn data_ref_neither_location_nor_embedded_rejected() {
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: None,
        };
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn data_ref_both_location_and_embedded_rejected() {
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Uri("https://x/y".into())),
            embedded: Some(embedded_json(json!({"a": 1}))),
        };
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    // ── DataRef.location URI ─────────────────────────────────────────────────

    #[test]
    fn uri_credentials_rejected() {
        let dr = DataRef::uri(DataRefType::RawData, "https://user:pass@example.com/data");
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn uri_without_scheme_rejected() {
        let dr = DataRef::uri(DataRefType::RawData, "no-scheme");
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn uri_too_long_rejected() {
        let long_uri = format!("https://x.com/{}", "a".repeat(MAX_URI_LEN));
        let dr = DataRef::uri(DataRefType::RawData, long_uri);
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    // ── DataRef.location structured ──────────────────────────────────────────

    #[test]
    fn structured_locator_missing_scheme_rejected() {
        let mut map = serde_json::Map::new();
        map.insert("offset".into(), json!(42));
        let dr = DataRef {
            ref_type: DataRefType::RawData,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Structured(map)),
            embedded: None,
        };
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn structured_locator_bad_scheme_rejected() {
        let dr = DataRef::structured(DataRefType::RawData, "not_dotted", serde_json::Map::new());
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn structured_locator_valid() {
        let mut extra = serde_json::Map::new();
        extra.insert("topic".into(), json!("events"));
        let dr = DataRef::structured(DataRefType::RawData, "kafka.offset", extra);
        validate_data_ref(&dr).unwrap();
    }

    // ── DataRef.embedded ─────────────────────────────────────────────────────

    #[test]
    fn embedded_utf8_must_be_string() {
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Utf8,
                content: json!(42),
            }),
        };
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn embedded_too_large_rejected() {
        // 70 KB of UTF-8 content
        let big = "a".repeat(70 * 1024);
        let dr = DataRef::embedded_utf8(DataRefType::PrimaryResult, big);
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::EmbeddedTooLarge(_))
        ));
    }

    // ── Embedded hash ────────────────────────────────────────────────────────

    #[test]
    fn embedded_hash_json_round_trip() {
        let emb = embedded_json(json!({"b": 2, "a": 1}));
        let h = compute_embedded_hash(&emb).unwrap();
        // JCS sorts keys → {"a":1,"b":2}, hash is deterministic
        let expected = {
            let bytes = b"{\"a\":1,\"b\":2}";
            format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
        };
        assert_eq!(h.as_str(), expected);
    }

    #[test]
    fn embedded_hash_utf8() {
        let emb = EmbeddedContent {
            encoding: EmbeddedEncoding::Utf8,
            content: json!("hello"),
        };
        let h = compute_embedded_hash(&emb).unwrap();
        let expected = format!("sha256:{}", hex::encode(Sha256::digest(b"hello")));
        assert_eq!(h.as_str(), expected);
    }

    #[test]
    fn embedded_hash_base64() {
        let raw = b"binary data";
        let b64 = STANDARD.encode(raw);
        let emb = EmbeddedContent {
            encoding: EmbeddedEncoding::Base64,
            content: json!(b64),
        };
        let h = compute_embedded_hash(&emb).unwrap();
        let expected = format!("sha256:{}", hex::encode(Sha256::digest(raw)));
        assert_eq!(h.as_str(), expected);
    }

    #[test]
    fn verify_embedded_hash_mismatch_detected() {
        let emb = embedded_json(json!({"x": 1}));
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: Some(ContentHash("sha256:0000".into())),
            location: None,
            embedded: Some(emb),
        };
        assert!(matches!(
            verify_embedded_hash(&dr),
            Err(AcdpError::HashMismatch { .. })
        ));
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn metadata_too_many_properties_rejected() {
        let mut obj = serde_json::Map::new();
        for i in 0..101 {
            obj.insert(format!("k{i}"), json!(i));
        }
        assert!(matches!(
            validate_metadata(&serde_json::Value::Object(obj)),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn metadata_too_deep_rejected() {
        // Build an object nested 10 levels deep
        let mut v = json!("leaf");
        for _ in 0..10 {
            let mut o = serde_json::Map::new();
            o.insert("a".into(), v);
            v = serde_json::Value::Object(o);
        }
        assert!(matches!(
            validate_metadata(&v),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn metadata_too_large_rejected() {
        let big = "a".repeat(70 * 1024);
        let v = json!({"big": big});
        assert!(matches!(
            validate_metadata(&v),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn metadata_must_be_object() {
        assert!(matches!(
            validate_metadata(&json!([1, 2, 3])),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    // ── Visibility / audience ────────────────────────────────────────────────

    #[test]
    fn public_with_audience_rejected() {
        let aud = vec![AgentDid::new("did:web:x")];
        assert!(matches!(
            validate_visibility_audience(&Visibility::Public, Some(&aud)),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn public_with_empty_audience_ok() {
        validate_visibility_audience(&Visibility::Public, Some(&[])).unwrap();
        validate_visibility_audience(&Visibility::Public, None).unwrap();
    }

    #[test]
    fn restricted_without_audience_rejected() {
        assert!(matches!(
            validate_visibility_audience(&Visibility::Restricted, None),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    // ── data_period ──────────────────────────────────────────────────────────

    #[test]
    fn data_period_start_after_end_rejected_via_builder() {
        use crate::crypto::SigningKey;
        use crate::producer::Producer;
        use crate::types::body::DataPeriod;
        use chrono::TimeZone;

        let p = Producer::new(
            SigningKey::from_bytes(&[0u8; 32]),
            AgentDid::new("did:web:agents.example.com:test"),
            "did:web:agents.example.com:test#key-1",
        );
        let err = p
            .publish_request()
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .data_period(DataPeriod {
                start: chrono::Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap(),
                end: chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            })
            .build()
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    // ── Tags ─────────────────────────────────────────────────────────────────

    #[test]
    fn tag_pattern_validation() {
        validate_tag("hello").unwrap();
        validate_tag("Q1-2026").unwrap();
        validate_tag("a_b.c").unwrap();
        // Cannot start with non-alphanumeric
        assert!(validate_tag("-bad").is_err());
        // Disallowed chars
        assert!(validate_tag("space here").is_err());
        // Empty
        assert!(validate_tag("").is_err());
    }

    #[test]
    fn duplicate_tags_rejected() {
        let tags = vec!["a".to_string(), "b".to_string(), "a".to_string()];
        assert!(validate_tags(&tags).is_err());
    }

    // ── Signature length ─────────────────────────────────────────────────────

    #[test]
    fn ed25519_sig_must_be_88_chars() {
        assert!(validate_signature_length("ed25519", "AAAA").is_err());
        validate_signature_length("ed25519", &"A".repeat(88)).unwrap();
        // Unknown algorithm: skipped
        validate_signature_length("future-alg", "any").unwrap();
    }

    // ── context_type custom ──────────────────────────────────────────────────

    #[test]
    fn namespaced_context_type_pattern() {
        validate_namespaced_context_type("finance:portfolio_snapshot").unwrap();
        assert!(validate_namespaced_context_type("Finance:portfolio").is_err());
        assert!(validate_namespaced_context_type("finance:Portfolio").is_err());
        assert!(validate_namespaced_context_type("no-colon").is_err());
    }
}
