//! Data references — `acdp-data-ref.schema.json`.
//!
//! Each `DataRef` MUST contain exactly one of `location` (URI string or
//! structured locator object) or `embedded` (inline payload, ≤ 64 KB
//! decoded). The `type` field is a closed enum identifying the role of the
//! reference within the context.

use crate::types::primitives::ContentHash;
use serde::{Deserialize, Serialize};

/// Role of a data reference. Closed enum per
/// `acdp-data-ref.schema.json` `type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataRefType {
    /// The principal output of the context.
    PrimaryResult,
    /// Source data the context describes or refers back to.
    RawData,
    /// Auxiliary material that supports the context (notes, plots, etc.).
    SupportingInfo,
    /// Output computed/derived from the primary result.
    DerivedData,
}

/// A reference to a piece of data the context describes.
///
/// Per `acdp-data-ref.schema.json` `oneOf`: exactly one of `location` or
/// `embedded` MUST be present. The struct does not enforce this at
/// construction time; runtime validation is done by `validate_data_ref`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRef {
    /// Role of this reference within the context.
    #[serde(rename = "type")]
    pub ref_type: DataRefType,

    /// Human-readable description (≤ 1000 chars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Size of the referenced or embedded data in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,

    /// Producer-defined format identifier (e.g. `parquet`, `csv`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Producer-specific schema version for this data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,

    /// Optional SHA-256 hash for verifying data integrity at fetch time.
    /// For embedded data, computed over the decoded bytes per
    /// `acdp-data-ref.schema.json`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<ContentHash>,

    /// Where the data resides — either a URI string or a structured
    /// locator object with a dotted-namespace `scheme` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,

    /// Inline embedded payload. Decoded size MUST NOT exceed 64 KB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded: Option<EmbeddedContent>,
}

/// Locator for `DataRef.location` — either a URI string or a structured
/// locator object. See `acdp-data-ref.schema.json` `location.oneOf`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Location {
    /// URI form: scheme + authority + path. MUST NOT contain credentials in
    /// the userinfo component (the body is signed and immutable, so leaked
    /// secrets cannot be redacted later).
    Uri(String),
    /// Structured locator: object with a required dotted-namespace `scheme`
    /// (e.g. `kafka.offset`, `ipfs.cid`, `db.row`). Additional keys are
    /// permitted by schema.
    Structured(serde_json::Map<String, serde_json::Value>),
}

impl DataRef {
    /// URI-form data reference (no integrity hash).
    pub fn uri(ref_type: DataRefType, uri: impl Into<String>) -> Self {
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Uri(uri.into())),
            embedded: None,
        }
    }

    /// URI-form data reference with a SHA-256 integrity hash.
    pub fn uri_verified(ref_type: DataRefType, uri: impl Into<String>, hash: ContentHash) -> Self {
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: Some(hash),
            location: Some(Location::Uri(uri.into())),
            embedded: None,
        }
    }

    /// Structured-locator data reference. `scheme` MUST match
    /// `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`. Additional fields go in `extra`.
    pub fn structured(
        ref_type: DataRefType,
        scheme: impl Into<String>,
        extra: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        let mut map = extra;
        map.insert("scheme".into(), serde_json::Value::String(scheme.into()));
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Structured(map)),
            embedded: None,
        }
    }

    /// Embedded JSON data reference.
    pub fn embedded_json(ref_type: DataRefType, content: serde_json::Value) -> Self {
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: Some("application/json".into()),
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Json,
                content,
            }),
        }
    }

    /// Embedded UTF-8 text data reference. The text is stored as a JSON string.
    pub fn embedded_utf8(ref_type: DataRefType, text: impl Into<String>) -> Self {
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Utf8,
                content: serde_json::Value::String(text.into()),
            }),
        }
    }

    /// Embedded base64 binary data reference. `b64` is stored as a JSON string.
    pub fn embedded_base64(ref_type: DataRefType, b64: impl Into<String>) -> Self {
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Base64,
                content: serde_json::Value::String(b64.into()),
            }),
        }
    }
}

/// Inline embedded data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedContent {
    /// Content encoding / interpretation.
    pub encoding: EmbeddedEncoding,
    /// The actual content. For `json` encoding this is any JSON value.
    /// For `utf8` / `base64` it MUST be a JSON string.
    pub content: serde_json::Value,
}

/// How the `content` field of an embedded data reference is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmbeddedEncoding {
    /// Any JSON value (object, array, number, …).
    Json,
    /// A UTF-8 text payload encoded as a JSON string.
    Utf8,
    /// Binary data encoded as standard base64, stored as a JSON string.
    Base64,
}
