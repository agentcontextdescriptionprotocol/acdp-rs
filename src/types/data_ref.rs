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
    ///
    /// Optional and absent-or-string in `acdp-data-ref.schema.json` — not
    /// nullable. `de_present` rejects an explicit `"description": null`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::types::serde_helpers::de_present"
    )]
    pub description: Option<String>,

    /// Size of the referenced or embedded data in bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::types::serde_helpers::de_present"
    )]
    pub size_bytes: Option<u64>,

    /// Producer-defined format identifier (e.g. `parquet`, `csv`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::types::serde_helpers::de_present"
    )]
    pub format: Option<String>,

    /// Producer-specific schema version for this data.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::types::serde_helpers::de_present"
    )]
    pub schema_version: Option<String>,

    /// Optional SHA-256 hash for verifying data integrity at fetch time.
    /// For embedded data, computed over the decoded bytes per
    /// `acdp-data-ref.schema.json`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::types::serde_helpers::de_present"
    )]
    pub content_hash: Option<ContentHash>,

    /// Where the data resides — either a URI string or a structured
    /// locator object with a dotted-namespace `scheme` field.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::types::serde_helpers::de_present"
    )]
    pub location: Option<Location>,

    /// Inline embedded payload. Decoded size MUST NOT exceed 64 KB.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::types::serde_helpers::de_present"
    )]
    pub embedded: Option<EmbeddedContent>,

    /// Unknown producer-controlled `DataRef` fields, preserved verbatim.
    ///
    /// `acdp-data-ref.schema.json` has NO `additionalProperties: false`
    /// at its root — the object is open by design. A `DataRef` lives
    /// inside `ProducerContent` (the `content_hash` preimage), so a
    /// future ACDP minor version that adds a producer-controlled DataRef
    /// field must round-trip through this map: without it an older
    /// consumer would silently drop the new field on deserialization and
    /// recompute a different `content_hash`, falsely failing verification.
    /// Mirrors the [`crate::types::body::Body::extensions`] pattern
    /// (RFC-ACDP-0001 §5.7, conformance fixture can-010).
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
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
            extensions: serde_json::Map::new(),
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
            extensions: serde_json::Map::new(),
        }
    }

    /// Structured-locator data reference. `scheme` MUST match
    /// `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`. Additional fields go in `extra`.
    ///
    /// In debug builds, an invalid scheme triggers a `debug_assert!`
    /// to surface the bug at construction time. Release builds accept
    /// the malformed value silently — pair this constructor with
    /// [`crate::validation::validate_data_ref`] (called automatically
    /// by `RequestBuilder::build`) for runtime rejection. For a
    /// fallible variant, use [`Self::try_structured`].
    pub fn structured(
        ref_type: DataRefType,
        scheme: impl Into<String>,
        extra: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        let scheme: String = scheme.into();
        debug_assert!(
            is_dotted_namespace_scheme(&scheme),
            "DataRef::structured: scheme '{scheme}' does not match \
             ^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$ — pass a dotted-namespace identifier \
             like 'kafka.offset' or use try_structured for runtime checking"
        );
        let mut map = extra;
        map.insert("scheme".into(), serde_json::Value::String(scheme));
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Structured(map)),
            embedded: None,
            extensions: serde_json::Map::new(),
        }
    }

    /// Fallible structured-locator constructor. Returns
    /// [`crate::error::AcdpError::SchemaViolation`] if `scheme` does
    /// not match the dotted-namespace pattern.
    pub fn try_structured(
        ref_type: DataRefType,
        scheme: impl Into<String>,
        extra: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, crate::error::AcdpError> {
        let scheme: String = scheme.into();
        if !is_dotted_namespace_scheme(&scheme) {
            return Err(crate::error::AcdpError::SchemaViolation(format!(
                "structured locator scheme '{scheme}' must match \
                 ^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$"
            )));
        }
        let mut map = extra;
        map.insert("scheme".into(), serde_json::Value::String(scheme));
        Ok(Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Structured(map)),
            embedded: None,
            extensions: serde_json::Map::new(),
        })
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
            extensions: serde_json::Map::new(),
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
            extensions: serde_json::Map::new(),
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
            extensions: serde_json::Map::new(),
        }
    }

    // ── Type-bound URI shortcuts ─────────────────────────────────────────────
    //
    // The four DataRefType variants come up frequently; these one-liners
    // save a `DataRefType::PrimaryResult` mention at every call site.

    /// `DataRef::uri(DataRefType::PrimaryResult, uri)`.
    pub fn primary_result_uri(uri: impl Into<String>) -> Self {
        Self::uri(DataRefType::PrimaryResult, uri)
    }
    /// `DataRef::uri(DataRefType::RawData, uri)`.
    pub fn raw_data_uri(uri: impl Into<String>) -> Self {
        Self::uri(DataRefType::RawData, uri)
    }
    /// `DataRef::uri(DataRefType::SupportingInfo, uri)`.
    pub fn supporting_info_uri(uri: impl Into<String>) -> Self {
        Self::uri(DataRefType::SupportingInfo, uri)
    }
    /// `DataRef::uri(DataRefType::DerivedData, uri)`.
    pub fn derived_data_uri(uri: impl Into<String>) -> Self {
        Self::uri(DataRefType::DerivedData, uri)
    }

    /// `DataRef::embedded_json(DataRefType::PrimaryResult, content)`.
    pub fn primary_result_json(content: serde_json::Value) -> Self {
        Self::embedded_json(DataRefType::PrimaryResult, content)
    }
    /// `DataRef::embedded_json(DataRefType::DerivedData, content)`.
    pub fn derived_data_json(content: serde_json::Value) -> Self {
        Self::embedded_json(DataRefType::DerivedData, content)
    }
}

/// Inline embedded data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedContent {
    /// Content encoding / interpretation.
    pub encoding: EmbeddedEncoding,
    /// The actual content. For `json` encoding this is any JSON value.
    /// For `utf8` / `base64` it MUST be a JSON string.
    pub content: serde_json::Value,
}

/// Validate dotted-namespace scheme pattern.
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
