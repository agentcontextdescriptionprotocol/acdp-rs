//! Shared parsers used by `producer.rs`. Kept narrow on purpose — the
//! conversions mirror what serde does at deserialize time so JS callers
//! get the same validation Rust callers do.

use acdp::types::{ContextType, DataPeriod, DataRef, LineageId, Visibility};
use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;

/// Parse a context-type string into the typed enum.
pub(crate) fn parse_context_type(s: &str) -> Result<ContextType> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| Error::from_reason(format!("invalid contextType '{s}': {e}")))
}

/// Parse a visibility string into the typed enum.
pub(crate) fn parse_visibility(s: &str) -> Result<Visibility> {
    match s {
        "public" => Ok(Visibility::Public),
        "restricted" => Ok(Visibility::Restricted),
        "private" => Ok(Visibility::Private),
        other => Err(Error::from_reason(format!(
            "invalid visibility '{other}'; expected public | restricted | private"
        ))),
    }
}

/// Parse a JSON-encoded `DataRef[]` string into the typed vector.
/// Each element MUST satisfy `acdp-data-ref.schema.json`; serde applies
/// the same field validation Rust callers get.
pub(crate) fn parse_data_refs(s: &str) -> Result<Vec<DataRef>> {
    serde_json::from_str(s).map_err(|e| Error::from_reason(format!("invalid dataRefs JSON: {e}")))
}

/// Parse a JSON-encoded `{ "start": <rfc3339>, "end": <rfc3339> }`
/// object into a `DataPeriod`. The builder re-truncates both ends to
/// millisecond precision.
pub(crate) fn parse_data_period(s: &str) -> Result<DataPeriod> {
    serde_json::from_str(s).map_err(|e| Error::from_reason(format!("invalid dataPeriod JSON: {e}")))
}

/// Parse an RFC 3339 timestamp string into `DateTime<Utc>` for
/// `expiresAt`. The builder re-truncates to millisecond precision.
pub(crate) fn parse_timestamp(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::from_reason(format!("invalid RFC 3339 timestamp '{s}': {e}")))
}

/// Validate and wrap a `lin:sha256:<64-hex>` lineage-id string.
pub(crate) fn parse_lineage_id(s: &str) -> Result<LineageId> {
    LineageId::parse(s).map_err(|e| Error::from_reason(format!("invalid lineageId: {e}")))
}
