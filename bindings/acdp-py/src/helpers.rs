//! Small shared conversions used by both `producer.rs` and `verifier.rs`.

use acdp::types::{ContextType, DataPeriod, DataRef, LineageId, Visibility};
use chrono::{DateTime, Utc};
use pyo3::exceptions::PyValueError;
use pyo3::PyResult;

/// Parse a context-type string into the typed enum. Accepts the four
/// standard values (`data_snapshot`, `analysis`, `prediction`, `alert`)
/// and any namespaced custom type matching
/// `^[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*$` — same validation the Rust core
/// applies on deserialization.
pub(crate) fn parse_context_type(s: &str) -> PyResult<ContextType> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| PyValueError::new_err(format!("invalid context_type '{s}': {e}")))
}

/// Parse a visibility string into the typed enum.
pub(crate) fn parse_visibility(s: &str) -> PyResult<Visibility> {
    match s {
        "public" => Ok(Visibility::Public),
        "restricted" => Ok(Visibility::Restricted),
        "private" => Ok(Visibility::Private),
        other => Err(PyValueError::new_err(format!(
            "invalid visibility '{other}'; expected public | restricted | private"
        ))),
    }
}

/// Parse a JSON-encoded `DataRef[]` string into the typed vector.
/// Each element MUST satisfy `acdp-data-ref.schema.json`; serde applies
/// the same field validation Rust callers get.
pub(crate) fn parse_data_refs(s: &str) -> PyResult<Vec<DataRef>> {
    serde_json::from_str(s)
        .map_err(|e| PyValueError::new_err(format!("invalid data_refs JSON: {e}")))
}

/// Parse a JSON-encoded `{ "start": <rfc3339>, "end": <rfc3339> }`
/// object into a `DataPeriod`. The builder re-truncates both ends to
/// millisecond precision.
pub(crate) fn parse_data_period(s: &str) -> PyResult<DataPeriod> {
    serde_json::from_str(s)
        .map_err(|e| PyValueError::new_err(format!("invalid data_period JSON: {e}")))
}

/// Parse an RFC 3339 timestamp string into `DateTime<Utc>` for
/// `expires_at`. The builder re-truncates to millisecond precision.
pub(crate) fn parse_timestamp(s: &str) -> PyResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| PyValueError::new_err(format!("invalid RFC 3339 timestamp '{s}': {e}")))
}

/// Validate and wrap a `lin:sha256:<64-hex>` lineage-id string.
pub(crate) fn parse_lineage_id(s: &str) -> PyResult<LineageId> {
    LineageId::parse(s).map_err(|e| PyValueError::new_err(format!("invalid lineage_id: {e}")))
}
