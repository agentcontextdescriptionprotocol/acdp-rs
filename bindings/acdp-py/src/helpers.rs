//! Small shared conversions used by both `producer.rs` and `verifier.rs`.

use acdp::types::{ContextType, Visibility};
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
