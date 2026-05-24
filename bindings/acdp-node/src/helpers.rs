//! Shared parsers used by `producer.rs`. Kept narrow on purpose — the
//! conversions mirror what serde does at deserialize time so JS callers
//! get the same validation Rust callers do.

use acdp::types::{ContextType, Visibility};
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
