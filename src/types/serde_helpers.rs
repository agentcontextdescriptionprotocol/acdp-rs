//! Crate-local serde helpers for the ACDP wire types.
//!
//! ## Absent-vs-null convention
//!
//! `acdp-search-response.schema.json` (and the rest of the v0.1.0 schemas
//! except `supersedes`) type their optional fields as the bare value
//! type (e.g. `"type": "string"`), **not** as `["string","null"]`. The
//! absent-vs-null rule (RFC-ACDP-0005 §2.2.1; conformance fixtures
//! `schema-005`/`schema-006`/`schema-007`) requires:
//!
//! - **Absent key** → `None`.
//! - **Present key with a real value** → `Some(value)`.
//! - **Present key with `null`** → schema_violation: a strict consumer
//!   MUST reject rather than coerce `null` → absent.
//!
//! [`de_present`] implements this: it is wired to a field via
//! `#[serde(default, deserialize_with = "de_present", skip_serializing_if = "Option::is_none")]`.
//! `default` handles the absent case (yielding `None`); `de_present` is
//! invoked only when the key is present, and it deserializes via the
//! field's native `T::deserialize` so a JSON `null` is rejected with the
//! standard "invalid type: null, expected …" message.
//!
//! `supersedes` is the one v0.1.0 field whose schema declares
//! `type: ["string","null"]` (RFC-ACDP-0002 §3.1) — it is legitimately
//! nullable and MUST NOT use [`de_present`].

use serde::Deserialize;

/// Reject an explicit JSON `null` on a present optional field.
///
/// Pair with `#[serde(default, deserialize_with = "de_present",
/// skip_serializing_if = "Option::is_none")]` on any `Option<T>` whose
/// schema types it as the bare value (not `[T, "null"]`).
pub(crate) fn de_present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

/// Reject an explicit JSON `null` — and any other non-object value — on a
/// present optional field whose schema types it as `"type": "object"`.
///
/// [`de_present`] alone cannot do this when the field is
/// `Option<serde_json::Value>`: `Value::deserialize` happily accepts
/// `null` (→ `Value::Null`) and every other JSON type. This helper
/// deserializes the value and then enforces the object constraint, so a
/// strict consumer rejects `"details": null` (and `"details": "x"`,
/// arrays, numbers, …).
///
/// Used for `WireErrorBody.details` (`acdp-error.schema.json`, where
/// `details` is optional but `"type": "object"` when present).
pub(crate) fn de_present_object<'de, D>(d: D) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(d)?;
    if !v.is_object() {
        let kind = match &v {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => unreachable!("is_object() was false"),
        };
        return Err(serde::de::Error::custom(format!(
            "field present but {kind}; the ACDP schema types it as a \
             non-nullable JSON object"
        )));
    }
    Ok(Some(v))
}
