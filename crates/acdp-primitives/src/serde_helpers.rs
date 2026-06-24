//! Shared serde helpers for the ACDP wire types.
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
pub fn de_present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
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
pub fn de_present_object<'de, D>(d: D) -> Result<Option<serde_json::Value>, D::Error>
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    // A field wired to `de_present` (rejects null) and one wired to
    // `de_present_object` (rejects null + any non-object).
    #[derive(Debug, Deserialize)]
    struct Holder {
        #[serde(default, deserialize_with = "de_present")]
        bare: Option<String>,
        #[serde(default, deserialize_with = "de_present_object")]
        obj: Option<serde_json::Value>,
    }

    #[test]
    fn de_present_absent_key_yields_none() {
        let h: Holder = serde_json::from_value(json!({})).unwrap();
        assert_eq!(h.bare, None);
        assert_eq!(h.obj, None);
    }

    #[test]
    fn de_present_accepts_real_value() {
        let h: Holder = serde_json::from_value(json!({"bare": "x"})).unwrap();
        assert_eq!(h.bare.as_deref(), Some("x"));
    }

    #[test]
    fn de_present_rejects_explicit_null() {
        let err = serde_json::from_value::<Holder>(json!({"bare": null})).unwrap_err();
        assert!(
            err.to_string().contains("null"),
            "expected an 'invalid type: null' message, got: {err}"
        );
    }

    #[test]
    fn de_present_object_accepts_object() {
        let h: Holder = serde_json::from_value(json!({"obj": {"k": 1}})).unwrap();
        assert_eq!(h.obj, Some(json!({"k": 1})));
    }

    #[test]
    fn de_present_object_rejects_null_and_non_objects() {
        // Each non-object JSON type names itself in the error message.
        for (val, kind) in [
            (json!(null), "null"),
            (json!(true), "boolean"),
            (json!(7), "number"),
            (json!("s"), "string"),
            (json!([1, 2]), "array"),
        ] {
            let err = serde_json::from_value::<Holder>(json!({"obj": val})).unwrap_err();
            assert!(
                err.to_string().contains(kind),
                "obj={val} should be rejected naming {kind}, got: {err}"
            );
        }
    }
}
