//! JSON Canonicalization Scheme (JCS) — RFC 8785.
//!
//! Implemented inline to avoid an external dependency and to guarantee
//! correct handling of all edge cases, especially:
//!   - Object key sorting (lexicographic Unicode code-point order)
//!   - No whitespace
//!   - Negative zero (`-0.0`) MUST become `0`  (the most common bug)
//!   - Non-ASCII characters emitted as-is, not `\uXXXX`-escaped

use std::io::Write;

use crate::error::AcdpError;
use serde::Serialize;

/// Canonicalize any serializable value to JCS bytes.
///
/// The returned bytes are the canonical UTF-8 JSON representation.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, AcdpError> {
    let v = serde_json::to_value(value).map_err(|e| AcdpError::Canonicalization(e.to_string()))?;
    let mut out = Vec::with_capacity(256);
    write_value(&v, &mut out);
    Ok(out)
}

/// Canonicalize a pre-parsed `serde_json::Value`.
pub fn canonicalize_value(value: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    write_value(value, &mut out);
    out
}

fn write_value(v: &serde_json::Value, out: &mut Vec<u8>) {
    match v {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => out.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => out.extend_from_slice(b"false"),
        serde_json::Value::Number(n) => write_number(n, out),
        serde_json::Value::String(s) => write_string(s, out),
        serde_json::Value::Array(arr) => {
            out.push(b'[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(elem, out);
            }
            out.push(b']');
        }
        serde_json::Value::Object(map) => {
            // Collect and sort keys in Unicode code-point (lexicographic) order
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(&map[key.as_str()], out);
            }
            out.push(b'}');
        }
    }
}

fn write_number(n: &serde_json::Number, out: &mut Vec<u8>) {
    if let Some(f) = n.as_f64() {
        // RFC 8785 §3.2.2.3: negative zero MUST be serialized as "0"
        if f == 0.0 && f.is_sign_negative() {
            out.push(b'0');
            return;
        }
        // JSON cannot represent NaN or Infinity. In practice
        // `serde_json::Number::from_f64` rejects these (returns None),
        // so this branch is unreachable on input that was deserialized
        // from JSON. We keep a `null` fallback for defensive parity if
        // an unsafe-built Number ever reaches us — but emitting `null`
        // means the canonical bytes silently disagree with the in-memory
        // value. Producers writing custom numeric paths SHOULD detect
        // non-finite floats *before* canonicalization rather than rely
        // on this fallback.
        if f.is_nan() || f.is_infinite() {
            out.extend_from_slice(b"null");
            return;
        }
    }
    // For all other numbers, serde_json's display representation is
    // ES6-compatible for integers and common float values.
    out.extend_from_slice(n.to_string().as_bytes());
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                // Control characters below U+0020 must be escaped
                write!(out, "\\u{:04x}", c as u32).unwrap();
            }
            c => {
                // Non-ASCII characters emitted as-is (UTF-8 bytes, not \uXXXX)
                let mut buf = [0u8; 4];
                let encoded = c.encode_utf8(&mut buf);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    out.push(b'"');
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys() {
        let v = json!({"z": 1, "a": 2, "m": 3});
        let out = canonicalize_value(&v);
        assert_eq!(out, b"{\"a\":2,\"m\":3,\"z\":1}");
    }

    #[test]
    fn negative_zero_becomes_zero() {
        // The critical RFC 8785 edge case
        let v = json!({"values": [42, -7, 0, 1.1, 1.5, -0.0_f64]});
        let out = canonicalize_value(&v);
        let s = std::str::from_utf8(&out).unwrap();
        // -0.0 must become 0
        assert!(!s.contains("-0"), "found '-0' in: {s}");
    }

    #[test]
    fn unicode_as_is() {
        let v = json!({"title": "café"});
        let out = canonicalize_value(&v);
        assert_eq!(out, "{\"title\":\"café\"}".as_bytes());
    }

    #[test]
    fn empty_vs_absent() {
        let with_tags = json!({"tags": [], "v": 1});
        let without = json!({"v": 1});
        let h1 = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(canonicalize_value(&with_tags)))
        };
        let h2 = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(canonicalize_value(&without)))
        };
        assert_ne!(h1, h2, "empty array and absent field must hash differently");
    }

    #[test]
    fn minimal_body_golden_hash() {
        // Reproduces can-001 vector from schemas/conformance/can-001-jcs-vector.json
        let body = json!({
            "agent_id": "did:agent:test",
            "contributors": [],
            "data_refs": [],
            "supersedes": null,
            "title": "Minimal",
            "type": "data_snapshot",
            "version": 1
        });
        use sha2::{Digest, Sha256};
        let h = hex::encode(Sha256::digest(canonicalize_value(&body)));
        assert_eq!(
            h,
            "5f8d88d6758cfd43be875d49edc9eaa494de8ec645bf7de6c592b15bbb1e2e3c"
        );
    }
}
