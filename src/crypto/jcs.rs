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
    // Integer `Number`s (i64 / u64) are already canonical — serde_json prints
    // the exact digits with no decimal point and no exponent, exactly what
    // RFC 8785 requires. Only floats need the ECMAScript reformatting below.
    if n.is_i64() || n.is_u64() {
        out.extend_from_slice(n.to_string().as_bytes());
        return;
    }

    // Float path. `as_f64` is `Some` for any non-integer `Number`; the `None`
    // arm is unreachable but kept total rather than panicking.
    let Some(f) = n.as_f64() else {
        out.extend_from_slice(n.to_string().as_bytes());
        return;
    };

    // RFC 8785 §3.2.2.3: both negative and positive zero serialize as "0".
    if f == 0.0 {
        out.push(b'0');
        return;
    }

    // JSON cannot represent NaN or Infinity. `serde_json::Number::from_f64`
    // rejects these and this crate does not enable `arbitrary_precision`, so a
    // non-finite `Number` cannot be built through the safe API — unreachable on
    // parsed input. Refuse it loudly in debug/test builds; the `null` fallback
    // is a release-only last resort so canonicalization stays total (emitting
    // `null` would corrupt the hash preimage). Producers with custom numeric
    // paths MUST reject non-finite floats *before* canonicalization.
    debug_assert!(
        f.is_finite(),
        "non-finite f64 reached JCS canonicalization ({f}); reject \
         non-finite numbers before hashing (RFC 8785 §3.2.2.3)"
    );
    if !f.is_finite() {
        out.extend_from_slice(b"null");
        return;
    }

    out.extend_from_slice(ecma_number_string(f).as_bytes());
}

/// Serialize a finite, non-zero `f64` per the ECMAScript `Number::toString`
/// algorithm that RFC 8785 §3.2.2.3 references: the shortest decimal that
/// round-trips, rendered with the ES6 band rules — plain decimal for
/// magnitudes in `[1e-6, 1e21)`, otherwise exponential with a signed,
/// zero-padding-free exponent; the mantissa never carries a trailing `.0`.
///
/// Rust's `{:e}` formatter already produces the shortest round-tripping
/// mantissa (via the stdlib's Grisu/Ryū path) as `d.ddde±EE`; we extract its
/// digits and decimal exponent and reformat into the band ECMAScript chooses.
fn ecma_number_string(f: f64) -> String {
    let neg = f.is_sign_negative();
    // e.g. "1.23e25", "5e-324", "1e21", "1.0000005e6".
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').expect("{:e} always emits 'e'");
    let e10: i32 = exp.parse().expect("{:e} exponent is an integer");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let k = digits.len() as i32; // count of significant digits
    let n = e10 + 1; // value = digits × 10^(n − k)

    let body = if (k..=21).contains(&n) {
        // Integer-valued: all digits then (n − k) trailing zeros.
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if (1..=21).contains(&n) {
        // Decimal point falls inside the digit run (here n < k).
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if (-5..=0).contains(&n) {
        // Leading "0." then (−n) zeros then the digits.
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else if k == 1 {
        // Single-digit mantissa, exponential form.
        format!("{digits}e{}{}", exp_sign(n - 1), (n - 1).abs())
    } else {
        // Multi-digit mantissa, exponential form.
        format!(
            "{}.{}e{}{}",
            &digits[..1],
            &digits[1..],
            exp_sign(n - 1),
            (n - 1).abs()
        )
    };

    if neg {
        format!("-{body}")
    } else {
        body
    }
}

/// `'+'` for a non-negative ECMAScript exponent, `'-'` otherwise. RFC 8785
/// requires the exponent sign to always be present (`1e+21`, `1e-7`).
fn exp_sign(e: i32) -> char {
    if e >= 0 {
        '+'
    } else {
        '-'
    }
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

    // ── RFC 8785 numeric serialization vectors (Appendix B subset) ──────
    //
    // RFC 8785 §3.2.2.3 / Appendix B pin the serialization of JSON
    // numbers. ACDP wire bodies only ever carry *integers* (version
    // numbers, counts) and the occasional plain decimal — never the
    // exponential / integer-valued-float forms (e.g. `1e21`, `1.0`) whose
    // ECMAScript `Number::toString` output diverges from serde_json's
    // shortest-float Display. We therefore pin the cases that actually
    // occur on the wire and that this canonicalizer guarantees, plus the
    // negative-zero rule that is the most common JCS bug. Full ECMAScript
    // `Number::toString` formatting (exponential bands, shortest
    // round-trip) is implemented in `write_number` and is covered by
    // `rfc8785_ecmascript_float_bands` below.

    /// Helper: canonicalize a single JSON number token (parsed from
    /// text, so integers stay integers) and return the emitted string.
    fn canon_number(json_token: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(json_token).unwrap();
        String::from_utf8(canonicalize_value(&v)).unwrap()
    }

    #[test]
    fn rfc8785_integer_vectors() {
        // Integers serialize with no decimal point, no leading zeros,
        // no plus sign — exactly their canonical decimal form.
        for (input, expected) in [
            ("0", "0"),
            ("-0", "0"), // negative-zero *integer* normalizes to "0"
            ("1", "1"),
            ("-1", "-1"),
            ("100", "100"),
            ("9007199254740992", "9007199254740992"), // 2^53
            ("9007199254740993", "9007199254740993"), // 2^53 + 1 (exact as i64)
            ("18446744073709551615", "18446744073709551615"), // u64::MAX
            ("-9223372036854775808", "-9223372036854775808"), // i64::MIN
        ] {
            assert_eq!(canon_number(input), expected, "input={input}");
        }
    }

    #[test]
    fn rfc8785_negative_zero_float_becomes_zero() {
        // RFC 8785 §3.2.2.3: -0.0 MUST serialize as "0".
        assert_eq!(canon_number("-0.0"), "0");
        // And nested inside a structure (the realistic case). The other
        // entries are integers to avoid the integer-valued-float case
        // (`0.0` → "0.0") that is out of scope per the note above.
        let v = json!({"a": [-0.0_f64, 1], "b": -0.0_f64});
        let s = String::from_utf8(canonicalize_value(&v)).unwrap();
        assert_eq!(s, r#"{"a":[0,1],"b":0}"#);
    }

    #[test]
    fn rfc8785_plain_decimal_vectors() {
        // Plain decimals whose shortest representation is unambiguous and
        // identical under ES6 and serde_json's Display.
        for (input, expected) in [
            ("0.1", "0.1"),
            ("1.5", "1.5"),
            ("-2.5", "-2.5"),
            ("123.456", "123.456"),
        ] {
            assert_eq!(canon_number(input), expected, "input={input}");
        }
    }

    #[test]
    fn rfc8785_numeric_serialization_is_idempotent() {
        // Re-canonicalizing the emitted form reproduces it byte-for-byte
        // (no drift across a parse → serialize round trip).
        for token in ["0", "-0", "42", "9007199254740993", "0.1", "-2.5", "-0.0"] {
            let once = canon_number(token);
            let twice = canon_number(&once);
            assert_eq!(once, twice, "token={token}");
        }
    }

    /// RFC 8785 §3.2.2.3 float serialization — the `can-011` numeric
    /// bands, now that ECMAScript `Number::toString` is implemented in
    /// `write_number`. These canonical tokens are fixed by the algorithm,
    /// so they hold regardless of the spec fixture's own SHA-256 values.
    #[test]
    fn rfc8785_ecmascript_float_bands() {
        for (token, expected) in [
            // Large-magnitude exponential (≥ 1e21).
            ("1e21", "1e+21"),
            ("1e22", "1e+22"),
            ("1.23e25", "1.23e+25"),
            ("1e100", "1e+100"),
            // Small-magnitude exponential (< 1e-6).
            ("1e-7", "1e-7"),
            ("1e-10", "1e-10"),
            ("5e-9", "5e-9"),
            ("1e-20", "1e-20"),
            // Decimal band [1e-6, 1e21).
            ("1e-6", "0.000001"),
            ("0.1", "0.1"),
            ("1000000.5", "1000000.5"),
            ("12345.6789", "12345.6789"),
            // Integer-valued floats normalize like integers (no trailing .0).
            ("1.0", "1"),
            ("100.0", "100"),
            // IEEE 754 magnitude extremes.
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            ("5e-324", "5e-324"),
        ] {
            assert_eq!(canon_number(token), expected, "token={token}");
        }
    }

    /// Positive and negative zero — including the float and exponential
    /// spellings — all canonicalize to "0" (RFC 8785 §3.2.2.3).
    #[test]
    fn rfc8785_all_zeros_normalize() {
        for token in ["0", "-0", "0.0", "-0.0", "0e0", "-0.0e10"] {
            assert_eq!(canon_number(token), "0", "token={token}");
        }
    }
}
