//! Property-based tests for JCS canonicalization.
//!
//! Properties checked:
//! 1. Determinism: same Value → same bytes.
//! 2. Key-order independence: shuffling object keys yields the same output.
//! 3. No whitespace ever appears.
//! 4. Non-ASCII characters are emitted as UTF-8, not `\uXXXX`-escaped.
//! 5. content_hash is invariant under exclusion-set additions.

use acdp::crypto::{canonicalize_value, compute_content_hash};
use proptest::prelude::*;
use serde_json::{Map, Value};

// ── Strategies ───────────────────────────────────────────────────────────────

/// Bounded JSON value strategy (depth ≤ 4, breadth ≤ 6).
fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(n.into())),
        // ASCII strings only — UTF-8 round-trips trivially through serde
        "[ -~]{0,16}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::hash_map("[a-z]{1,6}", inner, 0..6).prop_map(|m| {
                let mut map = Map::new();
                for (k, v) in m {
                    map.insert(k, v);
                }
                Value::Object(map)
            }),
        ]
    })
}

// ── Properties ───────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Canonicalization is deterministic.
    #[test]
    fn jcs_is_deterministic(v in json_value()) {
        let a = canonicalize_value(&v);
        let b = canonicalize_value(&v);
        prop_assert_eq!(a, b);
    }

    /// Output is always valid JSON parseable by serde.
    #[test]
    fn jcs_round_trips_through_serde(v in json_value()) {
        let bytes = canonicalize_value(&v);
        let parsed: Value = serde_json::from_slice(&bytes)
            .expect("canonical output must be valid JSON");
        // Re-canonicalizing the round-tripped value must produce the same bytes
        let bytes2 = canonicalize_value(&parsed);
        prop_assert_eq!(bytes, bytes2);
    }

    /// Output never contains a literal space, tab, CR, or LF.
    #[test]
    fn jcs_has_no_whitespace(v in json_value()) {
        let bytes = canonicalize_value(&v);
        let in_string = std::cell::Cell::new(false);
        let mut prev_escape = false;
        for &b in &bytes {
            // Naive walker: track whether we're inside a JSON string. Whitespace
            // INSIDE a string literal is fine; outside, none is allowed.
            if !prev_escape && b == b'"' {
                in_string.set(!in_string.get());
                prev_escape = false;
                continue;
            }
            prev_escape = !prev_escape && b == b'\\';
            if !in_string.get() {
                prop_assert!(
                    b != b' ' && b != b'\t' && b != b'\n' && b != b'\r',
                    "whitespace outside string at byte {b:#x} in {bytes:?}"
                );
            }
        }
    }
}

// ── Concrete invariants (no proptest needed) ─────────────────────────────────

#[test]
fn key_order_independence() {
    use serde_json::json;
    let a = json!({"a": 1, "b": 2, "c": 3});
    let b = json!({"c": 3, "b": 2, "a": 1});
    let c = json!({"b": 2, "a": 1, "c": 3});
    let canon_a = canonicalize_value(&a);
    assert_eq!(canon_a, canonicalize_value(&b));
    assert_eq!(canon_a, canonicalize_value(&c));
}

#[test]
fn exclusion_set_invariant_under_proptest_inputs() {
    // Adding any of the §5.7 excluded fields to a body must not change content_hash.
    // Hand-rolled exhaustively here; proptest version is in tests/golden_vector.rs.
    use serde_json::json;
    let base = json!({
        "version": 1, "supersedes": null,
        "agent_id": "did:web:x", "contributors": [],
        "title": "T", "type": "data_snapshot",
        "data_refs": [], "derived_from": [], "visibility": "public"
    });
    let h_base = compute_content_hash(&base).unwrap();

    for extra_key in [
        "ctx_id",
        "lineage_id",
        "origin_registry",
        "created_at",
        "content_hash",
        "signature",
    ] {
        let mut m = base.as_object().unwrap().clone();
        m.insert(extra_key.into(), json!("anything"));
        let h = compute_content_hash(&serde_json::Value::Object(m)).unwrap();
        assert_eq!(h, h_base, "extra key {extra_key} affected hash");
    }
}

#[test]
fn non_ascii_emitted_as_utf8() {
    use serde_json::json;
    let v = json!({"title": "café — 北京"});
    let bytes = canonicalize_value(&v);
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(s.contains("café"));
    assert!(s.contains("北京"));
    assert!(!s.contains("\\u"));
}
