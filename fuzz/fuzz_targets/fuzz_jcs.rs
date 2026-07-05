//! Fuzz `acdp_jcs` (RFC 8785 JSON Canonicalization Scheme).
//!
//! Builds an arbitrary `serde_json::Value` with bounded depth (20, far
//! below the crate's internal 256-level recursion ceiling) and bounded
//! container sizes, then asserts:
//!
//! 1. `try_canonicalize_value` succeeds for depth-bounded input, and the
//!    infallible `canonicalize_value` wrapper never panics on it (the two
//!    must agree byte-for-byte).
//! 2. Canonicalization is idempotent: parsing the canonical bytes back
//!    into a `Value` and canonicalizing again yields identical bytes.
//!    (This relies on serde_json's `float_roundtrip` feature, matching
//!    the feature set the library crates enable.)

#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

/// Depth cap for generated values. Well under `MAX_JCS_DEPTH` (256), so
/// canonicalization must always succeed; deeper inputs are the documented
/// fallible domain of `try_canonicalize_value`, not a panic path.
const MAX_DEPTH: usize = 20;
/// Element/key cap per container, to keep individual inputs small.
const MAX_CONTAINER_LEN: usize = 8;

fn arb_value(u: &mut Unstructured<'_>, depth: usize) -> arbitrary::Result<serde_json::Value> {
    // 0..=5 are leaves; 6..=7 are containers, only allowed below MAX_DEPTH.
    let max_choice: u8 = if depth >= MAX_DEPTH { 5 } else { 7 };
    Ok(match u.int_in_range(0u8..=max_choice)? {
        0 => serde_json::Value::Null,
        1 => serde_json::Value::Bool(u.arbitrary()?),
        2 => serde_json::Value::from(u.arbitrary::<i64>()?),
        3 => serde_json::Value::from(u.arbitrary::<u64>()?),
        4 => {
            let f: f64 = u.arbitrary()?;
            // NaN / infinity are unrepresentable in JSON; `from_f64`
            // rejects them (the library's documented precondition is
            // that non-finite floats never reach canonicalization).
            match serde_json::Number::from_f64(f) {
                Some(n) => serde_json::Value::Number(n),
                None => serde_json::Value::Null,
            }
        }
        5 => serde_json::Value::String(u.arbitrary()?),
        6 => {
            let len = u.int_in_range(0usize..=MAX_CONTAINER_LEN)?;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(arb_value(u, depth + 1)?);
            }
            serde_json::Value::Array(arr)
        }
        _ => {
            let len = u.int_in_range(0usize..=MAX_CONTAINER_LEN)?;
            let mut map = serde_json::Map::new();
            for _ in 0..len {
                let key: String = u.arbitrary()?;
                map.insert(key, arb_value(u, depth + 1)?);
            }
            serde_json::Value::Object(map)
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(value) = arb_value(&mut u, 0) else {
        return;
    };

    // (1) Depth-bounded input must canonicalize, via both entry points.
    let canonical = acdp_jcs::try_canonicalize_value(&value)
        .expect("try_canonicalize_value failed on depth-bounded input");
    let canonical_infallible = acdp_jcs::canonicalize_value(&value);
    assert_eq!(
        canonical, canonical_infallible,
        "fallible and infallible canonicalization disagree"
    );

    // Canonical output is valid UTF-8 JSON.
    let reparsed: serde_json::Value =
        serde_json::from_slice(&canonical).expect("canonical bytes must parse as JSON");

    // (2) Idempotence: canonicalize(parse(canonicalize(v))) == canonicalize(v).
    let canonical_again = acdp_jcs::try_canonicalize_value(&reparsed)
        .expect("re-canonicalization of canonical form failed");
    assert_eq!(
        canonical, canonical_again,
        "JCS canonicalization is not idempotent"
    );
});
