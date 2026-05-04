//! Conformance tests against the canonical ACDP spec fixtures and examples.
//!
//! Locates the spec repo via the `ACDP_SPEC_DIR` environment variable, with
//! a fallback to the sibling path `../agentcontextdescriptionprotocol` (the
//! layout used in this monorepo). If neither path resolves, the tests
//! gracefully skip with a notice — they don't fail the suite when the spec
//! isn't co-located, so this crate remains buildable in isolation.

use std::path::{Path, PathBuf};

use acdp::types::{
    body::Body,
    capabilities::CapabilitiesDocument,
    publish::{PublishRequest, WireError},
    search::SearchResponse,
};

fn spec_root() -> Option<PathBuf> {
    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sibling = manifest_dir
        .parent()?
        .join("agentcontextdescriptionprotocol");
    if sibling.exists() {
        return Some(sibling);
    }
    None
}

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

#[test]
fn all_conformance_fixtures_parse_as_valid_json() {
    let Some(root) = spec_root() else {
        eprintln!("ACDP spec not found; skipping conformance fixtures test");
        return;
    };
    let dir = root.join("schemas/conformance");
    let mut count = 0usize;
    for entry in std::fs::read_dir(&dir).expect("conformance dir readable") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let v = read_json(&path);
        // Every fixture has at minimum `id` + `description`.
        assert!(
            v.get("id").is_some(),
            "fixture {} missing 'id'",
            path.display()
        );
        assert!(
            v.get("description").is_some(),
            "fixture {} missing 'description'",
            path.display()
        );
        count += 1;
    }
    assert!(count >= 16, "expected ≥16 fixtures, found {count}");
}

#[test]
fn capabilities_example_deserializes() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/capabilities/acdp-capabilities.json");
    if !path.exists() {
        return;
    }
    let v = read_json(&path);
    let _: CapabilitiesDocument = serde_json::from_value(v)
        .expect("capabilities example must deserialize into CapabilitiesDocument");
}

#[test]
fn publish_request_examples_deserialize() {
    let Some(root) = spec_root() else {
        return;
    };
    let dir = root.join("examples/publish");
    if !dir.exists() {
        return;
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let v = read_json(&path);
        let _: PublishRequest = serde_json::from_value(v.clone()).unwrap_or_else(|e| {
            panic!(
                "{} did not deserialize as PublishRequest: {e}",
                path.display()
            )
        });
    }
}

#[test]
fn retrieval_examples_deserialize_as_body() {
    let Some(root) = spec_root() else {
        return;
    };
    let dir = root.join("examples/retrieval");
    if !dir.exists() {
        return;
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let v = read_json(&path);
        // Some examples are full ACDP "context" envelopes (body+registry_state)
        // others are just bodies. Try both.
        if v.get("body").is_some() {
            let _: acdp::types::body::FullContext = serde_json::from_value(v)
                .unwrap_or_else(|e| panic!("{}: not FullContext: {e}", path.display()));
        } else {
            let _: Body = serde_json::from_value(v)
                .unwrap_or_else(|e| panic!("{}: not Body: {e}", path.display()));
        }
    }
}

#[test]
fn visibility_example_bodies_deserialize() {
    let Some(root) = spec_root() else {
        return;
    };
    let dir = root.join("examples/visibility");
    if !dir.exists() {
        return;
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let v = read_json(&path);
        // Visibility examples wrap a Body under `body`.
        let body_value = v.get("body").cloned().unwrap_or(v);
        let _: Body = serde_json::from_value(body_value)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
}

#[test]
fn search_response_example_deserializes() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/search/keyword-search-response.json");
    if !path.exists() {
        return;
    }
    let v = read_json(&path);
    let _: SearchResponse =
        serde_json::from_value(v).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

#[test]
fn error_example_deserializes() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/error/invalid-signature.json");
    if !path.exists() {
        return;
    }
    let v = read_json(&path);
    let _: WireError =
        serde_json::from_value(v).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

#[test]
fn lineage_multi_step_example_parses_each_body() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/lineage/multi-step-derivation.json");
    if !path.exists() {
        return;
    }
    let v = read_json(&path);
    // Multi-step examples are typically arrays of contexts. Be generous: try
    // array-of-bodies, then array-of-FullContext, then a wrapping object.
    if let Some(arr) = v.as_array() {
        for (i, item) in arr.iter().enumerate() {
            if item.get("body").is_some() {
                let _: acdp::types::body::FullContext = serde_json::from_value(item.clone())
                    .unwrap_or_else(|e| panic!("element {i}: not FullContext: {e}"));
            } else {
                let _: Body = serde_json::from_value(item.clone())
                    .unwrap_or_else(|e| panic!("element {i}: not Body: {e}"));
            }
        }
    }
}

#[test]
fn supersession_example_v2_deserializes() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/supersession/v2-supersedes-v1.json");
    if !path.exists() {
        return;
    }
    let v = read_json(&path);
    // The example may be a publish request or a body or a wrapping object.
    if v.get("body").is_some() {
        let _: acdp::types::body::FullContext = serde_json::from_value(v).unwrap();
    } else if v.get("ctx_id").is_some() && v.get("origin_registry").is_some() {
        let _: Body = serde_json::from_value(v).unwrap();
    } else if v.get("content_hash").is_some() && v.get("signature").is_some() {
        let _: PublishRequest = serde_json::from_value(v).unwrap();
    }
}

#[test]
fn mixed_data_refs_example_deserializes() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/mixed-data-refs/alert-mixed-data-refs.json");
    if !path.exists() {
        return;
    }
    let v = read_json(&path);
    if v.get("body").is_some() {
        let _: acdp::types::body::FullContext = serde_json::from_value(v).unwrap();
    } else if v.get("ctx_id").is_some() && v.get("origin_registry").is_some() {
        let _: Body = serde_json::from_value(v).unwrap();
    } else {
        let _: PublishRequest = serde_json::from_value(v).unwrap();
    }
}

/// Replays `sig-001-ed25519-golden.json` end-to-end through the producer
/// builder + verifier, asserting every emitted value matches the spec.
#[test]
fn sig_001_full_round_trip_against_spec_fixture() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("schemas/conformance/sig-001-ed25519-golden.json");
    if !path.exists() {
        return;
    }
    let v = read_json(&path);
    let vec = v["vectors"][0].clone();
    let pc = &vec["producer_content"];
    let expected_canonical = vec["expected"]["canonical_form"].as_str().unwrap();
    let expected_hash = vec["expected"]["content_hash"].as_str().unwrap();
    let expected_sig = vec["expected"]["signature_value_base64"].as_str().unwrap();

    // 1. Canonical form
    let canonical = acdp::crypto::canonicalize_value(pc);
    assert_eq!(std::str::from_utf8(&canonical).unwrap(), expected_canonical);

    // 2. Content hash
    let h = acdp::crypto::compute_content_hash(pc).unwrap();
    assert_eq!(h.as_str(), expected_hash);

    // 3. Signature with the test seed
    let seed_hex = v["test_keypair"]["private_seed_hex"].as_str().unwrap();
    let seed_bytes: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
    let key = acdp::crypto::SigningKey::from_bytes(&seed_bytes);
    assert_eq!(key.sign_content_hash(&h), expected_sig);
}
