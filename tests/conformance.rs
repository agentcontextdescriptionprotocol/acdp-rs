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
    assert!(
        count >= 29,
        "expected ≥29 fixtures (post round-2 spec), found {count}"
    );
}

/// FEAT-03 — capabilities conformance fixtures (caps-001..006).
#[test]
fn capabilities_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("caps-") {
            continue;
        }
        let v = read_json(&path);
        let Some(body) = v.pointer("/input/response_body") else {
            continue;
        };
        let outcome = v["expected"]["outcome"].as_str().unwrap_or("");
        let parsed: Result<acdp::types::CapabilitiesDocument, _> =
            serde_json::from_value(body.clone());
        match (parsed, outcome) {
            (Ok(caps), "accept") => {
                acdp::validation::validate_capabilities(&caps)
                    .unwrap_or_else(|e| panic!("{name}: expected accept, validation failed: {e}"));
            }
            (Ok(caps), "reject") => {
                let err = acdp::validation::validate_capabilities(&caps).err();
                assert!(
                    err.is_some(),
                    "{name}: expected reject, validation accepted"
                );
            }
            (Err(e), "reject") => {
                // Schema-level rejection at deserialize time also satisfies "reject".
                let _ = e;
            }
            (Err(e), "accept") => {
                panic!("{name}: expected accept, deserialization failed: {e}");
            }
            (_, other) => panic!("{name}: unrecognized outcome '{other}'"),
        }
        checked += 1;
    }
    assert!(checked >= 4, "expected ≥4 caps-* fixtures, got {checked}");
}

/// FEAT-03 — status fixtures (status-001..004).
#[test]
fn status_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("status-") {
            continue;
        }
        let v = read_json(&path);
        // Try both shapes: `input.response_body.registry_state.status` and
        // `input.status_value` if present.
        let status_value = v
            .pointer("/input/response_body/registry_state/status")
            .and_then(|x| x.as_str())
            .or_else(|| v.pointer("/input/status_value").and_then(|x| x.as_str()))
            .or_else(|| {
                // status-002/003/004 embed the bad value directly in registry_state
                v.pointer("/input/response_body").and_then(|rb| {
                    rb.as_object()
                        .and_then(|m| m.get("registry_state"))
                        .and_then(|rs| rs.get("status"))
                        .and_then(|x| x.as_str())
                })
            });
        let Some(s) = status_value else {
            continue;
        };
        let outcome = v["expected"]["outcome"]
            .as_str()
            .or_else(|| v["expected"]["consumer_outcome"].as_str())
            .unwrap_or("");
        let parsed = acdp::types::Status::parse(s);
        match outcome {
            "accept" | "success" => assert!(parsed.is_ok(), "{name}: '{s}' should accept"),
            "reject" | "failure" => assert!(parsed.is_err(), "{name}: '{s}' should reject"),
            other => panic!("{name}: unrecognized outcome '{other}'"),
        }
        checked += 1;
    }
    assert!(checked >= 1, "expected ≥1 status-* fixture, got {checked}");
}

/// FEAT-03 — DataRef fixtures (data-ref-001..007).
#[test]
fn data_ref_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("data-ref-") {
            continue;
        }
        let v = read_json(&path);
        let Some(dr_value) = v.pointer("/input/data_ref_under_test") else {
            continue;
        };
        let outcome = v["expected"]["outcome"].as_str().unwrap_or("");
        // Try to deserialize into DataRef, then validate.
        match serde_json::from_value::<acdp::types::DataRef>(dr_value.clone()) {
            Ok(dr) => {
                let result = acdp::validation::validate_data_ref(&dr);
                match outcome {
                    "accept" | "success" => {
                        assert!(result.is_ok(), "{name}: expected accept, got {result:?}");
                    }
                    "failure" | "reject" => {
                        assert!(
                            result.is_err(),
                            "{name}: expected failure, validate accepted"
                        );
                    }
                    other => panic!("{name}: unrecognized outcome '{other}'"),
                }
            }
            Err(e) if matches!(outcome, "failure" | "reject") => {
                // Deserialize-time rejection is also acceptable for negative cases.
                let _ = e;
            }
            Err(e) => panic!("{name}: deserialize failed: {e}"),
        }
        checked += 1;
    }
    assert!(
        checked >= 5,
        "expected ≥5 data-ref-* fixtures, got {checked}"
    );
}

/// FEAT-03 — metadata fixtures (meta-001..003).
#[test]
fn metadata_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("meta-") {
            continue;
        }
        let v = read_json(&path);
        let Some(meta) = v.pointer("/input/metadata_under_test") else {
            continue;
        };
        let outcome = v["expected"]["outcome"].as_str().unwrap_or("");
        let result = acdp::validation::validate_metadata(meta);
        match outcome {
            "accept" | "success" => {
                assert!(result.is_ok(), "{name}: expected accept, got {result:?}")
            }
            "failure" | "reject" => {
                assert!(
                    result.is_err(),
                    "{name}: expected failure, validate accepted"
                )
            }
            other => panic!("{name}: unrecognized outcome '{other}'"),
        }
        checked += 1;
    }
    assert!(checked >= 2, "expected ≥2 meta-* fixtures, got {checked}");
}

/// FEAT-03 — closed-schema fixtures (schema-001..004).
#[test]
fn closed_schema_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("schema-") {
            continue;
        }
        let v = read_json(&path);
        let outcome = v["expected"]["outcome"].as_str().unwrap_or("");
        match name {
            "schema-001-search-response-extra-results.json" => {
                if let Some(body) = v.pointer("/input/response_body") {
                    let r: Result<SearchResponse, _> = serde_json::from_value(body.clone());
                    match outcome {
                        "reject" | "failure" => {
                            assert!(r.is_err(), "{name}: expected reject")
                        }
                        _ => {}
                    }
                }
            }
            "schema-002-publish-response-extra-content-hash.json" => {
                if let Some(body) = v.pointer("/input/response_body") {
                    let r: Result<acdp::types::PublishResponse, _> =
                        serde_json::from_value(body.clone());
                    match outcome {
                        "reject" | "failure" => {
                            assert!(r.is_err(), "{name}: expected reject")
                        }
                        _ => {}
                    }
                }
            }
            "schema-004-capabilities-extra-top-level-allowed.json" => {
                if let Some(body) = v.pointer("/input/response_body") {
                    let r: Result<acdp::types::CapabilitiesDocument, _> =
                        serde_json::from_value(body.clone());
                    if matches!(outcome, "accept" | "success") {
                        assert!(r.is_ok(), "{name}: expected accept");
                    }
                }
            }
            _ => {}
        }
    }
}

/// FEAT-03 — `did:web` enforcement fixtures (pub-008/009/010).
#[test]
fn did_web_enforcement_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    for fixture in &[
        "pub-008-non-did-web-agent-id.json",
        "pub-009-non-did-web-key-id.json",
        "pub-010-non-did-web-contributor.json",
    ] {
        let path = dir.join(fixture);
        if !path.exists() {
            continue;
        }
        let _v = read_json(&path);
        // The fixtures describe scenarios; the library-level guarantee is
        // that `validate_publish_request` rejects non-did:web agent_id /
        // key_id and accepts non-did:web contributors. Sanity-checked
        // here against a synthetic minimal case rather than the descriptive
        // fixture body.
    }

    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::types::{AgentDid, ContextType};

    // pub-008: did:key agent_id rejected
    let key = SigningKey::from_bytes(&[0u8; 32]);
    let p = Producer::new(
        key,
        AgentDid::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSshBHqcWv6Vt8mfWAFs"),
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSshBHqcWv6Vt8mfWAFs#key-1",
    );
    let err = p
        .publish_request()
        .title("t")
        .context_type(ContextType::DataSnapshot)
        .build()
        .unwrap_err();
    assert!(
        matches!(err, acdp::AcdpError::SchemaViolation(_)),
        "pub-008: did:key agent_id MUST be rejected"
    );

    // pub-010: did:key contributor accepted
    let p = Producer::new(
        SigningKey::from_bytes(&[0u8; 32]),
        AgentDid::new("did:web:agents.example.com:test"),
        "did:web:agents.example.com:test#key-1",
    );
    p.publish_request()
        .title("t")
        .context_type(ContextType::DataSnapshot)
        .contributors(vec![AgentDid::new(
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSshBHqcWv6Vt8mfWAFs",
        )])
        .build()
        .expect("pub-010: did:key contributor MUST be accepted");
}

/// BUG-09 — When a registry mistakenly returns `{"results": [...]}`
/// instead of `{"matches": [...]}`, the consumer MUST NOT silently
/// coerce. With `deny_unknown_fields` on `SearchResponse`, the
/// deserializer surfaces a serde error rather than empty matches.
#[test]
fn vis_003_consumer_rejects_results_key() {
    let raw = r#"{"results":[{"ctx_id":"acdp://r/x","lineage_id":"lin:sha256:a","agent_id":"did:web:r","title":"t","type":"data_snapshot","created_at":"2026-01-01T00:00:00.000Z","status":"active"}]}"#;
    let parsed: Result<SearchResponse, _> = serde_json::from_str(raw);
    assert!(
        parsed.is_err(),
        "consumer MUST reject `results` key per vis-003 (got Ok)"
    );
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

/// T9 — every `can-*` canonicalization vector that publishes an
/// `expected.canonical_form` and `expected.sha256_hex` (or
/// `expected.content_hash_field_value`) MUST hash-match exactly.
#[test]
fn can_vectors_match_expected_hash() {
    use sha2::{Digest, Sha256};

    let Some(root) = spec_root() else {
        return;
    };
    let dir = root.join("schemas/conformance");
    let mut checked = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("can-") {
            continue;
        }
        let v = read_json(&path);
        let Some(vectors) = v.get("vectors").and_then(|x| x.as_array()) else {
            continue;
        };
        for (i, vec) in vectors.iter().enumerate() {
            let Some(input) = vec.get("input") else {
                continue;
            };
            let Some(expected) = vec.get("expected") else {
                continue;
            };

            // Body canonicalization → SHA-256 hex.
            if let (Some(canonical), Some(hex_hash)) = (
                expected.get("canonical_form").and_then(|x| x.as_str()),
                expected.get("sha256_hex").and_then(|x| x.as_str()),
            ) {
                let bytes = acdp::crypto::canonicalize_value(input);
                let got_canonical = std::str::from_utf8(&bytes).unwrap();
                assert_eq!(
                    got_canonical, canonical,
                    "{name} vector {i}: canonical_form mismatch"
                );
                let digest = format!("{:x}", Sha256::digest(&bytes));
                assert_eq!(digest, hex_hash, "{name} vector {i}: sha256 mismatch");
                checked += 1;
            }

            // Lineage derivation: input.ctx_id → expected.lineage_id.
            if let (Some(ctx), Some(lineage)) = (
                input.get("ctx_id").and_then(|x| x.as_str()),
                expected.get("lineage_id").and_then(|x| x.as_str()),
            ) {
                let derived =
                    acdp::crypto::derive_lineage_id(&acdp::types::primitives::CtxId(ctx.into()));
                assert_eq!(
                    derived.as_str(),
                    lineage,
                    "{name} vector {i}: lineage_id mismatch"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 1,
        "expected at least one hashable can-* vector; checked {checked}"
    );
}

/// FEAT-04 — verify the sig-002 ECDSA-P256 golden vector with the test
/// public key. The library does not produce ecdsa-p256 signatures
/// (signing is ed25519-only); this confirms the verify path matches
/// the spec wire form (IEEE 1363 r‖s, 88 base64 chars).
#[test]
fn sig_002_ecdsa_p256_verify_against_spec_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/sig-002-ecdsa-p256-golden.json");
    if !path.exists() {
        return;
    }
    let v = read_json(&path);
    let kp = &v["test_keypair"];
    let sec1_hex = kp["public_key_uncompressed_sec1_hex"].as_str().unwrap();
    let pub_sec1 = hex::decode(sec1_hex).unwrap();
    let vec = &v["vectors"][0]["expected"];
    let sig_b64 = vec["signature_value_base64"].as_str().unwrap();
    let content_hash = vec["content_hash"].as_str().unwrap();
    acdp::crypto::verify::verify_ecdsa_p256(&pub_sec1, sig_b64, content_hash)
        .expect("sig-002 ecdsa-p256 verification must pass");
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
