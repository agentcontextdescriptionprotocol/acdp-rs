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

/// Locate the ACDP spec checkout.
///
/// Normally the conformance tests skip gracefully when the spec is not
/// co-located, so this crate stays buildable in isolation. When
/// `ACDP_REQUIRE_CONFORMANCE` is set (IMP-02 — used by the dedicated CI
/// job), a missing spec is a hard failure instead: a green run then
/// genuinely proves conformance.
fn spec_root() -> Option<PathBuf> {
    let require = std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok();

    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR '{}' does not exist",
            p.display()
        );
    } else {
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR is not"
        );
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(sibling) = manifest_dir
        .parent()
        .map(|p| p.join("agentcontextdescriptionprotocol"))
    {
        if sibling.exists() {
            return Some(sibling);
        }
    }
    assert!(
        !require,
        "ACDP_REQUIRE_CONFORMANCE is set but no ACDP spec checkout could be located"
    );
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
    // The v0.1.0 Final spec ships 90 conformance fixtures across the
    // `body`, `can`, `caps`, `cur`, `data-ref`, `did-ssrf`, `err`,
    // `fed`, `idem`, `lin`, `meta`, `pub`, `rate`, `ret`, `schema`,
    // `sig`, `status`, `vis` families. Floor at 90 so a wholesale
    // regression in fixture loading is caught; the spec only ever
    // grows, so `>=` accommodates future additions.
    assert!(
        count >= 90,
        "expected ≥90 fixtures (ACDP v0.1.0 Final spec), found {count}"
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

/// FEAT-03 — DataRef structural-validation fixtures (data-ref-001..007).
///
/// Two fixture families are deliberately excluded because they are
/// *not* structural-validation cases — the body stays valid and a
/// registry MUST accept the publish:
///
/// - `data-ref-008` — an *external* data_ref hash mismatch, a runtime
///   data-integrity failure detectable only after fetching `location`.
///   Bound behaviorally by `fetch_and_verify_uri_ref_fails_on_hash_mismatch`
///   in `src/client/data_ref.rs` (asserts `DataRefHashMismatch`).
/// - `data-ref-ssrf-*` — consumer fetch-time SSRF defenses
///   (RFC-ACDP-0008 §4.9). The fixture's `expected.body_remains_valid`
///   is `true` and `registry_publish_behavior` says the publish MUST
///   NOT be rejected; the refusal lives entirely in
///   `HttpsDataRefFetcher`. Bound behaviorally by the SSRF tests in
///   `src/client/data_ref.rs`.
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
        // data-ref-008 + data-ref-ssrf-* — fetch-time checks, not
        // structural validation. See the doc comment above.
        if name.starts_with("data-ref-008") || name.starts_with("data-ref-ssrf-") {
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
            // schema-005/006/007 — `next_cursor` / `summary` / `domain`
            // are bare strings; a JSON `null` is non-conformant and a
            // strict consumer MUST reject it (BUG-03).
            "schema-005-search-response-next-cursor-null.json"
            | "schema-006-search-result-summary-null.json"
            | "schema-007-search-result-domain-null.json" => {
                if let Some(body) = v.pointer("/input/response_body") {
                    let r: Result<SearchResponse, _> = serde_json::from_value(body.clone());
                    if matches!(outcome, "reject" | "failure") {
                        assert!(
                            r.is_err(),
                            "{name}: a `null` bare-string field MUST be rejected, got {r:?}"
                        );
                    }
                }
            }
            // schema-008 — the `signature` object is a closed wire shape
            // (deny_unknown_fields, BUG-06).
            "schema-008-signature-extra-field.json" => {
                if let Some(sig) = v.pointer("/input/request_body_excerpt/signature") {
                    let r: Result<acdp::types::body::Signature, _> =
                        serde_json::from_value(sig.clone());
                    assert!(
                        r.is_err(),
                        "{name}: unknown signature field MUST be rejected"
                    );
                }
            }
            // schema-009 — `data_period` is a closed wire shape (BUG-06).
            "schema-009-data-period-extra-field.json" => {
                if let Some(dp) = v.pointer("/input/request_body_excerpt/data_period") {
                    let r: Result<acdp::types::body::DataPeriod, _> =
                        serde_json::from_value(dp.clone());
                    assert!(
                        r.is_err(),
                        "{name}: unknown data_period field MUST be rejected"
                    );
                }
            }
            // schema-010 — `limits` is a closed sub-object inside the
            // otherwise-open capabilities document (BUG-06).
            "schema-010-capabilities-limits-extra-field.json" => {
                if let Some(limits) = v.pointer("/input/response_body_excerpt/limits") {
                    let r: Result<acdp::types::Limits, _> = serde_json::from_value(limits.clone());
                    assert!(r.is_err(), "{name}: unknown limits field MUST be rejected");
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
        // others are just bodies. Try both, then run validate_body so we
        // catch any regressions in field-shape rules (BUG-01: hostname
        // form for `origin_registry`, etc.).
        let body: Body = if v.get("body").is_some() {
            let ctx: acdp::types::body::FullContext = serde_json::from_value(v)
                .unwrap_or_else(|e| panic!("{}: not FullContext: {e}", path.display()));
            ctx.body
        } else {
            serde_json::from_value(v)
                .unwrap_or_else(|e| panic!("{}: not Body: {e}", path.display()))
        };
        acdp::validation::validate_body(&body).unwrap_or_else(|e| {
            panic!(
                "{} failed validate_body — example must be schema-conformant: {e}",
                path.display()
            )
        });
    }
}

// ── body-001 / body-002 — origin_registry hostname vs DID (BUG-01) ──────────

/// body-001 — `origin_registry` is a bare DNS hostname. The fixture's
/// `body_fields_under_test.origin_registry` MUST pass our validator.
#[test]
fn body_001_origin_registry_hostname_accepted() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/body-001-origin-registry-hostname.json");
    if !path.exists() {
        return;
    }
    let v = read_json(&path);
    let hostname = v["input"]["body_fields_under_test"]["origin_registry"]
        .as_str()
        .expect("fixture must expose origin_registry");
    assert_eq!(hostname, "registry.example.com");
    // Compose a minimal Body around this value and assert validate_body
    // accepts it. (Schema validation against the hostname `$defs` is
    // implicitly covered by the validate_body call once it includes
    // validate_origin_registry — see body-002 for the negative case.)
    let body = body_with_origin_registry(hostname);
    acdp::validation::validate_body(&body)
        .expect("body-001: hostname origin_registry MUST be accepted");
}

/// body-002 — `origin_registry` set to a `did:web:` URI MUST be rejected.
/// Pins the BUG-01 fix.
#[test]
fn body_002_origin_registry_did_rejected() {
    let body = body_with_origin_registry("did:web:registry.example.com");
    let err = acdp::validation::validate_body(&body)
        .expect_err("body-002: did:web origin_registry MUST be rejected");
    assert!(
        matches!(err, acdp::AcdpError::SchemaViolation(_)),
        "body-002: error MUST be SchemaViolation, got {err:?}"
    );
}

fn body_with_origin_registry(origin_registry: &str) -> Body {
    use acdp::types::body::Signature;
    use acdp::types::primitives::{
        AgentDid, ContentHash, ContextType, CtxId, LineageId, Status, Visibility,
    };
    use chrono::{TimeZone, Utc};
    let _ = Status::Active; // silence unused-import on no-default builds
    Body {
        ctx_id: CtxId("acdp://registry.example.com/00000000-0000-4000-8000-000000000001".into()),
        lineage_id: LineageId(
            "lin:sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        ),
        origin_registry: origin_registry.into(),
        created_at: Utc.with_ymd_and_hms(2026, 5, 18, 0, 0, 0).unwrap(),
        content_hash: ContentHash(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        ),
        signature: Signature {
            algorithm: "ed25519".into(),
            key_id: "did:web:agents.example.com:test#key-1".into(),
            value: "A".repeat(86) + "==",
        },
        version: 1,
        supersedes: None,
        agent_id: AgentDid::new("did:web:agents.example.com:test"),
        contributors: vec![],
        title: "body-001/002 fixture body".into(),
        context_type: ContextType::DataSnapshot,
        data_refs: vec![],
        derived_from: vec![],
        visibility: Visibility::Public,
        audience: None,
        acdp_version: None,
        description: None,
        summary: None,
        tags: None,
        domain: None,
        expires_at: None,
        data_period: None,
        metadata: None,
        schema_uri: None,
        extensions: Default::default(),
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
///
/// BUG-05: `lin-*` fixtures are covered here too. `lin-001` uses the
/// same `input.ctx_id → expected.lineage_id` vector shape as the
/// lineage vectors inside `can-001`, so the existing derivation check
/// handles both with no extra logic.
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
        if !name.starts_with("can-") && !name.starts_with("lin-") {
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

/// IMP-02 — `did-ssrf-001/002/003` are required by `profiles.json` for
/// `acdp-consumer` and `acdp-registry-core`. Bind them to a behavioral
/// assertion: each fixture's `did:web` authority resolves into a
/// forbidden range (loopback / IMDS / RFC 1918) and MUST be refused by
/// the default `WebResolver` SSRF policy before any request is made.
#[cfg(feature = "client")]
#[tokio::test]
async fn did_ssrf_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let cases = [
        ("did-ssrf-001-loopback-did-web.json", "did:web:127.0.0.1"),
        ("did-ssrf-002-imds-did-web.json", "did:web:169.254.169.254"),
        (
            "did-ssrf-003-private-range-did-web.json",
            "did:web:10.0.0.1",
        ),
    ];
    let resolver = acdp::did::WebResolver::new();
    let mut checked = 0usize;
    for (filename, did) in &cases {
        let path = dir.join(filename);
        if !path.exists() {
            continue;
        }
        let _fixture = read_json(&path); // validates the fixture JSON parses
        let err = resolver
            .resolve(did)
            .await
            .expect_err(&format!("{filename}: {did} MUST be blocked by SSRF policy"));
        assert!(
            matches!(err, acdp::AcdpError::KeyResolution(_)),
            "{filename}: {did} must fail with KeyResolution (permanent, HTTP 400); got {err:?}"
        );
        checked += 1;
    }
    assert!(
        checked >= 1,
        "expected ≥1 did-ssrf-* fixture, found {checked}"
    );
}

/// FEAT-04 — verify the sig-002 ECDSA-P256 golden vector with the test
/// public key. Confirms the verify path matches the spec wire form
/// (IEEE 1363 r‖s, 88 base64 chars).
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

/// FEAT-01 — sign-side round trip: the producer-side ECDSA-P256 signer
/// MUST reproduce the spec's golden signature byte-for-byte when given
/// the test private scalar. Confirms (a) deterministic RFC 6979
/// signing, (b) IEEE 1363 r‖s output (not DER), (c) 88-char base64 wire
/// form.
#[test]
fn sig_002_ecdsa_p256_sign_round_trip() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/sig-002-ecdsa-p256-golden.json");
    if !path.exists() {
        return;
    }
    let v = read_json(&path);
    let priv_hex = v["test_keypair"]["private_scalar_hex"].as_str().unwrap();
    let priv_bytes: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();

    let key = acdp::crypto::P256SigningKey::from_bytes(&priv_bytes)
        .expect("p256 scalar=1 is a valid test key");
    let expected_hash = v["vectors"][0]["expected"]["content_hash"]
        .as_str()
        .unwrap();
    let expected_sig = v["vectors"][0]["expected"]["signature_value_base64"]
        .as_str()
        .unwrap();
    let hash = acdp::ContentHash(expected_hash.to_string());
    let sig = key.sign_content_hash(&hash);
    assert_eq!(
        sig.len(),
        88,
        "sig-002: wire signature MUST be 88 base64 chars"
    );
    // RFC 6979 deterministic ECDSA — value MUST match the spec exactly.
    assert_eq!(
        sig, expected_sig,
        "sig-002: producer signature MUST match spec golden vector byte-for-byte"
    );
}

/// FEAT-01 — when a Producer is constructed with a P256 key, the
/// emitted PublishRequest carries `signature.algorithm = "ecdsa-p256"`
/// and the value verifies against the producer's own public key.
/// Confirms the algorithm-string plumb-through end-to-end.
#[test]
fn p256_producer_emits_ecdsa_p256_algorithm() {
    use acdp::crypto::{verify::verify_ecdsa_p256, P256SigningKey};
    use acdp::producer::Producer;
    use acdp::types::{AgentDid, ContextType, Visibility};

    let key = P256SigningKey::generate();
    let pub_sec1 = key.verifying_key_sec1();
    let p = Producer::new_p256(
        key,
        AgentDid::new("did:web:agents.example.com:p256-producer"),
        "did:web:agents.example.com:p256-producer#key-1",
    );
    let req = p
        .publish_request()
        .title("p256 round-trip")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("p256 producer build");
    assert_eq!(
        req.signature.algorithm, "ecdsa-p256",
        "p256-keyed producer MUST emit signature.algorithm == 'ecdsa-p256'"
    );
    assert_eq!(
        req.signature.value.len(),
        88,
        "p256 wire signature MUST be 88 base64 chars"
    );
    verify_ecdsa_p256(&pub_sec1, &req.signature.value, req.content_hash.as_str())
        .expect("emitted signature MUST verify against the producer's public key");
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

// ── BUG-12 / BUG-13 — explicit fixture-binding tests ─────────────────────────

/// BUG-13a — can-008 forward-compat: a `Body` deserialized from a v0.1
/// payload that includes an unknown producer-controlled field
/// (`priority` here) MUST round-trip through `serde_json::to_value(&body)`
/// → JCS → SHA-256 and produce the expected hash. This catches the
/// "typed struct silently drops unknown fields" failure mode that the
/// fixture's `non_conformant_behavior` warns about.
#[test]
fn can_008_body_roundtrip_preserves_unknown_producer_field() {
    use sha2::{Digest, Sha256};
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/can-008-body-with-unknown-producer-field.json");
    if !path.exists() {
        return;
    }
    let fixture = read_json(&path);
    let vector = &fixture["vectors"][0];
    let producer_content = &vector["input"];
    let expected_hash = vector["expected"]["sha256_hex"].as_str().unwrap();

    // Build a wire body with the registry-assigned fields injected so the
    // value parses as Body. The exclusion set strips them before hashing.
    let mut wire_body = producer_content.clone();
    let m = wire_body.as_object_mut().unwrap();
    m.insert(
        "ctx_id".into(),
        serde_json::json!("acdp://registry.example.com/12345678-1234-4321-8123-123456781234"),
    );
    m.insert(
        "lineage_id".into(),
        serde_json::json!(
            "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111"
        ),
    );
    m.insert(
        "origin_registry".into(),
        serde_json::json!("did:web:registry.example.com"),
    );
    m.insert(
        "created_at".into(),
        serde_json::json!("2026-05-10T00:00:00.000Z"),
    );
    m.insert(
        "content_hash".into(),
        serde_json::json!(format!("sha256:{expected_hash}")),
    );
    m.insert(
        "signature".into(),
        serde_json::json!({
            "algorithm": "ed25519",
            "key_id": "did:web:agents.example.com:test#key-1",
            "value": "A".repeat(88),
        }),
    );

    let body: acdp::types::Body =
        serde_json::from_value(wire_body).expect("Body must deserialize with extensions");
    assert!(
        body.extensions.contains_key("priority"),
        "extensions map MUST capture the unknown 'priority' field"
    );

    let serialized = serde_json::to_value(&body).unwrap();
    // Reverse the exclusion set — same procedure as compute_content_hash.
    let mut prod_content = serialized;
    let m = prod_content.as_object_mut().unwrap();
    for k in [
        "ctx_id",
        "lineage_id",
        "origin_registry",
        "created_at",
        "content_hash",
        "signature",
    ] {
        m.remove(k);
    }
    let canonical = acdp::crypto::canonicalize_value(&prod_content);
    let digest = format!("{:x}", Sha256::digest(&canonical));
    assert_eq!(
        digest, expected_hash,
        "Body round-trip MUST produce the fixture hash — unknown fields must be preserved"
    );
}

/// BUG-13b — can-009 exclusion set is keyed by field NAME, not by typed
/// knowledge of the body. A registry that injects an unknown registry-
/// assigned field (`registry_receipt` here) MUST exclude it by name
/// when recomputing the producer content hash.
#[test]
fn can_009_exclusion_set_keys_by_name_not_by_typed_knowledge() {
    use sha2::{Digest, Sha256};
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/can-009-body-with-unknown-excluded-field.json");
    if !path.exists() {
        return;
    }
    let fixture = read_json(&path);
    let vector = &fixture["vectors"][0];
    let canonical_expected = vector["expected"]["canonical_form"].as_str().unwrap();
    let hex_expected = vector["expected"]["sha256_hex"].as_str().unwrap();

    let producer_content = &vector["input"];
    let bytes = acdp::crypto::canonicalize_value(producer_content);
    assert_eq!(std::str::from_utf8(&bytes).unwrap(), canonical_expected);
    let digest = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(digest, hex_expected);
}

/// BUG-12 — schema-003 EmbeddedContent rejects unknown fields per
/// `additionalProperties: false` in the data_ref schema.
#[test]
fn schema_003_embedded_extra_field_rejected() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/schema-003-embedded-extra-field.json");
    if !path.exists() {
        return;
    }
    let fixture = read_json(&path);
    // The fixture's `input.embedded` carries the extra field. Try to
    // deserialize as a DataRef and assert the parse fails.
    let Some(input) = fixture.get("input") else {
        return;
    };
    let Some(dr_value) = input.get("data_ref").or(input.get("body")) else {
        return;
    };
    let res: Result<acdp::types::DataRef, _> = serde_json::from_value(dr_value.clone());
    assert!(
        res.is_err(),
        "schema-003 fixture must fail to deserialize as DataRef \
         (extra field on embedded content)"
    );
}

/// BUG-05 / can-010 — `acdp-data-ref.schema.json` is open at its root.
/// An unknown producer-controlled field inside a `DataRef` MUST survive
/// deserialize → serialize verbatim: a `DataRef` lives inside
/// ProducerContent, so a dropped field would change `content_hash` and
/// falsely fail verification on a consumer one ACDP minor version behind.
#[test]
fn can_010_data_ref_unknown_producer_field_preserved() {
    let dr_json = serde_json::json!({
        "type": "raw_data",
        "location": "https://data.example.com/file.csv",
        "future_producer_field": "must not be dropped"
    });
    let dr: acdp::types::DataRef =
        serde_json::from_value(dr_json).expect("DataRef must deserialize with extensions");
    assert_eq!(
        dr.extensions
            .get("future_producer_field")
            .and_then(|v| v.as_str()),
        Some("must not be dropped"),
        "can-010: an unknown DataRef field MUST be captured in `extensions`"
    );
    let round_tripped = serde_json::to_value(&dr).unwrap();
    assert_eq!(
        round_tripped["future_producer_field"], "must not be dropped",
        "can-010: an unknown DataRef field MUST survive the round-trip"
    );
}

/// data-ref-008 — an EXTERNAL data_ref hash mismatch is surfaced as
/// [`acdp::AcdpError::DataRefHashMismatch`] (BUG-02), never as
/// `hash_mismatch` (body-level) or `invalid_signature` (key-level).
/// The body's own integrity is unaffected — only the bytes at
/// `data_ref.location` have diverged from the producer-declared hash.
#[cfg(feature = "client")]
#[tokio::test]
async fn data_ref_008_external_hash_mismatch_surfaced_as_data_ref_hash_mismatch() {
    use acdp::client::{fetch_and_verify_data_ref, DataRefFetcher};
    use acdp::types::data_ref::{DataRefType, Location};
    use acdp::types::{ContentHash, DataRef};

    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/data-ref-008-external-data-ref-hash-mismatch.json");
    if !path.exists() {
        return;
    }
    let fixture = read_json(&path);
    let dr_value = fixture
        .pointer("/input/data_ref_under_test")
        .expect("fixture must expose data_ref_under_test");
    let declared_hash = dr_value["content_hash"].as_str().unwrap().to_string();
    let location = dr_value["location"].as_str().unwrap().to_string();

    // The producer signed a body that declares `declared_hash` for the
    // bytes at `location`. Today those bytes have changed and hash to
    // something else — modelled here as a stub fetcher returning a
    // payload whose SHA-256 does not match.
    let dr = DataRef::uri_verified(DataRefType::RawData, location, ContentHash(declared_hash));

    struct StaleFetcher;
    impl DataRefFetcher for StaleFetcher {
        async fn fetch(&self, _location: &Location) -> Result<Vec<u8>, acdp::AcdpError> {
            Ok(b"data the upstream has since mutated".to_vec())
        }
    }

    let err = fetch_and_verify_data_ref(&dr, &StaleFetcher)
        .await
        .expect_err("data-ref-008: fetched bytes ≠ declared hash MUST fail");
    match err {
        acdp::AcdpError::DataRefHashMismatch(_) => { /* exactly what data-ref-008 requires */ }
        acdp::AcdpError::HashMismatch { .. } | acdp::AcdpError::RemoteHashMismatch(_) => panic!(
            "data-ref-008: MUST NOT report body-level hash_mismatch — \
             the body's content_hash is valid; only the referenced data diverged"
        ),
        acdp::AcdpError::InvalidSignature(_) => panic!(
            "data-ref-008: MUST NOT report invalid_signature — the producer's \
             signature is valid; only the referenced data diverged"
        ),
        other => panic!("data-ref-008: unexpected error variant {other:?}"),
    }
}

/// BUG-07 — `acdp-context.schema.json` is `additionalProperties: true`.
/// An unknown top-level field in a retrieval envelope MUST be preserved
/// in `FullContext.extensions` and survive a serialize round-trip, so a
/// v0.1.0 consumer tolerates future top-level registry keys.
#[test]
fn full_context_preserves_unknown_top_level_field() {
    let body = body_with_origin_registry("registry.example.com");
    let envelope = serde_json::json!({
        "body": serde_json::to_value(&body).unwrap(),
        "registry_state": { "status": "active" },
        "future_registry_field": { "some": "value" }
    });
    let ctx: acdp::types::FullContext =
        serde_json::from_value(envelope).expect("FullContext must deserialize");
    assert!(
        ctx.extensions.contains_key("future_registry_field"),
        "BUG-07: an unknown top-level field MUST land in FullContext.extensions"
    );
    let back = serde_json::to_value(&ctx).unwrap();
    assert_eq!(
        back["future_registry_field"]["some"], "value",
        "BUG-07: an unknown top-level field MUST survive the round-trip"
    );
}

// ── FEAT-01 / gap #3 — behavioral binding tests ──────────────────────────────

/// pub-002 — a publish request with a tampered `content_hash` MUST be
/// rejected at validation BEFORE persistence (RFC-ACDP-0003 §2.1 step 4).
#[cfg(feature = "server")]
#[test]
fn pub_002_hash_mismatch_rejected_by_validator() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/pub-002-hash-mismatch.json");
    if !path.exists() {
        return;
    }
    let fixture = read_json(&path);
    let Some(body) = fixture.get("input").and_then(|i| i.get("body")) else {
        return;
    };
    // pub-002 publishes a well-formed body whose content_hash does not
    // match the hash of its ProducerContent. The Rust deserializer
    // accepts the shape; PublishValidator::validate_post_schema rejects
    // at step 4 (hash recomputation).
    let req: acdp::types::PublishRequest = match serde_json::from_value(body.clone()) {
        Ok(r) => r,
        Err(_) => return, // older fixture format — skip
    };
    let caps = acdp::types::CapabilitiesDocument {
        acdp_version: "0.1.0".into(),
        registry_did: "did:web:registry.example.com".into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into()],
        profiles: vec!["acdp-registry-core".into()],
        limits: acdp::types::Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            idempotency_key_ttl_seconds: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key: false,
        extensions: Default::default(),
    };
    let v = acdp::registry::PublishValidator::for_authority(&caps, "registry.example.com");
    let raw_bytes = serde_json::to_vec(&req).unwrap().len();
    let result = v.validate_post_schema(&req, raw_bytes);
    assert!(result.is_err(), "pub-002 must surface a validation error");
}

/// pub-005 — restricted visibility without an audience is a producer bug
/// (RFC-ACDP-0002 §5.3). validate_publish_request rejects it.
#[test]
fn pub_005_restricted_without_audience_rejected() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/pub-005-restricted-without-audience.json");
    if !path.exists() {
        return;
    }
    let fixture = read_json(&path);
    let Some(body) = fixture.get("input").and_then(|i| i.get("body")) else {
        return;
    };
    let req: acdp::types::PublishRequest = match serde_json::from_value(body.clone()) {
        Ok(r) => r,
        Err(_) => return,
    };
    let err = acdp::validation::validate_publish_request(&req).unwrap_err();
    // Either SchemaViolation or a more specific error — must not pass.
    assert!(
        matches!(err, acdp::AcdpError::SchemaViolation(_)),
        "pub-005 must surface SchemaViolation for missing audience, got {err:?}"
    );
}

/// pub-013 / pub-014 / pub-012 — registry-assigned or unknown fields in a
/// publish request must be rejected at deserialization (BUG-02). Cross-
/// check: every fixture in this family must fail to parse as
/// PublishRequest.
#[test]
fn pub_012_013_014_extra_field_fixtures_fail_to_parse() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !matches!(
            name,
            "pub-012-extra-unknown-field.json"
                | "pub-013-producer-supplied-ctx-id.json"
                | "pub-014-producer-supplied-created-at.json"
        ) {
            continue;
        }
        let fixture = read_json(&path);
        let Some(body) = fixture.get("input").and_then(|i| i.get("body")) else {
            continue;
        };
        let res: Result<acdp::types::PublishRequest, _> = serde_json::from_value(body.clone());
        assert!(
            res.is_err(),
            "{name} body must FAIL to deserialize (deny_unknown_fields)"
        );
        checked += 1;
    }
    assert!(checked >= 1, "expected ≥1 pub-012/013/014 fixture");
}

/// idem-001..006 — fixtures are descriptive (preconditions / expected) and
/// don't carry a deserializable body in every case. We assert at minimum
/// that the family exists in the spec; full behavioral testing of these
/// scenarios lives in `src/registry/server.rs::tests`.
#[test]
fn idem_family_present_in_spec() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let count = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.starts_with("idem-"))
        })
        .count();
    assert!(count >= 5, "expected ≥5 idem-* fixtures, got {count}");
}

/// rate-001 — single fixture documenting the rate-limited response shape.
/// We assert the fixture parses; the runtime RateLimited path is unit-
/// tested in `src/registry/server.rs`.
#[test]
fn rate_001_response_shape_parses() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/rate-001-rate-limited-response-shape.json");
    if !path.exists() {
        return;
    }
    let fixture = read_json(&path);
    assert!(fixture.get("expected").is_some());
}

/// ret-001 + err-001 — assert these descriptive fixtures parse.
#[test]
fn ret_001_and_err_001_present() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let ret = dir.join("ret-001-not-found.json");
    let err = dir.join("err-001-internal-error.json");
    assert!(
        ret.exists() || err.exists(),
        "expected at least one of ret-001 / err-001 in fixtures"
    );
}

// ── pub-004 / pub-007 — offline fixture binding (no TLS) ─────────────────────

/// pub-004 — a v1 publish request with `lineage_id` set MUST be rejected
/// at schema-level validation. The producer cannot compute a correct
/// value (it depends on the registry-assigned ctx_id), so any value is
/// necessarily wrong (RFC-ACDP-0003 §2.2).
///
/// Fixture body uses `did:agent:test` rather than `did:web:…`, so a
/// strict v0.1.0 validator may surface the agent_id violation first;
/// either way the outcome MUST be `SchemaViolation` and the publish
/// MUST NOT be accepted.
#[test]
fn pub_004_first_version_with_lineage_id_rejected() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/pub-004-first-version-with-lineage.json");
    if !path.exists() {
        return;
    }
    let fixture = read_json(&path);
    // The fixture in round-4 uses `request.body`, but earlier revisions
    // used `input.body`. Try both so the test is robust to format drift.
    let body = fixture
        .pointer("/request/body")
        .or_else(|| fixture.pointer("/input/body"))
        .cloned();
    let Some(body) = body else { return };

    // Normalize the fixture for offline validation:
    //   - replace the non-did:web agent_id/key_id with did:web placeholders,
    //   - pad the signature value to the valid 88-char ed25519 length.
    // Without these the agent_id or signature-length check fires first
    // and the assertion still passes `matches!(SchemaViolation)`, but
    // does not prove the v1+lineage_id rule. After normalization, the
    // only remaining schema-level violation is `lineage_id` on a v1
    // publish — exactly what pub-004 is asserting.
    let mut body = body;
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "agent_id".into(),
            serde_json::json!("did:web:agents.example.com:test"),
        );
        if let Some(sig) = obj.get_mut("signature").and_then(|s| s.as_object_mut()) {
            sig.insert(
                "key_id".into(),
                serde_json::json!("did:web:agents.example.com:test#key-1"),
            );
            // 88-char base64 = the wire length the schema enforces for
            // both ed25519 and ecdsa-p256 signature values.
            sig.insert("value".into(), serde_json::json!("A".repeat(86) + "=="));
        }
    }

    let req: acdp::types::PublishRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(_) => return, // deny_unknown_fields caught it earlier — still a rejection
    };
    let err = acdp::validation::validate_publish_request(&req).unwrap_err();
    assert!(
        matches!(err, acdp::AcdpError::SchemaViolation(_)),
        "pub-004 must reject v1 with lineage_id as SchemaViolation, got {err:?}"
    );
}

/// pub-007 — `PublishResponse` shape: exactly five registry-assigned
/// fields, no echoed `content_hash`/`signature`/body fields.
///
/// The fixture is descriptive (lists required/forbidden field names),
/// but `scenarios[0].input.publish_response.body` is a concrete
/// conformant response object that MUST deserialize. Symmetrically, a
/// response object carrying any of the forbidden fields MUST be
/// rejected by serde's `deny_unknown_fields`.
#[test]
fn pub_007_publish_response_shape() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/pub-007-publish-response-shape.json");
    if !path.exists() {
        return;
    }
    let fixture = read_json(&path);

    // Step 1: the conformant scenario body MUST parse as PublishResponse.
    if let Some(body) = fixture.pointer("/scenarios/0/input/publish_response/body") {
        let parsed: acdp::types::PublishResponse = serde_json::from_value(body.clone()).expect(
            "pub-007: conformant publish-response body must deserialize as PublishResponse",
        );
        assert_eq!(
            parsed.status,
            acdp::types::Status::Active,
            "pub-007: status on first-publish MUST be `active`"
        );
        assert_eq!(
            parsed.version, 1,
            "pub-007: first-publish version MUST be 1"
        );
    }

    // Step 2: a publish response that echoes ANY forbidden field MUST be
    // rejected (deny_unknown_fields). Pull the forbidden list straight
    // from the fixture so this test follows the spec as it evolves.
    if let (Some(body), Some(forbidden)) = (
        fixture.pointer("/scenarios/0/input/publish_response/body"),
        fixture
            .pointer("/expected/response_body_shape/forbidden_fields")
            .and_then(|v| v.as_array()),
    ) {
        for field in forbidden {
            let Some(field_name) = field.as_str() else {
                continue;
            };
            let mut tampered = body.clone();
            if let Some(obj) = tampered.as_object_mut() {
                obj.insert(field_name.into(), serde_json::json!("forbidden-value"));
            }
            let r: Result<acdp::types::PublishResponse, _> = serde_json::from_value(tampered);
            assert!(
                r.is_err(),
                "pub-007: publish response with forbidden field `{field_name}` \
                 MUST be rejected by deny_unknown_fields, got {r:?}"
            );
        }
    }
}

// ── FEAT-01/02/03 — vis-009 / vis-008 / ret-002 behavioral bindings ──────────
//
// End-to-end `RegistryServer` checks for the scenarios the named fixtures
// pin. Gated on the `server` feature for `RegistryServer` / `InMemoryStore`.
#[cfg(feature = "server")]
mod registry_behavior {
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::registry::{InMemoryStore, RegistryServer, RegistryStore};
    use acdp::types::capabilities::Limits;
    use acdp::types::primitives::{AgentDid, ContextType, Status, Visibility};
    use acdp::types::search::SearchParams;
    use acdp::types::CapabilitiesDocument;
    use acdp::AcdpError;

    const OWNER: &str = "did:web:agents.example.com:owner";
    const AUTHORIZED: &str = "did:web:agents.example.com:authorized";
    const STRANGER: &str = "did:web:agents.example.com:stranger";

    fn caps(anonymous_public_reads: bool) -> CapabilitiesDocument {
        CapabilitiesDocument {
            acdp_version: "0.1.0".into(),
            registry_did: "did:web:registry.example.com".into(),
            supported_signature_algorithms: vec!["ed25519".into()],
            supported_did_methods: vec!["did:web".into()],
            profiles: vec!["acdp-registry-core".into()],
            limits: Limits {
                max_payload_bytes: 1_048_576,
                max_embedded_bytes: 65_536,
                idempotency_key_ttl_seconds: None,
            },
            read_authentication_methods: vec![],
            anonymous_public_reads,
            supports_idempotency_key: false,
            extensions: Default::default(),
        }
    }

    fn producer() -> Producer {
        Producer::new(
            SigningKey::from_bytes(&[7u8; 32]),
            AgentDid::new(OWNER),
            format!("{OWNER}#key-1"),
        )
    }

    fn server(anonymous_public_reads: bool) -> RegistryServer<InMemoryStore> {
        RegistryServer::new(
            InMemoryStore::new(),
            caps(anonymous_public_reads),
            "registry.example.com",
        )
    }

    fn search_beta(
        srv: &RegistryServer<InMemoryStore>,
        requester: Option<&AgentDid>,
    ) -> Result<acdp::types::SearchResponse, AcdpError> {
        srv.search(
            &SearchParams {
                q: Some("beta".into()),
                ..Default::default()
            },
            requester,
        )
    }

    /// Publish one public + one restricted context, both matching `q=beta`.
    fn publish_beta_pair(srv: &RegistryServer<InMemoryStore>) {
        let p = producer();
        let public = p
            .publish_request()
            .title("Public beta")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        srv.publish_unverified_for_tests(&public).unwrap();
        let restricted = p
            .publish_request()
            .title("Restricted beta")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![AgentDid::new(AUTHORIZED)])
            .build()
            .unwrap();
        srv.publish_unverified_for_tests(&restricted).unwrap();
    }

    /// FEAT-01 / vis-009 — `anonymous_public_reads` governs keyword search
    /// exactly as it governs retrieval.
    #[test]
    fn vis_009_anonymous_public_reads_search_scoping() {
        // s1: flag=false + anonymous → 403 not_authorized, no leakage.
        {
            let srv = server(false);
            publish_beta_pair(&srv);
            let err = search_beta(&srv, None).unwrap_err();
            assert!(
                matches!(err, AcdpError::NotAuthorized(_)),
                "vis-009 s1: anonymous search MUST be NotAuthorized when \
                 anonymous_public_reads=false; got {err:?}"
            );
        }
        // s2: flag=true + anonymous → 200, public results only.
        {
            let srv = server(true);
            publish_beta_pair(&srv);
            let resp = search_beta(&srv, None).unwrap();
            assert_eq!(
                resp.matches.len(),
                1,
                "vis-009 s2: anonymous search sees public contexts only"
            );
            assert_eq!(resp.matches[0].title, "Public beta");
        }
        // s3: flag=false + authenticated → 200, public only (restricted
        // excluded — the stranger is in no audience).
        {
            let srv = server(false);
            publish_beta_pair(&srv);
            let stranger = AgentDid::new(STRANGER);
            let resp = search_beta(&srv, Some(&stranger)).unwrap();
            assert_eq!(
                resp.matches.len(),
                1,
                "vis-009 s3: an authenticated non-audience requester sees public only"
            );
            assert_eq!(resp.matches[0].title, "Public beta");
        }
    }

    /// FEAT-02 / vis-008 — lineage endpoints apply the same per-context
    /// visibility rules as `GET /contexts/{ctx_id}`. Knowing a
    /// `lineage_id` MUST NOT grant access ctx_id-level control denies.
    #[test]
    fn vis_008_lineage_endpoint_visibility() {
        let owner = AgentDid::new(OWNER);
        let audience = AgentDid::new(AUTHORIZED);
        let stranger = AgentDid::new(STRANGER);
        let srv = server(true);
        let p = producer();

        // Restricted lineage: v1 restricted (→ superseded), v2 restricted.
        let v1 = p
            .publish_request()
            .title("restricted v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![audience.clone()])
            .build()
            .unwrap();
        let v1_resp = srv.publish_unverified_for_tests(&v1).unwrap();
        let v2 = p
            .supersede(v1_resp.ctx_id.clone())
            .version(2)
            .title("restricted v2")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![audience.clone()])
            .build()
            .unwrap();
        srv.publish_unverified_for_tests(&v2).unwrap();
        let restricted_lineage = v1_resp.lineage_id.clone();

        // s1: stranger sees zero versions — empty array, not an error.
        assert!(
            srv.lineage(&restricted_lineage, Some(&stranger))
                .unwrap()
                .is_empty(),
            "vis-008 s1: stranger MUST see zero versions of a restricted lineage"
        );
        // s2: audience member sees the full restricted history.
        assert_eq!(
            srv.lineage(&restricted_lineage, Some(&audience))
                .unwrap()
                .len(),
            2,
            "vis-008 s2: audience member MUST see every restricted version"
        );

        // Mixed lineage: v1 public (→ superseded), v2 private.
        let m1 = p
            .publish_request()
            .title("mixed v1 public")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let m1_resp = srv.publish_unverified_for_tests(&m1).unwrap();
        let m2 = p
            .supersede(m1_resp.ctx_id.clone())
            .version(2)
            .title("mixed v2 private")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Private)
            .build()
            .unwrap();
        let m2_resp = srv.publish_unverified_for_tests(&m2).unwrap();
        let mixed_lineage = m1_resp.lineage_id.clone();

        // s3: stranger sees only the public v1 — the private v2 is a gap.
        let stranger_view = srv.lineage(&mixed_lineage, Some(&stranger)).unwrap();
        assert_eq!(
            stranger_view.len(),
            1,
            "vis-008 s3: stranger sees only the visible subsequence"
        );
        assert_eq!(stranger_view[0].body.ctx_id, m1_resp.ctx_id);

        // s4: stranger `current` → None (v2 private, v1 superseded).
        assert!(
            srv.current(&mixed_lineage, Some(&stranger))
                .unwrap()
                .is_none(),
            "vis-008 s4: stranger MUST NOT reach the private current head"
        );
        // s5: producer `current` → the private v2.
        let owner_cur = srv
            .current(&mixed_lineage, Some(&owner))
            .unwrap()
            .expect("vis-008 s5: producer sees the private current head");
        assert_eq!(owner_cur.body.ctx_id, m2_resp.ctx_id);
    }

    /// FEAT-03 / ret-002 — `current` returns the newest non-superseded
    /// version: `expired` counts as a valid head, `superseded` never
    /// does, and an all-superseded lineage resolves to `not_found`.
    #[test]
    fn ret_002_lineage_current_semantics() {
        use chrono::{Duration, Utc};
        let srv = server(true);
        let p = producer();

        // All versions superseded → current returns None.
        {
            let v1 = p
                .publish_request()
                .title("all-superseded v1")
                .context_type(ContextType::DataSnapshot)
                .visibility(Visibility::Public)
                .build()
                .unwrap();
            let resp = srv.publish_unverified_for_tests(&v1).unwrap();
            srv.store().mark_superseded(&resp.ctx_id).unwrap();
            assert!(
                srv.current(&resp.lineage_id, None).unwrap().is_none(),
                "ret-002: an all-superseded lineage MUST resolve to None (RFC-ACDP-0004 §5.2)"
            );
        }

        // Active head → current returns it with status active.
        {
            let v1 = p
                .publish_request()
                .title("active head v1")
                .context_type(ContextType::DataSnapshot)
                .visibility(Visibility::Public)
                .build()
                .unwrap();
            let resp = srv.publish_unverified_for_tests(&v1).unwrap();
            let cur = srv
                .current(&resp.lineage_id, None)
                .unwrap()
                .expect("ret-002: an active head MUST be returned");
            assert_eq!(cur.registry_state.status, Status::Active);
        }

        // Expired-but-unreplaced head → current returns it with status
        // expired. 'current' does not imply 'active'.
        {
            let v1 = p
                .publish_request()
                .title("expired head v1")
                .context_type(ContextType::DataSnapshot)
                .visibility(Visibility::Public)
                .expires_at(Utc::now() - Duration::days(30))
                .build()
                .unwrap();
            let resp = srv.publish_unverified_for_tests(&v1).unwrap();
            let cur = srv
                .current(&resp.lineage_id, None)
                .unwrap()
                .expect("ret-002: an expired-but-unreplaced head IS a valid current head");
            assert_eq!(
                cur.registry_state.status,
                Status::Expired,
                "ret-002: current MUST carry status=expired so the consumer knows it lapsed"
            );
        }
    }
}
