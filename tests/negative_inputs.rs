//! Error-path coverage for the public API surface.
//!
//! The other integration suites (`registry_client`, `tls_conformance`,
//! `conformance`) mostly exercise happy paths and spec fixtures. This file
//! is the complementary "what does a downstream consumer get when they
//! feed in garbage" suite: malformed identifiers, builder rule violations,
//! and oversize fields. It uses only the always-on core, so it runs under
//! both the default and `--no-default-features` test configurations.
//!
//! Every assertion here doubles as executable documentation of an error
//! contract — if one of these variants changes, that is an intentional API
//! change and this file should change with it.

use acdp::crypto::SigningKey;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::types::{AgentDid, ContentHash, ContextType, CtxId, LineageId, Visibility};

/// A well-formed lineage_id used where the *value* is valid but the
/// *placement* (on a v1 request) is what should be rejected.
const VALID_LINEAGE: &str =
    "lin:sha256:4c63394418b2e784aef68f5a091535c557453c21231f5905f21a38c02913cd86";

fn test_producer() -> Producer {
    Producer::new(
        SigningKey::generate(),
        AgentDid::new("did:web:agents.example.com:my-agent"),
        "did:web:agents.example.com:my-agent#key-1",
    )
}

// ── Identifier parsing ────────────────────────────────────────────────────────

#[test]
fn ctx_id_parse_rejects_malformed() {
    // Missing scheme, missing uuid path, and a non-UUID tail are all rejected.
    for bad in [
        "registry.example.com/uuid",                      // no acdp:// scheme
        "acdp://registry.example.com",                    // no /<uuid>
        "acdp://registry.example.com/not-a-uuid",         // tail is not a UUID
        "acdp://registry.example.com/11111111-1111-1111", // truncated UUID
    ] {
        let err = CtxId::parse(bad).expect_err(bad);
        assert!(
            matches!(err, AcdpError::SchemaViolation(_)),
            "{bad}: expected SchemaViolation, got {err:?}"
        );
    }
    // The canonical form round-trips.
    let ok = "acdp://registry.example.com/11111111-1111-4111-8111-111111111111";
    assert_eq!(CtxId::parse(ok).unwrap().as_str(), ok);
}

#[test]
fn lineage_id_parse_rejects_malformed() {
    for bad in [
        "sha256:abcd",    // missing lin: prefix
        "lin:md5:abcd",   // wrong hash algorithm
        "lin:sha256:xyz", // not 64 hex chars
    ] {
        assert!(
            matches!(LineageId::parse(bad), Err(AcdpError::SchemaViolation(_))),
            "{bad}: expected SchemaViolation"
        );
    }
    assert!(LineageId::parse(VALID_LINEAGE).is_ok());
}

#[test]
fn content_hash_parse_rejects_malformed() {
    for bad in [
        "f170150d",      // missing sha256: prefix
        "sha256:nothex", // not hex
        "sha256:abcd",   // wrong length
    ] {
        assert!(
            matches!(ContentHash::parse(bad), Err(AcdpError::SchemaViolation(_))),
            "{bad}: expected SchemaViolation"
        );
    }
    let ok = "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5";
    assert!(ContentHash::parse(ok).is_ok());
}

#[test]
fn agent_did_parse_rejects_non_did() {
    for bad in [
        "agents.example.com", // no did: prefix
        "did:",               // no method:id
        "did:web",            // no id segment
    ] {
        assert!(
            matches!(AgentDid::parse(bad), Err(AcdpError::SchemaViolation(_))),
            "{bad}: expected SchemaViolation"
        );
    }
}

#[test]
fn agent_did_parse_web_rejects_other_methods() {
    // v0.1.0 producers MUST use did:web — other methods are refused by the
    // stricter `parse_web`, even though generic `parse` would accept them.
    assert!(AgentDid::parse("did:key:z6Mk...").is_ok());
    assert!(matches!(
        AgentDid::parse_web("did:key:z6Mk..."),
        Err(AcdpError::SchemaViolation(_))
    ));
    assert!(AgentDid::parse_web("did:web:agents.example.com:my-agent").is_ok());
}

// ── Builder: v1 vs v2 lineage rules (RFC-ACDP-0003 §3.1) ───────────────────────

#[test]
fn v1_rejects_expected_lineage_id() {
    // v1 publications MUST NOT include lineage_id (RFC-ACDP-0003 §2.2).
    let err = test_producer()
        .publish_request()
        .title("v1 with stray lineage_id")
        .context_type(ContextType::DataSnapshot)
        .expected_lineage_id(LineageId::parse(VALID_LINEAGE).unwrap())
        .build()
        .expect_err("v1 + lineage_id must be rejected");
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
}

#[test]
fn first_version_rejects_non_one_version() {
    let err = test_producer()
        .publish_request()
        .title("first version claiming v2")
        .context_type(ContextType::DataSnapshot)
        .version(2)
        .build()
        .expect_err("first-version + version=2 must be rejected");
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
}

#[test]
fn supersede_requires_explicit_version() {
    // `supersede` (unlike `supersede_body`) does not know the previous
    // version, so the caller must supply it.
    let prev =
        CtxId::parse("acdp://registry.example.com/11111111-1111-4111-8111-111111111111").unwrap();
    let err = test_producer()
        .supersede(prev)
        .title("missing version")
        .context_type(ContextType::DataSnapshot)
        .build()
        .expect_err("supersede without version must be rejected");
    assert!(
        matches!(err, AcdpError::MissingField("version")),
        "got {err:?}"
    );
}

#[test]
fn supersede_rejects_version_below_two() {
    let prev =
        CtxId::parse("acdp://registry.example.com/11111111-1111-4111-8111-111111111111").unwrap();
    let err = test_producer()
        .supersede(prev)
        .version(1)
        .title("supersession claiming v1")
        .context_type(ContextType::DataSnapshot)
        .build()
        .expect_err("supersession with version<2 must be rejected");
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
}

// ── Builder: required + bounded fields ─────────────────────────────────────────

#[test]
fn build_requires_title() {
    let err = test_producer()
        .publish_request()
        .context_type(ContextType::DataSnapshot)
        .build()
        .expect_err("missing title must be rejected");
    assert!(
        matches!(err, AcdpError::MissingField("title")),
        "got {err:?}"
    );
}

#[test]
fn build_rejects_oversize_title() {
    // Title is bounded at 500 chars by acdp-publish-request.schema.json.
    let err = test_producer()
        .publish_request()
        .title("x".repeat(501))
        .context_type(ContextType::DataSnapshot)
        .build()
        .expect_err("501-char title must be rejected");
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
}

#[test]
fn build_rejects_restricted_without_audience() {
    // `restricted` visibility requires at least one audience DID.
    let err = test_producer()
        .publish_request()
        .title("restricted but no audience")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Restricted)
        .build()
        .expect_err("restricted without audience must be rejected");
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
}
