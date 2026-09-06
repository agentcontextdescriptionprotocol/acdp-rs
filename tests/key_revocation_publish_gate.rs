//! RFC-ACDP-0014 §5 step 2 on the `did:web` publish path (issue #207,
//! Phase 7 of `plans/issues-206-208-bindings-registry-release-gate.md`).
//!
//! `tests/key_revocation.rs` MUST NOT be edited by this file (it is a
//! separate integration-test crate); it already pins §5 step 2 for a
//! `did:key` signer at the parse level
//! (`rev_001_did_key_self_revocation_rejected_at_parse`, via
//! `KeyRevocation::from_body`) and the §4 shape table at the validator
//! level. This file additionally pins, at the `RegistryServer` level:
//!
//! - the new `did:web` hook in `publish_verified_in_tenant`: a resolved
//!   `did:web` signing key whose fingerprint equals the revocation's own
//!   `metadata.revoked_key_fingerprint` is rejected with
//!   `key_not_authorized`, only once `acdp_version >= 0.3.0`;
//! - the positive controls proving the version gate — not a blanket
//!   rejection — is what changes the outcome, and that a genuinely
//!   different signing key is accepted at both versions;
//! - that the `did:key` publish path (`publish_verified_did_key_in_tenant`)
//!   already enforces the identical rule with no code change in this
//!   phase, confirming Phase 5/6's claim that `PublishValidator::validate_post_schema`
//!   covers it for free;
//! - the fail-closed polarity on a malformed `capabilities.acdp_version`,
//!   consistent with Phase 6;
//! - that an ordinary (non-key-revocation) `did:web` publish is
//!   unaffected — no new rejection, no accidental invocation of
//!   `KeyRevocation::from_publish_request` on a body shape it was never
//!   meant to see.

mod common;

use acdp::crypto::{fingerprint_ed25519, SigningKey};
use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::{InMemoryStore, RegistryServer};
use acdp::types::capabilities::Limits;
use acdp::types::{AgentDid, CapabilitiesDocument, ContextType, PublishRequest, Visibility};
use axum::{routing::get, Json, Router};
use common::TlsTestServer;
use serde_json::json;

const REGISTRY_AUTHORITY: &str = "localhost";
const REGISTRY_DID: &str = "did:web:localhost";
const PRODUCER_DID: &str = "did:web:localhost:producer";
const COMPROMISED_SINCE: &str = "2026-05-01T00:00:00.000Z";

fn caps_at(version: &str) -> CapabilitiesDocument {
    CapabilitiesDocument {
        acdp_version: version.into(),
        registry_did: REGISTRY_DID.into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into(), "did:key".into()],
        profiles: vec!["acdp-registry-core".into()],
        limits: Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            // Required whenever supports_idempotency_key is true
            // (RFC-ACDP-0007 §3.2), which it is unconditionally below.
            idempotency_key_ttl_seconds: Some(86_400),
            max_publish_per_minute: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        // Required true once acdp_version >= 0.3.0 (RFC-ACDP-0007 §3.5
        // item 10); harmless at 0.2.0 too, so set unconditionally.
        supports_idempotency_key: true,
        extensions: Default::default(),
    }
}

fn revocation_request(
    signing_key: SigningKey,
    key_fragment: &str,
    revoked_fingerprint: &str,
) -> PublishRequest {
    Producer::new(
        signing_key,
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#{key_fragment}"),
    )
    .publish_request()
    .acdp_version("0.3.0")
    .title("Key revocation — test")
    .context_type(ContextType::KeyRevocation)
    .visibility(Visibility::Public)
    .metadata(json!({
        "revoked_key_fingerprint": revoked_fingerprint,
        "compromised_since": COMPROMISED_SINCE,
        "reason": "test compromise",
    }))
    .build()
    .expect("valid revocation publish request")
}

fn analysis_request(signing_key: SigningKey, key_fragment: &str) -> PublishRequest {
    Producer::new(
        signing_key,
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#{key_fragment}"),
    )
    .publish_request()
    .acdp_version("0.3.0")
    .title("An ordinary context, not a revocation")
    .context_type(ContextType::Analysis)
    .visibility(Visibility::Public)
    .build()
    .expect("valid analysis publish request")
}

/// Serve `PRODUCER_DID`'s DID document (`did:web:localhost:producer` ⇒
/// `/producer/did.json`) over the in-process TLS harness and return a
/// resolver pinned to it.
async fn start_producer_harness(producer_pub: &[u8; 32]) -> (TlsTestServer, WebResolver) {
    let producer_doc = common::ed25519_did_doc(PRODUCER_DID, "key-1", producer_pub);
    let router = Router::new().route(
        "/producer/did.json",
        get(move || {
            let doc = producer_doc.clone();
            async move { Json(doc) }
        }),
    );
    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    (tls, resolver)
}

// ── did:web, acceptance criterion 1 + 2 ──────────────────────────────────────

#[tokio::test]
async fn did_web_self_revocation_rejected_at_0_3_0() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    let req = revocation_request(signing_key, "key-1", &fp);
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let err = server
        .publish_verified(&req, None, &resolver)
        .await
        .expect_err("a did:web revocation signed by the very key it revokes must be rejected");
    assert!(
        matches!(err, AcdpError::KeyNotAuthorized(_)),
        "expected KeyNotAuthorized, got {err:?}"
    );
}

#[tokio::test]
async fn did_web_self_revocation_accepted_at_0_2_0() {
    // Positive control for the test above: the identical request,
    // signed by the identical self-revoking key, against a registry
    // that has not turned the §4/§5 gate on yet. Proves the version
    // gate — not some other rejection — is what changed the outcome.
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    let req = revocation_request(signing_key, "key-1", &fp);
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.2.0"), REGISTRY_AUTHORITY)
            .expect("server");

    server
        .publish_verified(&req, None, &resolver)
        .await
        .expect("a 0.2.0 registry has not yet turned the RFC-ACDP-0014 gate on");
}

// ── did:web, acceptance criterion 3 ──────────────────────────────────────────

#[tokio::test]
async fn did_web_different_key_revocation_accepted_at_both_versions() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let other_key_fp =
        fingerprint_ed25519(&SigningKey::from_bytes(&[9u8; 32]).verifying_key_bytes());
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    for version in ["0.2.0", "0.3.0"] {
        let req = revocation_request(SigningKey::from_bytes(&[3u8; 32]), "key-1", &other_key_fp);
        let server =
            RegistryServer::try_new(InMemoryStore::new(), caps_at(version), REGISTRY_AUTHORITY)
                .expect("server");

        server
            .publish_verified(&req, None, &resolver)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "a revocation signed by a DIFFERENT key must be accepted at {version} \
                 (this is the positive control proving the check isn't rejecting \
                 everything): {e:?}"
                )
            });
    }
}

// ── did:key, acceptance criterion 4 ──────────────────────────────────────────

/// Pins, at the `RegistryServer` level (not just the type-parse level
/// `tests/key_revocation.rs` already covers), that a `did:key` producer
/// "revoking" its own key is rejected by `publish_verified_did_key_in_tenant`
/// — via `PublishValidator::validate_post_schema` ⇒
/// `KeyRevocation::from_publish_request` ⇒ `from_parts`'s did:key
/// sub-case — with NO change from this phase. No network / TLS harness
/// needed: this path is pure and synchronous.
#[test]
fn did_key_self_revocation_rejected_at_registry_server_level() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let producer = Producer::new_did_key(signing_key);

    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("Key revocation — did:key self-revocation")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": fp,
            "compromised_since": COMPROMISED_SINCE,
            "reason": "test compromise",
        }))
        .build()
        .expect("builder does not resolve keys; the publish shape itself is valid");

    let mut caps = caps_at("0.3.0");
    caps.registry_did = REGISTRY_DID.into();
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps, REGISTRY_AUTHORITY).expect("server");

    let err = server
        .publish_verified_did_key(&req, None)
        .expect_err("a did:key revocation signed by the very key it revokes must be rejected");
    assert!(
        matches!(err, AcdpError::KeyNotAuthorized(_)),
        "expected KeyNotAuthorized, got {err:?}"
    );
}

// ── fail-closed on a malformed acdp_version ──────────────────────────────────

/// `RegistryServer::try_new`/`try_new_for_test_authority` validate
/// `capabilities.acdp_version` against the schema's semver pattern and
/// would refuse to construct a server with a malformed one at all — so
/// this test uses the unchecked `RegistryServer::new` (as tests
/// elsewhere in this crate use for fixtures with deliberately
/// non-conformant shapes) purely to exercise `key_revocation_gate_applies`'s
/// fail-closed polarity through the did:web hook, matching Phase 6's
/// validator-level coverage of the same predicate.
#[tokio::test]
async fn did_web_self_revocation_rejected_under_malformed_acdp_version() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    let req = revocation_request(signing_key, "key-1", &fp);
    let mut caps = caps_at("0.2.0");
    caps.acdp_version = "0.3x.0".into(); // malformed: not MAJOR.MINOR.PATCH
    let server = RegistryServer::new(InMemoryStore::new(), caps, REGISTRY_AUTHORITY);

    let err = server
        .publish_verified(&req, None, &resolver)
        .await
        .expect_err(
            "a malformed acdp_version must turn the §5 step 2 gate ON, not OFF \
             (fail-closed, matching Phase 6's §4 gate)",
        );
    assert!(
        matches!(err, AcdpError::KeyNotAuthorized(_)),
        "expected KeyNotAuthorized, got {err:?}"
    );
}

// ── non-key-revocation publishes are unaffected ──────────────────────────────

#[tokio::test]
async fn ordinary_publish_unaffected_by_the_new_hook() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    let req = analysis_request(signing_key, "key-1");
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    server.publish_verified(&req, None, &resolver).await.expect(
        "an ordinary (non-key-revocation) publish must be unaffected by the new §5 \
         step 2 hook — it is gated on ContextType::is_key_revocation() and must not \
         fire, let alone fail, for any other context type",
    );
}

// ── pinned path (`publish_pinned_verified_in_tenant`) ───────────────────────
//
// This path resolves no DID at all — the caller has already verified the
// signature against `verified_public_key_b64` out of band (e.g. a
// playground registry's pinned-key allowlist) — so unlike the `did:web`
// tests above, none of these need a TLS harness or resolver; they call the
// (synchronous) pinned-publish method directly. Before this phase,
// `fingerprint_pinned_key` only ran when a receipt signer was configured;
// now it also runs whenever `revocation_check_needed` is true, so a
// key-revocation publish on the pinned path gets the same §5 step 2
// enforcement as the did:web and did:key paths above, at no added
// resolution cost (the pinned key is already in hand). None of this was
// tested anywhere before this phase.

/// Encode raw Ed25519 public key bytes the way `publish_pinned_verified_in_tenant`
/// expects them: standard base64, matching `fingerprint_pinned_key`'s decoder.
fn encode_pinned_key(public_key_bytes: &[u8; 32]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(public_key_bytes)
}

#[test]
fn pinned_self_revocation_rejected_at_0_3_0() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let pinned_pub_b64 = encode_pinned_key(&signing_key.verifying_key_bytes());
    let req = revocation_request(signing_key, "key-1", &fp);

    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let err = server
        .publish_pinned_verified_in_tenant(&req, None, None, &pinned_pub_b64, "ed25519")
        .expect_err(
            "a pinned-path revocation signed by the very key it revokes must be \
             rejected, matching the did:web and did:key paths",
        );
    assert!(
        matches!(err, AcdpError::KeyNotAuthorized(_)),
        "expected KeyNotAuthorized, got {err:?}"
    );
}

#[test]
fn pinned_self_revocation_accepted_at_0_2_0() {
    // Positive control for the test above: the identical request and
    // pinned key, against a registry that has not turned the §4/§5 gate
    // on yet. Proves the version gate — not some other rejection — is
    // what changes the outcome.
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let pinned_pub_b64 = encode_pinned_key(&signing_key.verifying_key_bytes());
    let req = revocation_request(signing_key, "key-1", &fp);

    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.2.0"), REGISTRY_AUTHORITY)
            .expect("server");

    server
        .publish_pinned_verified_in_tenant(&req, None, None, &pinned_pub_b64, "ed25519")
        .expect("a 0.2.0 registry has not yet turned the RFC-ACDP-0014 gate on");
}

#[test]
fn pinned_different_key_revocation_accepted() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let pinned_pub_b64 = encode_pinned_key(&signing_key.verifying_key_bytes());
    let other_key_fp =
        fingerprint_ed25519(&SigningKey::from_bytes(&[12u8; 32]).verifying_key_bytes());
    let req = revocation_request(signing_key, "key-1", &other_key_fp);

    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    server
        .publish_pinned_verified_in_tenant(&req, None, None, &pinned_pub_b64, "ed25519")
        .unwrap_or_else(|e| {
            panic!(
                "a revocation pinned-signed by a DIFFERENT key must be accepted (this \
                 is the positive control proving the check isn't rejecting \
                 everything): {e:?}"
            )
        });
}

#[test]
fn pinned_malformed_verified_public_key_b64_fails_closed_on_key_revocation() {
    // Pins the new rejection this phase introduced: before this phase,
    // `fingerprint_pinned_key` (and therefore its base64/length
    // validation) only ran when a receipt signer was configured. Now a
    // key-revocation at >= 0.3.0 always fingerprints the pinned key —
    // including validating its shape — so a malformed
    // `verified_public_key_b64` fails the publish instead of silently
    // skipping the check.
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let req = revocation_request(signing_key, "key-1", &fp);

    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let err = server
        .publish_pinned_verified_in_tenant(&req, None, None, "not-valid-base64!!!", "ed25519")
        .expect_err(
            "a malformed pinned public key on a key-revocation publish must fail \
             closed, not silently skip the §5 step 2 check",
        );
    assert!(
        matches!(err, AcdpError::KeyResolution(_)),
        "expected KeyResolution (base64 decode failure), got {err:?}"
    );
}
