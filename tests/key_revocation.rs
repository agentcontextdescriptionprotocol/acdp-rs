//! Producer key-revocation signal (ACDP 0.3, RFC-ACDP-0014) —
//! rev-001/rev-002 fixture bindings.
//!
//! rev-001 is EXECUTED: the golden producer-signed `key-revocation`
//! context (producer revokes K1 — the sig-001 key — signing with its
//! current key K2, the 0x42-seed) is rebuilt from the test keypair and
//! byte-compared against the pinned canonical form, `content_hash`,
//! and Ed25519 signature; the §4 shape rules and the §5 step 2
//! not-self-signed rule are asserted both positively and negatively.
//!
//! rev-002 is the §7 boundary matrix: receipt-attested publish time
//! strictly before T → *historically authorized (pre-compromise,
//! receipt-attested)*; at/after T → fail closed despite a valid
//! receipt; no verifiable publish time → fail closed under strict; and
//! the two trust classes stay distinguishable. The classification is
//! exercised both as the pure rule and end-to-end through
//! `VerifiedContext::fetch_with_policy` over the in-process TLS
//! registry harness (no external network).

mod common;

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use acdp::client::{
    classify_under_revocation, verify_revocation_body, KeyAuthorization, ReceiptPolicy,
    RegistryClient, RevocationPolicy, VerificationPolicy, VerifiedContext,
};
use acdp::crypto::{
    canonicalize_value, compute_content_hash, derive_lineage_id, fingerprint_ed25519,
    verify_ed25519, SigningKey,
};
use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::{InMemoryStore, RegistryServer, RegistryStore as _};
use acdp::types::receipt::ReceiptSigner;
use acdp::types::revocation::{KeyRevocation, RevocationTrustClass};
use acdp::types::{AgentDid, Body, ContentHash, ContextType, CtxId, LineageId, Visibility};
use axum::{routing::get, Json, Router};
use chrono::{DateTime, Utc};
use common::{ed25519_did_doc, TlsTestServer};
use serde_json::json;

// ── rev-001 pinned values ────────────────────────────────────────────────────

/// K2 — the producer's CURRENT key (the sig-003 test seed, rot-001's K2).
const K2_SEED: [u8; 32] = [0x42u8; 32];
const K2_PUB_HEX: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
const K2_FP: &str = "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f";

/// K1 — the revoked key (the sig-001 all-zero test seed).
const K1_SEED: [u8; 32] = [0u8; 32];
const K1_PUB_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
const K1_FP: &str = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070";

const PRODUCER_DID: &str = "did:web:agents.example.com:test-producer";
const TITLE: &str = "Key revocation — key-1 compromised";
const SUMMARY: &str = "Revocation of the Ed25519 key \
    did:web:agents.example.com:test-producer#key-1, compromised since 2026-05-01T00:00:00.000Z.";
const REASON: &str = "laptop theft; private key material presumed exfiltrated";
/// The compromise boundary T.
const T: &str = "2026-05-01T00:00:00.000Z";

const EXPECTED_CANONICAL: &str = "{\"acdp_version\":\"0.3.0\",\"agent_id\":\"did:web:agents.example.com:test-producer\",\"contributors\":[],\"data_refs\":[],\"derived_from\":[],\"metadata\":{\"compromised_since\":\"2026-05-01T00:00:00.000Z\",\"reason\":\"laptop theft; private key material presumed exfiltrated\",\"revoked_key_fingerprint\":\"sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070\"},\"summary\":\"Revocation of the Ed25519 key did:web:agents.example.com:test-producer#key-1, compromised since 2026-05-01T00:00:00.000Z.\",\"supersedes\":null,\"title\":\"Key revocation — key-1 compromised\",\"type\":\"key-revocation\",\"version\":1,\"visibility\":\"public\"}";
const EXPECTED_CONTENT_HASH: &str =
    "sha256:210bb03ec4bd39de893eb7d39ee992913cda80f767b135a02992a71491bf57ca";
const EXPECTED_SIGNATURE_B64: &str =
    "Lf7P+ZifUGPXIkR2i9Vy4LByaTb6ktsakKcjm4ZFUlcgTs2r9/3eyjDJDNWfT+qAseNYecvYggTIGnT7EZiPAw==";
const EXPECTED_SIGNATURE_HEX: &str =
    "2dfecff9989f5063d72244768bd572e0b0726936fa92db1a90a7239b86455257204ecdabf7fddeca30c90cd59f4fea80b1e35879cbd88204c81a74fb11988f03";

const REGISTRY_ASSIGNED_CTX_ID: &str =
    "acdp://registry.example.com/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e5f";
const REGISTRY_ASSIGNED_LINEAGE: &str =
    "lin:sha256:6af6229c1c6a4a119695c77e47f6554941aebce3d25ba8567e2ae6ffbb6059cb";

/// rev-002 receipt-attested publish times.
const BEFORE_T: &str = "2026-04-16T10:30:15.123Z";
const AFTER_T: &str = "2026-05-03T09:00:00.000Z";

fn at(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

fn revocation_metadata() -> serde_json::Value {
    json!({
        "revoked_key_fingerprint": K1_FP,
        "compromised_since": T,
        "reason": REASON,
    })
}

/// The fixture's producer_content, verbatim.
fn golden_producer_content() -> serde_json::Value {
    json!({
        "version": 1,
        "supersedes": null,
        "agent_id": PRODUCER_DID,
        "contributors": [],
        "title": TITLE,
        "summary": SUMMARY,
        "type": "key-revocation",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public",
        "metadata": revocation_metadata(),
        "acdp_version": "0.3.0",
    })
}

/// Rebuild the golden publish request through the real producer path:
/// K2 signs the revocation of K1.
fn golden_publish_request() -> acdp::types::PublishRequest {
    Producer::new(
        SigningKey::from_bytes(&K2_SEED),
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#key-2"),
    )
    .publish_request()
    .acdp_version("0.3.0")
    .title(TITLE)
    .summary(SUMMARY)
    .context_type(ContextType::KeyRevocation)
    .visibility(Visibility::Public)
    .metadata(revocation_metadata())
    .build()
    .expect("the golden revocation request must pass builder validation")
}

/// Materialize the golden stored Body with the fixture's
/// registry-assigned identity fields.
fn golden_body() -> Body {
    Body::from_publish_request(
        &golden_publish_request(),
        CtxId(REGISTRY_ASSIGNED_CTX_ID.into()),
        LineageId(REGISTRY_ASSIGNED_LINEAGE.into()),
        "registry.example.com",
        at("2026-05-02T08:00:00.000Z"),
    )
}

// ── rev-001: executed golden vector ──────────────────────────────────────────

#[test]
fn rev_001_keypair_constants_are_consistent() {
    let k2 = SigningKey::from_bytes(&K2_SEED);
    assert_eq!(hex::encode(k2.verifying_key_bytes()), K2_PUB_HEX);
    assert_eq!(fingerprint_ed25519(&k2.verifying_key_bytes()), K2_FP);

    let k1 = SigningKey::from_bytes(&K1_SEED);
    assert_eq!(hex::encode(k1.verifying_key_bytes()), K1_PUB_HEX);
    assert_eq!(fingerprint_ed25519(&k1.verifying_key_bytes()), K1_FP);
}

#[test]
fn rev_001_canonical_form_matches() {
    let canonical = canonicalize_value(&golden_producer_content());
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        EXPECTED_CANONICAL,
        "JCS canonical form mismatch"
    );
}

#[test]
fn rev_001_content_hash_matches() {
    let hash = compute_content_hash(&golden_producer_content()).unwrap();
    assert_eq!(hash.as_str(), EXPECTED_CONTENT_HASH);
}

#[test]
fn rev_001_signature_matches_and_verifies() {
    // Sign the ASCII bytes of the content_hash string with K2.
    let sig = SigningKey::from_bytes(&K2_SEED)
        .sign_content_hash(&ContentHash(EXPECTED_CONTENT_HASH.into()));
    assert_eq!(sig, EXPECTED_SIGNATURE_B64);
    assert_eq!(
        hex::encode(base64_decode(&sig)),
        EXPECTED_SIGNATURE_HEX,
        "raw signature bytes drifted"
    );

    let pub_bytes: [u8; 32] = hex::decode(K2_PUB_HEX).unwrap().try_into().unwrap();
    verify_ed25519(&pub_bytes, EXPECTED_SIGNATURE_B64, EXPECTED_CONTENT_HASH).unwrap();
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// The full producer path (builder validation → hash → signature)
/// reproduces the golden vector byte-for-byte.
#[test]
fn rev_001_full_producer_round_trip() {
    let req = golden_publish_request();
    assert_eq!(req.content_hash.as_str(), EXPECTED_CONTENT_HASH);
    assert_eq!(req.signature.value, EXPECTED_SIGNATURE_B64);
    assert_eq!(req.signature.algorithm, "ed25519");
    assert_eq!(req.signature.key_id, format!("{PRODUCER_DID}#key-2"));
}

#[test]
fn rev_001_lineage_id_derivation() {
    let lid = derive_lineage_id(&CtxId(REGISTRY_ASSIGNED_CTX_ID.into()));
    assert_eq!(lid.as_str(), REGISTRY_ASSIGNED_LINEAGE);
}

/// KeyRevocation::from_body parses the golden body into the typed §4
/// view with the producer-signed trust class.
#[test]
fn rev_001_parses_as_producer_signed_revocation() {
    let rev = KeyRevocation::from_body(&golden_body()).expect("golden body must parse");
    assert_eq!(rev.revoked_key_fingerprint, K1_FP);
    assert_eq!(rev.compromised_since, at(T));
    assert_eq!(rev.reason.as_deref(), Some(REASON));
    assert_eq!(rev.revoked_key_id, None);
    assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);
    assert_eq!(rev.revoked_key_controller.as_str(), PRODUCER_DID);
    assert_eq!(rev.publisher.as_str(), PRODUCER_DID);
    assert!(rev.revokes(K1_FP));
    assert!(!rev.revokes(K2_FP));

    // §5 step 2 against the resolved signer fingerprints: K2 signed it
    // (fine); had K1 signed it, it would be self-signed (rejected).
    rev.check_not_self_signed(K2_FP)
        .expect("K2-signed revocation of K1 is not self-signed");
    let err = rev.check_not_self_signed(K1_FP).unwrap_err();
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// §10 interim form: the identical §4 metadata under the custom type
/// `acdp:key-revocation` MUST be treated as equivalent.
#[test]
fn rev_001_interim_custom_form_is_equivalent() {
    let mut body = golden_body();
    body.context_type = ContextType::Custom("acdp:key-revocation".into());
    assert!(body.context_type.is_key_revocation());
    let rev = KeyRevocation::from_body(&body).expect("interim form must parse");
    assert_eq!(rev.revoked_key_fingerprint, K1_FP);
    assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);
}

/// §5 step 2, pure did:key sub-case: a did:key producer "revoking" its
/// own key is rejected at parse time — the fingerprint is derivable
/// without resolution.
#[test]
fn rev_001_did_key_self_revocation_rejected_at_parse() {
    // The all-zero seed IS K1: this did:key's fingerprint equals the
    // revoked fingerprint.
    let producer = Producer::new_did_key(SigningKey::from_bytes(&K1_SEED));
    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title(TITLE)
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(revocation_metadata())
        .build()
        .expect("builder does not resolve keys; the publish shape itself is valid");
    let body = Body::from_publish_request(
        &req,
        CtxId(REGISTRY_ASSIGNED_CTX_ID.into()),
        LineageId(REGISTRY_ASSIGNED_LINEAGE.into()),
        "registry.example.com",
        at("2026-05-02T08:00:00.000Z"),
    );
    let err = KeyRevocation::from_body(&body).unwrap_err();
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// §4 shape violations → schema_violation, matching what a 0.3.0
/// registry must reject at publish.
#[test]
fn rev_001_shape_violations_rejected() {
    // Wrong context type.
    let mut body = golden_body();
    body.context_type = ContextType::Analysis;
    assert!(matches!(
        KeyRevocation::from_body(&body),
        Err(AcdpError::SchemaViolation(_))
    ));

    // Non-public visibility protects nobody.
    let mut body = golden_body();
    body.visibility = acdp::types::Visibility::Restricted;
    assert!(matches!(
        KeyRevocation::from_body(&body),
        Err(AcdpError::SchemaViolation(_))
    ));

    // Missing metadata entirely.
    let mut body = golden_body();
    body.metadata = None;
    assert!(matches!(
        KeyRevocation::from_body(&body),
        Err(AcdpError::SchemaViolation(_))
    ));

    // Fingerprint not in RFC-ACDP-0010 §6 form.
    for bad_fp in [
        json!("139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070"), // no prefix
        json!("sha256:139E3940E64B5491722088D9A0D741628FC826E09475D341A780ACDE3C4B8070"), // uppercase
        json!("sha256:139e39"),                                                           // short
        json!(42), // not a string
    ] {
        let mut body = golden_body();
        body.metadata.as_mut().unwrap()["revoked_key_fingerprint"] = bad_fp.clone();
        assert!(
            matches!(
                KeyRevocation::from_body(&body),
                Err(AcdpError::SchemaViolation(_))
            ),
            "fingerprint {bad_fp} must be rejected"
        );
    }

    // compromised_since must be canonical millisecond RFC 3339 UTC.
    for bad_t in [
        json!("2026-05-01T00:00:00Z"),          // no millis
        json!("2026-05-01T00:00:00.000+00:00"), // offset spelling
        json!("2026-05-01"),                    // date only
        json!(1_777_000_000),                   // epoch number
    ] {
        let mut body = golden_body();
        body.metadata.as_mut().unwrap()["compromised_since"] = bad_t.clone();
        assert!(
            matches!(
                KeyRevocation::from_body(&body),
                Err(AcdpError::SchemaViolation(_))
            ),
            "compromised_since {bad_t} must be rejected"
        );
    }

    // reason capped at 1024 characters.
    let mut body = golden_body();
    body.metadata.as_mut().unwrap()["reason"] = json!("x".repeat(1025));
    assert!(matches!(
        KeyRevocation::from_body(&body),
        Err(AcdpError::SchemaViolation(_))
    ));

    // revoked_key_controller present-and-equal is the explicit
    // producer-signed binding (§5 rule 3) — accepted.
    let mut body = golden_body();
    body.metadata.as_mut().unwrap()["revoked_key_controller"] = json!(PRODUCER_DID);
    let rev = KeyRevocation::from_body(&body).unwrap();
    assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);
}

/// Cross-check the inline constants against the canonical spec fixture
/// and execute the fixture's own vector end-to-end. Skips when the spec
/// checkout is absent; hard-fails under ACDP_REQUIRE_CONFORMANCE.
#[test]
fn rev_001_fixture_file_cross_check() {
    let require = std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok();
    let Some(root) = spec_root() else {
        assert!(!require, "ACDP_REQUIRE_CONFORMANCE set but spec not found");
        eprintln!("ACDP spec not found; skipping rev-001 fixture cross-check");
        return;
    };
    let path = root.join("schemas/conformance/rev-001-revocation-context-golden.json");
    if !path.exists() {
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE set but {} is missing",
            path.display()
        );
        eprintln!("rev-001 fixture not present; skipping");
        return;
    }
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

    // Keypair constants.
    assert_eq!(v["test_keypair"]["private_seed_hex"], hex::encode(K2_SEED));
    assert_eq!(v["test_keypair"]["public_key_hex"], K2_PUB_HEX);
    assert_eq!(v["test_keypair"]["key_fingerprint"], K2_FP);
    assert_eq!(v["revoked_key"]["public_key_hex"], K1_PUB_HEX);
    assert_eq!(v["revoked_key"]["key_fingerprint"], K1_FP);

    let vector = &v["vectors"][0];

    // Execute the vector from the fixture's own producer_content.
    let pc = &vector["producer_content"];
    let canonical = canonicalize_value(pc);
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        vector["expected"]["canonical_form"].as_str().unwrap()
    );
    let hash = compute_content_hash(pc).unwrap();
    assert_eq!(
        hash.as_str(),
        vector["expected"]["content_hash"].as_str().unwrap()
    );
    let sig = SigningKey::from_bytes(&K2_SEED).sign_content_hash(&hash);
    assert_eq!(
        sig,
        vector["expected"]["signature_value_base64"]
            .as_str()
            .unwrap()
    );

    // The fixture's expected values equal our inline pins.
    assert_eq!(vector["expected"]["canonical_form"], EXPECTED_CANONICAL);
    assert_eq!(vector["expected"]["content_hash"], EXPECTED_CONTENT_HASH);
    assert_eq!(
        vector["expected"]["signature_value_base64"],
        EXPECTED_SIGNATURE_B64
    );
    assert_eq!(
        vector["expected"]["signature_value_hex"],
        EXPECTED_SIGNATURE_HEX
    );

    // The fixture's full publish_request_body round-trips through the
    // typed PublishRequest (this requires ContextType to accept the
    // standard `key-revocation` value).
    let req: acdp::types::PublishRequest =
        serde_json::from_value(vector["expected"]["publish_request_body"].clone()).unwrap();
    assert_eq!(req.context_type, ContextType::KeyRevocation);
    assert_eq!(req.content_hash.as_str(), EXPECTED_CONTENT_HASH);
}

fn spec_root() -> Option<PathBuf> {
    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
    }
    let sibling = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("agentcontextdistributionprotocol");
    sibling.exists().then_some(sibling)
}

// ── rev-002: §7 boundary matrix (pure classification) ───────────────────────

fn golden_revocation() -> KeyRevocation {
    KeyRevocation::from_body(&golden_body()).unwrap()
}

/// Scenario A — receipt-attested publish time strictly before T:
/// historically authorized (pre-compromise, receipt-attested), and the
/// status is distinguishable from every other verdict.
#[test]
fn rev_002_a_before_t_is_pre_compromise_historical() {
    let verdict = classify_under_revocation(&[golden_revocation()], K1_FP, Some(at(BEFORE_T)))
        .unwrap()
        .expect("the revocation names K1 — it must produce a verdict");
    assert_eq!(
        verdict,
        KeyAuthorization::HistoricallyAuthorizedPreCompromise
    );
    // MUST NOT be reported as fully current, and MUST NOT be reported
    // identically to the no-revocation rot-001 A status.
    assert_ne!(verdict, KeyAuthorization::CurrentlyAuthorized);
    assert_ne!(verdict, KeyAuthorization::HistoricallyAuthorized);
}

/// Scenario B — at or after T: fail closed despite the valid receipt.
#[test]
fn rev_002_b_at_or_after_t_fails_closed() {
    for when in [AFTER_T, T] {
        let err = classify_under_revocation(&[golden_revocation()], K1_FP, Some(at(when)))
            .expect_err("at/after the boundary must fail closed");
        assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
    }
}

/// Scenario C — no receipt: the publish time is unverifiable and the
/// strict profile fails closed (the bare body created_at MUST NOT be
/// used — there is no parameter through which to pass it).
#[test]
fn rev_002_c_unverifiable_time_fails_closed() {
    let err = classify_under_revocation(&[golden_revocation()], K1_FP, None)
        .expect_err("receipt-less revoked-key context must fail closed under strict");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// Scenario D — trust classes are distinguishable: the same statement
/// arriving as a registry-attested context is classified
/// registry-attested, never collapsed into producer-signed; and a
/// K1-self-signed "revocation" is unverified, triggering none of §7.
#[test]
fn rev_002_d_trust_classes_distinguishable() {
    // Registry-attested form: agent_id is the registry,
    // revoked_key_controller (REQUIRED here) names the producer.
    let mut body = golden_body();
    body.agent_id = AgentDid::new("did:web:registry.example.com");
    body.signature.key_id = "did:web:registry.example.com#receipt-key-1".into();
    body.metadata.as_mut().unwrap()["revoked_key_controller"] = json!(PRODUCER_DID);
    let registry_attested = KeyRevocation::from_body(&body).unwrap();
    assert_eq!(
        registry_attested.trust_class,
        RevocationTrustClass::RegistryAttested
    );
    assert_eq!(
        registry_attested.revoked_key_controller.as_str(),
        PRODUCER_DID
    );
    assert_eq!(
        registry_attested.publisher.as_str(),
        "did:web:registry.example.com"
    );

    let producer_signed = golden_revocation();
    assert_eq!(
        producer_signed.trust_class,
        RevocationTrustClass::ProducerSigned
    );
    assert_ne!(
        producer_signed.trust_class, registry_attested.trust_class,
        "the classes MUST NOT be collapsed (RFC-ACDP-0014 §6)"
    );

    // A "revocation" signed by K1 itself: §5 step 2 rejects it before
    // it can ever enter the §7 classifier.
    let err = producer_signed.check_not_self_signed(K1_FP).unwrap_err();
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// §4 earliest-T monotonicity across a revocation lineage: a
/// supersession can widen but never quietly shrink the window.
#[test]
fn rev_002_earliest_boundary_across_lineage() {
    let head = golden_revocation();
    // A superseding revocation that moved T EARLIER (widening).
    let mut widened = head.clone();
    widened.compromised_since = at("2026-04-01T00:00:00.000Z");
    let lineage = [head, widened];

    // A publish time before the head's T but after the widened T is
    // inside the effective window.
    let err = classify_under_revocation(&lineage, K1_FP, Some(at(BEFORE_T)))
        .expect_err("the earliest compromised_since across the lineage is effective");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // Strictly before both boundaries still verifies.
    assert_eq!(
        classify_under_revocation(&lineage, K1_FP, Some(at("2026-03-01T00:00:00.000Z"))).unwrap(),
        Some(KeyAuthorization::HistoricallyAuthorizedPreCompromise)
    );
}

// ── §5 pipeline: verify_revocation_body over an offline did:key body ────────

/// A did:key producer CAN issue a producer-signed revocation for some
/// *other* key's fingerprint; the full §5 pipeline verifies it with no
/// network (pure did:key resolution).
#[tokio::test]
async fn verify_revocation_body_did_key_offline() {
    let producer = Producer::new_did_key(SigningKey::from_bytes(&[9u8; 32]));
    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title(TITLE)
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(revocation_metadata()) // revokes K1's fingerprint
        .build()
        .unwrap();
    let body = Body::from_publish_request(
        &req,
        CtxId(REGISTRY_ASSIGNED_CTX_ID.into()),
        LineageId(REGISTRY_ASSIGNED_LINEAGE.into()),
        "registry.example.com",
        at("2026-05-02T08:00:00.000Z"),
    );

    let resolver = WebResolver::new();
    let rev = verify_revocation_body(&body, &resolver)
        .await
        .expect("did:key revocation of a different key must verify offline");
    assert_eq!(rev.revoked_key_fingerprint, K1_FP);
    assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);

    // Tampering with the boundary breaks the content hash → the §5
    // pipeline rejects before the shape is ever consulted.
    let mut tampered = body;
    tampered.metadata.as_mut().unwrap()["compromised_since"] = json!("2026-06-01T00:00:00.000Z");
    assert!(verify_revocation_body(&tampered, &resolver).await.is_err());
}

// ── rev-002 end-to-end: the fetch pipeline honors RevocationPolicy ──────────

const REGISTRY_AUTHORITY: &str = "localhost";
const REGISTRY_DID: &str = "did:web:localhost";
const LOCAL_PRODUCER_DID: &str = "did:web:localhost:agent";

fn caps() -> acdp::types::CapabilitiesDocument {
    use acdp::types::capabilities::Limits;
    acdp::types::CapabilitiesDocument {
        acdp_version: "0.2.0".into(),
        registry_did: REGISTRY_DID.into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into(), "did:key".into()],
        profiles: vec!["acdp-registry-core".into()],
        limits: Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            idempotency_key_ttl_seconds: None,
            max_publish_per_minute: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key: false,
        extensions: Default::default(),
    }
}

struct Harness {
    tls: TlsTestServer,
    context_json: Arc<RwLock<Option<serde_json::Value>>>,
    resolver: WebResolver,
}
async fn start_harness(registry_receipt_pub: &[u8; 32], producer_pub: &[u8; 32]) -> Harness {
    let registry_doc = ed25519_did_doc(REGISTRY_DID, "receipt-key-1", registry_receipt_pub);
    let producer_doc = ed25519_did_doc(LOCAL_PRODUCER_DID, "key-1", producer_pub);
    let context_json: Arc<RwLock<Option<serde_json::Value>>> = Arc::new(RwLock::new(None));

    let router = Router::new()
        .route(
            "/.well-known/did.json",
            get(move || {
                let doc = registry_doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/agent/did.json",
            get(move || {
                let doc = producer_doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/contexts/:id",
            get({
                let ctx = context_json.clone();
                move || {
                    let ctx = ctx.clone();
                    async move {
                        Json(
                            ctx.read()
                                .unwrap()
                                .clone()
                                .expect("context not yet published"),
                        )
                    }
                }
            }),
        );

    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    Harness {
        tls,
        context_json,
        resolver,
    }
}

impl Harness {
    fn client(&self) -> RegistryClient {
        RegistryClient::with_test_endpoint(
            &format!("https://{REGISTRY_AUTHORITY}"),
            self.tls.addr,
            &self.tls.root_cert_pem,
        )
        .expect("pinned client")
    }
}

/// Publish through a receipt-minting in-process registry; the receipt's
/// `created_at` (mint time = now) is the receipt-attested publish time
/// the §7 boundary is compared against.
async fn publish_with_receipt(h: &Harness, producer_key: SigningKey) -> (CtxId, serde_json::Value) {
    let server = RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY)
        .expect("server")
        .with_receipt_signer(
            ReceiptSigner::new(
                SigningKey::from_bytes(&[0x11u8; 32]),
                REGISTRY_DID,
                format!("{REGISTRY_DID}#receipt-key-1"),
            )
            .expect("signer"),
        )
        .expect("receipt signer accepted");

    let producer = Producer::new(
        producer_key,
        AgentDid::new(LOCAL_PRODUCER_DID),
        format!("{LOCAL_PRODUCER_DID}#key-1"),
    );
    let req = producer
        .publish_request()
        .title("context signed by the soon-to-be-revoked key")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("build");

    let resp = server
        .publish_verified(&req, None, &h.resolver)
        .await
        .expect("publish with receipt minting");
    let full = server
        .store()
        .get(&resp.ctx_id)
        .expect("get")
        .expect("present");
    (resp.ctx_id, serde_json::to_value(&full).expect("serialize"))
}

/// A verified producer-signed revocation of the harness producer key,
/// with boundary T.
fn local_revocation(producer_fp: &str, t: DateTime<Utc>) -> KeyRevocation {
    KeyRevocation {
        revoked_key_fingerprint: producer_fp.into(),
        compromised_since: acdp::time::trunc_ms(t),
        reason: Some("test compromise".into()),
        revoked_key_id: Some(format!("{LOCAL_PRODUCER_DID}#key-1")),
        revoked_key_controller: AgentDid::new(LOCAL_PRODUCER_DID),
        publisher: AgentDid::new(LOCAL_PRODUCER_DID),
        trust_class: RevocationTrustClass::ProducerSigned,
    }
}

/// rev-002 through the real retrieval pipeline: pre-T receipt →
/// pre-compromise historical; post/at-T → fail closed; no verified
/// receipt → fail closed. `key_status` stays `CurrentlyAuthorized`
/// when no supplied revocation names the key.
#[tokio::test]
async fn rev_002_fetch_pipeline_boundary_matrix() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let producer_fp = fingerprint_ed25519(&producer_pub);
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json) = publish_with_receipt(&h, producer_key).await;
    *h.context_json.write().unwrap() = Some(ctx_json.clone());
    let client = h.client();

    let policy_with = |revs: Vec<KeyRevocation>, receipts: ReceiptPolicy| VerificationPolicy {
        receipts,
        revocations: RevocationPolicy { known: revs },
        ..Default::default()
    };

    // No revocation supplied: unchanged 0.2 behavior.
    let verified = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect("baseline fetch");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    let receipt_time = verified.verified_receipt().expect("receipt").created_at;

    // A: boundary strictly after the receipt-attested publish time →
    // historically authorized (pre-compromise, receipt-attested), even
    // though the key is still in assertionMethod.
    let pre = policy_with(
        vec![local_revocation(
            &producer_fp,
            receipt_time + chrono::Duration::days(1),
        )],
        ReceiptPolicy::VerifyIfPresent,
    );
    let verified = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &pre)
        .await
        .expect("pre-compromise context must verify");
    assert_eq!(
        verified.key_status(),
        KeyAuthorization::HistoricallyAuthorizedPreCompromise
    );

    // B: boundary at/before the receipt-attested publish time → fail
    // closed despite the valid receipt.
    for boundary in [receipt_time, receipt_time - chrono::Duration::days(1)] {
        let post = policy_with(
            vec![local_revocation(&producer_fp, boundary)],
            ReceiptPolicy::VerifyIfPresent,
        );
        let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &post)
            .await
            .expect_err("inside the compromise window must fail closed");
        assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
    }

    // C: no verified receipt → publish time unverifiable → fail closed,
    // whether the receipt is absent…
    let mut stripped = ctx_json.clone();
    stripped.as_object_mut().unwrap().remove("registry_receipt");
    *h.context_json.write().unwrap() = Some(stripped);
    let future_boundary = policy_with(
        vec![local_revocation(
            &producer_fp,
            receipt_time + chrono::Duration::days(1),
        )],
        ReceiptPolicy::VerifyIfPresent,
    );
    let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &future_boundary)
        .await
        .expect_err("receipt-less revoked-key context must fail closed");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // …or present but unverified because policy ignores receipts.
    *h.context_json.write().unwrap() = Some(ctx_json.clone());
    let ignoring = policy_with(
        vec![local_revocation(
            &producer_fp,
            receipt_time + chrono::Duration::days(1),
        )],
        ReceiptPolicy::Ignore,
    );
    let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &ignoring)
        .await
        .expect_err("an unverified receipt provides no publish time");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // A revocation of some OTHER key leaves this context fully current.
    let unrelated = policy_with(
        vec![local_revocation(
            K1_FP,
            receipt_time - chrono::Duration::days(30),
        )],
        ReceiptPolicy::VerifyIfPresent,
    );
    let verified = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &unrelated)
        .await
        .expect("unrelated revocation is inert");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
}

// ── §8 discovery: find_revocations over a searchable harness ────────────────

/// `find_revocations` returns the producer's verified revocations and
/// silently skips candidates that fail §5 — here a "revocation" signed
/// by the very key it revokes, which is at most a hint (§5 step 2).
#[tokio::test]
async fn find_revocations_returns_only_verified() {
    use acdp::client::find_revocations;
    use std::collections::HashMap;

    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let producer_fp = fingerprint_ed25519(&producer_pub);
    let producer_doc = ed25519_did_doc(LOCAL_PRODUCER_DID, "key-1", &producer_pub);

    // Stand up DID hosting first — publish-side verification resolves
    // the producer document through it.
    let did_router = Router::new().route(
        "/agent/did.json",
        get(move || {
            let doc = producer_doc.clone();
            async move { Json(doc) }
        }),
    );

    // Publish both candidates through the real registry server so the
    // served bodies are genuine (hash + signature valid for BOTH — the
    // self-signed one is cryptographically fine; §5 is what rejects it).
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY).expect("server");
    let make_producer = |seed: [u8; 32]| {
        Producer::new(
            SigningKey::from_bytes(&seed),
            AgentDid::new(LOCAL_PRODUCER_DID),
            format!("{LOCAL_PRODUCER_DID}#key-1"),
        )
    };
    let good_req = make_producer([7u8; 32])
        .publish_request()
        .acdp_version("0.3.0")
        .title("revocation of the old key")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(revocation_metadata()) // revokes K1's fingerprint
        .build()
        .unwrap();
    let self_signed_req = make_producer([7u8; 32])
        .publish_request()
        .acdp_version("0.3.0")
        .title("self-signed non-revocation")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            // Revokes the very key that signs it: §5 step 2.
            "revoked_key_fingerprint": producer_fp,
            "compromised_since": T,
        }))
        .build()
        .unwrap();

    let tls_did = TlsTestServer::start(did_router).await;
    let resolver =
        WebResolver::with_test_endpoint(&tls_did.root_cert_pem, "localhost", tls_did.addr)
            .expect("pinned resolver");

    let mut contexts: HashMap<String, serde_json::Value> = HashMap::new();
    let mut matches = Vec::new();
    for req in [&good_req, &self_signed_req] {
        let resp = server
            .publish_verified(req, None, &resolver)
            .await
            .expect("publish");
        let full = server
            .store()
            .get(&resp.ctx_id)
            .expect("get")
            .expect("present");
        matches.push(json!({
            "ctx_id": full.body.ctx_id.as_str(),
            "lineage_id": full.body.lineage_id.as_str(),
            "agent_id": LOCAL_PRODUCER_DID,
            "title": full.body.title,
            "type": "key-revocation",
            "created_at": "2026-05-02T08:00:00.000Z",
            "status": "active",
            "visibility": "public",
        }));
        contexts.insert(
            full.body.ctx_id.as_str().to_string(),
            serde_json::to_value(&full).unwrap(),
        );
    }

    // Serve search + retrieval + DID hosting from one harness.
    let search_body = json!({ "matches": matches });
    let contexts = Arc::new(contexts);
    let full_router = Router::new()
        .route(
            "/agent/did.json",
            get({
                let doc = ed25519_did_doc(LOCAL_PRODUCER_DID, "key-1", &producer_pub);
                move || {
                    let doc = doc.clone();
                    async move { Json(doc) }
                }
            }),
        )
        .route(
            "/contexts/search",
            get(move || {
                let body = search_body.clone();
                async move { Json(body) }
            }),
        )
        .route(
            "/contexts/:id",
            get({
                let contexts = contexts.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let contexts = contexts.clone();
                    async move { Json(contexts.get(&id).cloned().expect("known ctx_id")) }
                }
            }),
        );
    let tls = TlsTestServer::start(full_router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let revs = find_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
        .await
        .expect("discovery");
    assert_eq!(
        revs.len(),
        1,
        "exactly the verified revocation; the self-signed candidate is skipped, \
         and the four search passes (type forms × statuses) dedupe by ctx_id"
    );
    assert_eq!(revs[0].revoked_key_fingerprint, K1_FP);
    assert_eq!(revs[0].trust_class, RevocationTrustClass::ProducerSigned);
    assert_eq!(revs[0].publisher.as_str(), LOCAL_PRODUCER_DID);
}
