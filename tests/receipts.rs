//! Registry receipts (ACDP 0.2, RFC-ACDP-0010) — end-to-end tests.
//!
//! Covers the rcpt-001..004 fixture behaviors plus the WS-B
//! historical-key path (rot-001): publish over an in-process TLS
//! registry with a receipt signer, retrieve + verify through the full
//! client pipeline, rotate the producer key, and confirm the receipt
//! is what keeps history verifiable — and that everything fails closed
//! without it.

mod common;

use std::sync::{Arc, RwLock};

use acdp::client::{
    HistoricalKeyPolicy, KeyAuthorization, ReceiptPolicy, RegistryClient, VerificationPolicy,
    VerifiedContext,
};
use acdp::crypto::SigningKey;
use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::{InMemoryStore, RegistryServer, RegistryStore as _};
use acdp::types::receipt::{ReceiptSigner, RegistryReceipt};
use acdp::types::{AgentDid, CapabilitiesDocument, ContextType, CtxId, LineageId, Visibility};
use axum::{routing::get, Json, Router};
use common::{ed25519_did_doc, ed25519_did_doc_without_assertion, TlsTestServer};

const REGISTRY_AUTHORITY: &str = "localhost";
const REGISTRY_DID: &str = "did:web:localhost";
const PRODUCER_DID: &str = "did:web:localhost:agent";

fn caps() -> CapabilitiesDocument {
    use acdp::types::capabilities::Limits;
    CapabilitiesDocument {
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

/// Shared-state harness: one TLS server hosting the registry DID
/// document, a mutable producer DID document, and a mutable retrieval
/// endpoint for the published context.
struct Harness {
    tls: TlsTestServer,
    producer_doc: Arc<RwLock<serde_json::Value>>,
    context_json: Arc<RwLock<Option<serde_json::Value>>>,
    capabilities_json: Arc<RwLock<serde_json::Value>>,
    resolver: WebResolver,
}
async fn start_harness(registry_receipt_pub: &[u8; 32], producer_pub: &[u8; 32]) -> Harness {
    let registry_doc = ed25519_did_doc(REGISTRY_DID, "receipt-key-1", registry_receipt_pub);
    let producer_doc = Arc::new(RwLock::new(ed25519_did_doc(
        PRODUCER_DID,
        "key-1",
        producer_pub,
    )));
    let context_json: Arc<RwLock<Option<serde_json::Value>>> = Arc::new(RwLock::new(None));
    let capabilities_json = Arc::new(RwLock::new(serde_json::to_value(caps()).unwrap()));

    let router = Router::new()
        .route(
            "/.well-known/acdp.json",
            get({
                let caps = capabilities_json.clone();
                move || {
                    let caps = caps.clone();
                    async move { Json(caps.read().unwrap().clone()) }
                }
            }),
        )
        .route(
            "/.well-known/did.json",
            get(move || {
                let doc = registry_doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/agent/did.json",
            get({
                let doc = producer_doc.clone();
                move || {
                    let doc = doc.clone();
                    async move { Json(doc.read().unwrap().clone()) }
                }
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
        producer_doc,
        context_json,
        capabilities_json,
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

    fn rotate_producer_key_out(&self, old_pub: &[u8; 32]) {
        // Rotation per the RFC-ACDP-0010 retention rule: the old key
        // stays in verificationMethod, leaves assertionMethod.
        *self.producer_doc.write().unwrap() =
            ed25519_did_doc_without_assertion(PRODUCER_DID, "key-1", old_pub);
        self.resolver.invalidate(PRODUCER_DID);
    }

    fn serve_context(&self, value: serde_json::Value) {
        *self.context_json.write().unwrap() = Some(value);
    }

    fn advertise_profiles(&self, profiles: &[&str]) {
        self.capabilities_json.write().unwrap()["profiles"] = serde_json::json!(profiles);
    }
}

/// Publish through the receipt-minting server and return
/// `(ctx_id, full_context_json, response_receipt)`.
async fn publish_with_receipts(
    h: &Harness,
    producer_key: SigningKey,
) -> (CtxId, serde_json::Value, serde_json::Value) {
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
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#key-1"),
    );
    let req = producer
        .publish_request()
        .title("receipted context")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("build");

    let resp = server
        .publish_verified(&req, None, &h.resolver)
        .await
        .expect("publish with receipt minting");
    let receipt = resp
        .registry_receipt
        .clone()
        .expect("response must carry a receipt");

    let full = server
        .store()
        .get(&resp.ctx_id)
        .expect("store get")
        .expect("present");
    assert!(
        full.registry_receipt.is_some(),
        "persisted context must carry the receipt atomically"
    );
    let ctx_json = serde_json::to_value(&full).expect("serialize");
    (resp.ctx_id, ctx_json, receipt)
}

// ── Happy path: publish → receipt → fetch + verify ──────────────────────────

#[tokio::test]
async fn receipt_minted_verified_end_to_end() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json, response_receipt) = publish_with_receipts(&h, producer_key).await;

    // The response receipt parses, cross-checks, and verifies against
    // the registry key directly (pure path).
    let typed = RegistryReceipt::from_value(&response_receipt).expect("typed receipt");
    assert_eq!(typed.registry_did, REGISTRY_DID);
    assert_eq!(typed.ctx_id, ctx_id);
    typed
        .verify_signature_with_key(Some(&registry_key_pub), None)
        .expect("receipt signature");

    // Full client pipeline, default policy (VerifyIfPresent).
    h.serve_context(ctx_json);
    let client = h.client();
    let verified = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect("fetch + verify with receipt");
    assert_eq!(verified.key_status, KeyAuthorization::CurrentlyAuthorized);
    let vr = verified
        .verified_receipt
        .as_ref()
        .expect("receipt verified");
    assert_eq!(vr.ctx_id, ctx_id);
    assert_eq!(vr.content_hash, verified.body().content_hash);

    // Require policy also passes when the receipt is present.
    let strict = VerificationPolicy {
        receipts: ReceiptPolicy::Require,
        ..Default::default()
    };
    VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &strict)
        .await
        .expect("Require passes with a verified receipt");
}

// ── Require fails closed without a receipt ──────────────────────────────────

#[tokio::test]
async fn require_policy_fails_without_receipt() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, mut ctx_json, _) = publish_with_receipts(&h, producer_key).await;

    // Strip the receipt — a 0.1.0-mode response.
    ctx_json.as_object_mut().unwrap().remove("registry_receipt");
    h.serve_context(ctx_json);

    let client = h.client();
    // Default (VerifyIfPresent): absence is fine.
    VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect("VerifyIfPresent tolerates absence");

    // Require: fail closed.
    let strict = VerificationPolicy {
        receipts: ReceiptPolicy::Require,
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &strict)
        .await
        .expect_err("Require must fail without a receipt");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");
}

// ── rcpt-002: tampered receipt rejected ──────────────────────────────────────

#[tokio::test]
async fn tampered_receipt_rejected() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, mut ctx_json, _) = publish_with_receipts(&h, producer_key).await;

    // Backdate created_at inside the served receipt — the signature
    // no longer covers the mutated bytes.
    ctx_json["registry_receipt"]["created_at"] = serde_json::json!("2020-01-01T00:00:00.000Z");
    h.serve_context(ctx_json);

    let client = h.client();
    let err = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect_err("tampered receipt must be rejected");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");
}

// ── rot-001: historical key accepted via receipt, fails closed without ──────

#[tokio::test]
async fn rotated_key_verifies_historically_via_receipt() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json, _) = publish_with_receipts(&h, producer_key).await;
    h.serve_context(ctx_json.clone());

    // Rotate: key-1 leaves assertionMethod, stays in verificationMethod.
    h.rotate_producer_key_out(&producer_pub);

    let client = h.client();

    // Default policy: receipt attests the fingerprint → historically
    // authorized.
    let verified = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect("receipt-attested historical key must verify");
    assert_eq!(
        verified.key_status,
        KeyAuthorization::HistoricallyAuthorized
    );
    assert!(verified.verified_receipt.is_some());

    // Strict policy: historical keys rejected outright.
    let strict = VerificationPolicy {
        historical_keys: HistoricalKeyPolicy::Reject,
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &strict)
        .await
        .expect_err("Reject policy must refuse rotated-out keys");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // No receipt → the historical path never activates (fail closed).
    let mut stripped = ctx_json;
    stripped.as_object_mut().unwrap().remove("registry_receipt");
    h.serve_context(stripped);
    let err = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect_err("historical acceptance without a receipt must fail closed");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

// ── did:key producers get receipts too (offline server path) ────────────────

#[test]
fn did_key_publish_mints_receipt_offline() {
    let mut c = caps();
    c.registry_did = "did:web:registry.example.com".into();
    let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com")
        .with_receipt_signer(
            ReceiptSigner::new(
                SigningKey::from_bytes(&[0x11u8; 32]),
                "did:web:registry.example.com",
                "did:web:registry.example.com#receipt-key-1",
            )
            .unwrap(),
        )
        .unwrap();

    let producer = Producer::new_did_key(SigningKey::from_bytes(&[9u8; 32]));
    let expected_fp = acdp::crypto::fingerprint_ed25519(
        &SigningKey::from_bytes(&[9u8; 32]).verifying_key_bytes(),
    );
    let req = producer
        .publish_request()
        .title("did:key + receipt")
        .context_type(ContextType::DataSnapshot)
        .build()
        .unwrap();

    let resp = server.publish_verified_did_key(&req, None).unwrap();
    let receipt =
        RegistryReceipt::from_value(&resp.registry_receipt.expect("receipt minted")).unwrap();
    assert_eq!(
        receipt.key_fingerprint, expected_fp,
        "did:key receipt fingerprint must derive from the DID's own key"
    );
    receipt
        .verify_signature_with_key(
            Some(&SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes()),
            None,
        )
        .unwrap();
    receipt
        .cross_check(&resp.ctx_id, &req.content_hash, &expected_fp)
        .unwrap();
}

// ── rcpt-001 golden vector (deterministic mint) ──────────────────────────────

/// Pins the canonical `rcpt-001-receipt-golden.json` spec fixture:
/// registry seed 0x11×32, the sig-001 producer key fingerprint, and
/// the spec's fixed identifiers/timestamp. If the signature or
/// preimage hash drifts, the receipt wire format is broken.
#[test]
fn rcpt_001_golden_vector() {
    let signer = ReceiptSigner::new(
        SigningKey::from_bytes(&[0x11u8; 32]),
        "did:web:registry.example.com",
        "did:web:registry.example.com#receipt-key-1",
    )
    .unwrap();
    let receipt = signer
        .mint(
            &CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into()),
            &LineageId(
                "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a"
                    .into(),
            ),
            "registry.example.com",
            chrono::DateTime::parse_from_rfc3339("2026-04-16T10:30:15.123Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            &acdp::types::ContentHash(
                "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
            ),
            "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
        )
        .unwrap();

    assert_eq!(
        receipt.preimage_hash().unwrap().as_str(),
        RCPT_001_PREIMAGE_HASH
    );
    assert_eq!(receipt.signature.value, RCPT_001_SIGNATURE);

    let registry_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();
    receipt
        .verify_signature_with_key(Some(&registry_pub), None)
        .unwrap();
}

const RCPT_001_PREIMAGE_HASH: &str =
    "sha256:9deaa52778ad3b6be27a96d607c3017e9e11442905891a8972f34d8c2dbca9cf";
const RCPT_001_SIGNATURE: &str =
    "vBgQKmn17pHXXY95C07BBeconmjDIdYIvxN5B+YXrQ7tIzFsDNsh1TglzgxOyPUp8lwTz7zwMNiK+Sn5whveDg==";

// ── fed-009 — federated resolution vs receipts-advertising upstreams ────────

/// fed-009: a `CrossRegistryResolver` resolving from an upstream that
/// advertises `acdp-registry-receipts` MUST treat a missing receipt as
/// `invalid_receipt` (RFC-ACDP-0010 §7: no degraded mode); a present
/// receipt is verified against the REMOTE authority; an upstream that
/// does not advertise the profile resolves receipt-lessly under the
/// v0.1.0 trust model.
#[tokio::test]
async fn fed_009_missing_receipt_from_advertising_upstream_fails() {
    use acdp::client::CrossRegistryResolver;

    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json, _) = publish_with_receipts(&h, producer_key).await;

    let make_resolver = || {
        let r = CrossRegistryResolver::new().with_did_resolver(
            WebResolver::with_test_endpoint(&h.tls.root_cert_pem, "localhost", h.tls.addr).unwrap(),
        );
        r.seed_client(REGISTRY_AUTHORITY, h.client());
        r
    };

    // Case 1: advertising upstream + receipt present → success, receipt
    // verified against the remote authority.
    h.advertise_profiles(&["acdp-registry-core", "acdp-registry-receipts"]);
    h.serve_context(ctx_json.clone());
    let verified = make_resolver()
        .resolve(&ctx_id)
        .await
        .expect("advertising upstream with a valid receipt must resolve");
    assert!(verified.verified_receipt.is_some());

    // Case 2: advertising upstream + NO receipt → invalid_receipt
    // (registry fault, not degraded mode).
    let mut stripped = ctx_json.clone();
    stripped.as_object_mut().unwrap().remove("registry_receipt");
    h.serve_context(stripped.clone());
    let err = make_resolver()
        .resolve(&ctx_id)
        .await
        .expect_err("missing receipt from an advertising upstream is a fault");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");

    // Case 3: non-advertising upstream + no receipt → success under the
    // v0.1.0 trust model.
    h.advertise_profiles(&["acdp-registry-core"]);
    h.serve_context(stripped);
    let verified = make_resolver()
        .resolve(&ctx_id)
        .await
        .expect("receipt-less upstream without the profile must resolve");
    assert!(verified.verified_receipt.is_none());
}
