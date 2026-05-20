//! Logical registry handler (feature = "server").
//!
//! Wires [`PublishValidator`] together with a [`RegistryStore`] backend
//! to provide the seven core registry operations enumerated in
//! RFC-ACDP-0003 §2.1 and RFC-ACDP-0005:
//!
//! - capabilities — return the [`CapabilitiesDocument`].
//! - publish — validate, verify signature, assign identifiers, persist.
//! - retrieve — fetch a stored body + registry_state (visibility-filtered).
//! - retrieve_body — fetch just the body (visibility-filtered).
//! - lineage / current — lineage graph queries.
//! - search — keyword + filter projection (visibility-filtered).
//!
//! This is the building block an HTTP-binding layer can sit on top of;
//! the integration tests in this crate exercise it directly without
//! mocking.
//!
//! # Conformant publish
//!
//! [`RegistryServer::publish_verified`] runs the full RFC-ACDP-0003 §2.1
//! algorithm — structural validation, hash recomputation, DID resolution,
//! signature verification — before persistence. It requires the `client`
//! feature for [`crate::did::WebResolver`].
//!
//! [`RegistryServer::publish_unverified_for_tests`] performs only steps
//! 1–6 (skipping DID resolution + signature verification) and is
//! intentionally **not** RFC-conformant; use only in tests where DID
//! resolution would require a live network or mock server.

use crate::error::AcdpError;
use crate::registry::rate_limit::{NoopRateLimiter, RateLimiter};
use crate::registry::store::RegistryStore;
use crate::registry::validator::PublishValidator;
use crate::types::{
    body::{Body, FullContext},
    capabilities::CapabilitiesDocument,
    primitives::{AgentDid, CtxId, LineageId, Status, Visibility},
    publish::{PublishRequest, PublishResponse},
    search::{SearchParams, SearchResponse},
};

/// Logical registry handler over an arbitrary [`RegistryStore`].
///
/// `L` is the rate-limiting policy (RFC-ACDP-0008 §4.3). The default
/// [`NoopRateLimiter`] accepts every publish; operators that need a
/// real limiter construct via [`Self::with_rate_limiter`].
pub struct RegistryServer<S: RegistryStore, L: RateLimiter = NoopRateLimiter> {
    store: S,
    caps: CapabilitiesDocument,
    authority: String,
    rate_limiter: L,
}

impl<S: RegistryStore> RegistryServer<S, NoopRateLimiter> {
    /// Unchecked constructor. Skips capabilities and DID-authority binding
    /// validation; prefer [`Self::try_new`] in production. Retained for
    /// tests that build a server from known-good fixtures.
    #[doc(hidden)]
    pub fn new(store: S, caps: CapabilitiesDocument, authority: impl Into<String>) -> Self {
        Self {
            store,
            caps,
            authority: authority.into(),
            rate_limiter: NoopRateLimiter,
        }
    }

    /// Production constructor.
    ///
    /// Validates capabilities against RFC-ACDP-0007 §3 and enforces that
    /// `caps.registry_did` equals `did:web:<authority>` (per
    /// RFC-ACDP-0006 §4.1 step 3 — the registry's DID document binds it
    /// to the authority it claims).
    pub fn try_new(
        store: S,
        caps: CapabilitiesDocument,
        authority: impl Into<String>,
    ) -> Result<Self, AcdpError> {
        let authority = authority.into();
        crate::validation::validate_capabilities(&caps)?;
        // BUG-06: percent-encode `:` in `host:port` authorities — the
        // colon is a structural separator in did:web.
        let expected_did = crate::did::authority_to_did_web(&authority);
        if caps.registry_did != expected_did {
            return Err(AcdpError::SchemaViolation(format!(
                "capabilities.registry_did '{}' does not match expected '{expected_did}' \
                 for authority '{authority}'",
                caps.registry_did
            )));
        }
        Ok(Self {
            store,
            caps,
            authority,
            rate_limiter: NoopRateLimiter,
        })
    }
}

impl<S: RegistryStore, L: RateLimiter> RegistryServer<S, L> {
    /// Replace the rate-limiting policy (RFC-ACDP-0008 §4.3).
    pub fn with_rate_limiter<L2: RateLimiter>(self, limiter: L2) -> RegistryServer<S, L2> {
        RegistryServer {
            store: self.store,
            caps: self.caps,
            authority: self.authority,
            rate_limiter: limiter,
        }
    }

    /// Borrow the underlying store. Useful for tests that want to
    /// inspect side-effects directly.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// `GET /.well-known/acdp.json`.
    pub fn capabilities(&self) -> &CapabilitiesDocument {
        &self.caps
    }

    /// **RFC-conformant publish.**
    ///
    /// Runs RFC-ACDP-0003 §2.1 steps 1–11:
    ///
    /// - **1–6.** [`PublishValidator::validate_post_schema`] — schema,
    ///   payload + embedded size, hash recomputation, algorithm /
    ///   key_id binding.
    /// - **7–8.** [`crate::crypto::verify::verify_publish_request_signature`] —
    ///   DID resolution + signature verification.
    /// - **9.** Identifier assignment (`ctx_id`, `lineage_id`).
    /// - **10.** Lineage coherence on supersession.
    /// - **11.** Persistence and predecessor supersession.
    ///
    /// Steps 7–8 require a [`crate::did::WebResolver`], so this method
    /// is gated on the `client` feature.
    #[cfg(feature = "client")]
    pub async fn publish_verified(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
        resolver: &crate::did::WebResolver,
    ) -> Result<PublishResponse, AcdpError> {
        // Rate-limit gate runs before any expensive work — RFC-ACDP-0008 §4.3.
        self.rate_limiter.check_publish(&req.agent_id)?;

        let raw_bytes = serde_json::to_vec(req)?.len();
        let validator = PublishValidator::for_authority(&self.caps, &self.authority);
        let _validated = validator.validate_post_schema(req, raw_bytes)?;

        // Steps 7–8: DID resolution + signature verification.
        crate::crypto::verify::verify_publish_request_signature(req, resolver).await?;

        // FEAT-01: hand the rest of the pipeline to the store as a
        // single atomic commit. Idempotency lookup, predecessor
        // verification, body insertion, predecessor supersession
        // marking, and idempotency record writing all happen under one
        // critical section. Two concurrent publishes against the same
        // `supersedes` (or the same `Idempotency-Key`) can no longer
        // both succeed.
        self.commit_via_store(req, idempotency_key)
    }

    /// **NOT RFC-conformant.** Skips DID resolution and signature
    /// verification (RFC-ACDP-0003 §2.1 steps 7–8).
    ///
    /// Intended for integration tests where DID resolution would require
    /// a live network or mock server. Production callers MUST use
    /// [`Self::publish_verified`].
    #[doc(hidden)]
    pub fn publish_unverified_for_tests(
        &self,
        req: &PublishRequest,
    ) -> Result<PublishResponse, AcdpError> {
        // Rate-limit gate fires here too — the limiter is intentionally
        // wired BEFORE validation so it works as a defensive cap even
        // when the test path is used.
        self.rate_limiter.check_publish(&req.agent_id)?;

        let raw_bytes = serde_json::to_vec(req)?.len();
        let validator = PublishValidator::for_authority(&self.caps, &self.authority);
        let _validated = validator.validate_post_schema(req, raw_bytes)?;
        self.commit_via_store(req, None)
    }

    /// Drive `RegistryStore::commit_publish` from a validated request.
    /// Unwraps `PublishCommitOutcome::Inserted` and `IdempotentReplay`
    /// to the same `PublishResponse` for the caller (the distinction
    /// only matters internally for logging/tracing).
    fn commit_via_store(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
    ) -> Result<PublishResponse, AcdpError> {
        let idempotency = if self.caps.supports_idempotency_key {
            idempotency_key.map(|key| crate::registry::store::PendingIdempotencyCommit {
                key,
                ttl: chrono::Duration::seconds(
                    self.caps
                        .limits
                        .idempotency_key_ttl_seconds
                        .unwrap_or(86_400) as i64,
                ),
            })
        } else {
            None
        };
        let outcome = self
            .store
            .commit_publish(crate::registry::store::PublishCommit {
                req,
                authority: &self.authority,
                idempotency,
            })?;
        Ok(match outcome {
            crate::registry::store::PublishCommitOutcome::Inserted(r)
            | crate::registry::store::PublishCommitOutcome::IdempotentReplay(r) => r,
        })
    }

    /// `GET /contexts/{ctx_id}`.
    ///
    /// Applies the RFC-ACDP-0008 §4.5 disclosure rules:
    ///
    /// | Visibility   | Authorized requester for retrieval                  |
    /// |--------------|-----------------------------------------------------|
    /// | `public`     | anyone (when `caps.anonymous_public_reads` is true) |
    /// | `restricted` | producer (`agent_id`) **or** any DID in `audience`  |
    /// | `private`    | producer (`agent_id`) **or** any DID in `audience`  |
    ///
    /// Returns `Ok(None)` (not `Err`) for unauthorized callers — prevents
    /// existence leakage via error codes.
    pub fn retrieve(
        &self,
        ctx_id: &CtxId,
        requester: Option<&AgentDid>,
    ) -> Result<Option<FullContext>, AcdpError> {
        let Some(ctx) = self.store.get(ctx_id)? else {
            return Ok(None);
        };
        if !can_retrieve(&ctx.body, requester, &self.caps) {
            return Ok(None);
        }
        Ok(Some(ctx))
    }

    /// `GET /contexts/{ctx_id}/body`. See [`Self::retrieve`] for visibility rules.
    pub fn retrieve_body(
        &self,
        ctx_id: &CtxId,
        requester: Option<&AgentDid>,
    ) -> Result<Option<Body>, AcdpError> {
        Ok(self.retrieve(ctx_id, requester)?.map(|c| c.body))
    }

    /// `GET /lineages/{lineage_id}`.
    ///
    /// BUG-03: applies the same visibility filter as `retrieve`. A
    /// caller who knows or guesses a `lineage_id` must not be able to
    /// surface restricted or private bodies through the lineage
    /// endpoint when `retrieve(ctx_id, requester)` would deny them.
    pub fn lineage(
        &self,
        lineage_id: &LineageId,
        requester: Option<&AgentDid>,
    ) -> Result<Vec<FullContext>, AcdpError> {
        let all = self.store.lineage(lineage_id)?;
        Ok(all
            .into_iter()
            .filter(|ctx| can_retrieve(&ctx.body, requester, &self.caps))
            .collect())
    }

    /// `GET /lineages/{lineage_id}/current`.
    ///
    /// BUG-03 + BUG-04: returns the newest non-`Superseded` version
    /// visible to the requester. `None` when the lineage is unknown,
    /// when every version is superseded (RFC-ACDP-0004 §5), or when no
    /// visible version exists.
    pub fn current(
        &self,
        lineage_id: &LineageId,
        requester: Option<&AgentDid>,
    ) -> Result<Option<FullContext>, AcdpError> {
        let all = self.store.lineage(lineage_id)?;
        // `lineage` returns versions ordered from v1 → vN; iterate in
        // reverse to find the newest non-superseded version. `Active`
        // and `Expired` both qualify as valid current heads (a body
        // that expired without being superseded is still the latest
        // and the consumer needs to see it to know it has lapsed).
        for ctx in all.into_iter().rev() {
            if !matches!(ctx.registry_state.status, Status::Superseded)
                && can_retrieve(&ctx.body, requester, &self.caps)
            {
                return Ok(Some(ctx));
            }
        }
        Ok(None)
    }

    /// `GET /contexts/search`.
    ///
    /// Applies the RFC-ACDP-0008 §4.5 search disclosure rules (note the
    /// asymmetry vs retrieval): private contexts surface in search only
    /// to their producer (audience members must already know the ctx_id).
    ///
    /// When `caps.anonymous_public_reads` is `false`, an anonymous search
    /// request is rejected outright with [`AcdpError::NotAuthorized`]
    /// (HTTP 403) rather than returning an empty `200`. An empty result
    /// set would still leak the registry's existence and confirm that
    /// the keyword query ran; the required response is `not_authorized`
    /// (RFC-ACDP-0005 §2.5.5, RFC-ACDP-0008 §6.3, fixture `vis-009`).
    pub fn search(
        &self,
        params: &SearchParams,
        requester: Option<&AgentDid>,
    ) -> Result<SearchResponse, AcdpError> {
        // BUG-01 + vis-009: reject anonymous search when the registry
        // does not allow anonymous reads. An empty 200 would still leak
        // the registry's existence (and that the query executed); the
        // normative response is 403 not_authorized.
        if requester.is_none() && !self.caps.anonymous_public_reads {
            return Err(AcdpError::NotAuthorized(
                "anonymous search requires authentication \
                 (registry caps: anonymous_public_reads=false)"
                    .into(),
            ));
        }
        // BUG-02: pass `anonymous_public_reads` to the store so search
        // and retrieve agree. A registry advertising the flag as false
        // MUST suppress public contexts for anonymous callers in BOTH
        // endpoints (RFC-ACDP-0008 §4.5).
        self.store
            .search(params, requester, self.caps.anonymous_public_reads)
    }
}

/// RFC-ACDP-0008 §4.5 retrieval disclosure rule.
pub(crate) fn can_retrieve(
    body: &Body,
    requester: Option<&AgentDid>,
    caps: &CapabilitiesDocument,
) -> bool {
    match body.visibility {
        Visibility::Public => caps.anonymous_public_reads || requester.is_some(),
        Visibility::Restricted | Visibility::Private => match requester {
            None => false,
            Some(r) => {
                r == &body.agent_id
                    || body
                        .audience
                        .as_deref()
                        .is_some_and(|a| a.iter().any(|d| d == r))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use crate::producer::Producer;
    use crate::registry::store::InMemoryStore;
    use crate::types::capabilities::Limits;
    use crate::types::primitives::{AgentDid, ContextType, Visibility};

    fn caps() -> CapabilitiesDocument {
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
            anonymous_public_reads: true,
            supports_idempotency_key: false,
            extensions: Default::default(),
        }
    }

    fn producer() -> Producer {
        Producer::new(
            SigningKey::from_bytes(&[1u8; 32]),
            AgentDid::new("did:web:agents.example.com:test"),
            "did:web:agents.example.com:test#key-1",
        )
    }

    #[test]
    fn publish_v1_then_retrieve() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();
        assert_eq!(resp.version, 1);
        let ctx = server.retrieve(&resp.ctx_id, None).unwrap().unwrap();
        assert_eq!(ctx.body.title, "v1");
        // Lineage round-trip
        let lineage = server.lineage(&resp.lineage_id, None).unwrap();
        assert_eq!(lineage.len(), 1);
        // Current points at the same record
        let cur = server.current(&resp.lineage_id, None).unwrap().unwrap();
        assert_eq!(cur.body.ctx_id, resp.ctx_id);
    }

    #[test]
    fn supersession_marks_predecessor_and_returns_v2() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let v1_req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v1 = server.publish_unverified_for_tests(&v1_req).unwrap();

        let v2_req = p
            .supersede(v1.ctx_id.clone())
            .version(2)
            .title("v2")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v2 = server.publish_unverified_for_tests(&v2_req).unwrap();
        assert_eq!(v2.version, 2);
        // v1 was marked superseded
        let v1_ctx = server.retrieve(&v1.ctx_id, None).unwrap().unwrap();
        assert!(matches!(
            v1_ctx.registry_state.status,
            crate::types::Status::Superseded
        ));
        // Same lineage
        assert_eq!(v1.lineage_id, v2.lineage_id);
        // Current resolves to v2
        let cur = server.current(&v1.lineage_id, None).unwrap().unwrap();
        assert_eq!(cur.body.ctx_id, v2.ctx_id);
    }

    /// FEAT-01: two concurrent publishes that both supersede the same
    /// v1 MUST resolve to exactly one success + one
    /// `SupersededTarget { AlreadySuperseded }`. The race was possible
    /// when the supersedes check, body insert, and predecessor mark
    /// lived in separate mutex acquisitions; `commit_publish` puts
    /// them under one critical section so only one of two contenders
    /// wins (RFC-ACDP-0003 §6).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_supersession_exactly_one_succeeds() {
        use std::sync::Arc;
        let server = Arc::new(RegistryServer::new(
            InMemoryStore::new(),
            caps(),
            "registry.example.com",
        ));
        let p = producer();
        let v1_req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v1 = server.publish_unverified_for_tests(&v1_req).unwrap();

        // Pre-build BOTH v2 requests up front, then fire them in
        // parallel on a multi-threaded runtime. With the prior
        // non-atomic sequence the test would fail intermittently;
        // with `commit_publish` it's deterministic.
        let v2a_req = p
            .supersede(v1.ctx_id.clone())
            .version(2)
            .title("v2-A")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v2b_req = p
            .supersede(v1.ctx_id.clone())
            .version(2)
            .title("v2-B")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let s1 = Arc::clone(&server);
        let s2 = Arc::clone(&server);
        let h1 = tokio::task::spawn_blocking(move || s1.publish_unverified_for_tests(&v2a_req));
        let h2 = tokio::task::spawn_blocking(move || s2.publish_unverified_for_tests(&v2b_req));
        let (r1, r2) = (h1.await.unwrap(), h2.await.unwrap());

        let outcomes = [r1, r2];
        let successes = outcomes.iter().filter(|r| r.is_ok()).count();
        let failures = outcomes.iter().filter(|r| r.is_err()).count();
        assert_eq!(
            successes, 1,
            "exactly one concurrent supersession MUST succeed; got {successes} successes / {failures} failures"
        );
        assert_eq!(failures, 1);
        // The loser MUST get AlreadySuperseded — the predecessor was
        // marked under the same lock the winner used.
        for r in &outcomes {
            if let Err(e) = r {
                match e {
                    AcdpError::SupersededTarget { reason, .. } => assert_eq!(
                        *reason,
                        crate::error::SupersessionReason::AlreadySuperseded,
                        "concurrent loser MUST be AlreadySuperseded"
                    ),
                    other => panic!("concurrent loser had wrong error: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn supersession_with_unknown_target_rejected_as_not_found() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let phantom =
            CtxId("acdp://registry.example.com/12345678-1234-4321-8123-deadbeefcafe".into());
        let req = p
            .supersede(phantom)
            .version(2)
            .title("v2-orphan")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let err = server.publish_unverified_for_tests(&req).unwrap_err();
        match err {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(reason, crate::error::SupersessionReason::NotFound);
            }
            other => panic!("expected SupersededTarget::NotFound, got {other:?}"),
        }
    }

    #[test]
    fn version_mismatch_rejected() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let v1_req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v1 = server.publish_unverified_for_tests(&v1_req).unwrap();
        // Build a v3 (wrong) supersession
        let v3_req = p
            .supersede(v1.ctx_id.clone())
            .version(3)
            .title("v3-skipped")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let err = server.publish_unverified_for_tests(&v3_req).unwrap_err();
        match err {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(reason, crate::error::SupersessionReason::VersionMismatch);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn search_finds_published_context() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("Q1 portfolio risk")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        server.publish_unverified_for_tests(&req).unwrap();
        let resp = server
            .search(
                &SearchParams {
                    q: Some("portfolio".into()),
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.matches[0].title, "Q1 portfolio risk");
    }

    // ── BUG-03 — lineage/current visibility filtering ──────────────────

    /// BUG-03: a stranger calling `lineage()` MUST NOT see restricted
    /// bodies they aren't on the audience for. The retrieval predicate
    /// is now mirrored here.
    #[test]
    fn lineage_filters_restricted_for_stranger() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let audience = AgentDid::new("did:web:audience.example.com:reader");
        let req = p
            .publish_request()
            .title("restricted v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![audience.clone()])
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();

        let stranger = AgentDid::new("did:web:other.example.com:reader");
        let stranger_view = server.lineage(&resp.lineage_id, Some(&stranger)).unwrap();
        assert!(
            stranger_view.is_empty(),
            "stranger MUST NOT see restricted bodies via lineage(); got {} entries",
            stranger_view.len()
        );

        let audience_view = server.lineage(&resp.lineage_id, Some(&audience)).unwrap();
        assert_eq!(
            audience_view.len(),
            1,
            "audience member MUST see the restricted body via lineage()"
        );
    }

    /// BUG-03: `current()` also filters by requester visibility.
    /// A stranger gets `None` for a private lineage.
    #[test]
    fn current_filters_private_for_stranger() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("private v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Private)
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();

        let stranger = AgentDid::new("did:web:other.example.com:reader");
        assert!(
            server
                .current(&resp.lineage_id, Some(&stranger))
                .unwrap()
                .is_none(),
            "stranger MUST NOT see private contexts via current()"
        );

        let producer_did = AgentDid::new("did:web:agents.example.com:test");
        assert!(
            server
                .current(&resp.lineage_id, Some(&producer_did))
                .unwrap()
                .is_some(),
            "producer MUST see private contexts via current()"
        );
    }

    // ── BUG-04 — current() superseded fallback ─────────────────────────

    /// BUG-04: when every version of a lineage is `Superseded`,
    /// `current()` MUST return `None`. Previously the fallback returned
    /// the last entry projected, which is a protocol violation
    /// (RFC-ACDP-0004 §5: "If no such version exists, returns not_found").
    ///
    /// Constructing an all-superseded lineage requires a direct store
    /// mark — there's no publish path that produces this state today,
    /// but the registry's `current()` MUST not implicitly fall through.
    #[test]
    fn current_returns_none_when_all_superseded() {
        use crate::registry::store::RegistryStore;
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();
        // Force the only version into Superseded directly.
        server.store().mark_superseded(&resp.ctx_id).unwrap();

        let cur = server.current(&resp.lineage_id, None).unwrap();
        assert!(
            cur.is_none(),
            "all-superseded lineage MUST resolve to None per RFC-ACDP-0004 §5; got {cur:?}"
        );
    }

    // ── BUG-01 / vis-009 — anonymous search honors anonymous_public_reads ──

    /// BUG-01 + vis-009: a registry advertising `anonymous_public_reads:
    /// false` MUST reject an anonymous search with `not_authorized`
    /// (HTTP 403) — not an empty `200`, which would still leak the
    /// registry's existence. The same context surfaces with a `200`
    /// once the requester authenticates.
    #[test]
    fn search_suppresses_public_when_anonymous_public_reads_false() {
        let mut c = caps();
        c.anonymous_public_reads = false;
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("public-but-flag-off")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        server.publish_unverified_for_tests(&req).unwrap();

        // Anonymous: MUST be rejected with NotAuthorized (vis-009 s1).
        let err = server
            .search(
                &SearchParams {
                    q: Some("public-but-flag-off".into()),
                    ..Default::default()
                },
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, AcdpError::NotAuthorized(_)),
            "vis-009: anonymous search MUST be NotAuthorized when \
             anonymous_public_reads=false; got {err:?}"
        );

        // Authenticated requester (any DID — public is universally visible
        // once authenticated): MUST see the context.
        let stranger = AgentDid::new("did:web:other.example.com:reader");
        let authed = server
            .search(
                &SearchParams {
                    q: Some("public-but-flag-off".into()),
                    ..Default::default()
                },
                Some(&stranger),
            )
            .unwrap();
        assert_eq!(
            authed.matches.len(),
            1,
            "authenticated search MUST see public contexts regardless of anonymous_public_reads"
        );
    }

    // ── try_new validation tests ────────────────────────────────────────

    #[test]
    fn try_new_rejects_did_authority_mismatch() {
        let mut c = caps();
        c.registry_did = "did:web:other.example.com".into(); // wrong authority
        let res = RegistryServer::try_new(InMemoryStore::new(), c, "registry.example.com");
        match res {
            Err(AcdpError::SchemaViolation(msg)) => {
                assert!(msg.contains("does not match expected"))
            }
            Err(other) => panic!("expected SchemaViolation, got {other:?}"),
            Ok(_) => panic!("expected Err"),
        }
    }

    #[test]
    fn try_new_rejects_caps_missing_ed25519() {
        let mut c = caps();
        c.supported_signature_algorithms = vec!["ecdsa-p256".into()]; // missing ed25519
        let res = RegistryServer::try_new(InMemoryStore::new(), c, "registry.example.com");
        assert!(matches!(res, Err(AcdpError::SchemaViolation(_))));
    }

    #[test]
    fn try_new_accepts_valid_caps() {
        RegistryServer::try_new(InMemoryStore::new(), caps(), "registry.example.com").unwrap();
    }

    // ── Visibility-enforcement tests (RFC-ACDP-0008 §4.5) ───────────────

    fn producer_for(seed: u8, did: &str) -> Producer {
        Producer::new(
            SigningKey::from_bytes(&[seed; 32]),
            AgentDid::new(did),
            format!("{did}#key-1"),
        )
    }

    #[test]
    fn retrieve_restricted_blocks_stranger_returns_none() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let owner = AgentDid::new("did:web:agents.example.com:owner");
        let audience_member = AgentDid::new("did:web:agents.example.com:friend");
        let p = producer_for(2, owner.as_str());
        let req = p
            .publish_request()
            .title("restricted")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![audience_member.clone()])
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();
        let stranger = AgentDid::new("did:web:agents.example.com:stranger");

        assert!(server.retrieve(&resp.ctx_id, None).unwrap().is_none());
        assert!(server
            .retrieve(&resp.ctx_id, Some(&stranger))
            .unwrap()
            .is_none());
        assert!(server
            .retrieve(&resp.ctx_id, Some(&owner))
            .unwrap()
            .is_some());
        assert!(server
            .retrieve(&resp.ctx_id, Some(&audience_member))
            .unwrap()
            .is_some());
    }

    #[test]
    fn search_restricted_filters_strangers() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let owner = AgentDid::new("did:web:agents.example.com:owner");
        let p = producer_for(3, owner.as_str());
        let req = p
            .publish_request()
            .title("hush hush")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![AgentDid::new("did:web:agents.example.com:friend")])
            .build()
            .unwrap();
        server.publish_unverified_for_tests(&req).unwrap();

        let stranger = AgentDid::new("did:web:agents.example.com:stranger");
        let r_anon = server.search(&SearchParams::default(), None).unwrap();
        assert!(
            r_anon.matches.is_empty(),
            "anonymous must not see restricted"
        );
        let r_stranger = server
            .search(&SearchParams::default(), Some(&stranger))
            .unwrap();
        assert!(r_stranger.matches.is_empty());
        let r_owner = server
            .search(&SearchParams::default(), Some(&owner))
            .unwrap();
        assert_eq!(r_owner.matches.len(), 1);
    }

    /// RFC-ACDP-0008 §4.5 asymmetry: a private context surfaces in search
    /// only to its producer — audience members can retrieve by id but can't
    /// discover via search.
    #[test]
    fn search_private_visible_only_to_producer() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let owner = AgentDid::new("did:web:agents.example.com:owner");
        let audience_member = AgentDid::new("did:web:agents.example.com:friend");
        let p = producer_for(4, owner.as_str());
        let req = p
            .publish_request()
            .title("private note")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Private)
            .audience(vec![audience_member.clone()])
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();

        let r_audience = server
            .search(&SearchParams::default(), Some(&audience_member))
            .unwrap();
        assert!(
            r_audience.matches.is_empty(),
            "audience must NOT see private in search"
        );
        let r_owner = server
            .search(&SearchParams::default(), Some(&owner))
            .unwrap();
        assert_eq!(
            r_owner.matches.len(),
            1,
            "owner sees their own private context"
        );

        // Audience CAN retrieve directly by id.
        assert!(server
            .retrieve(&resp.ctx_id, Some(&audience_member))
            .unwrap()
            .is_some());
    }

    // ── publish_verified offline-rejection tests ────────────────────────
    //
    // Full end-to-end `publish_verified` requires a TLS-mocked DID
    // document (because `WebResolver` is HTTPS-only). These tests cover
    // the rejection paths that fire BEFORE the resolver call so they
    // don't need a network: malformed key_id, non-did:web key_id,
    // agent_id ≠ key_id DID portion. Together with the existing
    // `verify_signature_envelope` algorithm-downgrade unit test, they
    // pin the entry checks of RFC-ACDP-0003 §2.1 steps 7–8 without
    // requiring a TLS mock harness.

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn publish_verified_rejects_non_did_web_key_id() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let mut req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        // Mutate post-build — validation already ran and accepted did:web.
        // Re-sign isn't necessary: the verifier rejects before signature check.
        req.signature.key_id = "did:key:z6Mki#key-1".into();
        let resolver = crate::did::WebResolver::new();
        let err = server
            .publish_verified(&req, None, &resolver)
            .await
            .unwrap_err();
        match err {
            AcdpError::KeyNotAuthorized(msg) => assert!(msg.contains("did:web")),
            other => panic!("expected KeyNotAuthorized for non-did:web, got {other:?}"),
        }
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn publish_verified_rejects_agent_id_keyid_mismatch() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let mut req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        req.signature.key_id = "did:web:other.example.com:agent#key-1".into();
        let resolver = crate::did::WebResolver::new();
        let err = server
            .publish_verified(&req, None, &resolver)
            .await
            .unwrap_err();
        match err {
            AcdpError::KeyNotAuthorized(msg) => assert!(msg.contains("agent_id")),
            other => panic!("expected KeyNotAuthorized for agent_id mismatch, got {other:?}"),
        }
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn publish_verified_rejects_keyid_without_fragment() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let mut req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        req.signature.key_id = "did:web:agents.example.com:test".into(); // no '#'
        let resolver = crate::did::WebResolver::new();
        let err = server
            .publish_verified(&req, None, &resolver)
            .await
            .unwrap_err();
        // Schema validation (step 1) catches missing-fragment before
        // step 7 fires, so the surface error is SchemaViolation.
        assert!(
            matches!(
                err,
                AcdpError::SchemaViolation(_) | AcdpError::KeyResolution(_)
            ),
            "expected fragment-rejection error, got {err:?}"
        );
    }

    // ── FEAT-04 idempotency tests ──────────────────────────────────────

    fn caps_with_idempotency() -> CapabilitiesDocument {
        let mut c = caps();
        c.supports_idempotency_key = true;
        c.limits.idempotency_key_ttl_seconds = Some(86_400);
        c
    }

    #[test]
    fn idempotency_same_hash_returns_original_response() {
        let server = RegistryServer::new(
            InMemoryStore::new(),
            caps_with_idempotency(),
            "registry.example.com",
        );
        let p = producer();
        let req = p
            .publish_request()
            .title("once")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        // First publish (using the offline path; idempotency works either way).
        let first = server.publish_unverified_for_tests(&req).unwrap();
        // Record the idempotency entry as if it had come in through
        // publish_verified — we test only the lookup logic here, so
        // simulate via the store API.
        let ttl = caps_with_idempotency()
            .limits
            .idempotency_key_ttl_seconds
            .unwrap() as i64;
        server
            .store()
            .idempotency_record(
                &req.agent_id,
                "k-001",
                &req.content_hash,
                &first,
                chrono::Utc::now() + chrono::Duration::seconds(ttl),
            )
            .unwrap();
        let prior = server
            .store()
            .idempotency_lookup(&req.agent_id, "k-001")
            .unwrap()
            .unwrap();
        assert_eq!(prior.content_hash, req.content_hash);
        assert_eq!(prior.response.ctx_id, first.ctx_id);
    }

    #[test]
    fn idempotency_evicts_after_ttl() {
        let store = InMemoryStore::new();
        let agent = AgentDid::new("did:web:agents.example.com:test");
        let resp = PublishResponse {
            ctx_id: crate::types::CtxId("acdp://r/12345678-1234-4321-8123-000000000099".into()),
            lineage_id: crate::types::LineageId(
                "lin:sha256:9999999999999999999999999999999999999999999999999999999999999999"
                    .into(),
            ),
            version: 1,
            created_at: chrono::Utc::now(),
            status: Status::Active,
        };
        // Already-past expiration.
        let past = chrono::Utc::now() - chrono::Duration::seconds(1);
        store
            .idempotency_record(
                &agent,
                "expired",
                &crate::types::ContentHash("sha256:0".into()),
                &resp,
                past,
            )
            .unwrap();
        // Lookup runs lazy eviction; the expired record MUST be gone.
        let prior = store.idempotency_lookup(&agent, "expired").unwrap();
        assert!(
            prior.is_none(),
            "lazy TTL eviction should drop expired record"
        );
    }

    // ── FEAT-05 rate limiter tests ─────────────────────────────────────

    struct AlwaysDeny;
    impl crate::registry::RateLimiter for AlwaysDeny {
        fn check_publish(&self, agent_id: &AgentDid) -> Result<(), AcdpError> {
            Err(AcdpError::RateLimited(format!("blocked: {agent_id}")))
        }
    }

    #[test]
    fn rate_limiter_blocks_publish_before_persist() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com")
            .with_rate_limiter(AlwaysDeny);
        let p = producer();
        let req = p
            .publish_request()
            .title("blocked")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let err = server.publish_unverified_for_tests(&req).unwrap_err();
        assert!(matches!(err, AcdpError::RateLimited(_)));
        // And the store is empty — the limiter MUST short-circuit before persist.
        let resp = server.search(&SearchParams::default(), None).unwrap();
        assert!(
            resp.matches.is_empty(),
            "rate-limited publish must not persist"
        );
    }

    #[test]
    fn created_at_is_ms_truncated() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("ms")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();
        // Nanosecond component of a ms-truncated timestamp is always a multiple of 1_000_000.
        assert_eq!(
            resp.created_at.timestamp_subsec_nanos() % 1_000_000,
            0,
            "created_at must be millisecond-truncated per RFC-ACDP-0001 §5.3"
        );
    }
}
