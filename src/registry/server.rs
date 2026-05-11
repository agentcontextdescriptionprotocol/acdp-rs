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
use crate::registry::store::RegistryStore;
use crate::registry::validator::{assign_identifiers, PublishValidator};
use crate::types::{
    body::{Body, FullContext},
    capabilities::CapabilitiesDocument,
    primitives::{AgentDid, CtxId, LineageId, Status, Visibility},
    publish::{PublishRequest, PublishResponse},
    search::{SearchParams, SearchResponse},
};

/// Logical registry handler over an arbitrary [`RegistryStore`].
pub struct RegistryServer<S: RegistryStore> {
    store: S,
    caps: CapabilitiesDocument,
    authority: String,
}

impl<S: RegistryStore> RegistryServer<S> {
    /// Unchecked constructor. Skips capabilities and DID-authority binding
    /// validation; prefer [`Self::try_new`] in production. Retained for
    /// tests that build a server from known-good fixtures.
    #[doc(hidden)]
    pub fn new(store: S, caps: CapabilitiesDocument, authority: impl Into<String>) -> Self {
        Self {
            store,
            caps,
            authority: authority.into(),
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
        let expected_did = format!("did:web:{authority}");
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
        })
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
        resolver: &crate::did::WebResolver,
    ) -> Result<PublishResponse, AcdpError> {
        let raw_bytes = serde_json::to_vec(req)?.len();
        let validator = PublishValidator::for_authority(&self.caps, &self.authority);
        let validated = validator.validate_post_schema(req, raw_bytes)?;

        // Steps 7–8: DID resolution + signature verification.
        crate::crypto::verify::verify_publish_request_signature(req, resolver).await?;

        // Steps 9–11: assign identifiers, enforce lineage coherence, persist.
        self.persist_validated(req, validated)
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
        let raw_bytes = serde_json::to_vec(req)?.len();
        let validator = PublishValidator::for_authority(&self.caps, &self.authority);
        let validated = validator.validate_post_schema(req, raw_bytes)?;
        self.persist_validated(req, validated)
    }

    /// Steps 9–11 in isolation: assumes the request has already been
    /// validated and (where appropriate) signature-verified.
    fn persist_validated(
        &self,
        req: &PublishRequest,
        validated: crate::registry::validator::ValidatedPublish,
    ) -> Result<PublishResponse, AcdpError> {
        // Determine the v1 ctx_id for lineage derivation on supersession.
        let first_v1 = if let Some(prev) = &req.supersedes {
            let prev_full = self
                .store
                .get(prev)?
                .ok_or_else(|| AcdpError::SupersededTarget {
                    reason: crate::error::SupersessionReason::NotFound,
                    message: format!("supersedes target '{prev}' not found in this registry"),
                })?;

            // Lineage coherence: the new request's lineage_id (when
            // declared) MUST match the predecessor's lineage_id.
            if let Some(declared) = &req.lineage_id {
                if declared != &prev_full.body.lineage_id {
                    return Err(AcdpError::SupersededTarget {
                        reason: crate::error::SupersessionReason::LineageMismatch,
                        message: format!(
                            "declared lineage_id '{declared}' ≠ predecessor's '{}'",
                            prev_full.body.lineage_id
                        ),
                    });
                }
            }
            // Version coherence: new.version MUST be predecessor.version + 1.
            if req.version != prev_full.body.version + 1 {
                return Err(AcdpError::SupersededTarget {
                    reason: crate::error::SupersessionReason::VersionMismatch,
                    message: format!(
                        "version {} ≠ predecessor.version + 1 ({})",
                        req.version,
                        prev_full.body.version + 1
                    ),
                });
            }
            // Already-superseded check.
            if matches!(prev_full.registry_state.status, Status::Superseded) {
                return Err(AcdpError::SupersededTarget {
                    reason: crate::error::SupersessionReason::AlreadySuperseded,
                    message: format!("supersedes target '{prev}' has already been superseded"),
                });
            }

            self.store
                .first_version_ctx_id(&prev_full.body.lineage_id)?
        } else {
            None
        };

        let (ctx_id, lineage_id) = assign_identifiers(
            &self.authority,
            &req.supersedes,
            first_v1.as_ref(),
            &validated,
        )?;

        // Build the stored Body from the request + registry-assigned fields.
        // RFC-ACDP-0001 §5.3 requires millisecond precision on stored timestamps.
        let created_at = crate::time::trunc_ms(chrono::Utc::now());
        let body = Body {
            ctx_id: ctx_id.clone(),
            lineage_id: lineage_id.clone(),
            origin_registry: format!("did:web:{}", self.authority),
            created_at,
            content_hash: req.content_hash.clone(),
            signature: req.signature.clone(),
            version: req.version,
            supersedes: req.supersedes.clone(),
            agent_id: req.agent_id.clone(),
            contributors: req.contributors.clone(),
            title: req.title.clone(),
            context_type: req.context_type.clone(),
            data_refs: req.data_refs.clone(),
            derived_from: req.derived_from.clone(),
            visibility: req.visibility.clone(),
            audience: req.audience.clone(),
            acdp_version: req.acdp_version.clone(),
            description: req.description.clone(),
            summary: req.summary.clone(),
            tags: req.tags.clone(),
            domain: req.domain.clone(),
            expires_at: req.expires_at,
            data_period: req.data_period.clone(),
            metadata: req.metadata.clone(),
            schema_uri: req.schema_uri.clone(),
            extensions: Default::default(),
        };

        self.store.put(body)?;
        if let Some(prev) = &req.supersedes {
            self.store.mark_superseded(prev)?;
        }

        Ok(PublishResponse {
            ctx_id,
            lineage_id,
            version: req.version,
            created_at,
            status: Status::Active,
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
    pub fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        self.store.lineage(lineage_id)
    }

    /// `GET /lineages/{lineage_id}/current`.
    pub fn current(&self, lineage_id: &LineageId) -> Result<Option<FullContext>, AcdpError> {
        self.store.current(lineage_id)
    }

    /// `GET /contexts/search`.
    ///
    /// Applies the RFC-ACDP-0008 §4.5 search disclosure rules (note the
    /// asymmetry vs retrieval): private contexts surface in search only
    /// to their producer (audience members must already know the ctx_id).
    pub fn search(
        &self,
        params: &SearchParams,
        requester: Option<&AgentDid>,
    ) -> Result<SearchResponse, AcdpError> {
        self.store.search(params, requester)
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
            acdp_version: "0.0.1".into(),
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
        let lineage = server.lineage(&resp.lineage_id).unwrap();
        assert_eq!(lineage.len(), 1);
        // Current points at the same record
        let cur = server.current(&resp.lineage_id).unwrap().unwrap();
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
        let cur = server.current(&v1.lineage_id).unwrap().unwrap();
        assert_eq!(cur.body.ctx_id, v2.ctx_id);
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
        let err = server.publish_verified(&req, &resolver).await.unwrap_err();
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
        let err = server.publish_verified(&req, &resolver).await.unwrap_err();
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
        let err = server.publish_verified(&req, &resolver).await.unwrap_err();
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
