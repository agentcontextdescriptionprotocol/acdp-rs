//! Logical registry handler (feature = "server").
//!
//! Wires [`PublishValidator`] together with a [`RegistryStore`] backend
//! to provide the seven core registry operations enumerated in
//! RFC-ACDP-0003 §2.1 and RFC-ACDP-0005:
//!
//! - capabilities — return the [`CapabilitiesDocument`].
//! - publish — validate, assign identifiers, persist.
//! - retrieve — fetch a stored body + registry_state.
//! - retrieve_body — fetch just the body.
//! - lineage / current — lineage graph queries.
//! - search — keyword + filter projection.
//!
//! This is the building block an HTTP-binding layer can sit on top of;
//! the integration tests in this crate exercise it directly without
//! mocking. Steps 7–8 (DID resolution + signature verification) are
//! NOT performed here — they require an async resolver and are the
//! consumer's responsibility per the spec
//! ([`crate::client::VerifiedContext::fetch`]).

use crate::error::AcdpError;
use crate::registry::store::RegistryStore;
use crate::registry::validator::{assign_identifiers, PublishValidator};
use crate::types::{
    body::{Body, FullContext},
    capabilities::CapabilitiesDocument,
    primitives::{CtxId, LineageId, Status},
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
    /// Build a registry server.
    ///
    /// `authority` is the DNS authority used to mint new `ctx_id`s
    /// (`acdp://<authority>/<uuid>`); it MUST match
    /// `caps.registry_did`'s `did:web:<authority>` portion.
    pub fn new(store: S, caps: CapabilitiesDocument, authority: impl Into<String>) -> Self {
        Self {
            store,
            caps,
            authority: authority.into(),
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

    /// `POST /contexts`.
    ///
    /// Runs full RFC-ACDP-0003 §2.1 validation (steps 1–6 + cross-registry
    /// supersession check), assigns identifiers (step 9), enforces lineage
    /// coherence on supersession (step 10), persists the body (step 11),
    /// and marks the predecessor superseded.
    ///
    /// Steps 7–8 (DID resolution + signature verification) are NOT
    /// performed here. Consumers are expected to verify on retrieval.
    pub fn publish(&self, req: &PublishRequest) -> Result<PublishResponse, AcdpError> {
        let raw_bytes = serde_json::to_vec(req)?.len();
        let validator = PublishValidator::for_authority(&self.caps, &self.authority);
        let validated = validator.validate_post_schema(req, raw_bytes)?;

        // Determine the v1 ctx_id for lineage derivation on supersession.
        let first_v1 = if let Some(prev) = &req.supersedes {
            // For supersession, the registry must look up the lineage of
            // the predecessor and pass its first version to
            // assign_identifiers. We tolerate a not-found predecessor
            // by returning superseded_target/not_found.
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
        let body = Body {
            ctx_id: ctx_id.clone(),
            lineage_id: lineage_id.clone(),
            origin_registry: format!("did:web:{}", self.authority),
            created_at: chrono::Utc::now(),
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

        let created_at = body.created_at;
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
    pub fn retrieve(&self, ctx_id: &CtxId) -> Result<Option<FullContext>, AcdpError> {
        self.store.get(ctx_id)
    }

    /// `GET /contexts/{ctx_id}/body`.
    pub fn retrieve_body(&self, ctx_id: &CtxId) -> Result<Option<Body>, AcdpError> {
        Ok(self.store.get(ctx_id)?.map(|c| c.body))
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
    pub fn search(&self, params: &SearchParams) -> Result<SearchResponse, AcdpError> {
        self.store.search(params)
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
        let resp = server.publish(&req).unwrap();
        assert_eq!(resp.version, 1);
        let ctx = server.retrieve(&resp.ctx_id).unwrap().unwrap();
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
        let v1 = server.publish(&v1_req).unwrap();

        let v2_req = p
            .supersede(v1.ctx_id.clone())
            .version(2)
            .title("v2")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v2 = server.publish(&v2_req).unwrap();
        assert_eq!(v2.version, 2);
        // v1 was marked superseded
        let v1_ctx = server.retrieve(&v1.ctx_id).unwrap().unwrap();
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
        let err = server.publish(&req).unwrap_err();
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
        let v1 = server.publish(&v1_req).unwrap();
        // Build a v3 (wrong) supersession
        let v3_req = p
            .supersede(v1.ctx_id.clone())
            .version(3)
            .title("v3-skipped")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let err = server.publish(&v3_req).unwrap_err();
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
        server.publish(&req).unwrap();
        let resp = server
            .search(&SearchParams {
                q: Some("portfolio".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.matches[0].title, "Q1 portfolio risk");
    }
}
