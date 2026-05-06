//! Server-side publish validation pipeline — RFC-ACDP-0003 §2.1 (feature = "server").
//!
//! Runs steps 1–8 (validation) before any persistence occurs.

use crate::crypto::hash::{compute_content_hash, derive_lineage_id};
use crate::error::AcdpError;
use crate::types::{
    capabilities::CapabilitiesDocument,
    primitives::{ContentHash, CtxId, LineageId},
    publish::PublishRequest,
};

/// Outcome of a successful validation — the registry can now assign
/// identifiers and persist.
#[derive(Debug)]
pub struct ValidatedPublish {
    /// The hash recomputed by the validator over ProducerContent.
    pub recomputed_hash: ContentHash,
}

/// Stateless publish request validator.
///
/// Runs §2.1 steps 1–8 (structural and cryptographic checks).
/// Steps 9+ (identifier assignment, lineage, supersession, persistence)
/// are registry-implementation concerns.
pub struct PublishValidator<'a> {
    caps: &'a CapabilitiesDocument,
    own_authority: Option<&'a str>,
}

impl<'a> PublishValidator<'a> {
    /// Create a validator without same-registry supersession enforcement.
    pub fn new(caps: &'a CapabilitiesDocument) -> Self {
        Self {
            caps,
            own_authority: None,
        }
    }

    /// Create a validator that rejects cross-registry supersession.
    ///
    /// `own_authority` is the registry's DNS authority (e.g.
    /// `registry.example.com`). When set, a publish request whose
    /// `supersedes` ctx_id has a different authority will be rejected with
    /// [`AcdpError::SupersededTarget`] / `CrossRegistrySupersessionUnsupported`
    /// (RFC-ACDP-0006 — v0.0.1 only allows same-registry supersession).
    pub fn for_authority(caps: &'a CapabilitiesDocument, own_authority: &'a str) -> Self {
        Self {
            caps,
            own_authority: Some(own_authority),
        }
    }

    /// Validate a publish request through the structural / cryptographic
    /// steps of RFC-ACDP-0003 §2.1, plus the cross-registry-supersession
    /// guard if the validator was built with [`Self::for_authority`].
    ///
    /// Mapped steps from RFC-ACDP-0003 §2.1:
    /// - **Step 1** (schema validation) — assumed performed upstream
    ///   (e.g. by `validate_publish_request`).
    /// - **Step 2** (payload size vs `limits.max_payload_bytes`).
    /// - **Step 3** (embedded size vs `limits.max_embedded_bytes`).
    /// - **Step 4** (hash recomputation over ProducerContent).
    /// - **Step 5** (signature algorithm vs
    ///   `supported_signature_algorithms`).
    /// - **Step 6** (key_id DID portion equals `agent_id`).
    /// - **Step 7–8** (DID resolution + signature verification) — async,
    ///   handled separately by `crypto::verify::Verifier::verify_body`.
    /// - Cross-registry supersession check (RFC-ACDP-0006): when an
    ///   own-authority is configured, rejects supersedes targets on a
    ///   different authority.
    pub fn validate_post_schema(
        &self,
        req: &PublishRequest,
        raw_body_bytes: usize,
    ) -> Result<ValidatedPublish, AcdpError> {
        // Run the full schema-aligned validation (string lengths, array
        // uniqueness, DataRef oneOf + URI rules, metadata depth/size,
        // visibility/audience invariants, did:web check, signature length,
        // identifier patterns, version coherence) on top of the raw
        // structural / cryptographic steps below. This makes
        // `validate_post_schema` a complete RFC-ACDP-0003 §2.1
        // implementation regardless of whether the producer side ran
        // [`crate::validation::validate_publish_request`] first.
        crate::validation::validate_publish_request(req)?;
        self.validate_registry_limits_and_crypto(req, raw_body_bytes)
    }

    /// Deprecated alias — now routes through [`Self::validate_post_schema`].
    ///
    /// The previous implementation skipped the schema-level validation
    /// (title length, metadata depth, DataRef integrity, did:web check,
    /// version coherence, …). Callers using `validate_structural`
    /// directly were silently bypassing those checks. The deprecated
    /// alias now runs the full pipeline so existing call sites remain
    /// safe; new code should call `validate_post_schema` explicitly.
    #[deprecated(
        since = "0.1.0",
        note = "Use validate_post_schema; this alias no longer skips runtime validation"
    )]
    pub fn validate_structural(
        &self,
        req: &PublishRequest,
        raw_body_bytes: usize,
    ) -> Result<ValidatedPublish, AcdpError> {
        self.validate_post_schema(req, raw_body_bytes)
    }

    /// Internal: registry-limit + cryptographic step list (no schema
    /// validation). Keep private — bypassing the schema validation is
    /// not a publishable surface.
    fn validate_registry_limits_and_crypto(
        &self,
        req: &PublishRequest,
        raw_body_bytes: usize,
    ) -> Result<ValidatedPublish, AcdpError> {
        // Step 2: payload size
        if raw_body_bytes as u64 > self.caps.limits.max_payload_bytes {
            return Err(AcdpError::SchemaViolation(format!(
                "payload {} bytes exceeds limit {}",
                raw_body_bytes, self.caps.limits.max_payload_bytes
            )));
        }

        // Step 3: embedded size + optional embedded content_hash check
        // (RFC-ACDP-0003 §2.1 step 3 last sentence; RFC-ACDP-0002 §6.6 #8).
        for dr in &req.data_refs {
            if let Some(emb) = &dr.embedded {
                let decoded = crate::validation::embedded_decoded_bytes(emb)?;
                if decoded.len() as u64 > self.caps.limits.max_embedded_bytes {
                    return Err(AcdpError::EmbeddedTooLarge(format!(
                        "embedded data reference {} bytes exceeds {} limit",
                        decoded.len(),
                        self.caps.limits.max_embedded_bytes
                    )));
                }
                // If the producer declared an embedded content_hash, recompute
                // and verify per §2.1 step 3.
                crate::validation::verify_embedded_hash(dr)?;
            }
        }

        // Step 4: hash recomputation over ProducerContent
        let body_val = serde_json::to_value(req)?;
        let recomputed = compute_content_hash(&body_val)?;
        if recomputed != req.content_hash {
            return Err(AcdpError::HashMismatch {
                stored: req.content_hash.clone(),
                recomputed: recomputed.clone(),
            });
        }

        // Step 5: algorithm check
        if !self
            .caps
            .supported_signature_algorithms
            .iter()
            .any(|a| a == &req.signature.algorithm)
        {
            return Err(AcdpError::SchemaViolation(format!(
                "unsupported algorithm '{}'; registry supports {:?}",
                req.signature.algorithm, self.caps.supported_signature_algorithms,
            )));
        }

        // Step 6: key-id binding — DID portion must equal agent_id
        let key_id = &req.signature.key_id;
        let did_part = key_id.split_once('#').map(|(d, _)| d).ok_or_else(|| {
            AcdpError::KeyResolution(format!("key_id '{key_id}' has no '#fragment'"))
        })?;

        if did_part != req.agent_id.as_str() {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "key_id DID '{did_part}' ≠ agent_id '{}'",
                req.agent_id
            )));
        }

        // Cross-registry supersession check — v0.0.1 only allows same-registry.
        if let (Some(own), Some(target)) = (self.own_authority, &req.supersedes) {
            let target_authority = target.authority();
            if target_authority != own {
                return Err(AcdpError::SupersededTarget {
                    reason: crate::error::SupersessionReason::CrossRegistrySupersessionUnsupported,
                    message: format!(
                        "supersedes target on '{target_authority}' rejected by '{own}'; \
                         v0.0.1 only allows same-registry supersession"
                    ),
                });
            }
        }

        // Steps 7–8 (key resolution + signature verification) require async
        // DID resolution; the caller should invoke Verifier::verify_body for those.
        Ok(ValidatedPublish {
            recomputed_hash: recomputed,
        })
    }
}

/// Assign registry identifiers after successful validation per
/// RFC-ACDP-0001 §5.6.
///
/// For first-version publications (`supersedes == None`,
/// `first_version_ctx_id == None`), `lineage_id` is derived from the newly
/// assigned `ctx_id`. For supersession (`supersedes == Some(_)`), the
/// caller MUST supply the v1 `ctx_id` of the lineage so `lineage_id` is
/// derived from it — using the new ctx_id would orphan the supersession
/// from its lineage.
///
/// Returns `SchemaViolation` if `supersedes` is set but
/// `first_version_ctx_id` is not.
pub fn assign_identifiers(
    authority: &str,
    supersedes: &Option<CtxId>,
    first_version_ctx_id: Option<&CtxId>,
    _validated: &ValidatedPublish,
) -> Result<(CtxId, LineageId), AcdpError> {
    let uuid = uuid::Uuid::new_v4();
    let ctx_id = CtxId(format!("acdp://{authority}/{uuid}"));
    let lineage_source: &CtxId = match (supersedes, first_version_ctx_id) {
        (None, _) => &ctx_id,
        (Some(_), Some(v1)) => v1,
        (Some(_), None) => {
            return Err(AcdpError::SchemaViolation(
                "supersession assignment requires the v1 ctx_id to derive lineage_id".into(),
            ));
        }
    };
    let lineage_id = derive_lineage_id(lineage_source);
    Ok((ctx_id, lineage_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use crate::producer::Producer;
    use crate::types::{
        capabilities::Limits,
        primitives::{AgentDid, ContextType, Visibility},
    };

    fn test_caps() -> CapabilitiesDocument {
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

    fn test_request() -> PublishRequest {
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new("did:web:agents.example.com:test-producer"),
            "did:web:agents.example.com:test-producer#key-1",
        );
        p.publish_request()
            .title("Golden test vector — minimal first version")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap()
    }

    #[test]
    fn happy_path_validates() {
        let caps = test_caps();
        let v = PublishValidator::new(&caps);
        let req = test_request();
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn payload_too_large_rejected() {
        let mut caps = test_caps();
        caps.limits.max_payload_bytes = 10;
        let v = PublishValidator::new(&caps);
        let req = test_request();
        let err = v.validate_post_schema(&req, 1024).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn unsupported_algorithm_rejected() {
        let mut caps = test_caps();
        caps.supported_signature_algorithms = vec!["secp256k1".into()];
        let v = PublishValidator::new(&caps);
        let req = test_request();
        let err = v.validate_post_schema(&req, 1024).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn key_id_without_fragment_rejected() {
        let caps = test_caps();
        let v = PublishValidator::new(&caps);
        let mut req = test_request();
        req.signature.key_id = "did:web:agents.example.com:test-producer".into();
        let err = v.validate_post_schema(&req, 1024).unwrap_err();
        assert!(matches!(err, AcdpError::KeyResolution(_)));
    }

    #[test]
    fn key_id_did_must_match_agent_id() {
        let caps = test_caps();
        let v = PublishValidator::new(&caps);
        let mut req = test_request();
        req.signature.key_id = "did:web:other.example.com:attacker#key-1".into();
        let err = v.validate_post_schema(&req, 1024).unwrap_err();
        assert!(matches!(err, AcdpError::KeyNotAuthorized(_)));
    }

    #[test]
    fn tampered_hash_detected() {
        let caps = test_caps();
        let v = PublishValidator::new(&caps);
        let mut req = test_request();
        req.title = "tampered title".into();
        let err = v.validate_post_schema(&req, 1024).unwrap_err();
        assert!(matches!(err, AcdpError::HashMismatch { .. }));
    }

    #[test]
    fn assign_identifiers_first_version_derives_lineage_from_new_id() {
        let v = ValidatedPublish {
            recomputed_hash: ContentHash("sha256:abcd".into()),
        };
        let (ctx_id, lineage_id) =
            assign_identifiers("registry.example.com", &None, None, &v).unwrap();
        let expected = derive_lineage_id(&ctx_id);
        assert_eq!(lineage_id, expected);
    }

    #[test]
    fn assign_identifiers_supersession_uses_v1_ctx_id() {
        let v = ValidatedPublish {
            recomputed_hash: ContentHash("sha256:abcd".into()),
        };
        let v1 = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
        let supersedes = Some(CtxId(
            "acdp://registry.example.com/12345678-1234-4321-8123-123456781299".into(),
        ));
        let (_new_id, lineage_id) =
            assign_identifiers("registry.example.com", &supersedes, Some(&v1), &v).unwrap();
        assert_eq!(lineage_id, derive_lineage_id(&v1));
    }

    #[test]
    fn cross_registry_supersession_rejected() {
        let caps = test_caps();
        let v = PublishValidator::for_authority(&caps, "registry.example.com");
        // Build a v2 request that supersedes a context on a different registry
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new("did:web:agents.example.com:test-producer"),
            "did:web:agents.example.com:test-producer#key-1",
        );
        let other_reg =
            CtxId("acdp://other.example.com/12345678-1234-4321-8123-123456781234".into());
        let req = p
            .supersede(other_reg)
            .version(2)
            .title("v2")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap();
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        match err {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(
                    reason,
                    crate::error::SupersessionReason::CrossRegistrySupersessionUnsupported
                );
            }
            other => panic!("expected SupersededTarget, got {other:?}"),
        }
    }

    #[test]
    fn same_registry_supersession_passes_authority_check() {
        let caps = test_caps();
        let v = PublishValidator::for_authority(&caps, "registry.example.com");
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new("did:web:agents.example.com:test-producer"),
            "did:web:agents.example.com:test-producer#key-1",
        );
        let same = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
        let req = p
            .supersede(same)
            .version(2)
            .title("v2")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap();
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn assign_identifiers_supersession_without_v1_id_rejected() {
        let v = ValidatedPublish {
            recomputed_hash: ContentHash("sha256:abcd".into()),
        };
        let supersedes = Some(CtxId("acdp://x/y".into()));
        let err = assign_identifiers("registry.example.com", &supersedes, None, &v).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }
}
