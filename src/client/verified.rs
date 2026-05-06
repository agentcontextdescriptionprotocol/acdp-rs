//! VerifiedContext: retrieve + verify in one call.

use super::registry::RegistryClient;
use crate::crypto::verify::Verifier;
use crate::did::WebResolver;
use crate::error::AcdpError;
use crate::types::{body::FullContext, primitives::CtxId};

/// Consumer-tunable strictness for [`VerifiedContext::fetch_with_policy`].
///
/// The defaults match the strict spec-conformant behavior; loosen only
/// for tightly controlled environments (e.g. testing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPolicy {
    /// If true, reject bodies whose `agent_id` is not `did:web` (and
    /// whose `key_id` doesn't start with `did:web:`). Default `true`.
    pub require_did_web: bool,

    /// If true, run [`crate::validation::validate_body`] before any
    /// cryptographic check. Default `true`.
    pub validate_body_schema: bool,

    /// If true, embedded `data_refs` with declared `content_hash` are
    /// re-hashed and compared. Default `true`.
    pub verify_embedded_hashes: bool,

    /// If true, accept `Status::Other` values (degrade to active per
    /// RFC-ACDP-0004 §4.1). When false, reject unknown statuses.
    /// Default `true`.
    pub allow_unknown_status: bool,

    /// If true, attempt to verify the optional `registry_receipt`
    /// (RFC-ACDP-0009 §2.7, reserved for v0.1+). Default `false`.
    pub verify_registry_receipt: bool,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            require_did_web: true,
            validate_body_schema: true,
            verify_embedded_hashes: true,
            allow_unknown_status: true,
            verify_registry_receipt: false,
        }
    }
}

/// A retrieved context that has been cryptographically verified.
pub struct VerifiedContext {
    pub inner: FullContext,
}

impl VerifiedContext {
    /// Retrieve a context and verify its signature using the strict
    /// default [`VerificationPolicy`].
    pub async fn fetch(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
    ) -> Result<Self, AcdpError> {
        Self::fetch_with_policy(client, resolver, ctx_id, &VerificationPolicy::default()).await
    }

    /// Retrieve a context and verify its signature with caller-controlled
    /// strictness.
    ///
    /// 1. Fetches `body + registry_state` from the registry.
    /// 2. Optionally runs `validate_body` (policy-controlled).
    /// 3. Recomputes `content_hash` over ProducerContent.
    /// 4. Resolves the producer's DID document; rejects non-`did:web`
    ///    when policy requires it.
    /// 5. Verifies the Ed25519 signature (or other supported algorithm).
    /// 6. Optionally verifies the `registry_receipt` placeholder.
    /// 7. Optionally rejects unknown statuses.
    pub async fn fetch_with_policy(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
    ) -> Result<Self, AcdpError> {
        let ctx = client.retrieve(ctx_id).await?;

        if policy.validate_body_schema {
            crate::validation::validate_body(&ctx.body)?;
        }

        if policy.verify_embedded_hashes {
            for dr in &ctx.body.data_refs {
                if dr.embedded.is_some() && dr.content_hash.is_some() {
                    crate::validation::verify_embedded_hash(dr)?;
                }
            }
        }

        if policy.require_did_web && !ctx.body.agent_id.as_str().starts_with("did:web:") {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "policy requires did:web agent_id; got '{}'",
                ctx.body.agent_id
            )));
        }

        let verifier = Verifier::new(resolver);
        verifier.verify_body(&ctx.body).await?;

        if !policy.allow_unknown_status {
            if let Some(other) = ctx.registry_state.status.as_other() {
                return Err(AcdpError::SchemaViolation(format!(
                    "policy.allow_unknown_status=false; registry returned '{other}'"
                )));
            }
        }

        if policy.verify_registry_receipt && ctx.registry_receipt.is_some() {
            return Err(AcdpError::NotImplemented(
                "registry_receipt verification reserved for v0.1+ (RFC-ACDP-0009 §2.7)".into(),
            ));
        }

        Ok(Self { inner: ctx })
    }

    pub fn body(&self) -> &crate::types::body::Body {
        &self.inner.body
    }

    pub fn registry_state(&self) -> &crate::types::body::RegistryState {
        &self.inner.registry_state
    }

    /// Optional registry receipt placeholder (RFC-ACDP-0009 §2.7,
    /// reserved for v0.1+).
    pub fn receipt(&self) -> Option<&serde_json::Value> {
        self.inner.registry_receipt.as_ref()
    }

    /// Verify the registry receipt, when one is present.
    ///
    /// In v0.0.1 receipts are not specified; this method is forward-compat
    /// scaffolding:
    /// - Returns `Ok(())` when no receipt is present (typical case).
    /// - Returns [`AcdpError::NotImplemented`] when a receipt **is**
    ///   present, signaling the consumer is talking to a v0.1+ registry
    ///   while running this v0.0.1 library. Consumers SHOULD upgrade.
    pub async fn verify_receipt(&self, _resolver: &WebResolver) -> Result<(), AcdpError> {
        if self.inner.registry_receipt.is_some() {
            return Err(AcdpError::NotImplemented(
                "registry_receipt verification is reserved for ACDP v0.1+ \
                 (RFC-ACDP-0009 §2.7); upgrade the acdp library to verify receipts"
                    .into(),
            ));
        }
        Ok(())
    }
}
