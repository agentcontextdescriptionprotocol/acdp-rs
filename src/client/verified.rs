//! VerifiedContext: retrieve + verify in one call.

use super::registry::RegistryClient;
use crate::crypto::verify::Verifier;
use crate::did::WebResolver;
use crate::error::AcdpError;
use crate::types::{body::FullContext, primitives::CtxId};

/// A retrieved context that has been cryptographically verified.
pub struct VerifiedContext {
    pub inner: FullContext,
}

impl VerifiedContext {
    /// Retrieve a context and verify its signature in one call.
    ///
    /// 1. Fetches `body + registry_state` from the registry.
    /// 2. Recomputes `content_hash` over ProducerContent.
    /// 3. Resolves the producer's DID document.
    /// 4. Verifies the Ed25519 signature.
    pub async fn fetch(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
    ) -> Result<Self, AcdpError> {
        let ctx = client.retrieve(ctx_id).await?;
        let verifier = Verifier::new(resolver);
        verifier.verify_body(&ctx.body).await?;
        Ok(Self { inner: ctx })
    }

    pub fn body(&self) -> &crate::types::body::Body {
        &self.inner.body
    }

    pub fn registry_state(&self) -> &crate::types::body::RegistryState {
        &self.inner.registry_state
    }
}
