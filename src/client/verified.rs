//! VerifiedContext: retrieve + verify in one call.

use super::data_ref::{fetch_and_verify_data_ref, DataRefFetcher};
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

        // BUG-05: use `verify_body_signed` (hash + signature only) so
        // the schema / embedded-hash / did-web checks above stay
        // policy-controlled. Calling `verify_body` here re-runs
        // `validate_body` unconditionally — which previously made
        // `policy.validate_body_schema = false`, `require_did_web =
        // false`, and `verify_embedded_hashes = false` no-ops.
        let verifier = Verifier::new(resolver);
        verifier.verify_body_signed(&ctx.body).await?;

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

    /// Retrieve + verify, returning a structured [`VerificationReport`]
    /// alongside the verified context. Does NOT attempt external
    /// `DataRef` fetches — use [`Self::fetch_report_with_fetcher`] for
    /// that. Each `data_ref_external` slot in the returned report is
    /// `None`.
    ///
    /// Unlike [`Self::fetch_with_policy`], per-`DataRef` embedded-hash
    /// failures are recorded in the report instead of aborting the
    /// verification. The top-level checks (schema, body hash,
    /// signature) remain hard-fail: if any of them fails, the method
    /// returns an `AcdpError` and produces no report.
    ///
    /// For diagnostic callers that want a populated report even when
    /// a top-level check fails (e.g. an audit walker that needs to
    /// distinguish "wrong hash" from "wrong signature"), use
    /// [`Self::fetch_report_diagnose`] instead.
    pub async fn fetch_report(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
    ) -> Result<(Self, VerificationReport), AcdpError> {
        Self::fetch_report_inner::<NoFetcher>(client, resolver, ctx_id, policy, None).await
    }

    /// Diagnostic variant of [`Self::fetch_report`] that never
    /// short-circuits on a top-level failure — schema, body-hash, and
    /// signature outcomes are each recorded individually in the
    /// returned [`VerificationReport`]. Returns `Ok((None, report))`
    /// when any top-level stage failed (the report shows which one);
    /// `Ok((Some(verified), report))` only when every check passed
    /// (FEAT-05).
    ///
    /// Use cases:
    /// - Audit walkers that need to classify failures by stage.
    /// - Admin tooling that wants to distinguish "hash mismatch"
    ///   (probable tampering / encoding drift) from "signature
    ///   verification failed" (key compromise / DID resolution
    ///   problem).
    ///
    /// Network errors (retrieve, DID resolution) still propagate as
    /// `Err` — there's no body to inspect when the registry is
    /// unreachable.
    pub async fn fetch_report_diagnose(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
    ) -> Result<(Option<Self>, VerificationReport), AcdpError> {
        let ctx = client.retrieve(ctx_id).await?;
        let mut report = VerificationReport {
            body_hash_ok: false,
            signature_ok: false,
            schema_ok: false,
            data_ref_embedded: Vec::with_capacity(ctx.body.data_refs.len()),
            data_ref_external: Vec::with_capacity(ctx.body.data_refs.len()),
        };

        // Schema (structural) — record pass/fail.
        if policy.validate_body_schema {
            match crate::validation::validate_body_structural(&ctx.body) {
                Ok(()) => report.schema_ok = true,
                Err(_) => { /* keep schema_ok=false; continue collecting */ }
            }
        } else {
            report.schema_ok = true;
        }

        // Per-DataRef embedded hashes — same as fetch_report_inner.
        for dr in &ctx.body.data_refs {
            if let (Some(emb), Some(_)) = (&dr.embedded, &dr.content_hash) {
                let outcome = crate::validation::verify_embedded_hash(dr)
                    .and_then(|()| crate::validation::embedded_decoded_bytes(emb).map(|b| b.len()));
                report.data_ref_embedded.push(outcome);
            } else {
                report.data_ref_embedded.push(Ok(0));
            }
        }

        // Hash + signature recorded independently (FEAT-05).
        let verifier = Verifier::new(resolver);
        report.body_hash_ok = verifier.verify_body_hash(&ctx.body).is_ok();
        report.signature_ok = verifier.verify_body_signature(&ctx.body).await.is_ok();

        // External fetches were not attempted (this method has no
        // fetcher param — diagnostic callers can wire their own).
        for _ in &ctx.body.data_refs {
            report.data_ref_external.push(None);
        }

        // Decide whether to surface the verified handle.
        let all_top_level_pass = report.schema_ok && report.body_hash_ok && report.signature_ok;
        let verified = if all_top_level_pass {
            Some(Self { inner: ctx })
        } else {
            None
        };
        Ok((verified, report))
    }

    /// Retrieve + verify like [`Self::fetch_report`], and additionally
    /// fetch every `DataRef` whose `location` resolves through `fetcher`.
    /// Each external fetch outcome is recorded in `report.data_ref_external`.
    pub async fn fetch_report_with_fetcher<F: DataRefFetcher>(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
        fetcher: &F,
    ) -> Result<(Self, VerificationReport), AcdpError> {
        Self::fetch_report_inner(client, resolver, ctx_id, policy, Some(fetcher)).await
    }

    async fn fetch_report_inner<F: DataRefFetcher>(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
        fetcher: Option<&F>,
    ) -> Result<(Self, VerificationReport), AcdpError> {
        let ctx = client.retrieve(ctx_id).await?;
        let mut report = VerificationReport {
            body_hash_ok: false,
            signature_ok: false,
            schema_ok: false,
            data_ref_embedded: Vec::with_capacity(ctx.body.data_refs.len()),
            data_ref_external: Vec::with_capacity(ctx.body.data_refs.len()),
        };

        // Structural-only schema validation — embedded-hash checks are
        // intentionally skipped here so per-DataRef hash failures land
        // in the report (below) instead of short-circuiting the whole
        // verification. That's the diagnostic shape `fetch_report`
        // promises in its docstring.
        if policy.validate_body_schema {
            crate::validation::validate_body_structural(&ctx.body)?;
        }
        report.schema_ok = true;

        // Per-DataRef embedded-hash outcomes — recorded individually.
        for dr in &ctx.body.data_refs {
            if let (Some(emb), Some(_)) = (&dr.embedded, &dr.content_hash) {
                let outcome = crate::validation::verify_embedded_hash(dr)
                    .and_then(|()| crate::validation::embedded_decoded_bytes(emb).map(|b| b.len()));
                report.data_ref_embedded.push(outcome);
            } else {
                report.data_ref_embedded.push(Ok(0));
            }
        }

        if policy.require_did_web && !ctx.body.agent_id.as_str().starts_with("did:web:") {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "policy requires did:web agent_id; got '{}'",
                ctx.body.agent_id
            )));
        }

        // `verify_body_signed` recomputes content_hash + verifies the
        // signature WITHOUT re-running the schema validator (we already
        // ran the structural part above, and embedded-hash failures are
        // recorded per-DataRef rather than aborting).
        Verifier::new(resolver)
            .verify_body_signed(&ctx.body)
            .await?;
        report.body_hash_ok = true;
        report.signature_ok = true;

        if !policy.allow_unknown_status {
            if let Some(other) = ctx.registry_state.status.as_other() {
                return Err(AcdpError::SchemaViolation(format!(
                    "policy.allow_unknown_status=false; registry returned '{other}'"
                )));
            }
        }

        // External fetches — record per-ref outcomes when a fetcher is
        // supplied; otherwise leave each slot as `None` so callers can
        // distinguish "skipped" from "failed".
        for dr in &ctx.body.data_refs {
            let slot: Option<Result<usize, AcdpError>> = match (fetcher, &dr.location) {
                (Some(f), Some(_)) => Some(fetch_and_verify_data_ref(dr, f).await.map(|b| b.len())),
                _ => None,
            };
            report.data_ref_external.push(slot);
        }

        Ok((Self { inner: ctx }, report))
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
    /// In v0.1.0 receipts are not specified; this method is forward-compat
    /// scaffolding:
    /// - Returns `Ok(())` when no receipt is present (typical case).
    /// - Returns [`AcdpError::NotImplemented`] when a receipt **is**
    ///   present, signaling the consumer is talking to a v0.1+ registry
    ///   while running this v0.1.0 library. Consumers SHOULD upgrade.
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

/// Structured diagnostic outcome from [`VerifiedContext::fetch_report`].
///
/// Top-level booleans report the per-stage outcome of the verification
/// pipeline. Per-`DataRef` slots track outcomes for each entry in
/// `body.data_refs`, in declaration order:
///
/// - `data_ref_embedded[i]` — `Ok(decoded_size_bytes)` when the embedded
///   payload's `content_hash` matched; `Err` when it didn't (or the
///   embedded was malformed). Refs without an embedded payload or
///   without a declared `content_hash` produce `Ok(0)`.
/// - `data_ref_external[i]` — `None` when no external fetch was
///   attempted (either no `location` or no `fetcher` was provided);
///   `Some(Ok(bytes_len))` when the fetch + hash succeeded;
///   `Some(Err(_))` on any failure (SSRF rejection, hash mismatch,
///   timeout, …).
///
/// `AcdpError` doesn't implement `Clone`, so the report is move-only.
#[derive(Debug)]
pub struct VerificationReport {
    /// `content_hash` recomputed from the body matches the declared one.
    pub body_hash_ok: bool,
    /// The producer signature verified against the resolved DID key.
    pub signature_ok: bool,
    /// `validate_body` passed (or was disabled by policy).
    pub schema_ok: bool,
    /// Per-`DataRef` embedded-hash outcome, in `body.data_refs` order.
    pub data_ref_embedded: Vec<Result<usize, AcdpError>>,
    /// Per-`DataRef` external-fetch outcome, in `body.data_refs` order.
    /// `None` indicates "not attempted" (no fetcher provided or no
    /// `location` to fetch from).
    pub data_ref_external: Vec<Option<Result<usize, AcdpError>>>,
}

/// Sentinel `DataRefFetcher` used as the type parameter for
/// `fetch_report_inner` when no fetcher is supplied. `fetch` is never
/// actually called — the option is matched out before that — but
/// providing a real impl lets the generic monomorphize cleanly without
/// requiring `fetch_report`'s callers to name a type.
struct NoFetcher;

impl DataRefFetcher for NoFetcher {
    async fn fetch(
        &self,
        _location: &crate::types::data_ref::Location,
    ) -> Result<Vec<u8>, AcdpError> {
        Err(AcdpError::NotImplemented(
            "NoFetcher should never be called — this is a fetch_report sentinel".into(),
        ))
    }
}
