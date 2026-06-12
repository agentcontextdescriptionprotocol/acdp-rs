//! VerifiedContext: retrieve + verify in one call.

use super::data_ref::{fetch_and_verify_data_ref, DataRefFetcher};
use super::registry::RegistryClient;
use crate::crypto::verify::Verifier;
use crate::did::WebResolver;
use crate::error::AcdpError;
use crate::types::{body::FullContext, primitives::CtxId};

/// Consumer-tunable strictness for [`VerifiedContext::fetch_with_policy`].
///
/// For ACDP v0.1.0 the verification profile is **always strict**:
///
/// - `did:web` is required for every producer identity — enforced
///   unconditionally by `verify_signature_envelope`
///   (RFC-ACDP-0001 §5.4), regardless of any policy field.
/// - Embedded `DataRef` hashes are verified by
///   [`crate::validation::validate_body`] whenever `validate_body_schema`
///   is set.
///
/// Only the fields below have real effect in this version; there are no
/// relaxed-mode `did:web` or embedded-hash knobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPolicy {
    /// If true, run [`crate::validation::validate_body`] (structural
    /// schema checks plus embedded-`DataRef` hash verification) before
    /// any cryptographic check. Default `true`. Set `false` only in
    /// diagnostic paths that want to attempt signature verification
    /// despite a body known to fail structural checks.
    pub validate_body_schema: bool,

    /// If true, accept `Status::Other` values (degrade to active per
    /// RFC-ACDP-0004 §4.1). When false, reject unknown statuses.
    /// Default `true`.
    pub allow_unknown_status: bool,

    /// Registry-receipt handling (ACDP 0.2, RFC-ACDP-0010).
    /// Default [`ReceiptPolicy::VerifyIfPresent`].
    pub receipts: ReceiptPolicy,

    /// Historical-key handling (ACDP 0.2, WS-B). Default
    /// [`HistoricalKeyPolicy::AcceptWithReceipt`].
    pub historical_keys: HistoricalKeyPolicy,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            validate_body_schema: true,
            allow_unknown_status: true,
            receipts: ReceiptPolicy::VerifyIfPresent,
            historical_keys: HistoricalKeyPolicy::AcceptWithReceipt,
        }
    }
}

/// How to treat the optional `registry_receipt` on retrieval
/// (RFC-ACDP-0010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReceiptPolicy {
    /// Skip receipt verification entirely (0.1.0 behavior). The
    /// receipt value is still preserved verbatim on the context.
    Ignore,
    /// Verify the receipt when one is present; absence is not an
    /// error (the registry may simply be a 0.1.0 registry). Default.
    #[default]
    VerifyIfPresent,
    /// Fail closed unless a receipt is present AND verifies. Use when
    /// the deployment requires audit-grade provenance — registry
    /// claims (`ctx_id`, `created_at`, `origin_registry`) are
    /// assertions, not proofs, without a receipt.
    Require,
}

/// How to treat a producer key that is present in the DID document's
/// `verificationMethod` but no longer in `assertionMethod` — i.e. a
/// key the producer rotated out but retained per the RFC-ACDP-0010
/// key-retention rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HistoricalKeyPolicy {
    /// Strict 0.1.0 behavior: only `assertionMethod` keys verify.
    /// Every context signed by a rotated-out key fails.
    Reject,
    /// Accept a retained key **only** when a verified registry receipt
    /// attests (via `key_fingerprint`) that this exact key was the
    /// authorized one at publish time. Without a verified receipt the
    /// historical path never activates — fail closed. Default.
    #[default]
    AcceptWithReceipt,
}

/// How the producer key that verified the body relates to the
/// producer's *current* DID document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAuthorization {
    /// The signing key is currently listed in `assertionMethod`.
    CurrentlyAuthorized,
    /// The signing key was rotated out of `assertionMethod` but is
    /// retained in `verificationMethod`, and a verified registry
    /// receipt attests it was the authorized key at publish time
    /// (RFC-ACDP-0010). Weigh accordingly: valid history, not a
    /// current endorsement.
    HistoricallyAuthorized,
}

impl VerificationPolicy {
    /// The v0.1.0 strict verification profile (RFC-ACDP-0001 §5.11, §9.2).
    ///
    /// Runs the full §5.11 pipeline: body schema validation, `content_hash`
    /// recomputation, `did:web` key resolution, signature verification, and
    /// embedded `data_ref.content_hash` checks. Returns on the first failure.
    ///
    /// This is the **only** mode covered by the `acdp-consumer` conformance
    /// profile. Relaxed modes (`Diagnostic`, `UnsafeForTests`) are NOT
    /// available in this crate in v0.1.0 — they would be separately-named
    /// opt-ins per §9.2, and are not currently implemented.
    ///
    /// NOT identical to [`Default::default()`] as of 0.2: the default
    /// policy is receipt-aware (`VerifyIfPresent` + `AcceptWithReceipt`),
    /// while this named profile preserves the exact v0.1.0 semantics —
    /// receipts inert ([`ReceiptPolicy::Ignore`]) and only
    /// `assertionMethod` keys accepted
    /// ([`HistoricalKeyPolicy::Reject`]). Callers pinned to this
    /// constructor keep v0.1.0 behavior across the 0.2 upgrade.
    pub fn strict_v0_1_0() -> Self {
        Self {
            validate_body_schema: true,
            allow_unknown_status: true,
            receipts: ReceiptPolicy::Ignore,
            historical_keys: HistoricalKeyPolicy::Reject,
        }
    }
}

/// A retrieved context that has been cryptographically verified.
#[derive(Debug)]
pub struct VerifiedContext {
    pub inner: FullContext,
    /// Whether the body verified against a currently authorized key or
    /// a receipt-attested historical one (ACDP 0.2, WS-B).
    pub key_status: KeyAuthorization,
    /// The verified registry receipt, when one was present and the
    /// policy verified it (RFC-ACDP-0010). `None` under
    /// [`ReceiptPolicy::Ignore`] or when the registry minted none.
    pub verified_receipt: Option<crate::types::receipt::RegistryReceipt>,
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
    /// 2. Optionally runs `validate_body` — structural schema checks
    ///    plus embedded-`DataRef` hash verification (policy-controlled).
    /// 3. Recomputes `content_hash` over ProducerContent.
    /// 4. Resolves the producer's DID document. `did:web` is required
    ///    unconditionally for v0.1.0 (RFC-ACDP-0001 §5.4).
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

        // Hash recomputation first: from here on `ctx.body.content_hash`
        // IS the independently recomputed value, which the receipt
        // cross-check below relies on.
        let verifier = Verifier::new(resolver);
        verifier.verify_body_hash(&ctx.body)?;

        // ── Receipt phase (RFC-ACDP-0010) ───────────────────────────
        // Verified BEFORE the signature phase because the historical-
        // key path is gated on a verified receipt.
        let serving_authority = client
            .authority()
            .unwrap_or_else(|| ctx_id.authority().to_string());
        let verified_receipt = match (policy.receipts, &ctx.registry_receipt) {
            (ReceiptPolicy::Ignore, _) | (ReceiptPolicy::VerifyIfPresent, None) => None,
            (ReceiptPolicy::Require, None) => {
                return Err(AcdpError::InvalidReceipt(
                    "policy requires a registry receipt but the response carries none \
                     (registry without the acdp-registry-receipts profile, or a \
                     pre-receipts context)"
                        .into(),
                ));
            }
            (_, Some(value)) => {
                let fingerprint = crate::crypto::fingerprint::fingerprint_for_key_id(
                    &ctx.body.signature.key_id,
                    &ctx.body.signature.algorithm,
                    resolver,
                )
                .await?;
                Some(
                    super::receipt::verify_receipt_value(
                        value,
                        ctx_id,
                        &ctx.body,
                        &ctx.body.content_hash,
                        &fingerprint,
                        &serving_authority,
                        resolver,
                    )
                    .await?,
                )
            }
        };

        // ── Signature phase ──────────────────────────────────────────
        // Standard path enforces assertionMethod membership. A
        // KeyNotAuthorized failure falls back to the historical path
        // only under AcceptWithReceipt AND a verified receipt — the
        // receipt's key_fingerprint (already cross-checked against this
        // exact key above) is what attests publish-time authorization.
        let key_status = match verifier.verify_body_signature(&ctx.body).await {
            Ok(()) => KeyAuthorization::CurrentlyAuthorized,
            Err(AcdpError::KeyNotAuthorized(_))
                if policy.historical_keys == HistoricalKeyPolicy::AcceptWithReceipt
                    && verified_receipt.is_some() =>
            {
                crate::crypto::verify::verify_body_signature_historical(&ctx.body, resolver)
                    .await?;
                KeyAuthorization::HistoricallyAuthorized
            }
            Err(e) => return Err(e),
        };

        if !policy.allow_unknown_status {
            if let Some(other) = ctx.registry_state.status.as_other() {
                return Err(AcdpError::SchemaViolation(format!(
                    "policy.allow_unknown_status=false; registry returned '{other}'"
                )));
            }
        }

        Ok(Self {
            inner: ctx,
            key_status,
            verified_receipt,
        })
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

        // Decide whether to surface the verified handle. Report paths
        // run the strict assertionMethod check only (no receipt /
        // historical handling — use `fetch_with_policy` for those).
        let all_top_level_pass = report.schema_ok && report.body_hash_ok && report.signature_ok;
        let verified = if all_top_level_pass {
            Some(Self {
                inner: ctx,
                key_status: KeyAuthorization::CurrentlyAuthorized,
                verified_receipt: None,
            })
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

        // `verify_body_signed` recomputes content_hash + verifies the
        // signature WITHOUT re-running the schema validator (we already
        // ran the structural part above, and embedded-hash failures are
        // recorded per-DataRef rather than aborting). It still enforces
        // `did:web` for the producer key (RFC-ACDP-0001 §5.4).
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

        Ok((
            Self {
                inner: ctx,
                key_status: KeyAuthorization::CurrentlyAuthorized,
                verified_receipt: None,
            },
            report,
        ))
    }

    pub fn body(&self) -> &crate::types::body::Body {
        &self.inner.body
    }

    pub fn registry_state(&self) -> &crate::types::body::RegistryState {
        &self.inner.registry_state
    }

    /// Raw registry receipt value as served on the wire
    /// (RFC-ACDP-0010), preserved verbatim. For the verified, typed
    /// form see [`Self::verified_receipt`].
    pub fn receipt(&self) -> Option<&serde_json::Value> {
        self.inner.registry_receipt.as_ref()
    }

    /// Verify the registry receipt, when one is present
    /// (RFC-ACDP-0010).
    ///
    /// Standalone variant for contexts obtained via the report paths or
    /// constructed externally; `fetch_with_policy` already does this
    /// under [`ReceiptPolicy::VerifyIfPresent`]/`Require`. The serving
    /// authority is taken from the context's own `ctx_id` — correct
    /// when the context was fetched from its home registry, which is
    /// the only retrieval shape v0.2 defines.
    ///
    /// Returns `Ok(None)` when no receipt is present, `Ok(Some(_))`
    /// with the verified receipt otherwise.
    pub async fn verify_receipt(
        &self,
        resolver: &WebResolver,
    ) -> Result<Option<crate::types::receipt::RegistryReceipt>, AcdpError> {
        let Some(value) = &self.inner.registry_receipt else {
            return Ok(None);
        };
        // Recompute the body hash rather than trusting the echoed
        // `body.content_hash`: all fields of this type are public, so a
        // caller may have constructed it around an unverified
        // FullContext, and the receipt cross-check is only meaningful
        // against an independently recomputed hash (RFC-ACDP-0010 §8
        // step 4).
        let body_val = serde_json::to_value(&self.inner.body)?;
        let recomputed = crate::crypto::compute_content_hash(&body_val)?;
        if recomputed != self.inner.body.content_hash {
            return Err(AcdpError::HashMismatch {
                stored: self.inner.body.content_hash.clone(),
                recomputed,
            });
        }
        let fingerprint = crate::crypto::fingerprint::fingerprint_for_key_id(
            &self.inner.body.signature.key_id,
            &self.inner.body.signature.algorithm,
            resolver,
        )
        .await?;
        let receipt = super::receipt::verify_receipt_value(
            value,
            &self.inner.body.ctx_id,
            &self.inner.body,
            &self.inner.body.content_hash,
            &fingerprint,
            self.inner.body.ctx_id.authority(),
            resolver,
        )
        .await?;
        Ok(Some(receipt))
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

#[cfg(test)]
mod tests {
    use super::{HistoricalKeyPolicy, ReceiptPolicy, VerificationPolicy};

    /// The RFC-ACDP-0001 §9.2 named constructor preserves exact v0.1.0
    /// semantics: receipts inert, assertionMethod-only keys. It is
    /// deliberately NOT the 0.2 default (which is receipt-aware).
    #[test]
    fn strict_v0_1_0_preserves_v0_1_0_semantics() {
        let strict = VerificationPolicy::strict_v0_1_0();
        assert!(strict.validate_body_schema);
        assert!(strict.allow_unknown_status);
        assert_eq!(strict.receipts, ReceiptPolicy::Ignore);
        assert_eq!(strict.historical_keys, HistoricalKeyPolicy::Reject);
        assert_ne!(
            strict,
            VerificationPolicy::default(),
            "the 0.2 default is receipt-aware; the v0.1.0 profile is not"
        );
    }
}
