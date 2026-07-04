//! High-level body / publish-request verification — RFC-ACDP-0001 §5.11
//! (7-step algorithm).
//!
//! This layer sits above `validation`, `types`, `crypto`, and `did`: it
//! recomputes the `content_hash`, runs structural validation, resolves
//! the producer DID, and verifies the signature envelope. The byte-level
//! primitives ([`acdp_crypto::verify_ed25519`] /
//! [`acdp_crypto::verify_ecdsa_p256`]) live in `crypto`.

use acdp_crypto::{verify_content_hash, verify_ecdsa_p256, verify_ed25519};
use acdp_primitives::error::AcdpError;
use acdp_types::body::{Body, Signature};
use acdp_types::primitives::ContentHash;
use acdp_types::publish::PublishRequest;

#[cfg(feature = "client")]
use {acdp_did::web::WebResolver, acdp_types::primitives::AgentDid};

/// Stateless verifier.  Requires a DID resolver to fetch producer keys.
#[cfg(feature = "client")]
pub struct Verifier<'a> {
    resolver: &'a WebResolver,
}

#[cfg(feature = "client")]
impl<'a> Verifier<'a> {
    pub fn new(resolver: &'a WebResolver) -> Self {
        Self { resolver }
    }

    /// Full end-to-end verification per RFC-ACDP-0001 §5.11.
    ///
    /// Steps:
    ///  1. (Implicit) Check `key_id` has a `#fragment`.
    ///  2. Verify `key_id` DID portion equals `body.agent_id`.
    ///  3. Resolve the DID document.
    ///  4. Find the verification method by fragment.
    ///  5. Check `assertionMethod` authorization.
    ///  6. Extract the Ed25519 public key.
    ///  7. Verify the signature over the content_hash ASCII bytes.
    ///
    ///  (Hash recomputation is step 0, performed first.)
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(
            name = "acdp.verify_body",
            skip_all,
            fields(ctx_id = %body.ctx_id.0, agent_id = body.agent_id.as_str()),
            err(Display)
        )
    )]
    pub async fn verify_body(&self, body: &Body) -> Result<(), AcdpError> {
        // Step -1 (BUG-04): structural / runtime validation. A body may be
        // cryptographically correct but protocol-invalid (non-did:web
        // producer, inverted data_period, oversize metadata). Catch those
        // before paying the SHA-256 + DID resolution cost.
        acdp_validation::validate_body(body)?;

        self.verify_body_signed(body).await
    }

    /// Verify only the hash recomputation + DID resolution + signature
    /// envelope, assuming structural validation has already been done by
    /// the caller. Use when you want to separate structural failures
    /// from cryptographic ones — e.g.
    /// `acdp::client::VerifiedContext::fetch_report` runs the
    /// structural part itself and records per-`DataRef` outcomes
    /// individually.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(
            name = "acdp.verify_body_signed",
            skip_all,
            fields(ctx_id = %body.ctx_id.0),
            err(Display)
        )
    )]
    pub async fn verify_body_signed(&self, body: &Body) -> Result<(), AcdpError> {
        self.verify_body_hash(body)?;
        #[cfg(feature = "tracing")]
        tracing::debug!(
            stage = "content_hash",
            "content hash recomputed and matched"
        );
        self.verify_body_signature(body).await?;
        #[cfg(feature = "tracing")]
        tracing::debug!(stage = "signature", "producer signature verified");
        Ok(())
    }

    /// Step 0 only — recompute the `content_hash` over ProducerContent
    /// and compare against `body.content_hash`. Lets diagnostic
    /// callers record hash-pass/fail independently of the signature
    /// stage (FEAT-05).
    pub fn verify_body_hash(&self, body: &Body) -> Result<(), AcdpError> {
        let body_val = serde_json::to_value(body)?;
        verify_content_hash(&body_val, &body.content_hash)
    }

    /// Steps 1–7 only — resolve the producer's DID, find the signing
    /// key, verify the signature over the (already-stored)
    /// `body.content_hash`. Assumes [`Self::verify_body_hash`] (or an
    /// equivalent check) has already run.
    pub async fn verify_body_signature(&self, body: &Body) -> Result<(), AcdpError> {
        verify_signature_envelope(
            &body.agent_id,
            &body.signature,
            &body.content_hash,
            self.resolver,
        )
        .await
    }
}

/// Verify the producer signature on a [`PublishRequest`] per RFC-ACDP-0003
/// §2.1 steps 7–8.
///
/// Assumes structural validation and `content_hash` recomputation have
/// already been performed (e.g. by `acdp::registry::PublishValidator::validate_post_schema`).
/// Executes only the DID resolution + signature verification steps shared
/// with [`Verifier::verify_body`].
///
/// Used by `acdp::registry::RegistryServer::publish_verified` to fulfill
/// the §2.1 publish algorithm before persistence; consumers wanting end-to-end
/// verification on retrieval should prefer
/// `acdp::client::VerifiedContext::fetch` which calls [`Verifier::verify_body`].
#[cfg(feature = "client")]
#[cfg_attr(
    feature = "tracing",
    tracing::instrument(
        name = "acdp.verify_publish_request_signature",
        skip_all,
        fields(agent_id = req.agent_id.as_str(), key_id = %req.signature.key_id),
        err(Display)
    )
)]
pub async fn verify_publish_request_signature(
    req: &PublishRequest,
    resolver: &WebResolver,
) -> Result<(), AcdpError> {
    verify_signature_envelope(&req.agent_id, &req.signature, &req.content_hash, resolver).await
}

/// Steps 1–7 of RFC-ACDP-0001 §5.11 — the part of body verification that
/// operates only on the signature envelope and is identical for stored
/// `Body` values and incoming `PublishRequest` values. Caller is responsible
/// for hash recomputation (step 0).
#[cfg(feature = "client")]
async fn verify_signature_envelope(
    agent_id: &AgentDid,
    signature: &Signature,
    content_hash: &ContentHash,
    resolver: &WebResolver,
) -> Result<(), AcdpError> {
    // Step 1: parse key_id — must contain a non-empty '#' fragment
    // (RFC-ACDP-0001 §5.11 step 1). An empty fragment (`did:web:x#`) is
    // rejected rather than used as a lookup key (#22).
    let key_id = &signature.key_id;
    let (did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::KeyResolution(format!("signature.key_id '{key_id}' has no '#fragment'"))
    })?;
    if fragment.is_empty() {
        return Err(AcdpError::KeyResolution(format!(
            "signature.key_id '{key_id}' has an empty '#fragment'"
        )));
    }

    // Step 2: DID portion MUST equal agent_id
    if did_part != agent_id.as_str() {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "key_id DID '{did_part}' ≠ agent_id '{agent_id}'"
        )));
    }

    // Step 1.5: method dispatch. `did:key` resolves purely (the DID is
    // the key — no document fetch, no assertionMethod check); `did:web`
    // takes the HTTPS resolver path below. Any other method has no
    // resolver in this version.
    if did_part.starts_with("did:key:") {
        return verify_did_key_envelope(signature, content_hash);
    }
    if !did_part.starts_with("did:web:") {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "signatures require a did:web or did:key key_id; got '{did_part}'"
        )));
    }

    // Step 3: resolve DID document
    let doc = resolver.resolve(did_part).await?;

    // Step 4: find verification method by fragment
    let method = doc.find_by_fragment(fragment).ok_or_else(|| {
        AcdpError::KeyResolution(format!(
            "no verification method with fragment '#{fragment}'"
        ))
    })?;

    // Step 5: assertionMethod authorization
    if !doc.is_assertion_method(&method.id) {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "'{}' is not in assertionMethod",
            method.id
        )));
    }

    // Step 5.5: algorithm-downgrade rejection (RFC-ACDP-0008 §3.9 +
    // RFC-ACDP-0001 §5.11 step 6). When the verification method declares
    // an algorithm via its `type` (or `publicKeyJwk` params), it MUST equal
    // `signature.algorithm`. Otherwise an attacker could route an Ed25519
    // key through a verifier that thinks it's checking some other algorithm.
    if let Some(declared) = method.declared_algorithm() {
        if declared != signature.algorithm {
            return Err(AcdpError::InvalidSignature(format!(
                "signature.algorithm '{}' does not match verification method type \
                 (resolved key declares '{declared}')",
                signature.algorithm
            )));
        }
    }

    // Steps 6 + 7: dispatch by algorithm.
    match signature.algorithm.as_str() {
        "ed25519" => {
            let pub_bytes = method.ed25519_public_key_bytes()?;
            verify_ed25519(&pub_bytes, &signature.value, content_hash.as_str())
        }
        "ecdsa-p256" => {
            let pub_sec1 = method.ecdsa_p256_public_key_sec1()?;
            verify_ecdsa_p256(&pub_sec1, &signature.value, content_hash.as_str())
        }
        other => Err(AcdpError::UnsupportedAlgorithm(format!(
            "verifier does not support signature algorithm '{other}'"
        ))),
    }
}

/// Verify a signature envelope whose key is a `did:key` — a pure
/// function available without the `client` feature (no resolver, no
/// network, no async).
///
/// Performs:
/// 1. `key_id` form check (`did:key:z<mb>#z<mb>`, fragment = key).
/// 2. Pure key resolution from the DID itself.
/// 3. Algorithm-downgrade rejection: `signature.algorithm` MUST equal
///    the algorithm implied by the key's multicodec prefix
///    (RFC-ACDP-0008 §3.9).
/// 4. Signature verification over the ASCII bytes of `content_hash`.
///
/// The caller is responsible for the `key_id`-DID-equals-`agent_id`
/// binding check and for `content_hash` recomputation (use
/// [`verify_body_offline`] for the full pipeline).
pub fn verify_did_key_envelope(
    signature: &Signature,
    content_hash: &ContentHash,
) -> Result<(), AcdpError> {
    let material = acdp_did::key::resolve_did_key_url(&signature.key_id)?;

    if material.algorithm() != signature.algorithm {
        return Err(AcdpError::InvalidSignature(format!(
            "signature.algorithm '{}' does not match the did:key multicodec \
             (key implies '{}')",
            signature.algorithm,
            material.algorithm()
        )));
    }

    match material {
        acdp_did::key::DidKeyMaterial::Ed25519(pub_bytes) => {
            verify_ed25519(&pub_bytes, &signature.value, content_hash.as_str())
        }
        acdp_did::key::DidKeyMaterial::EcdsaP256(sec1_compressed) => {
            verify_ecdsa_p256(&sec1_compressed, &signature.value, content_hash.as_str())
        }
    }
}

/// Full offline body verification for `did:key` producers — works with
/// `--no-default-features` (no HTTP stack, no resolver, no async).
///
/// Pipeline (mirrors [`Verifier::verify_body`] minus DID-document
/// resolution, which did:key does not have):
/// 1. Structural validation ([`acdp_validation::validate_body`]).
/// 2. `content_hash` recomputation over ProducerContent (§5.7).
/// 3. `key_id` DID portion equals `agent_id`.
/// 4. Pure did:key envelope verification (algorithm + signature).
///
/// Returns [`AcdpError::KeyResolution`] for a `did:web` (or other
/// method) body — those require the resolver-backed
/// [`Verifier::verify_body`] under the `client` feature.
pub fn verify_body_offline(body: &Body) -> Result<(), AcdpError> {
    acdp_validation::validate_body(body)?;

    if !body.agent_id.as_str().starts_with("did:key:") {
        return Err(AcdpError::KeyResolution(format!(
            "verify_body_offline supports did:key producers only; '{}' requires \
             the resolver-backed Verifier (client feature)",
            body.agent_id
        )));
    }

    let body_val = serde_json::to_value(body)?;
    verify_content_hash(&body_val, &body.content_hash)?;

    let did_part = body
        .signature
        .key_id
        .split_once('#')
        .map(|(d, _)| d)
        .unwrap_or(body.signature.key_id.as_str());
    if did_part != body.agent_id.as_str() {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "key_id DID '{did_part}' ≠ agent_id '{}'",
            body.agent_id
        )));
    }

    verify_did_key_envelope(&body.signature, &body.content_hash)
}

/// Offline counterpart of [`verify_publish_request_signature`] for
/// `did:key` producers — used by registries (and the bindings) to verify
/// a publish request without the `client` feature. Assumes structural
/// validation and `content_hash` recomputation have already run
/// (e.g. via `PublishValidator::validate_post_schema`).
pub fn verify_publish_request_signature_offline(req: &PublishRequest) -> Result<(), AcdpError> {
    let key_id = req.signature.key_id.as_str();
    let did_part = key_id.split_once('#').map(|(d, _)| d).unwrap_or(key_id);
    if did_part != req.agent_id.as_str() {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "key_id DID '{did_part}' ≠ agent_id '{}'",
            req.agent_id
        )));
    }
    if !did_part.starts_with("did:key:") {
        return Err(AcdpError::KeyResolution(format!(
            "offline verification supports did:key only; got '{did_part}'"
        )));
    }
    verify_did_key_envelope(&req.signature, &req.content_hash)
}

/// Historical-key body-signature verification (ACDP 0.2, WS-B).
///
/// Identical to the standard envelope verification EXCEPT that the
/// `assertionMethod` membership check is skipped: a rotated-out key
/// that the producer retained in `verificationMethod` (per the
/// RFC-ACDP-0010 key-retention rule) still verifies. Callers MUST
/// gate this on a **verified registry receipt** whose
/// `key_fingerprint` matches this key — without that attestation,
/// accepting a non-assertion key is exactly the bypass the
/// `assertionMethod` check exists to prevent. did:key bodies never
/// take this path (the key cannot rotate).
#[cfg(feature = "client")]
pub async fn verify_body_signature_historical(
    body: &Body,
    resolver: &WebResolver,
) -> Result<(), AcdpError> {
    let key_id = &body.signature.key_id;
    let (did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::KeyResolution(format!("signature.key_id '{key_id}' has no '#fragment'"))
    })?;
    if did_part != body.agent_id.as_str() {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "key_id DID '{did_part}' ≠ agent_id '{}'",
            body.agent_id
        )));
    }
    if !did_part.starts_with("did:web:") {
        return Err(AcdpError::KeyResolution(format!(
            "historical-key verification applies to did:web only; got '{did_part}'"
        )));
    }
    let doc = resolver.resolve(did_part).await?;
    // Key fully removed from the DID document → fail closed. The
    // producer's obligation is to RETAIN rotated keys in
    // verificationMethod (RFC-ACDP-0010); a deleted key is
    // unverifiable by design.
    let method = doc.find_by_fragment(fragment).ok_or_else(|| {
        AcdpError::KeyResolution(format!(
            "no verification method with fragment '#{fragment}' — the key was \
             removed from the DID document, not just rotated out of assertionMethod"
        ))
    })?;
    if let Some(declared) = method.declared_algorithm() {
        if declared != body.signature.algorithm {
            return Err(AcdpError::InvalidSignature(format!(
                "signature.algorithm '{}' does not match verification method type \
                 (resolved key declares '{declared}')",
                body.signature.algorithm
            )));
        }
    }
    match body.signature.algorithm.as_str() {
        "ed25519" => verify_ed25519(
            &method.ed25519_public_key_bytes()?,
            &body.signature.value,
            body.content_hash.as_str(),
        ),
        "ecdsa-p256" => verify_ecdsa_p256(
            &method.ecdsa_p256_public_key_sec1()?,
            &body.signature.value,
            body.content_hash.as_str(),
        ),
        other => Err(AcdpError::UnsupportedAlgorithm(format!(
            "verifier does not support signature algorithm '{other}'"
        ))),
    }
}
