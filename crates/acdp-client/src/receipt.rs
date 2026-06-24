//! Client-side registry-receipt verification (ACDP 0.2, RFC-ACDP-0010).
//!
//! Runs the full cross-check set. The cross-checks — not the signature
//! alone — are the security value: a receipt that verifies
//! cryptographically but binds a different `ctx_id`, a different body
//! hash, a different producer key, or a foreign registry is an attack,
//! not a receipt.

use acdp_did::web::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::primitives::{ContentHash, CtxId};
use acdp_types::receipt::RegistryReceipt;

/// Verify a `registry_receipt` value end-to-end:
///
/// 1. Parse. The receipt schema is CLOSED (RFC-ACDP-0010 §4): an
///    unknown member fails parsing with `invalid_receipt`.
/// 2. `registry_did` equals `did:web:<serving_authority>` — the
///    authority the context was actually fetched from, not whatever
///    the receipt claims.
/// 3. Pure cross-checks: `ctx_id`, `content_hash` (against the
///    *recomputed* body hash), `key_fingerprint` (against the resolved
///    producer key), millisecond `created_at`, internal
///    `registry_did`/`origin_registry` consistency.
/// 4. Resolve the registry's DID document and verify the receipt
///    signature. The receipt key is looked up in `verificationMethod`
///    WITHOUT requiring `assertionMethod` membership: retired receipt
///    keys remain in `verificationMethod` indefinitely (RFC-ACDP-0010
///    key lifecycle), keeping old receipts verifiable after rotation.
///
/// All failures map to [`AcdpError::InvalidReceipt`] except transport-
/// level DID-resolution failures, which keep their transient/permanent
/// classification so retry logic still works.
pub async fn verify_receipt_value(
    value: &serde_json::Value,
    expected_ctx_id: &CtxId,
    body: &acdp_types::body::Body,
    recomputed_body_hash: &ContentHash,
    producer_key_fingerprint: &str,
    serving_authority: &str,
    resolver: &WebResolver,
) -> Result<RegistryReceipt, AcdpError> {
    let receipt = RegistryReceipt::from_value(value)?;

    // §8 step 6: canonical millisecond byte form, checked on the RAW
    // wire string before any parsing normalization.
    RegistryReceipt::validate_created_at_form(value)?;

    // Serving-authority binding (the client-side half of cross-check 2;
    // the receipt-internal half lives in `RegistryReceipt::cross_check`).
    let expected_did = acdp_did::web::authority_to_did_web(serving_authority);
    if receipt.registry_did != expected_did {
        return Err(AcdpError::InvalidReceipt(format!(
            "receipt registry_did '{}' ≠ serving authority's DID '{expected_did}'",
            receipt.registry_did
        )));
    }

    receipt.cross_check(
        expected_ctx_id,
        recomputed_body_hash,
        producer_key_fingerprint,
    )?;
    // §8 step 3 body bindings: lineage_id / origin_registry /
    // created_at must equal the accompanying body's fields.
    receipt.cross_check_body(body)?;

    // Resolve the registry's receipt key and verify the signature.
    let key_id = &receipt.signature.key_id;
    let (did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::InvalidReceipt(format!(
            "receipt signature.key_id '{key_id}' has no fragment"
        ))
    })?;
    if did_part != receipt.registry_did {
        return Err(AcdpError::InvalidReceipt(format!(
            "receipt signature.key_id DID '{did_part}' ≠ registry_did '{}'",
            receipt.registry_did
        )));
    }
    let doc = resolver.resolve(did_part).await?;
    let method = doc.find_by_fragment(fragment).ok_or_else(|| {
        AcdpError::InvalidReceipt(format!(
            "registry DID document has no verification method '#{fragment}' — \
             receipt keys (including retired ones) must remain in verificationMethod"
        ))
    })?;

    // §5 / RFC-ACDP-0001 §6 raw-JSON rule: hash the receipt exactly as
    // received — re-serializing the parsed struct could normalize byte
    // details and falsely reject an honest receipt.
    let raw_hash = RegistryReceipt::preimage_hash_of_value(value)?;
    match receipt.signature.algorithm.as_str() {
        "ed25519" => {
            let key = method
                .ed25519_public_key_bytes()
                .map_err(|e| AcdpError::InvalidReceipt(format!("receipt key extraction: {e}")))?;
            receipt.verify_signature_against_hash(&raw_hash, Some(&key), None)?;
        }
        "ecdsa-p256" => {
            let key = method
                .ecdsa_p256_public_key_sec1()
                .map_err(|e| AcdpError::InvalidReceipt(format!("receipt key extraction: {e}")))?;
            receipt.verify_signature_against_hash(&raw_hash, None, Some(&key))?;
        }
        other => {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt signature algorithm '{other}' is not supported"
            )));
        }
    }

    Ok(receipt)
}
