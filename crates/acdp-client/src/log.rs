//! Client-side transparency-log verification (ACDP 0.3, RFC-ACDP-0012
//! §9): checkpoints (§9.3) and inclusion proofs (§9.1) against the
//! registry's DID document.
//!
//! All failures map to [`AcdpError::InvalidLogProof`] — deliberately
//! **not** `InvalidReceipt`: a proof failure indicts the *log* (tree
//! membership, history consistency, checkpoint signature), never the
//! body, receipt, or head-receipt verdicts, which are independent
//! results and reported independently (RFC-ACDP-0012 §9.3, §11).
//! Transport-level DID-resolution failures keep their
//! transient/permanent classification so retry logic still works.

use acdp_did::web::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::log::{LogCheckpoint, LogInclusion, LogLeaf};

/// Verify a `log_checkpoint` value end-to-end per RFC-ACDP-0012 §9.3:
///
/// 1. **Schema-closed parse** — exact `checkpoint_version`
///    (`"acdp-log/1"`), well-formed `log_id`/`root_hash`, canonical
///    millisecond byte form of the RAW `timestamp`.
/// 2. **Recompute and verify the signature** — JCS-recompute the
///    preimage from the RAW wire JSON (minus `signature`), resolve
///    `signature.key_id` from the registry's DID document (with the
///    RFC-ACDP-0008 §4.8 SSRF protections the resolver applies), and
///    verify over the ASCII bytes of the checkpoint hash. Key
///    acceptance follows RFC-ACDP-0010 §9: the key is looked up in
///    `verificationMethod` WITHOUT requiring `assertionMethod`
///    membership, so retired receipt keys keep historical checkpoints
///    verifiable.
/// 3. **Registry binding** — the `registry_did` prefix of `log_id`
///    equals `did:web:<serving_authority>` (the authority the
///    checkpoint was actually fetched from) AND
///    `capabilities.registry_did`; `signature.key_id` is a DID URL
///    under that DID.
/// 4. **Form** — `timestamp` millisecond-truncated and not in the
///    future beyond `max_clock_skew` (RECOMMENDED 120 s). Staleness is
///    consumer freshness policy (§7.2), evaluated separately via
///    [`LogCheckpoint::age_at`].
pub async fn verify_log_checkpoint_value(
    value: &serde_json::Value,
    serving_authority: &str,
    capabilities_registry_did: &str,
    max_clock_skew: chrono::Duration,
    resolver: &WebResolver,
) -> Result<LogCheckpoint, AcdpError> {
    // §9.3 step 1: closed parse + form invariants.
    let checkpoint = LogCheckpoint::from_value(value)?;

    // §9.3 step 3 binding + step 4 form — pure checks before the
    // network round-trip for the signature, exactly like
    // `verify_receipt_value`.
    checkpoint.cross_check_registry_binding(serving_authority, capabilities_registry_did)?;
    checkpoint.check_timestamp_skew(chrono::Utc::now(), max_clock_skew)?;

    // §9.3 step 2: resolve the registry's receipt key and verify over
    // the RAW wire preimage (re-serializing the parsed struct could
    // normalize byte details and falsely reject an honest checkpoint —
    // and byte-comparing served values instead of recomputing is
    // exactly the mistake fixture log-004 exists to catch).
    let key_id = &checkpoint.signature.key_id;
    let (did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::InvalidLogProof(format!(
            "log_checkpoint signature.key_id '{key_id}' has no fragment"
        ))
    })?;
    let doc = resolver.resolve(did_part).await?;
    let method = doc.find_by_fragment(fragment).ok_or_else(|| {
        AcdpError::InvalidLogProof(format!(
            "registry DID document has no verification method '#{fragment}' — \
             receipt keys (including retired ones) must remain in verificationMethod \
             (RFC-ACDP-0010 §9)"
        ))
    })?;
    let raw_hash = LogCheckpoint::preimage_hash_of_value(value)?;
    match checkpoint.signature.algorithm.as_str() {
        "ed25519" => {
            let key = method.ed25519_public_key_bytes().map_err(|e| {
                AcdpError::InvalidLogProof(format!("checkpoint key extraction: {e}"))
            })?;
            checkpoint.verify_signature_against_hash(&raw_hash, Some(&key), None)?;
        }
        "ecdsa-p256" => {
            let key = method.ecdsa_p256_public_key_sec1().map_err(|e| {
                AcdpError::InvalidLogProof(format!("checkpoint key extraction: {e}"))
            })?;
            checkpoint.verify_signature_against_hash(&raw_hash, None, Some(&key))?;
        }
        other => {
            return Err(AcdpError::InvalidLogProof(format!(
                "log_checkpoint signature algorithm '{other}' is not supported"
            )));
        }
    }

    Ok(checkpoint)
}

/// Verify a `log_inclusion` value end-to-end per RFC-ACDP-0012 §9.1
/// (steps 2–6; step 1 — reconstructing the leaf from *verified*
/// material — is the caller's, since only the caller holds the
/// verified body, the recomputed `content_hash`, the resolved producer
/// key fingerprint, and the RFC-ACDP-0010-verified receipt):
///
/// 2. **Leaf hash** — `SHA-256(0x00 ‖ JCS(leaf))` over the
///    reconstructed leaf (§5.1). Any echoed `leaf` member in the proof
///    is ignored, never substituted.
/// 3. **Checkpoint** — the embedded `log_checkpoint` verified per §9.3
///    ([`verify_log_checkpoint_value`]).
/// 4. **Binding** — `tree_size` equals `log_checkpoint.tree_size`,
///    `log_id`s equal, `leaf_index < tree_size`.
/// 5. **Fold** the audit path (RFC 9162 §2.1.3.2).
/// 6. **Compare** the folded root against `log_checkpoint.root_hash`.
pub async fn verify_log_inclusion_value(
    value: &serde_json::Value,
    reconstructed_leaf: &LogLeaf,
    serving_authority: &str,
    capabilities_registry_did: &str,
    max_clock_skew: chrono::Duration,
    resolver: &WebResolver,
) -> Result<LogInclusion, AcdpError> {
    let inclusion = LogInclusion::from_value(value)?;

    // §9.1 step 3: verify the embedded checkpoint per §9.3, over its
    // RAW wire member.
    let checkpoint_value = value.get("log_checkpoint").ok_or_else(|| {
        AcdpError::InvalidLogProof("log_inclusion has no log_checkpoint member".into())
    })?;
    verify_log_checkpoint_value(
        checkpoint_value,
        serving_authority,
        capabilities_registry_did,
        max_clock_skew,
        resolver,
    )
    .await?;

    // §9.1 steps 2 + 4–6: hash the reconstructed leaf, check binding,
    // fold, compare.
    inclusion.verify_reconstructed_leaf(reconstructed_leaf)?;

    Ok(inclusion)
}
