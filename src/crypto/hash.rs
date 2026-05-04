//! content_hash and lineage_id computation per RFC-ACDP-0001 §5.7 / §5.6.

use super::jcs::canonicalize_value;
use crate::error::AcdpError;
use crate::types::primitives::{ContentHash, CtxId, LineageId};
use sha2::{Digest, Sha256};

/// Fields excluded from ProducerContent (the hash/signature preimage).
///
/// RFC-ACDP-0001 §5.7: these fields are not known to the producer at signing
/// time, or cannot be part of their own hash/signature inputs.
const EXCLUDE: &[&str] = &[
    "content_hash",    // cannot contain its own hash
    "signature",       // over the hash, not in the hash
    "ctx_id",          // registry-assigned
    "lineage_id",      // registry-assigned
    "origin_registry", // registry-assigned
    "created_at",      // registry-assigned
];

/// Compute `content_hash` over a JSON representation of a body.
///
/// Strips the §5.7 exclusion set, JCS-canonicalizes, SHA-256 hashes,
/// and returns the result as `"sha256:<64-lowercase-hex>"`.
///
/// The input may be a `PublishRequest`, a stored `Body`, or any JSON object
/// that contains the producer-controlled fields.
pub fn compute_content_hash(body_value: &serde_json::Value) -> Result<ContentHash, AcdpError> {
    let mut map = body_value
        .as_object()
        .ok_or_else(|| AcdpError::InvalidBody("expected a JSON object".into()))?
        .clone();

    for key in EXCLUDE {
        map.remove(*key);
    }

    let canonical = canonicalize_value(&serde_json::Value::Object(map));
    let digest = Sha256::digest(&canonical);
    Ok(ContentHash(format!("sha256:{}", hex::encode(digest))))
}

/// Derive the `lineage_id` from the first version's `ctx_id`.
///
/// Formula (RFC-ACDP-0001 §5.6):
/// `lineage_id = "lin:sha256:" + lowercase_hex(SHA-256(utf8(ctx_id)))`
pub fn derive_lineage_id(first_ctx_id: &CtxId) -> LineageId {
    let digest = Sha256::digest(first_ctx_id.as_str().as_bytes());
    LineageId(format!("lin:sha256:{}", hex::encode(digest)))
}

/// Verify that a stored `content_hash` matches the recomputed value.
///
/// Returns `Ok(())` if they match, `Err(AcdpError::HashMismatch)` otherwise.
pub fn verify_content_hash(
    body_value: &serde_json::Value,
    stored: &ContentHash,
) -> Result<(), AcdpError> {
    let recomputed = compute_content_hash(body_value)?;
    if &recomputed != stored {
        return Err(AcdpError::HashMismatch {
            stored: stored.clone(),
            recomputed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn golden_content_hash() {
        // Matches sig-001-ed25519-golden.json expected.content_hash
        let body = json!({
            "version": 1,
            "supersedes": null,
            "agent_id": "did:web:agents.example.com:test-producer",
            "contributors": [],
            "title": "Golden test vector — minimal first version",
            "type": "data_snapshot",
            "data_refs": [],
            "derived_from": [],
            "visibility": "public"
        });
        let h = compute_content_hash(&body).unwrap();
        assert_eq!(
            h.as_str(),
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5"
        );
    }

    #[test]
    fn exclusion_set_applied() {
        let base = json!({
            "version": 1, "supersedes": null,
            "agent_id": "did:web:x", "contributors": [],
            "title": "T", "type": "data_snapshot",
            "data_refs": [], "derived_from": [], "visibility": "public"
        });
        // Adding excluded fields should NOT change the hash
        let mut with_excluded = base.as_object().unwrap().clone();
        with_excluded.insert("ctx_id".into(), json!("acdp://x/y"));
        with_excluded.insert("created_at".into(), json!("2026-01-01T00:00:00.000Z"));
        with_excluded.insert("content_hash".into(), json!("sha256:aabb"));
        with_excluded.insert(
            "signature".into(),
            json!({"algorithm":"ed25519","key_id":"k","value":"v"}),
        );

        let h1 = compute_content_hash(&base).unwrap();
        let h2 = compute_content_hash(&serde_json::Value::Object(with_excluded)).unwrap();
        assert_eq!(h1, h2, "excluded fields must not affect content_hash");
    }

    #[test]
    fn lineage_id_golden() {
        let ctx = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
        let lid = derive_lineage_id(&ctx);
        assert_eq!(
            lid.as_str(),
            "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a"
        );
    }
}
