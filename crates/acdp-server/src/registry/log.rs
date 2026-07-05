//! Reference in-memory transparency log (RFC-ACDP-0012) — an
//! append-only RFC 6962-style Merkle tree over publish-event leaves.
//!
//! [`MerkleLog`] is a **building block**, deliberately not wired into
//! [`crate::registry::RegistryServer`] or the store: real registries
//! (the separate `acdp-registry-*` crates) own the §7.1 atomicity rule
//! — body, receipt, and leaf commit together, or none does — and the §8
//! endpoint surface. What this type provides is the tree arithmetic and
//! the signed artifacts:
//!
//! - [`MerkleLog::append`] — one accepted publish → one leaf, forever,
//!   `leaf_index` assigned consecutively from 0 in acceptance order
//!   (§5.3, §7.1 rule 2);
//! - [`MerkleLog::checkpoint`] / [`MerkleLog::checkpoint_at`] — signed
//!   tree heads under the RFC-ACDP-0010 receipt signing key (§6);
//! - [`MerkleLog::inclusion_proof`] — RFC 6962 §2.1.1 audit paths
//!   packaged as [`LogInclusion`] (§8.2 inclusion mode);
//! - [`MerkleLog::consistency_proof`] — RFC 6962 §2.1.2 proofs
//!   (§8.2 consistency mode).
//!
//! Everything a checkpoint commits to is recomputable from the ordered
//! leaf hashes alone (§8.3), so the in-memory representation is exactly
//! that: the leaves plus their §5.1 hashes.

use acdp_primitives::error::AcdpError;
use acdp_types::log::{
    encode_sha256_hex, parse_log_id, LogCheckpoint, LogConsistencyProof, LogInclusion, LogLeaf,
};
use acdp_types::receipt::ReceiptSigner;
use chrono::{DateTime, Utc};
use std::collections::HashSet;

/// An append-only, in-memory RFC 6962-style Merkle tree over
/// transparency-log leaves (RFC-ACDP-0012 §5).
#[derive(Debug, Clone)]
pub struct MerkleLog {
    /// The log instantiation identifier
    /// (`"<registry_did>/log/<instance>"`, §6). One live instantiation
    /// per registry; a new `log_id` is an explicit history reset (§7.4).
    log_id: String,
    /// Leaves in append (acceptance) order — never reordered or
    /// deleted (§5.3).
    leaves: Vec<LogLeaf>,
    /// §5.1 leaf hashes, index-aligned with `leaves`.
    leaf_hashes: Vec<[u8; 32]>,
    /// Exactly one leaf per ctx_id (§4) — bodies are immutable, so a
    /// publish event happens once.
    ctx_ids: HashSet<String>,
}

impl MerkleLog {
    /// Create an empty log for `log_id`
    /// (`"<registry_did>/log/<instance>"`, validated per RFC-ACDP-0012
    /// §6).
    pub fn new(log_id: impl Into<String>) -> Result<Self, AcdpError> {
        let log_id = log_id.into();
        parse_log_id(&log_id)?;
        Ok(Self {
            log_id,
            leaves: Vec::new(),
            leaf_hashes: Vec::new(),
            ctx_ids: HashSet::new(),
        })
    }

    /// The log instantiation identifier.
    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    /// The current tree size (number of leaves).
    pub fn tree_size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// The leaf at `leaf_index`, if present.
    pub fn leaf(&self, leaf_index: u64) -> Option<&LogLeaf> {
        usize::try_from(leaf_index)
            .ok()
            .and_then(|i| self.leaves.get(i))
    }

    /// The §5.1 leaf hash at `leaf_index`, wire form
    /// (`"sha256:<hex>"`) — what `GET /log/entries` serves for every
    /// entry regardless of visibility (§8.3).
    pub fn leaf_hash_hex(&self, leaf_index: u64) -> Option<String> {
        usize::try_from(leaf_index)
            .ok()
            .and_then(|i| self.leaf_hashes.get(i))
            .map(encode_sha256_hex)
    }

    /// Append a leaf, returning its assigned `leaf_index`
    /// (consecutive from 0 in acceptance order, §5.3 / §7.1 rule 2).
    ///
    /// Enforces the §4 leaf invariants at the door: exact
    /// `leaf_version` (via the closed reparse), one leaf per `ctx_id`,
    /// and `origin_registry` equal to both the `ctx_id` authority and
    /// the log's registry DID authority. Rejected publishes MUST NOT be
    /// logged — append only what has a receipt (§4).
    pub fn append(&mut self, leaf: LogLeaf) -> Result<u64, AcdpError> {
        // Closed-schema + version + timestamp-form invariants (§4).
        let leaf = LogLeaf::from_value(&serde_json::to_value(&leaf)?)?;
        if self.ctx_ids.contains(leaf.ctx_id.as_str()) {
            return Err(AcdpError::SchemaViolation(format!(
                "transparency log already holds a leaf for ctx_id '{}' — exactly one leaf \
                 per publish event (RFC-ACDP-0012 §4)",
                leaf.ctx_id
            )));
        }
        if leaf.ctx_id.authority() != leaf.origin_registry {
            return Err(AcdpError::SchemaViolation(format!(
                "leaf origin_registry '{}' ≠ ctx_id authority '{}' (RFC-ACDP-0012 §4)",
                leaf.origin_registry,
                leaf.ctx_id.authority()
            )));
        }
        let (registry_did, _) = parse_log_id(&self.log_id)?;
        let leaf_did = acdp_did::web::authority_to_did_web(&leaf.origin_registry);
        if leaf_did != registry_did {
            return Err(AcdpError::SchemaViolation(format!(
                "leaf origin_registry '{}' is not this log's registry ('{registry_did}') \
                 (RFC-ACDP-0012 §4)",
                leaf.origin_registry
            )));
        }
        let hash = leaf.leaf_hash()?;
        let index = self.leaves.len() as u64;
        self.ctx_ids.insert(leaf.ctx_id.as_str().to_string());
        self.leaves.push(leaf);
        self.leaf_hashes.push(hash);
        Ok(index)
    }

    /// `MTH(D[tree_size])` — the current root, raw digest (§5.2). The
    /// empty tree's root is SHA-256 of the empty string.
    pub fn root(&self) -> [u8; 32] {
        acdp_crypto::merkle::merkle_tree_hash(&self.leaf_hashes)
    }

    /// The current root in wire form: `"sha256:" + lowercase_hex(MTH)`.
    pub fn root_hash(&self) -> String {
        encode_sha256_hex(&self.root())
    }

    /// The root at a historical `tree_size` (`MTH(D[0:tree_size])`) —
    /// every prefix root remains committed by consistency (§8.2).
    pub fn root_at(&self, tree_size: u64) -> Result<[u8; 32], AcdpError> {
        let n = self.checked_size(tree_size)?;
        Ok(acdp_crypto::merkle::merkle_tree_hash(
            &self.leaf_hashes[..n],
        ))
    }

    /// Sign a checkpoint over the **current** tree (§6): the §7.2
    /// serve-on-demand head. `timestamp` is the registry-clock
    /// evaluation time (truncated to milliseconds by the minter).
    ///
    /// The signer is the RFC-ACDP-0010 **receipt** signer — the log
    /// introduces no new key role — and its `registry_did` MUST match
    /// the DID embedded in this log's `log_id`.
    pub fn checkpoint(
        &self,
        signer: &ReceiptSigner,
        timestamp: DateTime<Utc>,
    ) -> Result<LogCheckpoint, AcdpError> {
        self.checkpoint_at(signer, self.tree_size(), timestamp)
    }

    /// Sign a checkpoint at a historical `tree_size` (§8.2: "for a
    /// historical tree_size the registry serves a checkpoint it signed
    /// at that size, or signs one on demand — both roots are equally
    /// committed by consistency").
    pub fn checkpoint_at(
        &self,
        signer: &ReceiptSigner,
        tree_size: u64,
        timestamp: DateTime<Utc>,
    ) -> Result<LogCheckpoint, AcdpError> {
        let root = self.root_at(tree_size)?;
        signer.mint_log_checkpoint(
            &self.log_id,
            tree_size,
            &encode_sha256_hex(&root),
            timestamp,
        )
    }

    /// Build the §8.2 inclusion-mode proof object for `leaf_index`
    /// against `checkpoint` (which MUST be a checkpoint of this log at
    /// `leaf_index < tree_size ≤` current size — pass a
    /// [`Self::checkpoint`]/[`Self::checkpoint_at`] product).
    ///
    /// The `leaf` echo is left absent; per §8.2 it is echoed only to
    /// requesters authorized to retrieve the context, which is the
    /// caller's visibility decision — use [`Self::leaf`] and
    /// `LogInclusion::leaf` to attach it.
    pub fn inclusion_proof(
        &self,
        leaf_index: u64,
        checkpoint: &LogCheckpoint,
    ) -> Result<LogInclusion, AcdpError> {
        if checkpoint.log_id != self.log_id {
            return Err(AcdpError::SchemaViolation(format!(
                "checkpoint log_id '{}' is not this log ('{}')",
                checkpoint.log_id, self.log_id
            )));
        }
        let n = self.checked_size(checkpoint.tree_size)?;
        let m = usize::try_from(leaf_index)
            .ok()
            .filter(|m| *m < n)
            .ok_or_else(|| {
                AcdpError::SchemaViolation(format!(
                    "leaf_index {leaf_index} is not < tree_size {} (RFC-ACDP-0012 §8.2)",
                    checkpoint.tree_size
                ))
            })?;
        let path = acdp_crypto::merkle::inclusion_path(m, &self.leaf_hashes[..n])
            .expect("bounds checked above");
        Ok(LogInclusion {
            log_id: self.log_id.clone(),
            leaf_index,
            tree_size: checkpoint.tree_size,
            inclusion_path: path.iter().map(encode_sha256_hex).collect(),
            log_checkpoint: checkpoint.clone(),
            leaf: None,
        })
    }

    /// The RFC 6962 §2.1.2 consistency path `PROOF(first, D[second])`
    /// between two tree sizes of this log, wire form (§8.2 consistency
    /// mode; `0 < first ≤ second ≤` current size; empty when
    /// `first == second`).
    pub fn consistency_proof(&self, first: u64, second: u64) -> Result<Vec<String>, AcdpError> {
        let n = self.checked_size(second)?;
        if first == 0 || first > second {
            return Err(AcdpError::SchemaViolation(format!(
                "consistency proof requires 0 < first ({first}) ≤ second ({second}) \
                 (RFC-ACDP-0012 §8.2)"
            )));
        }
        let m = usize::try_from(first).expect("first ≤ second ≤ len");
        let path = acdp_crypto::merkle::consistency_proof(m, &self.leaf_hashes[..n])
            .expect("bounds checked above");
        Ok(path.iter().map(encode_sha256_hex).collect())
    }

    /// Build the full §8.2 consistency-mode response object:
    /// `PROOF(first, D[checkpoint.tree_size])` packaged with the
    /// checkpoint at the second size.
    pub fn consistency_proof_response(
        &self,
        first: u64,
        checkpoint: &LogCheckpoint,
    ) -> Result<LogConsistencyProof, AcdpError> {
        if checkpoint.log_id != self.log_id {
            return Err(AcdpError::SchemaViolation(format!(
                "checkpoint log_id '{}' is not this log ('{}')",
                checkpoint.log_id, self.log_id
            )));
        }
        Ok(LogConsistencyProof {
            log_id: self.log_id.clone(),
            first_tree_size: first,
            second_tree_size: checkpoint.tree_size,
            consistency_path: self.consistency_proof(first, checkpoint.tree_size)?,
            log_checkpoint: checkpoint.clone(),
        })
    }

    /// Validate `tree_size ≤ current size` and convert to a slice bound.
    fn checked_size(&self, tree_size: u64) -> Result<usize, AcdpError> {
        usize::try_from(tree_size)
            .ok()
            .filter(|n| *n <= self.leaves.len())
            .ok_or_else(|| {
                AcdpError::SchemaViolation(format!(
                    "tree_size {tree_size} exceeds the current log size {} (RFC-ACDP-0012 §8.2)",
                    self.leaves.len()
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_crypto::SigningKey;
    use acdp_types::log::{decode_sha256_hex, LOG_LEAF_VERSION};
    use acdp_types::primitives::{ContentHash, CtxId};

    const REGISTRY_DID: &str = "did:web:registry.example.com";
    const LOG_ID: &str = "did:web:registry.example.com/log/1";

    fn signer() -> ReceiptSigner {
        ReceiptSigner::new(
            SigningKey::from_bytes(&[0x11u8; 32]),
            REGISTRY_DID,
            format!("{REGISTRY_DID}#receipt-key-1"),
        )
        .unwrap()
    }

    fn registry_pub() -> [u8; 32] {
        SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes()
    }

    fn leaf(i: u8) -> LogLeaf {
        let ctx_id =
            format!("acdp://registry.example.com/00000000-0000-4000-8000-0000000000{i:02}");
        LogLeaf {
            leaf_version: LOG_LEAF_VERSION.into(),
            lineage_id: acdp_crypto::derive_lineage_id(&CtxId(ctx_id.clone())),
            ctx_id: CtxId(ctx_id),
            origin_registry: "registry.example.com".into(),
            created_at: chrono::DateTime::parse_from_rfc3339("2026-07-01T01:00:00.123Z")
                .unwrap()
                .with_timezone(&Utc),
            content_hash: ContentHash(format!("sha256:{}", "b".repeat(64))),
            key_fingerprint: format!("sha256:{}", "c".repeat(64)),
            receipt_hash: format!("sha256:{}", "d".repeat(64)),
        }
    }

    /// Round trip: append N, checkpoint, prove each leaf, verify every
    /// proof against the signed checkpoint; consistency between all
    /// size pairs.
    #[test]
    fn append_prove_verify_round_trip() {
        for n in 1..=8u8 {
            let mut log = MerkleLog::new(LOG_ID).unwrap();
            let mut roots = vec![log.root()]; // size 0
            for i in 0..n {
                let idx = log.append(leaf(i)).unwrap();
                assert_eq!(idx, u64::from(i), "acceptance-order indexing (§5.3)");
                roots.push(log.root());
            }
            assert_eq!(log.tree_size(), u64::from(n));

            let cp = log.checkpoint(&signer(), Utc::now()).unwrap();
            assert_eq!(cp.tree_size, u64::from(n));
            assert_eq!(cp.root_hash, log.root_hash());
            cp.verify_signature_with_key(Some(&registry_pub()), None)
                .expect("checkpoint signature");
            cp.cross_check_registry_binding("registry.example.com", REGISTRY_DID)
                .unwrap();

            for i in 0..u64::from(n) {
                let proof = log.inclusion_proof(i, &cp).unwrap();
                // §9.1 step 1: reconstruct the leaf independently — here
                // from the log's own copy, hashed fresh.
                proof
                    .verify_reconstructed_leaf(log.leaf(i).unwrap())
                    .expect("inclusion proof verifies");
            }

            // Consistency between every historical pair (m ≤ k ≤ n).
            for m in 1..=u64::from(n) {
                for k in m..=u64::from(n) {
                    let cp_k = log.checkpoint_at(&signer(), k, Utc::now()).unwrap();
                    cp_k.verify_signature_with_key(Some(&registry_pub()), None)
                        .unwrap();
                    let resp = log.consistency_proof_response(m, &cp_k).unwrap();
                    resp.verify_against_first_root(&encode_sha256_hex(
                        &roots[usize::try_from(m).unwrap()],
                    ))
                    .expect("consistency proof verifies");
                }
            }
        }
    }

    /// Append-only invariants: duplicate ctx_id, foreign authority, and
    /// out-of-range proof requests are refused; the empty log roots to
    /// SHA-256("").
    #[test]
    fn append_invariants_and_bounds() {
        let mut log = MerkleLog::new(LOG_ID).unwrap();
        assert_eq!(
            log.root_hash(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "empty tree root (RFC-ACDP-0012 §5.2)"
        );
        // An empty checkpoint (tree_size 0) is valid and signable.
        let cp0 = log.checkpoint(&signer(), Utc::now()).unwrap();
        assert_eq!(cp0.tree_size, 0);
        cp0.verify_signature_with_key(Some(&registry_pub()), None)
            .unwrap();

        log.append(leaf(0)).unwrap();
        let err = log.append(leaf(0)).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");

        // Foreign origin_registry refused.
        let mut foreign = leaf(1);
        foreign.origin_registry = "evil.example.com".into();
        assert!(log.append(foreign).is_err());
        // origin_registry ≠ ctx_id authority refused.
        let mut mismatched = leaf(2);
        mismatched.ctx_id =
            CtxId("acdp://other.example.com/00000000-0000-4000-8000-000000000002".into());
        assert!(log.append(mismatched).is_err());

        // Bounds.
        let cp = log.checkpoint(&signer(), Utc::now()).unwrap();
        assert!(log.inclusion_proof(1, &cp).is_err());
        assert!(log.checkpoint_at(&signer(), 2, Utc::now()).is_err());
        assert!(log.consistency_proof(0, 1).is_err());
        assert!(log.consistency_proof(1, 2).is_err());
        assert!(log.consistency_proof(1, 1).unwrap().is_empty());

        // A checkpoint from another instantiation is refused.
        let other = MerkleLog::new("did:web:registry.example.com/log/2").unwrap();
        let cp_other = other.checkpoint(&signer(), Utc::now()).unwrap();
        assert!(log.inclusion_proof(0, &cp_other).is_err());
        assert!(log.consistency_proof_response(1, &cp_other).is_err());

        // Malformed log_id refused at construction.
        assert!(MerkleLog::new("did:web:registry.example.com").is_err());
        assert!(MerkleLog::new("did:web:registry.example.com/log/UPPER").is_err());

        // Wire-form leaf hash accessor matches the leaf's own.
        assert_eq!(
            decode_sha256_hex(&log.leaf_hash_hex(0).unwrap()).unwrap(),
            log.leaf(0).unwrap().leaf_hash().unwrap()
        );
        assert!(log.leaf_hash_hex(1).is_none());
    }
}
