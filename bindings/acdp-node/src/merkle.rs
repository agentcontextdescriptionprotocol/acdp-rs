//! `AcdpMerkle` — RFC-ACDP-0012 §5 transparency-log tree arithmetic.
//!
//! Deliberately its OWN class rather than more methods on
//! `AcdpCanonicalizer`: the canonicalizer is the RFC 8785 / §5.7
//! producer-hashing surface, while these are the RFC 6962-style log
//! primitives (0x00/0x01 domain-separated SHA-256) — mirroring the
//! Rust core's `crypto::jcs` vs `crypto::merkle` module split. Pure
//! and synchronous; hosts use them for independent tree math when the
//! packaged `verifyLogInclusion` / `verifyLogConsistency` verdicts are
//! not enough (e.g. auditors recomputing roots over full leaf sets).
//!
//! Malformed inputs throw with `.code === "invalid_log_proof"` (the
//! same taxonomy the Python binding raises as typed exceptions).

use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::errors::{input_err, map_acdp_err};
use crate::v030;

/// RFC-ACDP-0012 §5 Merkle helpers. All methods are static.
#[napi]
pub struct AcdpMerkle;

#[napi]
impl AcdpMerkle {
    /// The §5.1 leaf hash of a transparency-log leaf:
    /// `SHA-256(0x00 ‖ JCS(leaf))`, returned in the wire form
    /// `"sha256:<64-hex>"`.
    ///
    /// * `leafJson` — the closed leaf object (e.g. the output of
    ///   `AcdpVerifier.buildLogLeaf`). Shape-validated first; a
    ///   malformed leaf throws (`.code === "invalid_log_proof"`)
    ///   rather than hashing bytes no conformant log ever committed.
    #[napi]
    pub fn leaf_hash(leaf_json: String) -> Result<String, String> {
        let value: serde_json::Value = serde_json::from_str(&leaf_json)
            .map_err(|e| input_err(format!("invalid leaf JSON: {e}")))?;
        v030::merkle_leaf_hash(&value).map_err(map_acdp_err)
    }

    /// The §5.1 interior-node hash `SHA-256(0x01 ‖ left ‖ right)` over
    /// the raw digests the two wire-form (`"sha256:<hex>"`) arguments
    /// encode. The 0x00/0x01 domain-separation prefixes are what stop
    /// leaf/node second-preimage forgeries — never hash without them.
    #[napi]
    pub fn node_hash(left_hash: String, right_hash: String) -> Result<String, String> {
        v030::merkle_node_hash(&left_hash, &right_hash).map_err(map_acdp_err)
    }

    /// The §5.2 RFC 6962 Merkle tree hash `MTH(D[n])` over an ordered
    /// JSON array of wire-form leaf hashes (`'["sha256:...", ...]'`).
    /// An empty array yields the empty-tree root, `SHA-256("")`.
    #[napi]
    pub fn root_hash(leaf_hashes_json: String) -> Result<String, String> {
        let hashes: Vec<String> = serde_json::from_str(&leaf_hashes_json)
            .map_err(|e| input_err(format!("invalid leafHashes JSON (array of strings): {e}")))?;
        v030::merkle_root_hash(&hashes).map_err(map_acdp_err)
    }
}
