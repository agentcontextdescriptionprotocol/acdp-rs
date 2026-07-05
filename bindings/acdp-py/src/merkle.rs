//! `AcdpMerkle` — RFC-ACDP-0012 §5 transparency-log tree arithmetic.
//!
//! Deliberately its OWN class rather than more methods on
//! `AcdpCanonicalizer`: the canonicalizer is the RFC 8785 / §5.7
//! producer-hashing surface, while these are the RFC 6962-style log
//! primitives (0x00/0x01 domain-separated SHA-256) — mirroring the
//! Rust core's `crypto::jcs` vs `crypto::merkle` module split. Pure
//! and synchronous; hosts use them for independent tree math when the
//! packaged `verify_log_inclusion` / `verify_log_consistency` verdicts
//! are not enough (e.g. auditors recomputing roots over full leaf
//! sets).
//!
//! Malformed inputs raise the typed [`InvalidLogProof`] exception
//! (`crate::errors`).

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::errors::map_acdp_error;
use crate::v030;

/// RFC-ACDP-0012 §5 Merkle helpers. All methods are static.
#[pyclass(name = "AcdpMerkle")]
pub struct PyAcdpMerkle;

#[pymethods]
impl PyAcdpMerkle {
    /// The §5.1 leaf hash of a transparency-log leaf:
    /// `SHA-256(0x00 ‖ JCS(leaf))`, returned in the wire form
    /// `"sha256:<64-hex>"`.
    ///
    /// * `leaf_json` — the closed leaf object (e.g. the output of
    ///   `AcdpVerifier.build_log_leaf`). Shape-validated first; a
    ///   malformed leaf raises `InvalidLogProof` rather than hashing
    ///   bytes no conformant log ever committed.
    #[staticmethod]
    fn leaf_hash(leaf_json: &str) -> PyResult<String> {
        let value: serde_json::Value = serde_json::from_str(leaf_json)
            .map_err(|e| PyValueError::new_err(format!("invalid leaf JSON: {e}")))?;
        v030::merkle_leaf_hash(&value).map_err(map_acdp_error)
    }

    /// The §5.1 interior-node hash `SHA-256(0x01 ‖ left ‖ right)` over
    /// the raw digests the two wire-form (`"sha256:<hex>"`) arguments
    /// encode. The 0x00/0x01 domain-separation prefixes are what stop
    /// leaf/node second-preimage forgeries — never hash without them.
    #[staticmethod]
    fn node_hash(left_hash: &str, right_hash: &str) -> PyResult<String> {
        v030::merkle_node_hash(left_hash, right_hash).map_err(map_acdp_error)
    }

    /// The §5.2 RFC 6962 Merkle tree hash `MTH(D[n])` over an ordered
    /// JSON array of wire-form leaf hashes (`'["sha256:...", ...]'`).
    /// An empty array yields the empty-tree root, `SHA-256("")`.
    #[staticmethod]
    fn root_hash(leaf_hashes_json: &str) -> PyResult<String> {
        let hashes: Vec<String> = serde_json::from_str(leaf_hashes_json).map_err(|e| {
            PyValueError::new_err(format!("invalid leaf_hashes JSON (array of strings): {e}"))
        })?;
        v030::merkle_root_hash(&hashes).map_err(map_acdp_error)
    }
}
