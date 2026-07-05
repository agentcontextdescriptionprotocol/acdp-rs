//! # acdp-crypto — cryptographic primitives for the Agent Context Distribution Protocol
//!
//! Content-hashing ([`hash`]), signing ([`sign`]), byte-level signature
//! verification ([`verify`]), key fingerprinting ([`fingerprint`]), and
//! the transparency-log Merkle machinery ([`merkle`]) per
//! RFC-ACDP-0001/0003/0008/0012. JCS canonicalization is re-exported
//! from [`acdp-jcs`](https://docs.rs/acdp-jcs) as [`jcs`].
//!
//! The high-level, resolver-backed verification pipeline (`Verifier`,
//! `verify_body`, …) lives in the separate `acdp-verify` crate — it
//! depends on structural validation, which sits above this layer.

pub mod fingerprint;
pub mod hash;
pub mod merkle;
pub mod sign;
pub mod verify;

// JCS canonicalization lives in its own crate; re-export under the
// historical `crypto::jcs` path.
pub use acdp_jcs as jcs;

pub use fingerprint::{
    fingerprint_did_key_material, fingerprint_ed25519, fingerprint_p256_sec1,
    fingerprint_verification_method,
};
pub use hash::{
    canonical_preimage, compute_content_hash, derive_lineage_id, explain_hash_mismatch,
    verify_content_hash,
};
pub use jcs::{canonicalize, canonicalize_value, try_canonicalize_value};
pub use merkle::{
    consistency_proof, inclusion_path, leaf_hash, merkle_tree_hash, node_hash, verify_consistency,
    verify_inclusion,
};
pub use sign::{AcdpSigningKey, P256SigningKey, SigningKey};
pub use verify::{verify_ecdsa_p256, verify_ed25519};
