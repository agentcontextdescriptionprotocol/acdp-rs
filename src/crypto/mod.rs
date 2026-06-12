pub mod fingerprint;
pub mod hash;
pub mod jcs;
pub mod sign;
pub mod verify;

pub use fingerprint::{
    fingerprint_did_key_material, fingerprint_ed25519, fingerprint_p256_sec1,
    fingerprint_verification_method,
};
pub use hash::{
    canonical_preimage, compute_content_hash, derive_lineage_id, explain_hash_mismatch,
    verify_content_hash,
};
pub use jcs::{canonicalize, canonicalize_value, try_canonicalize_value};
pub use sign::{AcdpSigningKey, P256SigningKey, SigningKey};
pub use verify::{
    verify_body_offline, verify_did_key_envelope, verify_ecdsa_p256, verify_ed25519,
    verify_publish_request_signature_offline,
};

#[cfg(feature = "client")]
pub use verify::verify_publish_request_signature;
