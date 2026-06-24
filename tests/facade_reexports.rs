//! Facade surface lock-in.
//!
//! The `acdp` crate is now a thin facade that re-exports the workspace
//! crates (`acdp-primitives`, `acdp-types`, `acdp-crypto`, `acdp-did`,
//! `acdp-validation`, `acdp-verify`, `acdp-producer`, `acdp-client`,
//! `acdp-server`). These tests assert the historical public paths still
//! resolve, so a future change to the re-export plumbing can't silently
//! drop part of the API.

// Module paths preserved across the split.
#[allow(unused_imports)]
use acdp::{
    crypto, did, error, limits, producer, profile, safe_http, time, types, validation, verify,
};

#[test]
fn protocol_constants_are_reexported() {
    assert_eq!(acdp::ACDP_VERSION, "0.2.0");
    assert!(acdp::ACDP_SCHEMA_NAMESPACE.starts_with("https://"));
}

#[test]
fn crate_root_convenience_reexports_resolve() {
    // Types re-exported at the crate root.
    let _t = acdp::ContextType::DataSnapshot;
    let _v = acdp::Visibility::Public;
    let did = acdp::AgentDid::new("did:web:agents.example.com:test");
    assert_eq!(did.as_str(), "did:web:agents.example.com:test");
    // Error vocabulary at the crate root.
    let e = acdp::AcdpError::NotFound("x".into());
    assert!(!e.is_transient());
}

#[test]
fn crypto_module_exposes_low_and_high_level_paths() {
    // Low-level byte verification lives in acdp-crypto, re-exported under
    // crate::crypto and crate::crypto::verify.
    let _f: fn(&[u8; 32], &str, &str) -> Result<(), acdp::AcdpError> = acdp::crypto::verify_ed25519;
    let _g: fn(&[u8; 32], &str, &str) -> Result<(), acdp::AcdpError> =
        acdp::crypto::verify::verify_ed25519;
    // High-level offline verification lives in acdp-verify, re-exported under
    // both crate::verify and (for back-compat) crate::crypto.
    let _h: fn(&acdp::types::body::Body) -> Result<(), acdp::AcdpError> =
        acdp::verify::verify_body_offline;
    let _i: fn(&acdp::types::body::Body) -> Result<(), acdp::AcdpError> =
        acdp::crypto::verify_body_offline;
    // JCS canonicalization re-exported under crate::crypto::jcs.
    let _j: fn(&serde_json::Value) -> Vec<u8> = acdp::crypto::jcs::canonicalize_value;
}

#[test]
fn producer_round_trip_through_facade() {
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::types::{ContextType, Visibility};

    let key = SigningKey::from_bytes(&[7u8; 32]);
    let prod = Producer::new(
        key,
        acdp::AgentDid::new("did:web:agents.example.com:test"),
        "did:web:agents.example.com:test#key-1",
    );
    let req = prod
        .publish_request()
        .title("smoke")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("facade producer build");
    assert!(req.content_hash.as_str().starts_with("sha256:"));
}

#[cfg(feature = "client")]
#[test]
fn client_types_reexported() {
    // Compile-time path checks only.
    #[allow(unused_imports)]
    use acdp::client::{CrossRegistryResolver, RegistryClient, VerifiedContext};
    #[allow(unused_imports)]
    use acdp::did::WebResolver;
}

#[cfg(feature = "server")]
#[test]
fn server_types_reexported() {
    #[allow(unused_imports)]
    use acdp::pagination;
    #[allow(unused_imports)]
    use acdp::registry::{InMemoryStore, PublishValidator, RegistryServer};
}
