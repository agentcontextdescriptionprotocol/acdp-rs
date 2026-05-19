//! ACDP conformance profiles (RFC-ACDP-0001 §9.1).
//!
//! Implementations declare their profile(s) in the capabilities document
//! `profiles` field. Each profile is a strict superset of its prerequisite.
//!
//! This crate's *consumer-side* claim is [`Profile::Consumer`]: it
//! verifies producer signatures end-to-end, resolves cross-registry
//! references, applies visibility rules client-side, and tolerates
//! unknown fields. The validation and SSRF building blocks
//! ([`crate::registry::PublishValidator`], [`crate::safe_http::SsrfPolicy`])
//! are designed for consumption by `acdp-registry-core` /
//! `acdp-registry-federated` registry implementations built on top.

use crate::types::capabilities::CapabilitiesDocument;

/// One of the four conformance profiles defined by RFC-ACDP-0001 §9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// `acdp-registry-core` — minimum profile for any registry.
    RegistryCore,
    /// `acdp-registry-discovery` — adds keyword search.
    RegistryDiscovery,
    /// `acdp-registry-federated` — adds cross-registry resolution.
    RegistryFederated,
    /// `acdp-consumer` — a consumer of contexts (not a registry).
    Consumer,
}

impl Profile {
    /// Wire-form identifier as it appears in
    /// `capabilities.profiles` and prose references.
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::RegistryCore => "acdp-registry-core",
            Profile::RegistryDiscovery => "acdp-registry-discovery",
            Profile::RegistryFederated => "acdp-registry-federated",
            Profile::Consumer => "acdp-consumer",
        }
    }
}

/// Profiles that this `acdp` crate is designed to satisfy on the
/// consumer side. A registry implementer building on top of the
/// crate's primitives (`PublishValidator`, `SsrfPolicy`,
/// `CrossRegistryResolver`) MAY claim additional profiles in their
/// own capabilities document.
pub const CLAIMED: &[Profile] = &[Profile::Consumer];

impl CapabilitiesDocument {
    /// Returns `true` if the registry advertises the given profile.
    pub fn claims_profile(&self, profile: Profile) -> bool {
        self.profiles.iter().any(|p| p == profile.as_str())
    }

    /// Returns `Ok(())` if the registry advertises every profile in
    /// `required`. Returns the first missing profile in
    /// [`crate::error::AcdpError::SchemaViolation`] otherwise.
    pub fn supports_required(&self, required: &[Profile]) -> Result<(), crate::error::AcdpError> {
        for p in required {
            if !self.claims_profile(*p) {
                return Err(crate::error::AcdpError::SchemaViolation(format!(
                    "registry does not advertise required profile '{}'",
                    p.as_str()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::capabilities::Limits;

    fn caps_with(profiles: Vec<&str>) -> CapabilitiesDocument {
        CapabilitiesDocument {
            acdp_version: "0.1.0".into(),
            registry_did: "did:web:r.example.com".into(),
            supported_signature_algorithms: vec!["ed25519".into()],
            supported_did_methods: vec!["did:web".into()],
            profiles: profiles.into_iter().map(String::from).collect(),
            limits: Limits {
                max_payload_bytes: 1_048_576,
                max_embedded_bytes: 65_536,
                idempotency_key_ttl_seconds: None,
            },
            read_authentication_methods: vec![],
            anonymous_public_reads: true,
            supports_idempotency_key: false,
            extensions: Default::default(),
        }
    }

    #[test]
    fn claimed_profile_matches() {
        let caps = caps_with(vec!["acdp-registry-core", "acdp-registry-discovery"]);
        assert!(caps.claims_profile(Profile::RegistryCore));
        assert!(caps.claims_profile(Profile::RegistryDiscovery));
        assert!(!caps.claims_profile(Profile::RegistryFederated));
    }

    #[test]
    fn supports_required_returns_first_missing() {
        let caps = caps_with(vec!["acdp-registry-core"]);
        caps.supports_required(&[Profile::RegistryCore]).unwrap();
        let err = caps
            .supports_required(&[Profile::RegistryCore, Profile::RegistryFederated])
            .unwrap_err();
        match err {
            crate::error::AcdpError::SchemaViolation(msg) => {
                assert!(msg.contains("acdp-registry-federated"));
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn claimed_includes_consumer() {
        assert!(CLAIMED.contains(&Profile::Consumer));
    }
}
