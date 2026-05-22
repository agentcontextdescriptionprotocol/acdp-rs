use serde::{Deserialize, Serialize};

/// Registry capabilities document served at `GET /.well-known/acdp.json`.
///
/// `additionalProperties` is `true` in the schema so future versions can add
/// capability flags without a schema bump. Unknown fields are preserved in
/// [`Self::extensions`] for forward-compatible inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesDocument {
    /// Protocol version this registry implements.
    pub acdp_version: String,

    /// Registry's Decentralized Identifier (`did:web:…`).
    pub registry_did: String,

    /// Signature algorithms accepted on publish.  MUST contain `"ed25519"`.
    pub supported_signature_algorithms: Vec<String>,

    /// DID methods the registry can resolve.  MUST contain `"did:web"`.
    pub supported_did_methods: Vec<String>,

    /// Profile(s) this registry claims.  MUST contain `"acdp-registry-core"`.
    pub profiles: Vec<String>,

    /// Resource limits.
    pub limits: Limits,

    /// Read-authentication methods supported for non-public contexts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_authentication_methods: Vec<String>,

    /// Whether anonymous reads of public contexts are permitted.
    #[serde(default)]
    pub anonymous_public_reads: bool,

    /// Whether `Idempotency-Key` is honoured on `POST /contexts`.
    #[serde(default)]
    pub supports_idempotency_key: bool,

    /// Forward-compatible extensions: any unknown top-level field appears
    /// here verbatim.
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

impl CapabilitiesDocument {
    /// Returns `true` if this registry supports keyword search.
    pub fn supports_discovery(&self) -> bool {
        self.profiles.iter().any(|p| p == "acdp-registry-discovery")
    }

    /// Returns `true` if this registry supports cross-registry resolution.
    pub fn supports_federation(&self) -> bool {
        self.profiles.iter().any(|p| p == "acdp-registry-federated")
    }

    /// Returns `true` if this registry advertises support for the given
    /// signature algorithm (case-sensitive match against
    /// `supported_signature_algorithms`).
    pub fn supports_algorithm(&self, algorithm: &str) -> bool {
        self.supported_signature_algorithms
            .iter()
            .any(|a| a == algorithm)
    }

    /// Returns `true` if this registry can resolve the given DID method
    /// (e.g. `"did:web"`).
    pub fn supports_did_method(&self, method: &str) -> bool {
        self.supported_did_methods.iter().any(|m| m == method)
    }

    /// Idempotency-key TTL as a [`std::time::Duration`], if the registry
    /// advertises one. Returns `None` when `supports_idempotency_key` is
    /// `false` or the TTL field is absent.
    pub fn idempotency_ttl(&self) -> Option<std::time::Duration> {
        self.limits
            .idempotency_key_ttl_seconds
            .map(|s| std::time::Duration::from_secs(u64::from(s)))
    }

    /// Returns `true` when the registry requires authenticated requests
    /// even for `visibility: public` reads (i.e. `anonymous_public_reads`
    /// is `false`).
    pub fn requires_anonymous_auth(&self) -> bool {
        !self.anonymous_public_reads
    }
}

/// Resource limits declared by the registry.
///
/// The capabilities document is OPEN at the top level, but `limits` is a
/// CLOSED sub-object (`additionalProperties: false`): new limit keys are
/// added by a spec version bump, not by registries inventing fields, so
/// `deny_unknown_fields` rejects an unknown key (RFC-ACDP-0007 §3.3.1,
/// conformance fixture schema-010).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Maximum total publish request size in bytes.
    pub max_payload_bytes: u64,

    /// Maximum size of any single embedded data reference in bytes (≤ 65536).
    pub max_embedded_bytes: u64,

    /// How long idempotency-key mappings are retained, in seconds.
    /// MUST be present when `supports_idempotency_key` is true.
    ///
    /// Optional and absent-or-integer in the schema — not nullable.
    /// `de_present` rejects an explicit `"idempotency_key_ttl_seconds": null`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::types::serde_helpers::de_present"
    )]
    pub idempotency_key_ttl_seconds: Option<u32>,
}
