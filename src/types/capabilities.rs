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
}

/// Resource limits declared by the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum total publish request size in bytes.
    pub max_payload_bytes: u64,

    /// Maximum size of any single embedded data reference in bytes (≤ 65536).
    pub max_embedded_bytes: u64,

    /// How long idempotency-key mappings are retained, in seconds.
    /// MUST be present when `supports_idempotency_key` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key_ttl_seconds: Option<u32>,
}
