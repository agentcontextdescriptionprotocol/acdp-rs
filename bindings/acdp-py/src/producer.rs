//! `AcdpProducer` — Ed25519 identity + PublishRequest builder.
//!
//! Stores a 32-byte Ed25519 seed and reconstructs `acdp::crypto::SigningKey`
//! on each call (`SigningKey` is `ZeroizeOnDrop` and not `Clone`).
//! Returns wire-ready PublishRequest JSON the caller sends via its own
//! HTTP client — this class never opens a socket.

// `build_publish_request` and `build_supersede_request` deliberately
// take one kwarg per optional Body field — that's the whole point of a
// Python-idiomatic surface. Refactoring through a Rust struct would
// just move the same field count behind another layer, and the PyO3
// `signature` attribute on the methods is what makes the kwargs visible
// on the Python side.
#![allow(clippy::too_many_arguments)]

use acdp::crypto::SigningKey;
use acdp::producer::Producer;
use acdp::types::{AgentDid, Body, CtxId};
use base64::{engine::general_purpose::STANDARD, Engine};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use zeroize::Zeroizing;

use crate::helpers::{parse_context_type, parse_visibility};

/// An ACDP producer: an Ed25519 signing key and its did:web identity.
///
/// All methods return wire-ready JSON strings the caller sends via its
/// own HTTP client (httpx, requests, etc.). No HTTP calls are made
/// inside this class.
#[pyclass(name = "AcdpProducer")]
pub struct PyAcdpProducer {
    /// Raw 32-byte Ed25519 seed. Reconstructs `SigningKey` on demand —
    /// `SigningKey` is `ZeroizeOnDrop` and not `Clone`, so the binding
    /// cannot hold a long-lived signing-key handle and replay it across
    /// pyclass methods.
    ///
    /// Wrapped in `Zeroizing` so the seed bytes are wiped when the
    /// pyclass is dropped. Without this, the binding would strip the
    /// zero-on-drop protection the Rust `SigningKey` provides.
    seed: Zeroizing<[u8; 32]>,
    agent_did: String,
    key_id: String,
}

#[pymethods]
impl PyAcdpProducer {
    /// Generate a producer with a fresh random Ed25519 key (OsRng).
    ///
    /// * `agent_did` — the full did:web DID
    ///   (e.g. `"did:web:registry.example.com:agents:my-agent"`).
    /// * `key_id` — the DID URL for the signing key
    ///   (e.g. `"did:web:registry.example.com:agents:my-agent#key-1"`).
    #[staticmethod]
    fn generate(agent_did: &str, key_id: &str) -> Self {
        let key = SigningKey::generate();
        Self {
            seed: Zeroizing::new(key.seed_bytes()),
            agent_did: agent_did.to_string(),
            key_id: key_id.to_string(),
        }
    }

    /// Construct from a 32-byte Ed25519 seed.
    ///
    /// Deterministic — useful for tests and for loading material from a
    /// secret store. The seed is the private key — protect it as such.
    #[staticmethod]
    fn from_seed(seed: &[u8], agent_did: &str, key_id: &str) -> PyResult<Self> {
        let arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| PyValueError::new_err("seed must be exactly 32 bytes"))?;
        Ok(Self {
            seed: Zeroizing::new(arr),
            agent_did: agent_did.to_string(),
            key_id: key_id.to_string(),
        })
    }

    /// The producer's DID (`did:web:…`).
    #[getter]
    fn agent_did(&self) -> &str {
        &self.agent_did
    }

    /// The producer's signing-key DID URL (`did:web:…#key-1`).
    #[getter]
    fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Raw Ed25519 public key as standard base64 (44 chars with padding).
    ///
    /// Use this to populate a did:web verification method
    /// (`Ed25519VerificationKey2020`) when standing up the producer's
    /// DID document.
    #[getter]
    fn public_key_b64(&self) -> String {
        let key = SigningKey::from_bytes(&self.seed);
        STANDARD.encode(key.verifying_key_bytes())
    }

    /// The raw 32-byte seed, for storage in a key vault.
    ///
    /// Returns a fresh `bytes` copy each call — Python owns the buffer.
    fn seed_bytes(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    /// Build and sign a first-version PublishRequest. Returns the
    /// wire JSON string.
    ///
    /// Only `title` and `context_type` are required; everything else
    /// is optional and follows the kwargs convention.
    /// `metadata` MUST be a JSON-encoded object string (it's re-parsed
    /// into `serde_json::Value` so it lands in the request as a JSON
    /// object, not a quoted string).
    #[pyo3(signature = (
        title, context_type,
        visibility=None, description=None, summary=None,
        tags=None, domain=None, metadata=None,
        derived_from=None, audience=None, schema_uri=None,
        contributors=None
    ))]
    fn build_publish_request(
        &self,
        title: String,
        context_type: String,
        visibility: Option<String>,
        description: Option<String>,
        summary: Option<String>,
        tags: Option<Vec<String>>,
        domain: Option<String>,
        metadata: Option<String>,
        derived_from: Option<Vec<String>>,
        audience: Option<Vec<String>>,
        schema_uri: Option<String>,
        contributors: Option<Vec<String>>,
    ) -> PyResult<String> {
        let key = SigningKey::from_bytes(&self.seed);
        let did = AgentDid::new(&self.agent_did);
        let producer = Producer::new(key, did, &self.key_id);
        let ctx_type = parse_context_type(&context_type)?;
        let vis = parse_visibility(visibility.as_deref().unwrap_or("public"))?;

        let mut b = producer
            .publish_request()
            .title(title)
            .context_type(ctx_type)
            .visibility(vis);

        if let Some(d) = description {
            b = b.description(d);
        }
        if let Some(s) = summary {
            b = b.summary(s);
        }
        if let Some(t) = tags {
            b = b.tags(t);
        }
        if let Some(d) = domain {
            b = b.domain(d);
        }
        if let Some(u) = schema_uri {
            b = b.schema_uri(u);
        }
        if let Some(m) = metadata {
            let v: serde_json::Value = serde_json::from_str(&m)
                .map_err(|e| PyValueError::new_err(format!("invalid metadata JSON: {e}")))?;
            b = b.metadata(v);
        }
        if let Some(df) = derived_from {
            b = b.derived_from(df.into_iter().map(CtxId).collect());
        }
        if let Some(aud) = audience {
            b = b.audience(aud.into_iter().map(|d| AgentDid::new(&d)).collect());
        }
        if let Some(c) = contributors {
            b = b.contributors(c.into_iter().map(|d| AgentDid::new(&d)).collect());
        }

        let req = b
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        serde_json::to_string(&req).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Build and sign a supersession PublishRequest from a previous
    /// version's `Body` JSON.
    ///
    /// `previous_body_json` is the `FullContext.body` JSON returned by
    /// a retrieve call. The version is propagated automatically
    /// (`previous.version + 1`) and `lineage_id` is carried forward.
    /// Any kwargs override the corresponding field from the previous
    /// body; omitted fields are retained (mirrors `new_version_from`).
    #[pyo3(signature = (
        previous_body_json,
        title=None, summary=None, description=None,
        tags=None, domain=None, metadata=None
    ))]
    fn build_supersede_request(
        &self,
        previous_body_json: &str,
        title: Option<String>,
        summary: Option<String>,
        description: Option<String>,
        tags: Option<Vec<String>>,
        domain: Option<String>,
        metadata: Option<String>,
    ) -> PyResult<String> {
        let key = SigningKey::from_bytes(&self.seed);
        let did = AgentDid::new(&self.agent_did);
        let producer = Producer::new(key, did, &self.key_id);

        let previous: Body = serde_json::from_str(previous_body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;

        let mut b = producer.new_version_from(&previous);
        if let Some(t) = title {
            b = b.title(t);
        }
        if let Some(s) = summary {
            b = b.summary(s);
        }
        if let Some(d) = description {
            b = b.description(d);
        }
        if let Some(t) = tags {
            b = b.tags(t);
        }
        if let Some(d) = domain {
            b = b.domain(d);
        }
        if let Some(m) = metadata {
            let v: serde_json::Value = serde_json::from_str(&m)
                .map_err(|e| PyValueError::new_err(format!("invalid metadata JSON: {e}")))?;
            b = b.metadata(v);
        }

        let req = b
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        serde_json::to_string(&req).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Sign a registry auth-challenge `signing_input` string.
    ///
    /// The ACDP registry's challenge response carries a `signing_input`
    /// field of the form
    ///   `"acdp-registry-auth:v1:{nonce}:{agent_id}:{authority}:{expires_at}"`.
    /// Pass that exact string here; include the returned base64 signature
    /// in the `POST /auth/token` request body as `signature`. The
    /// registry verifies it with `verify_ed25519` against the public key
    /// at `key_id`.
    fn sign_challenge(&self, signing_input: &str) -> String {
        let key = SigningKey::from_bytes(&self.seed);
        key.sign_string(signing_input)
    }
}
