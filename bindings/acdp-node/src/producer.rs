//! `AcdpProducer` — Ed25519 identity + PublishRequest builder.
//!
//! Stores a 32-byte Ed25519 seed and reconstructs `acdp::crypto::SigningKey`
//! on each call. Mirrors the surface exposed by the Python binding;
//! only naming and the `PublishOpts` / `SupersedeOpts` struct argument
//! shape are JS-idiomatic.

use acdp::crypto::SigningKey;
use acdp::producer::Producer;
use acdp::types::{AgentDid, Body, CtxId};
use base64::{engine::general_purpose::STANDARD, Engine};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use zeroize::Zeroizing;

use crate::helpers::{parse_context_type, parse_visibility};

/// Options for `buildPublishRequest`. Field names map directly to the
/// PublishRequest wire schema (camelCase on the JS side).
#[napi(object)]
pub struct PublishOpts {
    /// Human-readable title (1..=500 chars).
    pub title: String,
    /// Closed enum or namespaced custom (`^[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*$`).
    pub context_type: String,
    /// `public` | `restricted` | `private`. Defaults to `public`.
    pub visibility: Option<String>,
    /// Long human-readable description (≤ 5000 chars).
    pub description: Option<String>,
    /// Producer-supplied summary for search results (≤ 1000 chars).
    /// Part of ProducerContent — included in the content_hash preimage.
    pub summary: Option<String>,
    /// Free-form tags (each: `^[A-Za-z0-9][A-Za-z0-9_.-]*$`, ≤ 100 chars).
    pub tags: Option<Vec<String>>,
    /// Subject-domain identifier (≤ 200 chars).
    pub domain: Option<String>,
    /// Producer-specific structured metadata. MUST be a JSON-encoded
    /// object string (it is re-parsed so it lands as a JSON object,
    /// not a quoted string).
    pub metadata: Option<String>,
    /// Lineage of contexts this body was derived from (`acdp://…` ids,
    /// ≤ 1000 unique).
    pub derived_from: Option<Vec<String>>,
    /// Audience DIDs — required (≥ 1) when `visibility = "restricted"`.
    pub audience: Option<Vec<String>>,
    /// Optional JSON Schema URI describing the metadata shape.
    pub schema_uri: Option<String>,
    /// Contributors (DIDs, ≤ 100 unique).
    pub contributors: Option<Vec<String>>,
}

/// Options for `buildSupersedeRequest`. Any field omitted is carried
/// over from `previousBodyJson` unchanged (mirrors `new_version_from`).
#[napi(object)]
pub struct SupersedeOpts {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub domain: Option<String>,
    pub metadata: Option<String>,
}

/// An ACDP producer: an Ed25519 signing key and its did:web identity.
///
/// All methods return wire-ready JSON strings the caller sends via its
/// own HTTP client. No HTTP calls are made inside this class.
#[napi]
pub struct AcdpProducer {
    /// Raw 32-byte Ed25519 seed. Reconstructs `SigningKey` on demand —
    /// `SigningKey` is `ZeroizeOnDrop` and not `Clone`, so the binding
    /// cannot hold a long-lived signing-key handle and replay it.
    ///
    /// Wrapped in `Zeroizing` so the seed bytes are wiped when the
    /// napi class is dropped. Without this, the binding would strip
    /// the zero-on-drop protection the Rust `SigningKey` provides.
    seed: Zeroizing<[u8; 32]>,
    agent_did: String,
    key_id: String,
}

#[napi]
impl AcdpProducer {
    /// Generate a producer with a fresh random Ed25519 key (OsRng).
    #[napi(factory)]
    pub fn generate(agent_did: String, key_id: String) -> Self {
        let key = SigningKey::generate();
        Self {
            seed: Zeroizing::new(key.seed_bytes()),
            agent_did,
            key_id,
        }
    }

    /// Construct from a 32-byte Ed25519 seed (deterministic).
    #[napi(factory)]
    pub fn from_seed(seed: Buffer, agent_did: String, key_id: String) -> Result<Self> {
        let arr: [u8; 32] = seed
            .as_ref()
            .try_into()
            .map_err(|_| Error::from_reason("seed must be exactly 32 bytes"))?;
        Ok(Self {
            seed: Zeroizing::new(arr),
            agent_did,
            key_id,
        })
    }

    /// The producer's DID (`did:web:…`).
    #[napi(getter)]
    pub fn agent_did(&self) -> String {
        self.agent_did.clone()
    }

    /// The producer's signing-key DID URL (`did:web:…#key-1`).
    #[napi(getter)]
    pub fn key_id(&self) -> String {
        self.key_id.clone()
    }

    /// Raw Ed25519 public key as standard base64 (44 chars with padding).
    /// Use this to populate a did:web verification method.
    #[napi(getter)]
    pub fn public_key_b64(&self) -> String {
        let key = SigningKey::from_bytes(&self.seed);
        STANDARD.encode(key.verifying_key_bytes())
    }

    /// The raw 32-byte seed, for storage in a key vault. Returns a
    /// fresh `Buffer` each call — JS owns the bytes.
    #[napi]
    pub fn seed_bytes(&self) -> Buffer {
        self.seed.to_vec().into()
    }

    /// Build and sign a first-version PublishRequest. Returns the
    /// wire JSON string.
    #[napi]
    pub fn build_publish_request(&self, opts: PublishOpts) -> Result<String> {
        let key = SigningKey::from_bytes(&self.seed);
        let did = AgentDid::new(&self.agent_did);
        let producer = Producer::new(key, did, &self.key_id);
        let ctx_type = parse_context_type(&opts.context_type)?;
        let vis = parse_visibility(opts.visibility.as_deref().unwrap_or("public"))?;

        let mut b = producer
            .publish_request()
            .title(opts.title)
            .context_type(ctx_type)
            .visibility(vis);

        if let Some(d) = opts.description {
            b = b.description(d);
        }
        if let Some(s) = opts.summary {
            b = b.summary(s);
        }
        if let Some(t) = opts.tags {
            b = b.tags(t);
        }
        if let Some(d) = opts.domain {
            b = b.domain(d);
        }
        if let Some(u) = opts.schema_uri {
            b = b.schema_uri(u);
        }
        if let Some(m) = opts.metadata {
            let v: serde_json::Value = serde_json::from_str(&m)
                .map_err(|e| Error::from_reason(format!("invalid metadata JSON: {e}")))?;
            b = b.metadata(v);
        }
        if let Some(df) = opts.derived_from {
            b = b.derived_from(df.into_iter().map(CtxId).collect());
        }
        if let Some(aud) = opts.audience {
            b = b.audience(aud.into_iter().map(|d| AgentDid::new(&d)).collect());
        }
        if let Some(c) = opts.contributors {
            b = b.contributors(c.into_iter().map(|d| AgentDid::new(&d)).collect());
        }

        let req = b.build().map_err(|e| Error::from_reason(e.to_string()))?;
        serde_json::to_string(&req).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Build and sign a supersession PublishRequest from a previous
    /// version's `Body` JSON. Version is propagated automatically
    /// (`previous.version + 1`) and `lineage_id` is carried forward.
    #[napi]
    pub fn build_supersede_request(
        &self,
        previous_body_json: String,
        opts: SupersedeOpts,
    ) -> Result<String> {
        let key = SigningKey::from_bytes(&self.seed);
        let did = AgentDid::new(&self.agent_did);
        let producer = Producer::new(key, did, &self.key_id);

        let previous: Body = serde_json::from_str(&previous_body_json)
            .map_err(|e| Error::from_reason(format!("invalid body JSON: {e}")))?;

        let mut b = producer.new_version_from(&previous);
        if let Some(t) = opts.title {
            b = b.title(t);
        }
        if let Some(s) = opts.summary {
            b = b.summary(s);
        }
        if let Some(d) = opts.description {
            b = b.description(d);
        }
        if let Some(t) = opts.tags {
            b = b.tags(t);
        }
        if let Some(d) = opts.domain {
            b = b.domain(d);
        }
        if let Some(m) = opts.metadata {
            let v: serde_json::Value = serde_json::from_str(&m)
                .map_err(|e| Error::from_reason(format!("invalid metadata JSON: {e}")))?;
            b = b.metadata(v);
        }

        let req = b.build().map_err(|e| Error::from_reason(e.to_string()))?;
        serde_json::to_string(&req).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Sign a registry auth-challenge `signingInput` string. Returns
    /// the base64-encoded Ed25519 signature (88 chars with padding).
    /// Used by the ACDP registry's bearer-token flow.
    #[napi]
    pub fn sign_challenge(&self, signing_input: String) -> String {
        let key = SigningKey::from_bytes(&self.seed);
        key.sign_string(&signing_input)
    }
}
