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

use acdp::crypto::{P256SigningKey, SigningKey};
use acdp::did::{did_key_from_ed25519, did_key_from_p256_sec1};
use acdp::producer::{Producer, RequestBuilder};
use acdp::types::{AgentDid, Body, CtxId};
use base64::{engine::general_purpose::STANDARD, Engine};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use zeroize::Zeroizing;

use crate::helpers::{
    parse_anchors, parse_context_type, parse_data_period, parse_data_refs, parse_lineage_id,
    parse_timestamp, parse_visibility,
};

/// Apply the `acdp_version` controls shared by every build path.
///
/// **SDK default (since 0.2): `acdp_version` is emitted explicitly as
/// the library's current ACDP protocol version (`acdp::ACDP_VERSION`,
/// now `"0.2.0"`).** Per RFC-ACDP-0001 §6 consumers treat an absent
/// field as `"0.1.0"`, but the omitted and explicit forms are
/// *different JCS preimages* and therefore hash differently — pick one
/// form per lineage and never switch mid-lineage. `omit_acdp_version=True`
/// restores the 0.1.x omitted form (needed to reproduce hashes signed
/// under it, e.g. the sig-001 golden vector); it takes precedence over
/// an explicit `acdp_version` string.
fn apply_acdp_version(
    mut b: RequestBuilder<'_>,
    acdp_version: Option<String>,
    omit_acdp_version: Option<bool>,
) -> RequestBuilder<'_> {
    if let Some(v) = acdp_version {
        b = b.acdp_version(v);
    }
    if omit_acdp_version.unwrap_or(false) {
        b = b.omit_acdp_version();
    }
    b
}

/// Apply the optional first-version `Body` fields shared by the Ed25519
/// and P-256 publish paths. The complex fields (`data_refs`, `anchors`,
/// `data_period`, `expires_at`, `expected_lineage_id`) cross the FFI
/// boundary as JSON / RFC 3339 strings and are parsed into typed values
/// here so both producers behave identically.
fn apply_publish_fields(
    mut b: RequestBuilder<'_>,
    description: Option<String>,
    summary: Option<String>,
    tags: Option<Vec<String>>,
    domain: Option<String>,
    metadata: Option<String>,
    derived_from: Option<Vec<String>>,
    audience: Option<Vec<String>>,
    schema_uri: Option<String>,
    contributors: Option<Vec<String>>,
    data_refs: Option<String>,
    anchors: Option<String>,
    expires_at: Option<String>,
    data_period: Option<String>,
    expected_lineage_id: Option<String>,
    acdp_version: Option<String>,
    omit_acdp_version: Option<bool>,
) -> PyResult<RequestBuilder<'_>> {
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
    if let Some(dr) = data_refs {
        b = b.data_refs(parse_data_refs(&dr)?);
    }
    if let Some(a) = anchors {
        b = b.anchors(parse_anchors(&a)?);
    }
    if let Some(e) = expires_at {
        b = b.expires_at(parse_timestamp(&e)?);
    }
    if let Some(dp) = data_period {
        b = b.data_period(parse_data_period(&dp)?);
    }
    if let Some(l) = expected_lineage_id {
        b = b.expected_lineage_id(parse_lineage_id(&l)?);
    }
    Ok(apply_acdp_version(b, acdp_version, omit_acdp_version))
}

/// Apply the optional override fields shared by the supersession paths.
/// Any field left `None` is carried over from the previous body by
/// `new_version_from`.
///
/// `clear_anchors=True` unsets `anchors` entirely (the only way to
/// produce a version with none, since `new_version_from` otherwise
/// carries the previous version's `anchors` forward, and `anchors=[]`
/// is rejected by the absent-when-empty rule). Takes precedence over
/// `anchors`, mirroring `omit_acdp_version`'s precedence over
/// `acdp_version`.
fn apply_supersede_fields(
    mut b: RequestBuilder<'_>,
    title: Option<String>,
    summary: Option<String>,
    description: Option<String>,
    tags: Option<Vec<String>>,
    domain: Option<String>,
    metadata: Option<String>,
    data_refs: Option<String>,
    anchors: Option<String>,
    clear_anchors: Option<bool>,
    expires_at: Option<String>,
    data_period: Option<String>,
    expected_lineage_id: Option<String>,
    acdp_version: Option<String>,
    omit_acdp_version: Option<bool>,
) -> PyResult<RequestBuilder<'_>> {
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
    if let Some(dr) = data_refs {
        b = b.data_refs(parse_data_refs(&dr)?);
    }
    if let Some(a) = anchors {
        b = b.anchors(parse_anchors(&a)?);
    }
    if clear_anchors.unwrap_or(false) {
        b = b.clear_anchors();
    }
    if let Some(e) = expires_at {
        b = b.expires_at(parse_timestamp(&e)?);
    }
    if let Some(dp) = data_period {
        b = b.data_period(parse_data_period(&dp)?);
    }
    if let Some(l) = expected_lineage_id {
        b = b.expected_lineage_id(parse_lineage_id(&l)?);
    }
    Ok(apply_acdp_version(b, acdp_version, omit_acdp_version))
}

/// An ACDP producer: an Ed25519 signing key and its DID identity
/// (`did:web`, or `did:key` via the `*_did_key` constructors — ACDP 0.2).
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

impl PyAcdpProducer {
    /// Reconstruct the core [`Producer`] for this identity. For
    /// `did:key` identities the agent_id/key_id are re-derived from the
    /// key itself, and the derivation MUST reproduce the stored
    /// `agent_did` — a mismatch (e.g. `from_seed` paired with someone
    /// else's did:key) raises `ValueError` instead of silently signing
    /// under a different identity. For `did:web` the stored strings are
    /// authoritative.
    fn core_producer(&self) -> PyResult<Producer> {
        let key = SigningKey::from_bytes(&self.seed);
        if self.agent_did.starts_with("did:key:") {
            let derived = did_key_from_ed25519(&key.verifying_key_bytes());
            if derived != self.agent_did {
                return Err(PyValueError::new_err(format!(
                    "did:key identity mismatch: this seed derives '{derived}', \
                     not the stored agent_did '{}' — the seed does not correspond \
                     to the stored did:key (use from_seed_did_key, or pass the \
                     seed that owns this DID)",
                    self.agent_did
                )));
            }
            Ok(Producer::new_did_key(key))
        } else {
            Ok(Producer::new(
                key,
                AgentDid::new(&self.agent_did),
                &self.key_id,
            ))
        }
    }
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

    /// Generate a producer with a fresh random Ed25519 key whose
    /// identity **is** the key (`did:key`, ACDP 0.2).
    ///
    /// `agent_did` and `key_id` are derived from the public key — no
    /// domain, no DID-document hosting. Consumers verify did:key
    /// contexts fully offline via `AcdpVerifier.verify_body_offline`.
    ///
    /// Tradeoff: did:key cannot rotate — a new key is a new identity,
    /// and `supersedes` requires the same `agent_id`, so lineage
    /// continuity ends with the key. Use `did:web` for long-lived
    /// organizational anchors; use did:key for ephemeral or
    /// archival-critical producers.
    #[staticmethod]
    fn generate_did_key() -> Self {
        let key = SigningKey::generate();
        let did = did_key_from_ed25519(&key.verifying_key_bytes());
        let key_id = format!("{did}#{msi}", msi = &did["did:key:".len()..]);
        Self {
            seed: Zeroizing::new(key.seed_bytes()),
            agent_did: did,
            key_id,
        }
    }

    /// Construct a `did:key` producer from a 32-byte Ed25519 seed.
    ///
    /// Deterministic — the same seed always derives the same
    /// `agent_did` / `key_id`. The seed is the private key — protect it
    /// as such. See [`PyAcdpProducer::generate_did_key`] for the
    /// did:key rotation tradeoff.
    #[staticmethod]
    fn from_seed_did_key(seed: &[u8]) -> PyResult<Self> {
        let arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| PyValueError::new_err("seed must be exactly 32 bytes"))?;
        let key = SigningKey::from_bytes(&arr);
        let did = did_key_from_ed25519(&key.verifying_key_bytes());
        let key_id = format!("{did}#{msi}", msi = &did["did:key:".len()..]);
        Ok(Self {
            seed: Zeroizing::new(arr),
            agent_did: did,
            key_id,
        })
    }

    /// The producer's DID (`did:web:…` or `did:key:…`).
    #[getter]
    fn agent_did(&self) -> &str {
        &self.agent_did
    }

    /// The producer's signing-key DID URL (`did:web:…#key-1`, or the
    /// `did:key:z…#z…` self-fragment form).
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
    /// object, not a quoted string). `data_refs` MUST be a JSON-encoded
    /// array of `acdp-data-ref` objects; `data_period` a JSON object
    /// `{"start": <rfc3339>, "end": <rfc3339>}`; `expires_at` an RFC 3339
    /// timestamp string; `expected_lineage_id` a `lin:sha256:<hex>`
    /// string (v2+ only — rejected on first-version publishes).
    ///
    /// **`acdp_version` default (since 0.2): emitted explicitly as the
    /// library's current ACDP protocol version (`acdp::ACDP_VERSION`,
    /// now `"0.2.0"`).** The omitted and explicit forms are *different
    /// JCS preimages* and hash differently — pick one form per lineage
    /// and never switch mid-lineage. Pass `acdp_version` to override
    /// the string, or `omit_acdp_version=True` to restore the 0.1.x
    /// omitted form (e.g. to reproduce the sig-001 golden hash); the
    /// latter takes precedence.
    #[pyo3(signature = (
        title, context_type,
        visibility=None, description=None, summary=None,
        tags=None, domain=None, metadata=None,
        derived_from=None, audience=None, schema_uri=None,
        contributors=None, data_refs=None, anchors=None, expires_at=None,
        data_period=None, expected_lineage_id=None,
        acdp_version=None, omit_acdp_version=None
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
        data_refs: Option<String>,
        anchors: Option<String>,
        expires_at: Option<String>,
        data_period: Option<String>,
        expected_lineage_id: Option<String>,
        acdp_version: Option<String>,
        omit_acdp_version: Option<bool>,
    ) -> PyResult<String> {
        let producer = self.core_producer()?;
        let ctx_type = parse_context_type(&context_type)?;
        let vis = parse_visibility(visibility.as_deref().unwrap_or("public"))?;

        let b = producer
            .publish_request()
            .title(title)
            .context_type(ctx_type)
            .visibility(vis);
        let b = apply_publish_fields(
            b,
            description,
            summary,
            tags,
            domain,
            metadata,
            derived_from,
            audience,
            schema_uri,
            contributors,
            data_refs,
            anchors,
            expires_at,
            data_period,
            expected_lineage_id,
            acdp_version,
            omit_acdp_version,
        )?;

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
    ///
    /// `acdp_version` / `omit_acdp_version` behave as in
    /// [`PyAcdpProducer::build_publish_request`] — the explicit default
    /// (the library's current ACDP protocol version, now `"0.2.0"`) and
    /// the omitted form are *distinct preimages*; keep a lineage on
    /// whichever form it started with.
    #[pyo3(signature = (
        previous_body_json,
        title=None, summary=None, description=None,
        tags=None, domain=None, metadata=None,
        data_refs=None, anchors=None, clear_anchors=None,
        expires_at=None, data_period=None,
        expected_lineage_id=None,
        acdp_version=None, omit_acdp_version=None
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
        data_refs: Option<String>,
        anchors: Option<String>,
        clear_anchors: Option<bool>,
        expires_at: Option<String>,
        data_period: Option<String>,
        expected_lineage_id: Option<String>,
        acdp_version: Option<String>,
        omit_acdp_version: Option<bool>,
    ) -> PyResult<String> {
        let producer = self.core_producer()?;

        let previous: Body = serde_json::from_str(previous_body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;

        let b = producer.new_version_from(&previous);
        let b = apply_supersede_fields(
            b,
            title,
            summary,
            description,
            tags,
            domain,
            metadata,
            data_refs,
            anchors,
            clear_anchors,
            expires_at,
            data_period,
            expected_lineage_id,
            acdp_version,
            omit_acdp_version,
        )?;

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

/// An ACDP producer signing with ECDSA-P256 (RFC-ACDP signature-algorithms
/// `ecdsa-p256`) instead of the Ed25519 baseline.
///
/// Mirrors [`PyAcdpProducer`] exactly — same JSON-in/JSON-out surface —
/// but emits `signature.algorithm = "ecdsa-p256"` and the IEEE 1363
/// `r‖s` wire form. Use this when the producer's `did:web` verification
/// method declares a P-256 key (e.g. for FIPS-constrained deployments).
///
/// The DID document's verification method MUST declare the P-256
/// algorithm so consumers don't reject the signature on
/// algorithm-downgrade grounds (RFC-ACDP-0008 §3.9). Use
/// [`PyAcdpP256Producer::did_verification_method`] to mint that entry.
#[pyclass(name = "AcdpP256Producer")]
pub struct PyAcdpP256Producer {
    /// Raw 32-byte P-256 private scalar (big-endian). Reconstructs
    /// `P256SigningKey` on demand — the key zeroizes its scalar on drop
    /// and is not `Clone`, so the binding cannot hold a long-lived
    /// handle. Wrapped in `Zeroizing` so the seed is wiped on drop.
    seed: Zeroizing<[u8; 32]>,
    agent_did: String,
    key_id: String,
}

impl PyAcdpP256Producer {
    /// Reconstruct the core [`Producer`] for this identity. For
    /// `did:key` identities the agent_id/key_id are re-derived from the
    /// key itself, and the derivation MUST reproduce the stored
    /// `agent_did` — a mismatch (e.g. `from_seed` paired with someone
    /// else's did:key) raises `ValueError` instead of silently signing
    /// under a different identity. For `did:web` the stored strings are
    /// authoritative.
    fn core_producer(&self) -> PyResult<Producer> {
        let key = P256SigningKey::from_bytes(&self.seed)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        if self.agent_did.starts_with("did:key:") {
            let derived = did_key_from_p256_sec1(&key.verifying_key_sec1())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            if derived != self.agent_did {
                return Err(PyValueError::new_err(format!(
                    "did:key identity mismatch: this seed derives '{derived}', \
                     not the stored agent_did '{}' — the seed does not correspond \
                     to the stored did:key (use from_seed_did_key, or pass the \
                     seed that owns this DID)",
                    self.agent_did
                )));
            }
            Producer::new_did_key_p256(key).map_err(|e| PyRuntimeError::new_err(e.to_string()))
        } else {
            Ok(Producer::new_p256(
                key,
                AgentDid::new(&self.agent_did),
                &self.key_id,
            ))
        }
    }
}

#[pymethods]
impl PyAcdpP256Producer {
    /// Generate a producer with a fresh random P-256 key (OsRng).
    ///
    /// * `agent_did` — the full did:web DID.
    /// * `key_id` — the DID URL for the signing key (`…#key-1`).
    #[staticmethod]
    fn generate(agent_did: &str, key_id: &str) -> Self {
        let key = P256SigningKey::generate();
        Self {
            seed: Zeroizing::new(key.seed_bytes()),
            agent_did: agent_did.to_string(),
            key_id: key_id.to_string(),
        }
    }

    /// Construct from a 32-byte P-256 private scalar (big-endian).
    ///
    /// Deterministic — useful for tests and for loading material from a
    /// secret store. Raises `ValueError` if the bytes are not exactly 32
    /// or are not a valid scalar (zero or ≥ curve order).
    #[staticmethod]
    fn from_seed(seed: &[u8], agent_did: &str, key_id: &str) -> PyResult<Self> {
        let arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| PyValueError::new_err("seed must be exactly 32 bytes"))?;
        // Validate the scalar up-front so a bad seed fails at construction
        // rather than on first use.
        P256SigningKey::from_bytes(&arr).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            seed: Zeroizing::new(arr),
            agent_did: agent_did.to_string(),
            key_id: key_id.to_string(),
        })
    }

    /// Generate a producer with a fresh random P-256 key whose identity
    /// **is** the key (`did:key`, ACDP 0.2). P-256 counterpart of
    /// [`PyAcdpProducer::generate_did_key`] — same derivation, same
    /// no-rotation tradeoff.
    ///
    /// [`PyAcdpProducer::generate_did_key`]: crate::producer::PyAcdpProducer
    #[staticmethod]
    fn generate_did_key() -> PyResult<Self> {
        let key = P256SigningKey::generate();
        let did = did_key_from_p256_sec1(&key.verifying_key_sec1())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let key_id = format!("{did}#{msi}", msi = &did["did:key:".len()..]);
        Ok(Self {
            seed: Zeroizing::new(key.seed_bytes()),
            agent_did: did,
            key_id,
        })
    }

    /// Construct a `did:key` producer from a 32-byte P-256 private
    /// scalar (big-endian). Deterministic — the same seed always
    /// derives the same `agent_did` / `key_id`. Raises `ValueError` if
    /// the bytes are not exactly 32 or are not a valid scalar.
    #[staticmethod]
    fn from_seed_did_key(seed: &[u8]) -> PyResult<Self> {
        let arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| PyValueError::new_err("seed must be exactly 32 bytes"))?;
        let key =
            P256SigningKey::from_bytes(&arr).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let did = did_key_from_p256_sec1(&key.verifying_key_sec1())
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let key_id = format!("{did}#{msi}", msi = &did["did:key:".len()..]);
        Ok(Self {
            seed: Zeroizing::new(arr),
            agent_did: did,
            key_id,
        })
    }

    /// The producer's DID (`did:web:…` or `did:key:…`).
    #[getter]
    fn agent_did(&self) -> &str {
        &self.agent_did
    }

    /// The producer's signing-key DID URL (`did:web:…#key-1`, or the
    /// `did:key:z…#z…` self-fragment form).
    #[getter]
    fn key_id(&self) -> &str {
        &self.key_id
    }

    /// SEC1-uncompressed public key (`0x04 || x || y`, 65 bytes) as
    /// standard base64.
    ///
    /// Use this (or split into JWK `x`/`y` halves) to populate a did:web
    /// `JsonWebKey2020` verification method when standing up the
    /// producer's DID document.
    #[getter]
    fn public_key_sec1_b64(&self) -> PyResult<String> {
        let key = P256SigningKey::from_bytes(&self.seed)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(STANDARD.encode(key.verifying_key_sec1()))
    }

    /// The producer's P-256 public key as a JWK
    /// (`{"kty":"EC","crv":"P-256","x":…,"y":…}`), returned as a JSON
    /// object string. Drop this straight into a did:web `JsonWebKey2020`
    /// verification method's `publicKeyJwk`.
    #[getter]
    fn public_key_jwk(&self) -> PyResult<String> {
        let key = P256SigningKey::from_bytes(&self.seed)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        serde_json::to_string(&key.verifying_key_jwk())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// A complete `verificationMethod` entry (JSON object string) for a
    /// did:web DID document, of type `JsonWebKey2020`.
    ///
    /// * `method_id` — the full DID URL for this key (e.g.
    ///   `"did:web:agents.example.com:alice#key-1"`).
    /// * `controller` — the bare DID that owns the key (no fragment).
    ///
    /// Consumers resolve the signature algorithm from this entry, so
    /// publishing it is what keeps a P-256 signature from being rejected
    /// on algorithm-downgrade grounds (RFC-ACDP-0008 §3.9).
    fn did_verification_method(&self, method_id: &str, controller: &str) -> PyResult<String> {
        let key = P256SigningKey::from_bytes(&self.seed)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        serde_json::to_string(&key.did_verification_method(method_id, controller))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// The raw 32-byte private scalar, for storage in a key vault.
    ///
    /// Returns a fresh `bytes` copy each call — Python owns the buffer.
    fn seed_bytes(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    /// Build and sign a first-version PublishRequest. Returns the wire
    /// JSON string. Identical surface to
    /// [`PyAcdpProducer::build_publish_request`] (including the
    /// explicit-`acdp_version` default and the `omit_acdp_version`
    /// opt-out — distinct preimages, see there); only the signature
    /// algorithm differs.
    #[pyo3(signature = (
        title, context_type,
        visibility=None, description=None, summary=None,
        tags=None, domain=None, metadata=None,
        derived_from=None, audience=None, schema_uri=None,
        contributors=None, data_refs=None, anchors=None, expires_at=None,
        data_period=None, expected_lineage_id=None,
        acdp_version=None, omit_acdp_version=None
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
        data_refs: Option<String>,
        anchors: Option<String>,
        expires_at: Option<String>,
        data_period: Option<String>,
        expected_lineage_id: Option<String>,
        acdp_version: Option<String>,
        omit_acdp_version: Option<bool>,
    ) -> PyResult<String> {
        let producer = self.core_producer()?;
        let ctx_type = parse_context_type(&context_type)?;
        let vis = parse_visibility(visibility.as_deref().unwrap_or("public"))?;

        let b = producer
            .publish_request()
            .title(title)
            .context_type(ctx_type)
            .visibility(vis);
        let b = apply_publish_fields(
            b,
            description,
            summary,
            tags,
            domain,
            metadata,
            derived_from,
            audience,
            schema_uri,
            contributors,
            data_refs,
            anchors,
            expires_at,
            data_period,
            expected_lineage_id,
            acdp_version,
            omit_acdp_version,
        )?;

        let req = b
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        serde_json::to_string(&req).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Build and sign a supersession PublishRequest from a previous
    /// version's `Body` JSON. Same semantics as
    /// [`PyAcdpProducer::build_supersede_request`] (including the
    /// `acdp_version` / `omit_acdp_version` distinct-preimage rule).
    #[pyo3(signature = (
        previous_body_json,
        title=None, summary=None, description=None,
        tags=None, domain=None, metadata=None,
        data_refs=None, anchors=None, clear_anchors=None,
        expires_at=None, data_period=None,
        expected_lineage_id=None,
        acdp_version=None, omit_acdp_version=None
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
        data_refs: Option<String>,
        anchors: Option<String>,
        clear_anchors: Option<bool>,
        expires_at: Option<String>,
        data_period: Option<String>,
        expected_lineage_id: Option<String>,
        acdp_version: Option<String>,
        omit_acdp_version: Option<bool>,
    ) -> PyResult<String> {
        let producer = self.core_producer()?;

        let previous: Body = serde_json::from_str(previous_body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;

        let b = producer.new_version_from(&previous);
        let b = apply_supersede_fields(
            b,
            title,
            summary,
            description,
            tags,
            domain,
            metadata,
            data_refs,
            anchors,
            clear_anchors,
            expires_at,
            data_period,
            expected_lineage_id,
            acdp_version,
            omit_acdp_version,
        )?;

        let req = b
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        serde_json::to_string(&req).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Sign a registry auth-challenge `signing_input` string with the
    /// producer's P-256 key. Returns the base64 IEEE 1363 signature.
    /// Same flow as [`PyAcdpProducer::sign_challenge`].
    fn sign_challenge(&self, signing_input: &str) -> PyResult<String> {
        let key = P256SigningKey::from_bytes(&self.seed)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(key.sign_string(signing_input))
    }
}
