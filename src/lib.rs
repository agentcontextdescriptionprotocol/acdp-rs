//! # acdp — Rust library for the Agent Context Description Protocol
//!
//! ACDP lets agents publish immutable, producer-signed context descriptors,
//! retrieve and verify them locally, discover them by keyword, and follow
//! signed references across registries.
//!
//! ## Quick start — producer
//!
//! ```rust,no_run
//! # use acdp::{producer::Producer, crypto::SigningKey,
//! #            types::{AgentDid, ContextType, Visibility}};
//! // In production, load from secure storage; `generate` uses OsRng.
//! let key  = SigningKey::generate();
//! let prod = Producer::new(
//!     key,
//!     AgentDid::new("did:web:agents.example.com:my-agent"),
//!     "did:web:agents.example.com:my-agent#key-1",
//! );
//!
//! let req = prod.publish_request()
//!     .title("Q1 snapshot")
//!     .context_type(ContextType::DataSnapshot)
//!     .visibility(Visibility::Public)
//!     .build()
//!     .unwrap();
//!
//! println!("content_hash: {}", req.content_hash);
//! ```
//!
//! ## Quick start — consumer (feature = "client")
//!
//! ```rust,no_run
//! # #[cfg(feature = "client")]
//! # async fn example() -> Result<(), acdp::error::AcdpError> {
//! use acdp::{client::{RegistryClient, VerifiedContext}, did::WebResolver, types::CtxId};
//!
//! let client   = RegistryClient::new("https://registry.example.com")?;
//! let resolver = WebResolver::new();
//! let ctx_id   = CtxId("acdp://registry.example.com/…".into());
//! let ctx      = VerifiedContext::fetch(&client, &resolver, &ctx_id).await?;
//! println!("title: {}", ctx.body().title);
//! # Ok(())
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod crypto;
pub mod did;
pub mod error;
pub mod limits;
pub mod producer;
pub mod profile;
pub mod safe_http;
pub mod time;
pub mod types;
pub mod validation;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod registry;

// ── Protocol version ──────────────────────────────────────────────────────────

/// The ACDP protocol version this library implements.
///
/// Per the spec CHANGELOG the `0.0.1` identifier was never promoted past
/// draft and is superseded by `0.1.0`. Note that an absent
/// `acdp_version` field on a publish request is interpreted as this
/// version by the protocol — see [`producer::RequestBuilder::acdp_version`].
pub const ACDP_VERSION: &str = "0.1.0";

/// The JSON Schema namespace (`$id` prefix) for this protocol version,
/// e.g. `<ACDP_SCHEMA_NAMESPACE>/acdp-error.schema.json`.
pub const ACDP_SCHEMA_NAMESPACE: &str = "https://schemas.acdp.io/v0.1.0";

// ── Convenience re-exports ────────────────────────────────────────────────────
pub use error::{AcdpError, SupersessionReason};
pub use types::{
    AgentDid, Body, CapabilitiesDocument, ContentHash, ContextType, CtxId, DataRef, DataRefType,
    FullContext, LineageId, Location, PublishRequest, PublishResponse, RegistryState, SearchParams,
    SearchResponse, Status, Visibility, WireError,
};
