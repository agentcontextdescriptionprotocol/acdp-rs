//! # acdp-primitives — foundational types for the Agent Context Distribution Protocol
//!
//! The bottom layer of the `acdp` crate family: the typed error
//! vocabulary ([`error::AcdpError`]), the opaque identifier/enum
//! primitives ([`primitives`]), the wire error envelope (`WireError`,
//! whose canonical public path is `acdp::types::WireError`), and small
//! shared utilities (`limits`, `time`, `serde_helpers`). It has no
//! cryptography and makes no network calls.
//!
//! Most users should depend on the umbrella [`acdp`](https://docs.rs/acdp)
//! crate, which re-exports everything here.

pub mod error;
pub mod limits;
pub mod primitives;
pub mod serde_helpers;
pub mod time;
// The `WireError` envelope is *defined* here (down in `acdp-primitives`
// to break the historical error↔types dependency cycle), but its
// canonical public path is `acdp::types::WireError` / `WireErrorBody`.
// The module and the direct re-export below stay `pub` only for
// intra-workspace back-compat (`acdp-types` re-exports from here); they
// are `#[doc(hidden)]` so downstream users are steered to the single
// canonical path.
#[doc(hidden)]
pub mod wire_error;

pub use error::{AcdpError, SupersessionReason};
pub use primitives::{AgentDid, ContentHash, ContextType, CtxId, LineageId, Status, Visibility};
#[doc(hidden)]
pub use wire_error::{WireError, WireErrorBody};

// ── Protocol version ──────────────────────────────────────────────────────────

/// The ACDP protocol version this library implements.
///
/// `0.2.0` carries the Trust & Hardening amendments (registry receipts
/// — RFC-ACDP-0010, `did:key` producers, mandatory explicit
/// `acdp_version`, lineage anchoring). Every v0.1.0 body, signature, and
/// `content_hash` remains valid. An absent `acdp_version` field on a
/// publish request is interpreted as `0.1.0` by the protocol; 0.2.0
/// builders MUST emit the field explicitly (RFC-ACDP-0001 §6).
pub const ACDP_VERSION: &str = "0.2.0";

/// The JSON Schema namespace (`$id` prefix) for this protocol version,
/// e.g. `<ACDP_SCHEMA_NAMESPACE>/acdp-error.schema.json`.
pub const ACDP_SCHEMA_NAMESPACE: &str = "https://schemas.acdp.io/v0.1.0";
