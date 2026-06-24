//! Server-side re-exports of the shared SSRF defense primitives.
//!
//! The actual implementation lives in [`acdp_safe_http`] so client-side
//! code (e.g. `CrossRegistryResolver`) can use the same policy without
//! enabling the `server` feature. This module exists for back-compat with
//! `acdp::registry::safe_http::SsrfPolicy` import paths.

pub use acdp_primitives::limits::{MAX_CONTEXT_BYTES, MAX_METADATA_BYTES, MAX_REDIRECTS};
pub use acdp_safe_http::SsrfPolicy;
