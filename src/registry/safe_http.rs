//! Server-side re-exports of the shared SSRF defense primitives.
//!
//! The actual implementation lives in [`crate::safe_http`] so client-side
//! code (e.g. `CrossRegistryResolver`) can use the same policy without
//! enabling the `server` feature. This module exists for back-compat with
//! `acdp::registry::safe_http::SsrfPolicy` import paths.

pub use crate::limits::{MAX_CONTEXT_BYTES, MAX_METADATA_BYTES, MAX_REDIRECTS};
pub use crate::safe_http::SsrfPolicy;
