//! Network-policy constants shared by client and server code.
//!
//! Defined per RFC-ACDP-0006 §7. The same caps apply to:
//! - server-side cross-registry resolution ([`crate::registry::safe_http`]),
//! - client-side retrieval and DID resolution
//!   ([`crate::client::RegistryClient`], [`crate::did::WebResolver`]).

use std::time::Duration;

/// Maximum body bytes for a context retrieval (RFC-ACDP-0006 §7.3).
pub const MAX_CONTEXT_BYTES: usize = 1_048_576;

/// Maximum body bytes for capabilities or DID documents (§7.3).
pub const MAX_METADATA_BYTES: usize = 65_536;

/// Maximum HTTP redirects to follow (§7.5).
pub const MAX_REDIRECTS: usize = 3;

/// Default connect timeout (§7.4).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default total request timeout (§7.4).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
