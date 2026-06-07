//! `AcdpSsrfPolicy` — synchronous SSRF verdicts for host-language HTTP.
//!
//! The binding deliberately owns only the *verdict*, never the socket:
//! DNS resolution and the actual fetch stay in JS land (fetch / undici),
//! matching the SDK's "HTTP belongs to the host" design. These pure,
//! synchronous checks let the host stop re-implementing the
//! security-critical SSRF classification (RFC-ACDP-0006 §7,
//! RFC-ACDP-0008 §4.8) in JavaScript.
//!
//! On rejection the thrown `Error` carries the stable reason on its
//! `.code` property — the JS-idiomatic parallel to the Python SDK's
//! `SsrfRejected.reason`. Codes are `loopback`, `imds`, `private`,
//! `multicast_or_reserved`, `non_https`, `ip_literal`, `invalid_url`,
//! `cross_authority`, plus `invalid_ip` for an unparseable address.

use std::net::IpAddr;

use acdp::safe_http::{SsrfPolicy, SsrfRejection};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Convert a Rust [`SsrfRejection`] into a JS `Error` whose `.code` is the
/// stable reason and whose `.message` is the human-readable detail.
fn ssrf_err(rej: SsrfRejection) -> Error<String> {
    Error::new(rej.reason.as_str().to_string(), rej.detail)
}

/// An SSRF policy: the synchronous classification half of the Rust
/// `SsrfPolicy`, exposed verdict-only (no DNS, no sockets).
#[napi]
pub struct AcdpSsrfPolicy {
    inner: SsrfPolicy,
}

#[napi]
impl AcdpSsrfPolicy {
    /// The production policy: HTTPS-only, IP literals rejected, every
    /// private / loopback / link-local / IMDS / multicast / reserved
    /// range forbidden.
    #[napi(factory)]
    pub fn production() -> Self {
        Self {
            inner: SsrfPolicy::default(),
        }
    }

    /// A test-only policy that additionally permits loopback
    /// (`127.0.0.0/8` / `::1`) so a test harness can target a local
    /// listener. Never use in production.
    #[napi(factory)]
    pub fn allow_test_loopback() -> Self {
        Self {
            inner: SsrfPolicy::allow_test_loopback(),
        }
    }

    /// Validate a URL: scheme (HTTPS-only), IP-literal rejection, and —
    /// for literal hosts — per-IP range filtering.
    ///
    /// Resolves on success. Throws an `Error` whose `.code` is the stable
    /// reason on a policy violation.
    #[napi]
    pub fn check_url(&self, url: String) -> Result<(), String> {
        self.inner.classify_url(&url).map_err(ssrf_err)
    }

    /// Validate a single already-resolved IP address (IPv4 or IPv6
    /// string). This is the per-address predicate the host loops over
    /// after resolving DNS itself — rejecting the whole answer set if any
    /// address fails (the mixed-answer rule stays in the host).
    ///
    /// Resolves on success. Throws with `.code === "invalid_ip"` if `ip`
    /// is not a valid address, or with the stable range reason if it
    /// falls in a forbidden range.
    #[napi]
    pub fn check_ip(&self, ip: String) -> Result<(), String> {
        let parsed: IpAddr = ip.parse().map_err(|e| {
            Error::new(
                "invalid_ip".to_string(),
                format!("invalid IP address '{ip}': {e}"),
            )
        })?;
        self.inner.classify_ip(parsed).map_err(ssrf_err)
    }

    /// Validate that a redirect target stays within the origin's fetch
    /// authority — identical scheme, host, and effective port (an
    /// explicit `:443` equals the implicit https default).
    ///
    /// Resolves on success. Throws with `.code === "cross_authority"`
    /// when the authority differs.
    #[napi]
    pub fn check_redirect_authority(&self, from_url: String, to_url: String) -> Result<(), String> {
        self.inner
            .classify_redirect(&from_url, &to_url)
            .map_err(ssrf_err)
    }
}
