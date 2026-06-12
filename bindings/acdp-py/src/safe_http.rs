//! `AcdpSsrfPolicy` — synchronous SSRF verdicts for host-language HTTP.
//!
//! The binding deliberately owns only the *verdict*, never the socket:
//! DNS resolution and the actual GET stay in the host language (httpx /
//! requests), matching the SDK's "HTTP belongs to the host" design. These
//! pure, synchronous checks let the host stop re-implementing the
//! security-critical SSRF classification (RFC-ACDP-0006 §7,
//! RFC-ACDP-0008 §4.8) in Python.
//!
//! A rejection raises [`SsrfRejected`], whose `.reason` attribute carries
//! the stable [`acdp::safe_http::SsrfReason`] code (`"loopback"`,
//! `"imds"`, `"private"`, `"multicast_or_reserved"`, `"non_https"`,
//! `"ip_literal"`, `"invalid_url"`, `"cross_authority"`) so host code can
//! branch on it without string-matching the message.

use std::net::IpAddr;

use acdp::safe_http::{SsrfPolicy, SsrfRejection};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;

create_exception!(
    acdp,
    SsrfRejected,
    PyException,
    "Raised when an SSRF check rejects a URL, IP, or redirect. The \
     `.reason` attribute is a stable snake_case code."
);

/// Convert a Rust [`SsrfRejection`] into an [`SsrfRejected`] Python
/// exception, attaching the stable reason code as `.reason`.
fn ssrf_err(rej: SsrfRejection) -> PyErr {
    Python::with_gil(|py| {
        let err = SsrfRejected::new_err(rej.detail);
        // Attach the machine-readable reason for programmatic handling.
        // If the attribute set ever fails, surface that error instead of
        // silently dropping the reason.
        match err.value_bound(py).setattr("reason", rej.reason.as_str()) {
            Ok(()) => err,
            Err(set_err) => set_err,
        }
    })
}

/// An SSRF policy: the synchronous classification half of the Rust
/// `SsrfPolicy`, exposed verdict-only (no DNS, no sockets).
#[pyclass(name = "AcdpSsrfPolicy")]
pub struct PyAcdpSsrfPolicy {
    inner: SsrfPolicy,
}

#[pymethods]
impl PyAcdpSsrfPolicy {
    /// The production policy: HTTPS-only, IP literals rejected, every
    /// private / loopback / link-local / IMDS / multicast / reserved
    /// range forbidden.
    #[staticmethod]
    fn production() -> Self {
        Self {
            inner: SsrfPolicy::default(),
        }
    }

    /// A test-only policy that additionally permits loopback
    /// (`127.0.0.0/8` / `::1`) so a test harness can target a local
    /// listener. Never use in production.
    #[staticmethod]
    fn allow_test_loopback() -> Self {
        Self {
            inner: SsrfPolicy::allow_test_loopback(),
        }
    }

    /// Validate a URL: scheme (HTTPS-only), IP-literal rejection, and —
    /// for literal hosts — per-IP range filtering.
    ///
    /// Returns `None` on success. Raises `SsrfRejected` (with `.reason`)
    /// on a policy violation.
    fn check_url(&self, url: &str) -> PyResult<()> {
        self.inner.classify_url(url).map_err(ssrf_err)
    }

    /// Validate a single already-resolved IP address (IPv4 or IPv6
    /// string). This is the per-address predicate the host loops over
    /// after resolving DNS itself — rejecting the whole answer set if any
    /// address fails (the mixed-answer rule stays in the host).
    ///
    /// Returns `None` on success. Raises `ValueError` if `ip` is not a
    /// valid address, or `SsrfRejected` (with `.reason`) if it falls in a
    /// forbidden range.
    fn check_ip(&self, ip: &str) -> PyResult<()> {
        let parsed: IpAddr = ip
            .parse()
            .map_err(|e| PyValueError::new_err(format!("invalid IP address '{ip}': {e}")))?;
        self.inner.classify_ip(parsed).map_err(ssrf_err)
    }

    /// Validate that a redirect target stays within the origin's fetch
    /// authority — identical scheme, host, and effective port (an
    /// explicit `:443` equals the implicit https default).
    ///
    /// Returns `None` on success. Raises `SsrfRejected` (with `.reason ==
    /// "cross_authority"`) when the authority differs.
    fn check_redirect_authority(&self, from_url: &str, to_url: &str) -> PyResult<()> {
        self.inner
            .classify_redirect(from_url, to_url)
            .map_err(ssrf_err)
    }
}
