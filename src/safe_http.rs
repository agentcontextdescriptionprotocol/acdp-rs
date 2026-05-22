//! SSRF defenses for server-side cross-registry resolution
//! (RFC-ACDP-0006 §7).
//!
//! When a registry resolves a foreign `acdp://` reference on behalf of a
//! consumer, it must defend against attacker-supplied URIs that target the
//! registry's own internal network. This module implements the policy
//! decisions enumerated by §7:
//!
//! - **§7.1** Reject loopback, RFC 1918 / 4193 private ranges, link-local,
//!   multicast, the AWS / GCP metadata endpoint (`169.254.169.254`), and
//!   the IPv6 equivalents.
//! - **§7.2** HTTPS-only.
//! - **§7.3** Response-size caps.
//! - **§7.5** Maximum redirects, same-authority only.
//! - **§7.6** DNS rebinding protection. [`SsrfPolicy::pin_resolved_ip`]
//!   resolves a hostname once, validates **every** returned IP, and
//!   returns a [`SocketAddr`] that the caller pins into
//!   `reqwest::Client::builder().resolve(host, addr)` — so the filter
//!   and the connection use the same IP, defeating a hostile DNS server
//!   flipping the answer between the two. Per §7.1 the resolution is
//!   rejected outright if **any** returned IP is forbidden — a public
//!   answer cannot mask a private one.

#[cfg(feature = "client")]
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::AcdpError;

#[cfg(feature = "client")]
use std::sync::Arc;

// Re-exported from [`crate::limits`] for back-compat.
pub use crate::limits::{MAX_CONTEXT_BYTES, MAX_METADATA_BYTES, MAX_REDIRECTS};

/// SSRF policy applied to outbound HTTP requests.
#[derive(Debug, Clone)]
pub struct SsrfPolicy {
    /// If true, reject IP literals in the URL (forces DNS resolution).
    pub reject_ip_literals: bool,
    /// If false, only `https://` URLs are accepted. Default `false`.
    pub allow_http: bool,
    /// When true, permit IPv4 `127.0.0.0/8` and IPv6 `::1` (loopback)
    /// across [`Self::check_ip`] / [`Self::check_resolved_ip`] /
    /// [`Self::pin_resolved_ip`]. All other forbidden ranges
    /// (RFC 1918, link-local / IMDS, ULA, CGNAT, multicast, …) still
    /// apply. Default `false`.
    ///
    /// Intended for test harnesses that resolve `did:web:localhost…`
    /// against a self-signed in-process HTTPS server bound to
    /// `127.0.0.1`. Production callers MUST keep this `false` — opening
    /// loopback turns the resolver into an SSRF vector against
    /// process-internal listeners (RFC-ACDP-0008 §4.8).
    pub allow_loopback_resolved: bool,
}

impl Default for SsrfPolicy {
    fn default() -> Self {
        Self {
            reject_ip_literals: true,
            allow_http: false,
            allow_loopback_resolved: false,
        }
    }
}

impl SsrfPolicy {
    /// A test-only policy: defaults + `allow_loopback_resolved = true`.
    ///
    /// `#[doc(hidden)]` because production must never use this — see
    /// [`Self::allow_loopback_resolved`].
    #[doc(hidden)]
    pub fn allow_test_loopback() -> Self {
        Self {
            allow_loopback_resolved: true,
            ..Self::default()
        }
    }
}

impl SsrfPolicy {
    /// Validate a URL string (scheme + host) before issuing a request.
    pub fn check_url(&self, url: &str) -> Result<(), AcdpError> {
        let parsed = url::Url::parse(url)
            .map_err(|e| AcdpError::SchemaViolation(format!("invalid URL: {e}")))?;

        if !self.allow_http && parsed.scheme() != "https" {
            return Err(AcdpError::SchemaViolation(format!(
                "SSRF policy: scheme '{}' not permitted; only https",
                parsed.scheme()
            )));
        }

        let host = parsed
            .host()
            .ok_or_else(|| AcdpError::SchemaViolation(format!("URL has no host: {url}")))?;

        match host {
            url::Host::Ipv4(v4) => {
                if self.reject_ip_literals {
                    return Err(AcdpError::SchemaViolation(format!(
                        "SSRF policy: IPv4 literal '{v4}' not permitted; use a hostname"
                    )));
                }
                self.check_ip(IpAddr::V4(v4))?;
            }
            url::Host::Ipv6(v6) => {
                if self.reject_ip_literals {
                    return Err(AcdpError::SchemaViolation(format!(
                        "SSRF policy: IPv6 literal '{v6}' not permitted; use a hostname"
                    )));
                }
                self.check_ip(IpAddr::V6(v6))?;
            }
            url::Host::Domain(name) => {
                if name.is_empty() || name.len() > 253 {
                    return Err(AcdpError::SchemaViolation(format!(
                        "SSRF policy: invalid hostname length: {name}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate an already-resolved [`IpAddr`] — useful when DNS resolution
    /// is performed externally and the caller wants to filter pre-connect.
    /// Respects [`Self::allow_loopback_resolved`].
    pub fn check_resolved_ip(&self, ip: IpAddr) -> Result<(), AcdpError> {
        self.check_ip(ip)
    }

    /// Range filter for a single [`IpAddr`], respecting the policy's
    /// [`Self::allow_loopback_resolved`] flag.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), AcdpError> {
        let bad = match ip {
            IpAddr::V4(v4) => {
                if self.allow_loopback_resolved && v4.is_loopback() {
                    false
                } else {
                    is_unsafe_v4(v4)
                }
            }
            IpAddr::V6(v6) => {
                if self.allow_loopback_resolved && v6.is_loopback() {
                    false
                } else {
                    is_unsafe_v6(v6)
                }
            }
        };
        if bad {
            return Err(AcdpError::SchemaViolation(format!(
                "SSRF policy: IP address '{ip}' is in a forbidden range"
            )));
        }
        Ok(())
    }

    /// DNS rebinding protection per RFC-ACDP-0006 §7.6.
    ///
    /// Resolves `host:port`, validates **every** returned address, and
    /// returns one [`SocketAddr`] to pin. The caller MUST pin this exact
    /// address into the HTTP client via
    /// `reqwest::Client::builder().resolve(host, addr)` — otherwise a
    /// hostile authoritative DNS could flip the answer between the filter
    /// check and the connect, bypassing §7.1.
    ///
    /// RFC-ACDP-0006 §7.1 / RFC-ACDP-0008 §4.8: if **any** resolved
    /// address is in a forbidden range, the **entire** resolution is
    /// rejected — an attacker MUST NOT be able to bypass the filter by
    /// mixing one public and one private answer in a single DNS response.
    ///
    /// Returns [`AcdpError::Http`] when DNS returns no answers and
    /// [`AcdpError::SchemaViolation`] when any answer is in a forbidden
    /// range.
    #[cfg(feature = "client")]
    pub async fn pin_resolved_ip(&self, host: &str, port: u16) -> Result<SocketAddr, AcdpError> {
        let target = format!("{host}:{port}");
        let candidates: Vec<SocketAddr> = tokio::net::lookup_host(&target)
            .await
            .map_err(|e| AcdpError::Http(format!("DNS lookup for '{host}' failed: {e}")))?
            .collect();
        if candidates.is_empty() {
            return Err(AcdpError::Http(format!(
                "DNS lookup for '{host}' returned no addresses"
            )));
        }
        // Validate EVERY resolved address before pinning one. Any failure
        // aborts the whole resolution (no silent filtering).
        reject_if_any_forbidden(self, host, &candidates)?;
        // All candidates passed — pin the first (IPv4-preferred).
        let pinned = candidates
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| candidates.first())
            .copied()
            .expect("candidates is non-empty");
        Ok(pinned)
    }

    /// Per §7.5: a redirect is permitted only if it stays within the same
    /// fetch authority as the originating request — identical scheme,
    /// host, and effective port (RFC-ACDP-0008 §4.8: "host + port").
    pub fn check_redirect_authority(
        &self,
        original_url: &url::Url,
        redirect_url: &str,
    ) -> Result<(), AcdpError> {
        let redirect = url::Url::parse(redirect_url)
            .map_err(|e| AcdpError::SchemaViolation(format!("invalid redirect URL: {e}")))?;
        if !same_fetch_authority(original_url, &redirect) {
            return Err(AcdpError::SchemaViolation(format!(
                "SSRF policy: cross-authority redirect rejected: {original_url} → {redirect}"
            )));
        }
        Ok(())
    }
}

/// Returns `true` when `a` and `b` share the same fetch authority:
/// identical scheme, identical host, and identical effective port
/// (the scheme default applies — 443 for `https`, 80 for `http`).
///
/// RFC-ACDP-0006 §7.5 and RFC-ACDP-0008 §4.8: a "same authority"
/// redirect must match host **and** port; this also pins the scheme so
/// an `https → http` downgrade can never be treated as same-authority.
pub(crate) fn same_fetch_authority(a: &url::Url, b: &url::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Strict-default range filter (no loopback allowance). Retained as a
/// test-only helper that pins the legacy `check_safe_ip` semantics —
/// production callers should use the policy-aware
/// [`SsrfPolicy::check_ip`] instead.
#[cfg(test)]
fn check_safe_ip(ip: IpAddr) -> Result<(), AcdpError> {
    let bad = match ip {
        IpAddr::V4(v4) => is_unsafe_v4(v4),
        IpAddr::V6(v6) => is_unsafe_v6(v6),
    };
    if bad {
        return Err(AcdpError::SchemaViolation(format!(
            "SSRF policy: IP address '{ip}' is in a forbidden range"
        )));
    }
    Ok(())
}

// ── DNS-rebinding protection (RFC-ACDP-0006 §7.6 / RFC-ACDP-0008 §4.8) ──────
//
// Plumb [`SsrfPolicy::check_ip`] into reqwest's DNS resolver hook so the
// filter and the actual TCP connect see the SAME resolved IP. A hostile
// authoritative DNS server can no longer flip the answer between a
// pre-connect `pin_resolved_ip` check and the real connect: reqwest
// passes the addresses we return straight to the connector.

/// Reject the **entire** resolution if ANY candidate address is in a
/// forbidden range (RFC-ACDP-0006 §7.1 / RFC-ACDP-0008 §4.8). Shared by
/// [`SsrfPolicy::pin_resolved_ip`] and [`SafeDnsResolver::resolve`] so
/// both apply identical reject-all semantics — never silent filtering.
#[cfg(feature = "client")]
fn reject_if_any_forbidden(
    policy: &SsrfPolicy,
    host: &str,
    candidates: &[SocketAddr],
) -> Result<(), AcdpError> {
    for addr in candidates {
        if let Err(e) = policy.check_ip(addr.ip()) {
            return Err(AcdpError::SchemaViolation(format!(
                "SSRF policy: DNS answer for '{host}' contains a forbidden address \
                 ({} is disallowed); rejecting the entire resolution. {e}",
                addr.ip()
            )));
        }
    }
    Ok(())
}

/// `reqwest::dns::Resolve` implementation that validates every resolved
/// IP through an [`SsrfPolicy`] before handing them to the connector.
#[cfg(feature = "client")]
pub(crate) struct SafeDnsResolver {
    policy: SsrfPolicy,
}

#[cfg(feature = "client")]
impl SafeDnsResolver {
    pub(crate) fn arc(policy: SsrfPolicy) -> Arc<Self> {
        Arc::new(Self { policy })
    }
}

#[cfg(feature = "client")]
impl reqwest::dns::Resolve for SafeDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0 — reqwest replaces it with the URL's port (or the
            // scheme default) before connecting. We only care about the
            // IPs returned.
            let target = format!("{host}:0");
            let candidates: Vec<SocketAddr> = tokio::net::lookup_host(&target)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();

            if candidates.is_empty() {
                let msg: String = format!("DNS lookup for '{host}' returned no addresses");
                return Err(msg.into());
            }

            // RFC-ACDP-0006 §7.1 / RFC-ACDP-0008 §4.8: validate EVERY
            // resolved address. If any answer is in a forbidden range the
            // ENTIRE resolution is rejected — never silently filter, or an
            // attacker bypasses the filter by mixing one public and one
            // private answer in a single DNS response. reqwest bubbles
            // this up as a transport error and the caller's error mapper
            // (e.g. WebResolver) translates it.
            if let Err(e) = reject_if_any_forbidden(&policy, &host, &candidates) {
                let msg: String = e.to_string();
                return Err(msg.into());
            }

            let addrs: reqwest::dns::Addrs = Box::new(candidates.into_iter());
            Ok(addrs)
        })
    }
}

fn is_unsafe_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // 0.0.0.0/8 — current network
    o[0] == 0
        // 10.0.0.0/8 — private
        || o[0] == 10
        // 100.64.0.0/10 — CGNAT
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        // 127.0.0.0/8 — loopback
        || o[0] == 127
        // 169.254.0.0/16 — link-local + AWS/GCP IMDS
        || (o[0] == 169 && o[1] == 254)
        // 172.16.0.0/12 — private
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        // 192.0.0.0/24 — IETF protocol
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 192.168.0.0/16 — private
        || (o[0] == 192 && o[1] == 168)
        // 198.18.0.0/15 — benchmarking
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        // 224.0.0.0/4 — multicast
        || (o[0] >= 224 && o[0] <= 239)
        // 240.0.0.0/4 — reserved
        || o[0] >= 240
}

fn is_unsafe_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let segments = ip.segments();
    // ::ffff:0:0/96 — IPv4-mapped: re-check the embedded v4
    if segments[0..6] == [0, 0, 0, 0, 0, 0xffff] {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        return is_unsafe_v4(v4);
    }
    // fc00::/7 — unique local
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // fe80::/10 — link-local
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_only_by_default() {
        let p = SsrfPolicy::default();
        assert!(p.check_url("https://registry.example.com").is_ok());
        assert!(p.check_url("http://registry.example.com").is_err());
        assert!(p.check_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn rejects_ip_literals_by_default() {
        let p = SsrfPolicy::default();
        assert!(p.check_url("https://192.168.1.1").is_err());
        assert!(p.check_url("https://[::1]").is_err());
    }

    #[test]
    fn private_v4_ranges_rejected() {
        // RFC 1918
        assert!(check_safe_ip("10.0.0.1".parse().unwrap()).is_err());
        assert!(check_safe_ip("172.16.5.5".parse().unwrap()).is_err());
        assert!(check_safe_ip("192.168.1.1".parse().unwrap()).is_err());
        // Loopback
        assert!(check_safe_ip("127.0.0.1".parse().unwrap()).is_err());
        // Link-local + AWS IMDS
        assert!(check_safe_ip("169.254.169.254".parse().unwrap()).is_err());
        // Multicast
        assert!(check_safe_ip("239.0.0.1".parse().unwrap()).is_err());
        // Public
        assert!(check_safe_ip("8.8.8.8".parse().unwrap()).is_ok());
        assert!(check_safe_ip("203.0.113.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn unsafe_v6_rejected() {
        assert!(check_safe_ip("::1".parse().unwrap()).is_err());
        assert!(check_safe_ip("fc00::1".parse().unwrap()).is_err());
        assert!(check_safe_ip("fe80::1".parse().unwrap()).is_err());
        // IPv4-mapped private
        assert!(check_safe_ip("::ffff:10.0.0.1".parse().unwrap()).is_err());
        // Public v6
        assert!(check_safe_ip("2001:db8::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn cross_authority_redirect_rejected() {
        let p = SsrfPolicy::default();
        let orig = url::Url::parse("https://registry.example.com/a").unwrap();
        let err = p
            .check_redirect_authority(&orig, "https://attacker.com/x")
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
        // Same authority OK
        p.check_redirect_authority(&orig, "https://registry.example.com/y")
            .unwrap();
    }

    // ── SEC-02 — same_fetch_authority (scheme + host + port) ────────────
    fn u(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn same_host_same_implicit_port_allowed() {
        assert!(same_fetch_authority(
            &u("https://a.example/x"),
            &u("https://a.example/y")
        ));
    }

    #[test]
    fn same_host_explicit_443_same_as_implicit_allowed() {
        // Explicit :443 must compare equal to the implicit https default.
        assert!(same_fetch_authority(
            &u("https://a.example/x"),
            &u("https://a.example:443/y")
        ));
    }

    #[test]
    fn same_host_different_port_rejected() {
        assert!(!same_fetch_authority(
            &u("https://a.example/x"),
            &u("https://a.example:8443/y")
        ));
    }

    #[test]
    fn https_to_http_same_host_rejected() {
        // Scheme downgrade is never same-authority.
        assert!(!same_fetch_authority(
            &u("https://a.example/x"),
            &u("http://a.example/y")
        ));
    }

    #[test]
    fn different_host_rejected() {
        assert!(!same_fetch_authority(
            &u("https://a.example/x"),
            &u("https://b.example/y")
        ));
    }

    #[test]
    fn check_redirect_authority_rejects_port_change() {
        let p = SsrfPolicy::default();
        let orig = u("https://registry.example.com/a");
        let err = p
            .check_redirect_authority(&orig, "https://registry.example.com:8443/b")
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    // ── SEC-01 — reject the ENTIRE resolution on any forbidden IP ───────
    #[cfg(feature = "client")]
    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[cfg(feature = "client")]
    #[test]
    fn mixed_public_private_dns_rejected_entirely() {
        let p = SsrfPolicy::default();
        let candidates = [sock("203.0.113.10:443"), sock("10.0.0.1:443")];
        assert!(reject_if_any_forbidden(&p, "evil.example", &candidates).is_err());
    }

    #[cfg(feature = "client")]
    #[test]
    fn mixed_public_loopback_rejected() {
        let p = SsrfPolicy::default();
        let candidates = [sock("198.51.100.1:443"), sock("127.0.0.1:443")];
        assert!(reject_if_any_forbidden(&p, "evil.example", &candidates).is_err());
    }

    #[cfg(feature = "client")]
    #[test]
    fn mixed_public_imds_rejected() {
        let p = SsrfPolicy::default();
        let candidates = [sock("198.51.100.1:443"), sock("169.254.169.254:443")];
        assert!(reject_if_any_forbidden(&p, "evil.example", &candidates).is_err());
    }

    #[cfg(feature = "client")]
    #[test]
    fn single_public_ip_allowed() {
        let p = SsrfPolicy::default();
        let candidates = [sock("203.0.113.10:443")];
        assert!(reject_if_any_forbidden(&p, "ok.example", &candidates).is_ok());
    }

    #[cfg(feature = "client")]
    #[test]
    fn all_public_ips_allowed() {
        let p = SsrfPolicy::default();
        let candidates = [sock("203.0.113.10:443"), sock("198.51.100.1:443")];
        assert!(reject_if_any_forbidden(&p, "ok.example", &candidates).is_ok());
    }

    #[test]
    fn allow_http_can_be_opted_into() {
        let p = SsrfPolicy {
            allow_http: true,
            ..SsrfPolicy::default()
        };
        assert!(p.check_url("http://registry.example.com").is_ok());
    }

    /// FEAT-07 — `pin_resolved_ip` resolves localhost (which always maps
    /// to a forbidden range) and rejects it. This proves the §7.6 path
    /// runs the same range filter as `check_safe_ip`, so an attacker
    /// cannot use a hostname that only resolves to private IPs to slip
    /// past the URL-time check by hostname.
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn pin_resolved_ip_rejects_loopback_hostname() {
        let p = SsrfPolicy::default();
        let err = p.pin_resolved_ip("localhost", 443).await.unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }
}
