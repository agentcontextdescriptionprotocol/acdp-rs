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
//!   resolves a hostname once, applies the same range filter to the
//!   returned IPs, and returns a [`SocketAddr`] that the caller pins
//!   into `reqwest::Client::builder().resolve(host, addr)` — so the
//!   filter and the connection use the same IP, defeating a hostile
//!   DNS server flipping the answer between the two.

#[cfg(feature = "client")]
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::AcdpError;

// Re-exported from [`crate::limits`] for back-compat.
pub use crate::limits::{MAX_CONTEXT_BYTES, MAX_METADATA_BYTES, MAX_REDIRECTS};

/// SSRF policy applied to outbound HTTP requests.
#[derive(Debug, Clone)]
pub struct SsrfPolicy {
    /// If true, reject IP literals in the URL (forces DNS resolution).
    pub reject_ip_literals: bool,
    /// If false, only `https://` URLs are accepted. Default `false`.
    pub allow_http: bool,
}

impl Default for SsrfPolicy {
    fn default() -> Self {
        Self {
            reject_ip_literals: true,
            allow_http: false,
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
                check_safe_ip(IpAddr::V4(v4))?;
            }
            url::Host::Ipv6(v6) => {
                if self.reject_ip_literals {
                    return Err(AcdpError::SchemaViolation(format!(
                        "SSRF policy: IPv6 literal '{v6}' not permitted; use a hostname"
                    )));
                }
                check_safe_ip(IpAddr::V6(v6))?;
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
    pub fn check_resolved_ip(&self, ip: IpAddr) -> Result<(), AcdpError> {
        check_safe_ip(ip)
    }

    /// DNS rebinding protection per RFC-ACDP-0006 §7.6.
    ///
    /// Resolves `host:port`, applies the policy filter against every
    /// returned address, and returns the first [`SocketAddr`] that
    /// passes. The caller MUST pin this exact address into the HTTP
    /// client via `reqwest::Client::builder().resolve(host, addr)` —
    /// otherwise a hostile authoritative DNS could flip the answer
    /// between the filter check and the connect, bypassing §7.1.
    ///
    /// Returns [`AcdpError::Http`] when DNS returns no answers and
    /// [`AcdpError::SchemaViolation`] when every answer is in a
    /// forbidden range.
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
        let mut last_err: Option<AcdpError> = None;
        for addr in &candidates {
            match check_safe_ip(addr.ip()) {
                Ok(()) => return Ok(*addr),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            AcdpError::SchemaViolation(format!(
                "SSRF policy: no safe IP for '{host}' across {} candidate(s)",
                candidates.len()
            ))
        }))
    }

    /// Per §7.5: a redirect is permitted only if it stays within the same
    /// authority as the originating request.
    pub fn check_redirect_authority(
        &self,
        original_authority: &str,
        redirect_url: &str,
    ) -> Result<(), AcdpError> {
        let parsed = url::Url::parse(redirect_url)
            .map_err(|e| AcdpError::SchemaViolation(format!("invalid redirect URL: {e}")))?;
        let new_authority = parsed.host_str().unwrap_or("");
        if new_authority != original_authority {
            return Err(AcdpError::SchemaViolation(format!(
                "SSRF policy: cross-authority redirect rejected: {original_authority} → {new_authority}"
            )));
        }
        Ok(())
    }
}

/// Reject the danger ranges enumerated by RFC-ACDP-0006 §7.1.
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
        let err = p
            .check_redirect_authority("registry.example.com", "https://attacker.com/x")
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
        // Same authority OK
        p.check_redirect_authority("registry.example.com", "https://registry.example.com/y")
            .unwrap();
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
