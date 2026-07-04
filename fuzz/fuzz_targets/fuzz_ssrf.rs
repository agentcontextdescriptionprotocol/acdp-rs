//! Fuzz the SSRF policy (`acdp-safe-http`, RFC-ACDP-0006 §7).
//!
//! Exercises URL / IP / redirect classification with arbitrary hostnames,
//! paths, ports, and IP octets under both the default policy and
//! fuzzer-chosen `allow_http` / `reject_ip_literals` knobs
//! (`allow_loopback_resolved` stays `false`: it is the documented
//! test-only escape hatch, so loopback invariants below assume it off).
//!
//! Hard invariants, asserted on every run:
//! - no classification path panics;
//! - the IMDS endpoint `169.254.169.254` and loopback `127.0.0.1` are
//!   NEVER classified safe, whether they appear as resolved IPs, as
//!   IPv4-mapped IPv6, or as URL literals.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use acdp_safe_http::{same_fetch_authority, SsrfPolicy};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const IMDS: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

#[derive(Arbitrary, Debug)]
struct Input {
    host: String,
    path: String,
    v4: [u8; 4],
    v6: [u16; 8],
    port: u16,
    allow_http: bool,
    reject_ip_literals: bool,
}

fuzz_target!(|input: Input| {
    let default_policy = SsrfPolicy::default();
    let fuzz_policy = SsrfPolicy {
        allow_http: input.allow_http,
        reject_ip_literals: input.reject_ip_literals,
        ..SsrfPolicy::default()
    };

    // ── Hard invariants: IMDS and loopback are never safe ──────────────
    for policy in [&default_policy, &fuzz_policy] {
        assert!(
            policy.classify_ip(IpAddr::V4(IMDS)).is_err(),
            "169.254.169.254 classified safe"
        );
        assert!(
            policy.classify_ip(IpAddr::V4(LOOPBACK)).is_err(),
            "127.0.0.1 classified safe"
        );
        assert!(
            policy
                .classify_ip(IpAddr::V6(IMDS.to_ipv6_mapped()))
                .is_err(),
            "IPv4-mapped IMDS classified safe"
        );
        assert!(
            policy
                .classify_ip(IpAddr::V6(LOOPBACK.to_ipv6_mapped()))
                .is_err(),
            "IPv4-mapped loopback classified safe"
        );
        assert!(
            policy
                .classify_url("https://169.254.169.254/latest/meta-data/")
                .is_err(),
            "IMDS URL literal classified safe"
        );
        assert!(
            policy.classify_url("https://127.0.0.1/").is_err(),
            "loopback URL literal classified safe"
        );
    }

    // ── Arbitrary IPs: must not panic; re-assert when they hit the
    //    forbidden constants ───────────────────────────────────────────
    let v4 = Ipv4Addr::from(input.v4);
    let [a, b, c, d, e, f, g, h] = input.v6;
    let v6 = Ipv6Addr::new(a, b, c, d, e, f, g, h);

    let v4_result = default_policy.classify_ip(IpAddr::V4(v4));
    let _ = default_policy.classify_ip(IpAddr::V6(v6));
    let _ = default_policy.classify_ip(IpAddr::V6(v4.to_ipv6_mapped()));
    let _ = fuzz_policy.classify_ip(IpAddr::V4(v4));
    let _ = fuzz_policy.classify_ip(IpAddr::V6(v6));

    if v4 == IMDS || v4.is_loopback() {
        assert!(v4_result.is_err(), "{v4} classified safe by default policy");
    }

    // ── Arbitrary URL authorities: classification must not panic ───────
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{}:{}/{}", input.host, input.port, input.path);
        let _ = default_policy.classify_url(&url);
        let _ = fuzz_policy.classify_url(&url);
        // A self-redirect must not panic either.
        let _ = default_policy.classify_redirect(&url, &url);
    }
    // IP-literal spellings of the arbitrary IPs.
    let _ = default_policy.classify_url(&format!("https://{v4}/{}", input.path));
    let _ = default_policy.classify_url(&format!("https://[{v6}]:{}/", input.port));

    // ── Redirect / authority helpers ────────────────────────────────────
    let from = format!("https://{}/{}", input.host, input.path);
    let to = format!("https://{}:{}/redirected", input.host, input.port);
    let _ = default_policy.classify_redirect(&from, &to);
    let _ = fuzz_policy.classify_redirect(&from, &to);
    if let (Ok(u1), Ok(u2)) = (url::Url::parse(&from), url::Url::parse(&to)) {
        let _ = same_fetch_authority(&u1, &u2);
        let _ = same_fetch_authority(&u1, &u1);
    }
});
