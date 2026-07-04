//! Criterion benchmarks for the ACDP hot paths.
//!
//! Groups:
//! - `signing`: Ed25519 and ECDSA-P256 sign + verify over the ASCII
//!   `"sha256:<hex>"` content-hash string (the real signature preimage).
//! - `jcs`: RFC 8785 canonicalization of a ~1 KB publish-request-like
//!   body and a body carrying a ~64 KB metadata object nested to depth 6.
//! - `content_hash`: the full §5.7 pipeline (exclusion-set strip → JCS →
//!   SHA-256 → `"sha256:<hex>"`) over the same two bodies.
//! - `ssrf`: `SsrfPolicy::default()` IP classification over a mixed batch
//!   of IPv4/IPv6 addresses (loopback, RFC 1918, IMDS, CGNAT, public,
//!   IPv4-mapped IPv6, NAT64, ULA, link-local, multicast).
//!
//! No network or file I/O happens inside any measured iteration.

use std::hint::black_box;
use std::net::IpAddr;

use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::{json, Value};

use acdp::crypto::hash::compute_content_hash;
use acdp::crypto::jcs::try_canonicalize_value;
use acdp::crypto::sign::{P256SigningKey, SigningKey};
use acdp::crypto::verify::{verify_ecdsa_p256, verify_ed25519};
use acdp::safe_http::SsrfPolicy;
use acdp::types::ContentHash;

/// The sig-001 golden-vector content hash — a representative signature
/// preimage (`"sha256:" + 64 lowercase hex chars`, 71 ASCII bytes).
const GOLDEN_HASH: &str = "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5";

// ─── Input construction (setup only, outside measured loops) ────────────────

/// A publish-request-like body of roughly 1 KB serialized.
fn small_body() -> Value {
    json!({
        "acdp_version": "0.1.0",
        "schema": "acdp.software.release.v1",
        "context_type": "software_release",
        "producer": "did:web:registry.example.com:agents:release-bot",
        "summary": "Release 4.2.1 of the payments service. \
                    Fixes a race in the ledger reconciliation job, upgrades \
                    the TLS stack, and adds idempotency keys to the refund \
                    endpoint. Rollback window is 48 hours from deploy.",
        "data": {
            "type": "embedded",
            "content": {
                "version": "4.2.1",
                "artifact": "registry.example.com/payments@sha256:9f2c1a7e",
                "changes": [
                    "fix: ledger reconciliation race under concurrent settle",
                    "chore: bump rustls to 0.23, prune legacy cipher suites",
                    "feat: idempotency keys on POST /refunds"
                ],
                "rollback": {"supported": true, "window_hours": 48},
                "environments": ["staging", "prod-eu", "prod-us"]
            }
        },
        "tags": ["payments", "release", "backend", "rust"],
        "visibility": "public",
        "version": 1,
        "timestamp": "2026-07-01T12:00:00.000Z",
        "expires_at": "2027-07-01T12:00:00.000Z",
        "metadata": {
            "build_id": "b-20260701-1200-4f9a",
            "ci_run": "https://ci.example.com/runs/188422",
            "commit": "d543c0a1b2c3d4e5f60718293a4b5c6d7e8f9012"
        }
    })
}

/// A JSON object with `fanout` keys per level, nested to `depth` levels;
/// leaves carry `leaf_len`-byte string values.
fn nested_object(depth: usize, fanout: usize, leaf_len: usize) -> Value {
    if depth == 0 {
        return Value::String("v".repeat(leaf_len));
    }
    let mut map = serde_json::Map::new();
    for i in 0..fanout {
        map.insert(
            format!("k{depth}_{i:03}"),
            nested_object(depth - 1, fanout, leaf_len),
        );
    }
    Value::Object(map)
}

/// The small body with `metadata` replaced by a ~64 KB object nested to
/// depth 6 (3^6 = 729 leaves, 70 B each, plus 1092 keys of structure —
/// ~64 KB serialized in canonical form).
fn large_body() -> Value {
    let mut body = small_body();
    body["metadata"] = nested_object(6, 3, 70);
    body
}

/// Mixed batch for SSRF classification: forbidden and allowed, v4 and v6.
fn ssrf_batch() -> Vec<IpAddr> {
    [
        "127.0.0.1",            // loopback v4
        "10.0.0.1",             // RFC 1918
        "172.16.5.5",           // RFC 1918
        "192.168.1.1",          // RFC 1918
        "169.254.169.254",      // link-local / IMDS
        "100.64.0.1",           // CGNAT
        "8.8.8.8",              // public v4
        "93.184.216.34",        // public v4
        "::1",                  // loopback v6
        "fe80::1",              // link-local v6
        "fc00::1",              // ULA
        "::ffff:10.0.0.1",      // IPv4-mapped private
        "::ffff:8.8.8.8",       // IPv4-mapped public
        "64:ff9b::808:808",     // NAT64 well-known prefix
        "2606:4700:4700::1111", // public v6
        "ff02::1",              // multicast v6
    ]
    .iter()
    .map(|s| s.parse().expect("static IP literal"))
    .collect()
}

// ─── Benches ─────────────────────────────────────────────────────────────────

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");
    let hash = ContentHash(GOLDEN_HASH.to_owned());

    // Ed25519 (mandatory algorithm).
    let ed_key = SigningKey::from_bytes(&[7u8; 32]);
    let ed_pub = ed_key.verifying_key_bytes();
    let ed_sig = ed_key.sign_content_hash(&hash);
    group.bench_function("ed25519_sign", |b| {
        b.iter(|| ed_key.sign_content_hash(black_box(&hash)))
    });
    group.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            verify_ed25519(
                black_box(&ed_pub),
                black_box(&ed_sig),
                black_box(GOLDEN_HASH),
            )
            .expect("valid signature")
        })
    });

    // ECDSA-P256 (registry algorithm `ecdsa-p256`, IEEE 1363 r‖s wire form).
    let p256_key = P256SigningKey::from_bytes(&[7u8; 32]).expect("valid P-256 seed");
    let p256_pub = p256_key.verifying_key_sec1();
    let p256_sig = p256_key.sign_content_hash(&hash);
    group.bench_function("ecdsa_p256_sign", |b| {
        b.iter(|| p256_key.sign_content_hash(black_box(&hash)))
    });
    group.bench_function("ecdsa_p256_verify", |b| {
        b.iter(|| {
            verify_ecdsa_p256(
                black_box(&p256_pub),
                black_box(&p256_sig),
                black_box(GOLDEN_HASH),
            )
            .expect("valid signature")
        })
    });

    group.finish();
}

fn bench_jcs(c: &mut Criterion) {
    let mut group = c.benchmark_group("jcs");
    let small = small_body();
    let large = large_body();

    group.bench_function("canonicalize_small_1kb", |b| {
        b.iter(|| try_canonicalize_value(black_box(&small)).expect("canonicalizable"))
    });
    group.bench_function("canonicalize_large_64kb", |b| {
        b.iter(|| try_canonicalize_value(black_box(&large)).expect("canonicalizable"))
    });

    group.finish();
}

fn bench_content_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_hash");
    let small = small_body();
    let large = large_body();

    group.bench_function("compute_small_1kb", |b| {
        b.iter(|| compute_content_hash(black_box(&small)).expect("hashable"))
    });
    group.bench_function("compute_large_64kb", |b| {
        b.iter(|| compute_content_hash(black_box(&large)).expect("hashable"))
    });

    group.finish();
}

fn bench_ssrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("ssrf");
    let policy = SsrfPolicy::default();
    let batch = ssrf_batch();

    group.bench_function("classify_ip_batch_16", |b| {
        b.iter(|| {
            let mut rejected = 0usize;
            for ip in &batch {
                if policy.classify_ip(black_box(*ip)).is_err() {
                    rejected += 1;
                }
            }
            black_box(rejected)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_signing,
    bench_jcs,
    bench_content_hash,
    bench_ssrf
);
criterion_main!(benches);
