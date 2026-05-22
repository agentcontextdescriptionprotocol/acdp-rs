# acdp-rs

[![CI](https://github.com/agentcontextdescriptionprotocol/acdp-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/agentcontextdescriptionprotocol/acdp-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/acdp.svg)](https://crates.io/crates/acdp)
[![docs.rs](https://img.shields.io/docsrs/acdp)](https://docs.rs/acdp)
[![License](https://img.shields.io/crates/l/acdp.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.86-blue)](https://blog.rust-lang.org/2025/04/03/Rust-1.86.0.html)

Rust library for the **Agent Context Description Protocol (ACDP v0.1.0)**.

ACDP lets agents publish immutable, producer-signed context descriptors,
retrieve and verify them locally, discover them by keyword, and follow signed
`acdp://` references across registries.

> Spec: [agentcontextdescriptionprotocol/spec](https://github.com/agentcontextdescriptionprotocol)
> (RFC-ACDP-0001/0002/0003/0007).

## Install

```bash
cargo add acdp                          # client (default)
cargo add acdp --no-default-features    # types/crypto only, no HTTP
cargo add acdp --features server        # add the publish validator
```

## Conformance

This crate implements the **`acdp-consumer`** profile (RFC-ACDP-0001 §9.1):

- Verifies producer signatures end-to-end on every retrieved context.
- Resolves cross-registry `acdp://` references with cycle detection,
  depth caps, SSRF defenses, and registry-DID web-binding verification.
- Applies visibility rules client-side and tolerates unknown fields for
  forward compatibility.

The library also ships the building blocks (`PublishValidator`,
`SsrfPolicy`, `validate_publish_request`, `compute_embedded_hash`) that
registry implementers compose into `acdp-registry-core` /
`acdp-registry-discovery` / `acdp-registry-federated` services. See
`acdp::profile` for the typed profile vocabulary.

## Glossary

- **Body** — the immutable JSON object representing a context.
- **ProducerContent** — the Body with the §5.7 exclusion set removed
  (everything except the producer-controlled fields). The producer
  signs ProducerContent; the SHA-256 of its JCS-canonicalized bytes
  is the body's `content_hash`.
- **RegistryState** — the mutable, registry-derived state (`status` in
  v0.1.0) returned alongside the Body on retrieval.
- **Lineage** — a chain of contexts representing successive versions of
  the same logical work, identified by a stable `lineage_id` derived
  from the v1 ctx_id.
- **JCS** — JSON Canonicalization Scheme (RFC 8785). The deterministic
  serialization used as the SHA-256 input for `content_hash`.
- **DID** — Decentralized Identifier (W3C). v0.1.0 producers MUST use
  `did:web` so their keys can be resolved over HTTPS.

## Features

| Feature   | Default | Description                                                                  |
|-----------|---------|------------------------------------------------------------------------------|
| `client`  | ✓       | `RegistryClient`, `VerifiedContext`, `WebResolver`, `CrossRegistryResolver`  |
| `server`  | ✗       | `PublishValidator` for registry implementations                              |
| `tracing` | ✗       | `#[instrument]` spans on async ops; pulls in `tracing` (no subscriber)       |

## Security defaults

The library applies these defenses out of the box (RFC-ACDP-0006 §7,
RFC-ACDP-0008):

- **HTTPS-only** for all outbound requests; HTTP is rejected.
- **IP-literal rejection** in `SsrfPolicy` (forces DNS resolution).
- **Private-range blocking**: RFC 1918, loopback, link-local,
  multicast, IMDS (`169.254.169.254`), IPv6 equivalents.
- **Response-size caps**: 1 MB for context retrievals, 64 KB for
  capabilities and DID documents.
- **Redirect cap**: max 3 follows, same-authority only.
- **Algorithm-downgrade rejection**: signatures are checked against
  the algorithm declared by the resolved DID verification method.
- **Ed25519 mandatory** (RFC-ACDP-0001 §5.10).

DNS-rebinding pin (§7.6) is documented in
`plans/defered/README.md` as a follow-up.

## Quick start

### Producer — build and sign a request

```rust
use acdp::{
    crypto::SigningKey,
    producer::Producer,
    types::{AgentDid, ContextType, Visibility},
};

let seed = [/* your 32-byte key seed */ 0u8; 32];
let key  = SigningKey::from_bytes(&seed);

let producer = Producer::new(
    key,
    AgentDid::new("did:web:agents.example.com:my-agent"),
    "did:web:agents.example.com:my-agent#key-1",
);

let req = producer
    .publish_request()
    .title("Q1 2026 revenue snapshot")
    .context_type(ContextType::DataSnapshot)
    .visibility(Visibility::Public)
    .build()
    .expect("build failed");

// req.content_hash and req.signature are computed automatically
println!("content_hash: {}", req.content_hash);
```

#### `acdp_version` field

The builder omits `acdp_version` by default. Conformant consumers treat an absent
field as `"0.1.0"` (RFC-ACDP-0001 §6), so this is safe. To emit it explicitly:

```rust,ignore
builder.acdp_version(acdp::ACDP_VERSION) // adds "acdp_version": "0.1.0" to the body
```

**Note:** absent and explicit `"0.1.0"` are semantically identical but produce
**different `content_hash` values** (the JCS byte sequences differ). Pick one and
stay consistent within a lineage. The `sig-001` golden vector was signed without
the field; using the omission default keeps round-trip tests byte-stable.

### Consumer — retrieve and verify

```rust,no_run
# #[cfg(feature = "client")]
# async fn run() -> Result<(), acdp::AcdpError> {
use acdp::{
    client::{RegistryClient, VerifiedContext},
    did::WebResolver,
    types::CtxId,
};

let client   = RegistryClient::new("https://registry.example.com")?;
let resolver = WebResolver::new();
let ctx_id   = CtxId("acdp://registry.example.com/…".into());

// Fetches, recomputes hash, resolves DID, verifies signature
let ctx = VerifiedContext::fetch(&client, &resolver, &ctx_id).await?;
println!("title: {}", ctx.body().title);
println!("status: {:?}", ctx.registry_state().status);
# Ok(()) }
```

### Server — verify and publish a context (RFC-ACDP-0003 §2.1)

```rust,no_run
# #[cfg(feature = "server")]
# async fn run(
#     server: &acdp::registry::RegistryServer<acdp::registry::InMemoryStore>,
#     resolver: &acdp::did::WebResolver,
#     req: &acdp::PublishRequest,
# ) -> Result<acdp::types::PublishResponse, acdp::AcdpError> {
// `publish_verified` runs the full §2.1 pipeline: schema validation →
// hash recomputation → DID resolution → signature verification → and
// only then assigns a `ctx_id` and persists. This is the ONLY
// conformant server path — never persist before signature verification.
let response = server.publish_verified(req, None, resolver).await?;
# Ok(response) }
```

> `RegistryServer::publish_unverified_for_tests` is provided for unit tests
> that cannot run a live DID resolver. It MUST NOT be used in production —
> it skips DID resolution and signature verification, which is a protocol
> violation (RFC-ACDP-0003 §2.1).

## Cryptographic design

The library implements three protocol-critical operations exactly:

| Operation             | Spec reference        | Rust impl                                     |
|-----------------------|-----------------------|-----------------------------------------------|
| JCS canonicalization  | RFC 8785              | `src/crypto/jcs.rs` (inline, handles `-0.0`)  |
| `content_hash`        | RFC-ACDP-0001 §5.7    | `src/crypto/hash.rs`                          |
| Ed25519 sign/verify   | RFC-ACDP-0001 §5.8/11 | `src/crypto/{sign,verify}.rs`                 |

The signature input is the ASCII bytes of the full `"sha256:<hex>"` string —
**not** the raw 32-byte digest. See `src/crypto/sign.rs` for details.

## Examples

```bash
cargo run --example producer                       # build a signed request
cargo run --example consumer --features client     # verify the golden vector
```

## Testing

```bash
cargo test --all-features                          # full suite
cargo test --no-default-features                   # core (no HTTP)
```

The suite includes:
- Spec golden vectors (`tests/golden_vector.rs` — `sig-001`, `can-001`).
- Property tests for JCS canonicalization (`proptest`).
- HTTP-mocked tests for `RegistryClient` and `WebResolver` (`wiremock`).
- Unit tests in every module.

## Building docs

```bash
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --all-features --no-deps --open
```

## Dependencies

| Crate            | Purpose                                          |
|------------------|--------------------------------------------------|
| `ed25519-dalek`  | Ed25519 signing and verification                 |
| `sha2`           | SHA-256                                          |
| `serde`/`serde_json` | JSON                                         |
| `reqwest`/`rustls` | HTTPS (client feature, no OpenSSL)             |
| `zeroize`        | zeroes signing-key bytes on drop                 |

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the dev workflow and quality bars.
Security issues should follow [SECURITY.md](./SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE) or
[MIT license](https://opensource.org/license/mit/) at your option.
