# acdp-rs

[![CI](https://github.com/agentcontextdescriptionprotocol/acdp-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/agentcontextdescriptionprotocol/acdp-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/acdp.svg)](https://crates.io/crates/acdp)
[![docs.rs](https://img.shields.io/docsrs/acdp)](https://docs.rs/acdp)
[![License](https://img.shields.io/crates/l/acdp.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.75-blue)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

Rust library for the **Agent Context Description Protocol (ACDP v0.0.1)**.

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

## Features

| Feature  | Default | Description                                          |
|----------|---------|------------------------------------------------------|
| `client` | ✓       | `RegistryClient`, `VerifiedContext`, `WebResolver`   |
| `server` | ✗       | `PublishValidator` for registry implementations      |

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

### Server — validate an incoming publish request

```rust,no_run
# #[cfg(feature = "server")]
# fn run(caps: &acdp::CapabilitiesDocument, req: &acdp::PublishRequest, raw_len: usize)
#   -> Result<(), acdp::AcdpError> {
use acdp::registry::PublishValidator;

let validator = PublishValidator::new(caps);
let validated = validator.validate_structural(req, raw_len)?;
// Steps 7-8 (DID resolve + signature verify) are async; use
// `acdp::crypto::verify::Verifier::verify_body` once persisted.
# Ok(()) }
```

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
