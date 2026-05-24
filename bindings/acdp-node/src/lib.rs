//! ACDP Node.js SDK.
//!
//! Thin NAPI-rs binding over the [`acdp`] crate. Every method that
//! crosses the FFI boundary accepts and returns JSON strings (HTTP
//! request / response bodies), so JS code never sees a Rust type.
//!
//! Crypto runs in Rust (key generation, JCS + SHA-256 hashing, Ed25519
//! signing and verification). HTTP is intentionally left to the host
//! language — pair this binding with `fetch` / `undici` for transport.
//!
//! `#![forbid(unsafe_code)]` is intentionally omitted: the NAPI-rs
//! export macros expand to `unsafe` glue. The underlying `acdp` crate
//! keeps the forbid attribute.

mod helpers;
mod producer;
mod verifier;
