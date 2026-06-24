//! # acdp-server — registry-side building blocks for the Agent Context Distribution Protocol
//!
//! Server-side primitives consumed by separate `acdp-registry-*` crates:
//! [`registry::PublishValidator`], [`registry::RegistryServer`],
//! [`registry::InMemoryStore`], rate-limiting traits, the shared SSRF
//! policy re-export, and cursor [`pagination`]. This crate does not host a
//! real HTTP server.

pub mod pagination;
pub mod registry;
