//! Fuzz the serde wire types: arbitrary bytes must never panic the
//! deserializers, and anything that parses must re-serialize.
//!
//! Covers the request/response shapes a registry or consumer feeds
//! untrusted bytes into:
//! - `PublishRequest` / `PublishResponse` (`POST /contexts`)
//! - `FullContext` / `Body` (retrieval shape)
//! - `CapabilitiesDocument` (`GET /.well-known/acdp.json`)
//! - `SearchResponse`
//! - `WireError` (the RFC-ACDP-0007 §5 error envelope; canonical path
//!   `acdp_types::WireError`, defined in acdp-primitives)

#![no_main]

use libfuzzer_sys::fuzz_target;

fn parse_then_reserialize<T>(data: &[u8])
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    if let Ok(parsed) = serde_json::from_slice::<T>(data) {
        // A value accepted off the wire must always serialize back.
        serde_json::to_string(&parsed)
            .expect("re-serialization of a successfully parsed wire type failed");
    }
}

fuzz_target!(|data: &[u8]| {
    parse_then_reserialize::<acdp_types::PublishRequest>(data);
    parse_then_reserialize::<acdp_types::PublishResponse>(data);
    parse_then_reserialize::<acdp_types::FullContext>(data);
    parse_then_reserialize::<acdp_types::Body>(data);
    parse_then_reserialize::<acdp_types::CapabilitiesDocument>(data);
    parse_then_reserialize::<acdp_types::SearchResponse>(data);
    parse_then_reserialize::<acdp_types::WireError>(data);
    parse_then_reserialize::<acdp_types::WireErrorBody>(data);
});
