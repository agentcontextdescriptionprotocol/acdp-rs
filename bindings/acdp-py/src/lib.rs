//! ACDP Python SDK.
//!
//! Thin PyO3 binding over the [`acdp`] crate. Every method that crosses
//! the FFI boundary accepts and returns JSON strings (HTTP request /
//! response bodies), so Python agent code never sees a Rust type.
//!
//! Crypto runs in Rust (key generation, JCS + SHA-256 hashing, Ed25519
//! signing and verification). HTTP is intentionally left to the host
//! language — pair this binding with `httpx` / `requests` for transport.
//!
//! `#![forbid(unsafe_code)]` is intentionally omitted: the PyO3 export
//! macros expand to `unsafe` glue. The underlying `acdp` crate keeps
//! the forbid attribute.

// The PyO3 `#[pymethods]` macro expands to a result conversion that
// clippy's `useless_conversion` lint flags against the return-type span
// — a macro-expansion false positive, not our code.
#![allow(clippy::useless_conversion)]

mod helpers;
mod producer;
mod verifier;

use pyo3::prelude::*;

/// The `acdp` Python module — exposes `AcdpProducer` and `AcdpVerifier`.
#[pymodule]
fn acdp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<producer::PyAcdpProducer>()?;
    m.add_class::<verifier::PyAcdpVerifier>()?;
    Ok(())
}
