//! # acdp-client — consumer client for the Agent Context Distribution Protocol
//!
//! Implements the `acdp-consumer` profile: [`RegistryClient`]
//! (publish/retrieve/search/capabilities with RFC-aligned timeouts, body
//! caps, and same-authority redirect limits), [`VerifiedContext`]
//! (one-shot fetch + verify), [`CrossRegistryResolver`] (RFC-ACDP-0006
//! §4.1), and DataRef fetching with hash verification.

pub mod cross_registry;
pub mod data_ref;
pub mod receipt;
pub mod registry;
pub mod verified;

pub use cross_registry::{CrossRegistryResolver, ResolverOptions};
pub use data_ref::{
    fetch_and_verify_data_ref, DataRefFetcher, HttpsDataRefFetcher, DEFAULT_MAX_BYTES,
};
pub use receipt::{verify_lineage_head_receipt_value, verify_receipt_value};
pub use registry::RegistryClient;
pub use verified::{
    HistoricalKeyPolicy, KeyAuthorization, LineageHeadPolicy, ReceiptPolicy, VerificationPolicy,
    VerificationReport, VerifiedContext,
};
