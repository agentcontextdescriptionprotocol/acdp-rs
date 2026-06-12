pub mod cross_registry;
pub mod data_ref;
pub mod receipt;
pub mod registry;
pub mod verified;

pub use cross_registry::{CrossRegistryResolver, ResolverOptions};
pub use data_ref::{
    fetch_and_verify_data_ref, DataRefFetcher, HttpsDataRefFetcher, DEFAULT_MAX_BYTES,
};
pub use receipt::verify_receipt_value;
pub use registry::RegistryClient;
pub use verified::{
    HistoricalKeyPolicy, KeyAuthorization, ReceiptPolicy, VerificationPolicy, VerificationReport,
    VerifiedContext,
};
