pub mod document;
pub mod web;

pub use document::{AssertionMethodRef, DidDocument, VerificationMethod};
pub use web::did_web_to_url;

#[cfg(feature = "client")]
pub use web::WebResolver;
