pub mod document;
pub mod web;

pub use document::{AssertionMethodRef, DidDocument, VerificationMethod};
pub use web::{authority_to_did_web, did_web_to_authority, did_web_to_url};

#[cfg(feature = "client")]
pub use web::WebResolver;
