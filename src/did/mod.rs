pub mod document;
pub mod key;
pub mod web;

pub use document::{AssertionMethodRef, DidDocument, VerificationMethod};
pub use key::{
    did_key_from_ed25519, did_key_from_p256_sec1, did_key_url, resolve_did_key,
    resolve_did_key_url, DidKeyMaterial,
};
pub use web::{authority_to_did_web, did_web_to_authority, did_web_to_url};

#[cfg(feature = "client")]
pub use web::WebResolver;
