//! Fuzz DID-document parsing and key extraction (`acdp-did`).
//!
//! This is the exact pipeline `WebResolver` runs on an untrusted HTTPS
//! response body: `serde_json` deserialize into `DidDocument`, then
//! fragment lookup / assertion-method authorization / public-key
//! extraction on the result. None of it may panic. The pure `did:web`
//! string helpers are exercised on the same bytes when they are UTF-8.
//!
//! Built without the `client` feature, so no reqwest/tokio — parsing and
//! key extraction only.

#![no_main]

use acdp_did::{authority_to_did_web, did_web_to_authority, did_web_to_url, DidDocument};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(doc) = serde_json::from_slice::<DidDocument>(data) {
        // A parsed document must re-serialize.
        serde_json::to_string(&doc).expect("re-serialization of parsed DidDocument failed");

        // Lookups WebResolver / Verifier perform on resolved documents.
        let _ = doc.find_by_fragment("key-1");
        let _ = doc.is_assertion_method(&doc.id);
        let _ = doc.is_assertion_method("#key-1");

        for vm in &doc.verification_methods {
            // Key extraction over attacker-controlled JWK / multibase data.
            let _ = vm.ed25519_public_key_bytes();
            let _ = vm.ecdsa_p256_public_key_sec1();
            let _ = vm.declared_algorithm();
            let _ = doc.find_by_fragment(&vm.id);
            let _ = doc.is_assertion_method(&vm.id);
        }
    }

    // did:web string parsing helpers (pure, no network).
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = did_web_to_url(s);
        let _ = did_web_to_authority(s);
        let _ = authority_to_did_web(s);
    }
});
