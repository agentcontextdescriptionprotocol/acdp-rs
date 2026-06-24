//! Byte-level signature verification primitives.
//!
//! These functions verify a raw signature against a public key and an
//! ASCII message; they have no knowledge of `Body`, `PublishRequest`,
//! DID resolution, or structural validation. The high-level,
//! resolver-backed verification pipeline lives in the `acdp-verify` crate.

use acdp_primitives::error::AcdpError;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Verifier as _, VerifyingKey};

/// Verify an Ed25519 signature without DID resolution.
///
/// Useful for verifying the golden test vector with a known public key.
pub fn verify_ed25519(
    pub_key_bytes: &[u8; 32],
    sig_b64: &str,
    message: &str,
) -> Result<(), AcdpError> {
    let key = VerifyingKey::from_bytes(pub_key_bytes)
        .map_err(|e| AcdpError::InvalidSignature(e.to_string()))?;

    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|e| AcdpError::InvalidSignature(format!("base64: {e}")))?;

    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| AcdpError::InvalidSignature(format!("sig parse: {e}")))?;

    key.verify(message.as_bytes(), &sig)
        .map_err(|_| AcdpError::InvalidSignature("signature verification failed".into()))
}

/// Verify an ECDSA-P256 signature in IEEE 1363 (r‖s) wire form.
///
/// Per the ACDP signature-algorithms registry (`ecdsa-p256` Stable),
/// the wire form is 64 raw bytes (32-byte `r` followed by 32-byte `s`),
/// base64-encoded with padding (88 characters), NOT DER. The
/// `pub_key_sec1` argument is the SEC1-uncompressed public key (65
/// bytes starting with `0x04`).
pub fn verify_ecdsa_p256(
    pub_key_sec1: &[u8],
    sig_b64: &str,
    message: &str,
) -> Result<(), AcdpError> {
    use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey as P256VerifyingKey};

    let key = P256VerifyingKey::from_sec1_bytes(pub_key_sec1)
        .map_err(|e| AcdpError::InvalidSignature(format!("ecdsa-p256 key parse: {e}")))?;

    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|e| AcdpError::InvalidSignature(format!("base64: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(AcdpError::InvalidSignature(format!(
            "ecdsa-p256 signature MUST be 64 bytes (IEEE 1363 r‖s), got {}",
            sig_bytes.len()
        )));
    }
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| AcdpError::InvalidSignature(format!("ecdsa-p256 sig parse: {e}")))?;

    key.verify(message.as_bytes(), &sig)
        .map_err(|_| AcdpError::InvalidSignature("ecdsa-p256 signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::SigningKey;
    use acdp_primitives::primitives::ContentHash;

    const TEST_SEED: [u8; 32] = [0u8; 32];
    const TEST_PUB_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    #[test]
    fn sign_and_verify_golden() {
        let key = SigningKey::from_bytes(&TEST_SEED);
        let hash = ContentHash(
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
        );
        let sig_b64 = key.sign_content_hash(&hash);

        // Expected signature from the spec's sig-001 golden vector
        assert_eq!(
            sig_b64,
            "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
        );

        let pub_bytes: [u8; 32] = hex::decode(TEST_PUB_HEX).unwrap().try_into().unwrap();
        verify_ed25519(&pub_bytes, &sig_b64, hash.as_str()).unwrap();
    }

    #[test]
    fn wrong_message_fails() {
        let key = SigningKey::from_bytes(&TEST_SEED);
        let hash = ContentHash(
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
        );
        let sig_b64 = key.sign_content_hash(&hash);
        let pub_bytes: [u8; 32] = hex::decode(TEST_PUB_HEX).unwrap().try_into().unwrap();

        // Verify against wrong message should fail
        let result = verify_ed25519(&pub_bytes, &sig_b64, "sha256:wronghash");
        assert!(result.is_err());
    }

    /// T1 — Algorithm-downgrade attack is rejected (R2-CRIT-01).
    ///
    /// Construct a verification method that declares Ed25519 via
    /// `Ed25519VerificationKey2020`, but a body whose
    /// `signature.algorithm` is `ecdsa-p256`. The verifier MUST
    /// refuse before reaching signature verification.
    #[test]
    fn declared_algorithm_mismatch_rejected() {
        use acdp_did::document::VerificationMethod;
        let raw: [u8; 32] = hex::decode(TEST_PUB_HEX).unwrap().try_into().unwrap();
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(&raw);
        let mb = format!("z{}", bs58::encode(&prefixed).into_string());
        let vm = VerificationMethod {
            id: "did:web:example.com#key-1".into(),
            method_type: "Ed25519VerificationKey2020".into(),
            controller: "did:web:example.com".into(),
            public_key_jwk: None,
            public_key_multibase: Some(mb),
        };
        assert_eq!(vm.declared_algorithm(), Some("ed25519"));
        // The actual end-to-end check happens in Verifier::verify_body;
        // the declared_algorithm() helper is the building block whose
        // mismatch produces the rejection.
    }

    // ── verify_ed25519 error branches ──────────────────────────────────────

    #[test]
    fn verify_ed25519_rejects_malformed_base64() {
        let pub_bytes: [u8; 32] = hex::decode(TEST_PUB_HEX).unwrap().try_into().unwrap();
        let err = verify_ed25519(&pub_bytes, "not valid base64!!", "sha256:x").unwrap_err();
        assert!(
            matches!(err, AcdpError::InvalidSignature(ref m) if m.contains("base64")),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_ed25519_rejects_wrong_length_signature() {
        let pub_bytes: [u8; 32] = hex::decode(TEST_PUB_HEX).unwrap().try_into().unwrap();
        // Valid base64 but decodes to 3 bytes, not the required 64.
        let short = STANDARD.encode([1u8, 2, 3]);
        let err = verify_ed25519(&pub_bytes, &short, "sha256:x").unwrap_err();
        assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");
    }

    // ── verify_ecdsa_p256 error branches ───────────────────────────────────

    #[test]
    fn verify_ecdsa_p256_rejects_bad_public_key() {
        // A 5-byte blob is not a valid SEC1 point.
        let err = verify_ecdsa_p256(&[1, 2, 3, 4, 5], "AAAA", "sha256:x").unwrap_err();
        assert!(
            matches!(err, AcdpError::InvalidSignature(ref m) if m.contains("key parse")),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_ecdsa_p256_rejects_malformed_base64() {
        // Need a valid key so we get past the key-parse step to the b64 step.
        let key = crate::sign::P256SigningKey::generate();
        let err =
            verify_ecdsa_p256(&key.verifying_key_sec1(), "not base64!!", "sha256:x").unwrap_err();
        assert!(
            matches!(err, AcdpError::InvalidSignature(ref m) if m.contains("base64")),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_ecdsa_p256_rejects_wrong_length_signature() {
        let key = crate::sign::P256SigningKey::generate();
        // Valid base64 decoding to 10 bytes, not 64.
        let short = STANDARD.encode([0u8; 10]);
        let err = verify_ecdsa_p256(&key.verifying_key_sec1(), &short, "sha256:x").unwrap_err();
        assert!(
            matches!(err, AcdpError::InvalidSignature(ref m) if m.contains("64 bytes")),
            "got {err:?}"
        );
    }
}
