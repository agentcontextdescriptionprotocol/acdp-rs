//! End-to-end body verification — RFC-ACDP-0001 §5.11 (7-step algorithm).

use crate::error::AcdpError;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Verifier as _, VerifyingKey};

#[cfg(feature = "client")]
use {
    super::hash::verify_content_hash,
    crate::did::web::WebResolver,
    crate::types::{
        body::{Body, Signature},
        primitives::{AgentDid, ContentHash},
        publish::PublishRequest,
    },
};

/// Stateless verifier.  Requires a DID resolver to fetch producer keys.
#[cfg(feature = "client")]
pub struct Verifier<'a> {
    resolver: &'a WebResolver,
}

#[cfg(feature = "client")]
impl<'a> Verifier<'a> {
    pub fn new(resolver: &'a WebResolver) -> Self {
        Self { resolver }
    }

    /// Full end-to-end verification per RFC-ACDP-0001 §5.11.
    ///
    /// Steps:
    ///  1. (Implicit) Check `key_id` has a `#fragment`.
    ///  2. Verify `key_id` DID portion equals `body.agent_id`.
    ///  3. Resolve the DID document.
    ///  4. Find the verification method by fragment.
    ///  5. Check `assertionMethod` authorization.
    ///  6. Extract the Ed25519 public key.
    ///  7. Verify the signature over the content_hash ASCII bytes.
    ///
    ///  (Hash recomputation is step 0, performed first.)
    pub async fn verify_body(&self, body: &Body) -> Result<(), AcdpError> {
        // Step -1 (BUG-04): structural / runtime validation. A body may be
        // cryptographically correct but protocol-invalid (non-did:web
        // producer, inverted data_period, oversize metadata). Catch those
        // before paying the SHA-256 + DID resolution cost.
        crate::validation::validate_body(body)?;

        self.verify_body_signed(body).await
    }

    /// Verify only the hash recomputation + DID resolution + signature
    /// envelope, assuming structural validation has already been done by
    /// the caller. Use when you want to separate structural failures
    /// from cryptographic ones — e.g.
    /// [`crate::client::VerifiedContext::fetch_report`] runs the
    /// structural part itself and records per-`DataRef` outcomes
    /// individually.
    pub async fn verify_body_signed(&self, body: &Body) -> Result<(), AcdpError> {
        // Step 0: recompute content_hash over ProducerContent
        let body_val = serde_json::to_value(body)?;
        verify_content_hash(&body_val, &body.content_hash)?;

        // Steps 1–7: shared signature-envelope verification.
        verify_signature_envelope(
            &body.agent_id,
            &body.signature,
            &body.content_hash,
            self.resolver,
        )
        .await
    }
}

/// Verify the producer signature on a [`PublishRequest`] per RFC-ACDP-0003
/// §2.1 steps 7–8.
///
/// Assumes structural validation and `content_hash` recomputation have
/// already been performed (e.g. by [`crate::registry::PublishValidator::validate_post_schema`]).
/// Executes only the DID resolution + signature verification steps shared
/// with [`Verifier::verify_body`].
///
/// Used by [`crate::registry::RegistryServer::publish_verified`] to fulfill
/// the §2.1 publish algorithm before persistence; consumers wanting end-to-end
/// verification on retrieval should prefer
/// [`crate::client::VerifiedContext::fetch`] which calls [`Verifier::verify_body`].
#[cfg(feature = "client")]
pub async fn verify_publish_request_signature(
    req: &PublishRequest,
    resolver: &WebResolver,
) -> Result<(), AcdpError> {
    verify_signature_envelope(&req.agent_id, &req.signature, &req.content_hash, resolver).await
}

/// Steps 1–7 of RFC-ACDP-0001 §5.11 — the part of body verification that
/// operates only on the signature envelope and is identical for stored
/// `Body` values and incoming `PublishRequest` values. Caller is responsible
/// for hash recomputation (step 0).
#[cfg(feature = "client")]
async fn verify_signature_envelope(
    agent_id: &AgentDid,
    signature: &Signature,
    content_hash: &ContentHash,
    resolver: &WebResolver,
) -> Result<(), AcdpError> {
    // Step 1: parse key_id — must contain a '#' fragment
    let key_id = &signature.key_id;
    let (did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::KeyResolution(format!("signature.key_id '{key_id}' has no '#fragment'"))
    })?;

    // Step 1.5: `key_id` DID portion MUST be did:web for v0.0.1
    // (RFC-ACDP-0001 §5.4). A key_id pointing to e.g. did:key would mean
    // the resolver path could not even find the key.
    if !did_part.starts_with("did:web:") {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "v0.0.1 signatures require did:web key_id; got '{did_part}'"
        )));
    }

    // Step 2: DID portion MUST equal agent_id
    if did_part != agent_id.as_str() {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "key_id DID '{did_part}' ≠ agent_id '{agent_id}'"
        )));
    }

    // Step 3: resolve DID document
    let doc = resolver.resolve(did_part).await?;

    // Step 4: find verification method by fragment
    let method = doc.find_by_fragment(fragment).ok_or_else(|| {
        AcdpError::KeyResolution(format!(
            "no verification method with fragment '#{fragment}'"
        ))
    })?;

    // Step 5: assertionMethod authorization
    if !doc.is_assertion_method(&method.id) {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "'{}' is not in assertionMethod",
            method.id
        )));
    }

    // Step 5.5: algorithm-downgrade rejection (RFC-ACDP-0008 §3.9 +
    // RFC-ACDP-0001 §5.11 step 6). When the verification method declares
    // an algorithm via its `type` (or `publicKeyJwk` params), it MUST equal
    // `signature.algorithm`. Otherwise an attacker could route an Ed25519
    // key through a verifier that thinks it's checking some other algorithm.
    if let Some(declared) = method.declared_algorithm() {
        if declared != signature.algorithm {
            return Err(AcdpError::InvalidSignature(format!(
                "signature.algorithm '{}' does not match verification method type \
                 (resolved key declares '{declared}')",
                signature.algorithm
            )));
        }
    }

    // Steps 6 + 7: dispatch by algorithm.
    match signature.algorithm.as_str() {
        "ed25519" => {
            let pub_bytes = method.ed25519_public_key_bytes()?;
            verify_ed25519(&pub_bytes, &signature.value, content_hash.as_str())
        }
        "ecdsa-p256" => {
            let pub_sec1 = method.ecdsa_p256_public_key_sec1()?;
            verify_ecdsa_p256(&pub_sec1, &signature.value, content_hash.as_str())
        }
        other => Err(AcdpError::UnsupportedAlgorithm(format!(
            "verifier does not support signature algorithm '{other}'"
        ))),
    }
}

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
    use crate::crypto::sign::SigningKey;
    use crate::types::primitives::ContentHash;

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
        use crate::did::document::VerificationMethod;
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
}
