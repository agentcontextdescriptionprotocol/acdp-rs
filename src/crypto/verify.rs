//! End-to-end body verification — RFC-ACDP-0001 §5.11 (7-step algorithm).

use crate::error::AcdpError;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Verifier as _, VerifyingKey};

#[cfg(feature = "client")]
use {super::hash::verify_content_hash, crate::did::web::WebResolver, crate::types::body::Body};

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
        // Step 0: recompute content_hash over ProducerContent
        let body_val = serde_json::to_value(body)?;
        verify_content_hash(&body_val, &body.content_hash)?;

        // Step 1: parse key_id — must contain a '#' fragment
        let key_id = &body.signature.key_id;
        let (did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
            AcdpError::KeyResolution(format!("signature.key_id '{key_id}' has no '#fragment'"))
        })?;

        // Step 2: DID portion MUST equal body.agent_id
        if did_part != body.agent_id.as_str() {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "key_id DID '{did_part}' ≠ agent_id '{}'",
                body.agent_id
            )));
        }

        // Step 3: resolve DID document
        let doc = self.resolver.resolve(did_part).await?;

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

        // Step 6: extract raw Ed25519 public key bytes
        let pub_bytes = method.ed25519_public_key_bytes()?;

        // Step 7: verify signature over ASCII bytes of content_hash string
        verify_ed25519(
            &pub_bytes,
            &body.signature.value,
            body.content_hash.as_str(),
        )
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
}
