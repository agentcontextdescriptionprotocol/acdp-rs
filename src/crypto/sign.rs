//! Ed25519 signing — RFC-ACDP-0001 §5.8.
//!
//! The signature input MUST be the ASCII bytes of the full `content_hash`
//! string (e.g. `sha256:5f8d…`), NOT the raw 32-byte digest.

use crate::error::AcdpError;
use crate::types::primitives::ContentHash;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer as _, SigningKey as DalekSigningKey};
use zeroize::ZeroizeOnDrop;

/// An Ed25519 signing key.  Private bytes are zeroed on drop.
#[derive(ZeroizeOnDrop)]
pub struct SigningKey(DalekSigningKey);

impl SigningKey {
    /// Construct from a 32-byte raw private key seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(DalekSigningKey::from_bytes(bytes))
    }

    /// Try to construct from a slice.  Returns an error if the length is wrong.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AcdpError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            AcdpError::InvalidSignature(format!(
                "signing key must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self::from_bytes(&arr))
    }

    /// Sign the bytes of the full `content_hash` string per §5.8.
    ///
    /// Returns the signature as standard base64.
    pub fn sign_content_hash(&self, hash: &ContentHash) -> String {
        // Sign the ASCII bytes of "sha256:<64-hex>", not the raw digest
        let sig = self.0.sign(hash.as_str().as_bytes());
        STANDARD.encode(sig.to_bytes())
    }

    /// Raw public key bytes (32 bytes).
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(…)")
    }
}
