//! Producer-side signing — RFC-ACDP-0001 §5.8.
//!
//! Two algorithms are supported, matching the ACDP signature-algorithms
//! registry: `ed25519` (mandatory baseline) and `ecdsa-p256` (interop).
//!
//! For both, the signature input MUST be the ASCII bytes of the full
//! `content_hash` string (e.g. `sha256:5f8d…`), NOT the raw 32-byte
//! digest. The wire form is base64-encoded:
//!  - `ed25519` — 64 raw signature bytes → 88 base64 chars.
//!  - `ecdsa-p256` — IEEE 1363 `r‖s` (NOT DER) → 64 raw bytes → 88 base64 chars.
//!
//! Use [`AcdpSigningKey`] when you want a single key handle that selects
//! the algorithm at construction time; the producer builder treats both
//! variants uniformly. The concrete [`SigningKey`] / [`P256SigningKey`]
//! types remain available for callers that already know the algorithm.

use crate::error::AcdpError;
use crate::types::primitives::ContentHash;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer as _, SigningKey as DalekSigningKey};
use zeroize::ZeroizeOnDrop;

// ── Ed25519 ──────────────────────────────────────────────────────────────────

/// An Ed25519 signing key. Private bytes are zeroed on drop.
#[derive(ZeroizeOnDrop)]
pub struct SigningKey(DalekSigningKey);

impl SigningKey {
    /// Construct from a 32-byte raw private key seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(DalekSigningKey::from_bytes(bytes))
    }

    /// Try to construct from a slice. Returns an error if the length is wrong.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AcdpError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            AcdpError::InvalidSignature(format!(
                "signing key must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self::from_bytes(&arr))
    }

    /// Generate a fresh Ed25519 key pair using the operating system RNG.
    ///
    /// Recommended for production callers; `from_bytes` is for loading
    /// previously-stored key material. Do not persist the raw 32-byte
    /// seed in cleartext — use a key vault or HSM.
    pub fn generate() -> Self {
        Self(DalekSigningKey::generate(&mut rand_core::OsRng))
    }

    /// Sign the ASCII bytes of the full `content_hash` string per §5.8.
    ///
    /// Returns the signature as standard base64 (88 chars including
    /// padding for Ed25519).
    pub fn sign_content_hash(&self, hash: &ContentHash) -> String {
        // Sign the ASCII bytes of "sha256:<64-hex>", not the raw digest.
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

// ── ECDSA-P256 ───────────────────────────────────────────────────────────────

/// An ECDSA-P256 signing key. Private scalar is zeroed on drop.
///
/// Wire form: 64 raw bytes IEEE 1363 (`r‖s`), base64-encoded with padding
/// for 88 characters — matching the verify path in
/// [`crate::crypto::verify::verify_ecdsa_p256`]. DER-encoded signatures
/// are NOT compatible with the ACDP registry entry for `ecdsa-p256`.
pub struct P256SigningKey(p256::ecdsa::SigningKey);

impl P256SigningKey {
    /// Generate a fresh P-256 key pair using the OS RNG.
    ///
    /// Recommended for production callers; `from_bytes` is for loading
    /// previously-stored key material.
    pub fn generate() -> Self {
        Self(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng))
    }

    /// Construct from 32 raw scalar bytes (big-endian).
    ///
    /// Returns [`AcdpError::SchemaViolation`] when the scalar is invalid
    /// (e.g. zero or ≥ curve order). The error variant matches the
    /// shape used elsewhere for key-material parse failures
    /// (`AgentDid::parse_web`, `validate_signature_length`).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, AcdpError> {
        p256::ecdsa::SigningKey::from_bytes(bytes.into())
            .map(Self)
            .map_err(|e| AcdpError::SchemaViolation(format!("p256 key parse: {e}")))
    }

    /// Try to construct from a slice. Returns an error if the length is wrong.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AcdpError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            AcdpError::SchemaViolation(format!(
                "p256 signing key must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        Self::from_bytes(&arr)
    }

    /// Sign the ASCII bytes of the full `content_hash` string per §5.8.
    ///
    /// Uses RFC 6979 deterministic ECDSA (no `rng` parameter required).
    /// Returns the signature as standard base64 of the 64-byte IEEE 1363
    /// `r‖s` wire form (88 chars including padding).
    pub fn sign_content_hash(&self, hash: &ContentHash) -> String {
        use p256::ecdsa::{signature::Signer as _, Signature};
        let sig: Signature = self.0.sign(hash.as_str().as_bytes());
        // `Signature::to_bytes()` returns the fixed-size 64-byte IEEE 1363
        // form, exactly the wire shape ACDP requires.
        STANDARD.encode(sig.to_bytes())
    }

    /// SEC1-uncompressed public key (65 bytes: `0x04 || x || y`).
    ///
    /// Use this to populate a `did:web` verification method's
    /// `publicKeyJwk` (after splitting into the `x` / `y` halves) or
    /// `publicKeyMultibase` representation.
    pub fn verifying_key_sec1(&self) -> Vec<u8> {
        // `VerifyingKey::to_encoded_point` is delegated from the
        // `elliptic_curve::sec1::ToEncodedPoint` trait — inherent in the
        // crate's public surface, no extra `use` needed.
        self.0
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
}

impl std::fmt::Debug for P256SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("P256SigningKey(…)")
    }
}

// `p256::ecdsa::SigningKey` wraps a `Scalar` that implements
// `ZeroizeOnDrop`, so the private material is wiped automatically when
// `P256SigningKey` drops. No explicit `Drop` impl needed.

// ── Unified key handle ───────────────────────────────────────────────────────

/// Either-or signing key — selects the algorithm at construction time.
///
/// Producers normally use [`crate::producer::Producer::new_ed25519`] or
/// [`crate::producer::Producer::new_p256`] rather than constructing this
/// enum directly. The [`crate::producer::RequestBuilder`] inspects the
/// variant to emit the matching `signature.algorithm` field.
#[derive(Debug)]
pub enum AcdpSigningKey {
    /// Ed25519 — mandatory baseline.
    Ed25519(SigningKey),
    /// ECDSA-P256 — interop variant.
    P256(P256SigningKey),
}

impl AcdpSigningKey {
    /// Returns `(algorithm_str, base64_signature)` for the wire envelope.
    ///
    /// The first element is the literal string ACDP requires in
    /// `signature.algorithm` (`"ed25519"` or `"ecdsa-p256"`).
    pub fn sign_content_hash(&self, hash: &ContentHash) -> (&'static str, String) {
        match self {
            Self::Ed25519(k) => ("ed25519", k.sign_content_hash(hash)),
            Self::P256(k) => ("ecdsa-p256", k.sign_content_hash(hash)),
        }
    }

    /// The ACDP algorithm string for the wrapped key, regardless of
    /// whether a signature has been produced yet.
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "ed25519",
            Self::P256(_) => "ecdsa-p256",
        }
    }
}

impl From<SigningKey> for AcdpSigningKey {
    fn from(k: SigningKey) -> Self {
        Self::Ed25519(k)
    }
}

impl From<P256SigningKey> for AcdpSigningKey {
    fn from(k: P256SigningKey) -> Self {
        Self::P256(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_generate_produces_distinct_keys() {
        // Two fresh OsRng draws MUST produce different public keys.
        let a = SigningKey::generate();
        let b = SigningKey::generate();
        assert_ne!(
            a.verifying_key_bytes(),
            b.verifying_key_bytes(),
            "OsRng-backed generate() must not yield identical keys"
        );
    }

    #[test]
    fn p256_generate_produces_distinct_keys() {
        let a = P256SigningKey::generate();
        let b = P256SigningKey::generate();
        assert_ne!(
            a.verifying_key_sec1(),
            b.verifying_key_sec1(),
            "OsRng-backed P256 generate() must not yield identical keys"
        );
    }

    #[test]
    fn p256_sign_verify_round_trip() {
        use crate::crypto::verify::verify_ecdsa_p256;
        let key = P256SigningKey::generate();
        let hash = ContentHash(
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
        );
        let sig = key.sign_content_hash(&hash);
        // 88 base64 chars (64 raw + padding).
        assert_eq!(sig.len(), 88, "p256 wire signature MUST be 88 base64 chars");
        let pub_sec1 = key.verifying_key_sec1();
        verify_ecdsa_p256(&pub_sec1, &sig, hash.as_str())
            .expect("round-trip p256 signature must verify");
    }

    #[test]
    fn p256_sign_against_wrong_message_fails() {
        use crate::crypto::verify::verify_ecdsa_p256;
        let key = P256SigningKey::generate();
        let hash = ContentHash("sha256:".to_owned() + &"a".repeat(64));
        let sig = key.sign_content_hash(&hash);
        let pub_sec1 = key.verifying_key_sec1();
        let err =
            verify_ecdsa_p256(&pub_sec1, &sig, "sha256:0000000000000000").expect_err("must fail");
        assert!(matches!(err, AcdpError::InvalidSignature(_)));
    }

    #[test]
    fn p256_der_encoded_signature_rejected() {
        // The verifier requires IEEE 1363 r||s (64 bytes). A DER-encoded
        // signature is variable-length and starts with 0x30 — must be
        // rejected by length check.
        use crate::crypto::verify::verify_ecdsa_p256;
        let key = P256SigningKey::generate();
        let hash = ContentHash("sha256:".to_owned() + &"f".repeat(64));
        // Produce a DER-encoded signature using the lower-level API.
        use p256::ecdsa::signature::Signer as _;
        let der: p256::ecdsa::DerSignature = key.0.sign(hash.as_str().as_bytes());
        let sig_b64 = STANDARD.encode(der.as_bytes());
        let pub_sec1 = key.verifying_key_sec1();
        let err = verify_ecdsa_p256(&pub_sec1, &sig_b64, hash.as_str())
            .expect_err("DER-encoded p256 sig MUST be rejected");
        assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn acdp_signing_key_emits_correct_algorithm() {
        let ed = AcdpSigningKey::Ed25519(SigningKey::generate());
        let p2 = AcdpSigningKey::P256(P256SigningKey::generate());
        assert_eq!(ed.algorithm(), "ed25519");
        assert_eq!(p2.algorithm(), "ecdsa-p256");
        let hash = ContentHash("sha256:".to_owned() + &"a".repeat(64));
        let (alg_ed, _) = ed.sign_content_hash(&hash);
        let (alg_p2, _) = p2.sign_content_hash(&hash);
        assert_eq!(alg_ed, "ed25519");
        assert_eq!(alg_p2, "ecdsa-p256");
    }

    // ── Ed25519 golden vector regression (sig-001) ──────────────────────

    const ED25519_TEST_SEED: [u8; 32] = [0u8; 32];
    const ED25519_TEST_PUB_HEX: &str =
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    #[test]
    fn sign_and_verify_ed25519_golden() {
        use crate::crypto::verify::verify_ed25519;
        let key = SigningKey::from_bytes(&ED25519_TEST_SEED);
        let hash = ContentHash(
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
        );
        let sig_b64 = key.sign_content_hash(&hash);
        assert_eq!(
            sig_b64,
            "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
        );
        let pub_bytes: [u8; 32] = hex::decode(ED25519_TEST_PUB_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        verify_ed25519(&pub_bytes, &sig_b64, hash.as_str()).unwrap();
    }
}
