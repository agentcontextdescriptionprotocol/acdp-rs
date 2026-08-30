//! `did:key` — pure, offline DID resolution (no network, no document).
//!
//! A `did:key` DID *is* its public key: the method-specific identifier is
//! the multibase (`z` = base58btc) encoding of the multicodec-prefixed
//! public key bytes. Resolution is a pure function — no DNS, no HTTPS, no
//! DID-document fetch, and therefore no SSRF surface and no dependency on
//! the producer's infrastructure remaining online.
//!
//! Supported multicodec prefixes (unsigned-varint encoding):
//! - `ed25519-pub` (code `0xed`)   → bytes `0xed 0x01`, 32-byte raw key.
//! - `p256-pub`    (code `0x1200`) → bytes `0x80 0x24`, 33-byte
//!   SEC1-*compressed* point (per the did:key method spec — NOT the
//!   65-byte uncompressed form used in `publicKeyJwk`).
//!
//! The verification-method fragment convention follows the W3C did:key
//! method: the key's DID URL is `did:key:z<mb>#z<mb>` — the fragment is
//! the method-specific identifier itself. There is no `assertionMethod`
//! check for did:key: the DID is the key, so the key is authorized by
//! construction.
//!
//! Unlike `did:web`, a did:key identity cannot rotate — a new key is a
//! new identity, and `supersedes` requires the same `agent_id`, so
//! lineage continuity ends with the key. Conversely, did:key contexts
//! are immune to the historical-key-validity problem (RFC-ACDP-0008
//! §9.3) and to domain-lapse hijacking: verification outlives the
//! producer's infrastructure.

use acdp_primitives::error::AcdpError;

/// Multicodec prefix for `ed25519-pub` (code `0xed`, varint `0xed 0x01`).
const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];
/// Multicodec prefix for `p256-pub` (code `0x1200`, varint `0x80 0x24`).
const MULTICODEC_P256: [u8; 2] = [0x80, 0x24];

/// Public key material resolved from a `did:key` DID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidKeyMaterial {
    /// Raw 32-byte Ed25519 public key.
    Ed25519([u8; 32]),
    /// SEC1-compressed P-256 point (33 bytes, leading `0x02`/`0x03`).
    EcdsaP256([u8; 33]),
}

impl DidKeyMaterial {
    /// The ACDP `signature.algorithm` string this key verifies
    /// (`"ed25519"` or `"ecdsa-p256"`). Used for algorithm-downgrade
    /// rejection: the body's declared algorithm MUST equal this value.
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "ed25519",
            Self::EcdsaP256(_) => "ecdsa-p256",
        }
    }
}

/// Resolve a `did:key:z…` DID to its public key material — a pure
/// function, available without any HTTP feature.
///
/// Errors are [`AcdpError::KeyResolution`] (wire code
/// `key_resolution_failed`, permanent): a malformed did:key is a
/// producer error that no retry will fix.
pub fn resolve_did_key(did: &str) -> Result<DidKeyMaterial, AcdpError> {
    let msi = did
        .strip_prefix("did:key:")
        .ok_or_else(|| AcdpError::KeyResolution(format!("not a did:key DID: {did}")))?;
    decode_multibase_key(msi)
}

/// Decode a multibase-encoded, multicodec-prefixed public key (the
/// method-specific identifier of a did:key, e.g. `z6Mk…`).
fn decode_multibase_key(msi: &str) -> Result<DidKeyMaterial, AcdpError> {
    let rest = msi.strip_prefix('z').ok_or_else(|| {
        AcdpError::KeyResolution(format!(
            "did:key requires the 'z' (base58btc) multibase prefix, got '{msi}'"
        ))
    })?;
    let decoded = bs58::decode(rest)
        .into_vec()
        .map_err(|e| AcdpError::KeyResolution(format!("did:key base58 decode: {e}")))?;

    match decoded.get(0..2) {
        Some(p) if p == MULTICODEC_ED25519 => {
            let key: [u8; 32] = decoded[2..].try_into().map_err(|_| {
                AcdpError::KeyResolution(format!(
                    "did:key ed25519 key must be 32 bytes after the multicodec prefix, got {}",
                    decoded.len().saturating_sub(2)
                ))
            })?;
            Ok(DidKeyMaterial::Ed25519(key))
        }
        Some(p) if p == MULTICODEC_P256 => {
            let key: [u8; 33] = decoded[2..].try_into().map_err(|_| {
                AcdpError::KeyResolution(format!(
                    "did:key p256 key must be a 33-byte SEC1-compressed point after the \
                     multicodec prefix, got {}",
                    decoded.len().saturating_sub(2)
                ))
            })?;
            if !matches!(key[0], 0x02 | 0x03) {
                return Err(AcdpError::KeyResolution(
                    "did:key p256 key must be SEC1-compressed (leading 0x02/0x03)".into(),
                ));
            }
            Ok(DidKeyMaterial::EcdsaP256(key))
        }
        _ => Err(AcdpError::KeyResolution(
            "did:key multicodec prefix is neither ed25519-pub (0xed 0x01) \
             nor p256-pub (0x80 0x24)"
                .into(),
        )),
    }
}

/// Validate the `signature.key_id` form for a did:key producer and
/// return the resolved key material.
///
/// Per the did:key method, the only verification method a did:key DID
/// has is the key itself, addressed as `did:key:z<mb>#z<mb>` — the
/// fragment MUST equal the method-specific identifier. A fragment
/// addressing anything else cannot exist in a did:key document and is
/// rejected with `key_resolution_failed`.
pub fn resolve_did_key_url(key_id: &str) -> Result<DidKeyMaterial, AcdpError> {
    let (did_part, fragment) = key_id
        .split_once('#')
        .ok_or_else(|| AcdpError::KeyResolution(format!("key_id '{key_id}' has no '#fragment'")))?;
    let msi = did_part
        .strip_prefix("did:key:")
        .ok_or_else(|| AcdpError::KeyResolution(format!("not a did:key DID URL: {key_id}")))?;
    if fragment != msi {
        return Err(AcdpError::KeyResolution(format!(
            "did:key fragment '#{fragment}' must equal the method-specific identifier \
             '{msi}' (the did:key document's only verification method is the key itself)"
        )));
    }
    decode_multibase_key(msi)
}

/// Encode a raw 32-byte Ed25519 public key as a `did:key` DID.
pub fn did_key_from_ed25519(public_key: &[u8; 32]) -> String {
    let mut prefixed = Vec::with_capacity(2 + 32);
    prefixed.extend_from_slice(&MULTICODEC_ED25519);
    prefixed.extend_from_slice(public_key);
    format!("did:key:z{}", bs58::encode(&prefixed).into_string())
}

/// Encode a SEC1 P-256 public key (compressed 33-byte or uncompressed
/// 65-byte form) as a `did:key` DID. Uncompressed input is compressed
/// first, per the did:key method spec.
pub fn did_key_from_p256_sec1(sec1: &[u8]) -> Result<String, AcdpError> {
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
        .map_err(|e| AcdpError::KeyResolution(format!("p256 SEC1 parse: {e}")))?;
    let compressed = vk.to_sec1_point(true);
    let mut prefixed = Vec::with_capacity(2 + 33);
    prefixed.extend_from_slice(&MULTICODEC_P256);
    prefixed.extend_from_slice(compressed.as_bytes());
    Ok(format!(
        "did:key:z{}",
        bs58::encode(&prefixed).into_string()
    ))
}

/// The canonical `signature.key_id` DID URL for a did:key DID:
/// `did:key:z<mb>#z<mb>` (fragment = method-specific identifier).
pub fn did_key_url(did: &str) -> Result<String, AcdpError> {
    let msi = did
        .strip_prefix("did:key:")
        .ok_or_else(|| AcdpError::KeyResolution(format!("not a did:key DID: {did}")))?;
    Ok(format!("{did}#{msi}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ed25519 public key of the all-zero seed (sig-001 test key).
    const TEST_PUB_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    fn test_pub() -> [u8; 32] {
        hex::decode(TEST_PUB_HEX).unwrap().try_into().unwrap()
    }

    #[test]
    fn ed25519_round_trip() {
        let did = did_key_from_ed25519(&test_pub());
        assert!(did.starts_with("did:key:z"));
        match resolve_did_key(&did).unwrap() {
            DidKeyMaterial::Ed25519(k) => assert_eq!(k, test_pub()),
            other => panic!("expected Ed25519, got {other:?}"),
        }
    }

    #[test]
    fn p256_round_trip_compresses_uncompressed_input() {
        let key = acdp_crypto::sign::P256SigningKey::generate();
        let did = did_key_from_p256_sec1(&key.verifying_key_sec1()).unwrap();
        match resolve_did_key(&did).unwrap() {
            DidKeyMaterial::EcdsaP256(k) => {
                assert_eq!(k.len(), 33);
                assert!(matches!(k[0], 0x02 | 0x03));
                // Decompressing must give back the original point.
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&k).unwrap();
                assert_eq!(
                    vk.to_sec1_point(false).as_bytes(),
                    key.verifying_key_sec1().as_slice()
                );
            }
            other => panic!("expected EcdsaP256, got {other:?}"),
        }
    }

    #[test]
    fn key_url_fragment_must_equal_msi() {
        let did = did_key_from_ed25519(&test_pub());
        let url = did_key_url(&did).unwrap();
        resolve_did_key_url(&url).unwrap();

        // Wrong fragment → rejected.
        let bad = format!("{did}#key-1");
        let err = resolve_did_key_url(&bad).unwrap_err();
        assert!(matches!(err, AcdpError::KeyResolution(_)), "got {err:?}");

        // No fragment → rejected.
        let err = resolve_did_key_url(&did).unwrap_err();
        assert!(matches!(err, AcdpError::KeyResolution(_)), "got {err:?}");
    }

    #[test]
    fn rejects_unknown_multicodec() {
        // secp256k1-pub (0xe7 0x01) is not an ACDP algorithm.
        let mut prefixed = vec![0xe7, 0x01];
        prefixed.extend_from_slice(&[0u8; 33]);
        let did = format!("did:key:z{}", bs58::encode(&prefixed).into_string());
        let err = resolve_did_key(&did).unwrap_err();
        assert!(matches!(err, AcdpError::KeyResolution(_)), "got {err:?}");
    }

    #[test]
    fn rejects_non_z_multibase_and_garbage() {
        for bad in ["did:key:uAAAA", "did:key:z!!!not-base58!!!", "did:web:x"] {
            assert!(
                resolve_did_key(bad).is_err(),
                "'{bad}' must fail did:key resolution"
            );
        }
    }

    #[test]
    fn rejects_wrong_length_ed25519() {
        let mut prefixed = MULTICODEC_ED25519.to_vec();
        prefixed.extend_from_slice(&[0u8; 31]); // 31, not 32
        let did = format!("did:key:z{}", bs58::encode(&prefixed).into_string());
        assert!(resolve_did_key(&did).is_err());
    }

    #[test]
    fn rejects_uncompressed_p256_payload() {
        // 65-byte uncompressed point inside the multicodec wrapper is
        // not did:key-conformant (the spec mandates compressed).
        let key = acdp_crypto::sign::P256SigningKey::generate();
        let mut prefixed = MULTICODEC_P256.to_vec();
        prefixed.extend_from_slice(&key.verifying_key_sec1());
        let did = format!("did:key:z{}", bs58::encode(&prefixed).into_string());
        assert!(resolve_did_key(&did).is_err());
    }

    #[test]
    fn algorithm_strings() {
        assert_eq!(DidKeyMaterial::Ed25519([0; 32]).algorithm(), "ed25519");
        assert_eq!(DidKeyMaterial::EcdsaP256([2; 33]).algorithm(), "ecdsa-p256");
    }
}
