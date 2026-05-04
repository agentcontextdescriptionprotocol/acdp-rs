//! DID document types and key extraction.

use crate::error::AcdpError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

/// A minimal DID document (subset sufficient for ACDP §5.11).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,

    #[serde(rename = "verificationMethod", default)]
    pub verification_methods: Vec<VerificationMethod>,

    #[serde(rename = "assertionMethod", default)]
    pub assertion_method: Vec<AssertionMethodRef>,
}

impl DidDocument {
    /// Find a verification method by its `#fragment` (the part after `#`).
    pub fn find_by_fragment(&self, fragment: &str) -> Option<&VerificationMethod> {
        self.verification_methods
            .iter()
            .find(|m| m.id.ends_with(&format!("#{fragment}")) || m.id == format!("#{fragment}"))
    }

    /// Returns `true` if `vm_id` is listed in `assertionMethod`.
    pub fn is_assertion_method(&self, vm_id: &str) -> bool {
        self.assertion_method.iter().any(|r| match r {
            AssertionMethodRef::Id(id) => {
                id == vm_id || (id.starts_with('#') && vm_id.ends_with(id))
            }
            AssertionMethodRef::Embedded(m) => m.id == vm_id,
        })
    }
}

/// A DID document verification method entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,

    /// JWK public key representation.
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,

    /// Multibase-encoded public key (`z` prefix = base58btc + multicodec).
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
}

impl VerificationMethod {
    /// Extract the raw 32-byte Ed25519 public key.
    ///
    /// Supports both `publicKeyJwk` (OKP / Ed25519) and
    /// `publicKeyMultibase` (base58btc, multicodec 0xed01 prefix).
    pub fn ed25519_public_key_bytes(&self) -> Result<[u8; 32], AcdpError> {
        if let Some(jwk) = &self.public_key_jwk {
            return extract_from_jwk(jwk);
        }
        if let Some(mb) = &self.public_key_multibase {
            return extract_from_multibase(mb);
        }
        Err(AcdpError::KeyResolution(
            "verification method has neither publicKeyJwk nor publicKeyMultibase".into(),
        ))
    }
}

/// `assertionMethod` entries can be either an ID string or an embedded object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AssertionMethodRef {
    Id(String),
    Embedded(Box<VerificationMethod>),
}

// ── Key extraction helpers ────────────────────────────────────────────────────

fn extract_from_jwk(jwk: &serde_json::Value) -> Result<[u8; 32], AcdpError> {
    let kty = jwk["kty"].as_str().unwrap_or("");
    let crv = jwk["crv"].as_str().unwrap_or("");

    if kty != "OKP" || crv != "Ed25519" {
        return Err(AcdpError::KeyResolution(format!(
            "expected OKP/Ed25519 JWK, got kty={kty} crv={crv}"
        )));
    }

    let x = jwk["x"]
        .as_str()
        .ok_or_else(|| AcdpError::KeyResolution("JWK missing 'x' parameter".into()))?;

    let bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| AcdpError::KeyResolution(format!("JWK 'x' base64url decode: {e}")))?;

    bytes
        .try_into()
        .map_err(|_| AcdpError::KeyResolution("JWK 'x' is not 32 bytes (not Ed25519)".into()))
}

fn extract_from_multibase(mb: &str) -> Result<[u8; 32], AcdpError> {
    if !mb.starts_with('z') {
        return Err(AcdpError::KeyResolution(
            "only 'z' (base58btc) multibase prefix is supported".into(),
        ));
    }

    let decoded = bs58::decode(&mb[1..])
        .into_vec()
        .map_err(|e| AcdpError::KeyResolution(format!("base58 decode: {e}")))?;

    // Multicodec prefix for Ed25519 is 0xed 0x01
    if decoded.len() < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(AcdpError::KeyResolution(
            "multibase key does not have Ed25519 multicodec prefix (0xed 0x01)".into(),
        ));
    }

    decoded[2..].try_into().map_err(|_| {
        AcdpError::KeyResolution("Ed25519 key must be 32 bytes after multicodec prefix".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_PUB_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    fn test_pub_bytes() -> [u8; 32] {
        hex::decode(TEST_PUB_HEX).unwrap().try_into().unwrap()
    }

    #[test]
    fn extracts_from_jwk() {
        let raw = test_pub_bytes();
        let x = URL_SAFE_NO_PAD.encode(raw);
        let jwk = json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
        let vm = VerificationMethod {
            id: "did:web:example.com#key-1".into(),
            method_type: "JsonWebKey2020".into(),
            controller: "did:web:example.com".into(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        };
        assert_eq!(vm.ed25519_public_key_bytes().unwrap(), raw);
    }

    #[test]
    fn rejects_wrong_kty() {
        let jwk = json!({ "kty": "EC", "crv": "P-256", "x": "abc" });
        let vm = VerificationMethod {
            id: "did:web:example.com#key-1".into(),
            method_type: "JsonWebKey2020".into(),
            controller: "did:web:example.com".into(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        };
        assert!(matches!(
            vm.ed25519_public_key_bytes(),
            Err(AcdpError::KeyResolution(_))
        ));
    }

    #[test]
    fn extracts_from_multibase() {
        let raw = test_pub_bytes();
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
        assert_eq!(vm.ed25519_public_key_bytes().unwrap(), raw);
    }

    #[test]
    fn rejects_non_z_multibase() {
        let vm = VerificationMethod {
            id: "did:web:example.com#key-1".into(),
            method_type: "Ed25519VerificationKey2020".into(),
            controller: "did:web:example.com".into(),
            public_key_jwk: None,
            public_key_multibase: Some("uAAAA".into()),
        };
        assert!(matches!(
            vm.ed25519_public_key_bytes(),
            Err(AcdpError::KeyResolution(_))
        ));
    }

    #[test]
    fn rejects_non_ed25519_multicodec() {
        // 0xe7 = secp256k1 multicodec, not Ed25519 (0xed 0x01)
        let mut prefixed = vec![0xe7, 0x01];
        prefixed.extend_from_slice(&[0u8; 32]);
        let mb = format!("z{}", bs58::encode(&prefixed).into_string());
        let vm = VerificationMethod {
            id: "did:web:example.com#key-1".into(),
            method_type: "X".into(),
            controller: "did:web:example.com".into(),
            public_key_jwk: None,
            public_key_multibase: Some(mb),
        };
        assert!(matches!(
            vm.ed25519_public_key_bytes(),
            Err(AcdpError::KeyResolution(_))
        ));
    }

    #[test]
    fn assertion_method_authorization_by_full_id() {
        let doc = DidDocument {
            id: "did:web:example.com".into(),
            verification_methods: vec![VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: None,
                public_key_multibase: None,
            }],
            assertion_method: vec![AssertionMethodRef::Id("did:web:example.com#key-1".into())],
        };
        assert!(doc.is_assertion_method("did:web:example.com#key-1"));
        assert!(!doc.is_assertion_method("did:web:example.com#key-2"));
    }

    #[test]
    fn assertion_method_authorization_by_relative_fragment() {
        let doc = DidDocument {
            id: "did:web:example.com".into(),
            verification_methods: vec![VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: None,
                public_key_multibase: None,
            }],
            assertion_method: vec![AssertionMethodRef::Id("#key-1".into())],
        };
        assert!(doc.is_assertion_method("did:web:example.com#key-1"));
    }

    #[test]
    fn find_by_fragment() {
        let doc = DidDocument {
            id: "did:web:example.com".into(),
            verification_methods: vec![VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: None,
                public_key_multibase: None,
            }],
            assertion_method: vec![],
        };
        assert!(doc.find_by_fragment("key-1").is_some());
        assert!(doc.find_by_fragment("key-2").is_none());
    }
}
