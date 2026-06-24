//! Registry receipts (ACDP 0.2, RFC-ACDP-0010 — promoted from the
//! RFC-ACDP-0009 §2.7 reservation).
//!
//! A receipt is a **registry-signed attestation** binding the
//! registry-assigned identifiers (`ctx_id`, `lineage_id`,
//! `origin_registry`, `created_at`) and the resolved producer key
//! (`key_fingerprint`) to the producer's `content_hash`. It closes the
//! two v0.1.0 trust gaps documented in RFC-ACDP-0008 §9:
//!
//! - **Registry honesty (§9.1)** — without a receipt, a malicious
//!   registry can republish signed content under a different `ctx_id`
//!   or backdate `created_at` and producer-signature verification
//!   still passes. A receipt makes those claims attributable and
//!   non-repudiable (though not unforgeable at mint time — a registry
//!   can still lie when it first issues; the transparency log reserved
//!   by RFC-ACDP-0009 §2.11 is the next layer).
//! - **Historical key validity (§9.3)** — `key_fingerprint` records
//!   *which* producer key the registry resolved and verified at publish
//!   time, so consumers can verify old contexts after the producer
//!   rotates.
//!
//! ## Signing construction
//!
//! Deliberately identical to the producer signature (RFC-ACDP-0001
//! §5.8): the preimage is the JCS-canonicalized receipt object **minus
//! the `signature` field only** (no §5.7 exclusion set — the
//! registry-assigned fields are the entire point), hashed with SHA-256,
//! and the signature is over the **ASCII bytes of the
//! `"sha256:<hex>"` string**, not the raw digest.

use crate::body::Signature;
use acdp_jcs::try_canonicalize_value;
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::{ContentHash, CtxId, LineageId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A registry-signed publication receipt.
///
/// CLOSED schema (RFC-ACDP-0010 §4, `additionalProperties: false`):
/// a receipt has exactly the eight specified members. Future receipt
/// fields require a schema bump, not field-level extensibility —
/// unknown members are rejected at parse time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryReceipt {
    /// The registry's own identity — MUST be `did:web:<authority>`
    /// where `<authority>` is the authority the context is served from.
    pub registry_did: String,
    /// The ctx_id this receipt attests.
    pub ctx_id: CtxId,
    /// The lineage the registry assigned.
    pub lineage_id: LineageId,
    /// The registry's authority (bare hostname form).
    pub origin_registry: String,
    /// Publication acceptance time. Canonical millisecond-precision
    /// RFC 3339 UTC, always serialized with exactly three fractional
    /// digits (`…SS.mmmZ`, RFC-ACDP-0010 §8 step 6) — chrono's default
    /// drops trailing zeros, which would change the preimage bytes.
    #[serde(with = "ms_rfc3339")]
    pub created_at: DateTime<Utc>,
    /// The producer's content hash this receipt binds.
    pub content_hash: ContentHash,
    /// Fingerprint of the producer key the registry resolved and
    /// verified at publish time (see [`acdp_crypto::fingerprint`]).
    pub key_fingerprint: String,
    /// Registry signature over the receipt preimage.
    pub signature: Signature,
}

/// Fixed three-digit-millisecond RFC 3339 serde for receipt
/// `created_at` (RFC-ACDP-0010 §8 step 6: `…T…SS.mmmZ`).
mod ms_rfc3339 {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&raw)
            .map(|t| t.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

impl RegistryReceipt {
    /// Parse a receipt from the opaque JSON value carried in
    /// [`crate::body::FullContext::registry_receipt`].
    pub fn from_value(value: &serde_json::Value) -> Result<Self, AcdpError> {
        Self::deserialize(value)
            .map_err(|e| AcdpError::InvalidReceipt(format!("registry_receipt does not parse: {e}")))
    }

    /// Compute the preimage hash from the RAW wire JSON of a receipt
    /// (the value minus `signature`, canonicalized as received).
    ///
    /// Verifiers MUST hash the receipt exactly as received rather than
    /// re-serializing a parsed struct — the same "hash verification
    /// over raw JSON" rule as RFC-ACDP-0001 §6 bodies. Re-serialization
    /// can normalize byte details (e.g. timestamp fraction digits) and
    /// falsely fail an honest receipt.
    pub fn preimage_hash_of_value(value: &serde_json::Value) -> Result<ContentHash, AcdpError> {
        let mut map = value
            .as_object()
            .cloned()
            .ok_or_else(|| AcdpError::InvalidReceipt("receipt must be a JSON object".into()))?;
        map.remove("signature");
        let canonical = try_canonicalize_value(&serde_json::Value::Object(map))?;
        let digest = Sha256::digest(&canonical);
        Ok(ContentHash(format!("sha256:{}", hex::encode(digest))))
    }

    /// Validate the §8 step 6 byte form of the receipt's raw
    /// `created_at`: canonical millisecond-precision RFC 3339 UTC with
    /// exactly three fractional digits and a literal `Z`.
    pub fn validate_created_at_form(value: &serde_json::Value) -> Result<(), AcdpError> {
        let raw = value
            .get("created_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AcdpError::InvalidReceipt("receipt created_at missing or not a string".into())
            })?;
        let b = raw.as_bytes();
        let well_formed = b.len() == 24
            && b[10] == b'T'
            && b[19] == b'.'
            && b[23] == b'Z'
            && b[20..23].iter().all(u8::is_ascii_digit)
            && chrono::DateTime::parse_from_rfc3339(raw).is_ok();
        if !well_formed {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt created_at '{raw}' is not canonical millisecond-precision \
                 RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SS.mmmZ`, RFC-ACDP-0010 §8 step 6)"
            )));
        }
        Ok(())
    }

    /// §8 step 3 body bindings: `lineage_id`, `origin_registry`, and
    /// `created_at` MUST equal the corresponding fields of the
    /// accompanying body. (`ctx_id` is bound separately against the
    /// *requested* identifier in [`Self::cross_check`].)
    pub fn cross_check_body(&self, body: &crate::body::Body) -> Result<(), AcdpError> {
        if self.lineage_id != body.lineage_id {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt lineage_id '{}' ≠ body lineage_id '{}'",
                self.lineage_id, body.lineage_id
            )));
        }
        if self.origin_registry != body.origin_registry {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt origin_registry '{}' ≠ body origin_registry '{}'",
                self.origin_registry, body.origin_registry
            )));
        }
        if self.created_at != body.created_at {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt created_at '{}' ≠ body created_at '{}'",
                self.created_at, body.created_at
            )));
        }
        Ok(())
    }

    /// Compute the receipt's signature preimage hash: SHA-256 over the
    /// JCS canonical form of the receipt **minus `signature` only**.
    ///
    /// Struct-based form, used at MINT time (the struct's serializer
    /// emits the canonical three-digit-millisecond `created_at`).
    /// Verifiers should prefer [`Self::preimage_hash_of_value`] over
    /// the raw wire JSON.
    pub fn preimage_hash(&self) -> Result<ContentHash, AcdpError> {
        Self::preimage_hash_of_value(&serde_json::to_value(self)?)
    }

    /// Verify the receipt signature against a known registry public
    /// key (pure — no DID resolution; the `client` feature's
    /// `verify_receipt_value` resolves the registry DID and calls
    /// this).
    pub fn verify_signature_with_key(
        &self,
        registry_pub_ed25519: Option<&[u8; 32]>,
        registry_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        let hash = self.preimage_hash()?;
        self.verify_signature_against_hash(&hash, registry_pub_ed25519, registry_pub_p256_sec1)
    }

    /// Like [`Self::verify_signature_with_key`] but over an
    /// already-computed preimage hash — pair with
    /// [`Self::preimage_hash_of_value`] for raw-JSON verification.
    pub fn verify_signature_against_hash(
        &self,
        hash: &ContentHash,
        registry_pub_ed25519: Option<&[u8; 32]>,
        registry_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        match self.signature.algorithm.as_str() {
            "ed25519" => {
                let key = registry_pub_ed25519.ok_or_else(|| {
                    AcdpError::InvalidReceipt(
                        "receipt declares ed25519 but no ed25519 registry key was resolved".into(),
                    )
                })?;
                acdp_crypto::verify::verify_ed25519(key, &self.signature.value, hash.as_str())
                    .map_err(|e| AcdpError::InvalidReceipt(format!("receipt signature: {e}")))
            }
            "ecdsa-p256" => {
                let key = registry_pub_p256_sec1.ok_or_else(|| {
                    AcdpError::InvalidReceipt(
                        "receipt declares ecdsa-p256 but no p256 registry key was resolved".into(),
                    )
                })?;
                acdp_crypto::verify::verify_ecdsa_p256(key, &self.signature.value, hash.as_str())
                    .map_err(|e| AcdpError::InvalidReceipt(format!("receipt signature: {e}")))
            }
            other => Err(AcdpError::InvalidReceipt(format!(
                "receipt signature algorithm '{other}' is not supported"
            ))),
        }
    }

    /// The pure (offline) subset of the RFC-ACDP-0010 cross-checks —
    /// everything except registry-DID resolution and the
    /// served-authority comparison, which need the `client` feature:
    ///
    /// - `ctx_id` equals the requested one.
    /// - `content_hash` equals the *independently recomputed* body hash
    ///   (pass the recomputed value, never the body's echoed field).
    /// - `key_fingerprint` equals the fingerprint of the resolved
    ///   producer key.
    /// - `created_at` is millisecond-truncated.
    /// - `registry_did` is `did:web:<origin_registry>` (internal
    ///   consistency; the serving-authority comparison is the client's
    ///   job).
    pub fn cross_check(
        &self,
        expected_ctx_id: &CtxId,
        recomputed_body_hash: &ContentHash,
        producer_key_fingerprint: &str,
    ) -> Result<(), AcdpError> {
        if &self.ctx_id != expected_ctx_id {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt ctx_id '{}' ≠ requested '{expected_ctx_id}'",
                self.ctx_id
            )));
        }
        if &self.content_hash != recomputed_body_hash {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt content_hash '{}' ≠ recomputed body hash '{recomputed_body_hash}'",
                self.content_hash
            )));
        }
        if self.key_fingerprint != producer_key_fingerprint {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt key_fingerprint '{}' ≠ resolved producer key '{producer_key_fingerprint}'",
                self.key_fingerprint
            )));
        }
        if self.created_at.timestamp_subsec_nanos() % 1_000_000 != 0 {
            return Err(AcdpError::InvalidReceipt(
                "receipt created_at is not millisecond-truncated (RFC-ACDP-0001 §5.3)".into(),
            ));
        }
        let expected_did = acdp_did::web::authority_to_did_web(&self.origin_registry);
        if self.registry_did != expected_did {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt registry_did '{}' ≠ did:web form of origin_registry ('{expected_did}')",
                self.registry_did
            )));
        }
        Ok(())
    }
}

/// Registry-side receipt minting identity: the signing key plus the
/// DID URL it is published under in the registry's own DID document.
///
/// Lifecycle rule (RFC-ACDP-0010, normative): retired receipt keys
/// MUST remain in the registry DID document's `verificationMethod`
/// indefinitely — rotation removes them from `assertionMethod` only
/// (stops new receipts, keeps every previously minted receipt
/// verifiable). Deleting an old key bricks every receipt it signed.
pub struct ReceiptSigner {
    key: acdp_crypto::sign::AcdpSigningKey,
    /// e.g. `did:web:registry.example.com#receipt-key-1`.
    key_id: String,
    /// e.g. `did:web:registry.example.com`.
    registry_did: String,
}

impl ReceiptSigner {
    /// Create a signer. `key_id`'s DID portion MUST equal
    /// `registry_did`, which MUST be the `did:web` form of the
    /// registry's serving authority.
    pub fn new(
        key: impl Into<acdp_crypto::sign::AcdpSigningKey>,
        registry_did: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Result<Self, AcdpError> {
        let registry_did = registry_did.into();
        let key_id = key_id.into();
        if !registry_did.starts_with("did:web:") {
            return Err(AcdpError::SchemaViolation(format!(
                "receipt signer registry_did must be did:web, got '{registry_did}'"
            )));
        }
        match key_id.split_once('#') {
            Some((did, frag)) if did == registry_did && !frag.is_empty() => {}
            _ => {
                return Err(AcdpError::SchemaViolation(format!(
                    "receipt signer key_id '{key_id}' must be '<registry_did>#<fragment>'"
                )));
            }
        }
        Ok(Self {
            key: key.into(),
            key_id,
            registry_did,
        })
    }

    /// The registry DID this signer mints under.
    pub fn registry_did(&self) -> &str {
        &self.registry_did
    }

    /// Mint a signed receipt for an accepted publication.
    ///
    /// `producer_key_fingerprint` MUST be the fingerprint of the key
    /// the validator *actually used* for producer-signature
    /// verification — not re-resolved later (that is the whole
    /// historical-validity guarantee).
    pub fn mint(
        &self,
        ctx_id: &CtxId,
        lineage_id: &LineageId,
        origin_registry: &str,
        created_at: DateTime<Utc>,
        content_hash: &ContentHash,
        producer_key_fingerprint: &str,
    ) -> Result<RegistryReceipt, AcdpError> {
        let mut receipt = RegistryReceipt {
            registry_did: self.registry_did.clone(),
            ctx_id: ctx_id.clone(),
            lineage_id: lineage_id.clone(),
            origin_registry: origin_registry.to_string(),
            created_at: acdp_primitives::time::trunc_ms(created_at),
            content_hash: content_hash.clone(),
            key_fingerprint: producer_key_fingerprint.to_string(),
            signature: Signature {
                algorithm: self.key.algorithm().into(),
                key_id: self.key_id.clone(),
                value: String::new(), // filled below
            },
        };
        let hash = receipt.preimage_hash()?;
        let (algorithm, value) = self.key.sign_content_hash(&hash);
        receipt.signature.algorithm = algorithm.into();
        receipt.signature.value = value;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_crypto::SigningKey;

    fn test_signer() -> ReceiptSigner {
        ReceiptSigner::new(
            SigningKey::from_bytes(&[1u8; 32]),
            "did:web:registry.example.com",
            "did:web:registry.example.com#receipt-key-1",
        )
        .unwrap()
    }

    fn test_receipt() -> RegistryReceipt {
        test_signer()
            .mint(
                &CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into()),
                &LineageId(format!("lin:sha256:{}", "a".repeat(64))),
                "registry.example.com",
                chrono::DateTime::parse_from_rfc3339("2026-06-12T10:30:15.123Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                &ContentHash(format!("sha256:{}", "b".repeat(64))),
                "sha256:cafe0000000000000000000000000000000000000000000000000000000000ff",
            )
            .unwrap()
    }

    fn registry_pub() -> [u8; 32] {
        SigningKey::from_bytes(&[1u8; 32]).verifying_key_bytes()
    }

    #[test]
    fn mint_verify_round_trip() {
        let receipt = test_receipt();
        receipt
            .verify_signature_with_key(Some(&registry_pub()), None)
            .expect("freshly minted receipt must verify");
    }

    #[test]
    fn tampered_fields_fail_verification() {
        // rcpt-002-style: any mutated bound field breaks the signature.
        let pubkey = registry_pub();
        let mut r = test_receipt();
        r.created_at += chrono::Duration::milliseconds(1);
        assert!(r.verify_signature_with_key(Some(&pubkey), None).is_err());

        let mut r = test_receipt();
        r.ctx_id = CtxId("acdp://evil.example.com/12345678-1234-4321-8123-123456781234".into());
        assert!(r.verify_signature_with_key(Some(&pubkey), None).is_err());

        let mut r = test_receipt();
        r.key_fingerprint = format!("sha256:{}", "0".repeat(64));
        assert!(r.verify_signature_with_key(Some(&pubkey), None).is_err());
    }

    /// RFC-ACDP-0010 §4: the receipt schema is CLOSED. A receipt
    /// carrying an unknown member MUST be rejected at parse time.
    #[test]
    fn unknown_receipt_fields_rejected() {
        let mut wire = serde_json::to_value(test_receipt()).unwrap();
        wire.as_object_mut()
            .unwrap()
            .insert("transparency_log_index".into(), serde_json::json!(42));
        let err = RegistryReceipt::from_value(&wire).unwrap_err();
        assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");
    }

    /// Raw-JSON preimage equals the struct preimage for a minted
    /// receipt, and the fixed three-digit-millisecond `created_at`
    /// serialization survives a parse → re-serialize round trip even
    /// for whole-second timestamps (chrono would otherwise drop the
    /// `.000`).
    #[test]
    fn raw_and_struct_preimages_agree_incl_whole_second() {
        let receipt = test_receipt();
        let wire = serde_json::to_value(&receipt).unwrap();
        assert_eq!(
            RegistryReceipt::preimage_hash_of_value(&wire).unwrap(),
            receipt.preimage_hash().unwrap()
        );
        RegistryReceipt::validate_created_at_form(&wire).unwrap();

        // Whole-second created_at: serialization MUST keep `.000`.
        let signer = test_signer();
        let r = signer
            .mint(
                &receipt.ctx_id,
                &receipt.lineage_id,
                "registry.example.com",
                chrono::DateTime::parse_from_rfc3339("2026-06-12T09:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                &receipt.content_hash,
                &receipt.key_fingerprint,
            )
            .unwrap();
        let wire = serde_json::to_value(&r).unwrap();
        assert_eq!(wire["created_at"], "2026-06-12T09:00:00.000Z");
        RegistryReceipt::validate_created_at_form(&wire).unwrap();
        let parsed = RegistryReceipt::from_value(&wire).unwrap();
        parsed
            .verify_signature_with_key(Some(&registry_pub()), None)
            .expect("whole-second receipt must round-trip and verify");
    }

    #[test]
    fn cross_checks_fire() {
        let r = test_receipt();
        let ctx = r.ctx_id.clone();
        let hash = r.content_hash.clone();
        let fp = r.key_fingerprint.clone();

        r.cross_check(&ctx, &hash, &fp).expect("all aligned");

        // rcpt-004-style: wrong ctx_id.
        let other =
            CtxId("acdp://registry.example.com/aaaaaaaa-1234-4321-8123-123456781234".into());
        assert!(matches!(
            r.cross_check(&other, &hash, &fp).unwrap_err(),
            AcdpError::InvalidReceipt(_)
        ));
        // rcpt-003-style: fingerprint mismatch.
        assert!(r
            .cross_check(&ctx, &hash, &format!("sha256:{}", "9".repeat(64)))
            .is_err());
        // Body-hash mismatch.
        assert!(r
            .cross_check(
                &ctx,
                &ContentHash(format!("sha256:{}", "c".repeat(64))),
                &fp
            )
            .is_err());
    }

    #[test]
    fn signer_rejects_malformed_identity() {
        assert!(ReceiptSigner::new(
            SigningKey::from_bytes(&[1u8; 32]),
            "did:key:zNotWeb",
            "did:key:zNotWeb#k",
        )
        .is_err());
        assert!(ReceiptSigner::new(
            SigningKey::from_bytes(&[1u8; 32]),
            "did:web:registry.example.com",
            "did:web:other.example.com#k",
        )
        .is_err());
        assert!(ReceiptSigner::new(
            SigningKey::from_bytes(&[1u8; 32]),
            "did:web:registry.example.com",
            "did:web:registry.example.com",
        )
        .is_err());
    }
}
