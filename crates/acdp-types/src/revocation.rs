//! Producer key-revocation signal (ACDP 0.3, RFC-ACDP-0014).
//!
//! A revocation is not a new wire object: it is an ordinary signed,
//! permanent, content-addressed [`Body`] of type `key-revocation`
//! (interim pre-0.3.0 form: `acdp:key-revocation`) whose metadata
//! declares a key compromised **as of a stated time**. This module is
//! the typed view over that metadata: [`KeyRevocation::from_body`]
//! enforces the §4 shape rules and derives the §5/§6 trust class, and
//! [`effective_boundary`] applies the §4 earliest-`compromised_since`
//! rule across a set of revocations.
//!
//! Parsing a revocation does NOT verify it. A **verified revocation**
//! additionally requires the strict RFC-ACDP-0001 §5.11 body pipeline
//! plus the §5 not-self-signed check
//! ([`KeyRevocation::check_not_self_signed`]) against the *resolved*
//! signing key's fingerprint — `acdp-client` wires the full pipeline.

use crate::body::Body;
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::{AgentDid, Visibility};
use acdp_primitives::time::fmt_rfc3339_ms;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum length of `metadata.reason` (RFC-ACDP-0014 §4).
pub const MAX_REASON_CHARS: usize = 1024;

/// The two trust classes of RFC-ACDP-0014 §5–§6. They carry different
/// authority and MUST be reported distinguishably — never collapsed
/// (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTrustClass {
    /// Signed by the producer's own current, non-revoked key (§5): the
    /// stronger class, backed by the same trust anchor as every ACDP
    /// body. Consumers act on it without further judgment (§7).
    ProducerSigned,
    /// Published under the registry's identity on the producer's
    /// behalf after an out-of-band identity check (§6): the weaker,
    /// lost-everything fallback. It imports registry trust — a hostile
    /// or deceived registry can fabricate one. Strict-profile default:
    /// apply §7 only for contexts served by or receipted by that same
    /// registry; seek corroboration before applying it globally.
    RegistryAttested,
}

/// Typed, shape-validated view of a `key-revocation` context body
/// (RFC-ACDP-0014 §4).
///
/// Obtain via [`KeyRevocation::from_body`]. Field semantics:
///
/// - The **fingerprint is authoritative**; `revoked_key_id` is human
///   traceability only (§4).
/// - `compromised_since` is the compromise boundary **T**: signatures
///   made strictly before T are attributable to the producer; at or
///   after T they are not (§7). Across a superseding revocation
///   lineage the *earliest* T is effective (§4, [`effective_boundary`]).
/// - A revocation is permanent — there is no un-revoking. Consumers
///   SHOULD cache verified revocations indefinitely (§7); the type is
///   serde-serializable for exactly that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRevocation {
    /// RFC-ACDP-0010 §6 fingerprint of the revoked public key
    /// (`sha256:` + 64 lowercase hex), byte-for-byte the encoding
    /// receipts record. Authoritative over `revoked_key_id`.
    pub revoked_key_fingerprint: String,
    /// The compromise boundary T (canonical millisecond RFC 3339 UTC
    /// on the wire).
    pub compromised_since: DateTime<Utc>,
    /// Optional human-readable circumstances (≤ 1024 chars).
    /// Informational only — apply output hygiene before display
    /// (RFC-ACDP-0014 §13).
    pub reason: Option<String>,
    /// Optional DID URL of the revoked verification method. On any
    /// disagreement with the fingerprint, the fingerprint governs.
    pub revoked_key_id: Option<String>,
    /// The producer DID that controls the revoked key. Defaults to the
    /// body's `agent_id` when the metadata field is absent
    /// (producer-signed form); on registry-attested revocations it
    /// names the affected producer while `agent_id` is the registry.
    pub revoked_key_controller: AgentDid,
    /// The body's `agent_id` — the identity the revocation was
    /// published under (the producer for [`RevocationTrustClass::ProducerSigned`],
    /// the registry for [`RevocationTrustClass::RegistryAttested`]).
    pub publisher: AgentDid,
    /// §5/§6 trust class, derived from the controller binding:
    /// `revoked_key_controller` absent or equal to `agent_id` ⇒
    /// producer-signed; different ⇒ registry-attested. MUST NOT be
    /// collapsed when reporting (§6). For a registry-attested claim the
    /// caller still owns confirming that `publisher` really is the DID
    /// of a registry it talks to — see
    /// [`Self::cross_check_registry_binding`].
    pub trust_class: RevocationTrustClass,
}

impl KeyRevocation {
    /// Parse and shape-validate a `key-revocation` context body per
    /// RFC-ACDP-0014 §4.
    ///
    /// Enforced here (violations are [`AcdpError::SchemaViolation`], the
    /// code a 0.3.0 registry rejects them with at publish):
    ///
    /// - `type` is `key-revocation` (or the §10 interim
    ///   `acdp:key-revocation`).
    /// - `visibility` is `public` — an audience-restricted revocation
    ///   protects nobody outside the audience.
    /// - `metadata.revoked_key_fingerprint` present, in the
    ///   RFC-ACDP-0010 §6 form `sha256:` + 64 lowercase hex.
    /// - `metadata.compromised_since` present, canonical
    ///   millisecond-precision RFC 3339 UTC (RFC-ACDP-0001 §5.3).
    /// - `metadata.reason`, when present, ≤ 1024 characters.
    /// - `metadata.revoked_key_controller`, when present, a valid DID.
    ///
    /// Additionally, when the signing key's fingerprint is derivable
    /// *purely* from the body (a `did:key` signer), the §5 step 2
    /// not-self-signed rule is enforced here too. For `did:web` signers
    /// the fingerprint requires DID resolution: callers MUST follow up
    /// with [`Self::check_not_self_signed`] against the resolved
    /// fingerprint (`acdp-client`'s revocation pipeline does).
    ///
    /// This does NOT verify the body's hash or signature — a parsed
    /// revocation is untrusted until the strict §5.11 pipeline passes.
    pub fn from_body(body: &Body) -> Result<Self, AcdpError> {
        if !body.context_type.is_key_revocation() {
            return Err(AcdpError::SchemaViolation(format!(
                "not a key-revocation context: type is '{}' (RFC-ACDP-0014 §4 requires \
                 'key-revocation', or 'acdp:key-revocation' in the pre-0.3.0 interim form)",
                serde_json::to_value(&body.context_type)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            )));
        }
        if body.visibility != Visibility::Public {
            return Err(AcdpError::SchemaViolation(
                "a key-revocation context MUST be visibility 'public' — it is a safety \
                 broadcast; an audience-restricted revocation protects nobody outside the \
                 audience (RFC-ACDP-0014 §4)"
                    .into(),
            ));
        }

        let meta = body
            .metadata
            .as_ref()
            .and_then(|m| m.as_object())
            .ok_or_else(|| {
                AcdpError::SchemaViolation(
                    "key-revocation body has no metadata object; \
                     metadata.revoked_key_fingerprint and metadata.compromised_since are \
                     REQUIRED (RFC-ACDP-0014 §4)"
                        .into(),
                )
            })?;

        let fingerprint = required_str(meta, "revoked_key_fingerprint")?;
        if !is_sha256_fingerprint(fingerprint) {
            return Err(AcdpError::SchemaViolation(format!(
                "metadata.revoked_key_fingerprint '{fingerprint}' is not in the \
                 RFC-ACDP-0010 §6 form 'sha256:' + 64 lowercase hex (RFC-ACDP-0014 §4)"
            )));
        }

        let since_raw = required_str(meta, "compromised_since")?;
        let compromised_since = parse_canonical_ms(since_raw).ok_or_else(|| {
            AcdpError::SchemaViolation(format!(
                "metadata.compromised_since '{since_raw}' is not canonical \
                 millisecond-precision RFC 3339 UTC (RFC-ACDP-0001 §5.3, RFC-ACDP-0014 §4)"
            ))
        })?;

        let reason = optional_str(meta, "reason")?;
        if let Some(r) = &reason {
            if r.chars().count() > MAX_REASON_CHARS {
                return Err(AcdpError::SchemaViolation(format!(
                    "metadata.reason exceeds {MAX_REASON_CHARS} characters (RFC-ACDP-0014 §4)"
                )));
            }
        }
        let revoked_key_id = optional_str(meta, "revoked_key_id")?;

        let (revoked_key_controller, trust_class) =
            match optional_str(meta, "revoked_key_controller")? {
                None => (body.agent_id.clone(), RevocationTrustClass::ProducerSigned),
                Some(c) => {
                    let controller = AgentDid::parse(&c)?;
                    if controller == body.agent_id {
                        // §5 rule 3: present-and-equal is the explicit
                        // producer-signed controller binding.
                        (controller, RevocationTrustClass::ProducerSigned)
                    } else {
                        // §6: published under another identity (the
                        // registry's) on the controller's behalf.
                        (controller, RevocationTrustClass::RegistryAttested)
                    }
                }
            };

        let revocation = KeyRevocation {
            revoked_key_fingerprint: fingerprint.to_string(),
            compromised_since,
            reason,
            revoked_key_id,
            revoked_key_controller,
            publisher: body.agent_id.clone(),
            trust_class,
        };

        // §5 step 2, pure sub-case: a did:key signer's fingerprint is
        // derivable from the key_id itself with no resolution. A
        // malformed did:key key_id is left for signature verification
        // to reject — this check is best-effort by design.
        if body.signature.key_id.starts_with("did:key:") {
            if let Ok(material) = acdp_did::key::resolve_did_key_url(&body.signature.key_id) {
                if let Ok(fp) = acdp_crypto::fingerprint::fingerprint_did_key_material(&material) {
                    revocation.check_not_self_signed(&fp)?;
                }
            }
        }

        Ok(revocation)
    }

    /// RFC-ACDP-0014 §5 step 2 — the revocation MUST NOT be signed by
    /// the very key it revokes: such a statement proves only possession
    /// of the (by hypothesis, attacker-held) key. Registries at ≥ 0.3.0
    /// reject the publish with `key_not_authorized`; consumers MUST
    /// treat one as **unverified** (at most a hint to seek a real
    /// signal).
    ///
    /// `signing_key_fingerprint` is the RFC-ACDP-0010 §6 fingerprint of
    /// the *resolved* key that signed the revocation body (see
    /// `acdp_crypto::fingerprint`).
    pub fn check_not_self_signed(&self, signing_key_fingerprint: &str) -> Result<(), AcdpError> {
        if signing_key_fingerprint == self.revoked_key_fingerprint {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "revocation of key {} is signed by that same key — a key is not \
                 authorized to attest its own compromise; treat as unverified \
                 (RFC-ACDP-0014 §5 step 2)",
                self.revoked_key_fingerprint
            )));
        }
        Ok(())
    }

    /// True when this revocation applies to the given signing-key
    /// fingerprint (RFC-ACDP-0010 §6 encoding, exact match).
    pub fn revokes(&self, key_fingerprint: &str) -> bool {
        self.revoked_key_fingerprint == key_fingerprint
    }

    /// Registry-attestation binding (pure): `publisher` — the identity
    /// this revocation was actually published under — MUST equal both
    /// `did:web:<serving_authority>` (the authority the context was
    /// actually fetched from, not whatever the body claims) AND the
    /// serving registry's advertised `capabilities.registry_did`. The
    /// two halves have different citations: the `registry_did` half is
    /// RFC-ACDP-0014 §6 step 2; the `serving_authority` half is not a
    /// §6 step at all — it is the ACDP-wide `registry_did`↔authority
    /// invariant of RFC-ACDP-0011 §7 step 3 / RFC-ACDP-0012 §9.3 step 3
    /// (the two house-pattern siblings), applied here to key
    /// revocations.
    ///
    /// A [`RevocationTrustClass::RegistryAttested`] revocation imports
    /// its authority entirely from *who published it* — §5 body
    /// verification alone only proves the body is genuinely signed by
    /// `publisher`'s current key, not that `publisher` is the specific
    /// registry a caller actually talks to. Without this check a
    /// consumer could apply a registry-attested revocation on the say-so
    /// of any producer willing to name someone else as
    /// `revoked_key_controller`; this pins `publisher` to the one
    /// registry both the transport (`serving_authority`) and the
    /// registry's own self-description (`capabilities_registry_did`)
    /// agree on.
    ///
    /// Pure — no DID resolution or network I/O — so it stays exposable
    /// from the language bindings.
    pub fn cross_check_registry_binding(
        &self,
        serving_authority: &str,
        capabilities_registry_did: &str,
    ) -> Result<(), AcdpError> {
        let expected_did = acdp_did::web::authority_to_did_web(serving_authority);
        if self.publisher.as_str() != expected_did {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "key-revocation publisher '{}' ≠ serving authority's DID '{expected_did}' \
                 (RFC-ACDP-0014 §6 steps 2–3)",
                self.publisher
            )));
        }
        if self.publisher.as_str() != capabilities_registry_did {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "key-revocation publisher '{}' ≠ capabilities.registry_did \
                 '{capabilities_registry_did}' (RFC-ACDP-0014 §6 steps 2–3)",
                self.publisher
            )));
        }
        Ok(())
    }
}

/// The effective compromise boundary for `key_fingerprint` across a set
/// of (verified) revocations: the **earliest** `compromised_since`
/// among those that name the fingerprint, or `None` when none does.
///
/// This is the RFC-ACDP-0014 §4 monotonicity rule: a superseding
/// revocation may widen — never narrow — the compromise window, so a
/// supersession can never quietly shrink it. Feed every revocation of a
/// lineage (including superseded ones) through this, not just the head.
pub fn effective_boundary<'a>(
    revocations: impl IntoIterator<Item = &'a KeyRevocation>,
    key_fingerprint: &str,
) -> Option<DateTime<Utc>> {
    revocations
        .into_iter()
        .filter(|r| r.revokes(key_fingerprint))
        .map(|r| r.compromised_since)
        .min()
}

fn required_str<'m>(
    meta: &'m serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'m str, AcdpError> {
    meta.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
        AcdpError::SchemaViolation(format!(
            "key-revocation metadata.{key} is REQUIRED and must be a string \
             (RFC-ACDP-0014 §4)"
        ))
    })
}

fn optional_str(
    meta: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>, AcdpError> {
    match meta.get(key) {
        None => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(AcdpError::SchemaViolation(format!(
            "key-revocation metadata.{key} must be a string when present (RFC-ACDP-0014 §4)"
        ))),
    }
}

/// `sha256:` + exactly 64 lowercase hex digits (RFC-ACDP-0010 §6).
fn is_sha256_fingerprint(s: &str) -> bool {
    match s.strip_prefix("sha256:") {
        Some(hex) => {
            hex.len() == 64
                && hex
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        }
        None => false,
    }
}

/// Parse a timestamp REQUIRING the canonical millisecond RFC 3339 UTC
/// form `YYYY-MM-DDTHH:MM:SS.mmmZ` (RFC-ACDP-0001 §5.3): the string
/// must round-trip byte-identically through the canonical formatter.
fn parse_canonical_ms(raw: &str) -> Option<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(raw).ok()?.with_timezone(&Utc);
    (fmt_rfc3339_ms(parsed) == raw).then_some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_attested_rev(publisher: &str) -> KeyRevocation {
        KeyRevocation {
            revoked_key_fingerprint: format!("sha256:{}", "a1".repeat(32)),
            compromised_since: parse_canonical_ms("2026-05-01T00:00:00.000Z").unwrap(),
            reason: None,
            revoked_key_id: None,
            revoked_key_controller: AgentDid::new("did:web:agents.example.com:producer"),
            publisher: AgentDid::new(publisher),
            trust_class: RevocationTrustClass::RegistryAttested,
        }
    }

    /// RFC-ACDP-0014 §6 steps 2–3: `publisher` must equal both the
    /// serving authority's DID and `capabilities.registry_did`. All
    /// aligned ⇒ `Ok`; either mismatch ⇒ `Err(KeyNotAuthorized)`.
    #[test]
    fn cross_check_registry_binding_success_and_both_failure_directions() {
        let rev = registry_attested_rev("did:web:registry.example.com");

        rev.cross_check_registry_binding("registry.example.com", "did:web:registry.example.com")
            .expect("serving authority and capabilities.registry_did both match publisher");

        // Wrong serving authority.
        assert!(matches!(
            rev.cross_check_registry_binding("hostile.example", "did:web:registry.example.com"),
            Err(AcdpError::KeyNotAuthorized(_))
        ));

        // Wrong capabilities.registry_did.
        assert!(matches!(
            rev.cross_check_registry_binding("registry.example.com", "did:web:other.example"),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
    }

    /// `did:web:localhost%3A8443` — the percent-encoded-port form
    /// `authority_to_did_web` produces for a `host:port` authority
    /// (RFC-ACDP-0014 §6 steps 2–3; live in this codebase's own test
    /// harness, which binds ephemeral ports, not merely hypothetical).
    #[test]
    fn cross_check_registry_binding_percent_encoded_port_authority() {
        let rev = registry_attested_rev("did:web:localhost%3A8443");

        rev.cross_check_registry_binding("localhost:8443", "did:web:localhost%3A8443")
            .expect("host:port authority round-trips through authority_to_did_web");

        // A bare-hostname serving authority (no port) must NOT match a
        // publisher bound to the port-bearing form.
        assert!(matches!(
            rev.cross_check_registry_binding("localhost", "did:web:localhost%3A8443"),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
    }

    #[test]
    fn fingerprint_form_edges() {
        assert!(is_sha256_fingerprint(&format!(
            "sha256:{}",
            "a1".repeat(32)
        )));
        assert!(!is_sha256_fingerprint(&format!(
            "sha256:{}",
            "A1".repeat(32)
        ))); // uppercase
        assert!(!is_sha256_fingerprint(&format!(
            "sha512:{}",
            "a1".repeat(32)
        ))); // wrong alg
        assert!(!is_sha256_fingerprint(&format!(
            "sha256:{}",
            "a1".repeat(31)
        ))); // short
        assert!(!is_sha256_fingerprint("sha256:")); // empty hex
        assert!(!is_sha256_fingerprint(&"a1".repeat(32))); // no prefix
    }

    #[test]
    fn canonical_ms_timestamp_edges() {
        assert!(parse_canonical_ms("2026-05-01T00:00:00.000Z").is_some());
        // Non-canonical forms MUST be rejected even when RFC 3339-valid.
        for bad in [
            "2026-05-01T00:00:00Z",          // no fractional part
            "2026-05-01T00:00:00.0Z",        // 1 digit
            "2026-05-01T00:00:00.000000Z",   // microseconds
            "2026-05-01T00:00:00.000+00:00", // offset spelling
            "2026-05-01 00:00:00.000Z",      // space separator
            "not-a-time",
        ] {
            assert!(
                parse_canonical_ms(bad).is_none(),
                "{bad:?} must be rejected"
            );
        }
    }
}
