//! Consumer-side key-revocation semantics (ACDP 0.3, RFC-ACDP-0014).
//!
//! Three layers:
//!
//! - [`classify_under_revocation`] — the pure §7 boundary rule: given
//!   verified revocations and a (receipt-attested) publish time,
//!   decide *historically authorized (pre-compromise, receipt-attested)*
//!   vs fail-closed. This is what
//!   [`VerificationPolicy::revocations`](crate::VerificationPolicy)
//!   drives inside the fetch pipeline.
//! - [`verify_revocation_body`] — the §5 verification pipeline for a
//!   revocation context itself: strict RFC-ACDP-0001 §5.11 body
//!   verification, §4 shape parse, and the §5 step 2 not-self-signed
//!   check against the resolved signing key's fingerprint.
//! - [`find_revocations`] — the §8 discovery SHOULD: search a registry
//!   for a producer's revocation contexts and return the ones that
//!   verify.

use acdp_crypto::fingerprint::fingerprint_for_key_id;
use acdp_did::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::body::Body;
use acdp_types::primitives::AgentDid;
use acdp_types::revocation::{effective_boundary, KeyRevocation};
use acdp_types::search::SearchParamsBuilder;
use acdp_verify::Verifier;
use chrono::{DateTime, Utc};

use super::registry::RegistryClient;
use super::verified::KeyAuthorization;

/// Pagination safety cap for [`find_revocations`] — a hostile registry
/// must not be able to hold the helper in an endless cursor loop.
const MAX_SEARCH_PAGES: usize = 10;

/// Apply the RFC-ACDP-0014 §7 compromise-boundary rule.
///
/// Inputs:
///
/// - `revocations` — **verified** revocations the consumer has decided
///   to act on (see [`RevocationPolicy`](crate::RevocationPolicy) for
///   the §6 trust-class guidance). The §4 earliest-`compromised_since`
///   rule is applied across every entry naming the fingerprint.
/// - `signing_key_fingerprint` — the RFC-ACDP-0010 §6 fingerprint of
///   the key that signed the context under verification.
/// - `receipt_attested_created_at` — `created_at` from a registry
///   receipt **verified per RFC-ACDP-0010 §8** (whose step 5 confirms
///   the receipt attests this same fingerprint), or `None` when there
///   is no verified receipt. The bare body `created_at` MUST NOT be
///   passed here — it is registry-assigned, unsigned by the producer,
///   and attacker-backdatable (§7 step 1).
///
/// Verdicts:
///
/// - `Ok(None)` — no supplied revocation names this key; the ordinary
///   verification rules apply unchanged.
/// - `Ok(Some(`[`KeyAuthorization::HistoricallyAuthorizedPreCompromise`]`))`
///   — publish time strictly before the boundary (§7 step 2). The
///   caller must still verify the signature itself, under the
///   RFC-ACDP-0010 §10 historical rule.
/// - `Err(`[`AcdpError::KeyNotAuthorized`]`)` — fail closed: publish
///   time at/after the boundary (§7 step 3), or no verifiable publish
///   time at all (§7 step 4). Per RFC-ACDP-0014 §10 this is a
///   verification verdict, not a wire condition — there is no new wire
///   error code; the key is simply not authorized to speak for the
///   producer in (or without placement relative to) the compromise
///   window.
pub fn classify_under_revocation(
    revocations: &[KeyRevocation],
    signing_key_fingerprint: &str,
    receipt_attested_created_at: Option<DateTime<Utc>>,
) -> Result<Option<KeyAuthorization>, AcdpError> {
    let Some(boundary) = effective_boundary(revocations, signing_key_fingerprint) else {
        return Ok(None);
    };
    match receipt_attested_created_at {
        Some(created_at) if created_at < boundary => {
            Ok(Some(KeyAuthorization::HistoricallyAuthorizedPreCompromise))
        }
        Some(created_at) => Err(AcdpError::KeyNotAuthorized(format!(
            "signing key {signing_key_fingerprint} is revoked with compromise boundary \
             {}; the receipt-attested publish time {} is at/after the boundary, so the \
             signature is not attributable to the producer — fail closed regardless of \
             DID-document state or receipt validity (RFC-ACDP-0014 §7 step 3)",
            boundary.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            created_at.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        ))),
        None => Err(AcdpError::KeyNotAuthorized(format!(
            "signing key {signing_key_fingerprint} is revoked (compromise boundary {}) \
             and the context has no verified registry receipt, so its publish time \
             cannot be placed relative to the boundary — an unplaceable revoked-key \
             signature is exactly the artifact an attacker mints freely; the strict \
             profile fails closed (RFC-ACDP-0014 §7 step 4)",
            boundary.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        ))),
    }
}

/// Verify a `key-revocation` context body per RFC-ACDP-0014 §5 and
/// return its typed, trust-classified form.
///
/// Pipeline:
///
/// 1. Strict RFC-ACDP-0001 §5.11 body verification (schema, hash
///    recomputation, DID resolution, `assertionMethod` authorization,
///    signature) — §5 step 1's "signed by a currently authorized key".
/// 2. §4 shape parse + §5/§6 trust-class derivation
///    ([`KeyRevocation::from_body`]).
/// 3. §5 step 2 — the resolved signing key's fingerprint MUST NOT
///    equal `revoked_key_fingerprint`
///    ([`KeyRevocation::check_not_self_signed`]).
///
/// Note the §5 step 1 nuance this strict form does not cover: a
/// revocation whose own signing key was later rotated out *cleanly*
/// remains acceptable via the RFC-ACDP-0010 §10 receipt-attested
/// historical rule — fetch it through
/// [`VerifiedContext::fetch_with_policy`](crate::VerifiedContext::fetch_with_policy)
/// (default policy) and parse the body afterwards for that case.
///
/// The returned trust class MUST be honored per §6: act on
/// producer-signed revocations unconditionally; treat registry-attested
/// ones as the weaker class (verify that `publisher` is in fact the DID
/// of the registry involved, and corroborate before global use).
pub async fn verify_revocation_body(
    body: &Body,
    resolver: &WebResolver,
) -> Result<KeyRevocation, AcdpError> {
    Verifier::new(resolver).verify_body(body).await?;
    let revocation = KeyRevocation::from_body(body)?;
    let signer_fingerprint =
        fingerprint_for_key_id(&body.signature.key_id, &body.signature.algorithm, resolver).await?;
    revocation.check_not_self_signed(&signer_fingerprint)?;
    Ok(revocation)
}

/// Discover a producer's key revocations on a registry
/// (RFC-ACDP-0014 §8): search `type=key-revocation` (and the §10
/// interim `acdp:key-revocation`) with `agent_id=<producer>`, retrieve
/// each match, and return the ones that verify per §5
/// ([`verify_revocation_body`]). Candidates that fail verification —
/// including self-signed "revocations", which are at most a hint (§5
/// step 2) — are skipped, not errors. Superseded revocations are
/// queried too: the §4 earliest-boundary rule needs the whole lineage.
///
/// **The honest caveat (§8):** search is served by the registry, and a
/// malicious registry can hide a revocation exactly as it can hide any
/// context — an empty result is *not* evidence of absence, and a
/// registry colluding with a key thief can serve the stolen key's
/// contexts while suppressing this signal. Within the protocol the
/// systemic mitigation is the RFC-ACDP-0009 §2.11 append-only
/// transparency log (RFC-ACDP-0012); until it is deployed, query more
/// than one vantage where the stakes warrant it, and remember that
/// revocations are self-contained signed contexts — out-of-band
/// delivery verifies identically and is the one channel a registry
/// cannot suppress.
///
/// Registry-attested revocations (§6) are published under the
/// *registry's* DID, not the producer's, so this producer-scoped query
/// does not find them — search the registry's own `agent_id` and match
/// `revoked_key_controller` client-side for those.
pub async fn find_revocations(
    client: &RegistryClient,
    resolver: &WebResolver,
    agent_id: &AgentDid,
) -> Result<Vec<KeyRevocation>, AcdpError> {
    let mut revocations = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for type_form in ["key-revocation", "acdp:key-revocation"] {
        // Revocations are permanent but supersedable; the registry
        // defaults search to status=active, so ask for both explicitly.
        for status in ["active", "superseded"] {
            let mut params = SearchParamsBuilder::new()
                .context_type(type_form)
                .agent_id(agent_id.as_str())
                .status(status)
                .limit(100)
                .build();
            for _page in 0..MAX_SEARCH_PAGES {
                let resp = client.search(&params).await?;
                for m in &resp.matches {
                    if !seen.insert(m.ctx_id.as_str().to_string()) {
                        continue;
                    }
                    let ctx = client.retrieve(&m.ctx_id).await?;
                    if let Ok(rev) = verify_revocation_body(&ctx.body, resolver).await {
                        revocations.push(rev);
                    }
                }
                match resp.next_cursor {
                    Some(cursor) => params.cursor = Some(cursor),
                    None => break,
                }
            }
        }
    }
    Ok(revocations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_types::revocation::RevocationTrustClass;
    use chrono::TimeZone;

    fn rev(fp: &str, t: DateTime<Utc>) -> KeyRevocation {
        KeyRevocation {
            revoked_key_fingerprint: fp.into(),
            compromised_since: t,
            reason: None,
            revoked_key_id: None,
            revoked_key_controller: AgentDid::new("did:web:agents.example.com:p"),
            publisher: AgentDid::new("did:web:agents.example.com:p"),
            trust_class: RevocationTrustClass::ProducerSigned,
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    const F: &str = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070";

    /// §7 step 2: strictly-before-T verifies with the distinguishable
    /// pre-compromise status; §7 step 3: equal-to-T already fails.
    #[test]
    fn boundary_is_strict() {
        let t = at("2026-05-01T00:00:00.000Z");
        let revs = [rev(F, t)];
        assert_eq!(
            classify_under_revocation(&revs, F, Some(at("2026-04-30T23:59:59.999Z"))).unwrap(),
            Some(KeyAuthorization::HistoricallyAuthorizedPreCompromise)
        );
        assert!(matches!(
            classify_under_revocation(&revs, F, Some(t)),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
    }

    /// §7 step 4: no receipt-attested time → fail closed.
    #[test]
    fn no_receipt_fails_closed() {
        let revs = [rev(F, at("2026-05-01T00:00:00.000Z"))];
        assert!(matches!(
            classify_under_revocation(&revs, F, None),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
    }

    /// A revocation of some OTHER key changes nothing.
    #[test]
    fn unrelated_fingerprint_is_inert() {
        let revs = [rev(F, at("2026-05-01T00:00:00.000Z"))];
        let other = "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f";
        assert_eq!(classify_under_revocation(&revs, other, None).unwrap(), None);
        assert_eq!(
            classify_under_revocation(&[], F, None).unwrap(),
            None,
            "no known revocations ⇒ inert"
        );
    }

    /// §4 monotonicity: the earliest T across a revocation lineage is
    /// effective — a later supersession cannot quietly shrink the
    /// window.
    #[test]
    fn earliest_boundary_wins() {
        let early = at("2026-04-01T00:00:00.000Z");
        let late = at("2026-05-01T00:00:00.000Z");
        let revs = [rev(F, late), rev(F, early)];
        // Between the two boundaries: inside the (earliest-T) window.
        assert!(matches!(
            classify_under_revocation(&revs, F, Some(at("2026-04-15T00:00:00.000Z"))),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
        // Before both: pre-compromise.
        assert_eq!(
            classify_under_revocation(&revs, F, Some(at("2026-03-01T00:00:00.000Z"))).unwrap(),
            Some(KeyAuthorization::HistoricallyAuthorizedPreCompromise)
        );
    }

    #[test]
    fn pre_compromise_uses_millis() {
        // Sub-second boundaries compare at millisecond precision — the
        // canonical wire precision (RFC-ACDP-0001 §5.3).
        let t = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap()
            + chrono::Duration::milliseconds(500);
        let revs = [rev(F, t)];
        let just_before = t - chrono::Duration::milliseconds(1);
        assert_eq!(
            classify_under_revocation(&revs, F, Some(just_before)).unwrap(),
            Some(KeyAuthorization::HistoricallyAuthorizedPreCompromise)
        );
    }
}
