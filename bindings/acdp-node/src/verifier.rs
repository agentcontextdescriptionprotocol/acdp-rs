//! `AcdpVerifier` — consumer-side content_hash and signature verification.
//!
//! All methods are static. DID resolution is intentionally NOT done here
//! — that requires async HTTP and belongs in JS land. This binding
//! exposes the pure-crypto checks every consumer needs, including the
//! ACDP 0.2 offline path: `did:key` bodies and publish requests verify
//! with no network at all, and registry receipts verify against a
//! caller-resolved registry key.

//! ACDP 0.3 adds the offline verdict surface (documents supplied by
//! the caller, never fetched here): `verifyLineageHeadReceipt`
//! (RFC-ACDP-0011 §7), `verifyLogCheckpoint` / `verifyLogInclusion` /
//! `verifyLogConsistency` / `buildLogLeaf` (RFC-ACDP-0012 §9),
//! `verifyLifecycleEvent` (RFC-ACDP-0013 §5), and
//! `parseKeyRevocation` / `classifyUnderRevocation` (RFC-ACDP-0014
//! §4–§7). The 0.3 `verify*` methods return JSON **verdict strings**
//! (`{"valid": true, ...}` / `{"valid": false, "code": ..., "error":
//! ...}`) instead of throwing on verification failure — a failed
//! verification is a result to report, not a host programming error.
//! Only malformed host input throws.

use acdp::crypto::{
    canonical_preimage, explain_hash_mismatch, fingerprint_ed25519, verify_body_offline,
    verify_content_hash, verify_ecdsa_p256, verify_ed25519,
    verify_publish_request_signature_offline,
};
use acdp::types::revocation::KeyRevocation;
use acdp::types::{Body, ContentHash, CtxId, PublishRequest, RegistryReceipt};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::errors::input_err;
use crate::v030;

/// Parse an optional RFC 3339 `now` argument, defaulting to the system
/// clock (the fixture-friendly escape hatch: golden vectors pin their
/// timestamps, so tests pass an explicit consumer clock).
fn parse_now(now_rfc3339: Option<&str>) -> std::result::Result<DateTime<Utc>, Error<String>> {
    match now_rfc3339 {
        None => Ok(Utc::now()),
        Some(raw) => DateTime::parse_from_rfc3339(raw)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| input_err(format!("invalid nowRfc3339 '{raw}': {e}"))),
    }
}

/// Parse a required JSON-object argument, throwing with the argument's
/// name on malformed input.
fn parse_json(arg: &str, what: &str) -> std::result::Result<serde_json::Value, Error<String>> {
    serde_json::from_str(arg).map_err(|e| input_err(format!("invalid {what} JSON: {e}")))
}

/// Consumer-side verification utilities. All methods are static.
#[napi]
pub struct AcdpVerifier;

#[napi]
impl AcdpVerifier {
    /// Verify that a body's `content_hash` matches the SHA-256 over
    /// its JCS-canonicalized producer-controlled fields.
    ///
    /// * `bodyJson` — the `body` object from a `FullContext` retrieval
    ///   (or the `PublishRequest` itself — both share the §5.7 layout).
    /// * `expectedHash` — the `body.content_hash` string
    ///   (`"sha256:<64-hex>"`).
    ///
    /// Returns `true` on success; throws on mismatch or bad JSON.
    #[napi]
    pub fn verify_content_hash(body_json: String, expected_hash: String) -> Result<bool> {
        let body: serde_json::Value = serde_json::from_str(&body_json)
            .map_err(|e| Error::from_reason(format!("invalid body JSON: {e}")))?;
        // Validate the hash envelope up-front so a malformed
        // `expectedHash` (wrong prefix, wrong length, uppercase hex)
        // surfaces as a clear error instead of being treated as a
        // recomputation mismatch.
        let stored = ContentHash::parse(&expected_hash)
            .map_err(|e| Error::from_reason(format!("invalid content_hash: {e}")))?;
        verify_content_hash(&body, &stored)
            .map(|_| true)
            .map_err(|e| Error::from_reason(format!("content_hash mismatch: {e}")))
    }

    /// Verify an Ed25519 signature over a `content_hash` string.
    ///
    /// The signing input per RFC-ACDP-0001 §5.8 is the ASCII bytes of
    /// the full `"sha256:<hex>"` string — NOT the raw 32-byte digest.
    ///
    /// * `pubKeyB64` — standard base64 (padded) of the 32-byte raw
    ///   Ed25519 public key (same shape as
    ///   `AcdpProducer.publicKeyB64`).
    /// * `sigB64` — the `body.signature.value` field from the wire
    ///   format.
    /// * `contentHash` — the `body.content_hash` string.
    ///
    /// Returns `true` on success; throws on failure.
    #[napi]
    pub fn verify_signature(
        pub_key_b64: String,
        sig_b64: String,
        content_hash: String,
    ) -> Result<bool> {
        let pub_bytes: Vec<u8> = STANDARD
            .decode(&pub_key_b64)
            .map_err(|e| Error::from_reason(format!("invalid pubKeyB64: {e}")))?;
        let arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| Error::from_reason("public key must decode to 32 bytes"))?;
        verify_ed25519(&arr, &sig_b64, &content_hash)
            .map(|_| true)
            .map_err(|e| Error::from_reason(format!("signature invalid: {e}")))
    }

    /// Verify an ECDSA-P256 signature over a `content_hash` string.
    ///
    /// The counterpart to `AcdpP256Producer` signing. The signing input
    /// per RFC-ACDP-0001 §5.8 is the ASCII bytes of the full
    /// `"sha256:<hex>"` string — NOT the raw 32-byte digest. The wire
    /// signature is IEEE 1363 `r‖s` (64 bytes, base64), NOT DER.
    ///
    /// * `pubKeySec1B64` — standard base64 of the 65-byte
    ///   SEC1-uncompressed public key (`0x04 || x || y`), the same shape
    ///   as `AcdpP256Producer.publicKeySec1B64`.
    /// * `sigB64` — the `body.signature.value` field from the wire
    ///   format (88-char base64 of the 64-byte `r‖s`).
    /// * `contentHash` — the `body.content_hash` string.
    ///
    /// Returns `true` on success; throws on failure.
    #[napi]
    pub fn verify_signature_p256(
        pub_key_sec1_b64: String,
        sig_b64: String,
        content_hash: String,
    ) -> Result<bool> {
        let pub_bytes: Vec<u8> = STANDARD
            .decode(&pub_key_sec1_b64)
            .map_err(|e| Error::from_reason(format!("invalid pubKeySec1B64: {e}")))?;
        verify_ecdsa_p256(&pub_bytes, &sig_b64, &content_hash)
            .map(|_| true)
            .map_err(|e| Error::from_reason(format!("signature invalid: {e}")))
    }

    /// Full offline verification of a retrieved `Body` from a `did:key`
    /// producer (ACDP 0.2) — structural validation, `content_hash`
    /// recomputation, key_id/agent_id binding, and signature check, all
    /// with no network.
    ///
    /// * `bodyJson` — the `body` object from a `FullContext` retrieval
    ///   (the registry-assigned fields must be present).
    ///
    /// Throws for `did:web` bodies — those need DID-document
    /// resolution, which stays in JS land (resolve via `AcdpDid.webToUrl`
    /// + `fetch`, then use `verifySignature`).
    ///
    /// Returns `true` on success; throws on any failure.
    #[napi]
    pub fn verify_body_offline(body_json: String) -> Result<bool> {
        let body: Body = serde_json::from_str(&body_json)
            .map_err(|e| Error::from_reason(format!("invalid body JSON: {e}")))?;
        verify_body_offline(&body)
            .map(|_| true)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Offline verification of a `PublishRequest` from a `did:key`
    /// producer (ACDP 0.2): recomputes the `content_hash` over the
    /// request's producer-controlled fields, then verifies the
    /// signature against the key embedded in the `did:key` itself.
    ///
    /// * `requestJson` — the full PublishRequest wire JSON (e.g. the
    ///   string `buildPublishRequest` returned).
    ///
    /// Throws for non-`did:key` requests — `did:web` verification needs
    /// DID resolution, which stays in JS land by design.
    ///
    /// Returns `true` on success; throws on any failure.
    #[napi]
    pub fn verify_publish_request_offline(request_json: String) -> Result<bool> {
        let value: serde_json::Value = serde_json::from_str(&request_json)
            .map_err(|e| Error::from_reason(format!("invalid request JSON: {e}")))?;
        let req: PublishRequest = serde_json::from_value(value.clone())
            .map_err(|e| Error::from_reason(format!("invalid PublishRequest: {e}")))?;
        verify_content_hash(&value, &req.content_hash)
            .map_err(|e| Error::from_reason(format!("content_hash mismatch: {e}")))?;
        verify_publish_request_signature_offline(&req)
            .map(|_| true)
            .map_err(|e| Error::from_reason(format!("signature invalid: {e}")))
    }

    /// Diagnose a `content_hash` mismatch (ACDP 0.2 divergence
    /// tooling). Probes the known cross-implementation divergence
    /// patterns — `acdp_version` omitted vs explicit, null-vs-absent
    /// optionals, sub-millisecond timestamps — and returns a
    /// human-readable report naming the matching pattern (or the
    /// recomputed hash and preimage when none matches).
    ///
    /// Never use this to *accept* a body; it is producer/SDK-author
    /// tooling for chasing "the hash that won't reproduce".
    #[napi]
    pub fn explain_hash_mismatch(body_json: String, expected_hash: String) -> Result<String> {
        let value: serde_json::Value = serde_json::from_str(&body_json)
            .map_err(|e| Error::from_reason(format!("invalid body JSON: {e}")))?;
        let expected = ContentHash::parse(&expected_hash)
            .map_err(|e| Error::from_reason(format!("invalid content_hash: {e}")))?;
        explain_hash_mismatch(&value, &expected).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// The exact JCS canonical preimage hashed for `content_hash`,
    /// returned as a UTF-8 string. When two SDKs disagree on a hash,
    /// diffing their canonical preimages localizes the divergence in a
    /// way two opaque digests never can.
    #[napi]
    pub fn canonical_preimage(body_json: String) -> Result<String> {
        let value: serde_json::Value = serde_json::from_str(&body_json)
            .map_err(|e| Error::from_reason(format!("invalid body JSON: {e}")))?;
        let (bytes, _hash) =
            canonical_preimage(&value).map_err(|e| Error::from_reason(e.to_string()))?;
        String::from_utf8(bytes)
            .map_err(|e| Error::from_reason(format!("canonical form is not UTF-8: {e}")))
    }

    /// SHA-256 fingerprint (`"sha256:<64-hex>"`) of a raw Ed25519
    /// public key, as carried in a registry receipt's
    /// `key_fingerprint` (ACDP 0.2).
    ///
    /// * `publicKeyB64` — standard base64 of the 32-byte raw key (the
    ///   same shape as `AcdpProducer.publicKeyB64` /
    ///   `ResolvedDidKey.publicKeyB64`).
    #[napi]
    pub fn fingerprint_ed25519_b64(public_key_b64: String) -> Result<String> {
        let pub_bytes: Vec<u8> = STANDARD
            .decode(&public_key_b64)
            .map_err(|e| Error::from_reason(format!("invalid publicKeyB64: {e}")))?;
        let arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| Error::from_reason("public key must decode to 32 bytes"))?;
        Ok(fingerprint_ed25519(&arr))
    }

    /// Verify a registry receipt (ACDP 0.2, RFC-ACDP-0010): the
    /// canonical `created_at` byte-form check, the offline cross-checks
    /// (`ctx_id`, recomputed body hash, producer key fingerprint,
    /// ms-truncated `created_at`, `registry_did`/`origin_registry`
    /// consistency), then the Ed25519 signature check against the
    /// registry's receipt key — with the signature preimage hashed over
    /// the **raw wire JSON** of the receipt as received (minus
    /// `signature`), never a re-serialization of the parsed struct.
    ///
    /// Resolving `registry_did` to that key is the caller's job — DID
    /// resolution stays in JS land by design (resolve the registry's
    /// DID document via `AcdpDid.webToUrl` + `fetch`, extract the key
    /// with `AcdpDidDocument.keyForAlgorithm`).
    ///
    /// **Two checks remain the HOST's obligation** — this binding makes
    /// no HTTP calls and never sees the accompanying body:
    ///
    /// 1. **Serving-authority binding** — `receipt.registry_did` MUST
    ///    equal `"did:web:" + <authority>` where `<authority>` is the
    ///    authority the response was *actually fetched from*, not
    ///    whatever the receipt claims.
    /// 2. **Body bindings** — the receipt's `lineage_id`,
    ///    `origin_registry`, and `created_at` MUST equal the
    ///    accompanying body's fields, and the `recomputedBodyHash`
    ///    argument MUST be independently recomputed from that body
    ///    (run `AcdpVerifier.verifyContentHash` first) — never the
    ///    body's echoed `content_hash` field.
    ///
    /// * `receiptJson` — the `registry_receipt` object from a
    ///   `FullContext` retrieval.
    /// * `registryPublicKeyB64` — standard base64 of the registry's
    ///   32-byte raw Ed25519 receipt key.
    /// * `expectedCtxId` — the ctx_id the caller actually requested.
    /// * `recomputedBodyHash` — the *independently recomputed* body
    ///   hash, never the body's echoed `content_hash` field.
    /// * `producerKeyFingerprint` — fingerprint of the resolved
    ///   producer key (see `fingerprintEd25519B64`).
    ///
    /// Returns `true` on success; throws with the failing check's
    /// message otherwise.
    #[napi]
    pub fn verify_receipt(
        receipt_json: String,
        registry_public_key_b64: String,
        expected_ctx_id: String,
        recomputed_body_hash: String,
        producer_key_fingerprint: String,
    ) -> Result<bool> {
        let value: serde_json::Value = serde_json::from_str(&receipt_json)
            .map_err(|e| Error::from_reason(format!("invalid receipt JSON: {e}")))?;
        // §8 step 6: the raw `created_at` bytes must already be in the
        // canonical millisecond-precision form before anything is hashed.
        RegistryReceipt::validate_created_at_form(&value)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let receipt =
            RegistryReceipt::from_value(&value).map_err(|e| Error::from_reason(e.to_string()))?;
        let body_hash = ContentHash::parse(&recomputed_body_hash)
            .map_err(|e| Error::from_reason(format!("invalid recomputedBodyHash: {e}")))?;
        receipt
            .cross_check(
                &CtxId(expected_ctx_id),
                &body_hash,
                &producer_key_fingerprint,
            )
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let pub_bytes: Vec<u8> = STANDARD
            .decode(&registry_public_key_b64)
            .map_err(|e| Error::from_reason(format!("invalid registryPublicKeyB64: {e}")))?;
        let arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| Error::from_reason("registry public key must decode to 32 bytes"))?;
        // Hash the receipt exactly as received (raw wire JSON minus
        // `signature`) — re-serializing the parsed struct could
        // normalize byte details and verify a preimage the registry
        // never signed.
        let raw_hash = RegistryReceipt::preimage_hash_of_value(&value)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        receipt
            .verify_signature_against_hash(&raw_hash, Some(&arr), None)
            .map(|_| true)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    // ── ACDP 0.3 — lineage-head receipts (RFC-ACDP-0011) ─────────────

    /// Verify a lineage-head receipt offline per RFC-ACDP-0011 §7:
    /// closed parse, registry/lineage/head bindings, `as_of` clock
    /// skew, and the registry signature over the RAW wire preimage —
    /// against the registry key extracted from the caller-supplied DID
    /// document (RFC-ACDP-0010 §9 receipt-key lifecycle: retired keys
    /// verify with `historical: true`; fully removed keys fail closed).
    ///
    /// * `receiptJson` — the `lineage_head_receipt` object as received
    ///   on the wire.
    /// * `expectedJson` — the consumer's own expectations:
    ///   `{"authority" and/or "registry_did", "lineage_id",
    ///   "head_ctx_id", "head_version", "head_status",
    ///   "on_current_endpoint"?}`. `authority` is the authority the
    ///   response was *actually fetched from* (compare your HTTP
    ///   client's URL, not any response field); `registry_did` is
    ///   `capabilities.registry_did`; either derives the other.
    ///   `on_current_endpoint` defaults to `true` (`GET /current` — §7
    ///   step 5 byte-match); pass `false` for a full retrieval, where
    ///   the §7 step 5b stale-consistency rule applies.
    /// * `registryDidDocJson` — the registry's resolved DID document
    ///   (resolution stays in JS land: `AcdpDid.webToUrl` + `fetch`).
    /// * `nowRfc3339` — the consumer clock (defaults to now).
    /// * `maxSkewSecs` — §7 step 6 allowance (default 120).
    /// * `maxAgeSecs` — §6 freshness policy (default 300).
    ///
    /// Returns a JSON verdict: `{"valid": true, "stale": bool,
    /// "age_secs": int, "historical": bool}` — staleness is policy,
    /// not verification failure — or `{"valid": false, "code":
    /// "invalid_receipt"|..., "error": ...}`. Throws only on malformed
    /// host input.
    #[napi]
    pub fn verify_lineage_head_receipt(
        receipt_json: String,
        expected_json: String,
        registry_did_doc_json: String,
        now_rfc3339: Option<String>,
        max_skew_secs: Option<i64>,
        max_age_secs: Option<i64>,
    ) -> Result<String, String> {
        let value = parse_json(&receipt_json, "receipt")?;
        let expected = v030::parse_expected_head(&expected_json).map_err(input_err)?;
        let now = parse_now(now_rfc3339.as_deref())?;
        Ok(v030::lineage_head_receipt_verdict(
            &value,
            &expected,
            &registry_did_doc_json,
            now,
            max_skew_secs.unwrap_or(v030::DEFAULT_MAX_SKEW_SECS),
            max_age_secs.unwrap_or(v030::DEFAULT_MAX_AGE_SECS),
        ))
    }

    // ── ACDP 0.3 — transparency log (RFC-ACDP-0012) ──────────────────

    /// Verify a transparency-log checkpoint (signed tree head) offline
    /// per RFC-ACDP-0012 §9.3: closed parse, optional `logId` pin
    /// (§7.4 — a new `log_id` is an explicit history reset), timestamp
    /// form + clock skew, and the registry signature over the RAW wire
    /// preimage against the receipt key from the caller-supplied DID
    /// document (retired keys verify with `historical: true`).
    ///
    /// The HOST still owns the §9.3 step 3 serving-authority half:
    /// confirm the `log_id`'s registry DID matches the authority the
    /// checkpoint was actually fetched from and
    /// `capabilities.registry_did`.
    ///
    /// Returns `{"valid": true, "log_id", "tree_size", "root_hash",
    /// "age_secs", "historical"}` (retain `tree_size`/`root_hash` for
    /// future §9.2 consistency checks) or `{"valid": false, "code":
    /// "invalid_log_proof", "error": ...}`.
    #[napi]
    pub fn verify_log_checkpoint(
        checkpoint_json: String,
        registry_did_doc_json: String,
        expected_log_id: Option<String>,
        now_rfc3339: Option<String>,
        max_skew_secs: Option<i64>,
    ) -> Result<String, String> {
        let value = parse_json(&checkpoint_json, "checkpoint")?;
        let now = parse_now(now_rfc3339.as_deref())?;
        Ok(v030::log_checkpoint_verdict(
            &value,
            &registry_did_doc_json,
            expected_log_id.as_deref(),
            now,
            max_skew_secs.unwrap_or(v030::DEFAULT_MAX_SKEW_SECS),
        ))
    }

    /// Verify a transparency-log inclusion proof offline —
    /// RFC-ACDP-0012 §9.1 steps 2 and 4–6: hash the RECONSTRUCTED
    /// leaf, check the proof ↔ checkpoint bindings, fold the audit
    /// path, compare against the checkpoint root.
    ///
    /// * `inclusionJson` — the proof (`log_id`, `leaf_index`,
    ///   `tree_size`, `inclusion_path`, optionally an embedded
    ///   `log_checkpoint`).
    /// * `checkpointJson` — the checkpoint the proof verifies against.
    ///   Inserted when the proof carries none; when the proof embeds
    ///   one, the two MUST be byte-equal (a proof quietly carrying a
    ///   different checkpoint is the substitution §9.1 step 3 exists
    ///   to stop). Verify its signature separately with
    ///   `verifyLogCheckpoint` — the verdicts are independent.
    /// * `reconstructedLeafJson` — the leaf built from *verified* body
    ///   + receipt material via `buildLogLeaf` (§9.1 step 1). NEVER
    ///   pass a leaf echoed by the registry — the whole point is that
    ///   the verifier vouches for the leaf bytes itself.
    ///
    /// Returns `{"valid": true, "leaf_hash": "sha256:..."}` or
    /// `{"valid": false, "code": "invalid_log_proof", "error": ...}`.
    #[napi]
    pub fn verify_log_inclusion(
        inclusion_json: String,
        checkpoint_json: String,
        reconstructed_leaf_json: String,
    ) -> Result<String, String> {
        let inclusion = parse_json(&inclusion_json, "inclusion")?;
        let checkpoint = parse_json(&checkpoint_json, "checkpoint")?;
        let leaf = parse_json(&reconstructed_leaf_json, "leaf")?;
        Ok(v030::log_inclusion_verdict(&inclusion, &checkpoint, &leaf))
    }

    /// Verify a transparency-log consistency proof offline —
    /// RFC-ACDP-0012 §9.2, the history-rewrite detector: prove the
    /// tree the verifier RETAINED a root for (`firstRootHash`, at
    /// `first_tree_size`) is a prefix of the checkpointed later tree.
    ///
    /// * `consistencyJson` — the proof (`log_id`, `first_tree_size`,
    ///   `second_tree_size`, `consistency_path`, optionally an
    ///   embedded `log_checkpoint`).
    /// * `checkpointJson` — the later checkpoint (merged/byte-checked
    ///   exactly as in `verifyLogInclusion`; verify its signature
    ///   separately with `verifyLogCheckpoint`).
    /// * `firstRootHash` — the verifier's own retained root
    ///   (`"sha256:<hex>"`) — retaining it is the whole point.
    ///
    /// Returns `{"valid": true}` or `{"valid": false, "code":
    /// "invalid_log_proof", "error": ...}`. A fold failure between two
    /// signature-valid checkpoints of one `log_id` is cryptographic
    /// evidence of a logged-history rewrite — retain both checkpoints
    /// and the failing path (§9.2, §15).
    #[napi]
    pub fn verify_log_consistency(
        consistency_json: String,
        checkpoint_json: String,
        first_root_hash: String,
    ) -> Result<String, String> {
        let consistency = parse_json(&consistency_json, "consistency proof")?;
        let checkpoint = parse_json(&checkpoint_json, "checkpoint")?;
        Ok(v030::log_consistency_verdict(
            &consistency,
            &checkpoint,
            &first_root_hash,
        ))
    }

    /// Build the canonical RFC-ACDP-0012 §4 log leaf from a VERIFIED
    /// RFC-ACDP-0010 receipt (§9.1 step 1) — every leaf field other
    /// than `receipt_hash` duplicates a receipt field, and
    /// `receipt_hash` is the receipt's §5 preimage hash, computed here
    /// over the RAW wire JSON as received. Returns the leaf as a JSON
    /// string, ready for `verifyLogInclusion` / `AcdpMerkle.leafHash`.
    ///
    /// Run `verifyReceipt` on the receipt FIRST: a leaf reconstructed
    /// from an unverified receipt proves membership of a claim nobody
    /// has checked. Throws on a malformed receipt
    /// (`.code === "invalid_receipt"`).
    #[napi]
    pub fn build_log_leaf(receipt_json: String) -> Result<String, String> {
        let value = parse_json(&receipt_json, "receipt")?;
        v030::build_log_leaf_core(&value).map_err(crate::errors::map_acdp_err)
    }

    // ── ACDP 0.3 — lifecycle events (RFC-ACDP-0013) ──────────────────

    /// Verify one `registry_state.lifecycle_events` entry offline per
    /// RFC-ACDP-0013 §5: closed §4 parse, binding to `expectedCtxId`
    /// (a signed event cannot be replayed against another context),
    /// the §5 actor binding (`signature.key_id` DID = `actor`), and
    /// the signature over the RAW wire preimage.
    ///
    /// * `eventJson` — the event object as received.
    /// * `actorDidDocJson` — the ACTOR's resolved DID document, or
    ///   `null` for a `did:key` actor (self-certifying — verified
    ///   natively with no document). For `did:web` actors the key must
    ///   pass the `assertionMethod` gate, like a body signature.
    /// * `expectedCtxId` — the ctx_id of the context whose registry
    ///   state carries the event.
    ///
    /// The HOST still owns the §4/§12 authorization check that `actor`
    /// equals the context's `body.agent_id` (producer-initiated) or
    /// the registry's `capabilities.registry_did` (registry-initiated)
    /// — this binding sees neither document. Retraction state itself
    /// is derived from array order, last `retracted`/`republished`
    /// event wins; unknown event types are inert (§7.1, §7.3).
    ///
    /// Returns `{"valid": true, "event_id", "event_type", "actor"}` or
    /// `{"valid": false, "code": ..., "error": ...}` (an unsigned
    /// event fails — producer-initiated events MUST be signed).
    #[napi]
    pub fn verify_lifecycle_event(
        event_json: String,
        actor_did_doc_json: Option<String>,
        expected_ctx_id: String,
    ) -> Result<String, String> {
        let value = parse_json(&event_json, "event")?;
        Ok(v030::lifecycle_event_verdict(
            &value,
            actor_did_doc_json.as_deref(),
            &expected_ctx_id,
        ))
    }

    // ── ACDP 0.3 — key revocation (RFC-ACDP-0014) ────────────────────

    /// Parse and shape-validate a `key-revocation` context body
    /// (RFC-ACDP-0014 §4) and derive its §5/§6 trust class. Returns
    /// the typed revocation as JSON: `{"revoked_key_fingerprint",
    /// "compromised_since", "reason"?, "revoked_key_id"?,
    /// "revoked_key_controller", "publisher", "trust_class":
    /// "producer_signed"|"registry_attested"}`. The fingerprint is
    /// authoritative; `compromised_since` is the compromise boundary
    /// T. Never collapse the two trust classes when reporting (§6).
    ///
    /// * `bodyJson` — the retrieved context `body` (the §5.7 layout
    ///   including registry-assigned fields).
    /// * `signerFingerprint` — the RFC-ACDP-0010 §6 fingerprint of the
    ///   RESOLVED key that signed the body, for the §5 step 2
    ///   not-self-signed rule. For `did:key` signers the check runs
    ///   natively from the body itself; for `did:web` signers resolve
    ///   the key in JS land (`AcdpDidDocument.keyForAlgorithm` +
    ///   `fingerprintEd25519B64`) and pass its fingerprint here — a
    ///   revocation signed by the very key it revokes proves only
    ///   possession of the attacker-held key and throws
    ///   (`.code === "key_not_authorized"`).
    ///
    /// Parsing does NOT verify the body: run the ordinary hash +
    /// signature pipeline (`verifyContentHash` + `verifySignature`, or
    /// `verifyBodyOffline` for did:key) before trusting the result.
    /// Throws with `.code === "schema_violation"` on §4 shape
    /// violations.
    #[napi]
    pub fn parse_key_revocation(
        body_json: String,
        signer_fingerprint: Option<String>,
    ) -> Result<String, String> {
        let body: Body = serde_json::from_str(&body_json)
            .map_err(|e| input_err(format!("invalid body JSON: {e}")))?;
        v030::parse_key_revocation_core(&body, signer_fingerprint.as_deref())
            .map_err(crate::errors::map_acdp_err)
    }

    /// Apply the RFC-ACDP-0014 §7 compromise-boundary rule — the
    /// fail-closed classification the Rust client uses, over the
    /// earliest `compromised_since` among the supplied revocations
    /// naming the key (§4 monotonicity: a superseding revocation can
    /// widen, never quietly shrink, the window — feed the whole
    /// lineage through, superseded revocations included).
    ///
    /// * `revocationsJson` — JSON array of VERIFIED revocations (the
    ///   shapes `parseKeyRevocation` returns). Which trust classes to
    ///   act on is the caller's §6 policy.
    /// * `signerFingerprint` — fingerprint of the key that signed the
    ///   context under verification.
    /// * `receiptCreatedAtRfc3339` — `created_at` from a registry
    ///   receipt VERIFIED per RFC-ACDP-0010 §8, or `null` when there
    ///   is no verified receipt. NEVER the bare body `created_at` — it
    ///   is registry-assigned, producer-unsigned, and
    ///   attacker-backdatable (§7 step 1).
    ///
    /// Returns `{"authorization": "none"}` (no revocation names the
    /// key — ordinary rules apply), `{"authorization":
    /// "historically_authorized_pre_compromise", "boundary": ...}` (§7
    /// step 2 — still verify the signature itself, under the
    /// RFC-ACDP-0010 §10 historical rule), or `{"authorization":
    /// "none", "boundary": ..., "error": ...}` — fail closed (§7
    /// steps 3–4).
    #[napi]
    pub fn classify_under_revocation(
        revocations_json: String,
        signer_fingerprint: String,
        receipt_created_at_rfc3339: Option<String>,
    ) -> Result<String, String> {
        let revocations: Vec<KeyRevocation> = serde_json::from_str(&revocations_json)
            .map_err(|e| input_err(format!("invalid revocations JSON (array): {e}")))?;
        let created_at = match receipt_created_at_rfc3339.as_deref() {
            None => None,
            Some(raw) => Some(
                DateTime::parse_from_rfc3339(raw)
                    .map(|t| t.with_timezone(&Utc))
                    .map_err(|e| {
                        input_err(format!("invalid receiptCreatedAtRfc3339 '{raw}': {e}"))
                    })?,
            ),
        };
        Ok(v030::classify_under_revocation_core(
            &revocations,
            &signer_fingerprint,
            created_at,
        ))
    }
}
