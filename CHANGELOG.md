# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — ACDP 0.2 Trust & Hardening

Implements the four workstreams of
`plans/acdp-0.2-trust-hardening-2026-06-12.md`, verified against the
spec's published 0.2.0 Draft (RFC-ACDP-0010 + the RFC-ACDP-0001
amendments) and its conformance pack: `sig-003`, `fp-001`, `rcpt-001`
(arithmetic golden vectors, reproduced byte-for-byte), `can-012`
(divergence corpus), `dk-001..004`, and `rcpt-002..004` are all
executed by `tests/conformance.rs`; `rot-001` and `fed-009` behaviors
are covered by `tests/receipts.rs`. `ACDP_VERSION` is now `0.2.0` and
the builder default emits it explicitly (RFC-ACDP-0001 §6: the
omission default is closed for 0.2.0 builders). The receipt object is
a CLOSED schema per RFC-ACDP-0010 §4; receipt verification hashes the
raw wire JSON (never a re-serialized struct) and binds `lineage_id` /
`origin_registry` / `created_at` to the accompanying body per §8
step 3. `acdp-registry-receipts` requires capabilities
`acdp_version >= 0.2.0`, and `publish_unverified_for_tests` is
unavailable on receipts-advertising registries (§7: no degraded
mode).

### Added — did:key (WS-C)
- `did::key`: pure offline `did:key` resolution (Ed25519 + P-256
  compressed, multicodec-checked), encoding helpers, and the
  `did:key:z<mb>#z<mb>` key-URL convention. No network, no SSRF
  surface; verification outlives the producer's infrastructure.
- `Producer::new_did_key` / `Producer::new_did_key_p256` — identity
  derived from the key, no domain or DID hosting required.
- `crypto::verify_body_offline` /
  `verify_publish_request_signature_offline` /
  `verify_did_key_envelope` — full did:key verification with
  `--no-default-features`.
- `RegistryServer::publish_verified_did_key` — RFC-conformant publish
  without the `client` feature; gated on `supported_did_methods`
  advertising `"did:key"` (rejected with `key_resolution_failed`
  otherwise).

### Added — registry receipts (WS-A, RFC-ACDP-0010 draft)
- `types::receipt::{RegistryReceipt, ReceiptSigner}` — registry-signed
  attestation binding `ctx_id` / `lineage_id` / `origin_registry` /
  `created_at` / `key_fingerprint` to the producer `content_hash`.
  Preimage construction is identical to the producer signature
  (JCS minus `signature`, sign the ASCII `"sha256:<hex>"` string).
- `crypto::fingerprint` — pinned `key_fingerprint` encoding (SHA-256
  over raw Ed25519 / SEC1-compressed P-256 public key bytes).
- `RegistryServer::with_receipt_signer` — mints receipts atomically
  with persistence (via the new `PublishCommit::receipt_minter` hook),
  returns them in `PublishResponse::registry_receipt`, and advertises
  the `acdp-registry-receipts` profile.
- Client verification: `client::verify_receipt_value`, the
  `ReceiptPolicy` (`Ignore` / `VerifyIfPresent` default / `Require`)
  policy axis, and `VerifiedContext::{verified_receipt, key_status}`.
- New wire error code `invalid_receipt` (`AcdpError::InvalidReceipt`,
  permanent).

### Added — historical key validity (WS-B)
- `HistoricalKeyPolicy::AcceptWithReceipt` (default): a producer key
  rotated out of `assertionMethod` but retained in
  `verificationMethod` verifies as
  `KeyAuthorization::HistoricallyAuthorized` **only** when a verified
  receipt attests its fingerprint; fails closed otherwise.

### Changed — sharp edges (WS-D)
- **BREAKING (hash-visible):** `RequestBuilder` now emits
  `acdp_version` explicitly by default. The omitted and explicit forms
  are distinct JCS preimages; requests built with default settings
  hash differently than under 0.1.x. Use
  `RequestBuilder::omit_acdp_version()` to reproduce omitted-form
  hashes (e.g. the `sig-001` golden vector).
- **BREAKING (API):** `VerificationPolicy::verify_registry_receipt`
  (bool) replaced by the `receipts: ReceiptPolicy` /
  `historical_keys: HistoricalKeyPolicy` fields;
  `PublishCommit` gains `receipt_minter`; `PublishResponse` gains
  `registry_receipt`.
- `crypto::{canonical_preimage, explain_hash_mismatch}` — divergence
  diagnostics that name the known cross-implementation hash pitfalls
  (acdp_version toggle, null-vs-absent, sub-ms timestamps).
- Lineage anchoring and idempotency atomicity contracts documented on
  `RegistryStore` (the `InMemoryStore` already implements both).

## [0.1.0] - 2026-05-19

First public release. Full conformance with the **ACDP v0.1.0 Final**
specification (promoted to Final on 2026-05-19): the complete spec
conformance fixture suite, the `sig-001` / `can-001` / `lin-001` golden
vectors, and the `acdp-consumer` profile.

### Added — repository hygiene
- Project metadata: repository, homepage, documentation, README, exclude rules,
  `[package.metadata.docs.rs]` for all-features doc builds.
- GitHub Actions CI: rustfmt, clippy (default + no-default-features),
  cross-platform tests (Linux/macOS/Windows + beta), MSRV check (1.86),
  doc build with `-D warnings`, cargo-deny, cargo-audit, llvm-cov coverage.
- `release-plz` workflow for automated crates.io publishing.
- Dependabot configuration for cargo and github-actions.
- `rustfmt.toml`, `deny.toml`, and `.gitignore`.
- HTTP-mocked tests for `RegistryClient` and `WebResolver` (wiremock).
- Property-based tests for JCS canonicalization (proptest).
- `CONTRIBUTING.md`, `SECURITY.md`.

### Changed — wire-shape conformance (Phase 0)
- **BREAKING:** `PublishResponse` no longer carries `content_hash`; gains
  `version: u32` and `status: Status` per
  `acdp-publish-response.schema.json` (fixture pub-007).
- **BREAKING:** `SearchResponse.results` renamed to `matches` per
  `acdp-search-response.schema.json` (fixture vis-003); back-compat
  accessor `results()` provided.
- **BREAKING:** `SearchResult` (the `match_summary` projection) gains
  `summary: Option<String>`, types `context_type` as `ContextType`, drops
  `tags` and `description`.
- **BREAKING:** `DataRef` rewritten — `ref_type: DataRefType` is required
  (closed enum); `description`, `size_bytes`, `schema_version` added;
  `location: Option<Location>` (URI or structured locator); typed
  constructors (`uri`, `uri_verified`, `structured`,
  `embedded_{json,utf8,base64}`).
- **BREAKING:** `DataPeriod.start` and `.end` are now required (was
  `Option`).
- **BREAKING:** `Status` is now an open enum with `Other(String)` for
  forward-compat (e.g. `retracted` per RFC-ACDP-0009 §2.1); helper methods
  `is_active`, `is_superseded`, `is_expired`, `as_other`.
- `summary: Option<String>` added to `Body`, `PublishRequest`, and
  `RequestBuilder`; included in the ProducerContent hash preimage.
- `RequestBuilder::version` setter required for v2+ supersession;
  `Producer::supersede_body(&Body)` propagates `version + 1` and
  `expected_lineage_id`. v1+supersedes and v2+ without version both
  rejected.
- `assign_identifiers` now takes `first_version_ctx_id`; derives
  `lineage_id` from the v1 ctx_id on supersession (was incorrectly
  derived from the new ctx_id).
- `RegistryClient` applies RFC-ACDP-0006 §7.4 timeouts (5s connect,
  30s total).
- Producer-side `expires_at` and `data_period` setters truncate to
  millisecond precision per RFC-ACDP-0001 §5.3.

### Added — validation (Phase 1)
- New `validation` module providing `validate_publish_request`,
  `validate_body`, `validate_data_ref`, `validate_metadata`,
  `validate_identifiers`, `compute_embedded_hash`, `verify_embedded_hash`.
- `RequestBuilder::build()` runs full schema validation before emission.
- Runtime checks: public-no-audience, array uniqueness/size, string
  length, `data_period.start ≤ end`, `DataRef` oneOf + URI credential
  rejection + structured-scheme pattern + embedded ≤ 64 KB +
  `utf8`/`base64` content must be string, metadata depth ≤ 8 / JCS size
  ≤ 64 KB / ≤ 100 properties, `did:web` enforcement, signature length
  for `ed25519` / `ecdsa-p256`, embedded `content_hash` semantics
  (`json` → JCS, `utf8` → raw bytes, `base64` → decoded bytes).

### Added — error taxonomy and typed IDs (Phase 2)
- 13 new `AcdpError` variants matching RFC-ACDP-0007 §5 wire codes:
  `NotFound`, `NotAuthorized`, `RateLimited`, `PayloadTooLarge`,
  `EmbeddedTooLarge`, `SupersededTarget { reason, message }`,
  `UnsupportedAlgorithm`, `NotImplemented`, `CursorExpired`,
  `InvalidCursor`, `DuplicatePublish`, `CrossRegistryResolutionFailed`,
  `RegistryInternal`. New `SupersessionReason` enum.
- `RegistryClient::parse_success` now maps `WireError.code` to typed
  variants via `AcdpError::from_wire_error`.
- `CtxId::parse`, `LineageId::parse`, `ContentHash::parse`,
  `AgentDid::parse`, `AgentDid::parse_web` perform full pattern
  validation per `acdp-common.schema.json`. `CtxId::uuid()` extracts the
  v4 UUID component.

### Added — builder and API (Phase 3)
- `RequestBuilder::expected_lineage_id` for v2+ self-verification (v1
  publications reject this field per RFC-ACDP-0003 §2.2).
- `PublishRequest.lineage_id: Option<LineageId>`.
- `SearchParams` gains `data_period_start_after`,
  `data_period_end_before`, `expires_after`, `expires_before` filters
  (RFC-ACDP-0005 §2.1). New `SearchParamsBuilder` accepting
  `DateTime<Utc>`.
- `PublishValidator::for_authority` rejects cross-registry supersession
  with `SupersededTarget { CrossRegistrySupersessionUnsupported }`.
- `CapabilitiesDocument.extensions: Map<String, Value>` (`#[serde(flatten)]`)
  preserves unknown forward-compat capability flags.
- `ContextType` deserializer rejects strings that are neither standard
  values nor namespaced custom types matching
  `^[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*$`.

### Added — protocol completeness (Phase 4)
- `CrossRegistryResolver` (RFC-ACDP-0006 §4.1): seven-step algorithm
  with `walk_derived_from`, cycle detection, configurable `max_depth`
  (default 10), and optional authority allowlist.
- `registry::safe_http::SsrfPolicy` (RFC-ACDP-0006 §7): URL filtering
  for HTTPS-only, IP-literal rejection, RFC 1918 / loopback /
  link-local / multicast / IMDS (`169.254.169.254`) and IPv6
  equivalents (`::1`, `fc00::/7`, `fe80::/10`, IPv4-mapped); same-
  authority redirect check; constants `MAX_CONTEXT_BYTES` (1 MB),
  `MAX_METADATA_BYTES` (64 KB), `MAX_REDIRECTS` (3).
- `tests/conformance.rs` validates all 16 spec conformance fixtures
  parse, plus deserialization checks for every example under
  `examples/**/*.json`. The harness locates the spec via
  `ACDP_SPEC_DIR` (with a sibling-path fallback) and skips gracefully
  when neither is available.

### Added — quality of life (Phase 5)
- `FullContext.registry_receipt: Option<Value>` reserved for
  RFC-ACDP-0009 §2.7.
- `WebResolver` cache backed by `lru::LruCache` (default capacity 1000),
  with `WebResolver::with_capacity(n)`.
- `PublishValidator::validate_post_schema` alias with RFC-aligned
  documentation.
- Optional `tracing` feature: `RegistryClient::{capabilities, publish,
  retrieve}` and `WebResolver::resolve` carry `#[tracing::instrument]`
  spans when enabled.

### Deferred
- IMP-09 — standalone `acdp-cli` crate (sign / verify / publish /
  retrieve / search). Out of scope for this revision.
- IMP-05 — auto-populating `acdp_version = "0.0.1"` in the builder
  would change the content_hash and break the `sig-001` golden vector;
  v0.0.1 producers MAY include it explicitly via
  `RequestBuilder::acdp_version`.

### Fixed
- `crypto::jcs` now compiles cleanly (missing `io::Write` import,
  `serde_json::Value::String` shadowing, map indexing).
- `producer::RequestBuilder::build` no longer emits JSON `null` for unset
  optional fields; the canonical form now matches the wire format produced by
  serde with `skip_serializing_if = "Option::is_none"`, so the `content_hash`
  for a minimal request matches the spec golden vector
  (`sig-001-ed25519-golden`).
- Or-pattern bug in `Visibility::Restricted` audience check.

### Security
- Cross-registry resolution builds its per-authority `RegistryClient`
  with `new_pinned`: the foreign authority's DNS is resolved up-front,
  every resolved IP is filtered through the `SsrfPolicy`, and the
  connection is pinned to that address — closing a DNS-rebinding /
  internal-host SSRF gap (SEC-01).
- `HttpsDataRefFetcher` builds its HTTP client with a `SafeDnsResolver`
  DNS hook and a same-authority redirect cap, so a producer-controlled
  `DataRef` location resolving into a private range is refused at DNS
  time and cross-authority redirects are rejected (SEC-02).
- `validate_origin_registry` rejects uppercase, underscores, and
  malformed labels by delegating to the shared DNS-authority validator
  (BUG-02).

[0.1.0]: https://github.com/agentcontextdistributionprotocol/acdp-rs/releases/tag/v0.1.0
