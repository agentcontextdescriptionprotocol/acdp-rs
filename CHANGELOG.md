# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.6](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.5...acdp-v0.8.6) - 2026-09-05

### Fixed

- *(client)* enforce query scope and trust class in find_revocations ([#191](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/191)) ([#204](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/204))
- *(client)* bind the served ctx_id to the requested one ([#189](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/189)) ([#200](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/200))

### Other

- move off yanked wnaf 0.14.0 ([#201](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/201))

## [0.8.5](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.4...acdp-v0.8.5) - 2026-08-30

### Fixed

- release-hygiene follow-ups (tag lag, CHANGELOG gap, stale spec pin)

## [0.8.4](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.3...acdp-v0.8.4) - 2026-08-30

### Other

- reconcile RS-11 ACDP_VERSION default-bump assumption ([#180](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/180))

## [0.8.3](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.2...acdp-v0.8.3) - 2026-08-30

### Added

- *(bindings)* expose anchors (RFC-ACDP-0016) in acdp-py and acdp-node ([#175](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/175))

### Other

- *(release-runbook)* record the RS-8 anchors release as done ([#177](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/177))

## [0.8.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.1...acdp-v0.8.2) - 2026-08-30

### Added

- *(types)* add anchors support (RFC-ACDP-0016, 0.5.0) ([#169](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/169))

### Other

- *(deps)* bump the major-updates group across 1 directory with 9 updates ([#157](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/157))
- *(deps)* bump the minor-and-patch group across 1 directory with 6 updates ([#147](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/147))
- W4-RS hygiene batch (RS-6/7/9/11/12) ([#164](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/164))
- record RS-3's require-mode conformance evidence (RS-4) ([#160](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/160))
- close conformance CI gap, add fixture-family coverage, harden bindings supply chain ([#153](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/153))

### Changed

- **`ACDP_VERSION` default bumped `0.2.0` → `0.4.0`** (RS-11, family plan
  `agentcontextdistributionprotocol/plans/siblings/acdp-rs.md`). `RequestBuilder`
  has emitted `acdp_version` explicitly by default since the 0.2.0 line (WS-D1); that
  default tracked the wrong constant once RFC-ACDP-0011..0014 (0.3.0) and
  RFC-ACDP-0015 witness cosigning (0.4.0, promoted to Final 2026-08) shipped in this
  crate — a default-using producer was stamping `0.2.0` on bodies the crate already
  fully supports minting/verifying at 0.4.0. `ACDP_VERSION` now tracks the newest
  Final wire line, matching the design intent ("remove the omitted-vs-explicit
  ambiguity for everything built going forward").
  **Producer-visible behavior change:** any caller relying on the *implicit* default
  remaining `"0.2.0"` — rather than calling `.acdp_version(...)` /
  `.omit_acdp_version()` explicitly — will see their next default-built
  `content_hash` change (the JCS preimage includes `acdp_version`), and the emitted
  value move to `"0.4.0"`. A registry that hasn't adopted 0.4.0-line semantics yet
  should pin the version it expects explicitly rather than relying on the crate's
  default. No schema/validation requirement is newly triggered by this (there is no
  version-gated *required* field for produced bodies at 0.3.0 or 0.4.0 in this
  crate's `acdp-validation` — only `CapabilitiesDocument.acdp_version >= 0.3.0`
  gates a requirement, and that's a registry's own capabilities document, not a
  producer's request). See `ASSUMPTIONS.md` for the alternative considered
  (feature-derived default) and why it was rejected.

### Conformance evidence

RS-4 (family plan `agentcontextdistributionprotocol/plans/siblings/acdp-rs.md`): the Rust
half of RFC-ACDP-0015's Final-promotion evidence-input contract (SPEC-1), recording the
require-mode conformance run at the pin bumped by RS-3 (#159).

- **Crate / tag:** `acdp` (workspace-lockstep) `v0.8.1` — the currently released tag; the
  pending `v0.8.2` release PR (#154) had not merged at the time of this run.
- **Pinned spec SHA:** `bff3cf3afbdcea619834916e8f0bcac7e82ba658` (spec `main` as of
  2026-08-28).
- **Command:** `ACDP_SPEC_DIR=<pinned spec checkout> ACDP_REQUIRE_CONFORMANCE=1 cargo test
  --workspace --all-features` — 658 passed, 0 failed, exit 0.
- **Executed `wit-*` fixtures** (RFC-ACDP-0015 witness cosigning, the promotion-gating
  family): `wit_001_cosignature_golden_fixture`, `wit_002_consistency_refusal_fixture`,
  `wit_003_quorum_verification_fixture`, `wit_004_cosignature_key_mismatch_fixture` — all
  executed (not skipped), confirmed via `ACDP_REQUIRE_CONFORMANCE=1`'s hard-fail-on-missing
  behavior.
- **Also executed** (previously CI-silent, closed by RS-1/#153): `tests/transparency_log.rs`
  (`log_*`), `tests/key_revocation.rs` (`rev_*`), `tests/lifecycle.rs` (`lc_*`) — all green.
- **CI run:** https://github.com/agentcontextdistributionprotocol/acdp-rs/actions/runs/33232085544/job/99046540516
  (the `conformance (spec fixtures)` job on PR #159, which carried this exact pin and
  command; the PR itself is a pure pin bump with no test/fixture changes, so this run is the
  authoritative in-CI execution of the run recorded above).

## [0.8.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.0...acdp-v0.8.1) - 2026-07-10

### Other

- release v0.8.0 ([#128](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/128))

## [0.8.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.6.2...acdp-v0.8.0) - 2026-07-10

### Other

- unify the whole ecosystem to 0.8.0 and auto-release the SDKs ([#127](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/127))

## [0.6.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.6.1...acdp-v0.6.2) - 2026-07-10

### Added

- *(server)* publish_pinned_verified_in_tenant for operator-pinned keys ([#116](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/116))

## [0.6.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.5.3...acdp-v0.6.1) - 2026-07-09

### Added

- *(acdp-wasm)* publish browser wasm binding to npm

### Other

- release v0.6.0
- unify the acdp family to a single lockstep version (0.6.0)
- commit refreshed cargo-vet imports.lock
- fix supply-chain gates (crossbeam advisory + stale vet exemptions)
- update Cargo.lock for acdp-verify dev-dependencies
- refresh for the 0.2.0 trust & hardening layer and workspace split
- *(verify)* add direct coverage for the acdp-verify crate
- fix toolchain bug, pin spec, expand dependabot, add release smoke gates

## [0.6.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.5.3...acdp-v0.6.0) - 2026-07-09

### Added

- *(acdp-wasm)* publish browser wasm binding to npm

### Other

- unify the acdp family to a single lockstep version (0.6.0)
- commit refreshed cargo-vet imports.lock
- fix supply-chain gates (crossbeam advisory + stale vet exemptions)
- update Cargo.lock for acdp-verify dev-dependencies
- refresh for the 0.2.0 trust & hardening layer and workspace split
- *(verify)* add direct coverage for the acdp-verify crate
- fix toolchain bug, pin spec, expand dependabot, add release smoke gates

## [0.5.3](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.5.2...acdp-v0.5.3) - 2026-07-06

### Added

- *(bindings)* expose RFC-ACDP-0015 witness-cosigning surface (py + node 0.7.0)
- *(types)* add LogCosignature witness-cosignature types (RFC-ACDP-0015)

## [0.5.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.5.1...acdp-v0.5.2) - 2026-07-06

### Other

- add research-track evaluation memos (wasm, did:webvh, post-quantum)

## [0.5.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.5.0...acdp-v0.5.1) - 2026-07-06

### Added

- *(bindings)* expose ACDP 0.3.0 verification surfaces in both SDKs

### Other

- add supply-chain security policy
- add cargo-vet supply-chain dependency vetting
- *(bindings)* pin the 0.3.0 golden vectors and cross-binding parity

## [0.5.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.4.0...acdp-v0.5.0) - 2026-07-05

### Added

- feat!(client): hard-gate SSRF-relaxed test constructors behind test-transport
- [**breaking**] lifecycle events & retraction — RFC-ACDP-0013 (acdp/0.3.0 draft)

### Other

- rustfmt after integration merges
- Merge feature/rfc-0014-revocation: RFC-ACDP-0014 SDK surface
- Merge feature/rfc-0012-log-verification: RFC-ACDP-0012 SDK surface

## [0.4.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.3.0...acdp-v0.3.1) - 2026-07-05

### Added

- *(tracing)* instrument verify pipeline and server publish path
- *(client)* fallible WebResolver constructors; feature-gate SSRF-relaxed test constructors behind test-transport

### Other

- fix double-comparison lint; docs: fix intra-doc link; chore: bump anyhow past RUSTSEC-2026-0190
- bind lhr-001..004 fixtures and RFC-ACDP-0011 end-to-end suite
- rustfmt fuzz target; lockfile update for tracing deps
- *(bench)* criterion benchmarks for sign/verify, JCS, content-hash, SSRF classify

## [0.3.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.2.1...acdp-v0.3.0) - 2026-06-24

### Other

- preserve acdp::crypto::verify::* module path in the facade
- split acdp into a fine-grained Cargo workspace

## [0.2.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/v0.2.0...v0.2.1) - 2026-06-14

### Added

- *(bindings)* resolve retired registry receipt keys per RFC-ACDP-0010 §9

## [0.2.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/v0.1.0...v0.2.0) - 2026-06-13

### Added

- *(registry)* add publish_verified_did_key_in_tenant
- [**breaking**] ACDP 0.2.0 trust & hardening — registry receipts, did:key, divergence diagnostics

### Fixed

- *(registry)* scope the §7 no-degraded-mode check to newly inserted contexts

### Other

- add unit coverage for core types and crypto error paths
- add supersession + end-to-end examples and negative-input tests
- add library usage guides under docs/

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
