# Architecture

This page explains how the crate is organized internally and why. The
protocol-level rationale for the three-layer split lives in
[RFC-ACDP-0001 §5](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md)
(identifiers, canonicalization, hashing, signatures) and
[RFC-ACDP-0002](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0002-context-body.md)
(the body structure). This page maps that structure onto Rust modules and
explains the one rule you must never break: **a field's layer determines
whether it is hashed, signed, or mutable.**

## The three layers

```
PublishRequest                                         src/types/publish.rs
  │
  ├── Body                  ← immutable, JCS-canonicalized        src/types/body.rs
  │     │
  │     └── ProducerContent ← Body minus the §5.7 exclusion set
  │           │                (producer-controlled fields only)
  │           ├── content_hash  = sha256(JCS(ProducerContent))    src/crypto/hash.rs
  │           └── signature     = Ed25519( ASCII "sha256:<hex>" ) src/crypto/sign.rs
  │                                            ▲
  │                                            └─ ⚠️ the ASCII string, NOT the 32-byte digest
  │
  ├── content_hash          ← echoed in the request for transport
  └── signature             ← the producer's Ed25519 signature

FullContext = Body + RegistryState                     ← retrieval shape
                     │
                     └── status, … (mutable, registry-derived)    src/types/body.rs
```

Three operations are protocol-critical and the crate implements them exactly:

| Operation | Spec | Implementation |
|---|---|---|
| JCS canonicalization | RFC 8785 | `src/crypto/jcs.rs` — **in-house**, handles `-0.0` |
| `content_hash` | RFC-ACDP-0001 §5.7 | `src/crypto/hash.rs` — `sha256(JCS(ProducerContent))` |
| Ed25519 sign/verify | RFC-ACDP-0001 §5.8/§5.11 | `src/crypto/{sign,verify}.rs` |

### Three things that trip people up

1. **The signature preimage is the ASCII string `"sha256:<hex>"`** — the 71-byte
   text — not the raw 32-byte digest. This is the single most common
   implementation mistake. See `src/crypto/sign.rs`.
2. **`Option::is_none` fields are skipped, not emitted as `null`.** Emitting
   `null` for an unset field changes the JCS bytes and therefore the
   `content_hash`. This is load-bearing for the `sig-001` golden vector.
3. **`Body` and `RegistryState` are split deliberately.** `status` is *not* a
   body field — it's registry-derived and lives in `RegistryState`. Merging
   them would let mutable state into the signed preimage.

## Module map

| Path | Role |
|---|---|
| `src/lib.rs` | Crate root: module declarations, `ACDP_VERSION`, convenience re-exports. |
| `src/types/` | Wire types: `body`, `publish`, `search`, `data_ref`, `capabilities`, `primitives`. `Body` / `RegistryState` are kept apart. `Status`, `ContextType`, `Visibility` are **open enums** — they preserve `Other(String)` for forward compat. |
| `src/crypto/` | `jcs` (RFC 8785), `hash` (`content_hash` + `lineage_id` derivation), `sign` / `verify` (Ed25519, optional ECDSA-P256). |
| `src/validation.rs` | The one-stop schema validator: `validate_publish_request`, `validate_body`, `validate_data_ref`, `validate_metadata`, `validate_capabilities`. The builder runs this before emitting. |
| `src/producer/` | `Producer` + `RequestBuilder`. Enforces v1-vs-v2+ rules, ms-truncates timestamps, validates, computes `content_hash`, then signs. |
| `src/did/` | `WebResolver` for `did:web` (LRU-cached, SSRF-gated). v0.1.0 producers MUST use `did:web`. |
| `src/safe_http.rs` | `SsrfPolicy`, the HTTPS guard, and `SafeDnsResolver` (the DNS-time IP filter). The **only** copy; `src/registry/safe_http.rs` re-exports it. |
| `src/client/` *(feature `client`)* | `RegistryClient`, `VerifiedContext`, `VerificationPolicy`/`Report`, `CrossRegistryResolver`, `DataRefFetcher`. Implements the **`acdp-consumer`** profile. |
| `src/registry/` *(feature `server`)* | `RegistryServer`, `PublishValidator`, `RegistryStore`, `InMemoryStore`. Building blocks for separate `acdp-registry-*` crates. |
| `src/error.rs` | `AcdpError` — typed mapping of all RFC-ACDP-0007 §5 wire codes, plus `is_transient`. |
| `src/profile.rs` | Typed profile vocabulary (`acdp-consumer`, `acdp-registry-core`, …). |
| `src/bin/acdp.rs` *(feature `cli`)* | The CLI. Uses `std::env::args` directly — **no `clap`** by design. |

## Feature gating

The crate is single-crate (no workspace). Features add layers outward from a
pure core:

```
              ┌─────────────────────────────────────────────┐
   cli  ───►  │ src/bin/acdp.rs                              │
              ├─────────────────────────────────────────────┤
 client ───►  │ client::{RegistryClient, VerifiedContext,   │
              │   CrossRegistryResolver}  ·  did::WebResolver│
              ├─────────────────────────────────────────────┤
 server ───►  │ registry::{RegistryServer, PublishValidator,│
              │   RegistryStore, InMemoryStore}              │
              ├─────────────────────────────────────────────┤
  core   ───► │ types · crypto · validation · producer ·    │  ← always present,
 (no feat)    │ error · profile · safe_http · did (types)   │    no HTTP stack
              └─────────────────────────────────────────────┘
```

- **`client` and `server` are independent.** A consumer pulls `client`; a
  registry pulls `server`. They don't require each other.
- **The core has no async runtime and no HTTP.** `reqwest`/`tokio`/`rustls`
  only arrive with `client` (or `cli`). This is what lets the
  [bindings](bindings.md) ship a thin wheel/`.node` — crypto in Rust, HTTP in
  the host language.

## Where the work happens

Most behavior changes land in **`src/validation.rs`** (~44 KB). It is the
single source of structural truth: the builder calls it before signing, the
`server` feature calls it during publish, and `VerifiedContext` calls it during
retrieval. If you're changing what counts as a valid context, that's the file.

The crypto layer is intentionally small and rarely changes — and when it does,
it must keep passing the `sig-001` / `can-001` golden vectors (see
[Conformance & testing](conformance.md)).

## Design rules (repo conventions)

These are enforced and will fail CI or review if broken:

- **No `unsafe`** — `unsafe_code = "forbid"` at the crate root.
- **JCS is in-house** — do not swap `src/crypto/jcs.rs` for an external crate;
  the `-0.0` handling is pinned by `proptest_jcs.rs` and `can-001`.
- **No `clap`** in the CLI — manual arg parsing keeps the dep graph identical to
  the library.
- **`Option::is_none` skip-serialization** is load-bearing — never emit `null`
  for unset fields.
- **Producer timestamps are ms-truncated** (`time::trunc_ms`) per
  RFC-ACDP-0001 §5.3.
- **Conventional Commits** — `release-plz` derives versions from
  `feat:`/`fix:`/`docs:`/… prefixes.
