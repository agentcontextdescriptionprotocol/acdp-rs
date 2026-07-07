# acdp-wasm — ACDP WebAssembly verification core

The **browser / edge / WASI** member of the ACDP binding family
(`bindings/acdp-py`, `bindings/acdp-node`). A pure, **offline**
cryptographic verifier: it lets a consumer render an ACDP context and
independently reach a real verification **verdict** — the producer
signature, the `content_hash`, a registry receipt (RFC-ACDP-0010), a
lineage-head receipt (RFC-ACDP-0011), a transparency-log checkpoint /
inclusion / consistency proof (RFC-ACDP-0012), a lifecycle event
(RFC-ACDP-0013), a key revocation (RFC-ACDP-0014), and witness
cosignatures + quorum (RFC-ACDP-0015) — **without trusting any server to
have done it**. This is the client-side verification core the console's
verdicts consume.

It is a standalone Cargo package (its own `[workspace]`) that depends on
the umbrella `acdp` crate with `default-features = false`, so
`reqwest` / `tokio` / `rustls` never enter the `.wasm` binary. See
`docs/research/wasm-target.md` for the design rationale.

## Design (same rules as the Python / Node bindings)

- **JSON across the boundary.** Every export takes JSON strings and
  returns a JSON string — a **verdict object** (`{"valid": true, ...}` /
  `{"valid": false, "code"?, "error"}`) for verification outcomes, or a
  result string for constructors/resolvers. Malformed *host* input
  throws a `JsError`; a failed *verification* is `{"valid": false}`,
  never a throw.
- **Crypto in Rust, HTTP in the host.** No network calls. `did:web`
  resolution and all transport stay in JS (`fetch` the DID document /
  receipt / body, pass the JSON in). `did:key` verification is fully
  offline and needs no host help — the highest-value browser path.
- **No crypto reimplemented.** Every check delegates to the same `acdp`
  core the native library, Python, and Node bindings use. The 0.3/0.4
  verdict logic (`src/v030.rs`, `src/v040.rs`) is lifted **verbatim,
  byte-identical** from the other bindings.

## Exported surface

wasm-bindgen exports (camelCase in JS/TypeScript):

| Export | RFC | Purpose |
|---|---|---|
| `verifyContentHash` | 0001 §5.7 | recompute `sha256(JCS(producer_content))` |
| `verifySignatureEd25519` / `verifySignatureP256` | 0001 §5.8 | signature over the ASCII `"sha256:<hex>"` string |
| `verifyBodyOffline` / `verifyPublishRequestOffline` | 0002 | full `did:key` context verify (no resolution) |
| `fingerprintEd25519` / `verifyReceipt` | 0010 | registry-receipt verification |
| `verifyLineageHeadReceipt` | 0011 | lineage-head receipt |
| `verifyLogCheckpoint` / `verifyLogInclusion` / `verifyLogConsistency` / `buildLogLeaf` / `merkleLeafHash` / `merkleNodeHash` / `merkleRootHash` | 0012 | transparency log |
| `verifyLifecycleEvent` | 0013 | lifecycle event |
| `parseKeyRevocation` / `classifyUnderRevocation` | 0014 | key revocation |
| `buildWitnessCosignature` / `verifyWitnessCosignature` / `evaluateWitnessQuorum` | 0015 | witness cosignatures + quorum |
| `resolveDidKey` | — | offline `did:key` → public key |
| `canonicalPreimage` / `explainHashMismatch` | — | hash-divergence diagnostics |

## Build

```bash
rustup target add wasm32-unknown-unknown

# Raw wasm (regression build-check):
cargo build --target wasm32-unknown-unknown            # verify-only default

# Browser package (.js / .wasm / .d.ts) with wasm-pack:
wasm-pack build --target web --out-dir pkg
```

Import from a browser:

```js
import init, { verifyContentHash, verifySignatureEd25519 } from "./pkg/acdp_wasm.js";
await init();
const verdict = JSON.parse(verifyContentHash(bodyJson, body.content_hash));
if (verdict.valid) { /* the hash the consumer recomputed itself checks out */ }
```

## Golden-vector parity

`tests/golden.rs` is a **native** `cargo test` that runs the canonical
`sig-001` (content hash + Ed25519 signature) and `wit-001` (witness
cosignature mint + verify) spec fixtures through the same pure `core`
functions the wasm exports wrap, asserting byte-for-byte reproduction of
the pinned golden values — the same constants the `acdp-py` / `acdp-node`
suites pin. It locates fixtures via `ACDP_SPEC_DIR` and skips gracefully
when absent:

```bash
ACDP_SPEC_DIR=../../../agentcontextdistributionprotocol cargo test
```

`tests/wasm.rs` is a `wasm-bindgen-test` real-engine smoke test of the
exported wrappers (inline sig-001 constants, no fixtures needed):

```bash
wasm-pack test --node
```

## Randomness — a correction to the research memo

`docs/research/wasm-target.md` §4 predicted a **verify-only** build would
need **no `getrandom` backend** on any wasm target. That holds at
*runtime* — no exported verification (nor the deterministic Ed25519
witness mint) draws randomness. It does **not** hold at *compile time*
for `wasm32-unknown-unknown`: the core crates pull two randomness sources
**unconditionally**, and each emits a hard `compile_error!` on that
target unless a backend is wired:

1. **`getrandom 0.2`** via `rand_core 0.6` / `OsRng` (a non-optional
   dependency of `acdp-crypto`) → enabled with the getrandom **`js`
   feature**.
2. **`getrandom 0.4`** via **`uuid` v4** (a non-optional dependency of
   `acdp-primitives`) → enabled with the getrandom **`wasm_js` feature**
   *plus* `--cfg getrandom_backend="wasm_js"` (set in
   `.cargo/config.toml`). `uuid` additionally needs its own **`js`
   feature** for its v4 RNG shim.

All three are wired here, **target-gated to `wasm32` only** (see
`Cargo.toml` and `.cargo/config.toml`), so a native `cargo test` is
untouched. `crypto.getRandomValues` (the `js` backend) is the CSPRNG
RFC-ACDP-0001 §5.10 names for the browser, so the choice is spec-blessed
— but it is never invoked on the verify path; it is present only to link.

A future `producer` feature (reserved, not yet wired) would expose fresh
key generation (`SigningKey::generate`, the only `OsRng` caller) and is
where a runtime randomness draw would actually occur.

## Security notes

- This artifact is a **verifier, not a fetcher**. `RegistryClient`,
  `CrossRegistryResolver`, and `did:web` resolution do NOT move to wasm;
  the host owns HTTP and the RFC-ACDP-0006 §7 / RFC-ACDP-0008 SSRF
  defenses. Pass fetched documents in as JSON.
- A browser tab is not an HSM. Verification holds no secrets, but a
  future `producer`/keygen surface would place the signing seed in wasm
  linear memory during a call (RFC-ACDP-0001 §5.10).
