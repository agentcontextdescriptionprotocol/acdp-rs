# acdp — cross-language interop tests

Proves the Python and Node.js SDKs emit byte-compatible ACDP wire
output by building the same `PublishRequest` from the same all-zero
Ed25519 seed on each side and asserting:

* `content_hash` is byte-identical across both bindings (this follows
  from JCS being deterministic and SHA-256 being a function).
* `signature.value` is byte-identical across both bindings (Ed25519
  with a fixed seed is also deterministic).
* The Python verifier accepts Node-produced signatures and vice versa.
* Each side matches the spec's `sig-001` golden constants the Rust
  suite asserts (`f170150d…` / `ErkbV+FU…`).

The Python side runs in-process via the `acdp` extension built by
`maturin develop`. The Node side runs in a `node` subprocess driven
over line-delimited JSON-RPC (`node_worker.mjs`), which keeps a single
process alive across all tests so we don't pay subprocess startup per
RPC. Every wire message that crosses the language boundary is plain
JSON.

## Run

Build both bindings first:

```bash
(cd ../acdp-py   && maturin develop)
(cd ../acdp-node && npm install && npm run build:debug)
pytest
```

Or from the repo root: `make interop` (builds both bindings, then runs
pytest).

## Why this exists

The acdp protocol is content-addressable: every consumer recomputes
`sha256(JCS(producer_content))` and refuses bodies whose hash doesn't
match. If the Python and Node bindings disagree on JCS canonicalization
— even in something as small as how an unset optional field is
serialized — they emit different `content_hash` values and registries
reject one of the two. These tests pin that invariant in CI.

## Drift guard (`test_parity.py`)

Behavioral interop only catches divergence in code paths a test happens to
exercise. `test_parity.py` adds structural guards so the two SDKs can
never silently drift:

* **API-surface parity** — `expected_surface.json` is the single source of
  truth for the public surface. The test asserts the Python binding, the
  Node binding (introspected over the worker's `describe` RPC), and the
  manifest all expose the same classes and methods (names normalized to
  snake_case, so Node's camelCase compares equal). Add a method to one
  binding without the other — or without updating the manifest — and the
  test fails.
* **Behavioral parity for the sync primitives** — `AcdpCanonicalizer`
  (`canonicalize` / `content_hash`) and `AcdpSsrfPolicy` (the stable
  reason taxonomy: Python's `SsrfRejected.reason` vs Node's `Error.code`)
  are cross-checked across both bindings in `test_interop.py`.
* **Version parity** — `pyproject.toml`, both `Cargo.toml`s, and
  `package.json` must all carry the same version.

When you intentionally change the public API, update
`expected_surface.json` (and both bindings) in the same change. The guard
runs as part of `make interop` and the `bindings` CI workflow, so drift
fails the build locally and in CI.
