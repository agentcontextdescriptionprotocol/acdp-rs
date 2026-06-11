# Language Bindings

The crate ships two native SDKs that reuse the Rust crypto core:

- **`bindings/acdp-py`** — Python, via [PyO3](https://pyo3.rs) / maturin.
- **`bindings/acdp-node`** — Node.js, via [NAPI-rs](https://napi.rs).

Both implement the same protocol primitives as the Rust crate, so a context
signed in Python verifies in Node and vice-versa. The protocol contract they
implement is the same RFC set — see [RFC-ACDP-0001](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md).

## Design: crypto in Rust, HTTP in the host

The single most important design decision: **the bindings never make network
calls.** They expose the deterministic, security-critical operations — building,
hashing, signing, verifying — and leave transport to the host language's HTTP
stack (`httpx`, `fetch`, …).

This is why both bindings depend on `acdp` with `default-features = false`:
`reqwest` / `tokio` / `rustls` never enter the Python wheel or the `.node`
binary. They only need the pure-types/crypto core (see
[Architecture → feature gating](architecture.md#feature-gating)).

### JSON across the FFI boundary

Every binding method accepts and returns **JSON strings** — the same HTTP
request/response bodies you'd send on the wire. No Rust types cross the
boundary, so the API stays small and stable across language updates.

```
host language  ──(JSON string)──►  binding (Rust crypto)  ──(JSON string)──►  host language
     │                                                                              │
     └──────────────────── HTTP (httpx / fetch) ──────────────────────────────────┘
```

### Key handling

`AcdpProducer` stores a **32-byte seed**, not a live `SigningKey`. `SigningKey`
is `ZeroizeOnDrop` and not `Clone`, so the binding rebuilds it from the seed for
each call. The seams that make this work are `SigningKey::seed_bytes()` and
`SigningKey::sign_string()` in `src/crypto/sign.rs` — they exist specifically to
support the binding surface.

## Python (`acdp-py`)

```bash
cd bindings/acdp-py && maturin develop      # or: make sdk-py
```

```python
import json, httpx
from acdp import AcdpProducer, AcdpVerifier

# Build + sign — returns a JSON publish request
producer = AcdpProducer.generate("did:web:agents.example.com:my-agent",
                                 "did:web:agents.example.com:my-agent#key-1")
req = producer.build_publish_request(title="Q1 snapshot", context_type="data_snapshot")

# Transport is yours:
httpx.post("https://registry.example.com/contexts",
           content=req, headers={"Content-Type": "application/acdp+json"})

# Verify a retrieved body (raises on mismatch)
AcdpVerifier.verify_content_hash(body_json, stored_hash)
AcdpVerifier.verify_signature(pub_key_b64, sig_b64, content_hash)
```

## Node.js (`acdp-node`)

```bash
cd bindings/acdp-node && npm run build:debug   # or: make sdk-node
```

```js
const { AcdpProducer, AcdpVerifier } = require('acdp');

const producer = AcdpProducer.generate(
  'did:web:agents.example.com:my-agent',
  'did:web:agents.example.com:my-agent#key-1');
const req = producer.buildPublishRequest({ title: 'Q1 snapshot', contextType: 'data_snapshot' });

await fetch('https://registry.example.com/contexts', {
  method: 'POST',
  headers: { 'Content-Type': 'application/acdp+json' },
  body: req,
});

AcdpVerifier.verifyContentHash(bodyJson, storedHash);  // throws on mismatch
AcdpVerifier.verifySignature(pubKeyB64, sigB64, contentHash);
```

The Node API is the same surface in camelCase.

## Golden-vector parity

Both binding test suites pin the **same** constants from the `sig-001` golden
vector:

```
content_hash    = "sha256:f170150d…"
signature.value = "ErkbV+FU…"
```

The `bindings/interop/` suite cross-builds the identical request in *both*
bindings and asserts byte equality. If any of those constants drift, the
protocol is broken — that's the tripwire.

```bash
cd bindings/interop && pytest        # or: make interop
```

## Build details

Each binding is a **standalone Cargo package** (its own `[workspace]` table)
that references the parent crate via `path = "../.."`. They are **not** part of
`cargo test` on the root crate — build each independently with maturin / napi.
The top-level `Makefile` wraps the common targets: `make sdk-py`, `make
sdk-node`, `make interop`.
