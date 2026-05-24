# acdp — Python SDK

Thin PyO3 binding over the [`acdp`](https://crates.io/crates/acdp) Rust
library. Implements the producer- and consumer-side crypto for the Agent
Context Description Protocol v0.1.0 (RFC-ACDP-0001/0003/0008). HTTP is
intentionally left to the caller — pair this with `httpx` / `requests`
for transport.

## Install (development)

```bash
pip install maturin
maturin develop                # editable install into the active venv
pytest tests/                  # in-process unit tests, no HTTP
```

## Build a wheel

```bash
maturin build --release        # produces target/wheels/acdp-*.whl
pip install target/wheels/acdp-0.1.0-*.whl
```

## Quickstart

```python
import json, acdp

producer = acdp.AcdpProducer.generate(
    "did:web:agents.example.com:my-agent",
    "did:web:agents.example.com:my-agent#key-1",
)

raw = producer.build_publish_request(
    title="Q1 snapshot",
    context_type="data_snapshot",
    summary="Quarter-end inventory",
)
request = json.loads(raw)

# POST `raw` (the JSON string) to the registry's /v1/contexts endpoint
# with your HTTP client of choice. On retrieve, validate the response:
body = ...  # response.json()["body"]
acdp.AcdpVerifier.verify_content_hash(json.dumps(body), body["content_hash"])
acdp.AcdpVerifier.verify_signature(
    pub_key_b64,                  # resolved from the producer's did:web doc
    body["signature"]["value"],
    body["content_hash"],
)
```

## Design rules

* **JSON across the FFI boundary.** Every method accepts and returns
  JSON strings — never a Rust type, never a Python dataclass. The
  wheel stays at ~500 lines of glue.
* **Crypto in Rust, HTTP in Python.** Key generation, JCS + SHA-256
  hashing, Ed25519 signing, and signature verification all happen in
  the underlying `acdp` crate. The Python side handles transport,
  retries, and observability.
* **`AcdpProducer` stores a 32-byte seed.** The Rust `SigningKey` is
  `ZeroizeOnDrop` and not `Clone`, so the binding rebuilds the signing
  key from the seed on each call.
* **Golden vector parity.** `test_golden_content_hash` pins the
  Python-side `content_hash` and `signature.value` against the spec's
  `sig-001` fixture — the same constants the Rust suite asserts. A
  drift on either side is a protocol break.

## Layout

```
bindings/acdp-py/
├── Cargo.toml         # standalone [workspace]; depends on `acdp` via path
├── pyproject.toml     # maturin build backend
├── README.md          # this file
├── src/
│   ├── lib.rs         # #[pymodule] entry point
│   ├── producer.rs    # AcdpProducer: build/sign publish requests
│   ├── verifier.rs    # AcdpVerifier: content_hash + signature verify
│   └── helpers.rs     # visibility / context_type string parsers
└── tests/
    └── test_producer.py
```
