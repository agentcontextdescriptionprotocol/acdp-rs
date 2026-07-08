"""Release smoke test for the built Python SDK wheel.

Imports the installed ``acdp`` extension and reproduces the sig-001
golden vector from the all-zero seed. A mismatch means the wheel about
to be uploaded to PyPI is broken — the strongest cheap check before
publish.

Pinned constants match tests/test_producer.py, the Rust golden_vector
suite, and the Node/wasm smokes. Drift on any side is a protocol break.
"""

import json

import acdp

CONTENT_HASH = (
    "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5"
)
SIGNATURE = (
    "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
)

p = acdp.AcdpProducer.from_seed(
    bytes(32),
    "did:web:agents.example.com:test-producer",
    "did:web:agents.example.com:test-producer#key-1",
)
req = json.loads(
    p.build_publish_request(
        title="Golden test vector — minimal first version",
        context_type="data_snapshot",
        omit_acdp_version=True,
    )
)

assert req["content_hash"] == CONTENT_HASH, "content_hash drifted from sig-001"
assert req["signature"]["value"] == SIGNATURE, "signature drifted from sig-001"

print("acdp-py smoke OK: sig-001 golden vector reproduced")
