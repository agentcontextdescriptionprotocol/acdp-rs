"""Cross-language ACDP interop integration tests.

Exercises a real ACDP producer flow where both ends run in *different
language runtimes*:

* the **Python** end runs in-process via the ``acdp`` extension built by
  ``maturin develop``, and
* the **Node** end runs in a ``node`` subprocess driven over
  line-delimited JSON-RPC (see ``node_worker.mjs``).

Both ends sign a `PublishRequest` from the same all-zero Ed25519 seed
with the same inputs. JCS + SHA-256 is deterministic and Ed25519 with a
fixed seed is deterministic too, so the `content_hash` AND the
`signature.value` MUST be byte-identical across both bindings. We also
cross-verify: Node verifies Python-produced bodies and vice versa.

Run from ``bindings/interop/`` after building both bindings::

    (cd ../acdp-py    && maturin develop)
    (cd ../acdp-node  && npm install && npm run build:debug)
    pytest

or simply ``make interop``, which builds both bindings first.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

import acdp


HERE = os.path.dirname(os.path.abspath(__file__))

# Identity used by both ends. The all-zero seed is what `sig-001` golden
# fixture uses, so its content_hash + signature are pinned constants in
# both binding test suites.
SEED = bytes(32)
AGENT_DID = "did:web:agents.example.com:test-producer"
KEY_ID = f"{AGENT_DID}#key-1"
GOLDEN_HASH = (
    "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5"
)
GOLDEN_SIG = (
    "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
)


# ── Node side: a subprocess worker driven over JSON-RPC ─────────────────


class NodeWorker:
    """A ``node node_worker.mjs`` subprocess driven over JSON-RPC stdio."""

    def __init__(self) -> None:
        self._proc = subprocess.Popen(
            ["node", os.path.join(HERE, "node_worker.mjs")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,  # surface Node-side errors into pytest output
            text=True,
            bufsize=1,
        )
        self._next_id = 0

    def _rpc(self, method: str, params: dict) -> dict:
        self._next_id += 1
        request = {"id": self._next_id, "method": method, "params": params}
        self._proc.stdin.write(json.dumps(request) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            raise RuntimeError(
                f"node worker exited before answering {method!r}"
            )
        return json.loads(line)

    def call(self, method: str, **params):
        resp = self._rpc(method, params)
        if not resp.get("ok"):
            raise RuntimeError(f"node.{method} failed: {resp['error']}")
        return resp["result"]

    def call_expect_error(self, method: str, **params) -> str:
        resp = self._rpc(method, params)
        if resp.get("ok"):
            raise AssertionError(f"node.{method} unexpectedly succeeded")
        return resp["error"]

    def close(self) -> None:
        try:
            self._proc.stdin.close()
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()


@pytest.fixture(scope="module")
def node():
    """A live Node interop worker, shared across the module's tests."""
    if shutil.which("node") is None:
        pytest.skip("node executable not found on PATH")
    worker = NodeWorker()
    try:
        worker.call("ping")  # fail fast if the acdp-node binding is not built
        yield worker
    finally:
        worker.close()


# ── Tests ───────────────────────────────────────────────────────────────


def _python_publish(opts: dict) -> str:
    """Build a wire JSON publish request from the Python binding."""
    p = acdp.AcdpProducer.from_seed(SEED, AGENT_DID, KEY_ID)
    return p.build_publish_request(**opts)


def _node_publish(node, opts_camel: dict) -> str:
    """Build a wire JSON publish request from the Node binding."""
    producer = node.call(
        "new_producer", agent_did=AGENT_DID, key_id=KEY_ID, seed=list(SEED)
    )
    return node.call(
        "build_publish_request",
        producer=producer["handle"],
        opts=opts_camel,
    )["raw"]


def test_python_matches_golden_hash_and_signature():
    raw = _python_publish(
        {
            "title": "Golden test vector — minimal first version",
            "context_type": "data_snapshot",
        }
    )
    req = json.loads(raw)
    assert req["content_hash"] == GOLDEN_HASH
    assert req["signature"]["value"] == GOLDEN_SIG


def test_node_matches_golden_hash_and_signature(node):
    raw = _node_publish(
        node,
        {
            "title": "Golden test vector — minimal first version",
            "contextType": "data_snapshot",
        },
    )
    req = json.loads(raw)
    assert req["content_hash"] == GOLDEN_HASH
    assert req["signature"]["value"] == GOLDEN_SIG


def test_python_and_node_emit_byte_identical_publish_requests(node):
    """The JCS + SHA-256 content_hash and the deterministic Ed25519
    signature MUST match byte-for-byte across both bindings when given
    the same seed and the same minimal first-version inputs.
    """
    py_raw = _python_publish(
        {
            "title": "Golden test vector — minimal first version",
            "context_type": "data_snapshot",
        }
    )
    node_raw = _node_publish(
        node,
        {
            "title": "Golden test vector — minimal first version",
            "contextType": "data_snapshot",
        },
    )
    py_req = json.loads(py_raw)
    node_req = json.loads(node_raw)

    assert py_req["content_hash"] == node_req["content_hash"]
    assert py_req["signature"]["value"] == node_req["signature"]["value"]
    assert py_req["signature"]["algorithm"] == node_req["signature"]["algorithm"]
    assert py_req["signature"]["key_id"] == node_req["signature"]["key_id"]
    assert py_req["agent_id"] == node_req["agent_id"]


def test_python_and_node_match_on_a_richer_body(node):
    """Same equality check with summary, tags, domain, derived_from,
    contributors set — exercises every optional field that lands in the
    hash preimage.
    """
    derived = (
        "acdp://registry.example.com/12345678-1234-4321-8123-123456781234"
    )
    py_raw = _python_publish(
        {
            "title": "Interop body",
            "context_type": "analysis",
            "summary": "rich body",
            "tags": ["interop", "golden"],
            "domain": "test.interop",
            "derived_from": [derived],
            "contributors": ["did:web:agents.example.com:contributor"],
            "description": "Cross-language byte-equality assertion.",
        }
    )
    node_raw = _node_publish(
        node,
        {
            "title": "Interop body",
            "contextType": "analysis",
            "summary": "rich body",
            "tags": ["interop", "golden"],
            "domain": "test.interop",
            "derivedFrom": [derived],
            "contributors": ["did:web:agents.example.com:contributor"],
            "description": "Cross-language byte-equality assertion.",
        },
    )
    assert json.loads(py_raw)["content_hash"] == json.loads(node_raw)["content_hash"]
    assert (
        json.loads(py_raw)["signature"]["value"]
        == json.loads(node_raw)["signature"]["value"]
    )


def test_node_verifies_python_signature(node):
    """A PublishRequest built in Python verifies cleanly through the
    Node verifier — same Ed25519 algorithm, same JCS preimage.
    """
    raw = _python_publish(
        {"title": "From Python", "context_type": "data_snapshot"}
    )
    req = json.loads(raw)
    pub_key_b64 = acdp.AcdpProducer.from_seed(
        SEED, AGENT_DID, KEY_ID
    ).public_key_b64

    assert node.call(
        "verify_content_hash",
        body_json=raw,
        expected_hash=req["content_hash"],
    )["ok"]
    assert node.call(
        "verify_signature",
        pub_key_b64=pub_key_b64,
        sig_b64=req["signature"]["value"],
        content_hash=req["content_hash"],
    )["ok"]


def test_python_verifies_node_signature(node):
    """And the reverse: Node-built request verifies in Python."""
    producer = node.call(
        "new_producer", agent_did=AGENT_DID, key_id=KEY_ID, seed=list(SEED)
    )
    raw = node.call(
        "build_publish_request",
        producer=producer["handle"],
        opts={"title": "From Node", "contextType": "data_snapshot"},
    )["raw"]
    req = json.loads(raw)

    assert acdp.AcdpVerifier.verify_content_hash(raw, req["content_hash"])
    assert acdp.AcdpVerifier.verify_signature(
        producer["public_key_b64"],
        req["signature"]["value"],
        req["content_hash"],
    )


def test_sign_challenge_is_deterministic_across_bindings(node):
    """Both bindings sign the same auth-challenge bytes with the same
    seed and MUST produce the same base64 signature.
    """
    signing_input = (
        "acdp-registry-auth:v1:nonce-abc:"
        f"{AGENT_DID}:registry.example.com:1748000000"
    )
    py_sig = acdp.AcdpProducer.from_seed(
        SEED, AGENT_DID, KEY_ID
    ).sign_challenge(signing_input)
    producer = node.call(
        "new_producer", agent_did=AGENT_DID, key_id=KEY_ID, seed=list(SEED)
    )
    node_sig = node.call(
        "sign_challenge",
        producer=producer["handle"],
        signing_input=signing_input,
    )["signature"]
    assert py_sig == node_sig
