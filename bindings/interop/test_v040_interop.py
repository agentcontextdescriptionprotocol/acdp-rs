"""Cross-language parity for the ACDP 0.4 witness-cosigning surface
(RFC-ACDP-0015).

Every artifact the bindings MINT (witness cosignatures) and every verdict
they RENDER (single-cosignature verification, quorum reports) must be
byte-identical between the Python and Node bindings — both wrap the same
Rust core, so any divergence is a packaging bug, not an implementation
choice.

The strongest guard here is MINT byte-equality: the same witness seed
(0x33*32) MUST produce a byte-identical `log_cosignature` in both
languages — the witness-layer analogue of the sig-001 cross-binding
publish-request equality. Fixture material is the wit-001 / wit-003 /
wit-004 golden vectors, using the publicly-known TEST witness keypairs.

Run from ``bindings/interop/`` after building both bindings, or via
``make interop``.
"""

import json

import acdp

from test_interop import NodeWorker  # noqa: F401  (fixture plumbing)
from test_interop import node  # noqa: F401  (the shared node fixture)

REGISTRY_DID = "did:web:registry.example.com"
RECEIPT_KEY_ID = f"{REGISTRY_DID}#receipt-key-1"
LOG_ID = "did:web:registry.example.com/log/1"
ROOT = "sha256:0b5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731"

WITNESS_A = "did:web:witness.example.org"
WITNESS_A_SEED_HEX = "33" * 32
WITNESS_A_PUB_HEX = "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
WITNESS_B = "did:web:witness-2.example.org"
WITNESS_B_SEED_HEX = "44" * 32
WITNESS_B_PUB_HEX = "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48"

WITNESSED_CHECKPOINT = json.dumps(
    {
        "log_id": LOG_ID,
        "tree_size": 5,
        "root_hash": ROOT,
        "timestamp": "2026-07-04T12:00:00.000Z",
    }
)
WITNESSED_AT_A = "2026-07-04T12:00:05.000Z"
WITNESSED_AT_B = "2026-07-04T12:03:00.000Z"

WIT001_SIG_B64 = (
    "omUcflbxeirUvPyIbuiGW0t7fch/xO2lSzTQwAvOAqsawocn4Y5J69Nwracq1I2Zercj5Qdnlc18NZQyoPcEBA=="
)

LOG001_CHECKPOINT = json.dumps(
    {
        "checkpoint_version": "acdp-log/1",
        "log_id": LOG_ID,
        "tree_size": 5,
        "root_hash": ROOT,
        "timestamp": "2026-07-04T12:00:00.000Z",
        "signature": {
            "algorithm": "ed25519",
            "key_id": RECEIPT_KEY_ID,
            "value": "o5rJmVE+1w/f7xAvW2P4vHA9FqWcMpS0crUPkMUZKSrBhrCVt/jyS+PCgnHNsNpmr+N+sR9I9qbqQ/Y0ZfOrDQ==",
        },
    }
)


def _witness_doc(did: str, pub_hex: str) -> dict:
    import base64

    key_id = f"{did}#witness-key-1"
    x = base64.urlsafe_b64encode(bytes.fromhex(pub_hex)).rstrip(b"=").decode()
    return {
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
            }
        ],
        "assertionMethod": [key_id],
    }


def _py_build(did, seed_hex, witnessed_at):
    return acdp.AcdpVerifier.build_witness_cosignature(
        WITNESSED_CHECKPOINT, did, seed_hex, witnessed_at
    )


def _node_build(node, did, seed_hex, witnessed_at):
    return node.call(
        "build_witness_cosignature",
        witnessed_checkpoint_json=WITNESSED_CHECKPOINT,
        witness_did=did,
        witness_seed_hex=seed_hex,
        witnessed_at_rfc3339=witnessed_at,
    )["raw"]


def test_wit001_minted_cosignature_is_byte_identical(node):
    """The same witness seed produces a byte-identical cosignature in both
    languages — and both equal the wit-001 golden signature."""
    py = _py_build(WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A)
    nd = _node_build(node, WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A)
    assert py == nd
    assert json.loads(py)["signature"]["value"] == WIT001_SIG_B64


def test_witness_b_minted_cosignature_is_byte_identical(node):
    py = _py_build(WITNESS_B, WITNESS_B_SEED_HEX, WITNESSED_AT_B)
    nd = _node_build(node, WITNESS_B, WITNESS_B_SEED_HEX, WITNESSED_AT_B)
    assert py == nd


def test_verify_witness_cosignature_verdicts_match(node):
    cosig = _py_build(WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A)
    doc = json.dumps(_witness_doc(WITNESS_A, WITNESS_A_PUB_HEX))
    now = "2026-07-04T12:00:10.000Z"
    py = acdp.AcdpVerifier.verify_witness_cosignature(cosig, doc, LOG001_CHECKPOINT, now)
    nd = node.call(
        "verify_witness_cosignature",
        cosig_json=cosig,
        witness_did_doc_json=doc,
        expected_checkpoint_json=LOG001_CHECKPOINT,
        now=now,
    )["raw"]
    assert py == nd
    assert json.loads(py)["valid"]


def test_evaluate_witness_quorum_reports_match(node):
    cosig_a = _py_build(WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A)
    cosig_b = _py_build(WITNESS_B, WITNESS_B_SEED_HEX, WITNESSED_AT_B)
    cosigs = json.dumps([json.loads(cosig_a), json.loads(cosig_b)])
    trusted = json.dumps([WITNESS_A, WITNESS_B])
    docs = json.dumps(
        {
            WITNESS_A: _witness_doc(WITNESS_A, WITNESS_A_PUB_HEX),
            WITNESS_B: _witness_doc(WITNESS_B, WITNESS_B_PUB_HEX),
        }
    )
    policy = json.dumps({"min_witnesses": 2})
    now = "2026-07-04T12:10:00.000Z"
    py = acdp.AcdpVerifier.evaluate_witness_quorum(
        cosigs, LOG001_CHECKPOINT, trusted, docs, policy, now
    )
    nd = node.call(
        "evaluate_witness_quorum",
        cosignatures_json=cosigs,
        expected_checkpoint_json=LOG001_CHECKPOINT,
        trusted_witness_dids_json=trusted,
        witness_did_docs_json=docs,
        policy_json=policy,
        now=now,
    )["raw"]
    assert py == nd
    assert json.loads(py)["witnessed_count"] == 2
    assert json.loads(py)["meets_quorum"]
