"""Cross-language parity for the ACDP 0.3 surface (RFC-ACDP-0011/0012/
0013/0014).

Every artifact the bindings MINT (log leaves, parsed revocations) and
every verdict they RENDER (head receipts, checkpoints, inclusion /
consistency proofs, lifecycle events, revocation boundary
classifications) must be byte-identical between the Python and Node
bindings — both wrap the same Rust core, so any divergence is a
packaging bug, not an implementation choice.

Fixture material is the spec conformance suite: rcpt-001 / lhr-001 /
log-001 / log-003 / rev-001 golden vectors, using the publicly-known
TEST keypairs (registry receipt key seed [0x11]*32).

Run from ``bindings/interop/`` after building both bindings, or via
``make interop``.
"""

import base64
import json

import pytest

import acdp

from test_interop import NodeWorker  # noqa: F401  (fixture plumbing)
from test_interop import node  # noqa: F401  (the shared node fixture)

REGISTRY_DID = "did:web:registry.example.com"
RECEIPT_KEY_ID = f"{REGISTRY_DID}#receipt-key-1"
REGISTRY_SEED = bytes([0x11] * 32)
LINEAGE = "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a"
CTX = "acdp://registry.example.com/12345678-1234-4321-8123-123456781234"
LOG_ID = "did:web:registry.example.com/log/1"
K1_FP = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070"
K2_FP = "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f"

RCPT001 = json.dumps(
    {
        "registry_did": REGISTRY_DID,
        "ctx_id": CTX,
        "lineage_id": LINEAGE,
        "origin_registry": "registry.example.com",
        "created_at": "2026-04-16T10:30:15.123Z",
        "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
        "key_fingerprint": K1_FP,
        "signature": {
            "algorithm": "ed25519",
            "key_id": RECEIPT_KEY_ID,
            "value": "vBgQKmn17pHXXY95C07BBeconmjDIdYIvxN5B+YXrQ7tIzFsDNsh1TglzgxOyPUp8lwTz7zwMNiK+Sn5whveDg==",
        },
    }
)

LHR001 = json.dumps(
    {
        "receipt_version": "acdp-lhr/1",
        "registry_did": REGISTRY_DID,
        "lineage_id": LINEAGE,
        "head_ctx_id": CTX,
        "head_version": 1,
        "head_status": "active",
        "as_of": "2026-07-04T09:00:00.000Z",
        "signature": {
            "algorithm": "ed25519",
            "key_id": RECEIPT_KEY_ID,
            "value": "h4w9cdnmpNXWBkmQQLgbcQ2p22c1wKZCqnHx1sQXE2GuMRP2nlVt+twGikpFPP6zpRCjqEa3UxIxC8Y9qnl7BA==",
        },
    }
)

LHR_EXPECTED = json.dumps(
    {
        "authority": "registry.example.com",
        "lineage_id": LINEAGE,
        "head_ctx_id": CTX,
        "head_version": 1,
        "head_status": "active",
    }
)

LOG001_LEAF_HASHES = [
    "sha256:95d99654d4d3de54a4d7cc04e079de61135023c78bb8192bdb79a09253afb8c1",
    "sha256:846b4d6c07ca099eea348c1e219345ddd426c0531cc30d3dd626d0fa34ec7704",
    "sha256:db94dd74b5c68f6d362129703ea587c8756d65cad0cc9859829021746a114451",
    "sha256:dc309b7856483acb5b2a92323dd9c1571a778bdb7b446587100022b49ee5fb3b",
    "sha256:6f673f8532d24869047264d89e2ad65f6ff2fa3c2674bb2fb9fa02855e090b3a",
]

LOG001_CHECKPOINT = json.dumps(
    {
        "checkpoint_version": "acdp-log/1",
        "log_id": LOG_ID,
        "tree_size": 5,
        "root_hash": "sha256:0b5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731",
        "timestamp": "2026-07-04T12:00:00.000Z",
        "signature": {
            "algorithm": "ed25519",
            "key_id": RECEIPT_KEY_ID,
            "value": "o5rJmVE+1w/f7xAvW2P4vHA9FqWcMpS0crUPkMUZKSrBhrCVt/jyS+PCgnHNsNpmr+N+sR9I9qbqQ/Y0ZfOrDQ==",
        },
    }
)

LOG001_INCLUSION = json.dumps(
    {
        "log_id": LOG_ID,
        "leaf_index": 0,
        "tree_size": 5,
        "inclusion_path": [
            "sha256:846b4d6c07ca099eea348c1e219345ddd426c0531cc30d3dd626d0fa34ec7704",
            "sha256:54d7edc4ba9d151eedd7f4bb872884f0af5ff32b39f98866d67873b00687c605",
            "sha256:6f673f8532d24869047264d89e2ad65f6ff2fa3c2674bb2fb9fa02855e090b3a",
        ],
    }
)

LOG003_PROOF = json.dumps(
    {
        "log_id": LOG_ID,
        "first_tree_size": 3,
        "second_tree_size": 5,
        "consistency_path": [
            "sha256:db94dd74b5c68f6d362129703ea587c8756d65cad0cc9859829021746a114451",
            "sha256:dc309b7856483acb5b2a92323dd9c1571a778bdb7b446587100022b49ee5fb3b",
            "sha256:96659974ae162b1243bdf8b32a8f462cfc00c08a43d77574fad5361042d0a1bc",
            "sha256:6f673f8532d24869047264d89e2ad65f6ff2fa3c2674bb2fb9fa02855e090b3a",
        ],
    }
)
LOG003_FIRST_ROOT = "sha256:cf4604eee5578b1ca5b9414d901840b1c0e6e275222d3f613301989d20f58e9d"

REV001_BODY = json.dumps(
    {
        "version": 1,
        "supersedes": None,
        "agent_id": "did:web:agents.example.com:test-producer",
        "contributors": [],
        "title": "Key revocation — key-1 compromised",
        "summary": (
            "Revocation of the Ed25519 key "
            "did:web:agents.example.com:test-producer#key-1, compromised "
            "since 2026-05-01T00:00:00.000Z."
        ),
        "type": "key-revocation",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public",
        "metadata": {
            "revoked_key_fingerprint": K1_FP,
            "compromised_since": "2026-05-01T00:00:00.000Z",
            "reason": "laptop theft; private key material presumed exfiltrated",
        },
        "acdp_version": "0.3.0",
        "content_hash": "sha256:210bb03ec4bd39de893eb7d39ee992913cda80f767b135a02992a71491bf57ca",
        "signature": {
            "algorithm": "ed25519",
            "key_id": "did:web:agents.example.com:test-producer#key-2",
            "value": "Lf7P+ZifUGPXIkR2i9Vy4LByaTb6ktsakKcjm4ZFUlcgTs2r9/3eyjDJDNWfT+qAseNYecvYggTIGnT7EZiPAw==",
        },
        "ctx_id": "acdp://registry.example.com/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lineage_id": "lin:sha256:6af6229c1c6a4a119695c77e47f6554941aebce3d25ba8567e2ae6ffbb6059cb",
        "origin_registry": "registry.example.com",
        "created_at": "2026-05-02T08:00:00.000Z",
    }
)


def _registry_doc() -> str:
    registry = acdp.AcdpProducer.from_seed(REGISTRY_SEED, REGISTRY_DID, RECEIPT_KEY_ID)
    raw = base64.b64decode(registry.public_key_b64)
    return json.dumps(
        {
            "id": REGISTRY_DID,
            "verificationMethod": [
                {
                    "id": RECEIPT_KEY_ID,
                    "type": "Ed25519VerificationKey2020",
                    "controller": REGISTRY_DID,
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
                    },
                }
            ],
            "assertionMethod": [RECEIPT_KEY_ID],
        }
    )


NOW = "2026-07-04T12:00:10.000Z"


def test_build_log_leaf_is_byte_identical(node):
    py = acdp.AcdpVerifier.build_log_leaf(RCPT001)
    nd = node.call("build_log_leaf", receipt_json=RCPT001)["raw"]
    assert py == nd
    # And both hash to the log-001 pinned leaf-0 hash in both bindings.
    assert acdp.AcdpMerkle.leaf_hash(py) == LOG001_LEAF_HASHES[0]
    assert node.call("merkle_leaf_hash", leaf_json=nd)["result"] == (
        LOG001_LEAF_HASHES[0]
    )


def test_merkle_arithmetic_matches_across_bindings(node):
    hashes_json = json.dumps(LOG001_LEAF_HASHES)
    py_root = acdp.AcdpMerkle.root_hash(hashes_json)
    nd_root = node.call("merkle_root_hash", leaf_hashes_json=hashes_json)["result"]
    assert py_root == nd_root
    py_node = acdp.AcdpMerkle.node_hash(LOG001_LEAF_HASHES[0], LOG001_LEAF_HASHES[1])
    nd_node = node.call(
        "merkle_node_hash",
        left_hash=LOG001_LEAF_HASHES[0],
        right_hash=LOG001_LEAF_HASHES[1],
    )["result"]
    assert py_node == nd_node


def test_lineage_head_receipt_verdicts_match(node):
    doc = _registry_doc()
    now = "2026-07-04T09:00:30.000Z"
    py = acdp.AcdpVerifier.verify_lineage_head_receipt(LHR001, LHR_EXPECTED, doc, now)
    nd = node.call(
        "verify_lineage_head_receipt",
        receipt_json=LHR001,
        expected_json=LHR_EXPECTED,
        registry_did_doc_json=doc,
        now=now,
    )["raw"]
    assert py == nd
    assert json.loads(py)["valid"]

    # Failure verdicts (hostile authority) must match byte-for-byte too
    # — same code, same message.
    hostile = json.dumps(dict(json.loads(LHR_EXPECTED), authority="hostile.example"))
    py = acdp.AcdpVerifier.verify_lineage_head_receipt(LHR001, hostile, doc, now)
    nd = node.call(
        "verify_lineage_head_receipt",
        receipt_json=LHR001,
        expected_json=hostile,
        registry_did_doc_json=doc,
        now=now,
    )["raw"]
    assert py == nd
    assert not json.loads(py)["valid"]


def test_log_verdicts_match(node):
    doc = _registry_doc()
    py = acdp.AcdpVerifier.verify_log_checkpoint(LOG001_CHECKPOINT, doc, LOG_ID, NOW)
    nd = node.call(
        "verify_log_checkpoint",
        checkpoint_json=LOG001_CHECKPOINT,
        registry_did_doc_json=doc,
        expected_log_id=LOG_ID,
        now=NOW,
    )["raw"]
    assert py == nd and json.loads(py)["valid"]

    leaf = acdp.AcdpVerifier.build_log_leaf(RCPT001)
    py = acdp.AcdpVerifier.verify_log_inclusion(
        LOG001_INCLUSION, LOG001_CHECKPOINT, leaf
    )
    nd = node.call(
        "verify_log_inclusion",
        inclusion_json=LOG001_INCLUSION,
        checkpoint_json=LOG001_CHECKPOINT,
        leaf_json=leaf,
    )["raw"]
    assert py == nd and json.loads(py)["valid"]

    py = acdp.AcdpVerifier.verify_log_consistency(
        LOG003_PROOF, LOG001_CHECKPOINT, LOG003_FIRST_ROOT
    )
    nd = node.call(
        "verify_log_consistency",
        consistency_json=LOG003_PROOF,
        checkpoint_json=LOG001_CHECKPOINT,
        first_root_hash=LOG003_FIRST_ROOT,
    )["raw"]
    assert py == nd and json.loads(py)["valid"]


def test_lifecycle_event_minted_in_python_verifies_in_node(node):
    """One binding mints (did:key actor, §5 construction), the other
    verifies — and both verdicts are byte-identical."""
    p = acdp.AcdpProducer.generate_did_key()
    event = {
        "event_id": "018f6d0a-7b2e-4c4d-9e1f-3a5b7c9d1e2f",
        "ctx_id": CTX,
        "event_type": "retracted",
        "occurred_at": "2026-07-04T09:15:42.000Z",
        "actor": p.agent_did,
    }
    preimage_hash = acdp.AcdpCanonicalizer.content_hash(json.dumps(event))
    event["signature"] = {
        "algorithm": "ed25519",
        "key_id": p.key_id,
        "value": p.sign_challenge(preimage_hash),
    }
    event_json = json.dumps(event)
    py = acdp.AcdpVerifier.verify_lifecycle_event(event_json, None, CTX)
    nd = node.call(
        "verify_lifecycle_event", event_json=event_json, expected_ctx_id=CTX
    )["raw"]
    assert py == nd
    assert json.loads(py)["valid"]


def test_parsed_revocation_and_classification_match(node):
    py_rev = acdp.AcdpVerifier.parse_key_revocation(REV001_BODY, K2_FP)
    nd_rev = node.call(
        "parse_key_revocation", body_json=REV001_BODY, signer_fingerprint=K2_FP
    )["raw"]
    assert py_rev == nd_rev

    revs = f"[{py_rev}]"
    for created_at in ("2026-04-16T10:30:15.123Z", "2026-05-03T09:00:00.000Z", None):
        py = acdp.AcdpVerifier.classify_under_revocation(revs, K1_FP, created_at)
        nd = node.call(
            "classify_under_revocation",
            revocations_json=revs,
            signer_fingerprint=K1_FP,
            receipt_created_at=created_at,
        )["raw"]
        assert py == nd, f"classification diverged for created_at={created_at!r}"
