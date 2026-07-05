"""ACDP 0.3 surface: lineage-head receipts (RFC-ACDP-0011),
transparency-log verification (RFC-ACDP-0012), lifecycle events
(RFC-ACDP-0013), and key revocation (RFC-ACDP-0014).

Pins the spec conformance fixtures byte-for-byte: lhr-001 (golden head
receipt), log-001/log-003 (leaf encodings, leaf hashes, Merkle root,
signed checkpoint, inclusion + consistency proofs), rev-001 (golden
revocation context), plus the failure fixtures lhr-002/003/004,
log-002/004, and the rev-002 boundary scenarios. All keys are the
publicly-known spec TEST keypairs (registry receipt key seed
[0x11]*32; producer K2 seed [0x42]*32) — never production material.

Build with `maturin develop` from `bindings/acdp-py/`, then run
`pytest`. No HTTP is involved — every DID document is supplied inline,
mirroring how the binding pushes resolution to the host.

These mirror the Node SDK's tests/v030.mjs so both bindings stay in
sync against the same Rust core.
"""
import base64
import json

import pytest

import acdp

REGISTRY_DID = "did:web:registry.example.com"
RECEIPT_KEY_ID = f"{REGISTRY_DID}#receipt-key-1"
REGISTRY_SEED = bytes([0x11] * 32)

LINEAGE = "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a"
CTX = "acdp://registry.example.com/12345678-1234-4321-8123-123456781234"
LOG_ID = "did:web:registry.example.com/log/1"

# fp-001 / K1 — the sig-001 producer key fingerprint.
K1_FP = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070"
# rev-001 / K2 — the producer's current key (sig-003 seed).
K2_FP = "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f"


def _b64url(standard_b64: str) -> str:
    return (
        base64.urlsafe_b64encode(base64.b64decode(standard_b64))
        .rstrip(b"=")
        .decode()
    )


def _registry_doc(assertion: bool = True) -> str:
    """The registry's DID document carrying the [0x11]*32 receipt key,
    optionally rotated out of assertionMethod (retired receipt key)."""
    registry = acdp.AcdpProducer.from_seed(REGISTRY_SEED, REGISTRY_DID, RECEIPT_KEY_ID)
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
                        "x": _b64url(registry.public_key_b64),
                    },
                }
            ],
            "assertionMethod": [RECEIPT_KEY_ID] if assertion else [],
        }
    )


# ── lhr-001 — lineage-head receipt golden vector (RFC-ACDP-0011 §5) ─────

LHR001 = {
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

LHR_EXPECTED = {
    "authority": "registry.example.com",
    "lineage_id": LINEAGE,
    "head_ctx_id": CTX,
    "head_version": 1,
    "head_status": "active",
}


def _verify_lhr(receipt=None, expected=None, doc=None, now="2026-07-04T09:00:30.000Z", **kw):
    return json.loads(
        acdp.AcdpVerifier.verify_lineage_head_receipt(
            json.dumps(receipt if receipt is not None else LHR001),
            json.dumps(expected if expected is not None else LHR_EXPECTED),
            doc if doc is not None else _registry_doc(),
            now,
            **kw,
        )
    )


def test_lhr001_golden_receipt_verifies():
    v = _verify_lhr()
    assert v == {"valid": True, "stale": False, "age_secs": 30, "historical": False}


def test_lhr001_signature_pins_the_golden_bytes():
    """The lhr-001 pinned signature is exactly what the [0x11]*32
    registry key produces over the pinned receipt hash — the same
    sign-the-ASCII-hash construction as sig-001."""
    unsigned = {k: v for k, v in LHR001.items() if k != "signature"}
    receipt_hash = acdp.AcdpCanonicalizer.content_hash(json.dumps(unsigned))
    assert receipt_hash == (
        "sha256:ae53a9479349d5bc224a8d0ac2464762d47831e0ec74462e48b9aa6a6081ea2a"
    )
    registry = acdp.AcdpProducer.from_seed(REGISTRY_SEED, REGISTRY_DID, RECEIPT_KEY_ID)
    assert registry.sign_challenge(receipt_hash) == LHR001["signature"]["value"]


def test_lhr_stale_but_valid_is_a_freshness_verdict():
    # One hour past as_of: verification passes, staleness is policy.
    v = _verify_lhr(now="2026-07-04T10:00:00.000Z")
    assert v["valid"] and v["stale"] and v["age_secs"] == 3600
    # A larger max_age_secs unstales it.
    v = _verify_lhr(now="2026-07-04T10:00:00.000Z", max_age_secs=7200)
    assert v["valid"] and not v["stale"]


def test_lhr_retired_receipt_key_verifies_as_historical():
    v = _verify_lhr(doc=_registry_doc(assertion=False))
    assert v["valid"] and v["historical"]


def test_lhr002_stale_head_mismatch_on_current():
    """lhr-002: /current serves a v2 body but the receipt attests the
    v1 head — §7 step 5 byte-match MUST fail."""
    expected = dict(
        LHR_EXPECTED,
        head_ctx_id="acdp://registry.example.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        head_version=2,
    )
    v = _verify_lhr(expected=expected)
    assert not v["valid"]
    assert v["code"] == "invalid_receipt"
    assert "head_ctx_id" in v["error"]


def test_lhr_step5b_full_retrieval_of_superseded_version_is_consistent():
    """On full retrieval (not /current) a receipt naming a NEWER head is
    consistent iff head_version > served version and the served status
    is superseded (§7 step 5b)."""
    receipt = dict(
        LHR001,
        head_ctx_id="acdp://registry.example.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        head_version=2,
    )
    # Re-sign the modified receipt with the registry test key.
    unsigned = {k: v for k, v in receipt.items() if k != "signature"}
    registry = acdp.AcdpProducer.from_seed(REGISTRY_SEED, REGISTRY_DID, RECEIPT_KEY_ID)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "key_id": RECEIPT_KEY_ID,
        "value": registry.sign_challenge(
            acdp.AcdpCanonicalizer.content_hash(json.dumps(unsigned))
        ),
    }
    expected = dict(LHR_EXPECTED, head_status="superseded", on_current_endpoint=False)
    assert _verify_lhr(receipt=receipt, expected=expected)["valid"]
    # Self-contradictory: served status still 'active'.
    expected = dict(LHR_EXPECTED, on_current_endpoint=False)
    v = _verify_lhr(receipt=receipt, expected=expected)
    assert not v["valid"] and v["code"] == "invalid_receipt"


def test_lhr003_replay_on_hostile_authority_fails():
    """lhr-003: the golden receipt replayed verbatim from
    hostile.example — §7 step 3 registry binding MUST fail even though
    the signature verifies under registry.example.com's key."""
    expected = dict(LHR_EXPECTED, authority="hostile.example")
    v = _verify_lhr(expected=expected)
    assert not v["valid"] and v["code"] == "invalid_receipt"
    # capabilities.registry_did mismatch likewise.
    expected = dict(LHR_EXPECTED, registry_did="did:web:other.example")
    v = _verify_lhr(expected=expected)
    assert not v["valid"] and v["code"] == "invalid_receipt"


def test_lhr004_future_as_of_fails_step6():
    """lhr-004: as_of nearly a decade ahead of the consumer clock —
    signature-valid, but step 6 MUST reject the forged freshness
    claim. Honest skew within the allowance passes."""
    receipt = dict(LHR001, as_of="2036-01-01T00:00:00.000Z")
    receipt["signature"] = dict(
        LHR001["signature"],
        value="DjQpxCPq2Yai85KlTLCFhMu+nEOZE7dHhSLIsTEbcl+DI5p8cBx/bL+eHPenzD2Wd1d6p2hZpK9g+/xavLc3BA==",
    )
    v = _verify_lhr(receipt=receipt, now="2026-07-04T09:00:00.000Z")
    assert not v["valid"] and v["code"] == "invalid_receipt"
    assert "as_of" in v["error"]
    # Boundary case from the fixture: within-skew future as_of passes.
    v = _verify_lhr(now="2026-07-04T08:59:00.000Z")  # as_of 60s ahead
    assert v["valid"]


def test_lhr_tampered_field_fails_signature():
    receipt = dict(LHR001, head_status="expired")
    v = _verify_lhr(receipt=receipt, expected=dict(LHR_EXPECTED, head_status="expired"))
    assert not v["valid"] and v["code"] == "invalid_receipt"


def test_lhr_unknown_member_rejected_closed_schema():
    receipt = dict(LHR001, freshness_proof=True)
    v = _verify_lhr(receipt=receipt)
    assert not v["valid"] and v["code"] == "invalid_receipt"


def test_lhr_malformed_expected_raises():
    with pytest.raises(ValueError, match="lineage_id"):
        acdp.AcdpVerifier.verify_lineage_head_receipt(
            json.dumps(LHR001),
            json.dumps({"authority": "registry.example.com"}),
            _registry_doc(),
        )


# ── log-001 — transparency-log golden vector (RFC-ACDP-0012) ────────────

LOG001_LEAVES = [
    {
        "leaf_version": "acdp-log-leaf/1",
        "ctx_id": CTX,
        "lineage_id": LINEAGE,
        "origin_registry": "registry.example.com",
        "created_at": "2026-04-16T10:30:15.123Z",
        "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
        "key_fingerprint": K1_FP,
        "receipt_hash": "sha256:9deaa52778ad3b6be27a96d607c3017e9e11442905891a8972f34d8c2dbca9cf",
    },
    {
        "leaf_version": "acdp-log-leaf/1",
        "ctx_id": "acdp://registry.example.com/00000000-0000-4000-8000-000000000001",
        "lineage_id": "lin:sha256:a65dce2bc7d3d2f52513c14c9d7262903c960490b17308b272981240a76c2d42",
        "origin_registry": "registry.example.com",
        "created_at": "2026-07-01T01:00:00.000Z",
        "content_hash": "sha256:5b8be477da9b3e1354ebf2868494acb702301aaa825c1c3af3f92c5536ba7bd1",
        "key_fingerprint": K1_FP,
        "receipt_hash": "sha256:2b8fa37afe87358aa039e78802f4a9b9fb4bc5df2a814a3f7cf5200f7f64b3df",
    },
    {
        "leaf_version": "acdp-log-leaf/1",
        "ctx_id": "acdp://registry.example.com/00000000-0000-4000-8000-000000000002",
        "lineage_id": "lin:sha256:518c191ba24d2fea433a768e232cb1d0ff152a39b38f28ac7f91960c9f8f7aba",
        "origin_registry": "registry.example.com",
        "created_at": "2026-07-02T02:00:00.000Z",
        "content_hash": "sha256:a0c8d76890ec38db8791e82d7a8e24194f84c13ae67bdaa167540b58cb95507b",
        "key_fingerprint": K1_FP,
        "receipt_hash": "sha256:591fa4c29669546b777bd1a4583aa724e9586b083c096d4b62f68b630dd18834",
    },
    {
        "leaf_version": "acdp-log-leaf/1",
        "ctx_id": "acdp://registry.example.com/00000000-0000-4000-8000-000000000003",
        "lineage_id": "lin:sha256:1d941fb2ecdad88db6f9f3ecd5993178ab94f72e1061e685441d11ef04d92c05",
        "origin_registry": "registry.example.com",
        "created_at": "2026-07-03T03:00:00.000Z",
        "content_hash": "sha256:acbd2ea0c5608db56e1bd38bb0145a6f8363b30d8610abb746014a11f1a53c55",
        "key_fingerprint": K1_FP,
        "receipt_hash": "sha256:342e57dc6d174cc7fe974c99f16c19ba598dfa31f41e560112db3f5ef21c5d91",
    },
    {
        "leaf_version": "acdp-log-leaf/1",
        "ctx_id": "acdp://registry.example.com/00000000-0000-4000-8000-000000000004",
        "lineage_id": "lin:sha256:c1987e0ba3e82db332daaafd64547aa6cbb66f191d53d2023a0ff78dc6c07063",
        "origin_registry": "registry.example.com",
        "created_at": "2026-07-04T04:00:00.000Z",
        "content_hash": "sha256:6f72132b15b294cea2e753efc9b7a105d6d7ebd1527adecd9f2bfc7a677a129b",
        "key_fingerprint": K1_FP,
        "receipt_hash": "sha256:88ee7b664509a56dbd597ccd2f8e19c39e0aaf2c75133d0b73781ce14cf5169f",
    },
]

LOG001_LEAF_HASHES = [
    "sha256:95d99654d4d3de54a4d7cc04e079de61135023c78bb8192bdb79a09253afb8c1",
    "sha256:846b4d6c07ca099eea348c1e219345ddd426c0531cc30d3dd626d0fa34ec7704",
    "sha256:db94dd74b5c68f6d362129703ea587c8756d65cad0cc9859829021746a114451",
    "sha256:dc309b7856483acb5b2a92323dd9c1571a778bdb7b446587100022b49ee5fb3b",
    "sha256:6f673f8532d24869047264d89e2ad65f6ff2fa3c2674bb2fb9fa02855e090b3a",
]

LOG001_ROOT = "sha256:0b5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731"
EMPTY_ROOT = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

LOG001_CHECKPOINT = {
    "checkpoint_version": "acdp-log/1",
    "log_id": LOG_ID,
    "tree_size": 5,
    "root_hash": LOG001_ROOT,
    "timestamp": "2026-07-04T12:00:00.000Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": RECEIPT_KEY_ID,
        "value": "o5rJmVE+1w/f7xAvW2P4vHA9FqWcMpS0crUPkMUZKSrBhrCVt/jyS+PCgnHNsNpmr+N+sR9I9qbqQ/Y0ZfOrDQ==",
    },
}

LOG001_INCLUSION = {
    "log_id": LOG_ID,
    "leaf_index": 0,
    "tree_size": 5,
    "inclusion_path": [
        "sha256:846b4d6c07ca099eea348c1e219345ddd426c0531cc30d3dd626d0fa34ec7704",
        "sha256:54d7edc4ba9d151eedd7f4bb872884f0af5ff32b39f98866d67873b00687c605",
        "sha256:6f673f8532d24869047264d89e2ad65f6ff2fa3c2674bb2fb9fa02855e090b3a",
    ],
}

# rcpt-001: leaf 0's source receipt (its preimage hash is leaf 0's
# receipt_hash).
RCPT001 = {
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


def test_log001_leaf_hashes_match_golden():
    for leaf, expected in zip(LOG001_LEAVES, LOG001_LEAF_HASHES):
        assert acdp.AcdpMerkle.leaf_hash(json.dumps(leaf)) == expected


def test_log001_root_matches_golden():
    assert acdp.AcdpMerkle.root_hash(json.dumps(LOG001_LEAF_HASHES)) == LOG001_ROOT


def test_empty_tree_root_is_sha256_of_empty_string():
    assert acdp.AcdpMerkle.root_hash("[]") == EMPTY_ROOT


def test_node_hash_rebuilds_an_interior_node():
    # node(leaf0, leaf1) is the third consistency-path element of log-003.
    assert (
        acdp.AcdpMerkle.node_hash(LOG001_LEAF_HASHES[0], LOG001_LEAF_HASHES[1])
        == "sha256:96659974ae162b1243bdf8b32a8f462cfc00c08a43d77574fad5361042d0a1bc"
    )


def test_merkle_rejects_malformed_inputs_with_typed_exception():
    with pytest.raises(acdp.InvalidLogProof):
        acdp.AcdpMerkle.node_hash("sha256:short", LOG001_LEAF_HASHES[0])
    with pytest.raises(acdp.InvalidLogProof):
        acdp.AcdpMerkle.root_hash(json.dumps(["not-a-hash"]))
    # A leaf with an unknown member is not a §4 leaf — closed schema.
    bad_leaf = dict(LOG001_LEAVES[0], note="x")
    with pytest.raises(acdp.InvalidLogProof):
        acdp.AcdpMerkle.leaf_hash(json.dumps(bad_leaf))


def test_build_log_leaf_reconstructs_leaf0_from_rcpt001():
    """§9.1 step 1: the leaf rebuilt from the verified rcpt-001 receipt
    equals the fixture's leaf 0 byte-for-byte (including receipt_hash =
    rcpt-001's preimage hash)."""
    leaf = acdp.AcdpVerifier.build_log_leaf(json.dumps(RCPT001))
    assert json.loads(leaf) == LOG001_LEAVES[0]


def test_build_log_leaf_rejects_malformed_receipt():
    with pytest.raises(Exception, match="(?i)created_at"):
        acdp.AcdpVerifier.build_log_leaf(
            json.dumps(dict(RCPT001, created_at="2026-04-16T10:30:15Z"))
        )


def test_log001_checkpoint_verifies():
    v = json.loads(
        acdp.AcdpVerifier.verify_log_checkpoint(
            json.dumps(LOG001_CHECKPOINT),
            _registry_doc(),
            LOG_ID,
            "2026-07-04T12:00:10.000Z",
        )
    )
    assert v["valid"]
    assert v["log_id"] == LOG_ID
    assert v["tree_size"] == 5
    assert v["root_hash"] == LOG001_ROOT
    assert not v["historical"]


def test_log_checkpoint_log_id_pin():
    """§7.4: a different log_id (history reset) is detectable when the
    consumer pins the instance it has been following."""
    v = json.loads(
        acdp.AcdpVerifier.verify_log_checkpoint(
            json.dumps(LOG001_CHECKPOINT),
            _registry_doc(),
            "did:web:registry.example.com/log/2",
            "2026-07-04T12:00:10.000Z",
        )
    )
    assert not v["valid"] and v["code"] == "invalid_log_proof"


def test_log004_tampered_root_fails_checkpoint_signature():
    """log-004: root_hash flipped after signing — the signature no
    longer verifies; byte-comparing served values instead of
    recomputing would wrongly accept it."""
    tampered = dict(
        LOG001_CHECKPOINT,
        root_hash="sha256:fb5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731",
    )
    v = json.loads(
        acdp.AcdpVerifier.verify_log_checkpoint(
            json.dumps(tampered), _registry_doc(), LOG_ID, "2026-07-04T12:00:10.000Z"
        )
    )
    assert not v["valid"] and v["code"] == "invalid_log_proof"


def test_log_checkpoint_future_timestamp_fails_skew():
    v = json.loads(
        acdp.AcdpVerifier.verify_log_checkpoint(
            json.dumps(LOG001_CHECKPOINT),
            _registry_doc(),
            LOG_ID,
            "2026-07-04T11:00:00.000Z",  # checkpoint is 1h in the future
        )
    )
    assert not v["valid"] and v["code"] == "invalid_log_proof"


def test_log001_inclusion_proof_verifies():
    leaf = acdp.AcdpVerifier.build_log_leaf(json.dumps(RCPT001))
    v = json.loads(
        acdp.AcdpVerifier.verify_log_inclusion(
            json.dumps(LOG001_INCLUSION), json.dumps(LOG001_CHECKPOINT), leaf
        )
    )
    assert v["valid"]
    assert v["leaf_hash"] == LOG001_LEAF_HASHES[0]


def test_log002_tampered_inclusion_path_fails():
    """log-002: one flipped path element — the §9.1 fold no longer
    reaches the checkpoint root."""
    tampered = dict(
        LOG001_INCLUSION,
        inclusion_path=[
            LOG001_INCLUSION["inclusion_path"][0],
            "sha256:04d7edc4ba9d151eedd7f4bb872884f0af5ff32b39f98866d67873b00687c605",
            LOG001_INCLUSION["inclusion_path"][2],
        ],
    )
    leaf = acdp.AcdpVerifier.build_log_leaf(json.dumps(RCPT001))
    v = json.loads(
        acdp.AcdpVerifier.verify_log_inclusion(
            json.dumps(tampered), json.dumps(LOG001_CHECKPOINT), leaf
        )
    )
    assert not v["valid"] and v["code"] == "invalid_log_proof"


def test_log_inclusion_rejects_substituted_embedded_checkpoint():
    """A proof quietly embedding a DIFFERENT checkpoint than the one
    the caller verified must be refused, not silently preferred."""
    embedded = dict(LOG001_INCLUSION, log_checkpoint=dict(LOG001_CHECKPOINT, tree_size=6))
    leaf = acdp.AcdpVerifier.build_log_leaf(json.dumps(RCPT001))
    v = json.loads(
        acdp.AcdpVerifier.verify_log_inclusion(
            json.dumps(embedded), json.dumps(LOG001_CHECKPOINT), leaf
        )
    )
    assert not v["valid"] and "differs" in v["error"]


def test_log_inclusion_binding_checks_fire():
    leaf = acdp.AcdpVerifier.build_log_leaf(json.dumps(RCPT001))
    # leaf_index >= tree_size.
    v = json.loads(
        acdp.AcdpVerifier.verify_log_inclusion(
            json.dumps(dict(LOG001_INCLUSION, leaf_index=5)),
            json.dumps(LOG001_CHECKPOINT),
            leaf,
        )
    )
    assert not v["valid"]
    # tree_size ≠ checkpoint.tree_size.
    v = json.loads(
        acdp.AcdpVerifier.verify_log_inclusion(
            json.dumps(dict(LOG001_INCLUSION, tree_size=4)),
            json.dumps(LOG001_CHECKPOINT),
            leaf,
        )
    )
    assert not v["valid"]


# ── log-003 — consistency proof golden vector (§9.2) ────────────────────

LOG003_FIRST_ROOT = "sha256:cf4604eee5578b1ca5b9414d901840b1c0e6e275222d3f613301989d20f58e9d"

LOG003_PROOF = {
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


def test_log003_consistency_proof_verifies():
    # The retained size-3 root is recomputable from the golden leaves.
    assert (
        acdp.AcdpMerkle.root_hash(json.dumps(LOG001_LEAF_HASHES[:3])) == LOG003_FIRST_ROOT
    )
    v = json.loads(
        acdp.AcdpVerifier.verify_log_consistency(
            json.dumps(LOG003_PROOF), json.dumps(LOG001_CHECKPOINT), LOG003_FIRST_ROOT
        )
    )
    assert v == {"valid": True}


def test_log003_history_rewrite_detected():
    """A retained root the path cannot reach = evidence the registry
    rewrote logged history."""
    v = json.loads(
        acdp.AcdpVerifier.verify_log_consistency(
            json.dumps(LOG003_PROOF),
            json.dumps(LOG001_CHECKPOINT),
            "sha256:" + "e" * 64,
        )
    )
    assert not v["valid"] and v["code"] == "invalid_log_proof"
    # A tampered path element likewise.
    tampered = dict(LOG003_PROOF)
    tampered["consistency_path"] = ["sha256:" + "0" * 64] + LOG003_PROOF[
        "consistency_path"
    ][1:]
    v = json.loads(
        acdp.AcdpVerifier.verify_log_consistency(
            json.dumps(tampered), json.dumps(LOG001_CHECKPOINT), LOG003_FIRST_ROOT
        )
    )
    assert not v["valid"] and v["code"] == "invalid_log_proof"


# ── Lifecycle events (RFC-ACDP-0013) ────────────────────────────────────

EVENT_ID = "018f6d0a-7b2e-4c4d-9e1f-3a5b7c9d1e2f"


def _signed_event(producer, event_type="retracted", ctx_id=CTX, **overrides):
    """Mint a §5-signed lifecycle event with the binding's own crypto:
    the signature is over the ASCII bytes of the preimage hash (the
    event minus `signature`), exactly the receipt construction."""
    event = {
        "event_id": EVENT_ID,
        "ctx_id": ctx_id,
        "event_type": event_type,
        "occurred_at": "2026-07-04T09:15:42.000Z",
        "actor": producer.agent_did,
        "reason": "underlying data source found to be fabricated",
    }
    event.update(overrides)
    preimage_hash = acdp.AcdpCanonicalizer.content_hash(json.dumps(event))
    event["signature"] = {
        "algorithm": "ed25519",
        "key_id": producer.key_id,
        "value": producer.sign_challenge(preimage_hash),
    }
    return event


def test_lifecycle_event_did_key_actor_verifies_offline():
    p = acdp.AcdpProducer.generate_did_key()
    event = _signed_event(p)
    v = json.loads(
        acdp.AcdpVerifier.verify_lifecycle_event(json.dumps(event), None, CTX)
    )
    assert v["valid"]
    assert v["event_type"] == "retracted"
    assert v["actor"] == p.agent_did


def test_lifecycle_event_did_web_actor_verifies_against_supplied_doc():
    actor_did = "did:web:agents.example.com:test-producer"
    key_id = f"{actor_did}#key-2"
    p = acdp.AcdpProducer.generate(actor_did, key_id)
    doc = json.dumps(
        {
            "id": actor_did,
            "verificationMethod": [
                {
                    "id": key_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": actor_did,
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": _b64url(p.public_key_b64),
                    },
                }
            ],
            "assertionMethod": [key_id],
        }
    )
    event = _signed_event(p)
    v = json.loads(acdp.AcdpVerifier.verify_lifecycle_event(json.dumps(event), doc, CTX))
    assert v["valid"], v

    # did:web actor without a document → the host forgot resolution.
    v = json.loads(
        acdp.AcdpVerifier.verify_lifecycle_event(json.dumps(event), None, CTX)
    )
    assert not v["valid"] and v["code"] == "key_resolution"


def test_lifecycle_event_replay_against_other_ctx_fails():
    p = acdp.AcdpProducer.generate_did_key()
    event = _signed_event(p)
    other = "acdp://registry.example.com/00000000-0000-4000-8000-000000000009"
    v = json.loads(
        acdp.AcdpVerifier.verify_lifecycle_event(json.dumps(event), None, other)
    )
    assert not v["valid"] and "ctx_id" in v["error"]


def test_lifecycle_event_tampering_and_shape_violations_fail():
    p = acdp.AcdpProducer.generate_did_key()
    event = _signed_event(p)

    # Tampered reason breaks the signature.
    tampered = dict(event, reason="innocuous edit")
    v = json.loads(
        acdp.AcdpVerifier.verify_lifecycle_event(json.dumps(tampered), None, CTX)
    )
    assert not v["valid"]

    # Unsigned producer event fails (§5: MUST be signed).
    unsigned = {k: v for k, v in event.items() if k != "signature"}
    v = json.loads(
        acdp.AcdpVerifier.verify_lifecycle_event(json.dumps(unsigned), None, CTX)
    )
    assert not v["valid"] and "signature" in v["error"]

    # Closed schema: unknown member rejected.
    extended = dict(event, severity="high")
    v = json.loads(
        acdp.AcdpVerifier.verify_lifecycle_event(json.dumps(extended), None, CTX)
    )
    assert not v["valid"]

    # Non-canonical occurred_at byte form rejected.
    v = json.loads(
        acdp.AcdpVerifier.verify_lifecycle_event(
            json.dumps(dict(event, occurred_at="2026-07-04T09:15:42Z")), None, CTX
        )
    )
    assert not v["valid"]

    # Actor binding: signature.key_id DID ≠ actor.
    forged = dict(event, actor="did:key:z6MkghLt1e8m1fmANsdJJco3aCLV8Xnigr5UWwC3u5iZFPd3")
    v = json.loads(
        acdp.AcdpVerifier.verify_lifecycle_event(json.dumps(forged), None, CTX)
    )
    assert not v["valid"]


def test_lifecycle_unknown_event_type_is_tolerated_and_verifies():
    """§7.3: unknown event_type VALUES matching the pattern verify fine
    (retraction-state effect is the host's derivation, where they are
    inert)."""
    p = acdp.AcdpProducer.generate_did_key()
    event = _signed_event(p, event_type="annotated")
    v = json.loads(
        acdp.AcdpVerifier.verify_lifecycle_event(json.dumps(event), None, CTX)
    )
    assert v["valid"] and v["event_type"] == "annotated"


# ── rev-001 / rev-002 — key revocation (RFC-ACDP-0014) ──────────────────

REV001_BODY = {
    "version": 1,
    "supersedes": None,
    "agent_id": "did:web:agents.example.com:test-producer",
    "contributors": [],
    "title": "Key revocation — key-1 compromised",
    "summary": (
        "Revocation of the Ed25519 key did:web:agents.example.com:test-producer#key-1, "
        "compromised since 2026-05-01T00:00:00.000Z."
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
    # registry-assigned (rev-001 registry_assigned block)
    "ctx_id": "acdp://registry.example.com/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
    "lineage_id": "lin:sha256:6af6229c1c6a4a119695c77e47f6554941aebce3d25ba8567e2ae6ffbb6059cb",
    "origin_registry": "registry.example.com",
    "created_at": "2026-05-02T08:00:00.000Z",
}


def test_rev001_body_hash_and_signature_are_the_golden_ones():
    """The revocation is an ordinary signed body: content_hash
    recomputes and K2's signature verifies — the same pipeline as any
    context."""
    assert acdp.AcdpVerifier.verify_content_hash(
        json.dumps(REV001_BODY), REV001_BODY["content_hash"]
    )
    k2 = acdp.AcdpProducer.from_seed(
        bytes([0x42] * 32),
        "did:web:agents.example.com:test-producer",
        "did:web:agents.example.com:test-producer#key-2",
    )
    assert acdp.AcdpVerifier.verify_signature(
        k2.public_key_b64,
        REV001_BODY["signature"]["value"],
        REV001_BODY["content_hash"],
    )
    assert acdp.AcdpVerifier.fingerprint_ed25519_b64(k2.public_key_b64) == K2_FP


def test_rev001_parses_with_producer_signed_trust_class():
    rev = json.loads(
        acdp.AcdpVerifier.parse_key_revocation(json.dumps(REV001_BODY), K2_FP)
    )
    assert rev == {
        "revoked_key_fingerprint": K1_FP,
        "compromised_since": "2026-05-01T00:00:00.000Z",
        "reason": "laptop theft; private key material presumed exfiltrated",
        "revoked_key_controller": "did:web:agents.example.com:test-producer",
        "publisher": "did:web:agents.example.com:test-producer",
        "trust_class": "producer_signed",
    }


def test_rev001_self_signed_revocation_rejected():
    """§5 step 2: a revocation signed by the very key it revokes proves
    only possession of the attacker-held key."""
    with pytest.raises(Exception, match="(?i)not.*authorized|same key"):
        acdp.AcdpVerifier.parse_key_revocation(json.dumps(REV001_BODY), K1_FP)


def test_registry_attested_trust_class_is_distinguishable():
    """§6: published under the registry's identity with an explicit
    foreign controller → the weaker class, never collapsed."""
    body = json.loads(json.dumps(REV001_BODY))
    body["agent_id"] = REGISTRY_DID
    body["metadata"]["revoked_key_controller"] = (
        "did:web:agents.example.com:test-producer"
    )
    rev = json.loads(acdp.AcdpVerifier.parse_key_revocation(json.dumps(body)))
    assert rev["trust_class"] == "registry_attested"
    assert rev["publisher"] == REGISTRY_DID
    assert rev["revoked_key_controller"] == "did:web:agents.example.com:test-producer"


def test_rev_shape_violations_rejected():
    # Non-public visibility protects nobody outside the audience.
    body = dict(REV001_BODY, visibility="private")
    with pytest.raises(ValueError, match="(?i)public"):
        acdp.AcdpVerifier.parse_key_revocation(json.dumps(body))
    # Malformed fingerprint form.
    body = json.loads(json.dumps(REV001_BODY))
    body["metadata"]["revoked_key_fingerprint"] = "sha256:SHOUTING"
    with pytest.raises(ValueError):
        acdp.AcdpVerifier.parse_key_revocation(json.dumps(body))
    # Non-canonical compromised_since byte form.
    body = json.loads(json.dumps(REV001_BODY))
    body["metadata"]["compromised_since"] = "2026-05-01T00:00:00Z"
    with pytest.raises(ValueError):
        acdp.AcdpVerifier.parse_key_revocation(json.dumps(body))
    # Not a key-revocation context at all.
    body = dict(REV001_BODY, type="analysis")
    with pytest.raises(ValueError):
        acdp.AcdpVerifier.parse_key_revocation(json.dumps(body))


def _rev001_parsed():
    return acdp.AcdpVerifier.parse_key_revocation(json.dumps(REV001_BODY), K2_FP)


def test_rev002_scenario_a_pre_compromise_receipt_attested():
    """rev-002 A: rcpt-001's created_at (2026-04-16) < T (2026-05-01) →
    the distinguishable pre-compromise status, with the boundary
    visible in the verdict."""
    v = json.loads(
        acdp.AcdpVerifier.classify_under_revocation(
            "[" + _rev001_parsed() + "]", K1_FP, "2026-04-16T10:30:15.123Z"
        )
    )
    assert v == {
        "authorization": "historically_authorized_pre_compromise",
        "boundary": "2026-05-01T00:00:00.000Z",
    }


def test_rev002_scenario_b_at_or_after_boundary_fails_closed():
    v = json.loads(
        acdp.AcdpVerifier.classify_under_revocation(
            "[" + _rev001_parsed() + "]", K1_FP, "2026-05-03T09:00:00.000Z"
        )
    )
    assert v["authorization"] == "none" and "step 3" in v["error"]
    # Exactly-at-T is already inside the window (strict boundary).
    v = json.loads(
        acdp.AcdpVerifier.classify_under_revocation(
            "[" + _rev001_parsed() + "]", K1_FP, "2026-05-01T00:00:00.000Z"
        )
    )
    assert v["authorization"] == "none" and "error" in v


def test_rev002_scenario_c_no_receipt_fails_closed():
    v = json.loads(
        acdp.AcdpVerifier.classify_under_revocation(
            "[" + _rev001_parsed() + "]", K1_FP
        )
    )
    assert v["authorization"] == "none" and "step 4" in v["error"]


def test_unrelated_fingerprint_is_inert():
    v = json.loads(
        acdp.AcdpVerifier.classify_under_revocation(
            "[" + _rev001_parsed() + "]", K2_FP
        )
    )
    assert v == {"authorization": "none"}
    v = json.loads(acdp.AcdpVerifier.classify_under_revocation("[]", K1_FP))
    assert v == {"authorization": "none"}


def test_earliest_boundary_wins_across_lineage():
    """§4 monotonicity: with two revocations of one key, the EARLIEST
    compromised_since governs — a supersession can widen but never
    quietly shrink the window."""
    later = json.loads(_rev001_parsed())
    earlier = dict(later, compromised_since="2026-04-01T00:00:00.000Z")
    revs = json.dumps([later, earlier])
    # Between the two boundaries: inside the effective window.
    v = json.loads(
        acdp.AcdpVerifier.classify_under_revocation(
            revs, K1_FP, "2026-04-15T00:00:00.000Z"
        )
    )
    assert v["authorization"] == "none"
    assert v["boundary"] == "2026-04-01T00:00:00.000Z"
    # Before both: pre-compromise.
    v = json.loads(
        acdp.AcdpVerifier.classify_under_revocation(
            revs, K1_FP, "2026-03-01T00:00:00.000Z"
        )
    )
    assert v["authorization"] == "historically_authorized_pre_compromise"


# ── Typed exceptions are exported ───────────────────────────────────────


def test_typed_exceptions_are_exported_and_catchable():
    for name in ("InvalidLogProof", "ImmutableField", "InvalidLifecycleTransition"):
        exc = getattr(acdp, name)
        assert issubclass(exc, Exception)
