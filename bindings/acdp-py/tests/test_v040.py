"""ACDP 0.4 surface: transparency-log witness cosignatures
(RFC-ACDP-0015).

Pins the spec conformance fixtures byte-for-byte: wit-001 (the golden
cosignature — a single witness cosigns the log-001 tree-size-5
checkpoint with its own Ed25519 key, seed 0x33*32), wit-003 (two
distinct witnesses over one tuple → 2-witnessed), and wit-004 (a
cosignature signed by the WRONG witness key → invalid_witness_cosignature).
All keys are the publicly-known spec TEST keypairs — never production
material.

Build with `maturin develop` from `bindings/acdp-py/`, then run
`pytest`. No HTTP is involved — every DID document is supplied inline,
mirroring how the binding pushes resolution to the host.

These mirror the Node SDK's tests/v040.mjs so both bindings stay in
sync against the same Rust core.
"""
import base64
import json

import pytest

import acdp

REGISTRY_DID = "did:web:registry.example.com"
RECEIPT_KEY_ID = f"{REGISTRY_DID}#receipt-key-1"
LOG_ID = "did:web:registry.example.com/log/1"
ROOT = "sha256:0b5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731"

# wit-001 / wit-003 witness A (seed 0x33*32) and witness B (seed 0x44*32).
WITNESS_A = "did:web:witness.example.org"
WITNESS_A_SEED_HEX = "33" * 32
WITNESS_A_PUB_HEX = "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
WITNESS_B = "did:web:witness-2.example.org"
WITNESS_B_SEED_HEX = "44" * 32
WITNESS_B_PUB_HEX = "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48"

# The identity-bearing subset of the log-001 checkpoint the witnesses observe.
WITNESSED_CHECKPOINT = {
    "log_id": LOG_ID,
    "tree_size": 5,
    "root_hash": ROOT,
    "timestamp": "2026-07-04T12:00:00.000Z",
}

WITNESSED_AT_A = "2026-07-04T12:00:05.000Z"
WITNESSED_AT_B = "2026-07-04T12:03:00.000Z"

# wit-001 golden signature + full cosignature (the byte-exact re-mint target).
WIT001_SIG_B64 = (
    "omUcflbxeirUvPyIbuiGW0t7fch/xO2lSzTQwAvOAqsawocn4Y5J69Nwracq1I2Zercj5Qdnlc18NZQyoPcEBA=="
)
WIT001_COSIG_HASH = (
    "sha256:70f416e2ea52df79aeffb09f6e7bb0ff7ef85105ec73f1e3abefeeda7373edf0"
)
WIT001_LOG_COSIGNATURE = {
    "cosignature_version": "acdp-cosig/1",
    "witness_id": WITNESS_A,
    "witnessed_checkpoint": WITNESSED_CHECKPOINT,
    "witnessed_at": WITNESSED_AT_A,
    "signature": {
        "algorithm": "ed25519",
        "key_id": f"{WITNESS_A}#witness-key-1",
        "value": WIT001_SIG_B64,
    },
}

# wit-003 witness B golden signature.
WIT003_B_SIG_B64 = (
    "RYgjh3FYtkrHBupbZ8cXPbJ0rmHVrXtux23V66szHHMW8946IbXP3Kv9AbJReq/HbjarLqMGBk7rt8HtUnQyDA=="
)

# wit-004: witness A's body, but signature.value produced by the WRONG key
# (witness B's private key). The cosignature parses; the failure is cryptographic.
WIT004_COSIG = {
    "cosignature_version": "acdp-cosig/1",
    "witness_id": WITNESS_A,
    "witnessed_checkpoint": WITNESSED_CHECKPOINT,
    "witnessed_at": WITNESSED_AT_A,
    "signature": {
        "algorithm": "ed25519",
        "key_id": f"{WITNESS_A}#witness-key-1",
        "value": "q904p7YsZEtlVsTioF90JlFyY76z7+cD3mHTiC8sTI0VCGQ/ec0lf7pqILeqnL2w/PvUdaGFoGHlI0+8a31SBQ==",
    },
}

# The full log-001 checkpoint the consumer independently holds and verified.
LOG001_CHECKPOINT = {
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


def _witness_doc(did: str, pub_hex: str) -> str:
    """A minimal witness DID document with the key in BOTH
    verificationMethod and assertionMethod (RFC-ACDP-0015 §9)."""
    key_id = f"{did}#witness-key-1"
    x = base64.urlsafe_b64encode(bytes.fromhex(pub_hex)).rstrip(b"=").decode()
    return json.dumps(
        {
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
    )


# ── wit-001 — build (mint) golden vector ────────────────────────────────


def test_wit001_build_reproduces_the_golden_cosignature():
    """A witness-keyed re-mint over the log-001 checkpoint subset (seed
    0x33*32) reproduces the wit-001 canonical cosignature byte-for-byte,
    including the pinned Ed25519 signature."""
    out = acdp.AcdpVerifier.build_witness_cosignature(
        json.dumps(WITNESSED_CHECKPOINT), WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A
    )
    cosig = json.loads(out)
    assert cosig == WIT001_LOG_COSIGNATURE
    assert cosig["signature"]["value"] == WIT001_SIG_B64


def test_wit001_build_round_trips_through_verification():
    """The freshly minted cosignature verifies against the witness's
    resolved key for a consumer holding the log-001 checkpoint (§8)."""
    out = acdp.AcdpVerifier.build_witness_cosignature(
        json.dumps(WITNESSED_CHECKPOINT), WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A
    )
    verdict = json.loads(
        acdp.AcdpVerifier.verify_witness_cosignature(
            out,
            _witness_doc(WITNESS_A, WITNESS_A_PUB_HEX),
            json.dumps(LOG001_CHECKPOINT),
            "2026-07-04T12:00:10.000Z",
        )
    )
    assert verdict == {
        "valid": True,
        "witness_id": WITNESS_A,
        "age_secs": 5,
        "stale": False,
    }


def test_wit001_stale_but_valid_is_a_freshness_verdict():
    """§8.1: an old-but-honest cosignature stays valid; staleness is
    policy (for anti-backdating a cosignature never expires)."""
    verdict = json.loads(
        acdp.AcdpVerifier.verify_witness_cosignature(
            json.dumps(WIT001_LOG_COSIGNATURE),
            _witness_doc(WITNESS_A, WITNESS_A_PUB_HEX),
            json.dumps(LOG001_CHECKPOINT),
            "2026-07-04T12:10:05.000Z",  # 600s past witnessed_at
        )
    )
    assert verdict["valid"] and verdict["stale"] and verdict["age_secs"] == 600


def test_wit001_checkpoint_binding_fires():
    """§8 step 4: a cosignature over a DIFFERENT tuple than the checkpoint
    the consumer verified must not verify."""
    other = dict(LOG001_CHECKPOINT, tree_size=6, root_hash="sha256:" + "aa" * 32)
    # Re-sign the modified checkpoint would be needed to parse — but the
    # tuple mismatch is detected before signature checks. Use tree_size 6
    # with a still-parseable checkpoint (signature form only, not verified).
    verdict = json.loads(
        acdp.AcdpVerifier.verify_witness_cosignature(
            json.dumps(WIT001_LOG_COSIGNATURE),
            _witness_doc(WITNESS_A, WITNESS_A_PUB_HEX),
            json.dumps(other),
            "2026-07-04T12:00:10.000Z",
        )
    )
    assert not verdict["valid"]
    assert verdict["code"] == "invalid_witness_cosignature"


def test_wit001_wrong_witness_doc_id_fails_step3():
    """§8 step 3: a DID document whose id ≠ witness_id fails."""
    verdict = json.loads(
        acdp.AcdpVerifier.verify_witness_cosignature(
            json.dumps(WIT001_LOG_COSIGNATURE),
            _witness_doc(WITNESS_B, WITNESS_A_PUB_HEX),  # wrong id
            json.dumps(LOG001_CHECKPOINT),
            "2026-07-04T12:00:10.000Z",
        )
    )
    assert not verdict["valid"] and verdict["code"] == "invalid_witness_cosignature"


# ── wit-003 — quorum golden vector ──────────────────────────────────────


def _build(did, seed_hex, witnessed_at):
    return acdp.AcdpVerifier.build_witness_cosignature(
        json.dumps(WITNESSED_CHECKPOINT), did, seed_hex, witnessed_at
    )


def test_wit003_two_distinct_witnesses_are_2_witnessed():
    cosig_a = _build(WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A)
    cosig_b = _build(WITNESS_B, WITNESS_B_SEED_HEX, WITNESSED_AT_B)
    # Witness B's re-mint also matches its wit-003 golden signature.
    assert json.loads(cosig_b)["signature"]["value"] == WIT003_B_SIG_B64

    docs = {
        WITNESS_A: json.loads(_witness_doc(WITNESS_A, WITNESS_A_PUB_HEX)),
        WITNESS_B: json.loads(_witness_doc(WITNESS_B, WITNESS_B_PUB_HEX)),
    }
    report = json.loads(
        acdp.AcdpVerifier.evaluate_witness_quorum(
            json.dumps([json.loads(cosig_a), json.loads(cosig_b)]),
            json.dumps(LOG001_CHECKPOINT),
            json.dumps([WITNESS_A, WITNESS_B]),
            json.dumps(docs),
            json.dumps({"min_witnesses": 2}),
            "2026-07-04T12:10:00.000Z",
        )
    )
    assert report["witnessed_count"] == 2
    assert report["meets_quorum"] is True
    # Sorted distinct witnesses; WITNESS_B ('-') sorts before WITNESS_A ('.').
    assert report["witnesses"] == [WITNESS_B, WITNESS_A]
    assert report["failures"] == []


def test_wit003_repeat_from_one_witness_counts_once_and_min_policy():
    cosig_a = json.loads(_build(WITNESS_A, WITNESS_A_SEED_HEX, WITNESSED_AT_A))
    # A second cosignature from witness A (fresh witnessed_at) counts once.
    cosig_a2 = json.loads(_build(WITNESS_A, WITNESS_A_SEED_HEX, "2026-07-04T12:00:06.000Z"))
    docs = {WITNESS_A: json.loads(_witness_doc(WITNESS_A, WITNESS_A_PUB_HEX))}
    report = json.loads(
        acdp.AcdpVerifier.evaluate_witness_quorum(
            json.dumps([cosig_a, cosig_a2]),
            json.dumps(LOG001_CHECKPOINT),
            json.dumps([WITNESS_A]),
            json.dumps(docs),
            json.dumps({"min_witnesses": 2}),
            "2026-07-04T12:10:00.000Z",
        )
    )
    assert report["witnessed_count"] == 1
    assert report["meets_quorum"] is False


# ── wit-004 — cosignature key mismatch ──────────────────────────────────


def test_wit004_wrong_key_fails_with_typed_code():
    """A cosignature signed by the WRONG witness key MUST fail consumer
    verification as invalid_witness_cosignature (§8 step 2, §10)."""
    verdict = json.loads(
        acdp.AcdpVerifier.verify_witness_cosignature(
            json.dumps(WIT004_COSIG),
            _witness_doc(WITNESS_A, WITNESS_A_PUB_HEX),
            json.dumps(LOG001_CHECKPOINT),
            "2026-07-04T12:00:10.000Z",
        )
    )
    assert not verdict["valid"]
    assert verdict["code"] == "invalid_witness_cosignature"


def test_wit004_does_not_count_toward_quorum():
    docs = {WITNESS_A: json.loads(_witness_doc(WITNESS_A, WITNESS_A_PUB_HEX))}
    report = json.loads(
        acdp.AcdpVerifier.evaluate_witness_quorum(
            json.dumps([WIT004_COSIG]),
            json.dumps(LOG001_CHECKPOINT),
            json.dumps([WITNESS_A]),
            json.dumps(docs),
            json.dumps({}),
            "2026-07-04T12:00:10.000Z",
        )
    )
    assert report["witnessed_count"] == 0
    assert report["meets_quorum"] is False
    assert len(report["failures"]) == 1
    assert report["failures"][0]["code"] == "invalid_witness_cosignature"


# ── Host-input errors + typed exception export ──────────────────────────


def test_build_rejects_malformed_seed_and_identity():
    with pytest.raises(ValueError, match="witness_seed_hex"):
        acdp.AcdpVerifier.build_witness_cosignature(
            json.dumps(WITNESSED_CHECKPOINT), WITNESS_A, "abcd", WITNESSED_AT_A
        )
    # A non-witness DID form raises (WitnessSigner rejects it).
    with pytest.raises(ValueError):
        acdp.AcdpVerifier.build_witness_cosignature(
            json.dumps(WITNESSED_CHECKPOINT), "not-a-did", WITNESS_A_SEED_HEX, WITNESSED_AT_A
        )


def test_invalid_witness_cosignature_exception_is_exported():
    exc = acdp.InvalidWitnessCosignature
    assert issubclass(exc, Exception)
