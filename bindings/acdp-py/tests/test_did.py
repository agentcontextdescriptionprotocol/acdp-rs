"""Tests for AcdpDid / AcdpDidDocument — did:web URL translation and
DID-document key extraction.

Build with `maturin develop` from `bindings/acdp-py/`, then run `pytest`.
These mirror the Node SDK's tests/did.mjs so both bindings stay in sync
against the same Rust `acdp::did` core: the assertionMethod authorization
gate, the algorithm-downgrade defense (RFC-ACDP-0008 §3.9), and the
stable `.reason` taxonomy.
"""
import base64
import json

import pytest

import acdp

DID = "did:web:agents.example.com"
KEY_ID = f"{DID}#key-1"


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _ed25519_doc(producer, authorized: bool = True) -> str:
    raw = base64.b64decode(producer.public_key_b64)
    return json.dumps(
        {
            "id": DID,
            "verificationMethod": [
                {
                    "id": KEY_ID,
                    "type": "JsonWebKey2020",
                    "controller": DID,
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": _b64url_no_pad(raw),
                    },
                }
            ],
            "assertionMethod": [KEY_ID] if authorized else [],
        }
    )


# ── AcdpDid ───────────────────────────────────────────────────────────


def test_web_to_url_bare_authority():
    assert (
        acdp.AcdpDid.web_to_url("did:web:example.com")
        == "https://example.com/.well-known/did.json"
    )


def test_web_to_url_path_segments():
    assert (
        acdp.AcdpDid.web_to_url("did:web:example.com:users:alice")
        == "https://example.com/users/alice/did.json"
    )


def test_web_to_url_rejects_non_did_web():
    with pytest.raises(acdp.DidResolutionError) as ei:
        acdp.AcdpDid.web_to_url("did:key:z6Mk")
    assert ei.value.reason == "not_did_web"


def test_strip_fragment():
    assert acdp.AcdpDid.strip_fragment(KEY_ID) == DID
    assert acdp.AcdpDid.strip_fragment(DID) == DID


# ── AcdpDidDocument ─────────────────────────────────────────────────────


def test_parse_rejects_id_mismatch():
    p = acdp.AcdpProducer.generate(DID, KEY_ID)
    with pytest.raises(acdp.DidResolutionError) as ei:
        acdp.AcdpDidDocument.parse(_ed25519_doc(p), "did:web:other.com")
    assert ei.value.reason == "id_mismatch"


def test_key_for_algorithm_extracts_producer_key():
    p = acdp.AcdpProducer.generate(DID, KEY_ID)
    doc = acdp.AcdpDidDocument.parse(_ed25519_doc(p), DID)
    k = doc.key_for_algorithm(KEY_ID, "ed25519")
    assert k["algorithm"] == "ed25519"
    assert k["key_id"] == KEY_ID
    assert k["public_key_b64"] == p.public_key_b64


def test_key_for_algorithm_downgrade_defense():
    p = acdp.AcdpProducer.generate(DID, KEY_ID)
    doc = acdp.AcdpDidDocument.parse(_ed25519_doc(p), DID)
    with pytest.raises(acdp.DidResolutionError) as ei:
        doc.key_for_algorithm(KEY_ID, "ecdsa-p256")
    assert ei.value.reason == "alg_mismatch"


def test_key_for_algorithm_requires_assertion_method():
    p = acdp.AcdpProducer.generate(DID, KEY_ID)
    doc = acdp.AcdpDidDocument.parse(_ed25519_doc(p, authorized=False), DID)
    with pytest.raises(acdp.DidResolutionError) as ei:
        doc.key_for_algorithm(KEY_ID, "ed25519")
    assert ei.value.reason == "key_not_authorized"


def test_key_for_algorithm_key_not_found():
    p = acdp.AcdpProducer.generate(DID, KEY_ID)
    doc = acdp.AcdpDidDocument.parse(_ed25519_doc(p), DID)
    with pytest.raises(acdp.DidResolutionError) as ei:
        doc.key_for_algorithm(f"{DID}#key-2", "ed25519")
    assert ei.value.reason == "key_not_found"


def test_key_for_algorithm_unsupported_algorithm():
    p = acdp.AcdpProducer.generate(DID, KEY_ID)
    doc = acdp.AcdpDidDocument.parse(_ed25519_doc(p), DID)
    with pytest.raises(acdp.DidResolutionError) as ei:
        doc.key_for_algorithm(KEY_ID, "rsa")
    assert ei.value.reason == "unsupported_algorithm"


def test_key_for_algorithm_p256_from_jwk():
    p = acdp.AcdpP256Producer.generate(DID, KEY_ID)
    doc_json = json.dumps(
        {
            "id": DID,
            "verificationMethod": [json.loads(p.did_verification_method(KEY_ID, DID))],
            "assertionMethod": [KEY_ID],
        }
    )
    doc = acdp.AcdpDidDocument.parse(doc_json, DID)
    k = doc.key_for_algorithm(KEY_ID, "ecdsa-p256")
    assert k["algorithm"] == "ecdsa-p256"
    assert k["public_key_b64"] == p.public_key_sec1_b64


# ── receipt_key_for_algorithm — RFC-ACDP-0010 §9 receipt-key lifecycle ──────


def test_receipt_key_resolves_retired_key_as_historical():
    # A retired receipt key: retained in verificationMethod, removed
    # from assertionMethod. key_for_algorithm refuses it; the receipt
    # helper resolves it with historical=True so the auditor can report
    # the §9 "historically authorized" status instead of an error.
    p = acdp.AcdpProducer.generate(DID, KEY_ID)
    doc = acdp.AcdpDidDocument.parse(_ed25519_doc(p, authorized=False), DID)

    with pytest.raises(acdp.DidResolutionError) as ei:
        doc.key_for_algorithm(KEY_ID, "ed25519")
    assert ei.value.reason == "key_not_authorized"

    k = doc.receipt_key_for_algorithm(KEY_ID, "ed25519")
    assert k["public_key_b64"] == p.public_key_b64
    assert k["historical"] == "true"


def test_receipt_key_current_key_is_not_historical():
    p = acdp.AcdpProducer.generate(DID, KEY_ID)
    doc = acdp.AcdpDidDocument.parse(_ed25519_doc(p), DID)
    k = doc.receipt_key_for_algorithm(KEY_ID, "ed25519")
    assert k["historical"] == "false"
    assert k["public_key_b64"] == p.public_key_b64


def test_receipt_key_fully_removed_key_fails_closed():
    # Full removal from verificationMethod is the compromise-revocation
    # signal — the receipt helper must fail closed, same as the strict
    # one.
    p = acdp.AcdpProducer.generate(DID, KEY_ID)
    doc = acdp.AcdpDidDocument.parse(_ed25519_doc(p), DID)
    with pytest.raises(acdp.DidResolutionError) as ei:
        doc.receipt_key_for_algorithm(f"{DID}#retired-key-9", "ed25519")
    assert ei.value.reason == "key_not_found"


def test_receipt_key_keeps_downgrade_defense():
    p = acdp.AcdpProducer.generate(DID, KEY_ID)
    doc = acdp.AcdpDidDocument.parse(_ed25519_doc(p, authorized=False), DID)
    with pytest.raises(acdp.DidResolutionError) as ei:
        doc.receipt_key_for_algorithm(KEY_ID, "ecdsa-p256")
    assert ei.value.reason == "alg_mismatch"


def test_retired_receipt_key_verifies_rcpt001_receipt():
    # End-to-end auditor path: the rcpt-001 registry key rotated out of
    # assertionMethod (verificationMethod-only), resolved via the
    # receipt helper, then fed to verify_receipt — the receipt verifies
    # and the caller knows it was a historical key.
    import json

    registry_did = "did:web:registry.example.com"
    receipt_key_id = f"{registry_did}#receipt-key-1"
    registry = acdp.AcdpProducer.from_seed(
        bytes([0x11] * 32), registry_did, receipt_key_id
    )
    doc_json = json.dumps(
        {
            "id": registry_did,
            "verificationMethod": [
                {
                    "id": receipt_key_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": registry_did,
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": _b64url(registry.public_key_b64),
                    },
                }
            ],
            # Rotated: nothing in assertionMethod any more.
            "assertionMethod": [],
        }
    )
    doc = acdp.AcdpDidDocument.parse(doc_json, registry_did)
    resolved = doc.receipt_key_for_algorithm(receipt_key_id, "ed25519")
    assert resolved["historical"] == "true"

    receipt = json.dumps(
        {
            "registry_did": registry_did,
            "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
            "lineage_id": "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
            "origin_registry": "registry.example.com",
            "created_at": "2026-04-16T10:30:15.123Z",
            "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
            "key_fingerprint": "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
            "signature": {
                "algorithm": "ed25519",
                "key_id": receipt_key_id,
                "value": "vBgQKmn17pHXXY95C07BBeconmjDIdYIvxN5B+YXrQ7tIzFsDNsh1TglzgxOyPUp8lwTz7zwMNiK+Sn5whveDg==",
            },
        }
    )
    # The sig-001 body this receipt attests (assembled from
    # `producer_content` + `registry_assigned`; see RCPT_BODY in
    # test_offline.py for the full derivation).
    body = json.dumps(
        {
            "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
            "lineage_id": "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
            "origin_registry": "registry.example.com",
            "created_at": "2026-04-16T10:30:15.123Z",
            "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
            "signature": {
                "algorithm": "ed25519",
                "key_id": "did:web:agents.example.com:test-producer#key-1",
                "value": "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ==",
            },
            "version": 1,
            "supersedes": None,
            "agent_id": "did:web:agents.example.com:test-producer",
            "contributors": [],
            "title": "Golden test vector — minimal first version",
            "type": "data_snapshot",
            "data_refs": [],
            "derived_from": [],
            "visibility": "public",
        }
    )
    assert acdp.AcdpVerifier.verify_receipt(
        receipt,
        body,
        resolved["public_key_b64"],
        "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
        "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
        "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
    )


def _b64url(standard_b64: str) -> str:
    import base64

    return (
        base64.urlsafe_b64encode(base64.b64decode(standard_b64))
        .rstrip(b"=")
        .decode()
    )
