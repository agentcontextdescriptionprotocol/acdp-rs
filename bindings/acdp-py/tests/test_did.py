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
