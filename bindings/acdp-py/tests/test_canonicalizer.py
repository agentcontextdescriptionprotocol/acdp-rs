"""Tests for AcdpCanonicalizer — RFC 8785 (JCS) + content hashing.

Build with `maturin develop` from `bindings/acdp-py/`, then run `pytest`.
These pin the binding's canonicalization against hand-computed canonical
forms and SHA-256 digests so the Rust implementation is the single source
of truth for any host that previously re-implemented JCS.
"""
import hashlib
import json

import pytest

import acdp


def _sha256_envelope(canonical: str) -> str:
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_canonicalize_sorts_keys_and_strips_whitespace():
    out = acdp.AcdpCanonicalizer.canonicalize('{ "b": 1,\n  "a": 2 }')
    assert out == '{"a":2,"b":1}'


def test_canonicalize_normalizes_negative_zero():
    # RFC 8785: -0.0 MUST serialize as 0 (the classic JCS bug).
    out = acdp.AcdpCanonicalizer.canonicalize('{"x": -0.0}')
    assert out == '{"x":0}'


def test_canonicalize_nested_and_arrays():
    out = acdp.AcdpCanonicalizer.canonicalize(
        '{"z": [3, 2, 1], "a": {"d": 4, "c": 3}}'
    )
    # Array order is preserved; object keys are sorted at every level.
    assert out == '{"a":{"c":3,"d":4},"z":[3,2,1]}'


def test_canonicalize_unicode_passthrough():
    # Non-ASCII is emitted as UTF-8, not \uXXXX-escaped.
    out = acdp.AcdpCanonicalizer.canonicalize('{"k": "café — π"}')
    assert out == '{"k":"café — π"}'


def test_canonicalize_is_idempotent():
    once = acdp.AcdpCanonicalizer.canonicalize('{"b":1,"a":2}')
    twice = acdp.AcdpCanonicalizer.canonicalize(once)
    assert once == twice


def test_content_hash_matches_hashlib_over_canonical_form():
    doc = '{ "b": 1, "a": 2 }'
    canonical = acdp.AcdpCanonicalizer.canonicalize(doc)
    assert acdp.AcdpCanonicalizer.content_hash(doc) == _sha256_envelope(canonical)


def test_content_hash_is_order_independent():
    a = acdp.AcdpCanonicalizer.content_hash('{"a":1,"b":2}')
    b = acdp.AcdpCanonicalizer.content_hash('{"b":2,"a":1}')
    assert a == b
    assert a.startswith("sha256:")
    assert len(a) == 7 + 64


def test_content_hash_matches_producer_content_hash():
    """Hashing a body's producer-controlled fields with the canonicalizer
    reproduces the producer's `content_hash` — proving the JCS + SHA-256
    primitive is the same one the signing path uses."""
    p = acdp.AcdpProducer.from_seed(
        bytes(32),
        "did:web:agents.example.com:test-producer",
        "did:web:agents.example.com:test-producer#key-1",
    )
    req = json.loads(
        p.build_publish_request(
            title="Golden test vector — minimal first version",
            context_type="data_snapshot",
        )
    )
    # Strip the RFC-ACDP-0001 §5.7 exclusion set, then hash what remains.
    producer_content = {
        k: v
        for k, v in req.items()
        if k
        not in {
            "content_hash",
            "signature",
            "ctx_id",
            "lineage_id",
            "origin_registry",
            "created_at",
        }
    }
    recomputed = acdp.AcdpCanonicalizer.content_hash(json.dumps(producer_content))
    assert recomputed == req["content_hash"]


def test_canonicalize_rejects_malformed_json():
    with pytest.raises(Exception, match=r"(?i)json|invalid"):
        acdp.AcdpCanonicalizer.canonicalize("{not valid")
    with pytest.raises(Exception, match=r"(?i)json|invalid"):
        acdp.AcdpCanonicalizer.content_hash("{not valid")
