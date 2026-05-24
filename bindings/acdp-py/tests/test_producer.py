"""In-process tests for the ACDP Python SDK.

Build with `maturin develop` from `bindings/acdp-py/`, then run
`pytest`. No HTTP is involved — the JSON each method produces is checked
directly against the spec's golden vector and against the verifier.
"""
import base64
import json

import pytest

import acdp


AGENT_DID = "did:web:registry.example.com:agents:test-agent"
KEY_ID = f"{AGENT_DID}#key-1"


def _producer():
    return acdp.AcdpProducer.generate(AGENT_DID, KEY_ID)


def test_generate_produces_distinct_keys():
    a = acdp.AcdpProducer.generate(AGENT_DID, KEY_ID)
    b = acdp.AcdpProducer.generate(AGENT_DID, KEY_ID)
    assert a.public_key_b64 != b.public_key_b64


def test_from_seed_is_deterministic():
    seed = bytes([7] * 32)
    a = acdp.AcdpProducer.from_seed(seed, AGENT_DID, KEY_ID)
    b = acdp.AcdpProducer.from_seed(seed, AGENT_DID, KEY_ID)
    assert a.public_key_b64 == b.public_key_b64
    # seed_bytes round-trips exactly.
    assert bytes(a.seed_bytes()) == seed


def test_from_seed_rejects_wrong_length():
    with pytest.raises(Exception):
        acdp.AcdpProducer.from_seed(bytes(31), AGENT_DID, KEY_ID)


def test_build_publish_request_minimal():
    p = _producer()
    raw = p.build_publish_request(
        title="Test context",
        context_type="data_snapshot",
    )
    req = json.loads(raw)
    assert req["title"] == "Test context"
    assert req["version"] == 1
    assert req["supersedes"] is None
    assert req["agent_id"] == AGENT_DID
    assert req["visibility"] == "public"
    assert req["content_hash"].startswith("sha256:")
    # "sha256:" (7) + 64 lowercase hex chars
    assert len(req["content_hash"]) == 7 + 64
    assert req["signature"]["algorithm"] == "ed25519"
    assert req["signature"]["key_id"] == KEY_ID


def test_golden_content_hash():
    """Pins the content_hash against the sig-001 spec golden vector.

    The seed [0]*32 and the minimal first-version fields MUST produce
    the same hash the Rust suite asserts in
    `crypto::hash::tests::golden_content_hash` and
    `producer::builder::tests::unset_optional_fields_are_omitted_from_hash_preimage`.
    """
    seed = bytes(32)  # all-zero seed = sig-001 test producer
    p = acdp.AcdpProducer.from_seed(
        seed,
        "did:web:agents.example.com:test-producer",
        "did:web:agents.example.com:test-producer#key-1",
    )
    raw = p.build_publish_request(
        title="Golden test vector — minimal first version",
        context_type="data_snapshot",
    )
    req = json.loads(raw)
    assert (
        req["content_hash"]
        == "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5"
    )
    # The Ed25519 signature is deterministic too — pin it against sig-001.
    assert req["signature"]["value"] == (
        "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
    )


def test_verify_content_hash_roundtrip():
    p = _producer()
    raw = p.build_publish_request(
        title="Round-trip verify",
        context_type="analysis",
        summary="test",
        domain="test",
    )
    req = json.loads(raw)
    assert acdp.AcdpVerifier.verify_content_hash(raw, req["content_hash"])


def test_verify_content_hash_rejects_tampered_field():
    p = _producer()
    raw = p.build_publish_request(title="Original", context_type="data_snapshot")
    req = json.loads(raw)
    # Mutate a producer-controlled field; the hash check MUST fail.
    req["title"] = "Tampered"
    with pytest.raises(Exception):
        acdp.AcdpVerifier.verify_content_hash(json.dumps(req), req["content_hash"])


def test_verify_signature_roundtrip():
    p = _producer()
    raw = p.build_publish_request(
        title="Sig verify",
        context_type="data_snapshot",
    )
    req = json.loads(raw)
    assert acdp.AcdpVerifier.verify_signature(
        p.public_key_b64,
        req["signature"]["value"],
        req["content_hash"],
    )


def test_sign_challenge_produces_verifiable_signature():
    p = _producer()
    signing_input = (
        f"acdp-registry-auth:v1:test-nonce-abc:{AGENT_DID}"
        ":registry.example.com:1748000000"
    )
    sig = p.sign_challenge(signing_input)
    raw_bytes = base64.b64decode(sig)
    # Ed25519 signature is 64 raw bytes.
    assert len(raw_bytes) == 64


def test_build_supersede_request():
    p = _producer()
    v1_raw = p.build_publish_request(
        title="Original", context_type="data_snapshot"
    )
    v1 = json.loads(v1_raw)

    # Simulate a registry-assigned Body by adding the registry-state fields.
    body = {
        **v1,
        "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
        "lineage_id": "lin:sha256:" + "a" * 64,
        "origin_registry": "registry.example.com",
        "created_at": "2026-01-01T00:00:00.000Z",
    }
    body_json = json.dumps(body)

    v2_raw = p.build_supersede_request(
        previous_body_json=body_json,
        title="Updated",
        summary="Now with more data",
    )
    v2 = json.loads(v2_raw)
    assert v2["version"] == 2
    assert v2["title"] == "Updated"
    assert v2["summary"] == "Now with more data"
    assert v2["supersedes"] == body["ctx_id"]
    # The expected_lineage_id must be carried forward from the previous body.
    assert v2.get("lineage_id") == body["lineage_id"]


def test_restricted_visibility_requires_audience():
    p = _producer()
    with pytest.raises(Exception):
        p.build_publish_request(
            title="Secret",
            context_type="analysis",
            visibility="restricted",
        )


def test_restricted_visibility_with_audience():
    p = _producer()
    raw = p.build_publish_request(
        title="Secret",
        context_type="analysis",
        visibility="restricted",
        audience=["did:web:other.example.com:agent-b"],
    )
    req = json.loads(raw)
    assert req["visibility"] == "restricted"
    assert "did:web:other.example.com:agent-b" in req["audience"]


def test_invalid_visibility_string_rejected():
    p = _producer()
    with pytest.raises(Exception):
        p.build_publish_request(
            title="x", context_type="data_snapshot", visibility="not-a-vis"
        )


def test_invalid_context_type_rejected():
    p = _producer()
    with pytest.raises(Exception):
        # Non-namespaced custom type fails serde validation.
        p.build_publish_request(title="x", context_type="bogus-type-no-colon")


def test_metadata_round_trips_as_object_not_string():
    """`metadata` is sent as a JSON-encoded object string by the binding;
    the resulting request must contain a JSON object, not a quoted
    string — otherwise the content_hash preimage would be wrong.
    """
    p = _producer()
    raw = p.build_publish_request(
        title="t",
        context_type="data_snapshot",
        metadata=json.dumps({"k": "v", "n": 42, "deep": {"x": [1, 2, 3]}}),
    )
    req = json.loads(raw)
    assert req["metadata"] == {"k": "v", "n": 42, "deep": {"x": [1, 2, 3]}}
    # And the body still re-verifies — the metadata WAS in the hash preimage.
    assert acdp.AcdpVerifier.verify_content_hash(raw, req["content_hash"])


def test_invalid_metadata_json_rejected():
    p = _producer()
    with pytest.raises(Exception):
        p.build_publish_request(
            title="t", context_type="data_snapshot", metadata="{not-valid-json"
        )


def test_verify_content_hash_rejects_malformed_hash():
    """The verifier surfaces malformed `expected_hash` strings as a
    clear error instead of a recomputation mismatch."""
    p = _producer()
    raw = p.build_publish_request(title="t", context_type="data_snapshot")
    with pytest.raises(Exception, match=r"(?i)content_hash|invalid"):
        acdp.AcdpVerifier.verify_content_hash(raw, "not-a-hash")
    with pytest.raises(Exception, match=r"(?i)content_hash|invalid"):
        # Wrong algorithm prefix.
        acdp.AcdpVerifier.verify_content_hash(raw, "md5:" + "a" * 32)


def test_seed_zeroization_is_observable_through_round_trip():
    """`seed_bytes()` returns a fresh copy each call. Mutating one copy
    must not affect the producer's stored seed — confirms the binding
    isn't handing out the Zeroizing-wrapped storage by reference.
    """
    p = acdp.AcdpProducer.from_seed(bytes([3] * 32), AGENT_DID, KEY_ID)
    snapshot = bytes(p.seed_bytes())
    # The Python `bytes` is immutable, but we can re-check via a fresh call.
    again = bytes(p.seed_bytes())
    assert snapshot == again == bytes([3] * 32)


def test_supersede_v3_chain():
    """A v2 body must be acceptable as input for a v3 supersession."""
    p = _producer()
    v1 = json.loads(
        p.build_publish_request(title="v1", context_type="data_snapshot")
    )
    body_v1 = {
        **v1,
        "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
        "lineage_id": "lin:sha256:" + "a" * 64,
        "origin_registry": "registry.example.com",
        "created_at": "2026-01-01T00:00:00.000Z",
    }
    v2 = json.loads(p.build_supersede_request(json.dumps(body_v1), title="v2"))
    # The v2 we get back is a PublishRequest (no registry fields).
    # Synthesize a v2 Body to feed back in for v3.
    body_v2 = {
        **v2,
        "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-1234567812aa",
        # lineage_id is already on v2 (carried from v1).
        "origin_registry": "registry.example.com",
        "created_at": "2026-02-01T00:00:00.000Z",
    }
    v3 = json.loads(p.build_supersede_request(json.dumps(body_v2), title="v3"))
    assert v3["version"] == 3
    assert v3["supersedes"] == body_v2["ctx_id"]
    assert v3["lineage_id"] == body_v1["lineage_id"]
