"""ACDP 0.2 surface: did:key producers, offline verification, registry
receipts, and hash-divergence diagnostics.

Build with `maturin develop` from `bindings/acdp-py/`, then run
`pytest`. No HTTP is involved — did:key is resolution-free by
construction, and the receipt test injects the registry key directly
(resolving it from the registry's DID document is host-language work).
"""
import base64
import json

import pytest

import acdp


# sig-003 golden vector: the [0x42]*32 Ed25519 seed as a did:key
# identity, with `acdp_version: "0.2.0"` emitted explicitly (the
# default form — contrast sig-001, which pins the omitted form).
SIG003_SEED = bytes([0x42] * 32)
SIG003_DID = "did:key:z6MkghLt1e8m1fmANsdJJco3aCLV8Xnigr5UWwC3u5iZFPd3"
SIG003_TITLE = "Golden test vector — did:key first version"
SIG003_HASH = (
    "sha256:937448afc35bf79590bcf96f96da328d363d3ef6f2b87d274e2c1b242a09974f"
)
SIG003_SIG = (
    "3uDdFeyoU0kI53g0tQ6CbIPDaBxMsnZoSD77bE/3Bb0Hv8G+6iARbnZv7pgayyY3mksLjjqPno/DIPlrgeVVCA=="
)

# fp-001: receipt key fingerprint of the all-zero-seed public key.
FP001 = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070"


def _did_key_producer():
    return acdp.AcdpProducer.from_seed_did_key(SIG003_SEED)


def _sig003_request_json():
    return _did_key_producer().build_publish_request(
        title=SIG003_TITLE,
        context_type="data_snapshot",
        visibility="public",
        acdp_version="0.2.0",
    )


# ── did:key producers ───────────────────────────────────────────────────

def test_did_key_identity_is_derived_from_seed():
    p = _did_key_producer()
    assert p.agent_did == SIG003_DID
    # did:key fragment convention: the fragment IS the
    # method-specific identifier.
    assert p.key_id == SIG003_DID + "#" + SIG003_DID[len("did:key:"):]


def test_generate_did_key_produces_distinct_self_certifying_identities():
    a = acdp.AcdpProducer.generate_did_key()
    b = acdp.AcdpProducer.generate_did_key()
    assert a.agent_did != b.agent_did
    assert a.agent_did.startswith("did:key:z")
    assert a.key_id == a.agent_did + "#" + a.agent_did[len("did:key:"):]


def test_from_seed_did_key_rejects_wrong_length():
    with pytest.raises(Exception):
        acdp.AcdpProducer.from_seed_did_key(bytes(31))


def test_p256_did_key_identity_is_derived_and_distinct():
    a = acdp.AcdpP256Producer.generate_did_key()
    b = acdp.AcdpP256Producer.generate_did_key()
    assert a.agent_did != b.agent_did
    assert a.agent_did.startswith("did:key:z")
    assert a.key_id == a.agent_did + "#" + a.agent_did[len("did:key:"):]


def test_p256_from_seed_did_key_is_deterministic():
    seed = bytes([7] * 32)
    a = acdp.AcdpP256Producer.from_seed_did_key(seed)
    b = acdp.AcdpP256Producer.from_seed_did_key(seed)
    assert a.agent_did == b.agent_did
    assert bytes(a.seed_bytes()) == seed


def test_from_seed_with_mismatched_did_key_raises_on_build():
    """A did:key identity IS the key: pairing `from_seed` with someone
    else's did:key must raise ValueError on build, not silently sign
    under the seed-derived identity."""
    other = acdp.AcdpProducer.from_seed_did_key(bytes([0x43] * 32))
    assert other.agent_did != SIG003_DID
    mispaired = acdp.AcdpProducer.from_seed(
        SIG003_SEED, other.agent_did, other.key_id
    )
    with pytest.raises(ValueError, match=r"(?i)did:key.*mismatch|mismatch.*did:key"):
        mispaired.build_publish_request(
            title="t", context_type="data_snapshot"
        )


def test_from_seed_with_matching_did_key_builds():
    """The guard must NOT fire when the stored did:key really is the
    seed's derivation — `from_seed` with the matching DID behaves like
    `from_seed_did_key`."""
    p = acdp.AcdpProducer.from_seed(
        SIG003_SEED,
        SIG003_DID,
        SIG003_DID + "#" + SIG003_DID[len("did:key:"):],
    )
    req = json.loads(
        p.build_publish_request(title="t", context_type="data_snapshot")
    )
    assert req["agent_id"] == SIG003_DID


def test_p256_from_seed_with_mismatched_did_key_raises_on_build():
    """P-256 counterpart of the did:key mispairing guard."""
    other = acdp.AcdpP256Producer.from_seed_did_key(bytes([9] * 32))
    mispaired = acdp.AcdpP256Producer.from_seed(
        bytes([7] * 32), other.agent_did, other.key_id
    )
    with pytest.raises(ValueError, match=r"(?i)did:key.*mismatch|mismatch.*did:key"):
        mispaired.build_publish_request(
            title="t", context_type="data_snapshot"
        )


def test_sig003_did_key_golden_vector():
    """Pins the sig-003 spec golden vector: the [0x42]*32 seed as a
    did:key identity, minimal first-version fields, explicit
    `acdp_version: "0.2.0"`."""
    req = json.loads(_sig003_request_json())
    assert req["agent_id"] == SIG003_DID
    assert req["acdp_version"] == "0.2.0"
    assert req["content_hash"] == SIG003_HASH
    assert req["signature"]["value"] == SIG003_SIG
    assert req["signature"]["key_id"] == (
        SIG003_DID + "#" + SIG003_DID[len("did:key:"):]
    )


# ── Offline verification (did:key needs no resolution) ─────────────────

def test_verify_publish_request_offline_roundtrip():
    assert acdp.AcdpVerifier.verify_publish_request_offline(_sig003_request_json())


def test_verify_publish_request_offline_rejects_tampered_title():
    req = json.loads(_sig003_request_json())
    req["title"] = "Tampered"
    with pytest.raises(Exception):
        acdp.AcdpVerifier.verify_publish_request_offline(json.dumps(req))


def test_verify_publish_request_offline_rejects_did_web():
    """did:web requests need DID resolution — the offline path must
    refuse them rather than skip the key check."""
    p = acdp.AcdpProducer.generate(
        "did:web:agents.example.com:alice",
        "did:web:agents.example.com:alice#key-1",
    )
    raw = p.build_publish_request(title="t", context_type="data_snapshot")
    with pytest.raises(Exception, match=r"(?i)did:key"):
        acdp.AcdpVerifier.verify_publish_request_offline(raw)


def test_verify_body_offline_roundtrip():
    """A did:key PublishRequest plus registry-state fields is a Body —
    the full offline pipeline (validation, hash, key_id consistency,
    signature) accepts it and rejects tampering."""
    req = json.loads(_sig003_request_json())
    body = {
        **req,
        "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
        "lineage_id": "lin:sha256:" + "a" * 64,
        "origin_registry": "registry.example.com",
        "created_at": "2026-01-01T00:00:00.000Z",
    }
    assert acdp.AcdpVerifier.verify_body_offline(json.dumps(body))
    body["title"] = "Tampered"
    with pytest.raises(Exception):
        acdp.AcdpVerifier.verify_body_offline(json.dumps(body))


# ── ctx_id binding (RFC-ACDP-0006 §4.1 step 7) ──────────────────────────

CTX = "acdp://registry.example.com/12345678-1234-4321-8123-123456781234"
OTHER_CTX_UUID = "acdp://registry.example.com/00000000-0000-4000-8000-000000000000"
OTHER_CTX_AUTHORITY = "acdp://other.example.com/12345678-1234-4321-8123-123456781234"
# Mirrors the core `verify_ctx_id_binding` test fixture: only the last
# three UUID hex chars are uppercase.
UPPERCASE_UUID = "acdp://registry.example.com/00000000-0000-4000-8000-000000000AAA"


def _body_with_ctx_id(ctx_id):
    req = json.loads(_sig003_request_json())
    return {
        **req,
        "ctx_id": ctx_id,
        "lineage_id": "lin:sha256:" + "a" * 64,
        "origin_registry": "registry.example.com",
        "created_at": "2026-01-01T00:00:00.000Z",
    }


def test_verify_ctx_id_matching_ids_ok():
    """Positive control for every failure case below."""
    body = _body_with_ctx_id(CTX)
    assert acdp.AcdpVerifier.verify_ctx_id_binding(json.dumps(body), CTX)


def test_verify_ctx_id_rejects_uuid_only_mismatch():
    body = _body_with_ctx_id(CTX)
    with pytest.raises(Exception, match=r"(?i)context substitution"):
        acdp.AcdpVerifier.verify_ctx_id_binding(json.dumps(body), OTHER_CTX_UUID)


def test_verify_ctx_id_rejects_authority_only_mismatch():
    """A mismatch differing only in the authority (not the UUID) must
    also be rejected."""
    body = _body_with_ctx_id(CTX)
    with pytest.raises(Exception, match=r"(?i)context substitution"):
        acdp.AcdpVerifier.verify_ctx_id_binding(json.dumps(body), OTHER_CTX_AUTHORITY)


def test_verify_ctx_id_rejects_malformed_expected():
    body = _body_with_ctx_id(CTX)
    with pytest.raises(ValueError):
        acdp.AcdpVerifier.verify_ctx_id_binding(json.dumps(body), "not-a-ctx-id")


def test_verify_ctx_id_rejects_uppercase_uuid_on_served_side():
    """Uppercase-UUID rejection must be enforced on the *served* side
    too (the body's own ctx_id), not just the expected side."""
    body = _body_with_ctx_id(UPPERCASE_UUID)
    with pytest.raises(ValueError):
        acdp.AcdpVerifier.verify_ctx_id_binding(json.dumps(body), CTX)


def test_verify_ctx_id_rejects_uppercase_uuid_on_expected_side():
    body = _body_with_ctx_id(CTX)
    with pytest.raises(ValueError):
        acdp.AcdpVerifier.verify_ctx_id_binding(json.dumps(body), UPPERCASE_UUID)


def test_verify_ctx_id_rejects_malformed_body_json():
    with pytest.raises(ValueError):
        acdp.AcdpVerifier.verify_ctx_id_binding("not json", CTX)


# ── Key fingerprints (fp-001) ───────────────────────────────────────────

def test_fp001_fingerprint_of_zero_seed_key():
    p = acdp.AcdpProducer.from_seed_did_key(bytes(32))
    assert acdp.AcdpVerifier.fingerprint_ed25519_b64(p.public_key_b64) == FP001


def test_fingerprint_rejects_short_key():
    with pytest.raises(Exception, match=r"(?i)32 bytes"):
        acdp.AcdpVerifier.fingerprint_ed25519_b64(
            base64.b64encode(bytes(31)).decode()
        )


# ── Registry receipts (rcpt-001) ────────────────────────────────────────

# rcpt-001: a receipt over the sig-001 content_hash, minted by a
# registry whose Ed25519 receipt key has seed [0x11]*32. The producer
# key fingerprint is fp-001 (the zero-seed key).
RCPT001 = {
    "registry_did": "did:web:registry.example.com",
    "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
    "lineage_id": "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
    "origin_registry": "registry.example.com",
    "created_at": "2026-04-16T10:30:15.123Z",
    "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
    "key_fingerprint": "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "did:web:registry.example.com#receipt-key-1",
        "value": "vBgQKmn17pHXXY95C07BBeconmjDIdYIvxN5B+YXrQ7tIzFsDNsh1TglzgxOyPUp8lwTz7zwMNiK+Sn5whveDg==",
    },
}


def _registry_public_key_b64():
    # The registry's receipt key is the Ed25519 key with seed [0x11]*32.
    # In production this comes from the registry's DID document
    # (resolved in the host language); here we derive it directly.
    return acdp.AcdpProducer.from_seed(
        bytes([0x11] * 32), "did:web:x", "did:web:x#k"
    ).public_key_b64


def test_rcpt001_receipt_verifies():
    assert acdp.AcdpVerifier.verify_receipt(
        json.dumps(RCPT001),
        _registry_public_key_b64(),
        RCPT001["ctx_id"],
        RCPT001["content_hash"],
        RCPT001["key_fingerprint"],
    )


def test_rcpt001_rejects_wrong_producer_fingerprint():
    with pytest.raises(Exception, match=r"(?i)fingerprint"):
        acdp.AcdpVerifier.verify_receipt(
            json.dumps(RCPT001),
            _registry_public_key_b64(),
            RCPT001["ctx_id"],
            RCPT001["content_hash"],
            "sha256:" + "0" * 64,
        )


def test_rcpt001_rejects_mutated_created_at():
    """Backdating (or any mutation of) `created_at` changes the receipt
    preimage — the registry signature must no longer verify."""
    tampered = {**RCPT001, "created_at": "2026-04-16T10:30:15.124Z"}
    with pytest.raises(Exception, match=r"(?i)signature"):
        acdp.AcdpVerifier.verify_receipt(
            json.dumps(tampered),
            _registry_public_key_b64(),
            RCPT001["ctx_id"],
            RCPT001["content_hash"],
            RCPT001["key_fingerprint"],
        )


def test_rcpt001_rejects_unknown_member():
    """RegistryReceipt is a closed schema: an extra unknown member must
    fail to parse as an invalid receipt rather than be silently ignored."""
    extended = {**RCPT001, "totally_unknown_field": True}
    with pytest.raises(Exception):
        acdp.AcdpVerifier.verify_receipt(
            json.dumps(extended),
            _registry_public_key_b64(),
            RCPT001["ctx_id"],
            RCPT001["content_hash"],
            RCPT001["key_fingerprint"],
        )


def test_receipt_rejects_non_canonical_created_at_byte_form():
    """RFC-ACDP-0010 §8 step 6: the receipt's raw `created_at` must be
    canonical millisecond-precision RFC 3339 UTC (`...mmmZ`). A
    two-digit fraction parses fine as a timestamp but is a different
    byte form — it must be rejected before any signature work."""
    tampered = {**RCPT001, "created_at": "2026-04-16T10:30:15.12Z"}
    with pytest.raises(Exception, match=r"(?i)created_at"):
        acdp.AcdpVerifier.verify_receipt(
            json.dumps(tampered),
            _registry_public_key_b64(),
            RCPT001["ctx_id"],
            RCPT001["content_hash"],
            RCPT001["key_fingerprint"],
        )


def test_rcpt001_rejects_wrong_ctx_id():
    with pytest.raises(Exception, match=r"(?i)ctx_id"):
        acdp.AcdpVerifier.verify_receipt(
            json.dumps(RCPT001),
            _registry_public_key_b64(),
            "acdp://registry.example.com/00000000-0000-4000-8000-000000000000",
            RCPT001["content_hash"],
            RCPT001["key_fingerprint"],
        )


# ── Hash-divergence diagnostics (WS-D2) ─────────────────────────────────

def test_canonical_preimage_is_canonical_json_minus_exclusions():
    raw = _sig003_request_json()
    req = json.loads(raw)
    preimage = acdp.AcdpVerifier.canonical_preimage(raw)
    obj = json.loads(preimage)
    # §5.7 exclusion set is removed; producer fields survive.
    assert "signature" not in obj
    assert "content_hash" not in obj
    assert obj["title"] == req["title"]
    # JCS orders keys lexicographically.
    keys = list(obj.keys())
    assert keys == sorted(keys)


def test_explain_hash_mismatch_names_acdp_version_divergence():
    """The classic 0.2 divergence: one side omits `acdp_version`, the
    other emits it. The diagnostic must call that out by name."""
    p = _did_key_producer()
    omitted = json.loads(
        p.build_publish_request(
            title="t", context_type="data_snapshot", omit_acdp_version=True
        )
    )
    explicit = json.loads(
        p.build_publish_request(title="t", context_type="data_snapshot")
    )
    report = acdp.AcdpVerifier.explain_hash_mismatch(
        json.dumps(explicit), omitted["content_hash"]
    )
    assert "acdp_version" in report


def test_explain_hash_mismatch_reports_match():
    raw = _sig003_request_json()
    req = json.loads(raw)
    report = acdp.AcdpVerifier.explain_hash_mismatch(raw, req["content_hash"])
    assert "no divergence" in report
