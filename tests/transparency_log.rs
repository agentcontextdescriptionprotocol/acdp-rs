//! Transparency-log conformance bindings (ACDP 0.3, RFC-ACDP-0012) —
//! the log-001..004 fixtures executed against the SDK.
//!
//! - `log-001` / `log-003` are executed arithmetically (the runner's
//!   `check_log_vector` behavior): leaf encodings, §5.1 leaf hashes,
//!   the §5.2 root, checkpoint canonical forms/hashes/signatures via
//!   deterministic re-mint AND raw-JSON verification, and the §9.1/§9.2
//!   proof algorithms end-to-end.
//! - `log-002` / `log-004` are behavioral: a tampered `inclusion_path`
//!   and a post-signing `root_hash` rewrite MUST both surface as
//!   [`acdp::AcdpError::InvalidLogProof`] (never `InvalidReceipt` —
//!   the verdicts are independent, RFC-ACDP-0012 §9.3).
//! - The `server`-feature [`acdp::registry::MerkleLog`] must REPRODUCE
//!   the fixture tree — append the five fixture leaves and get the same
//!   root, the same signed checkpoints, and the same proofs (the
//!   two-implementations-in-one check).
//!
//! Fixture-gate pattern as `tests/conformance.rs`: locates the spec via
//! `ACDP_SPEC_DIR` (fallback: sibling checkout), skips gracefully when
//! absent, and hard-fails under `ACDP_REQUIRE_CONFORMANCE`.

#[cfg(all(feature = "client", feature = "server"))]
mod common;

use std::path::{Path, PathBuf};

use acdp::types::log::{
    decode_sha256_hex, encode_sha256_hex, LogCheckpoint, LogConsistencyProof, LogInclusion,
    LogLeaf, LOG_CHECKPOINT_VERSION, LOG_LEAF_VERSION,
};
use acdp::types::receipt::ReceiptSigner;
use acdp::AcdpError;

// ── Spec locator (the strict gate from tests/conformance.rs) ─────────────────

fn require_conformance() -> bool {
    std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok()
}

fn spec_root() -> Option<PathBuf> {
    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
        assert!(
            !require_conformance(),
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR '{}' does not exist",
            p.display()
        );
    } else {
        assert!(
            !require_conformance(),
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR is not"
        );
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(sibling) = manifest_dir
        .parent()
        .map(|p| p.join("agentcontextdistributionprotocol"))
    {
        if sibling.exists() {
            return Some(sibling);
        }
    }
    assert!(
        !require_conformance(),
        "ACDP_REQUIRE_CONFORMANCE is set but no ACDP spec checkout could be located"
    );
    None
}

fn fixture_missing(path: &Path) -> bool {
    if path.exists() {
        return false;
    }
    assert!(
        !require_conformance(),
        "ACDP_REQUIRE_CONFORMANCE is set but published fixture {} is missing",
        path.display()
    );
    eprintln!("fixture {} not present; skipping", path.display());
    true
}

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

// ── Fixture accessors ────────────────────────────────────────────────────────

fn registry_seed(fixture: &serde_json::Value) -> [u8; 32] {
    hex::decode(
        fixture["registry_test_keypair"]["private_seed_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap()
}

fn registry_pub(fixture: &serde_json::Value) -> [u8; 32] {
    hex::decode(
        fixture["registry_test_keypair"]["public_key_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap()
}

fn fixture_signer(fixture: &serde_json::Value) -> ReceiptSigner {
    let key_id = fixture["registry_test_keypair"]["key_id"].as_str().unwrap();
    let (did, _) = key_id.split_once('#').unwrap();
    ReceiptSigner::new(
        acdp::crypto::SigningKey::from_bytes(&registry_seed(fixture)),
        did,
        key_id,
    )
    .unwrap()
}

/// Decode a fixture array of `"sha256:<hex>"` strings to raw digests.
fn digests(values: &serde_json::Value) -> Vec<[u8; 32]> {
    values
        .as_array()
        .unwrap()
        .iter()
        .map(|v| decode_sha256_hex(v.as_str().unwrap()).unwrap())
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════
// log-001 — leaf-and-root golden vector (executed arithmetically)
// ═══════════════════════════════════════════════════════════════════════

/// The fixture's `verification_steps` 1–7, byte-compared throughout:
/// JCS leaf encodings, §5.1 leaf hashes, the §5.2 root (and empty-tree
/// root), the checkpoint canonical form / hash / deterministic
/// re-minted signature, the §9.1 fold of the pinned inclusion proof,
/// and the §4 cross-checks (v1 lineage derivation, producer-key
/// fingerprint, envelope versions).
#[test]
fn log_001_leaf_and_root_golden_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/log-001-leaf-and-root-golden.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let vector = &v["vectors"][0];
    let expected = &vector["expected"];

    // Step 1 + 2: leaf canonical forms and 0x00-prefixed leaf hashes.
    let fixture_leaves = vector["leaves"].as_array().unwrap();
    let mut leaves = Vec::new();
    let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();
    for (i, wire) in fixture_leaves.iter().enumerate() {
        let leaf = LogLeaf::from_value(wire).unwrap();
        assert_eq!(leaf.leaf_version, LOG_LEAF_VERSION);
        let canonical = leaf.canonical_bytes().unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            expected["leaf_canonical_forms"][i].as_str().unwrap(),
            "log-001 leaf {i}: JCS canonical form (RFC-ACDP-0012 §4)"
        );
        // Struct-serialized canonical bytes equal raw-wire canonical
        // bytes (the ms timestamp byte form survives the round trip).
        assert_eq!(
            canonical,
            acdp::crypto::try_canonicalize_value(wire).unwrap(),
            "log-001 leaf {i}: struct and raw-wire canonical forms agree"
        );
        assert_eq!(
            leaf.leaf_hash_hex().unwrap(),
            expected["leaf_hashes"][i].as_str().unwrap(),
            "log-001 leaf {i}: SHA-256(0x00 ‖ JCS(leaf)) (RFC-ACDP-0012 §5.1)"
        );

        // Step 7 cross-checks: v1 lineage derivation and producer-key
        // fingerprint.
        assert_eq!(
            acdp::crypto::derive_lineage_id(&leaf.ctx_id),
            leaf.lineage_id,
            "log-001 leaf {i}: v1 publish means lineage_id = lin:sha256:SHA-256(ctx_id)"
        );
        let producer_pub: [u8; 32] =
            hex::decode(v["producer_key"]["public_key_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            acdp::crypto::fingerprint_ed25519(&producer_pub),
            leaf.key_fingerprint,
            "log-001 leaf {i}: key_fingerprint binds the sig-001 producer key (RFC-ACDP-0010 §6)"
        );

        leaf_hashes.push(leaf.leaf_hash().unwrap());
        leaves.push(leaf);
    }

    // Step 3: the tree-size-5 root and the empty-tree root.
    let tree_root = acdp::crypto::merkle_tree_hash(&leaf_hashes);
    assert_eq!(
        encode_sha256_hex(&tree_root),
        expected["root_hash"].as_str().unwrap(),
        "log-001: MTH(D[5]) (RFC-ACDP-0012 §5.2)"
    );
    assert_eq!(
        encode_sha256_hex(&acdp::crypto::merkle_tree_hash(&[])),
        expected["empty_tree_root_hash"].as_str().unwrap(),
        "log-001: MTH({{}}) = SHA-256(\"\")"
    );

    // Step 4: checkpoint canonical form and checkpoint hash.
    let unsigned = &vector["checkpoint_unsigned"];
    let canonical = acdp::crypto::try_canonicalize_value(unsigned).unwrap();
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        expected["checkpoint_canonical_form"].as_str().unwrap(),
        "log-001: checkpoint canonical preimage bytes"
    );
    let checkpoint_hash = LogCheckpoint::preimage_hash_of_value(unsigned).unwrap();
    assert_eq!(
        checkpoint_hash.as_str(),
        expected["checkpoint_hash"].as_str().unwrap()
    );
    assert_eq!(
        checkpoint_hash.as_str(),
        expected["signature_input"].as_str().unwrap(),
        "log-001: the signing input IS the ASCII checkpoint-hash string"
    );

    // Step 5: deterministic Ed25519 re-mint reproduces the pinned
    // signature; the assembled wire form equals the fixture checkpoint.
    let minted = fixture_signer(&v)
        .mint_log_checkpoint(
            unsigned["log_id"].as_str().unwrap(),
            unsigned["tree_size"].as_u64().unwrap(),
            unsigned["root_hash"].as_str().unwrap(),
            chrono::DateTime::parse_from_rfc3339(unsigned["timestamp"].as_str().unwrap())
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
        .unwrap();
    assert_eq!(minted.checkpoint_version, LOG_CHECKPOINT_VERSION);
    assert_eq!(
        minted.signature.value,
        expected["signature_value_base64"].as_str().unwrap(),
        "log-001: deterministic Ed25519 re-mint must reproduce the fixture signature"
    );
    assert_eq!(
        serde_json::to_value(&minted).unwrap(),
        expected["log_checkpoint"],
        "log-001: minted wire form must equal the fixture checkpoint"
    );

    // The pinned wire checkpoint round-trips the closed parse and
    // verifies against the registry test public key over the RAW wire
    // preimage; §9.3 step 3 binding against the golden authority.
    let wire = &expected["log_checkpoint"];
    let checkpoint = LogCheckpoint::from_value(wire).unwrap();
    let raw_hash = LogCheckpoint::preimage_hash_of_value(wire).unwrap();
    assert_eq!(raw_hash, checkpoint_hash);
    checkpoint
        .verify_signature_against_hash(&raw_hash, Some(&registry_pub(&v)), None)
        .unwrap();
    checkpoint
        .cross_check_registry_binding("registry.example.com", "did:web:registry.example.com")
        .unwrap();

    // Step 6: the pinned inclusion proof for leaf 0 — regenerated
    // byte-for-byte, then folded per §9.1 back to the root.
    let incl = &expected["log_inclusion"];
    let pinned_path = digests(&incl["inclusion_path"]);
    let m = usize::try_from(incl["leaf_index"].as_u64().unwrap()).unwrap();
    let n = usize::try_from(incl["tree_size"].as_u64().unwrap()).unwrap();
    assert_eq!(
        acdp::crypto::inclusion_path(m, &leaf_hashes[..n]).unwrap(),
        pinned_path,
        "log-001: inclusion_path must equal RFC 6962 PATH(0, D[5])"
    );
    let inclusion = LogInclusion {
        log_id: incl["log_id"].as_str().unwrap().to_string(),
        leaf_index: incl["leaf_index"].as_u64().unwrap(),
        tree_size: incl["tree_size"].as_u64().unwrap(),
        inclusion_path: incl["inclusion_path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_string())
            .collect(),
        log_checkpoint: checkpoint.clone(),
        leaf: None,
    };
    inclusion
        .verify_reconstructed_leaf(&leaves[0])
        .expect("log-001: §9.1 folding must reproduce the checkpoint root");

    // The closed wire parse accepts the assembled proof object too.
    LogInclusion::from_value(&serde_json::to_value(&inclusion).unwrap()).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════
// log-003 — consistency-proof golden vector (executed arithmetically)
// ═══════════════════════════════════════════════════════════════════════

/// The fixture's `verification_steps` 1–4: prefix roots recomputed from
/// the pinned leaf hashes, both checkpoint canonical forms / hashes /
/// re-minted signatures, `PROOF(3, D[5])` regenerated byte-for-byte,
/// and the §9.2 verification algorithm end-to-end (plus tamper
/// rejections).
#[test]
fn log_003_consistency_proof_golden_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/log-003-consistency-proof-golden.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let vector = &v["vectors"][0];
    let expected = &vector["expected"];
    let leaf_hashes = digests(&vector["leaf_hashes"]);

    // Step 1: prefix roots.
    let first_cp_unsigned = &vector["first_checkpoint_unsigned"];
    let second_cp_unsigned = &vector["second_checkpoint_unsigned"];
    let m = usize::try_from(first_cp_unsigned["tree_size"].as_u64().unwrap()).unwrap();
    let n = usize::try_from(second_cp_unsigned["tree_size"].as_u64().unwrap()).unwrap();
    let first_root = acdp::crypto::merkle_tree_hash(&leaf_hashes[..m]);
    let second_root = acdp::crypto::merkle_tree_hash(&leaf_hashes[..n]);
    assert_eq!(
        encode_sha256_hex(&first_root),
        expected["first_root_hash"].as_str().unwrap(),
        "log-003: MTH(D[0:3])"
    );
    assert_eq!(
        encode_sha256_hex(&second_root),
        expected["second_root_hash"].as_str().unwrap(),
        "log-003: MTH(D[0:5])"
    );

    // Step 2: canonical forms, checkpoint hashes, deterministic
    // re-mints, raw-JSON signature verification — for BOTH checkpoints.
    let mut signed = Vec::new();
    for (unsigned, prefix) in [
        (first_cp_unsigned, "first_"),
        (second_cp_unsigned, "second_"),
    ] {
        let canonical = acdp::crypto::try_canonicalize_value(unsigned).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            expected[format!("{prefix}checkpoint_canonical_form")]
                .as_str()
                .unwrap(),
            "log-003: {prefix}checkpoint canonical form"
        );
        let hash = LogCheckpoint::preimage_hash_of_value(unsigned).unwrap();
        assert_eq!(
            hash.as_str(),
            expected[format!("{prefix}checkpoint_hash")]
                .as_str()
                .unwrap()
        );
        let minted = fixture_signer(&v)
            .mint_log_checkpoint(
                unsigned["log_id"].as_str().unwrap(),
                unsigned["tree_size"].as_u64().unwrap(),
                unsigned["root_hash"].as_str().unwrap(),
                chrono::DateTime::parse_from_rfc3339(unsigned["timestamp"].as_str().unwrap())
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            )
            .unwrap();
        assert_eq!(
            minted.signature.value,
            expected[format!("{prefix}signature_value_base64")]
                .as_str()
                .unwrap(),
            "log-003: {prefix}checkpoint deterministic re-mint"
        );
        minted
            .verify_signature_with_key(Some(&registry_pub(&v)), None)
            .unwrap();
        signed.push(minted);
    }
    let second_checkpoint = signed.pop().unwrap();

    // Step 3: PROOF(3, D[5]) regenerated byte-for-byte.
    let resp = &expected["consistency_proof_response"];
    let pinned_path = digests(&resp["consistency_path"]);
    assert_eq!(
        acdp::crypto::consistency_proof(m, &leaf_hashes[..n]).unwrap(),
        pinned_path,
        "log-003: consistency_path must equal RFC 6962 PROOF(3, D[5])"
    );

    // Step 4: §9.2 verification end-to-end via the wire shape, against
    // the RETAINED first root.
    let proof = LogConsistencyProof {
        log_id: resp["log_id"].as_str().unwrap().to_string(),
        first_tree_size: resp["first_tree_size"].as_u64().unwrap(),
        second_tree_size: resp["second_tree_size"].as_u64().unwrap(),
        consistency_path: resp["consistency_path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_string())
            .collect(),
        log_checkpoint: second_checkpoint,
    };
    proof
        .verify_against_first_root(expected["first_root_hash"].as_str().unwrap())
        .expect("log-003: §9.2 verification must succeed on the golden path");

    // Tamper rejections (the fixture's step 4 tail): any path element,
    // either root, or either size failing MUST yield invalid_log_proof.
    let mut tampered = proof.clone();
    let mut raw = decode_sha256_hex(&tampered.consistency_path[0]).unwrap();
    raw[0] ^= 1;
    tampered.consistency_path[0] = encode_sha256_hex(&raw);
    assert!(matches!(
        tampered
            .verify_against_first_root(expected["first_root_hash"].as_str().unwrap())
            .unwrap_err(),
        AcdpError::InvalidLogProof(_)
    ));
    assert!(matches!(
        proof
            .verify_against_first_root(expected["second_root_hash"].as_str().unwrap())
            .unwrap_err(),
        AcdpError::InvalidLogProof(_)
    ));
    let mut wrong_size = proof.clone();
    wrong_size.first_tree_size = 2;
    assert!(wrong_size
        .verify_against_first_root(expected["first_root_hash"].as_str().unwrap())
        .is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// log-002 — inclusion-proof mismatch (behavioral)
// ═══════════════════════════════════════════════════════════════════════

/// The checkpoint is genuine and its signature verifies (§9.3 passes);
/// the §9.1 step 4 bindings pass; the fold over the tampered path
/// yields a root ≠ `root_hash` → step 6 MUST fail with
/// `invalid_log_proof`. Restoring the untampered element makes the same
/// proof verify — the failure is the tree arithmetic, not the crypto.
#[test]
fn log_002_inclusion_proof_mismatch_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/log-002-inclusion-proof-mismatch.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let input = &v["input"];
    let leaf_hash = decode_sha256_hex(input["leaf_hash"].as_str().unwrap()).unwrap();
    let pub_bytes: [u8; 32] = hex::decode(input["registry_public_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let inclusion = LogInclusion::from_value(&input["log_inclusion"]).unwrap();

    // Premise: §9.3 passes — the checkpoint's own signature verifies
    // over its raw preimage.
    let cp_wire = &input["log_inclusion"]["log_checkpoint"];
    let cp_hash = LogCheckpoint::preimage_hash_of_value(cp_wire).unwrap();
    inclusion
        .log_checkpoint
        .verify_signature_against_hash(&cp_hash, Some(&pub_bytes), None)
        .expect("log-002 premise: the checkpoint signature verifies");
    // Premise: §9.1 step 4 bindings pass.
    inclusion.cross_check_binding().unwrap();

    // §9.1 steps 5–6: the fold over the tampered path MUST fail with
    // the invalid_log_proof category.
    let err = inclusion.verify_leaf_hash(&leaf_hash).unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidLogProof(_)),
        "log-002: tampered inclusion_path must fail as invalid_log_proof, got {err:?}"
    );
    assert!(!err.is_transient(), "a bad proof will not verify on retry");

    // Restoring the untampered element (the fixture pins it) makes the
    // identical proof verify — isolating the failure to the arithmetic.
    let mut repaired = inclusion.clone();
    repaired.inclusion_path[1] = input["untampered_path_element_1"]
        .as_str()
        .unwrap()
        .to_string();
    repaired
        .verify_leaf_hash(&leaf_hash)
        .expect("log-002: the untampered path must verify");
}

// ═══════════════════════════════════════════════════════════════════════
// log-004 — checkpoint signature invalid (behavioral)
// ═══════════════════════════════════════════════════════════════════════

/// §9.3 step 1 passes (closed parse, exact `checkpoint_version`);
/// step 2 MUST fail: JCS-recomputing the preimage over the served
/// (root_hash-rewritten) checkpoint yields a hash ≠ the genuine one,
/// and the pinned signature does not verify over its ASCII bytes. A
/// verifier that byte-compared `root_hash` instead of
/// recomputing-and-verifying would wrongly accept this checkpoint.
#[test]
fn log_004_checkpoint_signature_invalid_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/log-004-checkpoint-signature-invalid.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let input = &v["input"];
    let wire = &input["log_checkpoint"];
    let pub_bytes: [u8; 32] = hex::decode(input["registry_public_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    // §9.3 step 1 passes.
    let checkpoint = LogCheckpoint::from_value(wire).unwrap();
    assert_eq!(checkpoint.checkpoint_version, LOG_CHECKPOINT_VERSION);

    // The recomputed preimage hash over the SERVED bytes differs from
    // the hash the signature actually covers.
    let served_hash = LogCheckpoint::preimage_hash_of_value(wire).unwrap();
    assert_ne!(
        served_hash.as_str(),
        input["genuine_checkpoint_hash"].as_str().unwrap(),
        "log-004 premise: the rewrite changed the preimage"
    );

    // §9.3 step 2 MUST fail with invalid_log_proof.
    let err = checkpoint
        .verify_signature_against_hash(&served_hash, Some(&pub_bytes), None)
        .unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidLogProof(_)),
        "log-004: rewritten checkpoint must fail as invalid_log_proof, got {err:?}"
    );
    assert!(
        !err.is_transient(),
        "a bad checkpoint will not verify on retry"
    );

    // Sanity: the same signature DOES verify over the genuine hash the
    // registry originally signed (the signature bytes themselves are
    // authentic — the lie is the served root_hash).
    checkpoint
        .verify_signature_against_hash(
            &acdp::types::ContentHash(input["genuine_checkpoint_hash"].as_str().unwrap().into()),
            Some(&pub_bytes),
            None,
        )
        .expect("log-004 premise: the signature covers the genuine checkpoint hash");
}

// ═══════════════════════════════════════════════════════════════════════
// Retrieval envelope: log_inclusion is a typed top-level sibling
// ═══════════════════════════════════════════════════════════════════════

/// RFC-ACDP-0012 §10: `log_inclusion` rides the retrieval envelope as a
/// top-level member (a sibling of `registry_receipt`, never inside it).
/// Injecting the log-001 proof into the spec's golden retrieval example
/// must land in the typed `FullContext::log_inclusion` field — not the
/// extensions map — and round-trip byte-preserved; absence serializes
/// as absent, never `null`.
#[test]
fn log_inclusion_rides_the_retrieval_envelope() {
    let Some(root) = spec_root() else { return };
    let example = root.join("examples/retrieval/golden-context.json");
    let fixture = root.join("schemas/conformance/log-001-leaf-and-root-golden.json");
    if fixture_missing(&example) || fixture_missing(&fixture) {
        return;
    }
    let mut ctx_value = read_json(&example);
    let v = read_json(&fixture);
    let expected = &v["vectors"][0]["expected"];

    // Assemble the §10 member: the §8.2 inclusion object WITHOUT the
    // leaf echo (the leaf is reconstructed from the very body and
    // receipt the response carries).
    let mut incl = expected["log_inclusion"].clone();
    incl.as_object_mut()
        .unwrap()
        .insert("log_checkpoint".into(), expected["log_checkpoint"].clone());
    ctx_value
        .as_object_mut()
        .unwrap()
        .insert("log_inclusion".into(), incl.clone());

    let ctx: acdp::types::FullContext = serde_json::from_value(ctx_value).unwrap();
    let carried = ctx
        .log_inclusion
        .as_ref()
        .expect("log_inclusion lands in the typed field");
    assert_eq!(carried, &incl, "preserved verbatim");
    assert!(
        !ctx.extensions.contains_key("log_inclusion"),
        "typed member, not an unknown-extension passthrough"
    );
    let parsed = LogInclusion::from_value(carried).unwrap();
    assert_eq!(parsed.leaf_index, 0);
    assert!(parsed.leaf.is_none(), "§10: no leaf echo on retrieval");

    // Round trip: still a top-level member, sibling of body.
    let out = serde_json::to_value(&ctx).unwrap();
    assert_eq!(out["log_inclusion"], incl);

    // Absent stays absent (never null) — the §10 OPTIONAL posture.
    let mut without = ctx.clone();
    without.log_inclusion = None;
    let out = serde_json::to_value(&without).unwrap();
    assert!(out.get("log_inclusion").is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// MerkleLog reproduces the fixture tree (two implementations in one)
// ═══════════════════════════════════════════════════════════════════════

/// Append the five log-001 leaves to the `server`-feature
/// [`acdp::registry::MerkleLog`] and require the SAME tree: root,
/// signed checkpoints at sizes 5 (log-001) and 3 (log-003), the pinned
/// inclusion proof for leaf 0, and the pinned 3→5 consistency path —
/// so the SDK's producer-side tree and its verifier-side algorithms are
/// checked against each other *and* against the spec generator.
#[cfg(feature = "server")]
#[test]
fn merkle_log_reproduces_the_fixture_tree() {
    use acdp::registry::MerkleLog;

    let Some(root) = spec_root() else { return };
    let p001 = root.join("schemas/conformance/log-001-leaf-and-root-golden.json");
    let p003 = root.join("schemas/conformance/log-003-consistency-proof-golden.json");
    if fixture_missing(&p001) || fixture_missing(&p003) {
        return;
    }
    let v001 = read_json(&p001);
    let v003 = read_json(&p003);
    let vector = &v001["vectors"][0];
    let expected = &vector["expected"];
    let signer = fixture_signer(&v001);

    let mut log = MerkleLog::new(vector["log_id"].as_str().unwrap()).unwrap();
    for (i, wire) in vector["leaves"].as_array().unwrap().iter().enumerate() {
        let idx = log.append(LogLeaf::from_value(wire).unwrap()).unwrap();
        assert_eq!(idx, i as u64, "acceptance-order indexing (§5.3)");
        assert_eq!(
            log.leaf_hash_hex(idx).unwrap(),
            expected["leaf_hashes"][i].as_str().unwrap(),
            "leaf {i}: the log's stored §5.1 hash matches the fixture"
        );
    }
    assert_eq!(log.tree_size(), 5);
    assert_eq!(log.root_hash(), expected["root_hash"].as_str().unwrap());

    // Checkpoint at size 5 with the fixture timestamp reproduces the
    // pinned signed checkpoint byte-for-byte.
    let ts5 = chrono::DateTime::parse_from_rfc3339(
        vector["checkpoint_unsigned"]["timestamp"].as_str().unwrap(),
    )
    .unwrap()
    .with_timezone(&chrono::Utc);
    let cp5 = log.checkpoint(&signer, ts5).unwrap();
    assert_eq!(
        serde_json::to_value(&cp5).unwrap(),
        expected["log_checkpoint"],
        "MerkleLog checkpoint must equal the log-001 pinned checkpoint"
    );

    // Inclusion proof for leaf 0 at size 5 equals the pinned proof and
    // verifies against the independently reconstructed leaf.
    let proof = log.inclusion_proof(0, &cp5).unwrap();
    assert_eq!(
        serde_json::to_value(&proof.inclusion_path).unwrap(),
        expected["log_inclusion"]["inclusion_path"],
        "MerkleLog PATH(0, D[5]) must equal the pinned inclusion_path"
    );
    proof
        .verify_reconstructed_leaf(&LogLeaf::from_value(&vector["leaves"][0]).unwrap())
        .unwrap();

    // log-003: checkpoint at historical size 3 reproduces the pinned
    // first checkpoint signature; the 3→5 consistency response equals
    // the pinned path and verifies against the retained size-3 root.
    let v3 = &v003["vectors"][0];
    let e3 = &v3["expected"];
    let ts3 = chrono::DateTime::parse_from_rfc3339(
        v3["first_checkpoint_unsigned"]["timestamp"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .with_timezone(&chrono::Utc);
    let cp3 = log.checkpoint_at(&signer, 3, ts3).unwrap();
    assert_eq!(
        cp3.root_hash,
        e3["first_root_hash"].as_str().unwrap(),
        "MerkleLog historical root at size 3"
    );
    assert_eq!(
        cp3.signature.value,
        e3["first_signature_value_base64"].as_str().unwrap(),
        "MerkleLog size-3 checkpoint must reproduce the log-003 pinned signature"
    );

    let resp = log.consistency_proof_response(3, &cp5).unwrap();
    assert_eq!(
        serde_json::to_value(&resp.consistency_path).unwrap(),
        e3["consistency_proof_response"]["consistency_path"],
        "MerkleLog PROOF(3, D[5]) must equal the pinned consistency_path"
    );
    resp.verify_against_first_root(&cp3.root_hash)
        .expect("§9.2 verification across the log's own checkpoints");
}

// ═══════════════════════════════════════════════════════════════════════
// End-to-end: §9.3/§9.1 verification against a live did:web document
// ═══════════════════════════════════════════════════════════════════════

/// Full client pipeline over in-process TLS: a `MerkleLog`-minted
/// checkpoint and inclusion proof verify through
/// `verify_log_checkpoint_value` / `verify_log_inclusion_value` with
/// the registry key resolved from a live `did:web` document; the
/// log-004 (rewritten root) and log-002 (tampered path) behaviors
/// surface as `InvalidLogProof` through the same path, and a checkpoint
/// bound to a foreign authority is rejected at §9.3 step 3.
#[cfg(all(feature = "client", feature = "server"))]
#[tokio::test]
#[allow(deprecated)] // test-transport resolver constructor; gated in 0.4.0
async fn client_verifies_log_artifacts_end_to_end() {
    use acdp::client::{verify_log_checkpoint_value, verify_log_inclusion_value};
    use acdp::did::WebResolver;
    use acdp::registry::MerkleLog;
    use acdp::types::{ContentHash, CtxId};
    use common::{ed25519_did_doc, TlsTestServer};

    const REGISTRY_DID: &str = "did:web:localhost";
    const LOG_ID: &str = "did:web:localhost/log/1";
    const SEED: [u8; 32] = [0x11u8; 32];

    let signer = ReceiptSigner::new(
        acdp::crypto::SigningKey::from_bytes(&SEED),
        REGISTRY_DID,
        format!("{REGISTRY_DID}#receipt-key-1"),
    )
    .unwrap();

    // Three publish events on the localhost registry.
    let mut log = MerkleLog::new(LOG_ID).unwrap();
    let mut leaves = Vec::new();
    for i in 0..3u8 {
        let ctx_id = format!("acdp://localhost/00000000-0000-4000-8000-0000000000{i:02}");
        let leaf = LogLeaf {
            leaf_version: LOG_LEAF_VERSION.into(),
            lineage_id: acdp::crypto::derive_lineage_id(&CtxId(ctx_id.clone())),
            ctx_id: CtxId(ctx_id),
            origin_registry: "localhost".into(),
            created_at: chrono::DateTime::parse_from_rfc3339("2026-07-01T01:00:00.123Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            content_hash: ContentHash(format!("sha256:{}", "b".repeat(64))),
            key_fingerprint: format!("sha256:{}", "c".repeat(64)),
            receipt_hash: format!("sha256:{}", "d".repeat(64)),
        };
        log.append(leaf.clone()).unwrap();
        leaves.push(leaf);
    }
    let checkpoint = log.checkpoint(&signer, chrono::Utc::now()).unwrap();
    let checkpoint_wire = serde_json::to_value(&checkpoint).unwrap();
    let inclusion = log.inclusion_proof(1, &checkpoint).unwrap();
    let inclusion_wire = serde_json::to_value(&inclusion).unwrap();

    // Live did:web document for the registry's receipt key.
    let registry_pub = acdp::crypto::SigningKey::from_bytes(&SEED).verifying_key_bytes();
    let doc = ed25519_did_doc(REGISTRY_DID, "receipt-key-1", &registry_pub);
    let tls = TlsTestServer::start(axum::Router::new().route(
        "/.well-known/did.json",
        axum::routing::get(move || {
            let doc = doc.clone();
            async move { axum::Json(doc) }
        }),
    ))
    .await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let skew = chrono::Duration::seconds(120);

    // §9.3 end-to-end.
    let verified =
        verify_log_checkpoint_value(&checkpoint_wire, "localhost", REGISTRY_DID, skew, &resolver)
            .await
            .expect("checkpoint verifies against the live DID document");
    assert_eq!(verified.tree_size, 3);

    // §9.1 end-to-end, with the leaf "reconstructed" independently.
    verify_log_inclusion_value(
        &inclusion_wire,
        &leaves[1],
        "localhost",
        REGISTRY_DID,
        skew,
        &resolver,
    )
    .await
    .expect("inclusion proof verifies end-to-end");

    // log-004 behavior through the client path: rewritten root_hash.
    let mut rewritten = checkpoint_wire.clone();
    rewritten["root_hash"] = serde_json::json!(format!("sha256:{}", "f".repeat(64)));
    let err = verify_log_checkpoint_value(&rewritten, "localhost", REGISTRY_DID, skew, &resolver)
        .await
        .expect_err("rewritten checkpoint must fail");
    assert!(matches!(err, AcdpError::InvalidLogProof(_)), "got {err:?}");

    // log-002 behavior through the client path: tampered audit path.
    let mut tampered = inclusion_wire.clone();
    let el = tampered["inclusion_path"][0].as_str().unwrap();
    let mut raw = decode_sha256_hex(el).unwrap();
    raw[0] ^= 1;
    tampered["inclusion_path"][0] = serde_json::json!(encode_sha256_hex(&raw));
    let err = verify_log_inclusion_value(
        &tampered,
        &leaves[1],
        "localhost",
        REGISTRY_DID,
        skew,
        &resolver,
    )
    .await
    .expect_err("tampered inclusion_path must fail");
    assert!(matches!(err, AcdpError::InvalidLogProof(_)), "got {err:?}");

    // A wrong reconstructed leaf (registry served different material)
    // fails the fold even with an honest proof.
    let err = verify_log_inclusion_value(
        &inclusion_wire,
        &leaves[0],
        "localhost",
        REGISTRY_DID,
        skew,
        &resolver,
    )
    .await
    .expect_err("leaf/index mismatch must fail");
    assert!(matches!(err, AcdpError::InvalidLogProof(_)), "got {err:?}");

    // §9.3 step 3: foreign-authority binding rejected (fed-006 analogue).
    let err = verify_log_checkpoint_value(
        &checkpoint_wire,
        "hostile.example",
        "did:web:hostile.example",
        skew,
        &resolver,
    )
    .await
    .expect_err("foreign authority must fail the registry binding");
    assert!(matches!(err, AcdpError::InvalidLogProof(_)), "got {err:?}");

    // §9.3 step 4: a future-dated checkpoint beyond skew is a forged
    // freshness claim.
    let future_cp = log
        .checkpoint(&signer, chrono::Utc::now() + chrono::Duration::seconds(600))
        .unwrap();
    let err = verify_log_checkpoint_value(
        &serde_json::to_value(&future_cp).unwrap(),
        "localhost",
        REGISTRY_DID,
        skew,
        &resolver,
    )
    .await
    .expect_err("future-dated checkpoint must fail the skew check");
    assert!(matches!(err, AcdpError::InvalidLogProof(_)), "got {err:?}");
}
