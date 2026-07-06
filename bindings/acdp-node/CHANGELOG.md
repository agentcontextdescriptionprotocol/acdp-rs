# Changelog — @agentcontextdistributionprotocol/acdp (Node.js SDK)

Independently versioned from the Rust crates (this package is
`publish = false` on crates.io and released by its own workflow). Kept
in lock-step with the Python SDK (`bindings/acdp-py`) — the interop
suite fails if the two versions or API surfaces drift.

## 0.7.0 — 2026-07-05

ACDP 0.4 transparency-log **witness cosignatures** (RFC-ACDP-0015),
offline and JSON-over-FFI like everything else (documents supplied by
the caller; the binding never touches the network).

### Added

- **`AcdpVerifier.buildWitnessCosignature`** (RFC-ACDP-0015 §5) — the
  MINT surface a host-language witness service uses: cosign an observed
  checkpoint (`{log_id, tree_size, root_hash, timestamp}`) with the
  witness's OWN Ed25519 key (a 32-byte hex seed, mirroring
  `AcdpProducer`), signing-key DID URL derived as
  `"<witnessDid>#witness-key-1"`. Uses the RFC-ACDP-0010 §5
  construction verbatim; a fixed seed + input reproduces the wit-001
  golden signature byte-for-byte (pinned in the interop suite as the
  witness-layer analogue of the sig-001 cross-binding equality). This
  is the RAW mint — the §7 obligation (checkpoint signature +
  consistency) is the host's job.
- **`AcdpVerifier.verifyWitnessCosignature`** (RFC-ACDP-0015 §8
  steps 1–5) — verify one cosignature against a checkpoint the consumer
  has itself verified, against a caller-supplied witness DID document.
  Returns a JSON verdict (`valid` / `witness_id` / `age_secs` /
  `stale`); staleness (§8.1) is policy, never a verification failure.
  Failures carry `.code === "invalid_witness_cosignature"` —
  deliberately distinct from `invalid_log_proof` (§10).
- **`AcdpVerifier.evaluateWitnessQuorum`** (RFC-ACDP-0015 §8) — the
  N-witnessed count over a set of cosignatures for a verified
  checkpoint, under a `{min_witnesses, max_age_secs,
  max_clock_skew_secs}` policy. Returns `{witnessed_count, witnesses,
  meets_quorum, fresh_witnessed_count, meets_fresh_quorum, failures}`;
  distinct trusted `witness_id` values are counted, and a cosignature
  that fails a step is recorded in `failures` without failing the
  checkpoint.
- Witness-cosignature failures throw / verdict-carry the stable
  `.code === "invalid_witness_cosignature"` (RFC-ACDP-0015 §10),
  mirroring the Python `InvalidWitnessCosignature` exception.

## 0.6.0 — 2026-07-05

ACDP 0.3.0 surfaces, offline and JSON-over-FFI like everything else
(documents supplied by the caller; the binding never touches the
network).

### Added

- **`AcdpVerifier.verifyLineageHeadReceipt`** (RFC-ACDP-0011 §7) —
  full head-receipt verification against a caller-supplied registry
  DID document: closed parse, registry/lineage/head bindings, `as_of`
  clock skew, raw-JSON signature preimage. Returns a JSON verdict
  (`valid` / `stale` / `age_secs` / `historical`); staleness is
  reported as policy, never a verification failure.
- **Transparency-log verification** (RFC-ACDP-0012):
  `AcdpVerifier.verifyLogCheckpoint` (§9.3), `verifyLogInclusion`
  (§9.1 — the leaf is always the caller's reconstruction, never an
  echoed one), `verifyLogConsistency` (§9.2, the history-rewrite
  detector), and `buildLogLeaf` (§9.1 step 1 — rebuild the canonical
  leaf from a verified RFC-ACDP-0010 receipt, including its
  `receipt_hash`).
- **`AcdpMerkle`** — RFC-ACDP-0012 §5 tree arithmetic (`leafHash`,
  `nodeHash`, `rootHash`) for independent tree math; pinned against
  the log-001/log-003 golden vectors.
- **`AcdpVerifier.verifyLifecycleEvent`** (RFC-ACDP-0013 §5) — offline
  event verification: `did:key` actors natively, `did:web` actors via
  a caller-supplied DID document with the `assertionMethod` gate.
- **Key revocation** (RFC-ACDP-0014):
  `AcdpVerifier.parseKeyRevocation` (§4 shape + §5/§6 trust class +
  the §5 step 2 not-self-signed rule) and `classifyUnderRevocation`
  (the §7 fail-closed compromise-boundary rule with §4
  earliest-boundary monotonicity).
- **Stable error codes** on thrown errors — `invalid_log_proof`,
  `immutable_field`, `invalid_lifecycle_transition` (plus
  `invalid_receipt`, `schema_violation`, `key_not_authorized`, ...)
  on `Error.code`, the same taxonomy the Python binding raises as
  typed exception classes. Failure verdicts carry it in their `code`
  member.

### Notes

- New golden-vector pins: lhr-001, log-001, log-003, rev-001 (plus the
  lhr-002/003/004, log-002/004 and rev-002 failure fixtures).
- No changes to the pre-0.3 surface; sig-001 parity is unchanged.

## 0.5.0 and earlier

See the repository history (`git log -- bindings/acdp-node`).
