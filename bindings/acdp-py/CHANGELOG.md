# Changelog — acdp (Python SDK)

Independently versioned from the Rust crates (this package is
`publish = false` on crates.io and released by its own workflow). Kept
in lock-step with the Node SDK (`bindings/acdp-node`) — the interop
suite fails if the two versions or API surfaces drift.

## 0.7.0 — 2026-07-05

ACDP 0.4 transparency-log **witness cosignatures** (RFC-ACDP-0015),
offline and JSON-over-FFI like everything else (documents supplied by
the caller; the binding never touches the network).

### Added

- **`AcdpVerifier.build_witness_cosignature`** (RFC-ACDP-0015 §5) — the
  MINT surface a host-language witness service uses: cosign an observed
  checkpoint (`{log_id, tree_size, root_hash, timestamp}`) with the
  witness's OWN Ed25519 key (a 32-byte hex seed, mirroring
  `AcdpProducer`), signing-key DID URL derived as
  `"<witness_did>#witness-key-1"`. Uses the RFC-ACDP-0010 §5
  construction verbatim; a fixed seed + input reproduces the wit-001
  golden signature byte-for-byte (pinned in the interop suite as the
  witness-layer analogue of the sig-001 cross-binding equality). This
  is the RAW mint — the §7 obligation (checkpoint signature +
  consistency) is the host's job.
- **`AcdpVerifier.verify_witness_cosignature`** (RFC-ACDP-0015 §8
  steps 1–5) — verify one cosignature against a checkpoint the consumer
  has itself verified, against a caller-supplied witness DID document.
  Returns a JSON verdict (`valid` / `witness_id` / `age_secs` /
  `stale`); staleness (§8.1) is policy, never a verification failure.
  Failures carry `code: "invalid_witness_cosignature"` — deliberately
  distinct from `invalid_log_proof` (§10).
- **`AcdpVerifier.evaluate_witness_quorum`** (RFC-ACDP-0015 §8) — the
  N-witnessed count over a set of cosignatures for a verified
  checkpoint, under a `{min_witnesses, max_age_secs,
  max_clock_skew_secs}` policy. Returns `{witnessed_count, witnesses,
  meets_quorum, fresh_witnessed_count, meets_fresh_quorum, failures}`;
  distinct trusted `witness_id` values are counted, and a cosignature
  that fails a step is recorded in `failures` without failing the
  checkpoint.
- **`InvalidWitnessCosignature`** — the typed, catchable exception for
  the RFC-ACDP-0015 §10 wire code (mirrors `InvalidLogProof`).

## 0.6.0 — 2026-07-05

ACDP 0.3.0 surfaces, offline and JSON-over-FFI like everything else
(documents supplied by the caller; the binding never touches the
network).

### Added

- **`AcdpVerifier.verify_lineage_head_receipt`** (RFC-ACDP-0011 §7) —
  full head-receipt verification against a caller-supplied registry
  DID document: closed parse, registry/lineage/head bindings, `as_of`
  clock skew, raw-JSON signature preimage. Returns a JSON verdict
  (`valid` / `stale` / `age_secs` / `historical`); staleness is
  reported as policy, never a verification failure.
- **Transparency-log verification** (RFC-ACDP-0012):
  `AcdpVerifier.verify_log_checkpoint` (§9.3),
  `verify_log_inclusion` (§9.1 — the leaf is always the caller's
  reconstruction, never an echoed one), `verify_log_consistency`
  (§9.2, the history-rewrite detector), and
  `build_log_leaf` (§9.1 step 1 — rebuild the canonical leaf from a
  verified RFC-ACDP-0010 receipt, including its `receipt_hash`).
- **`AcdpMerkle`** — RFC-ACDP-0012 §5 tree arithmetic (`leaf_hash`,
  `node_hash`, `root_hash`) for independent tree math; pinned against
  the log-001/log-003 golden vectors.
- **`AcdpVerifier.verify_lifecycle_event`** (RFC-ACDP-0013 §5) —
  offline event verification: `did:key` actors natively, `did:web`
  actors via a caller-supplied DID document with the `assertionMethod`
  gate.
- **Key revocation** (RFC-ACDP-0014):
  `AcdpVerifier.parse_key_revocation` (§4 shape + §5/§6 trust class +
  the §5 step 2 not-self-signed rule) and
  `classify_under_revocation` (the §7 fail-closed compromise-boundary
  rule with §4 earliest-boundary monotonicity).
- **Typed exceptions** `InvalidLogProof`, `ImmutableField`,
  `InvalidLifecycleTransition` — the 0.3.0 wire codes, alongside the
  existing `SsrfRejected` / `DidResolutionError`. Failure verdicts
  carry the same taxonomy in their `code` member.

### Notes

- New golden-vector pins: lhr-001, log-001, log-003, rev-001 (plus the
  lhr-002/003/004, log-002/004 and rev-002 failure fixtures).
- No changes to the pre-0.3 surface; sig-001 parity is unchanged.

## 0.5.0 and earlier

See the repository history (`git log -- bindings/acdp-py`).
