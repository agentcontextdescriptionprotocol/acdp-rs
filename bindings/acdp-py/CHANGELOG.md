# Changelog — acdp (Python SDK)

Independently versioned from the Rust crates (this package is
`publish = false` on crates.io and released by its own workflow). Kept
in lock-step with the Node SDK (`bindings/acdp-node`) — the interop
suite fails if the two versions or API surfaces drift.

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
