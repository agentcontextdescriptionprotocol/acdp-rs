# Changelog — @agentcontextdistributionprotocol/acdp (Node.js SDK)

Independently versioned from the Rust crates (this package is
`publish = false` on crates.io and released by its own workflow). Kept
in lock-step with the Python SDK (`bindings/acdp-py`) — the interop
suite fails if the two versions or API surfaces drift.

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
