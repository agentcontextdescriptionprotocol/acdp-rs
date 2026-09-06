# ASSUMPTIONS

## Pin SHA for RS-1/RS-2 local verification
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** the user's literal instruction to pin the verification worktree to "the
  current spec main SHA" actually means the SHA already pinned in `ci.yml:75`
  (`f5b66b8f86f48ba16f79bba95eb246d6acb43989`), not today's live spec `main` HEAD
  (`2eb8fee`, 4 commits ahead) — since bumping the pin is explicitly out of scope (RS-3,
  wave 2, hazard H6) and testing against a different commit than the one CI actually uses
  would not be a faithful dry run of the CI job being edited.
- **Chose:** pinned the local verification worktree to `f5b66b8f86f48ba16f79bba95eb246d6acb43989`.
- **Alternatives:** pin to live spec `main` HEAD (rejected: tests a commit CI doesn't use);
  ask the user before proceeding (rejected: unambiguous given the "never bump the pin"
  hard rule, cheap to reverse).
- **Blast radius if wrong:** trivial — re-run the same commands against a different
  `worktree add` SHA. No code changes hinge on this choice.
- **Status:** CONFIRMED (2026-08-28) — see DECISIONS.md

## RS-2 KNOWN_FAMILIES / EXCUSED design (static vs. dynamic)
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** the RS-2 item's accept criterion ("dropping anc-001 fails the test until
  anc is executed or excused") requires a **static**, hand-maintained Rust-side
  `KNOWN_FAMILIES` list cross-checked against the **dynamic** canonical family list pulled
  from the pinned spec's `registries/profiles.json` — not a fully-dynamic design where the
  canonical list alone decides "known," which would let any new family silently pass.
- **Chose:** `KNOWN_FAMILIES: &[&str]` (28 entries, hand-reviewed) + `EXCUSED: &[(&str,
  &str)]` (currently empty) in `tests/conformance.rs`, matched against fixture ids via a
  longest-prefix-match ported from the spec's own `check-consistency.py::check_families`.
- **Alternatives:** derive "known" directly from `profiles.json` (rejected: defeats the
  forcing-function purpose — a new family would auto-pass); per-fixture (not per-family)
  coverage tracking (rejected: much finer-grained than RS-2 asks for, flagged as a future
  tightening in the plan's Long-term posture instead).
- **Blast radius if wrong:** low — verifier independently confirmed all 28 known families
  are genuinely covered (each has ≥1 fixture referenced by literal id somewhere in the test
  suite) and both accept-criteria negative scenarios (bare `anc-001` drop; drop +
  `profiles.json` addition) independently reproduced with the two distinct expected panic
  sites. If the design were wrong, the fix is a same-file, same-phase rewrite.
- **Status:** CONFIRMED (2026-08-28) — see DECISIONS.md

## RS-1 exclusion contingency (not needed)
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** RS-1's own text permits excluding a specific test target from the
  `--workspace` invocation if it genuinely fails at the pinned SHA due to a 0.2.0-branch
  fixture family not yet merged to spec `main`.
- **Chose:** ran the full `cargo test --workspace --all-features` against the pinned SHA
  (`f5b66b8f…`) under require-mode *before* touching `ci.yml`, empirically confirming zero
  failures — `wit-`, `log-`, `rev-`, `lc-` families and `crates/acdp-jcs/tests/differential_numbers.rs`
  (also newly swept in by `--workspace`) all pass. No exclusion was needed.
- **Alternatives:** none — this was a factual question resolved by running the suite, not
  a judgment call.
- **Blast radius if wrong:** none — this is a factual outcome, not a design decision.
- **Status:** CONFIRMED (empirically, by test run — not a genuine open question)

## Reusing root deny.toml for bindings advisory scanning
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** the root `deny.toml`'s `[licenses]`/`[bans]`/`[sources]` policy is generic
  enough to reuse for the bindings' dependency graphs via `--config`, and its one
  `[advisories] ignore` entry (RUSTSEC-2025-0134, axum-server-specific) is harmless when
  applied to graphs that don't pull axum-server at all.
- **Chose:** `cargo deny --manifest-path <binding>/Cargo.toml --config deny.toml check
  advisories` (scoped to `check advisories` only, not bare `check`), reusing the root file
  rather than authoring three near-duplicate `deny.toml`s.
- **Alternatives:** standalone `deny.toml` per binding (rejected: pure maintenance
  overhead with no current benefit, since the bindings never diverge from the root
  license/source policy today).
- **Blast radius if wrong:** low, and already partially confirmed — the reused ignore
  entry does produce a benign `advisory-not-detected` warning (not a failure) for each
  binding graph, exactly as anticipated. If the bindings' policy needs to diverge later
  (e.g. a binding-only license exception), splitting into standalone files is a small,
  additive change.
- **Status:** CONFIRMED (2026-08-28) — see DECISIONS.md

## Not reversing the binding-lockfiles-gitignored policy
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** RS-10's scope is "wire up advisory scanning," not "make the bindings'
  dependency graphs reproducible" — so the existing `.gitignore` policy (bindings'
  `Cargo.lock`/`package-lock.json` are gitignored, build output) stays as-is, and the new
  CI jobs resolve a fresh graph every run rather than auditing a pinned one.
- **Chose:** left `.gitignore` untouched; the new `bindings-deny`/`bindings-npm-audit`
  jobs audit whatever each manifest's version constraints resolve to at CI-run time.
- **Alternatives:** commit the three `Cargo.lock`s + `package-lock.json` for reproducible
  scanning (rejected: a materially larger, separate policy change — touches release
  workflow assumptions about what's "build output" — outside RS-10's stated scope).
- **Blast radius if wrong:** medium, ongoing — an unrelated transitive dependency landing
  a new RUSTSEC advisory can turn the new job red with no code change in a future PR. This
  is flagged explicitly in the job's own comment as expected supply-chain-gate behavior,
  not a flake to silence — but if it proves too noisy in practice, reversing this decision
  (committing the lockfiles) is a bigger, separate change.
- **Status:** CONFIRMED (2026-08-28) — see DECISIONS.md

## pyo3 version: bumped to 0.29 instead of the planned 0.24 line
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** discovered mid-implementation, not anticipated by the plan (which was
  researched before these advisories existed): `cargo deny check advisories` against the
  originally-planned pyo3 0.24.2 revealed **two additional 2026 RUSTSEC advisories**
  (RUSTSEC-2026-0176, out-of-bounds read in `PyList`/`PyTuple` iterator `nth`/`nth_back`;
  RUSTSEC-2026-0177, missing `Sync` bound on `PyCFunction::new_closure`), both only fixed
  at `>= 0.29.0`. RUSTSEC-2026-0176 is *unaffected* below `0.24.0` and only introduced
  starting at `0.24.0` — meaning the originally-planned 0.24 bump would have *newly
  introduced* a vulnerability that didn't exist at the starting version (0.22), while
  still leaving RUSTSEC-2025-0020 (the one RS-10 named) and RUSTSEC-2026-0177 unfixed.
  Landing 0.24 as literally planned would not have satisfied RS-10's own accept criterion
  ("advisory scan green in CI").
- **Chose:** bumped to `pyo3 = { version = "0.29", features = ["abi3-py39"] }` instead.
  Verified before committing to this: (1) `abi3-py39` still exists as a valid feature at
  0.29.2 (confirmed by inspecting pyo3's own `Cargo.toml` and by a successful `maturin
  develop --release` producing a `cp39-abi3` wheel) — so `requires-python = ">=3.9"` and
  the `bindings.yml` Python matrix (`3.9`/`3.11`/`3.13`) needed no change; (2) the
  migration was two call sites (`Python::with_gil` → `Python::attach`) plus the eight
  already-needed 0.24-era deprecation renames (`value_bound` → `value`, `get_type_bound`
  → `get_type`) — not the large migration effort initially feared; (3) all 172 existing
  Python tests pass unmodified, including the golden-vector parity constant
  (`sha256:f170150d…`) CLAUDE.md says must never drift; (4) `cargo deny check advisories`
  now genuinely exits 0 for this graph.
- **Alternatives:** stay on 0.24 and add reasoned `ignore` entries for RUSTSEC-2026-0176/
  -0177 to `deny.toml` (rejected: the "advisory scan green" criterion would then only be
  true by suppression, not by actually being unaffected — and unlike the existing
  RUSTSEC-2025-0134 ignore, verifying non-reachability of a memory-safety bug deep in
  pyo3's generated codegen is not something that can be confidently asserted by
  inspection); bump only as far as needed to fix each advisory individually (rejected: no
  intermediate version fixes both — both advisories' solution is ">= 0.29.0").
- **Blast radius if wrong:** low, independently verified by a fresh Opus verifier: pyo3
  0.29.2's own advisory-db entries confirm the version choice is strictly correct (clears
  RUSTSEC-2025-0020, -2026-0176, -2026-0177, and incidentally RUSTSEC-2026-0013 too); the
  `abi3-py39` claim was verified against pyo3's actual source, not assumed; all tests pass.
  If reversed, the two-call-site rename and the small deprecation cleanup are easy to
  revert together with the version pin.
- **Status:** CONFIRMED (2026-08-28) — see DECISIONS.md. Both required follow-ups applied:
  `bindings/acdp-py/CHANGELOG.md` now has an `## Unreleased` / `### Security` entry, and
  the PR description states the 0.24→0.29 deviation explicitly.

## bindings/acdp-wasm: pre-existing break discovered, excluded from new advisory job
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** not part of RS-10's scope to fix. Discovered while implementing Phase 3:
  `bindings/acdp-wasm/Cargo.toml:61` pins `getrandom = { version = "0.4", features =
  ["js"] }`, but `getrandom` 0.4 has no `js` feature (only `wasm_js` — see the correctly
  written `getrandom_wasm` alias two lines below). This makes `cargo metadata` fail
  outright for that crate — not just for a new `cargo deny` job, but for **every**
  existing command in `bindings.yml`'s `acdp-wasm` job (native `cargo test`, both wasm32
  builds, `wasm-pack build`, `wasm-pack test --node`). Confirmed via `git log`/`git
  merge-base` that this predates the branch (introduced by commit `d511e03`, "build(deps):
  update getrandom requirement (#133)", already on `main` before this session started),
  and independently confirmed via `gh run view` that the live `acdp-wasm` job on `main` is
  currently failing (run `29128956237` at commit `c4c9be8`) while all 7 sibling jobs
  succeed.
- **Chose (original, since superseded — see Status below):** excluded `bindings/acdp-wasm`
  from the new `bindings-deny` job's matrix (only `[bindings/acdp-py, bindings/acdp-node]`),
  with an explicit comment in `bindings.yml` and `Makefile` naming the exact cause, the
  introducing commit, and stating this is pre-existing and out of scope for this PR. Did
  not attempt the guessed one-line fix (`["js"]` → `["wasm_js"]`) since that's an unrelated
  dependency-resolution bug, not an advisory-scanning concern, and bundling an unrelated fix
  into a supply-chain PR would make the diff harder to review/revert cleanly. **This
  guessed fix was also wrong** — see the reconcile outcome in the Status line below and
  DECISIONS.md for the actual root cause and fix that shipped instead.
- **Alternatives:** fix the one-line `getrandom` bug as a drive-by (rejected: unrequested
  scope creep on a security-supply-chain-focused PR, and the fix deserves its own review —
  e.g., confirming whether the unaliased `getrandom` entry should be removed entirely
  since `getrandom_wasm` may already cover its purpose, which needs more investigation
  than a blind feature-rename); silently include `acdp-wasm` in the matrix anyway
  (rejected: would make the new job spuriously, permanently red for a reason unrelated to
  what it's meant to gate).
- **Blast radius if wrong:** **this is the highest-priority open item from this session,
  independent of RS-1/RS-2/RS-10.** The `acdp-wasm` binding is currently unbuildable and
  untested on `main` — its golden-vector parity guard (`sig-001`/`wit-001` cross-checks
  per CLAUDE.md's binding conventions) is providing zero coverage today, and this has been
  true since 2026-07-10 with nobody noticing (matches the family-wide "idle since
  2026-07-10" status). This should be raised to the user/maintainer promptly and likely
  warrants its own small, dedicated PR — not something this plan's scope should silently
  absorb or silently leave undiscovered.
- **Status:** NEEDS-CHANGE → **applied and re-verified, DONE (2026-08-28)** — see
  DECISIONS.md. User chose to fix in this PR rather than defer. Root cause was corrected
  during reconciliation (the guessed `js`→`wasm_js` fix was wrong; the actual fix is
  reverting the unaliased `getrandom` entry to `version = "0.2"` — the manifest
  deliberately carries two getrandom majors, and a Dependabot bump had mistakenly touched
  the wrong one, a recurrence of a previously-fixed incident, PR #122 → #129 → #133).
  Verified via a dedicated Phase 4 + Opus gate: native tests, wasm32 debug+release builds,
  `wasm-pack test --node`, and `cargo deny check advisories` all pass; `acdp-wasm` is now
  included in the `bindings-deny` job's matrix and the `audit-bindings` Makefile target.

## RS-11: `ACDP_VERSION` default bump — constant bump vs. feature-derived
- **Plan:** `agentcontextdistributionprotocol/plans/siblings/acdp-rs.md` (RS-11, Wave 4)
- **Assumed:** the plan explicitly left the mechanism open ("decide the default stamp
  deliberately — constant bump or feature-derived") without naming a preferred answer,
  so this was a real fork requiring a judgment call, not a defaultable question with an
  obvious answer stated elsewhere.
- **Chose:** a straight constant bump, `ACDP_VERSION = "0.2.0"` → `"0.4.0"`
  (`crates/acdp-primitives/src/lib.rs:43`) — no cargo feature in this crate gates 0.3.0-
  vs-0.4.0-line wire support; every RFC-0011..0015 type is always compiled in, so
  "feature-derived" has nothing to condition on. The newest Final line is exactly what
  the WS-D1 "explicit by default" design intended the constant to track.
- **Alternatives:** (1) feature-derived default (rejected — no feature boundary exists
  to derive from in this crate today; would require inventing cargo features purely to
  serve this switch, which is speculative machinery for a problem that doesn't exist
  yet); (2) leave the constant at `0.2.0` and only fix the stale "drafts" wording
  (rejected — the plan explicitly flagged this as a real drift: "a defaults-using
  producer can't legitimately carry 0.3.0-line fields," which is still true today with
  0.4.0 now Final too); (3) stop and ask before touching the default (considered, but
  the plan's own framing — "decide... deliberately... changelog it," not "ask the human"
  — plus this session's established convention of proceeding on costly-but-reversible,
  non-one-way-door changes with documentation rather than blocking, argued for
  proceeding here).
- **Blast radius if wrong:** moderate, not severe, and cheaply reversible. Verified
  before making the change: no test in this repo asserts a fixed golden `content_hash`
  for a *default*-built (no explicit `.acdp_version(...)`/`.omit_acdp_version()`) request
  — the two golden vectors that pin exact hashes (sig-001, sig-003) both call one of
  those two explicit overrides, so they're unaffected. No `acdp-validation` rule imposes
  a new *required* field on a produced body at 0.3.0/0.4.0 (the only version gate,
  `caps.acdp_version >= 0.3.0 ⇒ supports_idempotency_key`, is on a registry's
  `CapabilitiesDocument`, not a producer's request) — so a bare `.build()` call still
  succeeds. The real exposure is ecosystem-wide: sibling repos that build a default
  `PublishRequest` (e.g. `acdp-playground`, `acdp-control-plane`) will start emitting
  `acdp_version: "0.4.0"` bodies the next time they pick up this crate version, and any
  registry pinned to reject or mis-handle that value would need updating first. If this
  turns out to be premature, reverting is a one-line constant change plus a follow-up
  changelog entry — not a schema or API removal.
- **Status:** CONFIRMED (2026-08-30) — see DECISIONS.md. Confirmed as-is: the constant
  bump has already shipped in two releases (0.8.2, 0.8.3) with no reported breakage; no
  golden vector or validation rule regressed. Reverting now would itself be a second
  wire-behavior change, so the bump stands.

## anchors supersede-settability (RS-8 binding follow-up)
- **Plan:** plans/rs8-bindings-anchors.md
- **Assumed:** the plan's Open Question 1 had no explicit spec answer for whether
  `anchors` should be settable on a supersession request, only that a clearly-best
  default existed and was cheap to reverse.
- **Chose:** exposed `anchors` on both `build_publish_request`/`buildPublishRequest`
  AND `build_supersede_request`/`buildSupersedeRequest`, in both `bindings/acdp-py`
  (`PyAcdpProducer`/`PyAcdpP256Producer`) and `bindings/acdp-node` (`PublishOpts`/
  `SupersedeOpts`) — mirroring `data_refs`'s treatment (JSON-parsed, available on both
  publish and supersede), not `derived_from`'s (publish-only, excluded from supersede).
  Reasoning: anchors are external evidence tied to *this version's* content (a
  blockchain/timestamping commitment over the current body), not an immutable
  lineage fact fixed at first publish — so a later version legitimately needs its own,
  different anchors, same as it needs its own `data_refs`.
- **Alternatives:** publish-only exposure (mirroring `derived_from`) — rejected because
  anchors describe per-version content evidence, not lineage provenance, so restricting
  it to publish-only would block a legitimate supersede use case (re-anchoring a
  corrected or updated version) for no protocol reason; the core `RequestBuilder`
  itself imposes no such restriction (`anchors()` is available in every builder state).
- **Blast radius if wrong:** low and cheaply reversible — this is a pre-1.0, previously
  entirely-absent binding parameter (RS-8's core work never touched either binding), so
  removing `anchors` from `SupersedeOpts`/`apply_supersede_fields` later is a normal,
  expected kind of binding-surface change, not a breaking-contract event. No wire format,
  schema, or core-crate API is affected either way — this is purely which FFI methods
  accept the parameter.
- **Status:** CONFIRMED (2026-08-30) — see DECISIONS.md for the full reconciliation
  record, including two follow-up fixes (clear-anchors capability, an unrelated
  `BODY_FIELD_NAMES` gap) that landed in the same PR as a result.

## Byte equality for CtxId comparison in context-identity binding (fed-011)
- **Plan:** plans/issues-189-191-client-binding-hardening.md
- **Assumed:** byte equality on `CtxId` satisfies conformance fixture
  `fed-011-ctx-id-binding.json`'s requirement that ids be "compared as parsed `acdp://`
  URIs, never as raw strings."
- **Chose:** derived `PartialEq` byte comparison in `verify_retrieved` and
  `fetch_report_inner`. This is sound *today* because the `ctx_id` schema
  (`schemas/json/acdp-common.schema.json:40`) mandates a unique canonical text form —
  lowercase DNS authority, lowercase v4 UUID — so byte equality and parsed equality
  coincide for every valid input. The served side is additionally canonicalized by
  `validate_identifiers` → `CtxId::parse`.
- **Alternatives:** decomposing both sides into (authority, uuid) and comparing
  components — rejected as machinery with no behavioural difference under
  canonical-form uniqueness.
- **Blast radius if wrong:** if a non-canonical or alias form ever becomes legitimate,
  byte equality would produce false refusals (fail-closed, so refusing valid resolves
  rather than accepting invalid ones). Fix would be relaxing the comparison at those two
  call sites — a pure behaviour change, no API break, since `ContextIdMismatch` already
  carries both textual forms.
- **Status:** UNCONFIRMED
- **Update (2026-09-06, plans/issues-206-208-bindings-registry-release-gate.md Phase 2,
  #206):** the bindings' equivalent check, `acdp_verify::verify_ctx_id_binding`, makes the
  parse-then-compare step explicit rather than relying on the served side having already
  been canonicalized by an upstream `validate_identifiers` call (the bindings have no such
  call): it parses *both* `served_ctx_id` and `expected_ctx_id` with `CtxId::parse` before
  comparing, so a malformed id on either side fails closed with `SchemaViolation` instead
  of reaching the equality check at all. This is the same deliberate divergence from
  `fed-011-ctx-id-binding.json`'s `uri_encoding_and_path_style_equivalence` case as the
  client's byte-equality choice above — canonical-form-only comparison produces false
  refusals for percent-encoded/path-style forms, never false acceptances — recorded again
  here because it is a second, independent call site making the same choice.

## `String` (not `CtxId`) fields on `ContextIdMismatch` — corrected rationale
- **Plan:** plans/issues-189-191-client-binding-hardening.md
- **Assumed:** the outcome (`requested`/`served` typed as `String`, not `CtxId`) is
  correct, but the rationale as shipped — "a `CtxId` field would over-promise that it
  parsed" — is factually shaky: `CtxId` is an unvalidated `pub String` newtype today, and
  `ContentHash` in the sibling `HashMismatch` variant is identical in that respect, so the
  "over-promise" argument cuts against both fields equally and doesn't actually
  distinguish `ContextIdMismatch`'s choice.
- **Chose:** the corrected rationale — `requested`/`served` are forensic evidence
  (attacker-controlled text quoted back to an operator for diagnosis), and `String` stays
  honest under future hardening: if `CtxId` is later turned into a parse-validated type,
  a `CtxId` field on this variant would then need a validity bypass to hold a value that,
  by construction, failed to match what was requested. `String` requires no such escape
  hatch. No code change — this replaces the comment/doc rationale only.
- **Alternatives:** leave the original "over-promise" rationale in place (rejected: it is
  demonstrably not the distinguishing argument, since it applies equally to a field this
  PR is not questioning); retype the fields as `CtxId` now (out of scope — the task is
  fixing the rationale, not the type).
- **Blast radius if wrong:** none — this corrects documentation/reasoning only; the
  shipped field types (`String`) are unchanged.
- **Status:** UNCONFIRMED

## `semver-tool-health` is not a required status check
- **Plan:** plans/issues-206-208-bindings-registry-release-gate.md (Phase 1)
- **Assumed:** adding the job to `ci.yml` is sufficient to satisfy Phase 1's acceptance
  criterion 5 ("a tool-health check exists that is NOT continue-on-error").
- **Chose:** ship the job without touching branch protection. `main`'s required contexts are
  `[rustfmt, clippy, test (ubuntu/macos/windows × stable), conformance (spec fixtures),
  MSRV (1.86), docs, cargo-deny, cargo-vet]` — `semver-tool-health` is absent, so it reddens the
  run but does **not** block merge. The criterion is met literally; its intent needs a
  branch-protection update.
- **Alternatives:** adding it to required checks via `gh api .../branches/main/protection`
  — rejected here because repo-settings changes are outside the standing
  commit/PR/merge/publish authorization, and a required check that has never run green once
  would block every PR the moment it is added.
- **Blast radius if wrong:** a future cargo-semver-checks outage reddens CI visibly but someone
  could still merge past it — strictly better than today (silent false-green), strictly worse
  than a hard gate. Reversible: one branch-protection edit, best made after the job has a green
  history.
- **Status:** UNCONFIRMED

## Unpublished-crate baseline behaviour in cargo-semver-checks is untested
- **Plan:** plans/issues-206-208-bindings-registry-release-gate.md (Phase 1)
- **Assumed:** a workspace crate with no crates.io baseline (newly added, never published) is
  skipped by cargo-semver-checks rather than treated as an error.
- **Chose:** ship without covering this branch. Not triggered by anything in this plan — Phases
  2-7 add public API to existing crates, they do not add a new crate.
- **Alternatives:** constructing a throwaway unpublished crate to observe the exit code —
  rejected as disproportionate for a path this plan cannot reach.
- **Blast radius if wrong:** if such a crate exits 101 rather than 0, the `semver-tool-health`
  job hard-reds on the PR that introduces it, with a misleading "tool error" diagnosis. Caught
  immediately (first CI run on that PR), fixed by an exclusion or an exit-code carve-out.
- **Status:** UNCONFIRMED
