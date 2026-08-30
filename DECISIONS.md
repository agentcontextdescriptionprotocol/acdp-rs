# DECISIONS

Reconciliation log for `plans/rs-wave1-conformance-hardening.md` (RS-1, RS-2, RS-10). Each
entry: the original assumption, the recommending agent's analysis, the user's verdict, and
the resulting status.

## 2026-08-28 — bindings/acdp-wasm: pre-existing break discovered, excluded from new advisory job

**Assumption:** `bindings/acdp-wasm` was found completely broken on `main` (unrelated to
this PR — `getrandom` version/feature mismatch making `cargo metadata` fail outright,
introduced by commit `d511e03`). Executor's original response: exclude it from the new
`bindings-deny` job's matrix, document why, don't fix here.

**Recommendation (Fable):** Keep the exclusion in the PR as originally shipped, but the
guessed one-line fix (`js`→`wasm_js`) was actually wrong — deeper investigation revealed
the manifest deliberately carries two `getrandom` majors (0.2 for `rand_core`/OsRng
needing feature `js`; 0.4 for `uuid` needing `wasm_js`, already correctly aliased as
`getrandom_wasm`). The real fix is reverting the unaliased entry to `version = "0.2"`.
Recommended: don't fix in this PR (different root cause, deserves its own review); file a
tracked GitHub issue with the corrected diagnosis instead.

**User verdict:** Fix it now in this PR.

**What happened:** Reverted `bindings/acdp-wasm/Cargo.toml`'s unaliased `getrandom` entry
to `version = "0.2", features = ["js"]`. Discovered during the fix that a Dependabot
`ignore` rule already existed for exactly this class of regression (added by PR #129,
after a first occurrence via PR #122) — no new ignore rule was needed, only the revert.
Traced the full incident history via `gh pr view`/`gh run view`: PR #133 (a Dependabot
major-update PR) had its scan run start before PR #129's ignore rule merged, created the
PR ~3 minutes after that merge, and was auto-merged ~5 minutes later *despite its own
`acdp-wasm` CI check showing FAILURE 28 seconds before the merge* — a real auto-merge
governance gap (not gated on every `bindings.yml` job), documented in a `.github/
dependabot.yml` comment but explicitly NOT fixed here (scope: dependency fix only, not
CI-governance changes). Added `bindings/acdp-wasm` to the `bindings-deny` job's matrix and
the `Makefile`'s `audit-bindings` target now that `cargo metadata` resolves. Verified via a
dedicated Phase 4 + Opus verification gate: `cargo metadata`, native test (golden vectors),
`cargo build --target wasm32-unknown-unknown` (debug+release), `wasm-pack test --node`
(golden vectors), and `cargo deny check advisories` all pass; confirmed reverting to
getrandom 0.2 does not reintroduce any known RUSTSEC advisory (zero advisories exist
against any getrandom version in the local advisory DB).

**Status:** NEEDS-CHANGE → **applied and re-verified, DONE.** Not a merge blocker — the fix
landed as this PR's Phase 4.

## 2026-08-28 — pyo3 version: bumped to 0.29 instead of the planned 0.24

**Assumption:** Plan specified bumping `bindings/acdp-py`'s pyo3 to the `0.24` line to
clear RUSTSEC-2025-0020 while staying below a believed `abi3-py39`-dropping boundary at
0.26. Mid-implementation, `cargo deny check advisories` against 0.24.2 revealed two
additional 2026 RUSTSEC advisories (RUSTSEC-2026-0176, introduced at 0.24.0 and only fixed
at 0.29.0; RUSTSEC-2026-0177, unfixed at both 0.22 and 0.24) — landing 0.24 as literally
planned would not have achieved this PR's own "advisory scan green" criterion. Executor
bumped further to 0.29 instead, verifying `abi3-py39` still works there (no Python-matrix
widening needed), the migration was minimal (2 call-site renames), and all 172 tests pass
unmodified.

**Recommendation (Fable):** Confirm — 0.29 is the minimum version clearing all four
relevant advisories (no safer intermediate exists), MSRV is unaffected (0.29.2 needs
1.83, repo is 1.86), the vulnerable APIs aren't used anywhere in this binding's code, and
landing at the current head makes the *next* bump smaller, not larger. Two required
follow-ups: add a `bindings/acdp-py/CHANGELOG.md` entry (none existed for this bump), and
state the 0.24→0.29 deviation explicitly in the PR description.

**User verdict:** Confirm + do both follow-ups.

**What happened:** Added an `## Unreleased` / `### Security` section to
`bindings/acdp-py/CHANGELOG.md` (the file previously had no "unreleased" convention —
introduced one, consistent with the root `CHANGELOG.md`'s `[Unreleased]` pattern)
documenting the pyo3 bump and all three RUSTSEC advisories it clears. The PR description
(written at `/ship` time) states the deviation explicitly per this decision.

**Status:** CONFIRMED (2026-08-28)

## 2026-08-28 — Four lower-stakes design choices

Batched per the user's explicit choice to confirm all four together, after independent
Opus review of each against the actual current code (not just the original plan text):

1. **Pin SHA for RS-1/RS-2 local verification** (`f5b66b8f86f48ba16f79bba95eb246d6acb43989`,
   matching `ci.yml:75`, not live spec `main` HEAD) — recommendation: confirm, close
   permanently (no code artifact encodes this choice; it only affected local testing).
2. **RS-2's static `KNOWN_FAMILIES`/dynamic-`profiles.json` bucketing split** — recommendation:
   confirm; a fully-dynamic design would defeat the forcing-function purpose. Noted (not
   actioned, deferred per the plan's own Long-term posture): nothing yet asserts a
   `KNOWN_FAMILIES` entry still has real test coverage, so the list could silently drift to
   "listed but untested" over time — a future tightening, not a current gap.
3. **Reusing root `deny.toml` for bindings advisory scanning** — recommendation: confirm;
   sounder than originally assumed, since `check advisories` doesn't even evaluate the
   `[licenses]`/`[bans]` sections the reuse concern was originally about.
4. **Leaving binding lockfiles gitignored** (fresh-resolution scanning, not pinned) —
   recommendation: confirm; for a vulnerability gate specifically, auditing what a
   downstream consumer actually gets from the published manifest is arguably the *better*
   target population, not merely an accepted tradeoff.

**User verdict:** Confirm all four, no changes.

**Status:** CONFIRMED (2026-08-28) — all four, no code changes.

## anchors supersede-settability (RS-8 binding follow-up)

- **Plan:** plans/rs8-bindings-anchors.md
- **Assumption:** `anchors` exposed on both publish and supersede in both bindings,
  mirroring `data_refs` (not `derived_from`'s publish-only treatment).
- **Recommendation (fresh Opus subagent):** confirm as-is. The decisive point: since
  `Producer::new_version_from` (fixed in this same branch) now carries `anchors`
  forward on supersede, making anchors publish-only would make it an unreachable,
  permanently-frozen field after v1 — worse than the chosen option. Nothing in the core
  validation, wire schema, or RFC-ACDP-0016 framing suggests lineage-style (immutable)
  treatment; anchors are ordinary ProducerContent with no version coupling.
- **User verdict:** Confirm.
- **Status:** CONFIRMED (2026-08-30) — no code change from the as-implemented state.

Two side findings surfaced during this recommendation, both acted on before shipping
(not deferred):
1. **`anchors` had no way to be cleared on supersede** from either binding — omitting it
   carries the previous version's anchors forward forever (correct default), but there
   was no explicit "clear" signal, unlike `data_refs` (a plain `Vec`, where `[]` is a
   legal wire value). User verdict: fix now. See the `clear_anchors` addition
   (`RequestBuilder::clear_anchors`, plus `clear_anchors`/`clearAnchors` supersede-only
   binding parameters) landed in the same PR as this plan's phases.
2. **Unrelated pre-existing bug**: `BODY_FIELD_NAMES` in
   `crates/acdp-server/src/registry/lifecycle.rs` is missing `"anchors"` (introduced by
   RS-8/PR #169, not this branch) — a lifecycle envelope carrying an `anchors` member
   gets a generic `schema_violation` instead of the correct `immutable_field`. User
   verdict: fix now, same PR.

## 2026-08-30 — RS-11: `ACDP_VERSION` default bump (constant bump vs. feature-derived)

**Assumption:** `crates/acdp-primitives/src/lib.rs:51`'s default `ACDP_VERSION` constant
was bumped from `"0.2.0"` to `"0.4.0"` (PR #164, merged 2026-08-28) — every producer that
builds a `PublishRequest` without an explicit `.acdp_version(...)` now stamps `0.4.0`
instead of `0.2.0`. The plan (RS-11, Wave 4) left the mechanism open and flagged this as
the item most warranting deliberate human review before/at the next crate release, since
it changes wire output ecosystem-wide, not just in this repo.

**Analysis at reconciliation time:** the change has already shipped in two releases
(0.8.2 on 2026-08-28, 0.8.3 on 2026-08-30) with no reported breakage. No golden vector
(`sig-001`, `sig-003`) regressed — both pin an explicit version override. No
`acdp-validation` rule imposes a new required field on a producer at 0.3.0/0.4.0. The
only real exposure is downstream consumers (`acdp-playground`, `acdp-control-plane`, or
any other sibling repo relying on the un-pinned default) picking up `0.4.0`-stamped
bodies on their next crate bump — reverting now would itself be a second wire-behavior
change, not a neutral no-op, so standing pat is the lower-churn option.

**User verdict:** Confirm as-is.

**Status:** CONFIRMED (2026-08-30) — no code change; `ASSUMPTIONS.md` entry updated to
CONFIRMED.
