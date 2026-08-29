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
