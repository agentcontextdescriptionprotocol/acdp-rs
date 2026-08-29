# Release runbook — binding tags & publishes

**Human-assisted (RS-6).** This is a runbook, not automation: every step here needs
rights a CI session doesn't have (pushing tags, pausing/resuming workflows, PyPI/npm
publish credentials). No step in this document has been executed by an agent — verify
the "current state" section against `git tag`, `npm view`, and PyPI before acting, since
it can drift the moment someone else runs a step.

## Why this exists

The three language-binding release workflows (`bindings-release.yml` for
`acdp-node`, `acdp-py-release.yml`, `acdp-wasm-release.yml`) are **tag-triggered**:
pushing a tag matching `acdp-node-v*` / `acdp-py-v*` / `acdp-wasm-v*` runs the full
build-and-publish job unconditionally (`if: github.event_name == 'push' || !inputs.dry_run`
— the `dry_run` input only guards a manual `workflow_dispatch`, never a tag push). Some
past releases were published via manual `workflow_dispatch` **without** a corresponding
tag ever being pushed, so `git tag` now understates what's actually live on npm/PyPI.

**⚠ H11:** pushing a *retroactive* tag for a version that is already published will
refire the matching workflow and attempt to publish that exact version again — npm/PyPI
reject a republish of an existing version, so the run fails loudly (a red CI run, no
data corruption) rather than silently succeeding or overwriting anything. Loud-but-safe
is still not free: it wastes a CI run, pages whoever watches Actions, and (on the node
workflow specifically) sits *before* the `acdp-released` dispatch step to
`acdp-control-plane`, which only fires on the steps after a successful publish — so a
failed retroactive-tag run does **not** spuriously trigger a downstream auto-bump PR
there. Still, don't rely on "it'll just fail safely" as the plan — pick one of the three
options below deliberately.

## Current state (verified 2026-08-29 — re-check before acting)

The sibling plan (`agentcontextdistributionprotocol/plans/siblings/acdp-rs.md`, RS-6)
was written 2026-08-28 and states PyPI is "still 0.7.0." That's now stale — live
PyPI/npm state as of this runbook is materially ahead of what the plan assumed:

| Artifact | Last **tagged** release | Published versions (npm/PyPI, ground truth) | Local manifest version |
|---|---|---|---|
| `acdp` crate (this repo) | `acdp-v0.8.1` | — | `0.8.1` (`Cargo.toml` workspace version) |
| `acdp-node` (npm `@agentcontextdistributionprotocol/acdp`) | `acdp-node-v0.7.0` | **0.7.0, 0.8.0, 0.8.1** — 0.8.0 and 0.8.1 both published tag-less via `workflow_dispatch` on 2026-07-10 (runs at commits `c2a89032` and `c4c9be8d`) | `0.8.0` (`bindings/acdp-node/package.json`, stale relative to what's already published) |
| `acdp-py` (PyPI `acdp`) | `acdp-py-v0.7.0` | **0.7.0, 0.8.0, 0.8.1** — 0.8.0 and 0.8.1 both published tag-less via `workflow_dispatch` on 2026-07-10, same two commits as node | `0.8.0` (`bindings/acdp-py/Cargo.toml`, stale) |
| `acdp-wasm` (npm `@agentcontextdistributionprotocol/acdp-wasm`) | `acdp-wasm-v0.7.0` | **0.7.0, 0.8.0** — the 0.8.0 `workflow_dispatch` at commit `be72ca24` succeeded; a same-day follow-up attempt at 0.8.1 (commit `c4c9be8d`, run `29129059112`) **failed** during `cargo metadata` on a `getrandom` version conflict (`acdp-wasm` required `getrandom ^0.4` with feature `js`, which only exists on `0.2.x`) — that bug was the dual-major `getrandom` pin mixup fixed later by PR #153 (commit `c55eacd`, 2026-08-28). **0.8.1 was never published for wasm.** | `0.8.0` (`bindings/acdp-wasm/Cargo.toml`, matches the last successful publish) |

Re-run these checks before executing anything below — another session or the bot may
have moved the state again:

```bash
git tag -l "acdp-node-v*" "acdp-py-v*" "acdp-wasm-v*" | sort -V
npm view @agentcontextdistributionprotocol/acdp versions --json
npm view @agentcontextdistributionprotocol/acdp-wasm versions --json
curl -s https://pypi.org/pypi/acdp/json | python3 -c "import json,sys; print(sorted(json.load(sys.stdin)['releases']))"
```

## The plan

Target: all three bindings published **and tagged** at the crate family version,
`0.8.1` — matching the accept criterion ("node/py/wasm published at the family version
with matching git tags"). Node and py content is already there (published, just
untagged); wasm genuinely needs one more publish.

### Step 0 — pause the tag-triggered workflows

Do this before pushing *any* tag in this runbook, retroactive or new — it's what makes
every following step safe regardless of which option below you pick for the retroactive
markers:

```bash
gh workflow disable bindings-release.yml
gh workflow disable acdp-py-release.yml
gh workflow disable acdp-wasm-release.yml
```

(`gh workflow enable <name>` reverses this — needed again at the end of Step 2.)

### Step 1 — retroactive markers for what's already published, tag-less

With the workflows paused, tags can be pushed safely — nothing will fire. Point each
tag at the exact commit that workflow run actually published from (not current `HEAD`),
so the tag is historically accurate:

```bash
git tag acdp-node-v0.8.0 c2a89032a5b706d95efd1e5e69e1f7df22aa6084
git tag acdp-node-v0.8.1 c4c9be8d68dda2842b6a9b06efc2157d79090198
git tag acdp-py-v0.8.0   c2a89032a5b706d95efd1e5e69e1f7df22aa6084
git tag acdp-py-v0.8.1   c4c9be8d68dda2842b6a9b06efc2157d79090198
git tag acdp-wasm-v0.8.0 be72ca24fe7d0246b1fe132ef10c0eaed7ecfc0b
git push origin acdp-node-v0.8.0 acdp-node-v0.8.1 acdp-py-v0.8.0 acdp-py-v0.8.1 acdp-wasm-v0.8.0
```

Do **not** tag `acdp-wasm-v0.8.1` here — it was never actually published (see the table
above), so tagging it would be a false historical record. It gets a real, live tag in
Step 2 instead.

This is "tag with workflows paused" (H11 option 1) rather than non-triggering tag names:
it keeps the permanent tag names consistent with the live ones future releases will use
(`acdp-node-v0.8.0`, not some `retroactive/…` variant that `git describe`/tooling won't
recognize), at the cost of the two-step pause/resume — a fine trade for a one-time
backfill.

### Step 2 — the real, live wasm 0.8.1 publish

This is the one artifact that genuinely isn't at the family version yet.

1. Confirm the `getrandom` fix from PR #153 is present on the commit you're releasing
   from (it is, as of `main` post-2026-08-28) — spot-check:
   ```bash
   grep -n "getrandom" bindings/acdp-wasm/Cargo.toml
   # expect: getrandom = { version = "0.2", features = ["js"] }
   #         getrandom_wasm = { package = "getrandom", version = "0.4", features = ["wasm_js"] }
   ```
2. Bump `bindings/acdp-wasm/Cargo.toml`'s `version` to `0.8.1` (the workflow re-stamps
   this from the tag name at build time regardless, but committing it keeps the working
   tree honest — open a small PR for this one-line bump, same as any other code change).
3. Re-enable just the wasm workflow and do a dry run first, to catch any other drift
   before spending a real publish attempt:
   ```bash
   gh workflow enable acdp-wasm-release.yml
   gh workflow run acdp-wasm-release.yml -f version=0.8.1 -f dry_run=true
   # watch it green, then:
   git tag acdp-wasm-v0.8.1 <the commit the dry run built from>
   git push origin acdp-wasm-v0.8.1
   ```
   The pushed tag triggers the real (non-dry-run) publish.
4. Re-enable the other two workflows now that no more retroactive tags are pending:
   ```bash
   gh workflow enable bindings-release.yml
   gh workflow enable acdp-py-release.yml
   ```

### Step 3 — local manifest hygiene (optional, low-risk cleanup)

`bindings/acdp-node/package.json` and `bindings/acdp-py/Cargo.toml` still declare
`0.8.0` locally even though `0.8.1` is already published — harmless (the release
workflows stamp the version from the tag at build time, not from the committed
manifest) but confusing to a reader. Bump both to `0.8.1` in a normal PR, no tag
implications either way.

### Step 4 — unblocks

Once this runbook's tags exist, per `00-overview.md` §3: `PG-1` (PyPI→family version,
already effectively true, just needed the tag) and `UI-1` (wasm bump + tagged release)
are unblocked, and `CI-3` (tag-triggered publish = propagation head) can record this as
the policy going forward.

## Coordination note for SPEC-11 (`docs/version-matrix.md` refresh, spec repo)

This is a **read**, not an edit — `docs/version-matrix.md` lives in the spec repo
(`agentcontextdistributionprotocol/agentcontextdistributionprotocol`), not here; per this
family's cross-repo convention, the spec-repo session doing SPEC-11 should pull the
following facts from this runbook rather than this repo editing that file directly:

- `acdp` (Rust, this repo): crate `0.8.1`, tags `acdp-v0.8.1` etc. — already current.
- `acdp-node` / `acdp-py` / `acdp-wasm`: once this runbook's Steps 1–2 are executed,
  all three sit at `0.8.1` with matching git tags (`acdp-node-v0.8.1`, `acdp-py-v0.8.1`,
  `acdp-wasm-v0.8.1`) and their published registries (npm, npm, PyPI respectively).
- The RFC coverage is identical across all four artifacts (RFC-ACDP-0001 through 0015,
  0009 reserved) — `acdp-wasm` is verification-only (no producer/signing surface), the
  other three implement both sides.
- If Step 2 hasn't run yet when SPEC-11 executes, say so explicitly in the version
  matrix rather than asserting `0.8.1` for wasm — check `npm view
  @agentcontextdistributionprotocol/acdp-wasm versions` first.
