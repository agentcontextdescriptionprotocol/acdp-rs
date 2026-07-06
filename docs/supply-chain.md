# Supply-chain security

**Crate**: `acdp` &nbsp;|&nbsp; **Scope**: build provenance, action pinning, dependency vetting

`acdp` is a cryptographic-protocol SDK: the code that verifies producer
signatures and enforces the SSRF/HTTPS defenses is exactly the code an attacker
would most like to tamper with between our CI and your `Cargo.lock` /
`node_modules` / site-packages. This page documents the controls that make a
released artifact **traceable back to a specific commit built by this repo's
CI**, how *you* verify that, and how contributors keep the dependency graph
vetted.

Four layers, each independently verifiable:

| Layer | Control | Where |
|---|---|---|
| Released artifacts | Build provenance / signed attestations | npm `--provenance`, PyPI PEP 740, GitHub `attest-build-provenance` |
| CI itself | Every third-party Action pinned to a commit SHA | `.github/workflows/*` |
| Dependency graph | `cargo vet` — every dep audited or explicitly exempted (BLOCKING CI gate) | `supply-chain/` |
| Advisories & licenses | `cargo deny` + `cargo audit` | `deny.toml`, CI |

---

## 1. Verifying a released artifact came from this repo

Every publishable artifact this repo produces carries provenance minted from the
release workflow's OIDC identity. The mechanism differs per ecosystem.

### npm (`acdp` Node SDK)

Published by [`bindings-release.yml`](../.github/workflows/bindings-release.yml)
with **npm provenance** (`npm publish --provenance`, plus
`NPM_CONFIG_PROVENANCE=true` for the `napi prepublish` platform packages). The
publish job holds `id-token: write`, and npm mints a signed provenance
statement (Sigstore-backed) linking the tarball to this repo, workflow, and
commit.

```bash
# The registry shows a "Provenance" panel on the package page; from the CLI:
npm view acdp --json | jq '.dist.attestations'      # provenance present?
npm audit signatures                                  # verify install-time
```

On npm's website the package page displays a green **"Built and signed on GitHub
Actions"** badge with the source repo, commit, and workflow file.

> First-release note: npm provenance requires **npm ≥ 9.5** (the release runner
> uses Node 20 → npm ≥ 10, so this is satisfied) and a public package. On the
> *first* provenance-enabled publish, confirm the badge appears on
> `https://www.npmjs.com/package/acdp` and that `npm audit signatures` passes
> for a fresh install — this is the one step that can only be checked against
> the live registry.

### PyPI (`acdp` Python SDK)

Published by [`acdp-py-release.yml`](../.github/workflows/acdp-py-release.yml)
via `pypa/gh-action-pypi-publish` with `attestations: true` and **PyPI Trusted
Publishing** (OIDC, no long-lived token). Each wheel/sdist gets a **PEP 740**
digital attestation uploaded alongside it.

- On the PyPI release page, each file shows a **"Verified details / provenance"**
  section naming the GitHub repo + workflow.
- Programmatically, the attestations are served from PyPI's integrity API
  (`https://pypi.org/integrity/acdp/<version>/<filename>/provenance`).

> First-release note: PyPI attestations are default-on when `id-token: write`
> is present; we set `attestations: true` explicitly so the guarantee is visible
> and cannot silently regress. On the first attested release, confirm the
> provenance section renders on the PyPI file listing.

### GitHub build-provenance (raw wheels, sdist, `.node` prebuilts)

Independently of the registry mechanisms above, the build jobs attest every
**raw binary artifact** before it is uploaded, using
`actions/attest-build-provenance`. This produces a signed SLSA provenance
statement (stored via GitHub's attestations API) binding the artifact's SHA-256
to this repo + workflow + commit. Belt and suspenders: it covers the artifact
even if you obtained it outside the registry.

```bash
# Verify a downloaded wheel / sdist / .node against this repo:
gh attestation verify ./acdp-0.3.0-cp39-abi3-manylinux_2_17_x86_64.whl \
    --repo agentcontextdistributionprotocol/acdp-rs

gh attestation verify ./acdp.linux-x64-gnu.node \
    --repo agentcontextdistributionprotocol/acdp-rs
```

A pass prints the workflow, commit SHA, and signer identity. A mismatch (or an
artifact never built here) fails closed.

### crates.io (`acdp` and the workspace crates)

`acdp` is published to crates.io by
[`release-plz.yml`](../.github/workflows/release-plz.yml), which drives
`cargo publish`. **Status: documented follow-up, deliberately conservative.**

- `cargo publish` today has no build-provenance / attestation mechanism
  comparable to npm `--provenance` or PyPI PEP 740.
- crates.io **Trusted Publishing** (OIDC, no long-lived `CARGO_REGISTRY_TOKEN`)
  is being rolled out upstream. We have **not** altered release-plz's
  version/publish flow to adopt it yet — doing so touches the release
  machinery and is out of scope for a conservative supply-chain pass.
- Migration plan (tracked in the workflow header comment): when
  `release-plz-action` documents an `id-token: write` OIDC path, add
  `permissions: id-token: write` to the release-plz **job only** and drop
  `CARGO_REGISTRY_TOKEN`.

Until then, crate integrity rests on crates.io's own immutable-version guarantee
plus the `Cargo.lock` checksums, and provenance for the *contents* is available
via the GitHub build-provenance attestations above (same commits, same CI).

---

## 2. GitHub Actions pinning policy

**Policy (one consistent rule, applied repo-wide):**

- **Third-party Actions are pinned to a full 40-character commit SHA**, with a
  trailing `# vX.Y.Z` (or ref-name) comment for human readability. A moving tag
  like `@v2` is a mutable pointer the upstream owner can re-target at any commit;
  a SHA is immutable. This is the [OpenSSF Scorecard "Pinned-Dependencies"
  control](https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies).
- **First-party `actions/*` Actions MAY stay on a major version tag** (`@v4`,
  `@v5`). These are maintained by GitHub itself under the same trust boundary as
  the runner; pinning them buys little and costs a lot of churn. This covers
  `actions/checkout`, `actions/setup-node`, `actions/setup-python`,
  `actions/upload-artifact`, `actions/download-artifact`, and
  `actions/attest-build-provenance`.

### Special cases (ref name doubles as configuration)

Two upstreams use the *ref name* to select behavior. Pinning them to a SHA
**preserves that behavior**, because each behavior lives on its own branch/tag
whose `action.yml` bakes in the default:

- **`dtolnay/rust-toolchain@stable|nightly|1.86.0`** — the `stable` branch's
  `action.yml` defaults `toolchain: stable`, `nightly` → `nightly`, and the
  `1.86.0` branch hard-codes `toolchain: 1.86.0`. We pin each ref to *its own*
  branch SHA, so no explicit `toolchain:` input is needed and the toolchain
  selection is unchanged. (The `@master` use already passes `toolchain:`
  explicitly via the matrix.)
- **`taiki-e/install-action@cargo-deny|cargo-fuzz|…`** — each tool shorthand is a
  tag whose `action.yml` defaults `tool:` to that tool. We pin each to its
  shorthand-tag SHA; the `tool` default is preserved, no `with: tool:` needed.

The trailing comment on these records the ref name (`# stable`, `# cargo-deny`)
rather than a semver, because that is what identifies the pinned behavior.

### Pinned-action inventory

| Action | Pinned SHA | Version / ref |
|---|---|---|
| `Swatinem/rust-cache` | `e18b497796c12c097a38f9edb9d0641fb99eee32` | v2.9.1 |
| `dtolnay/rust-toolchain` (stable) | `4be7066ada62dd38de10e7b70166bc74ed198c30` | stable branch |
| `dtolnay/rust-toolchain` (nightly) | `efcb852328a9f50117170cc43094fb6f09eaf1ae` | nightly branch |
| `dtolnay/rust-toolchain` (master) | `fa04a1451ff1842e2626ccb99004d0195b455a88` | master branch |
| `dtolnay/rust-toolchain` (1.86.0) | `2767295e193a2ee92d23c1ff586f596cb6d94a7a` | 1.86.0 branch |
| `taiki-e/install-action` (cargo-deny) | `0751bff5da373f43f04fdc57a72795931a822bd7` | cargo-deny tag |
| `taiki-e/install-action` (cargo-semver-checks) | `28a94b8721026748876cf52d0a3048ff9e4c9769` | cargo-semver-checks tag |
| `taiki-e/install-action` (cargo-llvm-cov) | `7c1105379b6217809b9ed26c163a46c65c7a528f` | cargo-llvm-cov tag |
| `taiki-e/install-action` (cargo-fuzz) | `82fc405565b9cf90abfe700ba43b4751ce2fe422` | cargo-fuzz tag |
| `taiki-e/install-action` (cargo-vet) | `c0ae9b92c15529ec87e792a1233f3f4a6c726bfa` | cargo-vet tag |
| `mlugg/setup-zig` | `53fc45b17fe98b52f92ee5ea08ff48a85a3e7eb7` | v1.2.2 |
| `PyO3/maturin-action` | `e83996d129638aa358a18fbd1dfb82f0b0fb5d3b` | v1.51.0 |
| `rustsec/audit-check` | `69366f33c96575abad1ee0dba8212993eecbe998` | v2.0.0 |
| `pypa/gh-action-pypi-publish` | `cef221092ed1bacb1cc03d23a2d87d1d172e277b` | release/v1 (v1.14.0) |
| `peter-evans/repository-dispatch` | `28959ce8df70de7be546dd1250a005dd32156697` | v4.0.1 |
| `MarcoIeni/release-plz-action` | `e8792575c7f2366cf6ff3ccc33ead9ace5b691c7` | v0.5.130 |
| `codecov/codecov-action` | `b9fd7d16f6d7d1b5d2bec1a2887e65ceed900238` | v4 |

**First-party (major tag by policy):** `actions/checkout@v4`,
`actions/setup-node@v4`, `actions/setup-python@v5`, `actions/upload-artifact@v4`,
`actions/download-artifact@v4`, `actions/attest-build-provenance@v2`.

### Updating a pinned Action

Resolve the new SHA from the tag and update both the SHA and the comment:

```bash
gh api repos/OWNER/REPO/commits/TAG --jq .sha
# then edit `- uses: OWNER/REPO@<new-sha> # TAG` in the workflow
```

Dependabot (`.github/dependabot.yml`, if enabled for `github-actions`) will
open PRs that bump the SHA and keep the comment in sync.

---

## 3. Dependency vetting with `cargo vet`

Every third-party crate in the **locked** dependency graph must be covered by
one of: (a) a local audit we performed, (b) an audit imported from a trusted
external set, or (c) an explicit exemption. This is enforced by a **BLOCKING**
CI job — a new or version-bumped dependency that is not yet covered fails the
build.

```bash
cargo vet --locked        # what CI runs; must be green
```

Config lives under [`supply-chain/`](../supply-chain/):

| File | Role |
|---|---|
| `config.toml` | Trusted import sources, per-crate policy, and the `exemptions` block (the vetted-but-not-yet-audited long tail). |
| `audits.toml` | **Our own** audit certifications (the crypto-critical set). |
| `imports.lock` | Frozen snapshot of the imported audit sets — committed so `--locked` is reproducible. |

### Imported audit sets

We import the shared audit sets from three organizations that publish their
`cargo vet` audits publicly:

- **Mozilla** — `https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml`
- **Google** — `https://raw.githubusercontent.com/google/supply-chain/main/audits.toml`
- **Bytecode Alliance** — `https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml`

These cover a large fraction of the common ecosystem (serde, tokio, hyper,
rustls internals, …) so we don't re-audit what better-resourced teams already
have. Refresh them with `cargo vet` (updates `imports.lock`).

### The crypto-critical set — audited by us

The crates that implement or underpin ACDP's signature and TLS security were
inspected and **certified locally** (`safe-to-deploy`), not merely exempted.
The inspection criteria for each: canonical upstream source, latest compatible
release, and no open RUSTSEC advisory (`cargo audit`, verified 2026-07-05). See
`supply-chain/audits.toml` for the full per-crate notes.

| Crate | Version | Upstream | Role in ACDP |
|---|---|---|---|
| `ed25519-dalek` | 2.2.0 | dalek-cryptography | Mandatory signature primitive (RFC-ACDP-0002) |
| `curve25519-dalek` | 4.1.3 | dalek-cryptography | Curve arithmetic under ed25519 (≥4.1.3 fixes the timing advisory) |
| `signature` | 2.2.0 | RustCrypto | Signature traits |
| `sha2` | 0.10.9 | RustCrypto | `content_hash` / `lineage_id` (RFC-ACDP-0001 §5.7) |
| `zeroize` | 1.8.2 | RustCrypto | Secret-key zeroing (`SigningKey` `ZeroizeOnDrop`) |
| `subtle` | 2.6.1 | dalek-cryptography | Constant-time primitives |
| `p256` | 0.13.2 | RustCrypto | P-256 verification-method support |
| `ecdsa` | 0.16.9 | RustCrypto | Generic ECDSA under p256 |
| `elliptic-curve` | 0.13.8 | RustCrypto | Curve trait framework |
| `rustls` | 0.23.40 | rustls | HTTPS transport (RFC-ACDP-0008) |
| `ring` | 0.17.14 | briansmith | Default rustls crypto provider |

### Contributor workflow

**When you add or bump a dependency**, `cargo vet --locked` will fail locally
and in CI until it's covered. Two paths:

- **Certify it** (preferred for anything security-sensitive — crypto, TLS,
  parsing untrusted input, `unsafe`). Actually read the source of that version,
  then:

  ```bash
  cargo vet certify <crate> <version> \
      --criteria safe-to-deploy \
      --who "Your Name <you@example.com>" \
      --notes "Reviewed: <what you checked — unsafe, I/O, build.rs, provenance>."
  ```

  `safe-to-deploy` = safe to ship to users; `safe-to-run` = safe to run in
  dev/CI only (test-only deps). `certify` auto-removes any now-redundant
  exemption.

- **Exempt it** (acceptable for the low-risk long tail — leaf utility crates,
  build-only helpers) when a full audit isn't warranted yet:

  ```bash
  cargo vet add-exemption <crate> <version>   # or edit config.toml's exemptions
  ```

Then run `cargo vet --locked` to confirm green and commit the `supply-chain/`
changes with your PR. Run `cargo vet prune` occasionally to drop exemptions that
an imported audit now covers.

**Who audits.** The crypto-critical set is audited by the crate maintainers and
must stay `safe-to-deploy` with real inspection notes — treat a change there as
a security review, not a rubber stamp. The long-tail exemptions are a
maintenance backlog: prefer converting them to real audits (ours or imported)
over time. First-party workspace crates (`acdp`, `acdp-*`) are configured
`audit-as-crates-io = false` — they're our own code and need no audit or
exemption, and their version bumps therefore never trip the gate.

---

## 4. Advisory and license posture (`cargo deny` + `cargo audit`)

These run alongside `cargo vet` in CI and cover the axes `vet` does not:

- **`cargo deny check`** ([`deny.toml`](../deny.toml)) — advisories, license
  allow-list, banned/duplicate crates, and source registries. Blocking.
- **`cargo audit`** (`rustsec/audit-check`) — cross-checks `Cargo.lock` against
  the RustSec advisory database on every push/PR. Blocking.

**Known allowlisted advisory:** `RUSTSEC-2025-0134` (`rustls-pemfile`
unmaintained, folded into `rustls-pki-types` upstream). It is pulled in only
transitively by `axum-server`'s `tls-rustls` feature, which is used solely in
the **dev-dependency test harness** and never propagates to consumers. The
ignore is mirrored in both `deny.toml` and the `cargo audit` CI step. As of
2026-07-05 this is the only advisory in the tree, and none of the
crypto-critical crates carry one.

Together: **`vet`** answers "did a human look at this code?", **`deny`/`audit`**
answer "is there a known-bad advisory or license here?", and the **provenance +
pinning** layers answer "did this actually come from our CI?".
