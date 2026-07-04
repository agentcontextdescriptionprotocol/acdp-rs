# acdp fuzz harnesses

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets for
the ACDP crates. This directory is a **standalone Cargo workspace** (its
`Cargo.toml` carries its own `[workspace]` table, like `bindings/acdp-py` and
`bindings/acdp-node`), so the root workspace, its lockfile, MSRV, and
release-plz surface are unaffected. All library crates are pulled in with
`default-features = false` — no reqwest/tokio; only the pure parsing,
canonicalization, and policy-classification code is fuzzed.

## Targets

| Target | Input | Property |
|---|---|---|
| `fuzz_jcs` | arbitrary `serde_json::Value` (depth ≤ 20, containers ≤ 8) | `acdp_jcs::try_canonicalize_value` / `canonicalize_value` never panic for depth-bounded input, agree with each other, and canonicalization is idempotent (parse canonical bytes → canonicalize again → identical bytes) |
| `fuzz_wire` | raw bytes | `serde_json::from_slice` into `PublishRequest`, `PublishResponse`, `FullContext`, `Body`, `CapabilitiesDocument`, `SearchResponse`, `WireError`, `WireErrorBody` never panics; anything that parses re-serializes |
| `fuzz_did_doc` | raw bytes | `DidDocument` deserialization + fragment lookup / assertion-method authorization / Ed25519 & P-256 key extraction (the `WebResolver` response pipeline) never panic; `did:web` string helpers never panic on UTF-8 input |
| `fuzz_ssrf` | arbitrary host/path/port strings + IP octets | `SsrfPolicy` `classify_url` / `classify_ip` / `classify_redirect` and `same_fetch_authority` never panic; `169.254.169.254` and `127.0.0.1` are **never** classified safe (as IPs, IPv4-mapped IPv6, or URL literals) under any fuzzer-chosen `allow_http` / `reject_ip_literals` combination |

All four planned targets shipped — no API was too private to reach.

## Running locally

Requires nightly and cargo-fuzz:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked

# From the repository root:
cargo +nightly fuzz build                       # build all targets
cargo +nightly fuzz run fuzz_jcs -- -max_total_time=60
cargo +nightly fuzz list
```

Seed corpora live in `corpus/<target>/`; cargo-fuzz picks them up
automatically and grows the corpus in place (new entries are local only —
commit interesting ones deliberately). Crash artifacts land in
`artifacts/<target>/`.

CI (`.github/workflows/fuzz.yml`) runs every target for 5 minutes weekly and
on manual dispatch, and gate-checks `cargo fuzz build` on pull requests that
touch this directory.

## Notes / invariants encoded here

- `fuzz_jcs` keeps generated values well under the crate's internal
  256-level recursion ceiling, so the *infallible* `canonicalize_value` is
  also asserted panic-free; inputs past the ceiling are the documented
  error domain of `try_canonicalize_value`, not a panic path.
- Idempotence of JCS depends on serde_json's `float_roundtrip` feature,
  which this package enables to match the library crates.
- `fuzz_ssrf` never sets `allow_loopback_resolved` (the `#[doc(hidden)]`
  test-only escape hatch), so loopback rejection is asserted as a hard
  invariant alongside IMDS rejection, which no configuration may permit.
