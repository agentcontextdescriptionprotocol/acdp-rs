# Contributing to acdp-rs

Thanks for your interest in contributing! This document covers the dev workflow,
quality bars, and conventions for `acdp-rs`.

## Prerequisites

- Rust **1.75** or newer (MSRV — verified in CI).
- `cargo fmt`, `cargo clippy`, `cargo test` (the rust-toolchain components are
  installed by `rustup`).

## Local checks

Before opening a pull request, please run:

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo clippy --no-default-features --all-targets -- -D warnings
cargo test --all-features
cargo test --no-default-features
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --all-features --no-deps
```

(CI runs the same set on every PR.)

Optional but recommended for crypto-sensitive changes:

```bash
cargo install cargo-deny cargo-audit
cargo deny check
cargo audit
```

## Branching and commits

- Target the `main` branch.
- Use [Conventional Commits](https://www.conventionalcommits.org/) — the
  `release-plz` workflow uses commit prefixes (`feat:`, `fix:`, `docs:`,
  `refactor:`, `test:`, `chore:`, `BREAKING CHANGE:`) to derive changelog
  entries and version bumps.

## Spec changes

This crate implements **RFC-ACDP-0001 / 0002 / 0003 / 0007**. Any change that
affects the wire format, hash preimage, signature input, or DID resolution
behavior MUST:

1. Cite the specific RFC section in the PR description.
2. Update or extend the golden vectors in `tests/golden_vector.rs`.
3. Pass against the canonical conformance vectors at
   `schemas/conformance/sig-001-ed25519-golden.json` and
   `schemas/conformance/can-001-jcs-vector.json`.

## Adding tests

- Unit tests live alongside the code in `#[cfg(test)] mod tests`.
- Integration tests go in `tests/`.
- HTTP-mocked tests use [`wiremock`](https://docs.rs/wiremock).
- Property tests use [`proptest`](https://docs.rs/proptest).

## Reporting security issues

Please **do not** open a public GitHub issue for security vulnerabilities.
See [SECURITY.md](./SECURITY.md) for the responsible-disclosure process.

## License

By contributing, you agree that your contributions will be licensed under the
project's dual MIT / Apache-2.0 license.
