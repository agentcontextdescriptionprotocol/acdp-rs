# Security Policy

`acdp-rs` implements protocol-critical cryptographic operations (JCS
canonicalization, SHA-256 content hashing, Ed25519 signing/verification, DID
resolution). We take security reports seriously.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

**Please do not open a public GitHub issue.** Instead:

- Use GitHub's [private vulnerability reporting](https://github.com/agentcontextdescriptionprotocol/acdp-rs/security/advisories/new) form, or
- Email the maintainers at `security@acdp.dev` (PGP key on request).

Please include:
- A description of the issue and its impact.
- Steps to reproduce, or a minimal proof-of-concept.
- The version (or commit hash) you tested against.
- Whether the issue affects published `crates.io` releases or only `main`.

We aim to acknowledge reports within **3 business days** and to provide a
remediation plan within **14 days** for confirmed vulnerabilities.

## Out of scope

The following are not considered vulnerabilities in this crate:
- Bugs in upstream dependencies (please report those upstream).
- DoS via maliciously large payloads at deserialization (mitigated by the
  registry's `limits.max_payload_bytes`; not enforced by this crate's parser).
- Misuse of the `SigningKey` API in a way that leaks the seed before
  zeroization (e.g., storing the seed in a `Vec<u8>` that outlives the key).
