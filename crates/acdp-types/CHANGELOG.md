# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-types-v0.8.0...acdp-types-v0.8.1) - 2026-07-10

### Other

- release v0.8.0 ([#128](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/128))

## [0.8.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-types-v0.6.2...acdp-types-v0.8.0) - 2026-07-10

### Other

- unify the whole ecosystem to 0.8.0 and auto-release the SDKs ([#127](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/127))

## [0.6.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-types-v0.3.2...acdp-types-v0.6.1) - 2026-07-09

### Other

- release v0.6.0
- unify the acdp family to a single lockstep version (0.6.0)

## [0.6.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-types-v0.3.2...acdp-types-v0.6.0) - 2026-07-09

### Other

- unify the acdp family to a single lockstep version (0.6.0)

## [0.3.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-types-v0.3.1...acdp-types-v0.3.2) - 2026-07-06

### Added

- *(types)* add LogCosignature witness-cosignature types (RFC-ACDP-0015)

### Other

- *(conformance)* bind wit-001..004 witness-cosigning fixtures (RFC-ACDP-0015)

## [0.3.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-types-v0.3.0...acdp-types-v0.3.1) - 2026-07-06

### Other

- updated the following local packages: acdp-primitives, acdp-did, acdp-jcs, acdp-crypto

## [0.3.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-types-v0.2.0...acdp-types-v0.3.0) - 2026-07-05

### Added

- [**breaking**] lifecycle events & retraction — RFC-ACDP-0013 (acdp/0.3.0 draft)

### Other

- rustfmt after integration merges
- Merge feature/rfc-0014-revocation: RFC-ACDP-0014 SDK surface
- Merge feature/rfc-0012-log-verification: RFC-ACDP-0012 SDK surface

## [0.2.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-types-v0.1.1...acdp-types-v0.2.0) - 2026-07-05

### Added

- *(types)* lineage-head receipts per RFC-ACDP-0011
- feat!(types): 0.3.0 capabilities surface — limits.max_publish_per_minute + version-conditional idempotency rule
- *(types)* Body::from_publish_request — single PublishRequest→Body materialization point (IMP-02)

## [0.1.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-types-v0.1.0...acdp-types-v0.1.1) - 2026-06-24

### Other

- release

## [0.1.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/releases/tag/acdp-types-v0.1.0) - 2026-06-24

### Other

- split acdp into a fine-grained Cargo workspace
