# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.3](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.8.2...acdp-client-v0.8.3) - 2026-08-30

### Other

- release v0.8.3 ([#176](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/176))

## [0.8.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.8.1...acdp-client-v0.8.2) - 2026-08-30

### Other

- *(deps)* bump the major-updates group across 1 directory with 9 updates ([#157](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/157))
- W4-RS hygiene batch (RS-6/7/9/11/12) ([#164](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/164))

## [0.8.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.8.0...acdp-client-v0.8.1) - 2026-07-10

### Other

- release v0.8.0 ([#128](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/128))

## [0.8.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.6.2...acdp-client-v0.8.0) - 2026-07-10

### Other

- unify the whole ecosystem to 0.8.0 and auto-release the SDKs ([#127](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/127))

## [0.6.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.4.1...acdp-client-v0.6.1) - 2026-07-09

### Other

- release v0.6.0
- unify the acdp family to a single lockstep version (0.6.0)

## [0.6.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.4.1...acdp-client-v0.6.0) - 2026-07-09

### Other

- unify the acdp family to a single lockstep version (0.6.0)

## [0.4.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.4.0...acdp-client-v0.4.1) - 2026-07-06

### Added

- *(client)* witness cosignature verification, quorum, and safe mint (RFC-ACDP-0015)

### Other

- *(conformance)* bind wit-001..004 witness-cosigning fixtures (RFC-ACDP-0015)

## [0.4.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.3.0...acdp-client-v0.4.0) - 2026-07-06

### Added

- *(client)* [**breaking**] add RegistryClient::builder, deprecate new_pinned

### Other

- *(client)* drop the private-item intra-doc link in RegistryClientBuilder::build
- *(client)* [**breaking**] encapsulate VerifiedContext behind accessors

## [0.3.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.2.0...acdp-client-v0.3.0) - 2026-07-05

### Added

- feat!(client): hard-gate SSRF-relaxed test constructors behind test-transport
- *(revocation)* producer key-revocation signal (RFC-ACDP-0014, rev-001/rev-002)

### Other

- Merge feature/rfc-0014-revocation: RFC-ACDP-0014 SDK surface

## [0.2.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.1.0...acdp-client-v0.2.0) - 2026-07-05

### Added

- *(client)* verify lineage-head receipts on /current (RFC-ACDP-0011 §7)
- *(client)* fallible WebResolver constructors; feature-gate SSRF-relaxed test constructors behind test-transport

## [0.1.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/releases/tag/acdp-client-v0.1.0) - 2026-06-24

### Other

- split acdp into a fine-grained Cargo workspace
