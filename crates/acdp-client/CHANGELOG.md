# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
