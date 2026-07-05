# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.2.0...acdp-server-v0.3.0) - 2026-07-05

### Added

- [**breaking**] lifecycle events & retraction — RFC-ACDP-0013 (acdp/0.3.0 draft)

### Other

- rustfmt after integration merges
- Merge feature/rfc-0012-log-verification: RFC-ACDP-0012 SDK surface

## [0.2.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.1.0...acdp-server-v0.2.0) - 2026-07-05

### Added

- *(server)* mint lineage-head receipts on /current (RFC-ACDP-0011 §6)
- feat!(types): 0.3.0 capabilities surface — limits.max_publish_per_minute + version-conditional idempotency rule
- *(tracing)* instrument verify pipeline and server publish path
- *(types)* Body::from_publish_request — single PublishRequest→Body materialization point (IMP-02)

## [0.1.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/releases/tag/acdp-server-v0.1.0) - 2026-06-24

### Other

- split acdp into a fine-grained Cargo workspace
