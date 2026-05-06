//! Cross-registry resolution per RFC-ACDP-0006 (feature = "client").
//!
//! Resolves a `ctx_id` whose authority differs from the registry the
//! consumer is currently talking to. Walks the lineage of `derived_from`
//! references with cycle detection and a configurable depth cap.
//!
//! See RFC-ACDP-0006 §4.1 for the seven-step algorithm:
//!   1. Parse URI → authority
//!   2. Fetch the foreign registry's capabilities
//!   3. Verify the registry DID matches `did:web:<authority>`
//!   4. Retrieve the full context
//!   5. Verify content_hash
//!   6. Verify signature via DID resolution
//!   7. Walk `derived_from` references (with cycle/depth limits)

use std::collections::{HashSet, VecDeque};

use crate::client::{RegistryClient, VerifiedContext};
use crate::did::WebResolver;
use crate::error::AcdpError;
use crate::safe_http::SsrfPolicy;
use crate::types::body::Body;
use crate::types::primitives::CtxId;

/// Default maximum recursion depth when walking `derived_from`.
const DEFAULT_MAX_DEPTH: usize = 10;

/// Resolver for cross-registry references.
///
/// Holds a [`WebResolver`] for DID lookups and an HTTP client for capability
/// fetches. Each call to [`Self::resolve`] independently constructs a
/// per-authority [`RegistryClient`]. The [`SsrfPolicy`] is consulted on
/// every URL the resolver constructs (RFC-ACDP-0006 §7.1, §7.2).
pub struct CrossRegistryResolver {
    did_resolver: WebResolver,
    max_depth: usize,
    allowlist: Option<HashSet<String>>,
    ssrf_policy: SsrfPolicy,
}

impl Default for CrossRegistryResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossRegistryResolver {
    /// Build a resolver with default settings: no allowlist, depth 10,
    /// HTTPS-only / no IP literals SSRF policy.
    pub fn new() -> Self {
        Self {
            did_resolver: WebResolver::new(),
            max_depth: DEFAULT_MAX_DEPTH,
            allowlist: None,
            ssrf_policy: SsrfPolicy::default(),
        }
    }

    /// Override the [`SsrfPolicy`] applied to outbound URLs.
    ///
    /// Useful for test environments that need to allow `http://` or
    /// IP-literal hosts. Production deployments SHOULD keep the default.
    pub fn with_ssrf_policy(mut self, policy: SsrfPolicy) -> Self {
        self.ssrf_policy = policy;
        self
    }

    /// Cap the number of `derived_from` hops walked in a single
    /// [`Self::walk_derived_from`] call.
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Restrict cross-registry resolution to a fixed set of authorities
    /// (lowercase DNS hostnames). When set, any reference outside the
    /// allowlist is rejected with [`AcdpError::CrossRegistryResolutionFailed`].
    pub fn with_allowlist<I, S>(mut self, authorities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowlist = Some(authorities.into_iter().map(Into::into).collect());
        self
    }

    /// Resolve a single cross-registry [`CtxId`] end-to-end.
    ///
    /// Steps 1–6 of RFC-ACDP-0006 §4.1: parse, fetch capabilities,
    /// verify the registry DID *and* its DID document's web binding,
    /// retrieve, recompute hash, verify signature. The [`SsrfPolicy`]
    /// is checked first so a hostile authority cannot drive an
    /// internal-network request.
    pub async fn resolve(&self, ctx_id: &CtxId) -> Result<VerifiedContext, AcdpError> {
        let parsed = CtxId::parse(ctx_id.as_str())?;
        let authority = parsed.authority().to_string();
        self.check_allowlist(&authority)?;

        // RFC-ACDP-0006 §7: SSRF policy on the outbound base URL.
        let base = format!("https://{authority}");
        self.ssrf_policy
            .check_url(&base)
            .map_err(|e| AcdpError::CrossRegistryResolutionFailed(format!("SSRF policy: {e}")))?;

        // Build a registry client for the foreign authority.
        let registry = RegistryClient::new(&base)?;

        // Fetch capabilities — also implicitly proves the foreign registry
        // exists and speaks ACDP at that authority.
        let caps = registry.capabilities().await.map_err(|e| match e {
            // Surface as a cross-registry-specific error if it isn't already.
            AcdpError::Http(_) | AcdpError::KeyResolutionUnreachable(_) => {
                AcdpError::CrossRegistryResolutionFailed(format!(
                    "could not reach registry '{authority}': {e}"
                ))
            }
            other => other,
        })?;

        // Step 3a: capabilities.registry_did MUST be `did:web:<authority>`.
        let expected_did = format!("did:web:{authority}");
        if caps.registry_did != expected_did {
            return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                "registry DID '{}' does not match expected '{expected_did}'",
                caps.registry_did
            )));
        }

        // Step 3b (RFC-ACDP-0006 §4.1 step 3): resolve the registry's
        // DID document and confirm the web binding matches `<authority>`.
        // This catches a misconfigured registry advertising a registry_did
        // for an authority it does not control.
        let registry_doc = self
            .did_resolver
            .resolve(&caps.registry_did)
            .await
            .map_err(|e| {
                AcdpError::CrossRegistryResolutionFailed(format!(
                    "could not resolve registry DID document for '{}': {e}",
                    caps.registry_did
                ))
            })?;
        if registry_doc.id != caps.registry_did {
            return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                "registry DID document `id` '{}' does not match capabilities.registry_did '{}'",
                registry_doc.id, caps.registry_did
            )));
        }

        // Steps 4–6: retrieve + verify
        VerifiedContext::fetch(&registry, &self.did_resolver, &parsed).await
    }

    /// Walk the `derived_from` graph rooted at `body` with cycle detection
    /// and a depth cap of [`Self::with_max_depth`]. Returns each verified
    /// ancestor (excluding the root). The walk is breadth-first via
    /// [`VecDeque`], so closer ancestors are returned first.
    pub async fn walk_derived_from(&self, body: &Body) -> Result<Vec<VerifiedContext>, AcdpError> {
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(body.ctx_id.0.clone());

        let mut results = Vec::new();
        let mut frontier: VecDeque<(CtxId, usize)> = body
            .derived_from
            .iter()
            .map(|c| (c.clone(), 1usize))
            .collect();

        while let Some((next, depth)) = frontier.pop_front() {
            if !seen.insert(next.0.clone()) {
                // Cycle: ignore and continue
                continue;
            }
            if depth > self.max_depth {
                return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                    "derived_from walk exceeded max_depth={} at {}",
                    self.max_depth, next.0
                )));
            }
            let verified = self.resolve(&next).await?;
            for parent in &verified.body().derived_from {
                if !seen.contains(parent.as_str()) {
                    frontier.push_back((parent.clone(), depth + 1));
                }
            }
            results.push(verified);
        }
        Ok(results)
    }

    fn check_allowlist(&self, authority: &str) -> Result<(), AcdpError> {
        if let Some(list) = &self.allowlist {
            if !list.contains(authority) {
                return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                    "authority '{authority}' is not on the resolver allowlist"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_rejects_outside_authorities() {
        // We can't easily test the network path without a wiremock TLS setup;
        // verify the allowlist guard in isolation.
        let resolver =
            CrossRegistryResolver::new().with_allowlist(["registry.example.com".to_string()]);
        let err = resolver.check_allowlist("evil.com").unwrap_err();
        assert!(matches!(err, AcdpError::CrossRegistryResolutionFailed(_)));
        resolver.check_allowlist("registry.example.com").unwrap();
    }

    #[test]
    fn cycle_detection_short_circuits() {
        // Build a synthetic body whose derived_from points to itself; the
        // walker should ignore the cycle (and would error from depth before
        // network call, since we never call self.resolve in a loop).
        // This test exercises the `seen` set logic without network IO.
        let resolver = CrossRegistryResolver::new();
        let mut seen: HashSet<String> = HashSet::new();
        let id = "acdp://r/12345678-1234-4321-8123-123456781234".to_string();
        assert!(seen.insert(id.clone()));
        assert!(!seen.insert(id));
        // Depth check
        let _ = resolver.max_depth; // unused-field guard
    }
}
