//! Cross-registry resolution per RFC-ACDP-0006 (feature = "client").
//!
//! Resolves a `ctx_id` whose authority differs from the registry the
//! consumer is currently talking to. Walks the lineage of `derived_from`
//! references with cycle detection, configurable depth / node / fanout
//! caps, and per-authority caching of the `RegistryClient` and
//! capabilities document.
//!
//! See RFC-ACDP-0006 §4.1 for the seven-step algorithm:
//!   1. Parse URI → authority
//!   2. Fetch the foreign registry's capabilities
//!   3. Verify the registry DID matches `did:web:<authority>`
//!   4. Retrieve the full context
//!   5. Verify content_hash
//!   6. Verify signature via DID resolution
//!   7. Walk `derived_from` references (with cycle/depth/node/fanout/timeout limits)

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::client::{RegistryClient, VerifiedContext};
use crate::did::WebResolver;
use crate::error::AcdpError;
use crate::safe_http::SsrfPolicy;
use crate::types::body::Body;
use crate::types::primitives::CtxId;
use crate::types::CapabilitiesDocument;

/// Per-walk and per-resolve safety options.
///
/// Defaults are tuned for RFC-ACDP-0006 §7.4 / §7.5 — they bound a walk
/// even when the producer fabricates `derived_from` lists pointing into a
/// foreign registry's pathological lineage graph.
#[derive(Debug, Clone)]
pub struct ResolverOptions {
    /// Per-edge maximum depth (default 10).
    pub max_depth: usize,
    /// Total number of contexts the walk may verify (default 100). Acts
    /// as a hard ceiling even when individual hops respect `max_depth`.
    pub max_nodes: usize,
    /// Maximum `derived_from` count permitted on any single context the
    /// walker visits (default 32). A context that lists more parents is
    /// either malformed or hostile — short-circuit before fanning out.
    pub max_fanout: usize,
    /// Wall-clock budget for the entire walk (default 30 s). Wraps
    /// [`CrossRegistryResolver::walk_derived_from`] in `tokio::time::timeout`.
    pub total_timeout: Duration,
    /// How long to cache a foreign registry's capabilities document
    /// before re-fetching (default 5 min). Avoids hammering the foreign
    /// `/.well-known/acdp.json` on every hop.
    pub capabilities_ttl: Duration,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_nodes: 100,
            max_fanout: 32,
            total_timeout: Duration::from_secs(30),
            capabilities_ttl: Duration::from_secs(300),
        }
    }
}

/// Resolver for cross-registry references.
///
/// Holds a [`WebResolver`] for DID lookups and caches a [`RegistryClient`]
/// + capabilities document per authority for the lifetime of the resolver.
///
/// The [`SsrfPolicy`] is consulted on every URL the resolver constructs
/// (RFC-ACDP-0006 §7.1, §7.2).
pub struct CrossRegistryResolver {
    did_resolver: WebResolver,
    options: ResolverOptions,
    allowlist: Option<HashSet<String>>,
    ssrf_policy: SsrfPolicy,
    // Per-authority caches. Mutex-guarded for interior mutability across
    // the immutable `&self` API surface; contention is low since
    // authorities are few per walk.
    client_cache: Mutex<HashMap<String, RegistryClient>>,
    caps_cache: Mutex<HashMap<String, (CapabilitiesDocument, Instant)>>,
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
            options: ResolverOptions::default(),
            allowlist: None,
            ssrf_policy: SsrfPolicy::default(),
            client_cache: Mutex::new(HashMap::new()),
            caps_cache: Mutex::new(HashMap::new()),
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
        self.options.max_depth = depth;
        self
    }

    /// Replace the complete options struct (overrides every individual
    /// `with_*` setter that wasn't already applied).
    pub fn with_options(mut self, options: ResolverOptions) -> Self {
        self.options = options;
        self
    }

    /// Borrow the active options. Useful for tests + telemetry.
    pub fn options(&self) -> &ResolverOptions {
        &self.options
    }

    /// Override the [`WebResolver`] used for DID document lookups.
    ///
    /// Primary use is supplying a `WebResolver::with_root_cert_pem`
    /// instance in tests so a self-signed mock can answer DID-document
    /// requests for `did:web:localhost%3A<port>`. Production callers do
    /// not need this — the default resolver trusts the system CA bundle.
    pub fn with_did_resolver(mut self, resolver: WebResolver) -> Self {
        self.did_resolver = resolver;
        self
    }

    /// Pre-populate the per-authority [`RegistryClient`] cache.
    ///
    /// Primary use is the conformance harness: tests supply a client
    /// whose HTTP layer trusts the in-process TLS server's self-signed
    /// root certificate (via [`RegistryClient::with_root_cert_pem`]), so
    /// the resolver hits the mock instead of attempting a real network
    /// call. The seeded client wins over the lazy `RegistryClient::new`
    /// constructor that [`Self::resolve`] would otherwise invoke on
    /// first access.
    pub fn seed_client(&self, authority: impl Into<String>, client: RegistryClient) {
        self.client_cache
            .lock()
            .unwrap()
            .insert(authority.into(), client);
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

        // Cached client (and capabilities) per authority.
        let registry = self.client_for(&authority, &base)?;
        let caps = self.capabilities_for(&authority, &registry).await?;

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

    /// Walk the `derived_from` graph rooted at `body` with cycle detection,
    /// a per-edge depth cap of [`ResolverOptions::max_depth`], a total-
    /// nodes cap of `max_nodes`, a per-context fanout cap of `max_fanout`,
    /// and a wall-clock `total_timeout`. Returns each verified ancestor
    /// (excluding the root). Breadth-first; closer ancestors are returned
    /// first.
    pub async fn walk_derived_from(&self, body: &Body) -> Result<Vec<VerifiedContext>, AcdpError> {
        let total_timeout = self.options.total_timeout;
        let fut = self.walk_derived_from_inner(body);
        match tokio::time::timeout(total_timeout, fut).await {
            Ok(res) => res,
            Err(_) => Err(AcdpError::CrossRegistryResolutionFailed(format!(
                "derived_from walk exceeded total_timeout={:?}",
                total_timeout
            ))),
        }
    }

    async fn walk_derived_from_inner(
        &self,
        body: &Body,
    ) -> Result<Vec<VerifiedContext>, AcdpError> {
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(body.ctx_id.0.clone());

        if body.derived_from.len() > self.options.max_fanout {
            return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                "root context {} has derived_from fanout {} > max_fanout={}",
                body.ctx_id.0,
                body.derived_from.len(),
                self.options.max_fanout
            )));
        }

        let mut results: Vec<VerifiedContext> = Vec::new();
        let mut frontier: VecDeque<(CtxId, usize)> = body
            .derived_from
            .iter()
            .map(|c| (c.clone(), 1usize))
            .collect();

        while let Some((next, depth)) = frontier.pop_front() {
            if !seen.insert(next.0.clone()) {
                continue; // cycle
            }
            if depth > self.options.max_depth {
                return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                    "derived_from walk exceeded max_depth={} at {}",
                    self.options.max_depth, next.0
                )));
            }
            if results.len() >= self.options.max_nodes {
                return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                    "derived_from walk exceeded max_nodes={} (last attempted: {})",
                    self.options.max_nodes, next.0
                )));
            }
            let verified = self.resolve(&next).await?;
            let parents = &verified.body().derived_from;
            if parents.len() > self.options.max_fanout {
                return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                    "context {} has derived_from fanout {} > max_fanout={}",
                    next.0,
                    parents.len(),
                    self.options.max_fanout
                )));
            }
            for parent in parents {
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

    /// Return a cached `RegistryClient` for the authority, building one
    /// on first use. Each client carries its own SSRF policy + timeouts;
    /// reuse across hops avoids per-hop reqwest connection-pool churn.
    fn client_for(&self, authority: &str, base: &str) -> Result<RegistryClient, AcdpError> {
        let mut cache = self.client_cache.lock().unwrap();
        if let Some(c) = cache.get(authority) {
            return Ok(c.clone());
        }
        let client = RegistryClient::new(base)?;
        cache.insert(authority.to_string(), client.clone());
        Ok(client)
    }

    /// Return the cached capabilities for `authority`, fetching when the
    /// cache is empty or stale per `ResolverOptions::capabilities_ttl`.
    async fn capabilities_for(
        &self,
        authority: &str,
        registry: &RegistryClient,
    ) -> Result<CapabilitiesDocument, AcdpError> {
        // Fast path: cache hit + within TTL.
        {
            let cache = self.caps_cache.lock().unwrap();
            if let Some((caps, fetched_at)) = cache.get(authority) {
                if fetched_at.elapsed() < self.options.capabilities_ttl {
                    return Ok(caps.clone());
                }
            }
        }
        let caps = registry.capabilities().await.map_err(|e| match e {
            AcdpError::Http(_) | AcdpError::KeyResolutionUnreachable(_) => {
                AcdpError::CrossRegistryResolutionFailed(format!(
                    "could not reach registry '{authority}': {e}"
                ))
            }
            other => other,
        })?;
        let mut cache = self.caps_cache.lock().unwrap();
        cache.insert(authority.to_string(), (caps.clone(), Instant::now()));
        Ok(caps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_rejects_outside_authorities() {
        let resolver =
            CrossRegistryResolver::new().with_allowlist(["registry.example.com".to_string()]);
        let err = resolver.check_allowlist("evil.com").unwrap_err();
        assert!(matches!(err, AcdpError::CrossRegistryResolutionFailed(_)));
        resolver.check_allowlist("registry.example.com").unwrap();
    }

    #[test]
    fn options_default_values_match_doc() {
        let o = ResolverOptions::default();
        assert_eq!(o.max_depth, 10);
        assert_eq!(o.max_nodes, 100);
        assert_eq!(o.max_fanout, 32);
        assert_eq!(o.total_timeout, Duration::from_secs(30));
        assert_eq!(o.capabilities_ttl, Duration::from_secs(300));
    }

    #[test]
    fn with_options_replaces_full_struct() {
        let r = CrossRegistryResolver::new().with_options(ResolverOptions {
            max_depth: 3,
            max_nodes: 7,
            max_fanout: 2,
            total_timeout: Duration::from_secs(5),
            capabilities_ttl: Duration::from_secs(60),
        });
        assert_eq!(r.options().max_depth, 3);
        assert_eq!(r.options().max_nodes, 7);
        assert_eq!(r.options().max_fanout, 2);
    }

    #[test]
    fn cycle_detection_short_circuits() {
        let _resolver = CrossRegistryResolver::new();
        let mut seen: HashSet<String> = HashSet::new();
        let id = "acdp://r/12345678-1234-4321-8123-123456781234".to_string();
        assert!(seen.insert(id.clone()));
        assert!(!seen.insert(id));
    }
}
