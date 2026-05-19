//! HTTP client for ACDP registries (feature = "client").

use std::time::Duration;

use crate::error::AcdpError;
use crate::limits::{
    CONNECT_TIMEOUT, MAX_CONTEXT_BYTES, MAX_METADATA_BYTES, MAX_REDIRECTS, REQUEST_TIMEOUT,
};
use crate::safe_http::SsrfPolicy;
use crate::types::{
    body::FullContext,
    capabilities::CapabilitiesDocument,
    primitives::{CtxId, LineageId},
    publish::{PublishRequest, PublishResponse, WireError},
    search::{SearchParams, SearchResponse},
};
use chrono::{DateTime, Utc};
use reqwest::{redirect, Client};

/// HTTP client for a single ACDP registry.
///
/// `reqwest::Client` clones cheaply (it's an `Arc` internally), so this
/// struct is `Clone` to enable per-authority caching in
/// [`crate::client::CrossRegistryResolver`] without re-wiring HTTP+TLS
/// state on every hop.
#[derive(Clone)]
pub struct RegistryClient {
    base: String,
    http: Client,
}

/// Cache and integrity headers returned alongside a retrieved body.
///
/// `etag` is the body's `content_hash` (immutable; ideal cache key).
/// `cache_control` and `last_modified` are reported verbatim from the
/// upstream registry.
#[derive(Debug, Clone, Default)]
pub struct RetrievalMetadata {
    /// Strong validator for conditional retrieval (`If-None-Match`).
    pub etag: Option<String>,
    /// Raw `Cache-Control` header value, if any.
    pub cache_control: Option<String>,
    /// Parsed `Last-Modified` header, if any.
    pub last_modified: Option<DateTime<Utc>>,
}

impl RegistryClient {
    /// Connect to a registry at `base_url` (e.g. `https://registry.example.com`).
    ///
    /// Uses `rustls` for TLS; does not use the system OpenSSL. Applies
    /// the RFC-ACDP-0006 §7.4 default timeouts (5s connect, 30s total)
    /// and §7.5 redirect policy (max 3 follows, same authority only).
    pub fn new(base_url: &str) -> Result<Self, AcdpError> {
        Self::build(base_url, None, None)
    }

    /// Connect to a registry that trusts the given PEM-encoded root
    /// certificate in addition to the system roots.
    ///
    /// Primary use is the in-process self-signed HTTPS server in the
    /// crate's `tests/helpers/tls_did_server.rs` harness so the spec
    /// fixtures `fed-001..006` can drive `CrossRegistryResolver`
    /// end-to-end without going over the network.
    pub fn with_root_cert_pem(base_url: &str, pem: &[u8]) -> Result<Self, AcdpError> {
        Self::build(base_url, Some(pem), None)
    }

    /// Connect to a registry whose `<authority>` in `base_url` is routed
    /// to a fixed socket address. Trusts the given PEM-encoded root
    /// certificate in addition to the system roots.
    ///
    /// Use only in tests: a `CrossRegistryResolver` test that wants to
    /// drive `acdp://<host>/<uuid>` references requires `<host>` to be
    /// a valid lowercase DNS label (per `is_valid_dns_authority` in
    /// `types::primitives`), which precludes embedding the port in the
    /// `ctx_id`. This factory accepts a logical hostname (e.g.
    /// `localhost`) and pins it to the test server's actual
    /// `127.0.0.1:<port>` via reqwest's `.resolve()` hook.
    #[doc(hidden)]
    pub fn with_test_endpoint(
        base_url: &str,
        target: std::net::SocketAddr,
        pem: &[u8],
    ) -> Result<Self, AcdpError> {
        Self::build(base_url, Some(pem), Some(target))
    }

    fn build(
        base_url: &str,
        extra_root_pem: Option<&[u8]>,
        resolve_target: Option<std::net::SocketAddr>,
    ) -> Result<Self, AcdpError> {
        let base = base_url.trim_end_matches('/').to_string();
        let original_authority = url::Url::parse(&base)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string));

        let authority_for_redirect = original_authority.clone();
        let policy = redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                return attempt.error(format!(
                    "exceeded {MAX_REDIRECTS} redirects per RFC-ACDP-0006 §7.5"
                ));
            }
            // Same-authority enforcement (skip when we couldn't parse the base).
            let next_host = attempt.url().host_str().map(str::to_string);
            if let (Some(orig), Some(next_host)) = (&authority_for_redirect, &next_host) {
                if next_host != orig {
                    return attempt.error(format!(
                        "cross-authority redirect rejected ({orig} -> {next_host})"
                    ));
                }
            }
            attempt.follow()
        });

        let mut builder = Client::builder()
            .use_rustls_tls()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(policy);

        if let Some(pem) = extra_root_pem {
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| AcdpError::Http(format!("invalid root cert PEM: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }

        if let (Some(target), Some(host)) = (resolve_target, original_authority) {
            builder = builder.resolve(&host, target);
        }

        let http = builder
            .build()
            .map_err(|e| AcdpError::Http(e.to_string()))?;

        Ok(Self { base, http })
    }

    /// Connect to a registry with DNS-rebinding protection
    /// (RFC-ACDP-0006 §7.6).
    ///
    /// Resolves the hostname once, validates the resolved IP against
    /// `policy`, then pins that IP into the HTTP client so every
    /// connection uses the address that was filtered. Use this in
    /// server-side cross-registry contexts where a hostile authoritative
    /// DNS server could otherwise flip the answer between the SSRF
    /// filter check and the actual connect.
    ///
    /// Returns the same [`AcdpError`] variants as
    /// [`SsrfPolicy::pin_resolved_ip`] when the host cannot be safely
    /// resolved.
    pub async fn new_pinned(base_url: &str, policy: &SsrfPolicy) -> Result<Self, AcdpError> {
        let base = base_url.trim_end_matches('/').to_string();
        let parsed = url::Url::parse(&base)
            .map_err(|e| AcdpError::SchemaViolation(format!("invalid base URL: {e}")))?;
        // Pre-flight: scheme + host range checks via the same policy.
        policy.check_url(&base)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| AcdpError::SchemaViolation(format!("base URL has no host: {base}")))?
            .to_string();
        let port = parsed
            .port_or_known_default()
            .unwrap_or(if parsed.scheme() == "http" { 80 } else { 443 });

        let pinned = policy.pin_resolved_ip(&host, port).await?;

        let original_authority = Some(host.clone());
        let policy_redirect = redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                return attempt.error(format!(
                    "exceeded {MAX_REDIRECTS} redirects per RFC-ACDP-0006 §7.5"
                ));
            }
            let next_host = attempt.url().host_str().map(str::to_string);
            if let (Some(orig), Some(next_host)) = (&original_authority, &next_host) {
                if next_host != orig {
                    return attempt.error(format!(
                        "cross-authority redirect rejected ({orig} -> {next_host})"
                    ));
                }
            }
            attempt.follow()
        });

        let http = Client::builder()
            .use_rustls_tls()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(policy_redirect)
            .resolve(&host, pinned)
            .build()
            .map_err(|e| AcdpError::Http(e.to_string()))?;

        Ok(Self { base, http })
    }

    // ── Capabilities ────────────────────────────────────────────────────────

    /// Fetch the registry's capabilities document and run the
    /// RFC-ACDP-0007 §3 runtime validation
    /// ([`crate::validation::validate_capabilities`]).
    ///
    /// Body capped at 64 KB per RFC-ACDP-0006 §7.3.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn capabilities(&self) -> Result<CapabilitiesDocument, AcdpError> {
        Ok(self.capabilities_with_ttl().await?.0)
    }

    /// Like [`Self::capabilities`] but also returns the cache TTL
    /// derived from the response's `Cache-Control: max-age=N` header.
    ///
    /// Per RFC-ACDP-0006 §4.2, consumers SHOULD cache the capabilities
    /// document for `min(max-age, 3600s)` seconds. When no
    /// `Cache-Control` (or no parseable `max-age`) is returned, the
    /// fallback is `300s` — a conservative middle-ground that matches
    /// [`crate::client::ResolverOptions::capabilities_ttl`]'s default.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn capabilities_with_ttl(
        &self,
    ) -> Result<(CapabilitiesDocument, std::time::Duration), AcdpError> {
        let url = format!("{}/.well-known/acdp.json", self.base);
        let resp = self.http.get(&url).send().await?;
        let ttl = cache_ttl_from_response(&resp);
        let caps: CapabilitiesDocument = self.parse_success(resp, MAX_METADATA_BYTES).await?;
        crate::validation::validate_capabilities(&caps)?;
        Ok((caps, ttl))
    }

    // ── Publish ─────────────────────────────────────────────────────────────

    /// Publish a context.  Returns the registry-assigned identifiers.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, req)))]
    pub async fn publish(&self, req: &PublishRequest) -> Result<PublishResponse, AcdpError> {
        let url = format!("{}/contexts", self.base);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/acdp+json")
            .json(req)
            .send()
            .await?;
        self.parse_success(resp, MAX_METADATA_BYTES).await
    }

    /// Publish with an idempotency key for safe retries.
    pub async fn publish_idempotent(
        &self,
        req: &PublishRequest,
        idempotency_key: &str,
    ) -> Result<PublishResponse, AcdpError> {
        let url = format!("{}/contexts", self.base);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/acdp+json")
            .header("Idempotency-Key", idempotency_key)
            .json(req)
            .send()
            .await?;
        self.parse_success(resp, MAX_METADATA_BYTES).await
    }

    /// Publish with bounded retry for transient failures.
    ///
    /// Reuses `idempotency_key` across attempts so the registry can
    /// dedupe (RFC-ACDP-0003 §6). Retries only when the error is
    /// transient per [`AcdpError::is_transient`]. Bounded backoff:
    /// 250 ms, 500 ms, 1 s, 2 s.
    pub async fn publish_with_retry(
        &self,
        req: &PublishRequest,
        idempotency_key: &str,
        max_attempts: u32,
    ) -> Result<PublishResponse, AcdpError> {
        let attempts = max_attempts.max(1);
        let mut last_err: Option<AcdpError> = None;
        for attempt in 0..attempts {
            match self.publish_idempotent(req, idempotency_key).await {
                Ok(resp) => return Ok(resp),
                Err(e) if e.is_transient() && attempt + 1 < attempts => {
                    let backoff_ms = 250u64 * (1 << attempt.min(3));
                    last_err = Some(e);
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        attempt = attempt + 1,
                        backoff_ms,
                        "publish transient failure; retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err
            .unwrap_or_else(|| AcdpError::Http("publish_with_retry exhausted attempts".into())))
    }

    // ── Retrieval ────────────────────────────────────────────────────────────

    /// Retrieve a full context (body + registry_state) by ctx_id.
    ///
    /// Body capped at 1 MB per RFC-ACDP-0006 §7.3.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), fields(ctx_id = %ctx_id)))]
    pub async fn retrieve(&self, ctx_id: &CtxId) -> Result<FullContext, AcdpError> {
        let encoded = urlencoding::encode(ctx_id.as_str());
        let url = format!("{}/contexts/{}", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        self.parse_success(resp, MAX_CONTEXT_BYTES).await
    }

    /// Retrieve a full context plus cache / integrity headers.
    pub async fn retrieve_with_metadata(
        &self,
        ctx_id: &CtxId,
    ) -> Result<(FullContext, RetrievalMetadata), AcdpError> {
        let encoded = urlencoding::encode(ctx_id.as_str());
        let url = format!("{}/contexts/{}", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        let metadata = parse_retrieval_metadata(&resp);
        let body = self.parse_success(resp, MAX_CONTEXT_BYTES).await?;
        Ok((body, metadata))
    }

    /// Conditional retrieval using `If-None-Match`.
    ///
    /// Returns `Ok(None)` when the registry responds 304 Not Modified.
    /// Returns `Ok(Some((body, metadata)))` for a fresh retrieval.
    pub async fn retrieve_if_none_match(
        &self,
        ctx_id: &CtxId,
        etag: &str,
    ) -> Result<Option<(FullContext, RetrievalMetadata)>, AcdpError> {
        let encoded = urlencoding::encode(ctx_id.as_str());
        let url = format!("{}/contexts/{}", self.base, encoded);
        let resp = self
            .http
            .get(&url)
            .header("If-None-Match", etag)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(None);
        }
        let metadata = parse_retrieval_metadata(&resp);
        let body = self.parse_success(resp, MAX_CONTEXT_BYTES).await?;
        Ok(Some((body, metadata)))
    }

    /// Retrieve just the body (immutable, highly cacheable).
    pub async fn retrieve_body(
        &self,
        ctx_id: &CtxId,
    ) -> Result<crate::types::body::Body, AcdpError> {
        let encoded = urlencoding::encode(ctx_id.as_str());
        let url = format!("{}/contexts/{}/body", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        self.parse_success(resp, MAX_CONTEXT_BYTES).await
    }

    // ── Lineage ──────────────────────────────────────────────────────────────

    /// Retrieve all contexts in a lineage (oldest to newest).
    pub async fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        let encoded = urlencoding::encode(lineage_id.as_str());
        let url = format!("{}/lineages/{}", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        self.parse_success::<serde_json::Value>(resp, MAX_CONTEXT_BYTES)
            .await
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AcdpError::Serialization(e.to_string()))
            })
    }

    /// Retrieve the current (latest) context in a lineage.
    pub async fn current(&self, lineage_id: &LineageId) -> Result<FullContext, AcdpError> {
        let encoded = urlencoding::encode(lineage_id.as_str());
        let url = format!("{}/lineages/{}/current", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        self.parse_success(resp, MAX_CONTEXT_BYTES).await
    }

    // ── Discovery ────────────────────────────────────────────────────────────

    /// Keyword search across the registry.
    ///
    /// Body capped at 64 KB (search responses are projection-summaries —
    /// IMP-03: not the 1 MB context cap).
    pub async fn search(&self, params: &SearchParams) -> Result<SearchResponse, AcdpError> {
        let url = format!("{}/contexts/search", self.base);
        let resp = self.http.get(&url).query(params).send().await?;
        self.parse_success(resp, MAX_METADATA_BYTES).await
    }

    /// Begin a fluent search via [`RegistrySearch`]. Chains parameters
    /// with strong typing, then `.send().await` issues the request.
    ///
    /// ```no_run
    /// # async fn ex(client: &acdp::client::RegistryClient) -> Result<(), acdp::AcdpError> {
    /// let resp = client
    ///     .search_builder()
    ///     .q("market risk")
    ///     .tag("risk")
    ///     .tag("portfolio")
    ///     .limit(50)
    ///     .send()
    ///     .await?;
    /// # let _ = resp; Ok(()) }
    /// ```
    pub fn search_builder(&self) -> RegistrySearch<'_> {
        RegistrySearch::new(self)
    }
}

/// Fluent search builder bound to a [`RegistryClient`]. See
/// [`RegistryClient::search_builder`].
pub struct RegistrySearch<'a> {
    client: &'a RegistryClient,
    inner: crate::types::search::SearchParamsBuilder,
}

impl<'a> RegistrySearch<'a> {
    fn new(client: &'a RegistryClient) -> Self {
        Self {
            client,
            inner: crate::types::search::SearchParamsBuilder::new(),
        }
    }

    /// Issue the search.
    pub async fn send(self) -> Result<SearchResponse, AcdpError> {
        let params = self.inner.build();
        self.client.search(&params).await
    }
    /// Full-text query.
    pub fn q(mut self, q: impl Into<String>) -> Self {
        self.inner = self.inner.q(q);
        self
    }
    /// Filter on `type`.
    pub fn context_type(mut self, t: impl Into<String>) -> Self {
        self.inner = self.inner.context_type(t);
        self
    }
    /// Filter on `domain`.
    pub fn domain(mut self, d: impl Into<String>) -> Self {
        self.inner = self.inner.domain(d);
        self
    }
    /// Accumulate a tag.
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.inner = self.inner.tag(t);
        self
    }
    /// Filter on `agent_id`.
    pub fn agent_id(mut self, a: impl Into<String>) -> Self {
        self.inner = self.inner.agent_id(a);
        self
    }
    /// Filter on `derived_from` (strongly typed).
    pub fn derived_from(mut self, c: &crate::types::CtxId) -> Self {
        self.inner = self.inner.derived_from_ctx_id(c);
        self
    }
    /// Lower bound on `created_at`.
    pub fn created_after(mut self, dt: chrono::DateTime<chrono::Utc>) -> Self {
        self.inner = self.inner.created_after(dt);
        self
    }
    /// Upper bound on `created_at`.
    pub fn created_before(mut self, dt: chrono::DateTime<chrono::Utc>) -> Self {
        self.inner = self.inner.created_before(dt);
        self
    }
    /// Status filter.
    pub fn status(mut self, s: impl Into<String>) -> Self {
        self.inner = self.inner.status(s);
        self
    }
    /// Result page size cap.
    pub fn limit(mut self, l: u32) -> Self {
        self.inner = self.inner.limit(l);
        self
    }
    /// Pagination cursor.
    pub fn cursor(mut self, c: impl Into<String>) -> Self {
        self.inner = self.inner.cursor(c);
        self
    }
}

// ── Internal helpers on RegistryClient ───────────────────────────────────────

impl RegistryClient {
    async fn parse_success<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
        max_bytes: usize,
    ) -> Result<T, AcdpError> {
        if resp.status().is_success() {
            let bytes = read_body_capped(resp, max_bytes).await?;
            serde_json::from_slice(&bytes).map_err(|e| AcdpError::Serialization(e.to_string()))
        } else {
            // Error envelopes are tiny — apply the metadata cap so a
            // hostile registry can't exhaust memory via the error path.
            let bytes = match read_body_capped(resp, MAX_METADATA_BYTES).await {
                Ok(b) => b,
                Err(_) => {
                    return Err(AcdpError::from_wire_error(WireError {
                        error: crate::types::publish::WireErrorBody {
                            code: "unknown".into(),
                            message: "could not read registry error response".into(),
                            details: None,
                        },
                    }));
                }
            };
            let wire: WireError = serde_json::from_slice(&bytes).unwrap_or_else(|_| WireError {
                error: crate::types::publish::WireErrorBody {
                    code: "unknown".into(),
                    message: "could not parse registry error response".into(),
                    details: None,
                },
            });
            Err(AcdpError::from_wire_error(wire))
        }
    }
}

/// Extract the cache TTL for a capabilities response per
/// RFC-ACDP-0006 §4.2 — `min(Cache-Control: max-age=N, 3600s)`.
///
/// Falls back to a conservative 300s when no parseable `max-age`
/// directive is present (matches [`crate::client::ResolverOptions::capabilities_ttl`]'s
/// default so behavior is identical to the pre-BUG-09 code path on
/// silent registries).
fn cache_ttl_from_response(resp: &reqwest::Response) -> std::time::Duration {
    const MAX_CAPS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600);
    const DEFAULT_CAPS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

    let Some(cc) = resp
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    else {
        return DEFAULT_CAPS_CACHE_TTL;
    };
    for directive in cc.split(',') {
        let directive = directive.trim();
        if let Some(value) = directive
            .strip_prefix("max-age=")
            .or_else(|| directive.strip_prefix("s-maxage="))
        {
            if let Ok(secs) = value.parse::<u64>() {
                return std::time::Duration::from_secs(secs).min(MAX_CAPS_CACHE_TTL);
            }
        }
    }
    DEFAULT_CAPS_CACHE_TTL
}

fn parse_retrieval_metadata(resp: &reqwest::Response) -> RetrievalMetadata {
    let headers = resp.headers();
    let etag = headers
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cache_control = headers
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let last_modified = headers
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            DateTime::parse_from_rfc2822(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        });
    RetrievalMetadata {
        etag,
        cache_control,
        last_modified,
    }
}

/// Read the response body, aborting if the running total exceeds
/// `max_bytes`. Returns [`AcdpError::PayloadTooLarge`] on overflow.
async fn read_body_capped(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, AcdpError> {
    if let Some(len) = resp.content_length() {
        if len as usize > max_bytes {
            return Err(AcdpError::PayloadTooLarge(format!(
                "response Content-Length {len} exceeds cap {max_bytes}"
            )));
        }
    }
    let mut buf = Vec::with_capacity(8 * 1024);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| AcdpError::Http(e.to_string()))?
    {
        if buf.len() + chunk.len() > max_bytes {
            return Err(AcdpError::PayloadTooLarge(format!(
                "response body exceeded {max_bytes} bytes"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}
