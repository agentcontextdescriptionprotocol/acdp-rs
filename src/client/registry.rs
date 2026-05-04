//! HTTP client for ACDP registries (feature = "client").

use std::time::Duration;

use crate::error::AcdpError;
use crate::types::{
    body::FullContext,
    capabilities::CapabilitiesDocument,
    primitives::{CtxId, LineageId},
    publish::{PublishRequest, PublishResponse, WireError},
    search::{SearchParams, SearchResponse},
};
use reqwest::Client;

/// Default connect timeout per RFC-ACDP-0006 §7.4.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default total request timeout per RFC-ACDP-0006 §7.4.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP client for a single ACDP registry.
pub struct RegistryClient {
    base: String,
    http: Client,
}

impl RegistryClient {
    /// Connect to a registry at `base_url` (e.g. `https://registry.example.com`).
    ///
    /// Uses `rustls` for TLS; does not use the system OpenSSL. Applies
    /// the RFC-ACDP-0006 §7.4 default timeouts (5s connect, 30s total).
    pub fn new(base_url: &str) -> Result<Self, AcdpError> {
        let http = Client::builder()
            .use_rustls_tls()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| AcdpError::Http(e.to_string()))?;

        Ok(Self {
            base: base_url.trim_end_matches('/').to_string(),
            http,
        })
    }

    // ── Capabilities ────────────────────────────────────────────────────────

    /// Fetch the registry's capabilities document.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn capabilities(&self) -> Result<CapabilitiesDocument, AcdpError> {
        let url = format!("{}/.well-known/acdp.json", self.base);
        let resp = self.http.get(&url).send().await?;
        self.parse_success(resp).await
    }

    // ── Publish ─────────────────────────────────────────────────────────────

    /// Publish a context.  Returns the registry-assigned identifiers.
    pub async fn publish(&self, req: &PublishRequest) -> Result<PublishResponse, AcdpError> {
        let url = format!("{}/contexts", self.base);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/acdp+json")
            .json(req)
            .send()
            .await?;
        self.parse_success(resp).await
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
        self.parse_success(resp).await
    }

    // ── Retrieval ────────────────────────────────────────────────────────────

    /// Retrieve a full context (body + registry_state) by ctx_id.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), fields(ctx_id = %ctx_id)))]
    pub async fn retrieve(&self, ctx_id: &CtxId) -> Result<FullContext, AcdpError> {
        let encoded = urlencoding::encode(ctx_id.as_str());
        let url = format!("{}/contexts/{}", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        self.parse_success(resp).await
    }

    /// Retrieve just the body (immutable, highly cacheable).
    pub async fn retrieve_body(
        &self,
        ctx_id: &CtxId,
    ) -> Result<crate::types::body::Body, AcdpError> {
        let encoded = urlencoding::encode(ctx_id.as_str());
        let url = format!("{}/contexts/{}/body", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        self.parse_success(resp).await
    }

    // ── Lineage ──────────────────────────────────────────────────────────────

    /// Retrieve all contexts in a lineage (oldest to newest).
    pub async fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        let encoded = urlencoding::encode(lineage_id.as_str());
        let url = format!("{}/lineages/{}", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        self.parse_success::<serde_json::Value>(resp)
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
        self.parse_success(resp).await
    }

    // ── Discovery ────────────────────────────────────────────────────────────

    /// Keyword search across the registry.
    pub async fn search(&self, params: &SearchParams) -> Result<SearchResponse, AcdpError> {
        let url = format!("{}/contexts/search", self.base);
        let resp = self.http.get(&url).query(params).send().await?;
        self.parse_success(resp).await
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    async fn parse_success<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T, AcdpError> {
        if resp.status().is_success() {
            resp.json::<T>()
                .await
                .map_err(|e| AcdpError::Serialization(e.to_string()))
        } else {
            let wire: WireError = resp.json().await.unwrap_or_else(|_| WireError {
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
