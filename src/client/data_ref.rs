//! Data-reference fetching + hash verification (feature = "client").
//!
//! [`DataRef`] tells a consumer **where** a piece of underlying data
//! lives; this module fetches it and verifies its integrity against the
//! producer-signed `content_hash` (RFC-ACDP-0002 §6).
//!
//! Three pieces:
//!
//! - [`DataRefFetcher`] — trait that abstracts the fetch strategy. Native
//!   async-fn-in-trait, so `impl DataRefFetcher` works directly in
//!   generic positions. Wrap a custom impl in `Box<dyn …>` only if your
//!   call site needs dynamic dispatch.
//! - [`HttpsDataRefFetcher`] — concrete fetcher for `https://…` URIs.
//!   The default [`crate::safe_http::SsrfPolicy`] is HTTPS-only;
//!   `http://` is rejected at the URL boundary before any socket
//!   activity. A test SSRF policy with `allow_http: true` may relax
//!   this. Caps response size at 16 MiB and has a 30 s timeout.
//!   Structured locators are NOT handled — they need protocol-specific
//!   knowledge.
//! - [`fetch_and_verify_data_ref`] — convenience helper that wires a
//!   fetcher to the declared `content_hash`, returning bytes only after
//!   the SHA-256 matches.
//!
//! ## Embedded refs
//!
//! `fetch_and_verify_data_ref` short-circuits embedded refs without
//! touching the fetcher — the bytes are already in the body. The
//! embedded-hash check (RFC-ACDP-0003 §2.1 step 3) is the
//! [`crate::validation::verify_embedded_hash`] entry point.

use sha2::{Digest, Sha256};

use crate::error::AcdpError;
use crate::safe_http::SsrfPolicy;
use crate::types::data_ref::{DataRef, Location};
use crate::types::primitives::ContentHash;

/// Default response-size cap for an HTTPS data-ref fetch.
///
/// 16 MiB. Producers that need to publish larger payloads SHOULD use a
/// chunked storage scheme (S3 multipart, IPFS, etc.) rather than serve
/// raw HTTPS. The cap exists to bound consumer memory regardless of
/// what the producer claimed in `size_bytes`.
pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Pluggable fetch strategy for a [`DataRef`]. Implementations are
/// responsible for SSRF defenses and response-size caps on URI fetches;
/// structured locators are protocol-specific and likely need their own
/// trait impl per scheme (`kafka.offset`, `ipfs.cid`, …).
pub trait DataRefFetcher: Send + Sync {
    /// Fetch raw bytes referenced by `location`. Implementations MAY
    /// reject [`Location::Structured`] with a clear error rather than
    /// implementing every scheme.
    fn fetch(
        &self,
        location: &Location,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, AcdpError>> + Send;
}

/// Default HTTPS-only fetcher.
///
/// Enforces:
/// - [`SsrfPolicy`] checks on every URL (HTTPS-only, IP-literal
///   rejection, private-range blocking).
/// - `Range`-free `GET` with a hard byte cap (default 16 MiB).
/// - 30 s total timeout (matches RFC-ACDP-0006 §7.4 for registry RPCs).
///
/// Constructed via [`Self::new`] (default cap) or
/// [`Self::with_max_bytes`].
pub struct HttpsDataRefFetcher {
    http: reqwest::Client,
    ssrf_policy: SsrfPolicy,
    max_bytes: u64,
}

impl Default for HttpsDataRefFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpsDataRefFetcher {
    /// Build a fetcher with the default 16 MiB cap and the default
    /// [`SsrfPolicy`] (HTTPS-only, no IP literals, no private ranges).
    pub fn new() -> Self {
        Self::with_max_bytes(DEFAULT_MAX_BYTES)
    }

    /// Build a fetcher with a custom response-size cap.
    pub fn with_max_bytes(max_bytes: u64) -> Self {
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("HttpsDataRefFetcher reqwest build failed");
        Self {
            http,
            ssrf_policy: SsrfPolicy::default(),
            max_bytes,
        }
    }

    /// Replace the [`SsrfPolicy`] (useful for tests).
    pub fn with_ssrf_policy(mut self, policy: SsrfPolicy) -> Self {
        self.ssrf_policy = policy;
        self
    }
}

impl DataRefFetcher for HttpsDataRefFetcher {
    async fn fetch(&self, location: &Location) -> Result<Vec<u8>, AcdpError> {
        let uri = match location {
            Location::Uri(s) => s,
            Location::Structured(_) => {
                return Err(AcdpError::NotImplemented(
                    "HttpsDataRefFetcher does not handle structured locators \
                     (kafka.offset, ipfs.cid, …) — implement DataRefFetcher \
                     for the relevant scheme"
                        .into(),
                ));
            }
        };

        // SSRF policy gate — RFC-ACDP-0006 §7.1/§7.2.
        self.ssrf_policy
            .check_url(uri)
            .map_err(|e| AcdpError::SchemaViolation(format!("SSRF policy on data_ref: {e}")))?;

        let mut resp = self
            .http
            .get(uri)
            .send()
            .await
            .map_err(|e| AcdpError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(AcdpError::Http(format!(
                "data_ref fetch returned HTTP {}",
                resp.status()
            )));
        }

        // Cap response size as we stream — defends against a producer
        // that claimed a small size_bytes but the server returns more.
        let mut buf = Vec::with_capacity(8 * 1024);
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| AcdpError::Http(e.to_string()))?
        {
            if (buf.len() as u64).saturating_add(chunk.len() as u64) > self.max_bytes {
                return Err(AcdpError::PayloadTooLarge(format!(
                    "data_ref response exceeded {} bytes",
                    self.max_bytes
                )));
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    }
}

/// Convenience: fetch a [`DataRef`] and verify its declared
/// `content_hash`.
///
/// Behavior:
/// - **Embedded ref:** returns the decoded bytes via
///   [`crate::validation::embedded_decoded_bytes`]. If the ref also
///   declares a `content_hash`, [`crate::validation::verify_embedded_hash`]
///   has already verified it at validation time; this function
///   re-verifies as a defense-in-depth check.
/// - **URI ref:** delegates to `fetcher` and recomputes SHA-256 over the
///   returned bytes, checking against `dr.content_hash` when present.
///   If `content_hash` is absent, returns the bytes unverified — the
///   producer chose not to commit to a hash, so the consumer is on its own.
/// - **Both URI and embedded:** rejected at validation; this function
///   relies on that and assumes exactly one is present.
pub async fn fetch_and_verify_data_ref(
    dr: &DataRef,
    fetcher: &impl DataRefFetcher,
) -> Result<Vec<u8>, AcdpError> {
    if let Some(emb) = &dr.embedded {
        let bytes = crate::validation::embedded_decoded_bytes(emb)?;
        if dr.content_hash.is_some() {
            crate::validation::verify_embedded_hash(dr)?;
        }
        return Ok(bytes);
    }
    let Some(location) = &dr.location else {
        return Err(AcdpError::SchemaViolation(
            "data_ref has neither embedded nor location — cannot fetch".into(),
        ));
    };
    let bytes = fetcher.fetch(location).await?;
    if let Some(declared) = &dr.content_hash {
        check_sha256(&bytes, declared)?;
    }
    Ok(bytes)
}

fn check_sha256(bytes: &[u8], declared: &ContentHash) -> Result<(), AcdpError> {
    let Some(declared_hex) = declared.as_str().strip_prefix("sha256:") else {
        return Err(AcdpError::SchemaViolation(format!(
            "data_ref content_hash must start with 'sha256:', got '{}'",
            declared.as_str()
        )));
    };
    let got = format!("{:x}", Sha256::digest(bytes));
    if got != declared_hex {
        // BUG-07: a content-hash mismatch on external data is a data-
        // integrity failure, not a cryptographic signature failure.
        // `InvalidSignature` implies the producer's Ed25519 signature
        // didn't verify, which is a key/key-binding problem — distinct
        // from "the bytes the URL returned today aren't the bytes the
        // producer hashed". `RemoteHashMismatch` is the correct shape.
        return Err(AcdpError::RemoteHashMismatch(format!(
            "data_ref content_hash mismatch: declared sha256:{declared_hex}, got sha256:{got}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::data_ref::{DataRefType, EmbeddedContent, EmbeddedEncoding};
    use sha2::{Digest, Sha256};

    /// Stub fetcher returning canned bytes — used to test the
    /// fetch-and-verify wrapper without touching the network.
    struct StubFetcher {
        bytes: Vec<u8>,
    }
    impl DataRefFetcher for StubFetcher {
        async fn fetch(&self, _location: &Location) -> Result<Vec<u8>, AcdpError> {
            Ok(self.bytes.clone())
        }
    }

    #[tokio::test]
    async fn fetch_and_verify_uri_ref_passes_with_matching_hash() {
        let bytes = b"hello-world".to_vec();
        let hash = format!("sha256:{:x}", Sha256::digest(&bytes));
        let dr = DataRef::uri_verified(
            DataRefType::RawData,
            "https://example.com/data",
            ContentHash(hash),
        );
        let got = fetch_and_verify_data_ref(
            &dr,
            &StubFetcher {
                bytes: bytes.clone(),
            },
        )
        .await
        .unwrap();
        assert_eq!(got, bytes);
    }

    #[tokio::test]
    async fn fetch_and_verify_uri_ref_fails_on_hash_mismatch() {
        let dr = DataRef::uri_verified(
            DataRefType::RawData,
            "https://example.com/data",
            ContentHash(format!("sha256:{}", "0".repeat(64))),
        );
        let err = fetch_and_verify_data_ref(
            &dr,
            &StubFetcher {
                bytes: b"different bytes".to_vec(),
            },
        )
        .await
        .unwrap_err();
        // BUG-07: data-ref hash mismatch is a data-integrity failure,
        // not a signature failure. `RemoteHashMismatch` is the correct
        // variant; the old code mistakenly used `InvalidSignature`.
        assert!(
            matches!(err, AcdpError::RemoteHashMismatch(_)),
            "expected RemoteHashMismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_and_verify_uri_ref_without_declared_hash_returns_bytes_unverified() {
        let dr = DataRef::uri(DataRefType::RawData, "https://example.com/data");
        let got = fetch_and_verify_data_ref(
            &dr,
            &StubFetcher {
                bytes: b"unverified".to_vec(),
            },
        )
        .await
        .unwrap();
        assert_eq!(got, b"unverified");
    }

    #[tokio::test]
    async fn fetch_and_verify_embedded_ref_returns_decoded_bytes() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let payload = b"embedded-bytes";
        let encoded = STANDARD.encode(payload);
        let dr = DataRef {
            ref_type: DataRefType::RawData,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Base64,
                content: serde_json::json!(encoded),
            }),
        };
        let got = fetch_and_verify_data_ref(&dr, &StubFetcher { bytes: vec![] })
            .await
            .unwrap();
        assert_eq!(got, payload);
    }

    /// SSRF policy rejects HTTP-only URIs at the boundary, before the
    /// stub fetcher ever runs. This verifies the fetcher-side gate; the
    /// helper itself just defers to whatever the fetcher returns.
    #[tokio::test]
    async fn https_fetcher_rejects_http_uri() {
        let f = HttpsDataRefFetcher::new();
        let err = f
            .fetch(&Location::Uri("http://insecure.example.com/x".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    /// Structured locators surface NotImplemented from the HTTPS fetcher
    /// — a custom fetcher would override.
    #[tokio::test]
    async fn https_fetcher_rejects_structured_locator() {
        let f = HttpsDataRefFetcher::new();
        let mut m = serde_json::Map::new();
        m.insert("scheme".into(), serde_json::json!("kafka.offset"));
        let err = f.fetch(&Location::Structured(m)).await.unwrap_err();
        assert!(matches!(err, AcdpError::NotImplemented(_)));
    }
}
