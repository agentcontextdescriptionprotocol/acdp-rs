//! `did:web` resolver — RFC-ACDP-0001 §5.11, step 3.

use crate::error::AcdpError;

#[cfg(feature = "client")]
use {
    super::document::DidDocument,
    lru::LruCache,
    std::num::NonZeroUsize,
    std::sync::{Arc, Mutex},
    std::time::{Duration, Instant},
};

#[cfg(feature = "client")]
const CACHE_MAX: Duration = Duration::from_secs(24 * 3600); // 24 hours
#[cfg(feature = "client")]
const DEFAULT_CACHE_CAPACITY: usize = 1000;

#[cfg(feature = "client")]
struct CacheEntry {
    doc: DidDocument,
    cached_at: Instant,
}

/// Resolves `did:web:…` DIDs to DID documents via HTTPS.
///
/// Caches resolved documents for 5–24 hours per §5.11 guidance, evicting
/// the least-recently-used entry once the cache reaches the configured
/// capacity (default 1000).
#[cfg(feature = "client")]
pub struct WebResolver {
    http: reqwest::Client,
    cache: Arc<Mutex<LruCache<String, CacheEntry>>>,
}

#[cfg(feature = "client")]
impl WebResolver {
    /// Build a resolver with the default LRU capacity (1000 entries).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CACHE_CAPACITY)
    }

    /// Build a resolver with a custom LRU capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity > 0");
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client for DID resolver");

        Self {
            http,
            cache: Arc::new(Mutex::new(LruCache::new(cap))),
        }
    }

    /// Resolve a `did:web:…` DID to a DID document.
    ///
    /// Hits the cache on repeated calls for the same DID.  Refreshes
    /// on any downstream verification failure if needed.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), fields(did = did)))]
    pub async fn resolve(&self, did: &str) -> Result<DidDocument, AcdpError> {
        // Check cache (mutates LRU recency on hit)
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(did) {
                if entry.cached_at.elapsed() < CACHE_MAX {
                    return Ok(entry.doc.clone());
                }
            }
        }

        let url = did_web_to_url(did)?;
        let resp = self
            .http
            .get(&url)
            .header("Accept", "application/did+json, application/json")
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() || e.is_connect() {
                    AcdpError::KeyResolutionUnreachable(e.to_string())
                } else {
                    AcdpError::KeyResolution(e.to_string())
                }
            })?;

        if !resp.status().is_success() {
            return Err(AcdpError::KeyResolution(format!(
                "DID document fetch returned HTTP {}",
                resp.status()
            )));
        }

        let doc: DidDocument = resp
            .json()
            .await
            .map_err(|e| AcdpError::KeyResolution(format!("DID document parse: {e}")))?;

        // Store in cache (evicts LRU on overflow)
        {
            let mut cache = self.cache.lock().unwrap();
            cache.put(
                did.to_string(),
                CacheEntry {
                    doc: doc.clone(),
                    cached_at: Instant::now(),
                },
            );
        }

        Ok(doc)
    }

    /// Invalidate a specific DID's cache entry, forcing a fresh fetch.
    pub fn invalidate(&self, did: &str) {
        self.cache.lock().unwrap().pop(did);
    }
}

#[cfg(feature = "client")]
impl Default for WebResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a `did:web:…` DID to its HTTPS URL per the `did:web` spec.
///
/// `did:web:example.com` → `https://example.com/.well-known/did.json`
/// `did:web:example.com:users:alice` → `https://example.com/users/alice/did.json`
pub fn did_web_to_url(did: &str) -> Result<String, AcdpError> {
    let rest = did
        .strip_prefix("did:web:")
        .ok_or_else(|| AcdpError::KeyResolution(format!("not a did:web DID: {did}")))?;

    let parts: Vec<&str> = rest.split(':').collect();
    let authority = urlencoding::decode(parts[0])
        .map_err(|e| AcdpError::KeyResolution(format!("authority decode: {e}")))?;

    if parts.len() == 1 {
        Ok(format!("https://{}/.well-known/did.json", authority))
    } else {
        let path = parts[1..].join("/");
        Ok(format!("https://{}/{}/did.json", authority, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_authority() {
        let url = did_web_to_url("did:web:example.com").unwrap();
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn path_authority() {
        let url = did_web_to_url("did:web:example.com:users:alice").unwrap();
        assert_eq!(url, "https://example.com/users/alice/did.json");
    }
}
