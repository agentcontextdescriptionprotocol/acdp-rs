//! Registry persistence abstraction (feature = "server").
//!
//! [`RegistryStore`] is the minimal contract a registry implementation
//! must satisfy: store an immutable [`Body`] under a registry-assigned
//! [`CtxId`], track the parent lineage, mark predecessors superseded,
//! and project search/lineage queries. The trait is synchronous and
//! object-safe so a [`RegistryServer`](super::server::RegistryServer)
//! can be parameterised over any backend (in-memory for tests, SQLite
//! for production, etc.) without an async runtime dependency.
//!
//! [`InMemoryStore`] is the reference implementation used by the
//! integration tests and intended as a drop-in for prototyping.

use std::sync::Mutex;

use crate::error::AcdpError;
use crate::types::{
    body::{Body, FullContext, RegistryState},
    primitives::{CtxId, LineageId, Status},
    search::{SearchParams, SearchResponse, SearchResult},
};

/// Abstract registry persistence backend.
///
/// Synchronous — the in-memory implementation is mutex-guarded; async
/// backends should wrap blocking calls with `spawn_blocking` at the
/// HTTP boundary.
pub trait RegistryStore: Send + Sync {
    /// Persist a freshly-assigned context. `body.ctx_id` and
    /// `body.lineage_id` are already populated by the server.
    fn put(&self, body: Body) -> Result<(), AcdpError>;

    /// Retrieve a stored context by `ctx_id`.
    fn get(&self, ctx_id: &CtxId) -> Result<Option<FullContext>, AcdpError>;

    /// All contexts in a lineage, oldest first.
    fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError>;

    /// Latest active version in a lineage (or the highest version if
    /// every entry has been superseded).
    fn current(&self, lineage_id: &LineageId) -> Result<Option<FullContext>, AcdpError>;

    /// Mark `ctx_id`'s registry state as `superseded`. Idempotent.
    fn mark_superseded(&self, ctx_id: &CtxId) -> Result<(), AcdpError>;

    /// First-version `ctx_id` for a lineage, used to derive the
    /// lineage_id of a supersession publish per RFC-ACDP-0001 §5.6.
    fn first_version_ctx_id(&self, lineage_id: &LineageId) -> Result<Option<CtxId>, AcdpError>;

    /// Keyword/filter search. Implementations may project a subset of
    /// fields per RFC-ACDP-0005 §2.2 `match_summary`.
    fn search(&self, params: &SearchParams) -> Result<SearchResponse, AcdpError>;
}

// ── In-memory reference implementation ───────────────────────────────────────

/// Minimal in-memory backend. Not durable; intended for tests and
/// prototyping. Concurrency-safe (a single `Mutex` over the table).
#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// All contexts keyed by `ctx_id`. Insertion-ordered per lineage
    /// thanks to the parallel `lineages` index.
    by_ctx: std::collections::BTreeMap<String, FullContext>,
    /// `lineage_id -> [ctx_id, ctx_id, ...]` in publish order.
    lineages: std::collections::BTreeMap<String, Vec<String>>,
}

impl InMemoryStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("InMemoryStore mutex poisoned")
    }
}

impl RegistryStore for InMemoryStore {
    fn put(&self, body: Body) -> Result<(), AcdpError> {
        let ctx_id = body.ctx_id.0.clone();
        let lineage_id = body.lineage_id.0.clone();
        let ctx = FullContext {
            body,
            registry_state: RegistryState {
                status: Status::Active,
                extensions: Default::default(),
            },
            registry_receipt: None,
        };
        let mut g = self.lock();
        if g.by_ctx.contains_key(&ctx_id) {
            return Err(AcdpError::SchemaViolation(format!(
                "duplicate ctx_id '{ctx_id}' in store"
            )));
        }
        g.by_ctx.insert(ctx_id.clone(), ctx);
        g.lineages.entry(lineage_id).or_default().push(ctx_id);
        Ok(())
    }

    fn get(&self, ctx_id: &CtxId) -> Result<Option<FullContext>, AcdpError> {
        Ok(self.lock().by_ctx.get(ctx_id.as_str()).cloned())
    }

    fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        let g = self.lock();
        let Some(ids) = g.lineages.get(lineage_id.as_str()) else {
            return Ok(Vec::new());
        };
        Ok(ids
            .iter()
            .filter_map(|id| g.by_ctx.get(id).cloned())
            .collect())
    }

    fn current(&self, lineage_id: &LineageId) -> Result<Option<FullContext>, AcdpError> {
        let g = self.lock();
        let Some(ids) = g.lineages.get(lineage_id.as_str()) else {
            return Ok(None);
        };
        // Prefer the last `Active`; fall back to the highest version.
        for id in ids.iter().rev() {
            if let Some(ctx) = g.by_ctx.get(id) {
                if matches!(ctx.registry_state.status, Status::Active) {
                    return Ok(Some(ctx.clone()));
                }
            }
        }
        Ok(ids.last().and_then(|id| g.by_ctx.get(id).cloned()))
    }

    fn mark_superseded(&self, ctx_id: &CtxId) -> Result<(), AcdpError> {
        let mut g = self.lock();
        if let Some(ctx) = g.by_ctx.get_mut(ctx_id.as_str()) {
            ctx.registry_state.status = Status::Superseded;
        }
        Ok(())
    }

    fn first_version_ctx_id(&self, lineage_id: &LineageId) -> Result<Option<CtxId>, AcdpError> {
        let g = self.lock();
        Ok(g.lineages
            .get(lineage_id.as_str())
            .and_then(|ids| ids.first().cloned())
            .map(CtxId))
    }

    fn search(&self, params: &SearchParams) -> Result<SearchResponse, AcdpError> {
        let g = self.lock();

        let q_lower = params.q.as_deref().map(str::to_lowercase);
        let domain = params.domain.as_deref();
        let agent = params.agent_id.as_deref();
        let context_type = params.context_type.as_deref();
        let derived_from = params.derived_from.as_deref();
        let tags: Option<Vec<&str>> = params.tags.as_deref().map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .collect()
        });

        let mut matches: Vec<&FullContext> = g
            .by_ctx
            .values()
            .filter(|ctx| {
                let body = &ctx.body;

                if let Some(q) = &q_lower {
                    let haystack = format!(
                        "{} {} {} {} {} {}",
                        body.title,
                        body.description.as_deref().unwrap_or(""),
                        body.summary.as_deref().unwrap_or(""),
                        body.domain.as_deref().unwrap_or(""),
                        body.agent_id.as_str(),
                        body.tags.as_ref().map(|t| t.join(" ")).unwrap_or_default(),
                    )
                    .to_lowercase();
                    if !haystack.contains(q) {
                        return false;
                    }
                }
                if let Some(d) = domain {
                    if body.domain.as_deref() != Some(d) {
                        return false;
                    }
                }
                if let Some(a) = agent {
                    if body.agent_id.as_str() != a {
                        return false;
                    }
                }
                if let Some(t) = context_type {
                    let body_type = serde_json::to_value(&body.context_type)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default();
                    if body_type != t {
                        return false;
                    }
                }
                if let Some(df) = derived_from {
                    if !body.derived_from.iter().any(|c| c.as_str() == df) {
                        return false;
                    }
                }
                if let Some(req_tags) = &tags {
                    let body_tags = body.tags.as_deref().unwrap_or(&[]);
                    if !req_tags.iter().all(|t| body_tags.iter().any(|bt| bt == t)) {
                        return false;
                    }
                }
                // Status filter — registry default is `active`.
                let want_status = params.status.as_deref().unwrap_or("active");
                if ctx.registry_state.status.as_str() != want_status {
                    return false;
                }
                true
            })
            .collect();

        // Newest first
        matches.sort_by_key(|c| std::cmp::Reverse(c.body.created_at));

        let limit = params.limit.unwrap_or(50).min(100) as usize;
        let projected: Vec<SearchResult> = matches
            .iter()
            .take(limit)
            .map(|ctx| SearchResult {
                ctx_id: ctx.body.ctx_id.clone(),
                lineage_id: ctx.body.lineage_id.clone(),
                agent_id: ctx.body.agent_id.clone(),
                title: ctx.body.title.clone(),
                summary: ctx.body.summary.clone(),
                context_type: ctx.body.context_type.clone(),
                domain: ctx.body.domain.clone(),
                created_at: ctx.body.created_at,
                status: ctx.registry_state.status.clone(),
            })
            .collect();

        Ok(SearchResponse {
            matches: projected,
            total_estimate: Some(matches.len() as u64),
            next_cursor: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use crate::producer::Producer;
    use crate::types::body::{DataPeriod, Signature};
    use crate::types::primitives::{AgentDid, ContentHash, ContextType, Visibility};
    use chrono::Utc;

    fn fake_body(ctx_id: &str, lineage_id: &str, title: &str) -> Body {
        Body {
            ctx_id: CtxId(ctx_id.into()),
            lineage_id: LineageId(lineage_id.into()),
            origin_registry: "registry.example.com".into(),
            created_at: Utc::now(),
            content_hash: ContentHash("sha256:0".into()),
            signature: Signature {
                algorithm: "ed25519".into(),
                key_id: "did:web:agents.example.com:test#key-1".into(),
                value: "A".repeat(88),
            },
            version: 1,
            supersedes: None,
            agent_id: AgentDid::new("did:web:agents.example.com:test"),
            contributors: vec![],
            title: title.into(),
            context_type: ContextType::DataSnapshot,
            data_refs: vec![],
            derived_from: vec![],
            visibility: Visibility::Public,
            audience: None,
            acdp_version: None,
            description: None,
            summary: None,
            tags: None,
            domain: None,
            expires_at: None,
            data_period: None,
            metadata: None,
            schema_uri: None,
            extensions: Default::default(),
        }
    }

    #[test]
    fn put_get_round_trip() {
        let s = InMemoryStore::new();
        let id = "acdp://r/12345678-1234-4321-8123-123456781234";
        let lin = "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111";
        s.put(fake_body(id, lin, "A")).unwrap();
        let got = s.get(&CtxId(id.into())).unwrap().unwrap();
        assert_eq!(got.body.title, "A");
        assert!(matches!(got.registry_state.status, Status::Active));
    }

    #[test]
    fn lineage_orders_by_publish_order() {
        let s = InMemoryStore::new();
        let lin = "lin:sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let v1 = "acdp://r/12345678-1234-4321-8123-000000000001";
        let v2 = "acdp://r/12345678-1234-4321-8123-000000000002";
        s.put(fake_body(v1, lin, "v1")).unwrap();
        s.put(fake_body(v2, lin, "v2")).unwrap();
        let lineage = s.lineage(&LineageId(lin.into())).unwrap();
        assert_eq!(lineage.len(), 2);
        assert_eq!(lineage[0].body.title, "v1");
        assert_eq!(lineage[1].body.title, "v2");
    }

    #[test]
    fn supersession_marks_predecessor() {
        let s = InMemoryStore::new();
        let lin = "lin:sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let v1 = "acdp://r/12345678-1234-4321-8123-000000000003";
        s.put(fake_body(v1, lin, "v1")).unwrap();
        s.mark_superseded(&CtxId(v1.into())).unwrap();
        let got = s.get(&CtxId(v1.into())).unwrap().unwrap();
        assert!(matches!(got.registry_state.status, Status::Superseded));
    }

    #[test]
    fn search_filters_by_status_default_active() {
        let s = InMemoryStore::new();
        let lin = "lin:sha256:4444444444444444444444444444444444444444444444444444444444444444";
        let v1 = "acdp://r/12345678-1234-4321-8123-000000000004";
        let v2 = "acdp://r/12345678-1234-4321-8123-000000000005";
        s.put(fake_body(v1, lin, "old")).unwrap();
        s.put(fake_body(v2, lin, "new")).unwrap();
        s.mark_superseded(&CtxId(v1.into())).unwrap();
        let resp = s
            .search(&SearchParams {
                q: Some("old".into()),
                ..Default::default()
            })
            .unwrap();
        // Only `active` matches — superseded "old" filtered out.
        assert_eq!(resp.matches.len(), 0);
        let resp = s
            .search(&SearchParams {
                q: Some("new".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(resp.matches.len(), 1);
    }

    /// End-to-end: producer → server pipeline using the actual signing
    /// path. Uses a builder and the `RegistryServer` (see server.rs)
    /// to confirm the integration story.
    #[test]
    fn store_round_trip_from_real_publish_request() {
        use crate::registry::server::RegistryServer;
        use crate::types::capabilities::{CapabilitiesDocument, Limits};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new("did:web:agents.example.com:test"),
            "did:web:agents.example.com:test#key-1",
        );
        let req = p
            .publish_request()
            .title("hello")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let caps = CapabilitiesDocument {
            acdp_version: "0.0.1".into(),
            registry_did: "did:web:registry.example.com".into(),
            supported_signature_algorithms: vec!["ed25519".into()],
            supported_did_methods: vec!["did:web".into()],
            profiles: vec!["acdp-registry-core".into()],
            limits: Limits {
                max_payload_bytes: 1_048_576,
                max_embedded_bytes: 65_536,
                idempotency_key_ttl_seconds: None,
            },
            read_authentication_methods: vec![],
            anonymous_public_reads: true,
            supports_idempotency_key: false,
            extensions: Default::default(),
        };

        let server = RegistryServer::new(InMemoryStore::new(), caps, "registry.example.com");
        let resp = server.publish(&req).unwrap();
        assert_eq!(resp.version, 1);
        let ctx = server.retrieve(&resp.ctx_id).unwrap().unwrap();
        assert_eq!(ctx.body.title, "hello");

        // Ignore unused imports under different feature combinations
        let _: Option<DataPeriod> = ctx.body.data_period.clone();
    }
}
