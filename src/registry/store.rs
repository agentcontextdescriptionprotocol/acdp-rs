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
    primitives::{AgentDid, CtxId, LineageId, Status, Visibility},
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

    /// Keyword/filter search. Implementations MUST apply the RFC-ACDP-0008
    /// §4.5 search-disclosure rules using `requester`:
    ///
    /// | Visibility   | Surfaces in search to                        |
    /// |--------------|----------------------------------------------|
    /// | `public`     | anyone                                       |
    /// | `restricted` | producer (`agent_id`) **or** any DID in `audience` |
    /// | `private`    | producer (`agent_id`) only — audience members must already know the ctx_id |
    ///
    /// `requester == None` represents an anonymous caller. Public
    /// contexts surface only when `anonymous_public_reads` is true (the
    /// capability flag from [`RegistryServer`](super::server::RegistryServer));
    /// the store implements the same predicate as `RegistryServer::retrieve`
    /// so the two endpoints stay symmetric (RFC-ACDP-0008 §4.5).
    ///
    /// Projection follows RFC-ACDP-0005 §2.2 `match_summary`.
    fn search(
        &self,
        params: &SearchParams,
        requester: Option<&AgentDid>,
        anonymous_public_reads: bool,
    ) -> Result<SearchResponse, AcdpError>;

    // ── Idempotency (RFC-ACDP-0003 §6) ─────────────────────────────────
    //
    // Stores supporting the `idempotency_key` capability MUST implement
    // these three methods. The default impls treat the store as
    // non-idempotent: lookup always returns `None`, record is a no-op,
    // evict is a no-op. A `RegistryServer` configured with
    // `caps.supports_idempotency_key = false` MUST never call them
    // (RFC-ACDP-0007 §3.2).

    /// Look up a prior publish record for `(agent_id, key)`.
    ///
    /// Returns `Some((content_hash, response))` if a record exists and
    /// has not expired. Scoping by `agent_id` prevents a malicious
    /// producer from poisoning another producer's key namespace
    /// (RFC-ACDP-0003 §6 — idem-004 fixture).
    fn idempotency_lookup(
        &self,
        _agent_id: &AgentDid,
        _key: &str,
    ) -> Result<Option<IdempotencyRecord>, AcdpError> {
        Ok(None)
    }

    /// Record a successful publish under `(agent_id, key)` with TTL
    /// `expires_at`. Calling on a store that does not support
    /// idempotency is a no-op.
    fn idempotency_record(
        &self,
        _agent_id: &AgentDid,
        _key: &str,
        _hash: &crate::types::primitives::ContentHash,
        _response: &crate::types::publish::PublishResponse,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AcdpError> {
        Ok(())
    }

    /// Evict records whose `expires_at` is past `now`. Implementations
    /// may call this on a janitor schedule or lazily at lookup time.
    fn idempotency_evict_expired(
        &self,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AcdpError> {
        Ok(())
    }
}

/// Cached publish response keyed by `(agent_id, idempotency_key)`
/// (RFC-ACDP-0003 §6).
#[derive(Debug, Clone)]
pub struct IdempotencyRecord {
    /// The original request's `content_hash`. A retry with the same key
    /// but a different hash MUST be rejected as `duplicate_publish`.
    pub content_hash: crate::types::primitives::ContentHash,
    /// The response the registry returned on the first acceptance.
    pub response: crate::types::publish::PublishResponse,
    /// Eviction time (TTL window from caps.limits.idempotency_key_ttl_seconds).
    pub expires_at: chrono::DateTime<chrono::Utc>,
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
    /// `(agent_did, idempotency_key) -> record` (RFC-ACDP-0003 §6).
    idempotency: std::collections::HashMap<(String, String), IdempotencyRecord>,
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

/// RFC-ACDP-0004 §4 — derive `Status::Expired` from `body.expires_at` at
/// read time so a registry that does not run a janitor still surfaces the
/// correct lifecycle status.
///
/// `Superseded` outranks `Expired` (consistent with the lifecycle precedence
/// in RFC-ACDP-0004 §4.1 — once a successor replaces a context, expiry of
/// the predecessor is irrelevant to the lineage's current view).
pub(crate) fn project_status(
    stored: &Status,
    body: &Body,
    now: chrono::DateTime<chrono::Utc>,
) -> Status {
    match stored {
        Status::Active => match body.expires_at {
            Some(exp) if exp <= now => Status::Expired,
            _ => Status::Active,
        },
        other => other.clone(),
    }
}

/// Materialize the effective view of a stored context: applies
/// [`project_status`] to override the stored status when expired.
pub(crate) fn project_context(
    mut ctx: FullContext,
    now: chrono::DateTime<chrono::Utc>,
) -> FullContext {
    ctx.registry_state.status = project_status(&ctx.registry_state.status, &ctx.body, now);
    ctx
}

/// RFC-ACDP-0008 §4.5 search-disclosure rule.
///
/// Note the asymmetry vs retrieval: a `Private` context surfaces in search
/// **only** to its producer — audience members must already know the
/// `ctx_id` to fetch it. `Restricted` surfaces to producer + audience.
///
/// `anonymous_public_reads` mirrors the capability advertisement
/// (RFC-ACDP-0008 §4.5): a registry that does NOT permit anonymous
/// public reads MUST suppress public contexts for unauthenticated
/// callers in both `retrieve` and `search`. The retrieval helper
/// already consults this flag; this function pulls it through to the
/// store-side search path (BUG-02).
fn can_surface_in_search(
    body: &Body,
    requester: Option<&AgentDid>,
    anonymous_public_reads: bool,
) -> bool {
    match body.visibility {
        Visibility::Public => anonymous_public_reads || requester.is_some(),
        Visibility::Restricted => match requester {
            None => false,
            Some(r) => {
                r == &body.agent_id
                    || body
                        .audience
                        .as_deref()
                        .is_some_and(|a| a.iter().any(|d| d == r))
            }
        },
        Visibility::Private => requester == Some(&body.agent_id),
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
        let now = chrono::Utc::now();
        Ok(self
            .lock()
            .by_ctx
            .get(ctx_id.as_str())
            .cloned()
            .map(|c| project_context(c, now)))
    }

    fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        let now = chrono::Utc::now();
        let g = self.lock();
        let Some(ids) = g.lineages.get(lineage_id.as_str()) else {
            return Ok(Vec::new());
        };
        Ok(ids
            .iter()
            .filter_map(|id| g.by_ctx.get(id).cloned().map(|c| project_context(c, now)))
            .collect())
    }

    fn current(&self, lineage_id: &LineageId) -> Result<Option<FullContext>, AcdpError> {
        let now = chrono::Utc::now();
        let g = self.lock();
        let Some(ids) = g.lineages.get(lineage_id.as_str()) else {
            return Ok(None);
        };
        // RFC-ACDP-0004 §5: "Returns the unique version that has no
        // successor. If no such version exists, returns not_found."
        // Walk newest-to-oldest and return the first non-`Superseded`
        // version. Both `Active` and `Expired` count — an expired
        // body that hasn't been replaced is still the latest, and the
        // consumer needs to see it (with status=Expired) to know it
        // has lapsed.
        //
        // BUG-04: an earlier fallback returned the last entry even when
        // every version was `Superseded`; that's a protocol violation.
        // Now we return `None` instead.
        for id in ids.iter().rev() {
            if let Some(ctx) = g.by_ctx.get(id) {
                let projected = project_context(ctx.clone(), now);
                if !matches!(projected.registry_state.status, Status::Superseded) {
                    return Ok(Some(projected));
                }
            }
        }
        Ok(None)
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

    fn idempotency_lookup(
        &self,
        agent_id: &AgentDid,
        key: &str,
    ) -> Result<Option<IdempotencyRecord>, AcdpError> {
        // Lazy TTL eviction at lookup time keeps the table bounded
        // without requiring a janitor — see idempotency_evict_expired.
        self.idempotency_evict_expired(chrono::Utc::now())?;
        let g = self.lock();
        Ok(g.idempotency
            .get(&(agent_id.as_str().to_string(), key.to_string()))
            .cloned())
    }

    fn idempotency_record(
        &self,
        agent_id: &AgentDid,
        key: &str,
        hash: &crate::types::primitives::ContentHash,
        response: &crate::types::publish::PublishResponse,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AcdpError> {
        let mut g = self.lock();
        g.idempotency.insert(
            (agent_id.as_str().to_string(), key.to_string()),
            IdempotencyRecord {
                content_hash: hash.clone(),
                response: response.clone(),
                expires_at,
            },
        );
        Ok(())
    }

    fn idempotency_evict_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AcdpError> {
        let mut g = self.lock();
        g.idempotency.retain(|_, r| r.expires_at > now);
        Ok(())
    }

    fn search(
        &self,
        params: &SearchParams,
        requester: Option<&AgentDid>,
        anonymous_public_reads: bool,
    ) -> Result<SearchResponse, AcdpError> {
        let g = self.lock();
        let now = chrono::Utc::now();

        let q_lower = params.q.as_deref().map(str::to_lowercase);
        let domain = params.domain.as_deref();
        let agent = params.agent_id.as_deref();
        let context_type = params.context_type.as_deref();
        let derived_from = params.derived_from.as_deref();
        let schema_uri = params.schema_uri.as_deref();
        let tags: Option<Vec<&str>> = params.tags.as_deref().map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .collect()
        });

        // BUG-10: parse date-time filter params at the boundary so the
        // hot loop just compares DateTime<Utc> values.
        let created_after = parse_opt_rfc3339(&params.created_after)?;
        let created_before = parse_opt_rfc3339(&params.created_before)?;
        let dp_start_after = parse_opt_rfc3339(&params.data_period_start_after)?;
        let dp_end_before = parse_opt_rfc3339(&params.data_period_end_before)?;
        let expires_after = parse_opt_rfc3339(&params.expires_after)?;
        let expires_before = parse_opt_rfc3339(&params.expires_before)?;

        let mut matches: Vec<&FullContext> = g
            .by_ctx
            .values()
            .filter(|ctx| {
                let body = &ctx.body;

                // RFC-ACDP-0008 §4.5 search-disclosure gate (note the
                // private/restricted asymmetry: private contexts surface
                // in search only to their producer).
                if !can_surface_in_search(body, requester, anonymous_public_reads) {
                    return false;
                }

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
                if let Some(uri) = schema_uri {
                    if body.schema_uri.as_deref() != Some(uri) {
                        return false;
                    }
                }
                if let Some(after) = created_after {
                    if body.created_at < after {
                        return false;
                    }
                }
                if let Some(before) = created_before {
                    if body.created_at > before {
                        return false;
                    }
                }
                if let Some(after) = dp_start_after {
                    match &body.data_period {
                        Some(p) if p.start >= after => {}
                        _ => return false,
                    }
                }
                if let Some(before) = dp_end_before {
                    match &body.data_period {
                        Some(p) if p.end <= before => {}
                        _ => return false,
                    }
                }
                if let Some(after) = expires_after {
                    match body.expires_at {
                        Some(e) if e >= after => {}
                        _ => return false,
                    }
                }
                if let Some(before) = expires_before {
                    match body.expires_at {
                        Some(e) if e <= before => {}
                        _ => return false,
                    }
                }
                // Status filter — registry default is `active`. Compare
                // against PROJECTED status so a stored-Active body whose
                // expires_at has passed is filtered out (RFC-ACDP-0004 §4).
                let want_status = params.status.as_deref().unwrap_or("active");
                let effective = project_status(&ctx.registry_state.status, body, now);
                if effective.as_str() != want_status {
                    return false;
                }
                true
            })
            .collect();

        // Newest first; IMP-03 — fall back to ctx_id for a deterministic
        // total order when many contexts share a millisecond.
        matches.sort_by(|a, b| {
            b.body
                .created_at
                .cmp(&a.body.created_at)
                .then_with(|| a.body.ctx_id.as_str().cmp(b.body.ctx_id.as_str()))
        });

        // BUG-10 cursor: opaque base64 of "<created_at_ms>:<ctx_id>".
        // ≥1h validity is implicit — cursors do not embed a timestamp,
        // so they remain valid until the underlying context is deleted.
        let cursor_anchor = params
            .cursor
            .as_deref()
            .map(decode_cursor)
            .transpose()?
            .flatten();
        if let Some((anchor_ms, anchor_id)) = &cursor_anchor {
            matches.retain(|c| {
                let ms = c.body.created_at.timestamp_millis();
                ms < *anchor_ms || (ms == *anchor_ms && c.body.ctx_id.as_str() > anchor_id.as_str())
            });
        }

        let limit = params.limit.unwrap_or(50).min(100) as usize;
        let next_cursor = if matches.len() > limit {
            matches.get(limit - 1).map(|c| {
                encode_cursor(c.body.created_at.timestamp_millis(), c.body.ctx_id.as_str())
            })
        } else {
            None
        };
        let total_estimate = Some(matches.len() as u64);

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
                status: project_status(&ctx.registry_state.status, &ctx.body, now),
                // RFC-ACDP-0008 §4.5: only disclose visibility when the
                // requester is authorized for it. Public is always safe.
                // For restricted/private, the search filter above guarantees
                // the requester is producer-or-audience, so it's safe to
                // surface the label.
                visibility: Some(ctx.body.visibility.clone()),
            })
            .collect();

        Ok(SearchResponse {
            matches: projected,
            total_estimate,
            next_cursor,
        })
    }
}

/// Parse an optional RFC 3339 string parameter; surface a
/// [`AcdpError::SchemaViolation`] on malformed input.
fn parse_opt_rfc3339(
    s: &Option<String>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AcdpError> {
    let Some(raw) = s.as_deref() else {
        return Ok(None);
    };
    let dt = chrono::DateTime::parse_from_rfc3339(raw)
        .map_err(|e| AcdpError::SchemaViolation(format!("malformed datetime '{raw}': {e}")))?;
    Ok(Some(dt.with_timezone(&chrono::Utc)))
}

/// Opaque cursor encoding — base64 of `<created_at_millis>:<ctx_id>`.
/// Plain `STANDARD` engine so cursors are stable across machines.
fn encode_cursor(created_at_ms: i64, ctx_id: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(format!("{created_at_ms}:{ctx_id}"))
}

fn decode_cursor(s: &str) -> Result<Option<(i64, String)>, AcdpError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = STANDARD
        .decode(s)
        .map_err(|_| AcdpError::InvalidCursor("cursor is not valid base64".into()))?;
    let decoded = String::from_utf8(bytes)
        .map_err(|_| AcdpError::InvalidCursor("cursor is not utf-8".into()))?;
    let (ms_str, id) = decoded
        .split_once(':')
        .ok_or_else(|| AcdpError::InvalidCursor("cursor missing ':' separator".into()))?;
    let ms: i64 = ms_str
        .parse()
        .map_err(|_| AcdpError::InvalidCursor("cursor anchor millis is not an integer".into()))?;
    Ok(Some((ms, id.to_string())))
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

    // BUG-11 — Status::Expired derived from body.expires_at at read time.

    fn expired_body(
        ctx_id: &str,
        lineage_id: &str,
        title: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Body {
        let mut b = fake_body(ctx_id, lineage_id, title);
        b.expires_at = Some(expires_at);
        b
    }

    #[test]
    fn get_projects_active_to_expired_when_past_expires_at() {
        use chrono::Duration;
        let s = InMemoryStore::new();
        let lin = "lin:sha256:5555555555555555555555555555555555555555555555555555555555555555";
        let id = "acdp://r/12345678-1234-4321-8123-000000000006";
        s.put(expired_body(
            id,
            lin,
            "old",
            chrono::Utc::now() - Duration::hours(1),
        ))
        .unwrap();
        let got = s.get(&CtxId(id.into())).unwrap().unwrap();
        assert!(
            matches!(got.registry_state.status, Status::Expired),
            "expected Status::Expired projection, got {:?}",
            got.registry_state.status
        );
    }

    #[test]
    fn get_keeps_active_when_expires_at_in_future() {
        use chrono::Duration;
        let s = InMemoryStore::new();
        let lin = "lin:sha256:6666666666666666666666666666666666666666666666666666666666666666";
        let id = "acdp://r/12345678-1234-4321-8123-000000000007";
        s.put(expired_body(
            id,
            lin,
            "fresh",
            chrono::Utc::now() + Duration::hours(1),
        ))
        .unwrap();
        let got = s.get(&CtxId(id.into())).unwrap().unwrap();
        assert!(matches!(got.registry_state.status, Status::Active));
    }

    #[test]
    fn search_status_active_filters_out_expired() {
        use chrono::Duration;
        let s = InMemoryStore::new();
        let lin = "lin:sha256:7777777777777777777777777777777777777777777777777777777777777777";
        let id = "acdp://r/12345678-1234-4321-8123-000000000008";
        s.put(expired_body(
            id,
            lin,
            "old",
            chrono::Utc::now() - Duration::hours(1),
        ))
        .unwrap();
        let resp = s.search(&SearchParams::default(), None, true).unwrap();
        assert!(
            resp.matches.is_empty(),
            "expired must not surface under status=active default"
        );
        // Asking for `expired` SHOULD surface it.
        let resp = s
            .search(
                &SearchParams {
                    status: Some("expired".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(resp.matches.len(), 1);
    }

    /// BUG-10 — date/time filter is honored.
    #[test]
    fn search_filters_by_created_after() {
        let s = InMemoryStore::new();
        let lin = "lin:sha256:8888888888888888888888888888888888888888888888888888888888888888";
        let mut body = fake_body(
            "acdp://r/12345678-1234-4321-8123-000000000009",
            lin,
            "match",
        );
        body.created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        s.put(body).unwrap();
        // `created_after` AFTER body.created_at → 0 matches
        let resp = s
            .search(
                &SearchParams {
                    created_after: Some("2026-02-01T00:00:00.000Z".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(resp.matches.len(), 0);
        // `created_after` BEFORE body.created_at → 1 match
        let resp = s
            .search(
                &SearchParams {
                    created_after: Some("2025-12-01T00:00:00.000Z".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(resp.matches.len(), 1);
    }

    #[test]
    fn search_invalid_rfc3339_filter_rejected() {
        let s = InMemoryStore::new();
        let err = s
            .search(
                &SearchParams {
                    created_after: Some("not-a-date".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    /// BUG-10 cursor round-trips and pages correctly.
    #[test]
    fn search_cursor_pages_results() {
        let s = InMemoryStore::new();
        let lin = "lin:sha256:9999999999999999999999999999999999999999999999999999999999999999";
        // Insert 5 contexts with distinct created_at so order is deterministic.
        let base = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for i in 0..5u8 {
            let mut body = fake_body(
                &format!("acdp://r/12345678-1234-4321-8123-00000000010{i}"),
                lin,
                "match",
            );
            body.created_at = base + chrono::Duration::minutes(i as i64);
            s.put(body).unwrap();
        }
        let p1 = s
            .search(
                &SearchParams {
                    limit: Some(2),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(p1.matches.len(), 2);
        let cursor = p1.next_cursor.expect("page 1 should carry a cursor");
        let p2 = s
            .search(
                &SearchParams {
                    limit: Some(2),
                    cursor: Some(cursor.clone()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(p2.matches.len(), 2);
        // No overlap between page 1 and page 2.
        for r in &p2.matches {
            assert!(
                !p1.matches.iter().any(|q| q.ctx_id == r.ctx_id),
                "page 2 overlapped page 1"
            );
        }
    }

    #[test]
    fn search_malformed_cursor_rejected() {
        let s = InMemoryStore::new();
        let err = s
            .search(
                &SearchParams {
                    cursor: Some("not_base64!@#".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap_err();
        assert!(matches!(err, AcdpError::InvalidCursor(_)));
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
            .search(
                &SearchParams {
                    q: Some("old".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        // Only `active` matches — superseded "old" filtered out.
        assert_eq!(resp.matches.len(), 0);
        let resp = s
            .search(
                &SearchParams {
                    q: Some("new".into()),
                    ..Default::default()
                },
                None,
                true,
            )
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
        let resp = server.publish_unverified_for_tests(&req).unwrap();
        assert_eq!(resp.version, 1);
        let ctx = server.retrieve(&resp.ctx_id, None).unwrap().unwrap();
        assert_eq!(ctx.body.title, "hello");

        // Ignore unused imports under different feature combinations
        let _: Option<DataPeriod> = ctx.body.data_period.clone();
    }
}
