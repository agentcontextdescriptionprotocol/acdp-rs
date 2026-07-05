use crate::error::AcdpError;
use serde::{Deserialize, Serialize};

// ── Opaque identifier newtypes ───────────────────────────────────────────────

/// `acdp://<authority>/<uuid-v4>` — registry-assigned context identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CtxId(pub String);

impl CtxId {
    /// Underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract the authority (DNS hostname) component.
    pub fn authority(&self) -> &str {
        self.0
            .strip_prefix("acdp://")
            .and_then(|s| s.split('/').next())
            .unwrap_or("")
    }

    /// Validate against `acdp-common.schema.json#/$defs/ctx_id`.
    ///
    /// Form: `acdp://<lowercase-DNS-authority>/<v4-uuid>`. The UUID's
    /// version digit (13th hex char) MUST be `4` and the variant digit
    /// (17th hex char) MUST be one of `8`, `9`, `a`, `b`.
    pub fn parse(s: impl Into<String>) -> Result<Self, AcdpError> {
        let s: String = s.into();
        let rest = s.strip_prefix("acdp://").ok_or_else(|| {
            AcdpError::SchemaViolation(format!("ctx_id must start with 'acdp://', got: {s}"))
        })?;
        let (authority, uuid_str) = rest
            .split_once('/')
            .ok_or_else(|| AcdpError::SchemaViolation(format!("ctx_id missing '/<uuid>': {s}")))?;
        if !is_valid_dns_authority(authority) {
            return Err(AcdpError::SchemaViolation(format!(
                "ctx_id authority '{authority}' is not a lowercase DNS hostname"
            )));
        }
        if !is_valid_uuid_v4(uuid_str) {
            return Err(AcdpError::SchemaViolation(format!(
                "ctx_id uuid '{uuid_str}' is not a lowercase v4 UUID"
            )));
        }
        Ok(Self(s))
    }

    /// Extract the UUID component, if `self.0` is well-formed.
    pub fn uuid(&self) -> Option<uuid::Uuid> {
        let rest = self.0.strip_prefix("acdp://")?;
        let (_authority, uuid_str) = rest.split_once('/')?;
        uuid::Uuid::parse_str(uuid_str).ok()
    }
}

impl std::fmt::Display for CtxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `lin:sha256:<64-lowercase-hex>` — registry-assigned lineage identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LineageId(pub String);

impl LineageId {
    /// Underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate against `acdp-common.schema.json#/$defs/lineage_id`.
    /// Form: `lin:sha256:<64-lowercase-hex>`.
    pub fn parse(s: impl Into<String>) -> Result<Self, AcdpError> {
        let s: String = s.into();
        let hex = s.strip_prefix("lin:sha256:").ok_or_else(|| {
            AcdpError::SchemaViolation(format!(
                "lineage_id must start with 'lin:sha256:', got: {s}"
            ))
        })?;
        if hex.len() != 64 || !is_lowercase_hex(hex) {
            return Err(AcdpError::SchemaViolation(format!(
                "lineage_id digest must be 64 lowercase hex chars, got: {hex}"
            )));
        }
        Ok(Self(s))
    }
}

impl std::fmt::Display for LineageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `sha256:<64-lowercase-hex>` — content-addressable hash with algorithm prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash(pub String);

impl ContentHash {
    /// Underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate against `acdp-common.schema.json#/$defs/content_hash`.
    /// Form: `sha256:<64-lowercase-hex>`.
    pub fn parse(s: impl Into<String>) -> Result<Self, AcdpError> {
        let s: String = s.into();
        let hex = s.strip_prefix("sha256:").ok_or_else(|| {
            AcdpError::SchemaViolation(format!("content_hash must start with 'sha256:', got: {s}"))
        })?;
        if hex.len() != 64 || !is_lowercase_hex(hex) {
            return Err(AcdpError::SchemaViolation(format!(
                "content_hash digest must be 64 lowercase hex chars, got: {hex}"
            )));
        }
        Ok(Self(s))
    }
}

impl std::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A Decentralized Identifier — v0.1.0 mandates `did:web`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentDid(pub String);

impl AgentDid {
    /// Construct without validation (back-compat).
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate against `acdp-common.schema.json#/$defs/did`.
    ///
    /// Pattern: `^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$`. Length 7..=2048.
    /// Note: full method-specific validation (e.g. did:web hostname syntax)
    /// is delegated to the resolver per RFC-ACDP-0001 §5.11.
    pub fn parse(s: impl Into<String>) -> Result<Self, AcdpError> {
        let s: String = s.into();
        if s.len() < 7 || s.len() > 2048 {
            return Err(AcdpError::SchemaViolation(format!(
                "DID length {} not in 7..=2048",
                s.len()
            )));
        }
        let rest = s
            .strip_prefix("did:")
            .ok_or_else(|| AcdpError::SchemaViolation(format!("DID missing 'did:' prefix: {s}")))?;
        let (method, id) = rest.split_once(':').ok_or_else(|| {
            AcdpError::SchemaViolation(format!("DID must have method:id form: {s}"))
        })?;
        if method.is_empty()
            || !method
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err(AcdpError::SchemaViolation(format!(
                "DID method '{method}' must match [a-z0-9]+"
            )));
        }
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '%' | '-'))
        {
            return Err(AcdpError::SchemaViolation(format!(
                "DID method-specific id '{id}' contains invalid characters"
            )));
        }
        Ok(Self(s))
    }

    /// Validate and require `did:web:` (RFC-ACDP-0001 §5.4 mandate for v0.1.0).
    pub fn parse_web(s: impl Into<String>) -> Result<Self, AcdpError> {
        let parsed = Self::parse(s)?;
        if !parsed.0.starts_with("did:web:") {
            return Err(AcdpError::SchemaViolation(format!(
                "v0.1.0 producers MUST use did:web; got: {}",
                parsed.0
            )));
        }
        Ok(parsed)
    }
}

impl std::fmt::Display for AgentDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Enumerations ─────────────────────────────────────────────────────────────

/// Visibility level of a context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Restricted,
    Private,
}

/// Registered context types plus open-ended custom namespace.
///
/// Wire form is a single string. Standard values (`data_snapshot`,
/// `analysis`, `prediction`, `alert`, and — since acdp/0.3.0 —
/// `key-revocation`, RFC-ACDP-0014 §4) deserialize to the named variants;
/// any other value MUST be a namespaced custom type matching
/// `^[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*$` (e.g. `finance:portfolio_snapshot`)
/// per `acdp-common.schema.json#/$defs/context_type`. Inputs that match
/// neither are rejected at deserialization time so the type cannot encode
/// schema-invalid context types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextType {
    /// `data_snapshot` — point-in-time data.
    DataSnapshot,
    /// `analysis`.
    Analysis,
    /// `prediction`.
    Prediction,
    /// `alert`.
    Alert,
    /// `key-revocation` — a producer's time-scoped declaration that one
    /// of its signing keys is compromised (RFC-ACDP-0014 §4; standard in
    /// acdp/0.3.0). The interim form published on pre-0.3.0 registries
    /// is the namespaced custom type `acdp:key-revocation`
    /// ([`ContextType::Custom`]); use [`ContextType::is_key_revocation`]
    /// to recognize both, as 0.3.0 consumers MUST (RFC-ACDP-0014 §10).
    KeyRevocation,
    /// Namespaced custom type, e.g. `finance:portfolio_snapshot`.
    /// MUST match `^[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*$`.
    Custom(String),
}

impl ContextType {
    /// The interim namespaced form of `key-revocation` accepted from
    /// pre-0.3.0 registries (RFC-ACDP-0014 §10).
    pub const KEY_REVOCATION_INTERIM: &'static str = "acdp:key-revocation";

    /// True when this type denotes an RFC-ACDP-0014 key-revocation
    /// context: the standard `key-revocation` form or the interim
    /// `acdp:key-revocation` custom form, which 0.3.0 consumers MUST
    /// treat as equivalent when the body satisfies §4–§5
    /// (RFC-ACDP-0014 §10).
    pub fn is_key_revocation(&self) -> bool {
        match self {
            ContextType::KeyRevocation => true,
            ContextType::Custom(s) => s == Self::KEY_REVOCATION_INTERIM,
            _ => false,
        }
    }
}

impl Serialize for ContextType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = match self {
            ContextType::DataSnapshot => "data_snapshot",
            ContextType::Analysis => "analysis",
            ContextType::Prediction => "prediction",
            ContextType::Alert => "alert",
            ContextType::KeyRevocation => "key-revocation",
            ContextType::Custom(s) => s.as_str(),
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for ContextType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "data_snapshot" => ContextType::DataSnapshot,
            "analysis" => ContextType::Analysis,
            "prediction" => ContextType::Prediction,
            "alert" => ContextType::Alert,
            "key-revocation" => ContextType::KeyRevocation,
            other => {
                // Custom types MUST be namespaced
                if !is_namespaced_context_type(other) {
                    return Err(serde::de::Error::custom(format!(
                        "context_type '{other}' is not a known ACDP type and does not match the \
                         namespaced custom pattern ^[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*$"
                    )));
                }
                ContextType::Custom(s)
            }
        })
    }
}

fn is_namespaced_context_type(s: &str) -> bool {
    let Some((ns, name)) = s.split_once(':') else {
        return false;
    };
    if ns.is_empty()
        || !ns.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        || !ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return false;
    }
    if name.is_empty()
        || !name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
    {
        return false;
    }
    true
}

/// Registry-derived lifecycle status.
///
/// The schema (`acdp-common.schema.json#/$defs/status`) defines an open
/// `^[a-z][a-z0-9_]*$` pattern, length 1..=64. v0.1.0 emits `active`,
/// `superseded`, `expired`; future versions add `retracted`
/// (RFC-ACDP-0009 §2.1) and possibly others. Consumers MUST tolerate
/// unknown values matching the pattern; values that DO NOT match the
/// pattern (uppercase, whitespace, empty) are rejected on
/// deserialization as malformed registry state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// First-class, current version of its lineage.
    Active,
    /// Replaced by a later version in the same lineage.
    Superseded,
    /// Past `expires_at`.
    Expired,
    /// A status string this version of the library does not recognize.
    /// Per the spec, treat as `active` for read-side decisions until upgrade.
    Other(String),
}

impl Status {
    /// Validate against the schema pattern `^[a-z][a-z0-9_]*$`, length 1..=64.
    fn pattern_ok(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 64
            && s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }

    /// Wire-form string representation, matching the schema enum.
    pub fn as_str(&self) -> &str {
        match self {
            Status::Active => "active",
            Status::Superseded => "superseded",
            Status::Expired => "expired",
            Status::Other(s) => s,
        }
    }

    /// Parse a status string from any source, validating the pattern.
    pub fn parse(s: &str) -> Result<Self, AcdpError> {
        match s {
            "active" => Ok(Status::Active),
            "superseded" => Ok(Status::Superseded),
            "expired" => Ok(Status::Expired),
            other => {
                if !Self::pattern_ok(other) {
                    return Err(AcdpError::SchemaViolation(format!(
                        "status '{other}' does not match the open-enum pattern \
                         ^[a-z][a-z0-9_]*$ (length 1..=64)"
                    )));
                }
                Ok(Status::Other(other.to_string()))
            }
        }
    }
}

impl Serialize for Status {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Status {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Status::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl Status {
    /// Returns `true` if status is `Active`.
    pub fn is_active(&self) -> bool {
        matches!(self, Status::Active)
    }

    /// Returns `true` if status is `Superseded`.
    pub fn is_superseded(&self) -> bool {
        matches!(self, Status::Superseded)
    }

    /// Returns `true` if status is `Expired`.
    pub fn is_expired(&self) -> bool {
        matches!(self, Status::Expired)
    }

    /// Returns the unrecognized status string, if any.
    pub fn as_other(&self) -> Option<&str> {
        match self {
            Status::Other(s) => Some(s),
            _ => None,
        }
    }

    /// Forward-compatible degradation: maps unknown statuses to
    /// [`Status::Active`] for functional decisions, per RFC-ACDP-0004 §4.1
    /// ("v0.1.0 consumers MUST tolerate unknown status values and SHOULD
    /// treat them as 'active' until they upgrade"). Callers MUST log the
    /// original `Other(_)` value so the unknown is observable.
    pub fn known_or_active(&self) -> Status {
        match self {
            Status::Other(_) => Status::Active,
            s => s.clone(),
        }
    }
}

// ── Validation helpers (private) ─────────────────────────────────────────────

fn is_lowercase_hex(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Validate a bare DNS authority: lowercase ASCII labels separated by
/// dots, each `1..=63` chars of `[a-z0-9-]` with no leading/trailing
/// hyphen, total `<= 253`. Rejects uppercase, underscores, and ports.
///
/// Public so `acdp-validation` can reuse it for
/// `origin_registry` (BUG-02) — the schema's `hostname` type and
/// `CtxId`'s authority share exactly this grammar.
pub fn is_valid_dns_authority(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && label
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

/// Validate a UUID-v4 string per the ACDP ctx_id schema:
/// 8-4-4-4-12 lowercase hex with version digit `4` and variant digit in 8/9/a/b.
fn is_valid_uuid_v4(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !(b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                    return false;
                }
            }
        }
    }
    bytes[14] == b'4' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn known_status_values_deserialize() {
        let s: Status = serde_json::from_value(json!("active")).unwrap();
        assert!(s.is_active());
        let s: Status = serde_json::from_value(json!("superseded")).unwrap();
        assert!(s.is_superseded());
        let s: Status = serde_json::from_value(json!("expired")).unwrap();
        assert!(s.is_expired());
    }

    #[test]
    fn unknown_status_value_falls_back_to_other() {
        // RFC-ACDP-0009 §2.1 reserves `retracted` for v0.1+; v0.1.0 consumers
        // MUST tolerate it without panicking.
        let s: Status = serde_json::from_value(json!("retracted")).unwrap();
        assert_eq!(s.as_other(), Some("retracted"));
        assert!(!s.is_active());
        assert!(!s.is_superseded());
        assert!(!s.is_expired());

        let s: Status = serde_json::from_value(json!("archived")).unwrap();
        assert_eq!(s.as_other(), Some("archived"));
    }

    #[test]
    fn ctx_id_authority() {
        let id = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
        assert_eq!(id.authority(), "registry.example.com");
    }

    #[test]
    fn ctx_id_parse_valid() {
        let id = CtxId::parse(
            "acdp://registry.example.com/12345678-1234-4321-8123-123456781234".to_string(),
        )
        .unwrap();
        assert_eq!(id.authority(), "registry.example.com");
        assert!(id.uuid().is_some());
    }

    #[test]
    fn ctx_id_parse_rejects_uppercase_authority() {
        assert!(
            CtxId::parse("acdp://Registry.Example.com/12345678-1234-4321-8123-123456781234")
                .is_err()
        );
    }

    #[test]
    fn ctx_id_parse_rejects_non_v4_uuid() {
        // Version digit (13th hex char) is `1`, not `4`
        assert!(
            CtxId::parse("acdp://registry.example.com/12345678-1234-1321-8123-123456781234")
                .is_err()
        );
    }

    #[test]
    fn ctx_id_parse_rejects_bad_variant() {
        // Variant digit (17th hex char) is `0`, not 8/9/a/b
        assert!(
            CtxId::parse("acdp://registry.example.com/12345678-1234-4321-0123-123456781234")
                .is_err()
        );
    }

    #[test]
    fn lineage_id_parse() {
        let l = LineageId::parse(
            "lin:sha256:b14ccd2a8b34530309255db68c151a10689b6a82feb30aff9222d54fdd871720"
                .to_string(),
        )
        .unwrap();
        assert!(l.as_str().starts_with("lin:sha256:"));
        assert!(LineageId::parse("lin:sha256:abc").is_err());
        assert!(LineageId::parse(
            "lin:sha256:B14CCD2A8B34530309255DB68C151A10689B6A82FEB30AFF9222D54FDD871720"
        )
        .is_err());
    }

    #[test]
    fn content_hash_parse() {
        ContentHash::parse(
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".to_string(),
        )
        .unwrap();
        assert!(ContentHash::parse("md5:abc").is_err());
        assert!(ContentHash::parse("sha256:zzzz").is_err());
    }

    #[test]
    fn agent_did_parse_valid() {
        AgentDid::parse("did:web:agents.example.com:test").unwrap();
        AgentDid::parse("did:key:z6Mki...").unwrap();
    }

    #[test]
    fn agent_did_parse_rejects_invalid_method() {
        assert!(AgentDid::parse("did:WEB:agents.example.com").is_err());
        assert!(AgentDid::parse("did::test").is_err());
        assert!(AgentDid::parse("notadid").is_err());
    }

    #[test]
    fn agent_did_parse_web_enforces_method() {
        AgentDid::parse_web("did:web:agents.example.com:test").unwrap();
        assert!(AgentDid::parse_web("did:key:z6Mki...").is_err());
    }

    #[test]
    fn agent_did_new_skips_validation() {
        // `new` is the unchecked back-compat constructor — it must NOT reject.
        let did = AgentDid::new("not-a-did");
        assert_eq!(did.as_str(), "not-a-did");
    }

    #[test]
    fn agent_did_parse_rejects_length_bounds() {
        assert!(AgentDid::parse("did:w:").is_err(), "too short / empty id");
        let long = format!("did:web:{}", "a".repeat(2100));
        assert!(AgentDid::parse(long).is_err(), "over 2048 chars");
    }

    // ── ContextType ────────────────────────────────────────────────────────

    #[test]
    fn context_type_known_values_round_trip() {
        for (s, expect) in [
            ("data_snapshot", ContextType::DataSnapshot),
            ("analysis", ContextType::Analysis),
            ("prediction", ContextType::Prediction),
            ("alert", ContextType::Alert),
            ("key-revocation", ContextType::KeyRevocation),
        ] {
            let parsed: ContextType = serde_json::from_value(json!(s)).unwrap();
            assert_eq!(parsed, expect);
            assert_eq!(serde_json::to_value(&parsed).unwrap(), json!(s));
        }
    }

    /// RFC-ACDP-0014 §10 — both the standard `key-revocation` form and
    /// the interim `acdp:key-revocation` custom form MUST be
    /// recognizable as key-revocation contexts; nothing else is.
    #[test]
    fn context_type_key_revocation_recognition() {
        let standard: ContextType = serde_json::from_value(json!("key-revocation")).unwrap();
        assert_eq!(standard, ContextType::KeyRevocation);
        assert!(standard.is_key_revocation());

        // The interim form is a plain namespaced custom type on the
        // wire but MUST be treated as equivalent by 0.3.0 consumers.
        let interim: ContextType = serde_json::from_value(json!("acdp:key-revocation")).unwrap();
        assert_eq!(
            interim,
            ContextType::Custom(ContextType::KEY_REVOCATION_INTERIM.into())
        );
        assert!(interim.is_key_revocation());

        assert!(!ContextType::DataSnapshot.is_key_revocation());
        assert!(!ContextType::Custom("acdp:key-rotation".into()).is_key_revocation());
    }

    #[test]
    fn context_type_accepts_namespaced_custom() {
        let parsed: ContextType =
            serde_json::from_value(json!("finance:portfolio_snapshot")).unwrap();
        assert_eq!(
            parsed,
            ContextType::Custom("finance:portfolio_snapshot".into())
        );
        // Custom round-trips back to its exact wire string.
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            json!("finance:portfolio_snapshot")
        );
    }

    #[test]
    fn context_type_rejects_unnamespaced_unknown() {
        // No colon and not a known keyword ⇒ schema-invalid.
        for bad in [
            "totally_unknown",
            "Finance:x",
            "finance:",
            ":name",
            "1ns:name",
        ] {
            let parsed: Result<ContextType, _> = serde_json::from_value(json!(bad));
            assert!(parsed.is_err(), "context_type {bad:?} must be rejected");
        }
    }

    #[test]
    fn namespaced_context_type_helper_edges() {
        assert!(is_namespaced_context_type("a:b"));
        assert!(is_namespaced_context_type("ns1:name_2-x"));
        assert!(!is_namespaced_context_type("nocolon"));
        assert!(!is_namespaced_context_type("ns:Name")); // uppercase in name
        assert!(!is_namespaced_context_type("ns:-bad")); // name starts with hyphen
        assert!(!is_namespaced_context_type("ns:1bad")); // name starts with digit
    }

    // ── Status edge cases ──────────────────────────────────────────────────

    #[test]
    fn status_parse_rejects_pattern_violations() {
        for bad in ["Active", "has space", "", "UPPER", "trailing!"] {
            assert!(
                Status::parse(bad).is_err(),
                "status {bad:?} violates ^[a-z][a-z0-9_]*$ and must be rejected"
            );
        }
    }

    #[test]
    fn status_deserialize_rejects_malformed() {
        // Deserialization funnels through `Status::parse`.
        let parsed: Result<Status, _> = serde_json::from_value(json!("Active"));
        assert!(parsed.is_err());
    }

    #[test]
    fn status_known_or_active_degrades_unknown() {
        // Unknown ⇒ Active for read-side decisions (RFC-ACDP-0004 §4.1).
        let other = Status::Other("retracted".into());
        assert_eq!(other.known_or_active(), Status::Active);
        // Known statuses are preserved unchanged.
        assert_eq!(Status::Superseded.known_or_active(), Status::Superseded);
        assert_eq!(Status::Expired.known_or_active(), Status::Expired);
    }

    #[test]
    fn status_as_str_matches_wire_form() {
        assert_eq!(Status::Active.as_str(), "active");
        assert_eq!(Status::Superseded.as_str(), "superseded");
        assert_eq!(Status::Expired.as_str(), "expired");
        assert_eq!(Status::Other("custom".into()).as_str(), "custom");
    }

    // ── Visibility / Display ───────────────────────────────────────────────

    #[test]
    fn visibility_round_trips_snake_case() {
        for (s, expect) in [
            ("public", Visibility::Public),
            ("restricted", Visibility::Restricted),
            ("private", Visibility::Private),
        ] {
            let parsed: Visibility = serde_json::from_value(json!(s)).unwrap();
            assert_eq!(parsed, expect);
            assert_eq!(serde_json::to_value(&parsed).unwrap(), json!(s));
        }
        assert!(serde_json::from_value::<Visibility>(json!("Public")).is_err());
    }

    #[test]
    fn identifier_display_matches_inner_string() {
        let ctx = "acdp://r.example.com/12345678-1234-4321-8123-123456781234";
        assert_eq!(CtxId(ctx.into()).to_string(), ctx);
        let lin = "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(LineageId(lin.into()).to_string(), lin);
        let hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(ContentHash(hash.into()).to_string(), hash);
        assert_eq!(AgentDid::new("did:web:x").to_string(), "did:web:x");
    }

    #[test]
    fn ctx_id_uuid_returns_none_for_malformed() {
        // `uuid()` is best-effort: malformed input yields None, not a panic.
        assert!(CtxId("not-a-ctx-id".into()).uuid().is_none());
        assert!(CtxId("acdp://host/not-a-uuid".into()).uuid().is_none());
    }
}
