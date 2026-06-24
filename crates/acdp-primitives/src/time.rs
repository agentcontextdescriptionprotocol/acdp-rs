//! Time helpers shared by the producer builder and search-params formatter.
//!
//! ACDP timestamps in publish requests are part of the JCS-canonicalized
//! body (RFC-ACDP-0001 §5.3). Producers MUST emit canonical millisecond
//! precision so the resulting `content_hash` is reproducible across
//! implementations. `chrono::DateTime<Utc>` defaults to nanosecond
//! precision; this module centralizes the truncation and the canonical
//! string format used everywhere on the producer path.

use chrono::{DateTime, Utc};

/// Truncate to millisecond precision per RFC-ACDP-0001 §5.3.
///
/// Returns the input unchanged if `timestamp_millis()` cannot round-trip
/// (extremely far-future timestamps).
pub fn trunc_ms(dt: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(dt.timestamp_millis()).unwrap_or(dt)
}

/// Format as the canonical RFC 3339 string with explicit `Z` suffix
/// and millisecond precision, e.g. `2026-04-16T10:30:15.123Z`.
pub fn fmt_rfc3339_ms(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_truncation_drops_sub_ms() {
        let dt = DateTime::from_timestamp_nanos(1_700_000_000_123_456_789);
        let truncated = trunc_ms(dt);
        assert_eq!(truncated.timestamp_subsec_nanos() % 1_000_000, 0);
    }

    #[test]
    fn fmt_emits_canonical_form() {
        let dt = DateTime::from_timestamp_millis(1_700_000_000_123).unwrap();
        let s = fmt_rfc3339_ms(dt);
        assert!(s.ends_with("Z"), "got {s}");
        assert!(s.contains(".123"), "got {s}");
    }
}
