//! Cursor-pagination helpers for registry store backends.
//!
//! Registries paginate `list` / `search` with an opaque keyset cursor
//! (RFC-ACDP-0002). The standard backend idiom is:
//!
//! 1. fetch `limit + 1` rows from the database in page order,
//! 2. decode each row and apply an in-Rust visibility/status filter, then
//! 3. return at most `limit` items plus a `next_cursor` for the page that
//!    follows.
//!
//! Two correctness invariants in that idiom are easy to get wrong, and
//! every backend re-implements them:
//!
//! - **The "more rows?" signal must come from the raw DB row count, not
//!   the post-filter item count.** Fetching `limit + 1` and testing
//!   `rows.len() > limit` is the sentinel; comparing the *filtered*
//!   `items.len()` against `limit` sends clients to a phantom empty page
//!   whenever the in-Rust filter drops a row on the final page.
//! - **The next cursor must anchor on the last *scanned* row, not the
//!   last *kept* item.** If a whole page is filtered out, anchoring on the
//!   last kept item yields `None` and terminates pagination early even
//!   though the database had more matching rows; anchoring on the last
//!   scanned row keeps the walk going.
//!
//! [`paginate_scanned`] and [`try_paginate_rows`] centralize both
//! invariants (and their regression tests) so a backend supplies only the
//! per-row decode, the keep-filter, and the cursor extractor. The cursor
//! *encoding* stays with the backend — this module is generic over the
//! cursor type and never inspects it.

/// A page of results plus the opaque cursor for the page that follows.
///
/// `next_cursor` is `Some` only when the backend had at least one more row
/// beyond this page; `None` marks the end of the walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paginated<T, C = String> {
    /// The items that survived the keep-filter, in page order.
    pub items: Vec<T>,
    /// Cursor for the next page, or `None` at the end of the result set.
    pub next_cursor: Option<C>,
}

/// Apply a page's keep-filter and derive its `next_cursor` from the rows
/// already scanned for the page.
///
/// `scanned` is the decoded rows for *this page only* — i.e. already
/// truncated to the page size with `take(limit)` — in page order.
/// `has_more` MUST be computed from the raw database row count *before*
/// any in-Rust filtering (the canonical idiom fetches `limit + 1` rows and
/// tests `rows.len() > limit`); [`try_paginate_rows`] does this for you.
///
/// The next cursor is emitted iff `has_more`, and is taken from the last
/// element of `scanned` (the last row the backend looked at), not from the
/// last kept item — so a page whose rows are entirely filtered out still
/// advances the cursor instead of ending pagination early.
pub fn paginate_scanned<T, C>(
    scanned: Vec<T>,
    has_more: bool,
    keep: impl Fn(&T) -> bool,
    cursor_of: impl Fn(&T) -> C,
) -> Paginated<T, C> {
    let next_cursor = if has_more {
        scanned.last().map(&cursor_of)
    } else {
        None
    };
    let items = scanned.into_iter().filter(keep).collect();
    Paginated { items, next_cursor }
}

/// Owns the full backend idiom: take the raw `LIMIT limit + 1` result set,
/// compute the `has_more` sentinel, drop the sentinel row, decode each
/// remaining row with a fallible `decode`, then delegate to
/// [`paginate_scanned`].
///
/// `rows` is the raw result set exactly as fetched with `LIMIT limit + 1`.
/// A decode error short-circuits and is returned to the caller; the cursor
/// type `C` and error type `E` are whatever the backend uses.
pub fn try_paginate_rows<R, T, C, E>(
    rows: Vec<R>,
    limit: usize,
    decode: impl Fn(R) -> Result<T, E>,
    keep: impl Fn(&T) -> bool,
    cursor_of: impl Fn(&T) -> C,
) -> Result<Paginated<T, C>, E> {
    let has_more = rows.len() > limit;
    let mut scanned = Vec::with_capacity(rows.len().min(limit));
    for row in rows.into_iter().take(limit) {
        scanned.push(decode(row)?);
    }
    Ok(paginate_scanned(scanned, has_more, keep, cursor_of))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A row carries its keyset position and whether the keep-filter
    // accepts it, so tests can exercise the cursor-anchoring rules.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Row {
        cursor: u32,
        keep: bool,
    }

    fn row(cursor: u32, keep: bool) -> Row {
        Row { cursor, keep }
    }

    fn paginate(scanned: Vec<Row>, has_more: bool) -> Paginated<Row, u32> {
        paginate_scanned(scanned, has_more, |r| r.keep, |r| r.cursor)
    }

    #[test]
    fn empty_input_yields_no_items_and_no_cursor() {
        let page = paginate(vec![], false);
        assert!(page.items.is_empty());
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn no_more_rows_means_no_cursor_even_with_items() {
        let page = paginate(vec![row(1, true), row(2, true)], false);
        assert_eq!(page.items, vec![row(1, true), row(2, true)]);
        assert_eq!(page.next_cursor, None, "last page must not emit a cursor");
    }

    #[test]
    fn cursor_emitted_when_more_rows_exist() {
        let page = paginate(vec![row(1, true), row(2, true)], true);
        assert_eq!(page.items.len(), 2);
        assert_eq!(
            page.next_cursor,
            Some(2),
            "cursor anchors on last scanned row"
        );
    }

    #[test]
    fn cursor_anchors_on_last_scanned_not_last_kept() {
        // REG-P2-8: the final scanned row is filtered out. The cursor must
        // still advance to it (2), NOT fall back to the last *kept* item
        // (1) — otherwise the next page re-scans row 2 forever.
        let page = paginate(vec![row(1, true), row(2, false)], true);
        assert_eq!(page.items, vec![row(1, true)]);
        assert_eq!(
            page.next_cursor,
            Some(2),
            "cursor must anchor on the last scanned row, even when filtered out"
        );
    }

    #[test]
    fn fully_filtered_page_still_advances_the_cursor() {
        // The critical early-termination fix: every row on a non-final
        // page is dropped, but the walk must continue from the last
        // scanned row rather than ending with an empty page.
        let page = paginate(vec![row(1, false), row(2, false), row(3, false)], true);
        assert!(page.items.is_empty());
        assert_eq!(page.next_cursor, Some(3));
    }

    #[test]
    fn try_paginate_drops_the_sentinel_row() {
        // limit = 2, fetched limit + 1 = 3 rows → has_more, sentinel (30)
        // dropped, cursor anchors on the last *scanned* row (20).
        let rows = vec![10u32, 20, 30];
        let page: Paginated<u32, u32> =
            try_paginate_rows(rows, 2, Ok::<u32, ()>, |_| true, |v| *v).unwrap();
        assert_eq!(page.items, vec![10, 20]);
        assert_eq!(page.next_cursor, Some(20));
    }

    #[test]
    fn try_paginate_no_more_rows_when_exactly_limit() {
        let rows = vec![10u32, 20];
        let page: Paginated<u32, u32> =
            try_paginate_rows(rows, 2, Ok::<u32, ()>, |_| true, |v| *v).unwrap();
        assert_eq!(page.items, vec![10, 20]);
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn try_paginate_propagates_decode_errors() {
        let rows = vec![1u32, 2, 3];
        let result: Result<Paginated<u32, u32>, &'static str> = try_paginate_rows(
            rows,
            2,
            |v| if v == 2 { Err("boom") } else { Ok(v) },
            |_| true,
            |v| *v,
        );
        assert_eq!(result, Err("boom"));
    }
}
