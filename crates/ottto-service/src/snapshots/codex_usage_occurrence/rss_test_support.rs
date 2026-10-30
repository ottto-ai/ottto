//! Read-only inspection of the actual staged graph; no synthetic state injection.
use super::*;

impl CodexCounting {
    pub(in crate::snapshots) fn rss_pending_shape(&self) -> (usize, usize, usize) {
        let Some(turn) = self.reducer.as_ref().and_then(|r| r.turn.as_ref()) else {
            return (0, 0, 0);
        };
        let mut min = usize::MAX;
        let mut max = 0;
        for ((bucket, key), row) in turn.pending.iter() {
            let bytes = pending_row_content_bytes(
                bucket,
                key,
                &row.selector_context,
                &row.selector_sources,
            ) + row.first_activity_at.len()
                + row.last_activity_at.len();
            min = min.min(bytes);
            max = max.max(bytes);
        }
        (turn.pending.len(), if max == 0 { 0 } else { min }, max)
    }
}

// Test-only `Debug` for the archived-writer seed, which renders live state.
impl std::fmt::Debug for CodexCounting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexCounting")
            .field("evidence", &self.evidence)
            .field("cutover_unix_ms", &self.cutover_unix_ms)
            .field("version", &self.version)
            .field("reducer", &self.reducer)
            .finish()
    }
}

impl std::fmt::Debug for OccurrenceReducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OccurrenceReducer")
            .field("epoch", &self.epoch)
            .field("last_native", &self.last_native)
            .field("prev_ui", &self.prev_ui)
            .field("native_since_prev_ui", &self.native_since_prev_ui)
            .field("line_ui", &self.line_ui)
            .field("turn", &self.turn)
            .field("closed_turns", &self.closed_turns)
            .field("closed_filter", &self.closed_filter)
            .field("counters", &self.counters)
            .finish()
    }
}

impl std::fmt::Debug for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Epoch")
            .field("base", &self.base)
            .field("hwm", &self.hwm)
            .field("first_id", &self.first_id)
            .field("contiguous", &self.contiguous)
            .finish()
    }
}

impl std::fmt::Debug for LastNative {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LastNative")
            .field("id", &self.id)
            .field("usage", &self.usage)
            .field("after", &self.after)
            .finish()
    }
}

impl std::fmt::Debug for UiTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UiTuple")
            .field("last", &self.last)
            .field("total", &self.total)
            .field("last_t6", &self.last_t6)
            .field("total_t6", &self.total_t6)
            .finish()
    }
}

impl std::fmt::Debug for BoundTurn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundTurn")
            .field("id", &self.id)
            .field("native", &self.native)
            .field("ui_published", &self.ui_published)
            .field("staged_events", &self.staged_events)
            .field("pending", &self.pending)
            .finish()
    }
}

impl std::fmt::Debug for PendingRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRow")
            .field("selector_context", &self.selector_context)
            .field("selector_sources", &self.selector_sources)
            .field("usage", &self.usage)
            .field("events", &self.events)
            .field("first_activity_at", &self.first_activity_at)
            .field("last_activity_at", &self.last_activity_at)
            .finish()
    }
}

impl std::fmt::Debug for ClosedTurnFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ClosedTurnFilter").field(&self.0).finish()
    }
}
