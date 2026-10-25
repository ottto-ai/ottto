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
