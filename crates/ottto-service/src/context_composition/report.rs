//! The per-workspace accumulator: daily buckets, files and sessions.

use super::Category;
use std::collections::{BTreeMap, HashSet};
use time::{Date, OffsetDateTime};

/// How one transcript line counts. A line copied from a parent session (a
/// fork's inherited history, a resumed Claude transcript's earlier records)
/// entered context where it was first written; here it only stays resident
/// for this session's own requests, so it adds residency but no events,
/// entered tokens, files or session totals.
#[derive(Clone, Copy)]
pub(super) struct Weight {
    pub(super) mult: u64,
    pub(super) copied: bool,
}

// -------------------------------------------------------------------------
// Per-workspace accumulator.
// -------------------------------------------------------------------------

#[derive(Default, Clone)]
pub(super) struct Bucket {
    pub(super) events: u64,
    pub(super) tokens: u64,
    pub(super) residency: u64,
    pub(super) images: u64,
}

impl Bucket {
    pub(super) fn add_resident(&mut self, tokens: u64, mult: u64) {
        self.residency += tokens * mult;
    }

    pub(super) fn add(&mut self, tokens: u64, mult: u64, images: u64) {
        self.events += 1;
        self.tokens += tokens;
        self.residency += tokens * mult;
        self.images += images;
    }
}

#[derive(Clone)]
pub(super) struct FileAgg {
    pub(super) category: Category,
    pub(super) events: u64,
    pub(super) tokens: u64,
    pub(super) last_accessed: Option<OffsetDateTime>,
}

#[derive(Default, Clone)]
pub(super) struct SessionAgg {
    pub(super) cat_tokens: [u64; 10],
    pub(super) total: u64,
    pub(super) started_at: Option<OffsetDateTime>,
}

/// Inclusive `[floor, today]` window (UTC dates). Events outside are dropped so
/// the captured window never exceeds the backend's 92-day cap.
#[derive(Clone, Copy)]
pub(crate) struct DateWindow {
    pub(super) floor: Date,
    pub(super) today: Date,
}

impl DateWindow {
    pub(super) fn contains(&self, date: Date) -> bool {
        date >= self.floor && date <= self.today
    }
}

pub(crate) struct WorkspaceReport {
    pub(super) window: DateWindow,
    pub(super) daily: BTreeMap<(Date, Category), Bucket>,
    pub(super) files: BTreeMap<String, FileAgg>,
    pub(super) sessions: BTreeMap<String, SessionAgg>,
    /// Hashes of Claude record uuids already counted in this workspace. A
    /// resumed or forked transcript repeats earlier records under the same
    /// uuid. About 8 bytes per record, freed with the report.
    pub(super) claude_records: HashSet<u64>,
    /// Sessions skipped whole: a fork whose copied history has no boundary
    /// in the file, or a transcript made only of already-counted records.
    pub(crate) excluded_not_fresh: u64,
    /// Sessions whose copied history was trimmed to residency only.
    pub(crate) copied_history_sessions: u64,
}

impl WorkspaceReport {
    pub(crate) fn new(window: DateWindow) -> Self {
        Self {
            window,
            daily: BTreeMap::new(),
            files: BTreeMap::new(),
            sessions: BTreeMap::new(),
            claude_records: HashSet::new(),
            excluded_not_fresh: 0,
            copied_history_sessions: 0,
        }
    }

    #[expect(clippy::too_many_arguments, reason = "test helper, 9 case inputs")]
    pub(super) fn record(
        &mut self,
        session_id: &str,
        category: Category,
        tokens: u64,
        weight: Weight,
        images: u64,
        file_path: Option<&str>,
        date: Date,
        ts: Option<OffsetDateTime>,
    ) {
        if !self.window.contains(date) {
            return;
        }
        let bucket = self.daily.entry((date, category)).or_default();
        if weight.copied {
            bucket.add_resident(tokens, weight.mult);
            return;
        }
        bucket.add(tokens, weight.mult, images);
        if let Some(fp) = file_path {
            let entry = self.files.entry(fp.to_string()).or_insert(FileAgg {
                category,
                events: 0,
                tokens: 0,
                last_accessed: None,
            });
            entry.category = category;
            entry.events += 1;
            entry.tokens += tokens;
            if let Some(ts) = ts {
                entry.last_accessed = Some(match entry.last_accessed {
                    Some(existing) if existing >= ts => existing,
                    _ => ts,
                });
            }
        }
        let session = self.sessions.entry(session_id.to_string()).or_default();
        session.cat_tokens[category.index()] += tokens;
        session.total += tokens;
    }

    pub(super) fn note_session_start(&mut self, session_id: &str, ts: Option<OffsetDateTime>) {
        let Some(ts) = ts else { return };
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.started_at = Some(match session.started_at {
                Some(existing) if existing <= ts => existing,
                _ => ts,
            });
        }
    }

    /// Test-only view of a category's totals summed across every day.
    #[cfg(test)]
    pub(super) fn category_totals(&self, category: Category) -> (u64, u64, u64, u64) {
        let mut out = (0, 0, 0, 0);
        for ((_, cat), bucket) in &self.daily {
            if *cat == category {
                out.0 += bucket.events;
                out.1 += bucket.tokens;
                out.2 += bucket.residency;
                out.3 += bucket.images;
            }
        }
        out
    }
}
