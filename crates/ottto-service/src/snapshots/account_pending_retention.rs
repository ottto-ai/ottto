//! Keep the endpoints of consecutive runs identical in every non-boundary field.
//! Boundaries remain separate from the consumer projection; current is never collapsed.
use super::{
    rfc3339_unix_seconds, ClaudeAccountFamilyPending, ClaudeAccountFamilyPendingWindow,
    ClaudeAccountRequestSet, ScanIndex,
};
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub(crate) struct Counts {
    pub(crate) roots_collapsed: u64,
    pub(crate) windows_collapsed: u64,
    pub(crate) window_bytes_saved: u64,
    pub(crate) roots_refused: u64,
    /// Compact JSON bytes of historical arrays, summed across loaded families.
    pub(crate) window_bytes_before: u64,
    pub(crate) window_bytes_after: u64,
}
crate::heap_layout_bound::fields!(Counts; roots_collapsed, windows_collapsed, window_bytes_saved, roots_refused, window_bytes_before, window_bytes_after);

/// Per-window evidence view folded by `HistorySummary`: the window's account
/// and invalid flag, and each member with its identity revision.
#[derive(Debug, Clone, Copy)]
struct ConsumerProjection<'a> {
    account_identifier_hash: &'a str,
    invalid: bool,
    member_keys: &'a BTreeMap<String, u64>,
    requests: &'a BTreeMap<String, ClaudeAccountRequestSet>,
}
impl<'a> ConsumerProjection<'a> {
    fn members(self) -> impl Iterator<Item = (&'a String, Option<&'a String>)> {
        self.member_keys.keys().map(move |member| {
            (
                member,
                self.requests
                    .get(member)
                    .and_then(|requests| requests.identity_revision.as_ref()),
            )
        })
    }
}

/// An exhaustive destructure makes a newly added window field a compile error
/// until its retention semantics are explicitly included here. Nested request
/// sets use their derived equality, including counts, hashes and revisions.
impl ClaudeAccountFamilyPendingWindow {
    fn strict_evidence(&self) -> impl PartialEq + '_ {
        let Self {
            version,
            census_window_end: _,
            account_identifier_hash,
            evidence_request_count,
            census_complete,
            members,
            member_requests,
            invalid,
        } = self;
        (
            version,
            account_identifier_hash,
            evidence_request_count,
            census_complete,
            members,
            member_requests,
            invalid,
        )
    }
}

impl ClaudeAccountFamilyPendingWindow {
    fn consumer_projection(&self) -> ConsumerProjection<'_> {
        ConsumerProjection {
            account_identifier_hash: &self.account_identifier_hash,
            invalid: self.invalid,
            member_keys: &self.members,
            requests: &self.member_requests,
        }
    }
}

/// A family's archived windows. v1, import, raw holds and CAS custody keep
/// them `Resident`. A complete v2 hydrate without raw holds keeps them `Cold`:
/// the rows stay in the store and RAM keeps their summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ArchivedWindows {
    Resident(Vec<ClaudeAccountFamilyPendingWindow>),
    Cold(Box<ColdWindows>),
}
impl Default for ArchivedWindows {
    fn default() -> Self {
        Self::Resident(Vec::new())
    }
}
impl Serialize for ArchivedWindows {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Resident(windows) => windows.serialize(serializer),
            // Only the store holds these windows. An image without them would
            // drop their custody, so no encoder may write one.
            Self::Cold(_) => Err(serde::ser::Error::custom("account_windows_cold")),
        }
    }
}
impl HeapLayoutBound for ArchivedWindows {
    fn stable_heap(&self) -> bool {
        match self {
            Self::Resident(windows) => windows.stable_heap(),
            Self::Cold(cold) => cold.stable_heap(),
        }
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        match self {
            Self::Resident(windows) => windows.heap_bound(c),
            Self::Cold(cold) => cold.heap_bound(c),
        }
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        match self {
            Self::Resident(windows) => windows.completed_heap_bound(c),
            Self::Cold(cold) => cold.completed_heap_bound(c),
        }
    }
}
impl ArchivedWindows {
    #[cfg(test)]
    pub(super) fn resident(&self) -> &Vec<ClaudeAccountFamilyPendingWindow> {
        match self {
            Self::Resident(windows) => windows,
            Self::Cold(_) => panic!("account_windows_cold"),
        }
    }

    #[cfg(test)]
    pub(super) fn resident_mut(&mut self) -> &mut Vec<ClaudeAccountFamilyPendingWindow> {
        match self {
            Self::Resident(windows) => windows,
            Self::Cold(_) => panic!("account_windows_cold"),
        }
    }

    pub(super) fn is_empty_resident(&self) -> bool {
        matches!(self, Self::Resident(windows) if windows.is_empty())
    }

    /// Interior windows of equal-evidence runs left in the store: the v1
    /// load walk would collapse them, a cold archive is never walked.
    pub(super) fn uncollapsed(&self) -> usize {
        match self {
            Self::Resident(_) => 0,
            Self::Cold(cold) => cold.uncollapsed,
        }
    }

    /// After a committed save the store holds the replayed archive.
    pub(super) fn saved(&mut self, archived: &[u64]) {
        match self {
            Self::Resident(_) => {}
            Self::Cold(cold) => {
                cold.stored = archived.len();
                cold.last_id = archived.last().copied();
                cold.rolled = Vec::new();
            }
        }
    }
}

/// The summary of a family's stored archive, which rows it is (ids are never
/// reused, so the count and last id identify it) and the windows rolled
/// since, which the next save replays over the stored tail.
#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct ColdWindows {
    summary: HistorySummary,
    stored: usize,
    last_id: Option<u64>,
    uncollapsed: usize,
    rolled: Vec<Rolled>,
}
crate::heap_layout_bound::fields!(ColdWindows; summary, stored, last_id, uncollapsed, rolled);
impl std::fmt::Debug for ColdWindows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColdWindows")
            .field("stored", &self.stored)
            .field("rolled", &self.rolled.len())
            .finish_non_exhaustive()
    }
}
/// One rollover under a cold archive, with the arguments the resident
/// archive would have applied it with.
#[derive(Clone, PartialEq, Eq)]
struct Rolled {
    window: ClaudeAccountFamilyPendingWindow,
    strict: bool,
    current_end: String,
}
crate::heap_layout_bound::fields!(Rolled; window, strict, current_end);
impl ColdWindows {
    /// Stored archived rows and the last one's id.
    pub(super) fn base(&self) -> (usize, Option<u64>) {
        (self.stored, self.last_id)
    }

    pub(super) fn has_rolled(&self) -> bool {
        !self.rolled.is_empty()
    }

    /// `tail` is the stored archive's last (at most two) windows, oldest
    /// first. The endpoint rule reads only those, so the result ends exactly
    /// as the resident archive would after the same rollovers.
    pub(super) fn replay(
        &self,
        mut tail: Vec<ClaudeAccountFamilyPendingWindow>,
    ) -> Vec<ClaudeAccountFamilyPendingWindow> {
        for rolled in &self.rolled {
            let window = rolled.window.clone();
            if rolled.strict {
                retain_run_endpoint(&mut tail, window, &rolled.current_end);
            } else {
                tail.push(window);
            }
        }
        tail
    }
}
/// Streams one family's stored archive, oldest first, into a cold archive.
/// Only the previous window is held, to count equal-evidence runs.
#[derive(Default)]
pub(super) struct ColdFold {
    cold: ColdWindows,
    last: Option<ClaudeAccountFamilyPendingWindow>,
    run: usize,
}
impl ColdFold {
    pub(super) fn push(&mut self, window: ClaudeAccountFamilyPendingWindow) {
        self.cold.summary.fold(&window);
        self.cold.stored += 1;
        let same = self
            .last
            .as_ref()
            .is_some_and(|last| last.strict_evidence() == window.strict_evidence());
        self.run = if same { self.run + 1 } else { 1 };
        if self.run > 2 {
            self.cold.uncollapsed += 1;
        }
        self.last = Some(window);
    }

    pub(super) fn finish(self, last_id: Option<u64>) -> ArchivedWindows {
        ArchivedWindows::Cold(Box::new(ColdWindows {
            last_id,
            ..self.cold
        }))
    }
}

impl ClaudeAccountFamilyPending {
    pub(super) fn has_history(&self) -> bool {
        match &self.previous_windows {
            ArchivedWindows::Resident(windows) => !windows.is_empty(),
            ArchivedWindows::Cold(cold) => cold.stored != 0 || cold.has_rolled(),
        }
    }

    pub(super) fn history_summary(&self) -> HistorySummary {
        match &self.previous_windows {
            ArchivedWindows::Resident(windows) => HistorySummary::from_windows(windows),
            ArchivedWindows::Cold(cold) => cold.summary.clone(),
        }
    }

    /// Archive the replaced current window. Strict archives keep only the
    /// endpoints of equal runs; opaque evidence is funded by the whole
    /// encoded index, so it keeps every window until the hold resolves. A
    /// cold archive folds the window now and queues it for the next save.
    pub(super) fn archive(&mut self, old: ClaudeAccountFamilyPendingWindow, strict: bool) {
        let current_end = &self.current.census_window_end;
        match &mut self.previous_windows {
            ArchivedWindows::Resident(windows) if strict => {
                retain_run_endpoint(windows, old, current_end)
            }
            ArchivedWindows::Resident(windows) => windows.push(old),
            ArchivedWindows::Cold(cold) => {
                cold.summary.fold(&old);
                cold.rolled.push(Rolled {
                    window: old,
                    strict,
                    current_end: current_end.clone(),
                });
            }
        }
    }

    fn apply_checked_plan(&mut self, retained: Vec<usize>) -> Option<usize> {
        let ArchivedWindows::Resident(windows) = &mut self.previous_windows else {
            return None;
        };
        if HistorySummary::from_windows(&*windows)
            != HistorySummary::from_windows(retained.iter().map(|&i| &windows[i]))
        {
            return None;
        }
        let removed = windows.len() - retained.len();
        if removed != 0 {
            let mut retained = retained.into_iter().peekable();
            let mut position = 0;
            windows.retain(|_| {
                let keep = retained.peek() == Some(&position);
                if keep {
                    retained.next();
                }
                position += 1;
                keep
            });
        }
        Some(removed)
    }

    /// Validate before proposing any removal. Unsafe histories stay byte-for-
    /// byte equivalent in RAM; in particular no malformed boundary disappears.
    fn collapse_plan(&self) -> Option<Vec<usize>> {
        let ArchivedWindows::Resident(windows) = &self.previous_windows else {
            return None;
        };
        let current = rfc3339_unix_seconds(&self.census_window_end)?;
        let mut previous = None;
        for window in windows {
            let time = rfc3339_unix_seconds(&window.census_window_end)?;
            if time >= current || previous.is_some_and(|previous| time <= previous) {
                return None;
            }
            previous = Some(time);
        }
        let mut retained = Vec::new();
        let mut read = 0;
        while read < windows.len() {
            let start = read;
            read += 1;
            while read < windows.len()
                && windows[start].strict_evidence() == windows[read].strict_evidence()
            {
                read += 1;
            }
            retained.push(start);
            if read - start > 1 {
                retained.push(read - 1);
            }
        }
        Some(retained)
    }
}

/// First equal predecessor creates the second endpoint. Later equal pushes
/// replace only that endpoint. A -> B -> A always starts distinct runs.
fn retain_run_endpoint(
    windows: &mut Vec<ClaudeAccountFamilyPendingWindow>,
    old: ClaudeAccountFamilyPendingWindow,
    current_end: &str,
) {
    let len = windows.len();
    if len >= 2 {
        let first = &windows[len - 2];
        let last = &windows[len - 1];
        if let (Some(a), Some(b), Some(c), Some(current)) = (
            rfc3339_unix_seconds(&first.census_window_end),
            rfc3339_unix_seconds(&last.census_window_end),
            rfc3339_unix_seconds(&old.census_window_end),
            rfc3339_unix_seconds(current_end),
        ) {
            if a < b
                && b < c
                && c < current
                && first.strict_evidence() == last.strict_evidence()
                && last.strict_evidence() == old.strict_evidence()
            {
                windows[len - 1] = old;
                return;
            }
        }
    }
    windows.push(old);
}

/// Per-root decision summary of the archived windows: the newest boundary,
/// whether any boundary is unparsable, and each member's winning
/// boundary/account/invalid/revision (first wins on ties). Retirement reads it
/// with the current window; the load self-check compares it alone.
/// Current-window gates and family-level holds are untouched.
#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct HistorySummary {
    newest_boundary: Option<u64>,
    unparsable: bool,
    latest: BTreeMap<String, Latest>,
}
crate::heap_layout_bound::fields!(HistorySummary; newest_boundary, unparsable, latest);
/// A member's winning (boundary, account, invalid, revision).
pub(super) type Latest = (u64, String, bool, Option<String>);
impl HistorySummary {
    fn from_windows<'a>(
        windows: impl IntoIterator<Item = &'a ClaudeAccountFamilyPendingWindow>,
    ) -> Self {
        let mut summary = Self::default();
        windows.into_iter().for_each(|window| summary.fold(window));
        summary
    }

    fn fold(&mut self, window: &ClaudeAccountFamilyPendingWindow) {
        let Some(time) = rfc3339_unix_seconds(&window.census_window_end) else {
            self.unparsable = true;
            return;
        };
        self.newest_boundary = self.newest_boundary.max(Some(time));
        let projection = window.consumer_projection();
        for (member, revision) in projection.members() {
            if self
                .latest
                .get(member)
                .map_or(true, |(previous, _, _, _)| time > *previous)
            {
                self.latest.insert(
                    member.clone(),
                    (
                        time,
                        projection.account_identifier_hash.to_owned(),
                        projection.invalid,
                        revision.cloned(),
                    ),
                );
            }
        }
    }

    /// Each member's newest (boundary, account, invalid, revision) across the
    /// archive and `current`. `None` refuses the family: a boundary is
    /// unparsable or an archived window is not older than current. Current
    /// is then strictly newest, so folding it wins its own members.
    pub(super) fn with_current(
        mut self,
        current: &ClaudeAccountFamilyPendingWindow,
    ) -> Option<BTreeMap<String, Latest>> {
        let current_end = rfc3339_unix_seconds(&current.census_window_end)?;
        if self.unparsable
            || self
                .newest_boundary
                .is_some_and(|newest| newest >= current_end)
        {
            return None;
        }
        self.fold(current);
        Some(self.latest)
    }
}

// Streaming byte counter: never materialize the encoded histories.
fn window_bytes(windows: &[ClaudeAccountFamilyPendingWindow]) -> u64 {
    struct Counter(u64);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len() as u64);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, windows).expect("pending windows serialize to a counter");
    counter.0
}

impl ScanIndex {
    pub(super) fn collapse_account_pending_windows(&mut self) {
        let mut counts = Counts::default();
        // HeldRaw admission is funded by the serialized index size. Shrinking
        // another root can reduce that budget and make every save fail. Never
        // compact an index containing opaque holds, even in unrelated roots.
        let opaque_holds = !self.decode_holds.is_empty();
        for pending in self.claude_account_family_pending.values_mut() {
            // A cold archive is not loaded: v2 replays the endpoint rule at
            // save.
            let ArchivedWindows::Resident(windows) = &pending.previous_windows else {
                continue;
            };
            let empty = windows.is_empty();
            let before = window_bytes(windows);
            counts.window_bytes_before = counts.window_bytes_before.saturating_add(before);
            let mut after = before;
            let plan = if opaque_holds && !empty {
                None
            } else {
                pending.collapse_plan()
            };
            match plan {
                None => counts.roots_refused = counts.roots_refused.saturating_add(1),
                Some(retained) => {
                    // Check proposed summaries before deleting anything. A
                    // mismatch leaves this root unchanged, without a backup.
                    match pending.apply_checked_plan(retained) {
                        None => counts.roots_refused = counts.roots_refused.saturating_add(1),
                        Some(0) => {}
                        Some(removed) => {
                            after = match &pending.previous_windows {
                                ArchivedWindows::Resident(windows) => window_bytes(windows),
                                ArchivedWindows::Cold(_) => before,
                            };
                            counts.roots_collapsed = counts.roots_collapsed.saturating_add(1);
                            counts.windows_collapsed =
                                counts.windows_collapsed.saturating_add(removed as u64);
                        }
                    }
                }
            }
            counts.window_bytes_after = counts.window_bytes_after.saturating_add(after);
        }
        counts.window_bytes_saved = counts
            .window_bytes_before
            .saturating_sub(counts.window_bytes_after);
        self.claude_account_window_retention = counts;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn self_check_refuses_a_plan_that_changes_a_members_winning_boundary() {
        let window = |minute, member: &str| ClaudeAccountFamilyPendingWindow {
            version: super::super::CLAUDE_ACCOUNT_REQUEST_SET_VERSION.into(),
            census_window_end: format!("2026-08-02T07:0{minute}:00Z"),
            account_identifier_hash: "a".repeat(64),
            evidence_request_count: 1,
            census_complete: false,
            members: BTreeMap::from([(member.into(), 1)]),
            member_requests: BTreeMap::new(),
            invalid: true,
        };
        let mut pending = ClaudeAccountFamilyPending {
            current: window(3, "current"),
            previous_windows: ArchivedWindows::Resident(vec![
                window(0, "historical"),
                window(1, "historical"),
                window(2, "historical"),
            ]),
            confirmed_absent_members: BTreeSet::new(),
        };
        let before = serde_json::to_vec(&pending).unwrap();
        // A deliberately defective plan drops the last historical endpoint.
        assert_eq!(pending.apply_checked_plan(vec![0]), None);
        assert_eq!(serde_json::to_vec(&pending).unwrap(), before);
        assert_eq!(pending.apply_checked_plan(vec![0, 2]), Some(1));
    }
}
