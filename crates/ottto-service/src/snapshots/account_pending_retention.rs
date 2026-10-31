//! Keep the endpoints of consecutive runs identical in every non-boundary field.
//! Boundaries remain separate from the consumer projection; current is never collapsed.
use super::{
    rfc3339_unix_seconds, ClaudeAccountFamilyPending, ClaudeAccountFamilyPendingWindow,
    ClaudeAccountRequestSet, ScanIndex,
};
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

/// Historical evidence view used by retirement and the load self-check.
/// Borrowed maps avoid allocating a second per-member representation.
#[derive(Debug, Clone, Copy)]
pub(super) struct ConsumerProjection<'a> {
    pub(super) account_identifier_hash: &'a str,
    pub(super) invalid: bool,
    member_keys: &'a BTreeMap<String, u64>,
    requests: &'a BTreeMap<String, ClaudeAccountRequestSet>,
}
impl<'a> ConsumerProjection<'a> {
    pub(super) fn members(self) -> impl Iterator<Item = (&'a String, Option<&'a String>)> {
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
    pub(super) fn consumer_projection(&self) -> ConsumerProjection<'_> {
        ConsumerProjection {
            account_identifier_hash: &self.account_identifier_hash,
            invalid: self.invalid,
            member_keys: &self.members,
            requests: &self.member_requests,
        }
    }
}

impl ClaudeAccountFamilyPending {
    pub(super) fn retirement_observations(
        &self,
    ) -> impl Iterator<Item = (Option<u64>, ConsumerProjection<'_>, bool)> {
        self.previous_windows
            .iter()
            .chain(std::iter::once(&self.current))
            .map(|window| {
                (
                    rfc3339_unix_seconds(&window.census_window_end),
                    window.consumer_projection(),
                    std::ptr::eq(window, &self.current),
                )
            })
    }

    /// First equal predecessor creates the second endpoint. Later equal pushes
    /// replace only that endpoint. A -> B -> A always starts distinct runs.
    pub(super) fn retain_previous_window(&mut self, old: ClaudeAccountFamilyPendingWindow) {
        let len = self.previous_windows.len();
        if len >= 2 {
            let first = &self.previous_windows[len - 2];
            let last = &self.previous_windows[len - 1];
            if let (Some(a), Some(b), Some(c), Some(current)) = (
                rfc3339_unix_seconds(&first.census_window_end),
                rfc3339_unix_seconds(&last.census_window_end),
                rfc3339_unix_seconds(&old.census_window_end),
                rfc3339_unix_seconds(&self.census_window_end),
            ) {
                if a < b
                    && b < c
                    && c < current
                    && first.strict_evidence() == last.strict_evidence()
                    && last.strict_evidence() == old.strict_evidence()
                {
                    self.previous_windows[len - 1] = old;
                    return;
                }
            }
        }
        self.previous_windows.push(old);
    }

    fn apply_checked_plan(&mut self, retained: Vec<usize>) -> Option<usize> {
        if history_projection(self, 0..self.previous_windows.len())
            != history_projection(self, retained.iter().copied())
        {
            return None;
        }
        let removed = self.previous_windows.len() - retained.len();
        if removed != 0 {
            let mut retained = retained.into_iter().peekable();
            let mut position = 0;
            self.previous_windows.retain(|_| {
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
        let current = rfc3339_unix_seconds(&self.census_window_end)?;
        let mut previous = None;
        for window in &self.previous_windows {
            let time = rfc3339_unix_seconds(&window.census_window_end)?;
            if time >= current || previous.is_some_and(|previous| time <= previous) {
                return None;
            }
            previous = Some(time);
        }
        let mut retained = Vec::new();
        let mut read = 0;
        while read < self.previous_windows.len() {
            let start = read;
            read += 1;
            while read < self.previous_windows.len()
                && self.previous_windows[start].strict_evidence()
                    == self.previous_windows[read].strict_evidence()
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

/// Per-root decision summary: historical existence, the union of member keys,
/// and each member's winning boundary/account/invalid/revision. This covers the
/// retirement walk's absence check and timestamp competition, plus scheduling's
/// history-nonempty predicate. References borrow existing evidence, never clone
/// the history. Current-window gates and family-level holds are untouched.
#[derive(Debug, PartialEq, Eq)]
struct HistoryProjection<'a> {
    history_nonempty: bool,
    latest: BTreeMap<&'a String, (u64, &'a str, bool, Option<&'a String>)>,
}
fn history_projection<'a>(
    pending: &'a ClaudeAccountFamilyPending,
    retained: impl Iterator<Item = usize>,
) -> Option<HistoryProjection<'a>> {
    let mut history_nonempty = false;
    let mut latest = BTreeMap::new();
    for window in retained
        .map(|i| {
            history_nonempty = true;
            &pending.previous_windows[i]
        })
        .chain(std::iter::once(&pending.current))
    {
        let time = rfc3339_unix_seconds(&window.census_window_end)?;
        let projection = window.consumer_projection();
        for (member, revision) in projection.members() {
            if latest
                .get(member)
                .map_or(true, |(previous, _, _, _)| time > *previous)
            {
                latest.insert(
                    member,
                    (
                        time,
                        projection.account_identifier_hash,
                        projection.invalid,
                        revision,
                    ),
                );
            }
        }
    }
    Some(HistoryProjection {
        history_nonempty,
        latest,
    })
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
            let before = window_bytes(&pending.previous_windows);
            counts.window_bytes_before = counts.window_bytes_before.saturating_add(before);
            let mut after = before;
            let plan = if opaque_holds && !pending.previous_windows.is_empty() {
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
                            after = window_bytes(&pending.previous_windows);
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
            previous_windows: vec![
                window(0, "historical"),
                window(1, "historical"),
                window(2, "historical"),
            ],
            confirmed_absent_members: BTreeSet::new(),
        };
        let before = serde_json::to_vec(&pending).unwrap();
        // A deliberately defective plan drops the last historical endpoint.
        assert_eq!(pending.apply_checked_plan(vec![0]), None);
        assert_eq!(serde_json::to_vec(&pending).unwrap(), before);
        assert_eq!(pending.apply_checked_plan(vec![0, 2]), Some(1));
    }
}
