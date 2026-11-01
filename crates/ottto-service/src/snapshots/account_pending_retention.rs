//! Keep the newest window of each run of consecutive windows with equal
//! strict evidence. Boundaries remain separate from the consumer projection;
//! current is never collapsed.
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
/// `census_complete` is excluded: only the current window's flag gates
/// retirement, and no reader of an archived window uses it.
impl ClaudeAccountFamilyPendingWindow {
    fn strict_evidence(&self) -> impl PartialEq + '_ {
        let Self {
            version,
            census_window_end: _,
            account_identifier_hash,
            evidence_request_count,
            census_complete: _,
            members,
            member_requests,
            invalid,
        } = self;
        (
            version,
            account_identifier_hash,
            evidence_request_count,
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

    /// Windows older than their equal-evidence run's newest, boundaries
    /// unchecked; a cold archive is never walked.
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
/// One rollover under a cold archive, with the current boundary the
/// run rule reads. Cold archives exist only without raw holds, where
/// every rollover is strict. `seq` is unique in the process and survives
/// clones, so a save of a sibling graph names the rollovers it committed.
#[derive(Clone, PartialEq, Eq)]
struct Rolled {
    window: ClaudeAccountFamilyPendingWindow,
    current_end: String,
    seq: u64,
}
crate::heap_layout_bound::fields!(Rolled; window, current_end, seq);
static ROLL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
impl ColdWindows {
    /// Stored archived rows and the last one's id.
    pub(super) fn base(&self) -> (usize, Option<u64>) {
        (self.stored, self.last_id)
    }

    pub(super) fn has_rolled(&self) -> bool {
        !self.rolled.is_empty()
    }

    /// Whether rollovers remain queued after the first `skip`.
    pub(super) fn rolls_after(&self, skip: usize) -> bool {
        self.rolled.len() > skip
    }

    /// The last queued rollover's sequence.
    pub(super) fn last_roll(&self) -> Option<u64> {
        self.rolled.last().map(|rolled| rolled.seq)
    }

    /// How many queued rollovers a committed save of this graph or a clone
    /// already wrote, given the last one it wrote; None if none of ours.
    pub(super) fn committed(&self, last: Option<u64>) -> Option<usize> {
        let last = last?;
        let at = self.rolled.iter().position(|rolled| rolled.seq == last)?;
        Some(at + 1)
    }

    /// `tail` is the stored archive's last window, if any. The run rule reads
    /// only that one, so the result ends exactly as the resident archive
    /// would after the same rollovers. The first `skip` rollovers are already
    /// in the store; `archived` counts the outcomes of the rest.
    pub(super) fn replay(
        &self,
        mut tail: Vec<ClaudeAccountFamilyPendingWindow>,
        skip: usize,
        archived: &mut Archived,
    ) -> Vec<ClaudeAccountFamilyPendingWindow> {
        for rolled in &self.rolled[skip..] {
            let replaced =
                retain_run_endpoint(&mut tail, rolled.window.clone(), &rolled.current_end);
            archived.note(replaced);
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
}
impl ColdFold {
    pub(super) fn push(&mut self, window: ClaudeAccountFamilyPendingWindow) {
        self.cold.summary.fold(&window);
        self.cold.stored += 1;
        let same = self
            .last
            .as_ref()
            .is_some_and(|last| last.strict_evidence() == window.strict_evidence());
        if same {
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
    /// newest window of an equal run; opaque evidence is funded by the whole
    /// encoded index, so it keeps every window until the hold resolves. A
    /// cold archive folds the window now and queues it for the next save,
    /// whose replay counts its outcome.
    pub(super) fn archive(&mut self, old: ClaudeAccountFamilyPendingWindow, strict: bool) {
        let current_end = &self.current.census_window_end;
        match &mut self.previous_windows {
            ArchivedWindows::Resident(windows) if strict => {
                let replaced = retain_run_endpoint(windows, old, current_end);
                Archived::note_resident(replaced);
            }
            ArchivedWindows::Resident(windows) => {
                windows.push(old);
                Archived::note_resident(false);
            }
            ArchivedWindows::Cold(cold) => {
                debug_assert!(strict, "cold archives exist only without raw holds");
                cold.summary.fold(&old);
                cold.rolled.push(Rolled {
                    window: old,
                    current_end: current_end.clone(),
                    seq: ROLL_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                });
            }
        }
    }
}

fn apply_checked_plan(
    windows: &mut Vec<ClaudeAccountFamilyPendingWindow>,
    retained: Vec<usize>,
) -> Option<usize> {
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

/// Validate before proposing any removal. Unsafe histories stay byte-for-byte
/// equivalent in RAM; in particular no malformed boundary disappears.
fn collapse_plan(
    windows: &[ClaudeAccountFamilyPendingWindow],
    current_end: &str,
) -> Option<Vec<usize>> {
    let current = rfc3339_unix_seconds(current_end)?;
    let mut previous = None;
    for window in windows {
        let time = rfc3339_unix_seconds(&window.census_window_end)?;
        if time >= current || previous.is_some_and(|previous| time <= previous) {
            return None;
        }
        previous = Some(time);
    }
    // Boundaries are strictly increasing, so a run's newest window carries
    // every member's winning evidence for that run.
    let mut retained = Vec::new();
    for (at, window) in windows.iter().enumerate() {
        if windows.get(at + 1).map_or(true, |next| {
            next.strict_evidence() != window.strict_evidence()
        }) {
            retained.push(at);
        }
    }
    Some(retained)
}

/// An archived window equal to the last one at an ordered boundary replaces
/// it, so a run keeps one window, its newest. Equal members make the replaced
/// window win no member's summary. A -> B -> A always starts distinct runs.
/// Returns whether the last window was replaced.
fn retain_run_endpoint(
    windows: &mut Vec<ClaudeAccountFamilyPendingWindow>,
    old: ClaudeAccountFamilyPendingWindow,
    current_end: &str,
) -> bool {
    if let Some(last) = windows.last_mut() {
        if let (Some(b), Some(c), Some(current)) = (
            rfc3339_unix_seconds(&last.census_window_end),
            rfc3339_unix_seconds(&old.census_window_end),
            rfc3339_unix_seconds(current_end),
        ) {
            if b < c && c < current && last.strict_evidence() == old.strict_evidence() {
                *last = old;
                return true;
            }
        }
    }
    windows.push(old);
    false
}

/// Archived windows per outcome: replaced a run's newest window, or appended.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Archived {
    pub(super) replaced: u64,
    pub(super) pushed: u64,
}
// Resident archives decide at rollover; the next committed v2 save drains them.
static RESIDENT_REPLACED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static RESIDENT_PUSHED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
impl Archived {
    fn note(&mut self, replaced: bool) {
        if replaced {
            self.replaced += 1;
        } else {
            self.pushed += 1;
        }
    }

    fn note_resident(replaced: bool) {
        let counter = if replaced {
            &RESIDENT_REPLACED
        } else {
            &RESIDENT_PUSHED
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Resident outcomes since the last call.
    pub(super) fn take_resident() -> Self {
        Self {
            replaced: RESIDENT_REPLACED.swap(0, std::sync::atomic::Ordering::Relaxed),
            pushed: RESIDENT_PUSHED.swap(0, std::sync::atomic::Ordering::Relaxed),
        }
    }
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
            // A cold archive is not loaded: v2 replays the run rule at
            // save. Windows the walk would have collapsed show as
            // `uncollapsed` in the save's retained-windows event.
            let ArchivedWindows::Resident(windows) = &mut pending.previous_windows else {
                continue;
            };
            let before = window_bytes(windows);
            counts.window_bytes_before = counts.window_bytes_before.saturating_add(before);
            let mut after = before;
            let plan = if opaque_holds && !windows.is_empty() {
                None
            } else {
                collapse_plan(windows, &pending.current.census_window_end)
            };
            match plan {
                None => counts.roots_refused = counts.roots_refused.saturating_add(1),
                Some(retained) => {
                    // Check proposed summaries before deleting anything. A
                    // mismatch leaves this root unchanged, without a backup.
                    match apply_checked_plan(windows, retained) {
                        None => counts.roots_refused = counts.roots_refused.saturating_add(1),
                        Some(0) => {}
                        Some(removed) => {
                            after = window_bytes(windows);
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

    /// One member with a tagged request set; `account` also names the revision.
    fn rolled_window(
        minute: u32,
        complete: bool,
        account: char,
    ) -> ClaudeAccountFamilyPendingWindow {
        let hashes = BTreeSet::from(["e".repeat(64)]);
        let mut requests = ClaudeAccountRequestSet::from_full_hashes(&hashes).unwrap();
        requests.identity_revision = Some(account.to_string().repeat(64));
        ClaudeAccountFamilyPendingWindow {
            version: super::super::CLAUDE_ACCOUNT_REQUEST_SET_VERSION.into(),
            census_window_end: format!("2026-08-02T07:{minute:02}:00Z"),
            account_identifier_hash: account.to_string().repeat(64),
            evidence_request_count: 1,
            census_complete: complete,
            members: BTreeMap::from([("member".into(), 1)]),
            member_requests: BTreeMap::from([("member".into(), requests)]),
            invalid: false,
        }
    }

    /// Rolls each window of `sequence` in turn through `archive`, resident and
    /// cold. The cold replay over an empty store must end as the resident
    /// archive, with `replaced` replacements and one push per kept window, and
    /// both summaries must equal the summary of every archived window.
    fn roll_through(
        sequence: &[ClaudeAccountFamilyPendingWindow],
        replaced: u64,
    ) -> Vec<ClaudeAccountFamilyPendingWindow> {
        let mut arms = [
            ArchivedWindows::default(),
            ArchivedWindows::Cold(Box::default()),
        ]
        .map(|previous_windows| ClaudeAccountFamilyPending {
            current: sequence[0].clone(),
            previous_windows,
            confirmed_absent_members: BTreeSet::new(),
        });
        for pending in &mut arms {
            for next in &sequence[1..] {
                let old = std::mem::replace(&mut pending.current, next.clone());
                pending.archive(old, true);
            }
        }
        let [resident, cold] = arms;
        let ArchivedWindows::Cold(queued) = &cold.previous_windows else {
            panic!("cold arm stays cold");
        };
        let mut outcomes = Archived::default();
        let replayed = queued.replay(Vec::new(), 0, &mut outcomes);
        let archive = resident.previous_windows.resident().clone();
        assert_eq!(replayed, archive);
        let pushed = archive.len() as u64;
        assert_eq!(outcomes, Archived { replaced, pushed });
        let every = HistorySummary::from_windows(&sequence[..sequence.len() - 1]);
        assert!(resident.history_summary() == every);
        assert!(cold.history_summary() == every);
        archive
    }

    #[test]
    fn identical_rolls_keep_only_the_newest_window() {
        let sequence: Vec<_> = (0..4)
            .map(|minute| rolled_window(minute, true, 'a'))
            .collect();
        assert_eq!(roll_through(&sequence, 2), [sequence[2].clone()]);
    }

    #[test]
    fn census_completion_flips_do_not_split_a_run() {
        let sequence: Vec<_> = [true, false, true, true]
            .into_iter()
            .enumerate()
            .map(|(minute, complete)| rolled_window(minute as u32, complete, 'a'))
            .collect();
        assert_eq!(roll_through(&sequence, 2), [sequence[2].clone()]);
    }

    #[test]
    fn a_real_evidence_change_a_b_a_keeps_three_windows() {
        let sequence: Vec<_> = ['a', 'b', 'a', 'a']
            .into_iter()
            .enumerate()
            .map(|(minute, account)| rolled_window(minute as u32, true, account))
            .collect();
        assert_eq!(roll_through(&sequence, 0), sequence[..3].to_vec());
    }

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
        let plan = |pending: &mut ClaudeAccountFamilyPending, retained| {
            apply_checked_plan(pending.previous_windows.resident_mut(), retained)
        };
        assert_eq!(plan(&mut pending, vec![0]), None);
        assert_eq!(serde_json::to_vec(&pending).unwrap(), before);
        assert_eq!(plan(&mut pending, vec![0, 2]), Some(1));
    }
}
