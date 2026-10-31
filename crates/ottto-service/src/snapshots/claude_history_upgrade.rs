//! The one gate for Claude Code history that would be re-sent under a new
//! body-witness revision, whatever the reason a file is parsed.
//!
//! A history upgrade is owed when an unchanged file's stored revision is below
//! the active one (a missing or zero stamp counts as below), or when a file
//! that is new to the index was born before the index's history cutoff (or at
//! an unknown time). The cutoff is set when a destination that already
//! completed its Claude history bootstrap loads a fresh index (absent,
//! quarantined or undecodable) or a historical replay drops its entries; the
//! backfill state, not the index, remembers that bootstrap, so the signal
//! survives index loss. Unchanged means the same size and mtime
//! as the entry before this parse; the mixed source fingerprint is not used,
//! so a re-armed file (fingerprint cleared) is unchanged history.
//!
//! An owed upgrade passes only the protected-list state, the listed-family
//! skip, the no-list birth hold, the Amendment 10/11 stop latch and the page
//! budget, in that order. The no-list birth hold applies only where the
//! list is not intended (no list file and no seen-marker) and the Mac's
//! history is unverified or was recorded for another destination under a
//! claim policy other than an explicit `full` (`NoListPolicy`); everywhere
//! else without a list, owed history is paced through the budget (SOURCE
//! Amendment 16, StateMissing N1). A held file may still be parsed for its other
//! reason (census records, proofs, index identity), but none of its new
//! bodies reaches an upload path, and its upload tuple (revision, semantic
//! group, body witness, membership) stays as it was. A file that only owes
//! the upgrade is skipped as before; one held only by the page budget, once
//! the page admitted history, is queued again as a re-read (never a census
//! member) for the next page of the same walk, so a revision bump re-reads
//! the history in consecutive paced pages instead of one page per walk.
//!
//! The parse reason is a diagnostic only; no decision here reads it.
//!
//! Under a revision whose policy row denies the request-owned literal
//! (revision 3, SOURCE Amendment 14), a listed family, or any family while
//! the list is paused, still emits its ordinary body on a genuine change, as
//! today. Only items carrying `claude_request_owned_usage:v1` are removed,
//! and the file never stamps that revision, so it stays owed and gated.
//!
//! The only writers of a file's stored revision are
//! `stamp_effective_upload_body_witness_revision` (raise) and
//! `re_owe_effective_upload_body_witness_revision` (lower).

use super::claude_reemission_exclusions::{ListState, ReemissionExclusions};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Most history files one page may upgrade, for every revision (MONEY P2).
pub(super) const HISTORY_UPGRADE_FILES_PER_PAGE: usize = 2_000;
/// Bytes of history one page may upgrade (1 GiB), for every revision. No
/// file is admitted past it, including a page's first file.
pub(super) const HISTORY_UPGRADE_BYTES_PER_PAGE: u64 = 1024 * 1024 * 1024;
/// Highest active Claude revision the gate is open for (SOURCE F2). MONEY's
/// activation (E2) raised it to the revision-3 row together with
/// the Claude revision constant and the E2 gate (SOURCE h732 C1). Above it
/// every owed upgrade and every listed change is held, no file is stamped,
/// activation is refused at runtime
/// (`activate_effective_upload_body_witness_revision`), and the Claude
/// revision constant fails to compile. The release check reads the next
/// line, so keep it free of comments and other digits.
pub(crate) const MAX_GATED_CLAUDE_REVISION: u64 = 3;
/// E2's request-owned usage literal. Listed roots never emit it.
pub(crate) const REQUEST_OWNED_USAGE_CONTRACT: &str = "claude_request_owned_usage:v1";

/// At most one owed-without-list alarm an hour.
const OWED_WITHOUT_LIST_ALARM_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60 * 60);

/// What a listed family (or, while the list is paused, any family) may emit
/// when it is parsed as ordinary sync under one revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ListedEmission {
    /// Its whole body, as today.
    Ordinary,
    /// Its ordinary body; every item carrying the request-owned literal is
    /// removed, and the file never stamps this revision.
    WithoutRequestOwnedLiteral,
}

/// What one active revision allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RevisionPolicy {
    /// A listed family's (or, while the list is paused, any family's)
    /// ordinary sync, a genuine change included. Revision 2 adds only
    /// context numbers; revision 3 adds request-owned money, which listed
    /// roots must never emit (F3, Amendment 14).
    pub(super) listed_emission: ListedEmission,
    /// Before the list was ever installed, history born before this second,
    /// or at an unknown time, is held under this revision (F4b).
    pub(super) no_list_birth_cutoff_unix_seconds: u64,
}

/// The per-revision policy table. An unknown revision, or one above
/// `MAX_GATED_CLAUDE_REVISION`, has no row: it cannot be activated, and
/// every owed upgrade and every listed change is held.
pub(super) fn revision_policy(revision: u64) -> Option<RevisionPolicy> {
    if revision > max_gated_claude_revision() {
        return None;
    }
    match revision {
        0..=2 => Some(RevisionPolicy {
            listed_emission: ListedEmission::Ordinary,
            no_list_birth_cutoff_unix_seconds:
                super::claude_reemission_exclusions::NO_LIST_HOLD_BEFORE_UNIX_SECONDS,
        }),
        // Until owner B dates revision 3's no-list cutoff, no history born
        // at any time is upgraded to it without an installed list.
        3 => Some(RevisionPolicy {
            listed_emission: ListedEmission::WithoutRequestOwnedLiteral,
            no_list_birth_cutoff_unix_seconds: u64::MAX,
        }),
        _ => None,
    }
}

#[cfg(not(test))]
pub(super) fn max_gated_claude_revision() -> u64 {
    MAX_GATED_CLAUDE_REVISION
}

#[cfg(test)]
thread_local! {
    static MAX_GATED_FOR_TEST: std::cell::Cell<u64> =
        const { std::cell::Cell::new(MAX_GATED_CLAUDE_REVISION) };
}

#[cfg(test)]
pub(super) fn max_gated_claude_revision() -> u64 {
    MAX_GATED_FOR_TEST.with(std::cell::Cell::get)
}

/// Test seam: run `f` as if the policy table ended at `max` (a revision
/// above it has no row).
#[cfg(test)]
pub(crate) fn with_max_gated_claude_revision<T>(max: u64, f: impl FnOnce() -> T) -> T {
    struct Reset(u64);
    impl Drop for Reset {
        fn drop(&mut self) {
            MAX_GATED_FOR_TEST.with(|value| value.set(self.0));
        }
    }
    let _reset = Reset(MAX_GATED_FOR_TEST.with(|value| value.replace(max)));
    f()
}

/// How one candidate stands before its parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HistoryKind {
    /// Nothing owed: the stored revision covers the active one.
    Settled,
    /// The transcript changed since its entry was recorded.
    Changed,
    /// A new file born after the history cutoff second, or with no cutoff.
    Fresh,
    /// Unchanged history that would carry a new revision.
    Owed,
}

/// Where a destination's Claude prior-history evidence comes from. It is read
/// before scanning from state outside the index, so it survives index loss
/// (SOURCE F1a/F1b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PriorHistory {
    /// A positively fresh support state.
    None,
    /// This destination's own history (its completed bootstrap, a
    /// server-attested ledger record, a quarantined copy of its index), or
    /// the re-emission seen-marker.
    Here,
    /// History only another destination or a legacy layout recorded: a
    /// re-pair or an account move.
    Moved,
    /// The backfill state is unreadable, so this Mac's history is unknown.
    Unverified,
}

impl PriorHistory {
    pub(crate) fn any(self) -> bool {
        self != Self::None
    }
}

/// What owed history does where the protected list is not intended: no list
/// file and no seen-marker (`ListState::NotInstalled`). An intended list
/// (present, or its marker written once) applies the list rules instead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum NoListPolicy {
    /// Paced through the page budget: this destination's own history, a
    /// fresh install, or another destination's history under an explicit
    /// `full` claim (StateMissing N1; SOURCE ruling on a cross-org move).
    #[default]
    Pace,
    /// Held up to the later of 2026-10-21 and the history cutoff (SOURCE
    /// F4a): the backfill state is unreadable, so the Mac fails closed.
    HoldUnverified,
    /// Held likewise: history recorded for another destination (a re-pair
    /// or account move) under any claim policy but an explicit `full`. The
    /// named policy row for SOURCE's cross-org move ruling.
    HoldMoveNotFull,
}

impl crate::heap_layout_bound::HeapLayoutBound for NoListPolicy {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// Size and mtime of a file, as the index entry or the candidate holds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileExtent {
    pub(super) size_bytes: u64,
    pub(super) modified_unix_seconds: u64,
    pub(super) modified_unix_nanos: Option<u64>,
}

/// Classify a candidate against its entry before this parse.
/// `stored_below_active` is the index's own revision comparison for the
/// entry (true for a zero or missing stamp while a revision is active).
/// Only a size change is a genuine change: a same-size file whose mtime
/// alone moved (a touch, a copy, a restore) is unchanged history (F5).
pub(super) fn classify(
    entry: Option<FileExtent>,
    candidate: FileExtent,
    stored_below_active: bool,
    history_cutoff_unix_seconds: Option<u64>,
    birth_unix_seconds: Option<u64>,
) -> HistoryKind {
    let Some(entry) = entry else {
        let history = stored_below_active
            && history_cutoff_unix_seconds
                .is_some_and(|cutoff| !matches!(birth_unix_seconds, Some(birth) if birth > cutoff));
        return if history {
            HistoryKind::Owed
        } else {
            HistoryKind::Fresh
        };
    };
    if entry.size_bytes != candidate.size_bytes {
        HistoryKind::Changed
    } else if stored_below_active {
        HistoryKind::Owed
    } else {
        HistoryKind::Settled
    }
}

/// Why an owed upgrade (or a listed change) is not emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HistoryHold {
    /// The active revision has no policy row.
    UngatedRevision,
    /// The list is unreadable, missing after install, unrecorded, or its
    /// family closure overflowed.
    ListPaused,
    /// The list names the family.
    Listed,
    /// No list is intended, the Mac's history is unverified, and the file
    /// was born before the cutoff, or at an unknown time.
    NoListBirth,
    /// No list is intended, the history was recorded for another
    /// destination under a claim policy other than an explicit `full`, and
    /// the file was born before the cutoff, or at an unknown time.
    MoveNotFull,
    /// The stop latch is set (evidence bound or index rebuild).
    Latched,
    /// This page's history budget is spent.
    Budget,
    /// This page could not read Claude telemetry (E2 gate on): an upgrade
    /// would settle on transcript estimates for good, so it waits.
    TelemetryUnread,
}

impl HistoryHold {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UngatedRevision => "ungated_revision",
            Self::ListPaused => "list_paused",
            Self::Listed => "listed",
            Self::NoListBirth => "no_list_birth",
            Self::MoveNotFull => "move_not_full",
            Self::Latched => "latched",
            Self::Budget => "budget",
            Self::TelemetryUnread => "telemetry_unread",
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for HistoryHold {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// The gate's answer for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HistoryDecision {
    /// Not history: ordinary sync.
    NotOwed,
    /// Owed and permitted; the page budget is reserved for this file.
    Owed,
    /// Owed (or a listed change) and held: no body of this file is emitted.
    Held(HistoryHold),
    /// Ordinary sync of a listed family (or of any family while the list is
    /// paused) under a revision that denies the request-owned literal: the
    /// ordinary body emits, literal items are removed, and the file does not
    /// stamp the active revision.
    LiteralDenied,
}

/// Claude member files present under two or more paths (path twins), by
/// member id (`root` or `root_agent-*`): indexed paths with their indexed
/// sizes, plus paths this traversal observed that are not indexed yet
/// (`None`: a first-seen twin or a new copy). Twin groups are kept, plus the
/// single known path of a member this page reads: a page file not indexed
/// or observed yet (a new copy) is that path's twin. `path_twins` is the
/// twin-group view.
pub(super) type ClaudeTwinGroups = BTreeMap<String, Vec<(String, Option<u64>)>>;

/// The member's path twins: two or more known paths.
pub(super) fn path_twins<'a>(
    groups: &'a ClaudeTwinGroups,
    member: &str,
) -> Option<&'a [(String, Option<u64>)]> {
    groups
        .get(member)
        .filter(|keys| keys.len() > 1)
        .map(Vec::as_slice)
}

/// E2: the ONE path-twin rule and member spelling. Built once per scan page
/// (`HistoryPage::twin_groups`) and shared by candidate selection, twin
/// staging and the parse-time birth context; the page finish (after the
/// scan) builds it again only when a session's birth table names a path the
/// page does not hold. One sorted borrowed pass.
pub(super) fn claude_path_twin_groups(
    index: &super::ScanIndex,
    page_members: &BTreeSet<String>,
) -> ClaudeTwinGroups {
    let files = &index.files;
    let unindexed = index
        .traversal
        .as_ref()
        .map(|traversal| &traversal.observed_index_keys)
        .into_iter()
        .flatten()
        .filter(|key| !files.contains_key(*key))
        .map(|key| (key.as_str(), None));
    let mut members = files
        .iter()
        .map(|(key, entry)| (key.as_str(), Some(entry.size_bytes)))
        .chain(unindexed)
        .filter_map(|(key, size)| {
            let member = super::claude_index_path_member_ref(std::path::Path::new(key))?;
            Some(((member.root, member.subagent_stem), member, key, size))
        })
        .collect::<Vec<_>>();
    members.sort_unstable_by(|left, right| (left.0, left.2).cmp(&(right.0, right.2)));
    members
        .chunk_by(|left, right| left.0 == right.0)
        .filter(|group| {
            let member = &group[0].1;
            // Borrowed page lookup: the members sharing this root, then the stem.
            group.len() > 1
                || page_members
                    .range::<str, _>((
                        std::ops::Bound::Included(member.root),
                        std::ops::Bound::Unbounded,
                    ))
                    .take_while(|page| page.starts_with(member.root))
                    .any(|page| member.matches_member(page))
        })
        .map(|group| {
            let keys = group
                .iter()
                .map(|(_, _, key, size)| ((*key).to_owned(), *size))
                .collect();
            (group[0].1.into_owned().1, keys)
        })
        .collect()
}

/// The native read set for readable seeds: twins force every known member
/// of their root family, as do independent authority-forced roots. Shared by
/// scoped estimate/apply/preparation and native forced-family selection.
pub(super) fn claude_read_closure<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
    family_keys: impl IntoIterator<Item = &'a String>,
    twins: &ClaudeTwinGroups,
    forced_roots: &BTreeSet<String>,
) -> BTreeSet<PathBuf> {
    let mut paths = paths
        .into_iter()
        .map(Path::to_path_buf)
        .collect::<BTreeSet<_>>();
    let mut roots = crate::snapshots::claude_request_money::e2::selected_twin_roots(
        paths.iter().map(PathBuf::as_path),
        twins,
    );
    roots.extend(forced_roots.iter().cloned());
    paths.extend(family_keys.into_iter().filter_map(|key| {
        let path = Path::new(key);
        let member = super::claude_index_path_member_ref(path)?;
        roots.contains(member.root).then(|| path.to_path_buf())
    }));
    paths
}

/// One opened-birth probe of a path (metadata only, no content read), with
/// the test seam that stands in for creation time on Linux.
pub(super) fn probe_opened_birth(
    key: &str,
) -> Option<super::claude_context_file_birth::ClaudeOpenedBirth> {
    let opened = std::fs::metadata(key)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| super::claude_context_file_birth::ClaudeOpenedBirth::from_metadata(&m));
    #[cfg(test)]
    let opened = opened.map(|mut opened| {
        if let Some(birth) = STAGED_BIRTHS_FOR_TEST
            .with(|births| births.borrow().get(key).copied())
            .or_else(super::claude_request_money::e2::fixture_birth)
        {
            opened.birth = birth;
        }
        opened
    });
    opened
}

// Test-only synthetic physical births for staged twin probes, matching the
// parser's birth setter: Linux has no portable set-creation-time API.
#[cfg(test)]
thread_local! {
    static STAGED_BIRTHS_FOR_TEST: std::cell::RefCell<BTreeMap<String, u64>> =
        const { std::cell::RefCell::new(BTreeMap::new()) };
}

/// The staged synthetic birth of `key`, if any: the parser's opened-birth
/// read uses it too, so a Linux benchmark corpus has controlled births.
#[cfg(test)]
pub(super) fn staged_birth_for_test(key: &str) -> Option<u64> {
    STAGED_BIRTHS_FOR_TEST.with(|births| births.borrow().get(key).copied())
}

#[cfg(test)]
pub(crate) fn with_staged_births_for_test<T>(
    births: BTreeMap<String, u64>,
    run: impl FnOnce() -> T,
) -> T {
    let previous = STAGED_BIRTHS_FOR_TEST.with(|slot| slot.replace(births));
    let value = run();
    STAGED_BIRTHS_FOR_TEST.with(|slot| slot.replace(previous));
    value
}

/// The `history_emission_denied` reason of a literal-only denial.
pub(super) const LISTED_LITERAL_REASON: &str = "listed_literal";

/// Inputs the policy reads besides the classification.
pub(super) struct PolicyInputs<'a> {
    pub(super) exclusions: &'a ReemissionExclusions,
    pub(super) listed: bool,
    pub(super) birth_unix_seconds: Option<u64>,
    pub(super) latched: bool,
    pub(super) active_revision: u64,
    /// The index's history cutoff (rebuilt or prior-install history).
    pub(super) history_cutoff_unix_seconds: Option<u64>,
    /// What owed history does where no list is intended.
    pub(super) no_list_policy: NoListPolicy,
}

/// Apply the list, the birth hold, the family skip, the latch, the budget
/// and the per-revision policy. The budget is reserved once per index key.
pub(super) fn decide(
    kind: HistoryKind,
    inputs: &PolicyInputs<'_>,
    page: &mut HistoryPage,
    index_key: &str,
    size_bytes: u64,
) -> HistoryDecision {
    let policy = revision_policy(inputs.active_revision);
    // Under a paused list no family can be shown unlisted (F3).
    let maybe_listed = inputs.listed || inputs.exclusions.pauses_adoption();
    let decision = match kind {
        HistoryKind::Settled | HistoryKind::Fresh | HistoryKind::Changed => match policy {
            None if inputs.listed => HistoryDecision::Held(HistoryHold::UngatedRevision),
            Some(RevisionPolicy {
                listed_emission: ListedEmission::WithoutRequestOwnedLiteral,
                ..
            }) if maybe_listed => HistoryDecision::LiteralDenied,
            _ => HistoryDecision::NotOwed,
        },
        HistoryKind::Owed => {
            let hold = if policy.is_none() {
                Some(HistoryHold::UngatedRevision)
            } else if inputs.exclusions.pauses_adoption() {
                Some(HistoryHold::ListPaused)
            } else if inputs.listed {
                Some(HistoryHold::Listed)
            } else if let Some(hold) = no_list_hold(inputs, policy) {
                Some(hold)
            } else if inputs.latched {
                Some(HistoryHold::Latched)
            } else if !page.reserve(index_key, size_bytes) {
                Some(HistoryHold::Budget)
            } else {
                None
            };
            hold.map_or(HistoryDecision::Owed, HistoryDecision::Held)
        }
    };
    page.note(kind, decision, inputs.exclusions.state());
    decision
}

/// SOURCE F4a, narrowed by Amendment 16: where no list is intended and the
/// policy holds, owed history is held up to the later of the active
/// revision's own no-list cutoff (F4b) and the saved history cutoff. Unknown
/// birth is history. Under `Pace` nothing is held here; the budget paces it.
fn no_list_hold(inputs: &PolicyInputs<'_>, policy: Option<RevisionPolicy>) -> Option<HistoryHold> {
    let hold = match inputs.no_list_policy {
        NoListPolicy::Pace => return None,
        NoListPolicy::HoldUnverified => HistoryHold::NoListBirth,
        NoListPolicy::HoldMoveNotFull => HistoryHold::MoveNotFull,
    };
    let revision_cutoff =
        policy.map_or(u64::MAX, |policy| policy.no_list_birth_cutoff_unix_seconds);
    (inputs
        .exclusions
        .holds_without_list_before(inputs.birth_unix_seconds, revision_cutoff)
        || holds_until_history_cutoff(inputs))
    .then_some(hold)
}

/// The saved-cutoff half of the no-list hold.
fn holds_until_history_cutoff(inputs: &PolicyInputs<'_>) -> bool {
    inputs.exclusions.state() == ListState::NotInstalled
        && inputs.history_cutoff_unix_seconds.is_some_and(|cutoff| {
            inputs
                .birth_unix_seconds
                .map_or(true, |birth| birth <= cutoff)
        })
}

/// One page's history budget and its count-only, local diagnostics.
#[derive(Debug, Clone, Default)]
pub(crate) struct HistoryPage {
    // ON-only count of history files actually admitted to a parser, including
    // local work that bypasses the upgrade-only budget. No proof authority.
    read_files: usize,
    files: usize,
    bytes: u64,
    reserved: BTreeSet<String>,
    /// Candidates classified as owed upgrades.
    pub(super) owed: u64,
    /// Owed upgrades permitted on this page.
    pub(super) permitted: u64,
    /// Held candidates by (reason, list state).
    pub(super) denied: BTreeMap<(&'static str, &'static str), u64>,
    /// Family roots with a literal-only denial on this page. Local only:
    /// the census prints their count, never a root.
    pub(super) listed_literal_roots: BTreeSet<String>,
    /// Subagent members held as listed only through their family root, while
    /// the root file is absent (StateMissing M1, SOURCE d680b524).
    pub(super) family_closure_root_absent_excluded: u64,
    /// E2: the path twins (same Claude member file under another project
    /// directory, with indexed sizes) of the owed candidate being decided.
    /// Its reservation takes them too, both or neither.
    staged_twins: Option<(String, Vec<(String, u64)>)>,
    /// E2: this page's path-twin groups (`claude_path_twin_groups`), built
    /// once on first use (selection, staging or a parse-time birth context).
    twin_index: std::cell::OnceCell<ClaudeTwinGroups>,
    /// E2: this page cleared the birth table's page probes.
    birth_page_begun: bool,
}

crate::heap_layout_bound::fields!(HistoryPage; read_files, files, bytes, reserved, owed, permitted, denied, listed_literal_roots, family_closure_root_absent_excluded, staged_twins, twin_index, birth_page_begun);

impl HistoryPage {
    /// A page whose twin groups candidate selection already built.
    pub(super) fn with_twin_groups(twin_index: std::cell::OnceCell<ClaudeTwinGroups>) -> Self {
        Self {
            twin_index,
            ..Self::default()
        }
    }

    /// This page's twin groups, built on first use.
    pub(super) fn twin_groups(&self) -> &std::cell::OnceCell<ClaudeTwinGroups> {
        &self.twin_index
    }

    /// Reserve this page's budget for one file. A file reserved earlier on
    /// this page keeps its reservation and is not charged twice.
    pub(super) fn reserve(&mut self, index_key: &str, size_bytes: u64) -> bool {
        self.reserve_within(index_key, size_bytes, false)
    }

    /// Codex and Pi adoption-only pacing: the same budget, except that a
    /// page's first file is admitted whatever its size. A Codex transcript
    /// may exceed the byte budget, and without the exception it could never
    /// adopt. The Claude history gate never uses this.
    pub(super) fn reserve_admitting_first_file(
        &mut self,
        index_key: &str,
        size_bytes: u64,
    ) -> bool {
        self.reserve_within(index_key, size_bytes, true)
    }

    fn reserve_within(&mut self, index_key: &str, size_bytes: u64, first_file: bool) -> bool {
        if self.reserved.contains(index_key) {
            return true;
        }
        // E2 path twins settle as one entity, so they are reserved as one
        // group: a twin held only by this budget would hold its sibling's
        // body too, page after page. A page's first group passes the file
        // count (never the bytes), so a pair always fits within two pages.
        let twins = match self.staged_twins.take() {
            Some((key, twins)) if key == index_key => twins,
            _ => Vec::new(),
        };
        let twins = twins
            .into_iter()
            .filter(|(key, _)| !self.reserved.contains(key))
            .collect::<Vec<_>>();
        let files = 1 + twins.len();
        let bytes = twins
            .iter()
            .fold(size_bytes, |sum, (_, size)| sum.saturating_add(*size));
        let page_empty = self.files == 0;
        if (self.files.saturating_add(files) > super::body_witness_adoption_page_budget()
            && !(files > 1 && page_empty))
            || (self.bytes.saturating_add(bytes) > super::body_witness_adoption_byte_budget()
                && !(first_file && page_empty))
        {
            return false;
        }
        self.files += files;
        self.bytes = self.bytes.saturating_add(bytes);
        self.reserved.insert(index_key.to_owned());
        self.reserved.extend(twins.into_iter().map(|(key, _)| key));
        true
    }

    fn note(&mut self, kind: HistoryKind, decision: HistoryDecision, list: ListState) {
        if kind == HistoryKind::Owed {
            self.owed = self.owed.saturating_add(1);
        }
        match decision {
            HistoryDecision::Owed => self.permitted = self.permitted.saturating_add(1),
            HistoryDecision::Held(hold) => self.note_denied(hold, list),
            HistoryDecision::LiteralDenied => {
                self.note_reason(LISTED_LITERAL_REASON, list);
                note_listed_literal_denied();
            }
            HistoryDecision::NotOwed => {}
        }
    }

    pub(super) fn note_denied(&mut self, hold: HistoryHold, list: ListState) {
        self.note_reason(hold.as_str(), list);
    }

    fn note_reason(&mut self, reason: &'static str, list: ListState) {
        let count = self.denied.entry((reason, list.as_str())).or_default();
        *count = count.saturating_add(1);
    }

    /// Record the family root of a literal-only denial (once per root).
    pub(super) fn note_listed_literal_root(&mut self, root: &str) {
        if !self.listed_literal_roots.contains(root) {
            self.listed_literal_roots.insert(root.to_owned());
        }
    }

    /// Denials counted under one `history_emission_denied` reason.
    #[cfg(test)]
    pub(super) fn denied_for_reason(&self, reason: &str) -> u64 {
        self.denied
            .iter()
            .filter(|((denied, _), _)| *denied == reason)
            .map(|(_, count)| *count)
            .sum()
    }

    pub(super) fn denied_for(&self, holds: &[HistoryHold]) -> u64 {
        self.denied
            .iter()
            .filter(|((reason, _), _)| holds.iter().any(|hold| hold.as_str() == *reason))
            .map(|(_, count)| *count)
            .sum()
    }

    pub(super) fn note_family_closure_root_absent(&mut self) {
        self.family_closure_root_absent_excluded =
            self.family_closure_root_absent_excluded.saturating_add(1);
    }

    pub(super) fn note_history_read(&mut self) {
        if super::claude_terminal_off() {
            self.read_files = self.read_files.saturating_add(1);
        }
    }

    pub(super) fn emit_page_diagnostics(&self) {
        if !super::claude_terminal_off() {
            return;
        }
        let budget = super::body_witness_adoption_page_budget();
        crate::local_resource_diagnostics::traversal_point(
            "history_upgrade_page",
            "claude_code",
            &std::collections::BTreeMap::from([(
                "history_upgrade_page",
                std::collections::BTreeMap::from([
                    ("admitted_files", self.read_files),
                    ("budget", budget),
                    ("extra_files", self.read_files.saturating_sub(budget)),
                ]),
            )]),
        );
    }

    /// This page admitted at least one history file to its budget.
    pub(super) fn admitted_any(&self) -> bool {
        self.files > 0
    }

    pub(super) fn any(&self) -> bool {
        self.owed > 0 || !self.denied.is_empty() || self.family_closure_root_absent_excluded > 0
    }

    /// `reason:list_state=count` pairs for the census line, or `none`.
    pub(super) fn denied_summary(&self) -> String {
        if self.denied.is_empty() {
            return "none".to_owned();
        }
        self.denied
            .iter()
            .map(|((reason, list), count)| format!("{reason}:{list}={count}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// The upload-owned part of an index entry, kept for a held file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Its stored revision needs no copy: the parse carries it and the stamp
/// refuses a held file.
pub(super) struct HeldUploadTuple {
    pub(super) last_snapshot_fingerprint: Option<String>,
    pub(super) last_upload_body_witness: Option<String>,
    pub(super) file_snapshot_fingerprints: Option<BTreeSet<String>>,
    pub(super) confirmed_empty: bool,
}

crate::heap_layout_bound::fields!(HeldUploadTuple; last_snapshot_fingerprint, last_upload_body_witness, file_snapshot_fingerprints, confirmed_empty);

/// One gated Claude history file of this cycle, keyed by its source file
/// fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct GatedHistory {
    pub(super) index_key: String,
    /// `None` while permitted; a hold once denied.
    pub(super) held: Option<HistoryHold>,
    /// The gate permitted this upgrade (a later hold keeps it true).
    pub(super) permitted: bool,
    /// Ordinary sync whose request-owned literal is denied
    /// (`HistoryDecision::LiteralDenied`); never an upgrade.
    pub(super) literal_denied: bool,
    /// The entry's upload tuple before this parse; `None` for a new file.
    pub(super) previous: Option<HeldUploadTuple>,
    /// A held new file's local entity fingerprints. They name the file's
    /// semantic group only; they are never advertised as its membership.
    pub(super) local: BTreeSet<String>,
}

crate::heap_layout_bound::fields!(GatedHistory; index_key, held, permitted, literal_denied, previous, local);

/// Runtime-only gate state of one cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HistoryEmission {
    pub(super) files: BTreeMap<String, GatedHistory>,
    // Count-only diagnostics for carried files skipped before parsing. They
    // never enter the emission map or change any gate/finalization decision.
    pub(super) skipped_carried_entries: usize,
}

crate::heap_layout_bound::fields!(HistoryEmission; files, skipped_carried_entries);

impl HistoryEmission {
    pub(super) fn held(&self, source_file_fingerprint: &str) -> Option<HistoryHold> {
        self.files
            .get(source_file_fingerprint)
            .and_then(|gated| gated.held)
    }

    /// True when this source file emits only its ordinary body this cycle.
    pub(super) fn literal_denied(&self, source_file_fingerprint: &str) -> bool {
        self.files
            .get(source_file_fingerprint)
            .is_some_and(|gated| gated.held.is_none() && gated.literal_denied)
    }

    /// Whether this item may reach an upload path this cycle: no item of a
    /// held file, no request-owned literal of a literal-denied file, and no
    /// literal the guard denies whatever this cycle decided (C2).
    pub(super) fn permits(&self, item: &super::SnapshotItem, guard: &LiteralGuard) -> bool {
        if !guard.permits(item) {
            return false;
        }
        let Some(gated) = item
            .source_file_fingerprint
            .as_deref()
            .and_then(|fingerprint| self.files.get(fingerprint))
        else {
            return true;
        };
        gated.held.is_none() && !(gated.literal_denied && is_request_owned_literal(item))
    }

    /// Recheck the stop latch at the emission seam: a fold can latch after a
    /// candidate was permitted. A literal-denied file is ordinary sync, not
    /// an upgrade, and is not held.
    pub(super) fn hold_permitted_for_latch(&mut self) -> usize {
        self.hold_permitted(HistoryHold::Latched)
    }

    /// Hold every permitted upgrade of this cycle under `hold`. A
    /// literal-denied file is ordinary sync, not an upgrade, and is not held.
    fn hold_permitted(&mut self, hold: HistoryHold) -> usize {
        let mut held = 0;
        for gated in self.files.values_mut() {
            if gated.held.is_none() && !gated.literal_denied {
                gated.held = Some(hold);
                held += 1;
            }
        }
        held
    }
}

impl super::ScanIndex {
    /// E2: stage the births of every indexed path twin before the candidate
    /// folds; owed candidates also reserve their twins through HistoryPage.
    pub(super) fn stage_claude_history_twins(&mut self, index_key: &str, page: &mut HistoryPage) {
        if !page.birth_page_begun {
            page.birth_page_begun = true;
            self.claude_money_birth_store.begin_page();
        }
        let groups = page
            .twin_index
            .get_or_init(|| claude_path_twin_groups(self, &BTreeSet::new()));
        if let Some((_, member)) =
            super::claude_index_path_family_member(std::path::Path::new(index_key))
        {
            if let Some(keys) = path_twins(groups, &member) {
                for (key, size) in keys {
                    if self.claude_money_birth_store.staged(key) {
                        continue;
                    }
                    // Exactly one metadata read per indexed twin per page. No content read.
                    let opened = probe_opened_birth(key);
                    self.claude_money_birth_store.stage_opened(
                        &member,
                        key,
                        opened,
                        size.unwrap_or(0),
                    );
                }
            }
        }
        let twins = super::claude_index_path_family_member(std::path::Path::new(index_key))
            .and_then(|(_, member)| path_twins(groups, &member))
            .map(|keys| {
                // Only indexed twins carry a size to reserve.
                keys.iter()
                    .filter(|(key, _)| key != index_key)
                    .filter_map(|(key, size)| Some((key.clone(), (*size)?)))
                    .collect()
            })
            .unwrap_or_default();
        page.staged_twins = Some((index_key.to_owned(), twins));
    }

    /// E2: this page's Claude telemetry read failed. Every permitted owed
    /// upgrade is held (`telemetry_unread`) before the emission seam, so it
    /// emits nothing, keeps its upload tuple and stays owed: delayed, never
    /// settled on estimates. Returns how many files were held.
    pub(crate) fn hold_claude_history_for_unread_telemetry(&mut self) -> usize {
        self.claude_history_emission
            .hold_permitted(HistoryHold::TelemetryUnread)
    }
}

/// The one predicate for a request-owned literal body (gate, emitter, upload
/// batcher, ACK validation).
pub(crate) fn is_request_owned_literal(item: &super::SnapshotItem) -> bool {
    item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_USAGE_CONTRACT)
}

/// The Claude family root a request-owned literal body uploads with; `None`
/// for every other body. Typed: no serialization.
pub(crate) fn request_owned_family_root(item: &super::SnapshotItem) -> Option<&str> {
    is_request_owned_literal(item).then(|| super::claude_snapshot_family_root_ref(item))
}

/// True when `revision`'s row denies listed (or, while the list is paused,
/// all) families the request-owned literal. A revision with no row denies it
/// (fail closed).
pub(super) fn denies_request_owned_literal(revision: u64) -> bool {
    revision_policy(revision).map_or(true, |row| {
        row.listed_emission == ListedEmission::WithoutRequestOwnedLiteral
    })
}

/// The request-owned literal items one upload path may carry, read from the
/// active row, the list and the index, never from this cycle's decisions
/// (SOURCE h732 C2): a settlement, a re-offer outside the scan hints or an
/// in-place resend can carry a literal of a listed root that was not a
/// candidate this cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LiteralGuard {
    /// No literal item, or the literal's revision is active and no family
    /// is listed.
    Open,
    /// The active revision is below the literal's (S-726-1) or has no row,
    /// or the list is paused (every family may be listed): no literal passes.
    DenyAll,
    /// Only literals of these indexed source files, none of them in a listed
    /// family, pass. An unknown or unindexed source fails closed.
    Only(BTreeSet<String>),
}

impl LiteralGuard {
    pub(super) fn permits(&self, item: &super::SnapshotItem) -> bool {
        if !is_request_owned_literal(item) {
            return true;
        }
        match self {
            Self::Open => true,
            Self::DenyAll => false,
            Self::Only(sources) => item
                .source_file_fingerprint
                .as_deref()
                .is_some_and(|source| sources.contains(source)),
        }
    }

    /// The guard for `items`. `listed` says whether an indexed key's family
    /// is listed; `files` yields every indexed key with its source file.
    pub(super) fn for_items<'a>(
        items: &[super::SnapshotItem],
        active_revision: u64,
        list: &ReemissionExclusions,
        files: impl Iterator<Item = (&'a str, &'a str)>,
        listed: impl Fn(&str) -> bool,
    ) -> Self {
        if !items.iter().any(is_request_owned_literal) {
            return Self::Open;
        }
        // S-726-1: no literal is sent below the revision whose row carries
        // it (revision 3), nor under a revision with no row.
        let literal_row = revision_policy(active_revision)
            .is_some_and(|row| row.listed_emission == ListedEmission::WithoutRequestOwnedLiteral);
        if !literal_row || list.pauses_adoption() {
            return Self::DenyAll;
        }
        let literal_sources = items
            .iter()
            .filter(|item| is_request_owned_literal(item))
            .filter_map(|item| item.source_file_fingerprint.as_deref())
            .collect::<BTreeSet<_>>();
        if list.is_empty() {
            return Self::Open;
        }
        let mut unlisted = BTreeSet::new();
        let mut denied = BTreeSet::new();
        for (key, source) in files.filter(|(_, source)| literal_sources.contains(source)) {
            if listed(key) {
                denied.insert(source);
            } else {
                unlisted.insert(source);
            }
        }
        Self::Only(
            unlisted
                .difference(&denied)
                .map(|source| (*source).to_owned())
                .collect(),
        )
    }
}

#[derive(serde::Serialize)]
struct OwedWithoutListAlarm<'a> {
    history_upgrade_owed: u64,
    history_upgrade_permitted: u64,
    history_emission_denied: &'a str,
    list: &'static str,
}

#[cfg(not(test))]
static OWED_WITHOUT_LIST_LAST_ALARM: std::sync::Mutex<Option<std::time::Instant>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
thread_local! {
    static OWED_WITHOUT_LIST_LAST_ALARM: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(not(test))]
fn take_alarm_slot(now: std::time::Instant) -> bool {
    let mut last = OWED_WITHOUT_LIST_LAST_ALARM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let due = last.map_or(true, |at| {
        now.saturating_duration_since(at) >= OWED_WITHOUT_LIST_ALARM_INTERVAL
    });
    if due {
        *last = Some(now);
    }
    due
}

#[cfg(test)]
fn take_alarm_slot(now: std::time::Instant) -> bool {
    OWED_WITHOUT_LIST_LAST_ALARM.with(|last| {
        let due = last.get().map_or(true, |at| {
            now.saturating_duration_since(at) >= OWED_WITHOUT_LIST_ALARM_INTERVAL
        });
        if due {
            last.set(Some(now));
        }
        due
    })
}

/// One local alarm, at most hourly, while history is owed and the list was
/// never installed. Local only; counts, never ids.
pub(super) fn alarm_if_owed_without_list(page: &HistoryPage, list: ListState) {
    alarm_if_owed_without_list_at(page, list, std::time::Instant::now());
}

pub(super) fn alarm_if_owed_without_list_at(
    page: &HistoryPage,
    list: ListState,
    now: std::time::Instant,
) {
    if page.owed == 0 || list != ListState::NotInstalled || !take_alarm_slot(now) {
        return;
    }
    let denied = page.denied_summary();
    crate::local_resource_diagnostics::claude_history_upgrade_owed_without_list(
        &OwedWithoutListAlarm {
            history_upgrade_owed: page.owed,
            history_upgrade_permitted: page.permitted,
            history_emission_denied: &denied,
            list: list.as_str(),
        },
    );
}

/// Process-wide local counts, read by the census line. Counts only.
#[derive(Debug, Clone, Copy)]
pub(crate) enum LocalCount {
    /// Files whose request-owned literal was denied (`listed_literal`).
    ListedLiteralDenied = 0,
    /// Stored revisions lowered through the named re-owe.
    Reowed = 1,
    /// Revision activations refused for a missing policy row.
    ActivationRefused = 2,
}

#[cfg(not(test))]
static LOCAL_COUNTS: [std::sync::atomic::AtomicU64; 3] = [
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
];

#[cfg(not(test))]
fn add_local_count(count: LocalCount) {
    LOCAL_COUNTS[count as usize].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// The process-wide count so far.
#[cfg(not(test))]
pub(crate) fn local_count(count: LocalCount) -> u64 {
    LOCAL_COUNTS[count as usize].load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
thread_local! {
    static LOCAL_COUNTS: [std::cell::Cell<u64>; 3] = const {
        [std::cell::Cell::new(0), std::cell::Cell::new(0), std::cell::Cell::new(0)]
    };
}

#[cfg(test)]
fn add_local_count(count: LocalCount) {
    LOCAL_COUNTS.with(|counts| {
        let cell = &counts[count as usize];
        cell.set(cell.get().saturating_add(1));
    });
}

/// The count so far on this test thread.
#[cfg(test)]
pub(crate) fn local_count(count: LocalCount) -> u64 {
    LOCAL_COUNTS.with(|counts| counts[count as usize].get())
}

fn note_listed_literal_denied() {
    add_local_count(LocalCount::ListedLiteralDenied);
}

/// The one rule for lowering a stored body-witness revision (owner B):
/// only downward, and only to a value below `active` (before any
/// activation, below the highest revision with a policy row), so the file
/// is owed again and goes back through the history gate. Counts
/// `history_reowed`. Returns false and writes nothing otherwise.
pub(super) fn re_owe(stored: &mut u64, to: u64, active: u64) -> bool {
    let ceiling = if active == 0 {
        max_gated_claude_revision()
    } else {
        active
    };
    if to >= *stored || to >= ceiling {
        return false;
    }
    *stored = to;
    add_local_count(LocalCount::Reowed);
    true
}

#[derive(serde::Serialize)]
struct ActivationRefusedAlarm {
    refused_revision: u64,
    kept_revision: u64,
    max_gated_revision: u64,
    history_activation_refused: u64,
}

#[cfg(not(test))]
static ACTIVATION_REFUSED_LAST_ALARM: std::sync::Mutex<Option<std::time::Instant>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
thread_local! {
    static ACTIVATION_REFUSED_LAST_ALARM: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
}

fn activation_alarm_due(last: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    last.map_or(true, |at| {
        now.saturating_duration_since(at) >= OWED_WITHOUT_LIST_ALARM_INTERVAL
    })
}

#[cfg(not(test))]
fn take_activation_alarm_slot(now: std::time::Instant) -> bool {
    let mut last = ACTIVATION_REFUSED_LAST_ALARM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let due = activation_alarm_due(*last, now);
    if due {
        *last = Some(now);
    }
    due
}

#[cfg(test)]
fn take_activation_alarm_slot(now: std::time::Instant) -> bool {
    ACTIVATION_REFUSED_LAST_ALARM.with(|last| {
        let due = activation_alarm_due(last.get(), now);
        if due {
            last.set(Some(now));
        }
        due
    })
}

/// True when `revision` may be activated. Otherwise counts every refusal
/// and raises a local alarm on the first, then at most hourly (SOURCE h732
/// retry may happen each cycle); the caller keeps its active revision.
pub(super) fn admit_activation(revision: u64, kept_revision: u64) -> bool {
    admit_activation_at(revision, kept_revision, std::time::Instant::now())
}

fn admit_activation_at(revision: u64, kept_revision: u64, now: std::time::Instant) -> bool {
    if revision_policy(revision).is_some() {
        return true;
    }
    add_local_count(LocalCount::ActivationRefused);
    if !take_activation_alarm_slot(now) {
        return false;
    }
    crate::local_resource_diagnostics::claude_history_revision_activation_refused(
        &ActivationRefusedAlarm {
            refused_revision: revision,
            kept_revision,
            max_gated_revision: max_gated_claude_revision(),
            history_activation_refused: local_count(LocalCount::ActivationRefused),
        },
    );
    false
}

/// The prior-history-unverified diagnostic's process state.
#[derive(Debug, Clone, Copy)]
struct UnverifiedSince {
    since_unix_seconds: u64,
    claude_cycles: u64,
    last_alarm: Option<std::time::Instant>,
}

#[cfg(not(test))]
static PRIOR_HISTORY_UNVERIFIED: std::sync::Mutex<Option<UnverifiedSince>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
thread_local! {
    static PRIOR_HISTORY_UNVERIFIED: std::cell::Cell<Option<UnverifiedSince>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(not(test))]
fn with_unverified_since<T>(access: impl FnOnce(&mut Option<UnverifiedSince>) -> T) -> T {
    access(
        &mut PRIOR_HISTORY_UNVERIFIED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

#[cfg(test)]
fn with_unverified_since<T>(access: impl FnOnce(&mut Option<UnverifiedSince>) -> T) -> T {
    PRIOR_HISTORY_UNVERIFIED.with(|slot| {
        let mut seen = slot.get();
        let result = access(&mut seen);
        slot.set(seen);
        result
    })
}

#[derive(serde::Serialize)]
struct PriorHistoryUnverifiedAlarm {
    unverified_since_unix_seconds: u64,
    unverified_for_seconds: u64,
    claude_cycles: u64,
}

/// Count-only local diagnostic (StateMissing r3 of #712), useful where a
/// Claude census rarely settles: "prior_history_unverified set since T". T is
/// the first Claude cycle this process read the marker set; the marker's own
/// set time is not recorded, and this path never writes the backfill state,
/// so a restart starts T again. A cycle that reads it clear resets it. One
/// local alarm on the first such cycle, then at most hourly. No path, id or
/// wire event.
pub(crate) fn note_prior_history_unverified(unverified: bool) {
    let now_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    note_prior_history_unverified_at(unverified, now_unix_seconds, std::time::Instant::now());
}

fn note_prior_history_unverified_at(
    unverified: bool,
    now_unix_seconds: u64,
    now: std::time::Instant,
) {
    let alarm = with_unverified_since(|slot| {
        if !unverified {
            *slot = None;
            return None;
        }
        let seen = slot.get_or_insert(UnverifiedSince {
            since_unix_seconds: now_unix_seconds,
            claude_cycles: 0,
            last_alarm: None,
        });
        seen.claude_cycles = seen.claude_cycles.saturating_add(1);
        let due = seen.last_alarm.map_or(true, |at| {
            now.saturating_duration_since(at) >= OWED_WITHOUT_LIST_ALARM_INTERVAL
        });
        if !due {
            return None;
        }
        seen.last_alarm = Some(now);
        Some(PriorHistoryUnverifiedAlarm {
            unverified_since_unix_seconds: seen.since_unix_seconds,
            unverified_for_seconds: now_unix_seconds.saturating_sub(seen.since_unix_seconds),
            claude_cycles: seen.claude_cycles,
        })
    });
    if let Some(alarm) = alarm {
        crate::local_resource_diagnostics::claude_prior_history_unverified(&alarm);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// StateMissing r3: the unverified-since diagnostic reports its first
    /// cycle at once, then at most hourly, and a clear read resets T.
    #[test]
    fn prior_history_unverified_reports_since_when_at_most_hourly() {
        let start = std::time::Instant::now();
        let at = |seconds: u64| start + std::time::Duration::from_secs(seconds);
        let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
            note_prior_history_unverified_at(true, 1_000, at(0));
            note_prior_history_unverified_at(true, 1_600, at(600));
            note_prior_history_unverified_at(true, 4_700, at(3_700));
            note_prior_history_unverified_at(false, 4_800, at(3_800));
            note_prior_history_unverified_at(true, 9_000, at(8_000));
        });
        assert_eq!(alarms.len(), 3, "{alarms:?}");
        for alarm in &alarms {
            assert_eq!(alarm["stage"], "claude_prior_history_unverified");
            assert_eq!(alarm["source"], "claude_code");
        }
        let counts = |index: usize, field: &str| alarms[index]["counts"][field].clone();
        assert_eq!(counts(0, "unverified_since_unix_seconds"), 1_000);
        assert_eq!(counts(0, "unverified_for_seconds"), 0);
        assert_eq!(counts(0, "claude_cycles"), 1);
        assert_eq!(counts(1, "unverified_since_unix_seconds"), 1_000);
        assert_eq!(counts(1, "unverified_for_seconds"), 3_700);
        assert_eq!(counts(1, "claude_cycles"), 3);
        assert_eq!(counts(2, "unverified_since_unix_seconds"), 9_000, "reset");
        assert_eq!(counts(2, "claude_cycles"), 1);
    }

    const EXTENT: FileExtent = FileExtent {
        size_bytes: 10,
        modified_unix_seconds: 100,
        modified_unix_nanos: Some(100_000_000_000),
    };

    fn installed(text: &str) -> ReemissionExclusions {
        ReemissionExclusions::parse(text.as_bytes())
    }

    fn inputs(exclusions: &ReemissionExclusions, listed: bool, active: u64) -> PolicyInputs<'_> {
        PolicyInputs {
            exclusions,
            listed,
            birth_unix_seconds: Some(u64::MAX),
            latched: false,
            active_revision: active,
            history_cutoff_unix_seconds: None,
            no_list_policy: NoListPolicy::Pace,
        }
    }

    #[test]
    fn classification_ignores_the_reason_and_the_source_fingerprint() {
        // Unchanged size and mtime with a stale stamp is owed history, a
        // zero (unstamped or legacy) stamp included: the caller's comparison
        // says below-active for both.
        assert_eq!(
            classify(Some(EXTENT), EXTENT, true, None, None),
            HistoryKind::Owed
        );
        assert_eq!(
            classify(Some(EXTENT), EXTENT, false, None, None),
            HistoryKind::Settled
        );
        let grown = FileExtent {
            size_bytes: 11,
            ..EXTENT
        };
        assert_eq!(
            classify(Some(EXTENT), grown, true, None, None),
            HistoryKind::Changed
        );
        let shrunk = FileExtent {
            size_bytes: 9,
            ..EXTENT
        };
        assert_eq!(
            classify(Some(EXTENT), shrunk, true, None, None),
            HistoryKind::Changed
        );
        let legacy = FileExtent {
            modified_unix_nanos: None,
            ..EXTENT
        };
        assert_eq!(
            classify(Some(legacy), EXTENT, true, None, None),
            HistoryKind::Owed,
            "a legacy entry without nanos is unchanged when seconds agree"
        );
    }

    /// F5: a same-size file whose mtime alone moved (seconds or nanos) is
    /// not a genuine change; it is unchanged history, so it is gated.
    #[test]
    fn a_same_size_mtime_only_change_is_not_a_genuine_change() {
        with_max_gated_claude_revision(3, || {
            for touched in [
                FileExtent {
                    modified_unix_nanos: Some(100_000_000_001),
                    ..EXTENT
                },
                FileExtent {
                    modified_unix_seconds: 101,
                    modified_unix_nanos: Some(101_000_000_000),
                    ..EXTENT
                },
            ] {
                assert_eq!(
                    classify(Some(EXTENT), touched, true, None, None),
                    HistoryKind::Owed
                );
                assert_eq!(
                    classify(Some(EXTENT), touched, false, None, None),
                    HistoryKind::Settled
                );
            }
            let list = installed("");
            let mut page = HistoryPage::default();
            let touched = classify(
                Some(EXTENT),
                FileExtent {
                    modified_unix_seconds: 101,
                    ..EXTENT
                },
                true,
                None,
                None,
            );
            assert_eq!(
                decide(touched, &inputs(&list, true, 3), &mut page, "k", 1),
                HistoryDecision::Held(HistoryHold::Listed),
                "a touched listed file is held history, not a listed change"
            );
        });
    }

    #[test]
    fn new_files_are_history_only_before_a_known_cutoff() {
        assert_eq!(
            classify(None, EXTENT, true, None, None),
            HistoryKind::Fresh,
            "a genuine first install ingests normally"
        );
        assert_eq!(
            classify(None, EXTENT, true, Some(500), Some(499)),
            HistoryKind::Owed
        );
        assert_eq!(
            classify(None, EXTENT, true, Some(500), None),
            HistoryKind::Owed,
            "unknown birth under a cutoff is history"
        );
        assert_eq!(
            classify(None, EXTENT, true, Some(500), Some(500)),
            HistoryKind::Owed,
            "born within the cutoff second is history (fail closed)"
        );
        assert_eq!(
            classify(None, EXTENT, true, Some(500), Some(501)),
            HistoryKind::Fresh,
            "born after the cutoff is new"
        );
        assert_eq!(
            classify(None, EXTENT, false, Some(500), Some(1)),
            HistoryKind::Fresh,
            "no active revision, nothing to gate"
        );
    }

    #[test]
    fn policy_table_and_budget_constants() {
        assert_eq!(HISTORY_UPGRADE_FILES_PER_PAGE, 2_000);
        assert_eq!(HISTORY_UPGRADE_BYTES_PER_PAGE, 1 << 30);
        let revision_2 = revision_policy(2).unwrap();
        assert_eq!(revision_2.listed_emission, ListedEmission::Ordinary);
        assert_eq!(
            revision_2.no_list_birth_cutoff_unix_seconds, 1_792_540_800,
            "revision 2 keeps 2026-10-21"
        );
        // SOURCE h732 C1: revision 3's row opens only when E2 raises MAX.
        assert_eq!(revision_policy(MAX_GATED_CLAUDE_REVISION + 1), None);
        with_max_gated_claude_revision(3, || {
            let revision_3 = revision_policy(3).unwrap();
            assert_eq!(
                revision_3.listed_emission,
                ListedEmission::WithoutRequestOwnedLiteral
            );
            assert_ne!(
                revision_3.no_list_birth_cutoff_unix_seconds,
                revision_2.no_list_birth_cutoff_unix_seconds,
                "each revision carries its own no-list cutoff (F4b)"
            );
            assert_eq!(revision_policy(4), None);
        });
        with_max_gated_claude_revision(2, || assert_eq!(revision_policy(3), None));
        // SOURCE F2: without a complete row a revision is ungated: an owed
        // upgrade to it is held whatever the list says.
        with_max_gated_claude_revision(2, || {
            assert_eq!(
                decide(
                    HistoryKind::Owed,
                    &inputs(&installed(""), false, 3),
                    &mut HistoryPage::default(),
                    "k",
                    1
                ),
                HistoryDecision::Held(HistoryHold::UngatedRevision)
            );
        });
    }

    #[test]
    fn no_list_hold_reaches_the_later_history_cutoff() {
        // SOURCE F4a: history born after the fixed 2026-10-21 cutoff but at
        // or before the saved history cutoff is still held without a list.
        let not_installed = ReemissionExclusions::default();
        let mut cutoff = inputs(&not_installed, false, 2);
        cutoff.no_list_policy = NoListPolicy::HoldUnverified;
        cutoff.history_cutoff_unix_seconds = Some(u64::MAX - 1);
        for (birth, held) in [
            (Some(u64::MAX - 1), true),
            (None, true),
            (Some(u64::MAX), false),
        ] {
            cutoff.birth_unix_seconds = birth;
            let decision = decide(
                HistoryKind::Owed,
                &cutoff,
                &mut HistoryPage::default(),
                "k",
                1,
            );
            assert_eq!(
                decision == HistoryDecision::Held(HistoryHold::NoListBirth),
                held,
                "{birth:?}"
            );
        }
        // An installed list replaces the birth hold.
        let list = installed("");
        let mut listed = inputs(&list, false, 2);
        listed.history_cutoff_unix_seconds = Some(u64::MAX - 1);
        assert_eq!(
            decide(
                HistoryKind::Owed,
                &listed,
                &mut HistoryPage::default(),
                "k",
                1
            ),
            HistoryDecision::Owed
        );
    }

    /// SOURCE Amendment 16 and addendum 8, StateMissing N1: where no list is
    /// intended, old and unknown-birth history is paced unless the Mac is
    /// unverified (`no_list_birth`) or the history was moved under a claim
    /// policy other than `full` (`move_not_full`). An intended list (an
    /// installed list, or a marker with the list gone) applies its own rules
    /// whatever the policy.
    #[test]
    fn no_list_policy_paces_unless_unverified_or_a_move_not_full() {
        let not_installed = ReemissionExclusions::default();
        let list = installed("");
        let missing = ReemissionExclusions::with_state(ListState::MissingAfterInstall);
        for (policy, expected) in [
            (NoListPolicy::Pace, HistoryDecision::Owed),
            (
                NoListPolicy::HoldUnverified,
                HistoryDecision::Held(HistoryHold::NoListBirth),
            ),
            (
                NoListPolicy::HoldMoveNotFull,
                HistoryDecision::Held(HistoryHold::MoveNotFull),
            ),
        ] {
            for birth in [None, Some(1), Some(u64::MAX - 1)] {
                let mut old = inputs(&not_installed, false, 2);
                old.birth_unix_seconds = birth;
                old.history_cutoff_unix_seconds = Some(u64::MAX - 1);
                old.no_list_policy = policy;
                assert_eq!(
                    decide(HistoryKind::Owed, &old, &mut HistoryPage::default(), "k", 1),
                    expected,
                    "{policy:?} {birth:?}"
                );
                let mut intended = inputs(&list, false, 2);
                intended.birth_unix_seconds = birth;
                intended.no_list_policy = policy;
                assert_eq!(
                    decide(
                        HistoryKind::Owed,
                        &intended,
                        &mut HistoryPage::default(),
                        "k",
                        1
                    ),
                    HistoryDecision::Owed,
                    "an installed list paces unlisted history: {policy:?}"
                );
                let mut paused = inputs(&missing, false, 2);
                paused.no_list_policy = policy;
                assert_eq!(
                    decide(
                        HistoryKind::Owed,
                        &paused,
                        &mut HistoryPage::default(),
                        "k",
                        1
                    ),
                    HistoryDecision::Held(HistoryHold::ListPaused)
                );
            }
        }
    }

    /// F4b: where the no-list policy holds, the birth hold reads the active
    /// revision's own cutoff.
    #[test]
    fn the_no_list_birth_hold_is_per_revision() {
        with_max_gated_claude_revision(3, || {
            let not_installed = ReemissionExclusions::default();
            let born_after_revision_2_cutoff = Some(1_792_540_800 + 60);
            let mut page = HistoryPage::default();
            for (revision, held) in [(2, false), (3, true)] {
                let mut owed = inputs(&not_installed, false, revision);
                owed.no_list_policy = NoListPolicy::HoldUnverified;
                owed.birth_unix_seconds = born_after_revision_2_cutoff;
                let decision = decide(HistoryKind::Owed, &owed, &mut page, "k", 1);
                assert_eq!(
                    decision == HistoryDecision::Held(HistoryHold::NoListBirth),
                    held,
                    "revision {revision}: {decision:?}"
                );
            }
        });
    }

    #[test]
    fn listed_change_emits_under_revision_two_and_only_its_literal_is_denied_under_three() {
        with_max_gated_claude_revision(3, || {
            let list = installed("");
            let mut page = HistoryPage::default();
            assert_eq!(
                decide(
                    HistoryKind::Changed,
                    &inputs(&list, true, 2),
                    &mut page,
                    "k",
                    1
                ),
                HistoryDecision::NotOwed
            );
            assert_eq!(
                decide(
                    HistoryKind::Changed,
                    &inputs(&list, true, 3),
                    &mut page,
                    "k",
                    1
                ),
                HistoryDecision::LiteralDenied,
                "the ordinary body emits; only the request-owned literal is denied"
            );
            assert_eq!(
                decide(
                    HistoryKind::Fresh,
                    &inputs(&list, true, 3),
                    &mut page,
                    "k",
                    1
                ),
                HistoryDecision::LiteralDenied,
                "a listed root's new file never carries the literal either"
            );
            assert_eq!(page.denied_for_reason(LISTED_LITERAL_REASON), 2);
            assert!(page.denied_summary().contains("listed_literal:installed=2"));
            assert_eq!(
                decide(
                    HistoryKind::Changed,
                    &inputs(&list, false, 3),
                    &mut page,
                    "k",
                    1
                ),
                HistoryDecision::NotOwed,
                "an unlisted change always syncs"
            );
            assert_eq!(
                decide(
                    HistoryKind::Owed,
                    &inputs(&list, false, 4),
                    &mut page,
                    "k",
                    1
                ),
                HistoryDecision::Held(HistoryHold::UngatedRevision)
            );
            assert_eq!(
                decide(
                    HistoryKind::Changed,
                    &inputs(&list, true, 4),
                    &mut page,
                    "k",
                    1
                ),
                HistoryDecision::Held(HistoryHold::UngatedRevision)
            );
        });
    }

    /// F3: while the list is paused no family can be shown unlisted, so
    /// under revision 3 every ordinary sync loses only its literal; owed
    /// history stays held. Revision 2 is unchanged.
    #[test]
    fn a_paused_list_denies_only_the_literal_under_revision_three() {
        with_max_gated_claude_revision(3, || {
            for paused in [
                installed("not-a-digest\n"),
                ReemissionExclusions::default().with_state_for_test(ListState::MissingAfterInstall),
                ReemissionExclusions::default().with_state_for_test(ListState::ClosureOverflow),
            ] {
                assert!(paused.pauses_adoption());
                let mut page = HistoryPage::default();
                for kind in [HistoryKind::Changed, HistoryKind::Fresh] {
                    assert_eq!(
                        decide(kind, &inputs(&paused, false, 3), &mut page, "k", 1),
                        HistoryDecision::LiteralDenied
                    );
                    assert_eq!(
                        decide(kind, &inputs(&paused, false, 2), &mut page, "k", 1),
                        HistoryDecision::NotOwed
                    );
                }
                assert_eq!(
                    decide(
                        HistoryKind::Owed,
                        &inputs(&paused, false, 3),
                        &mut page,
                        "k",
                        1
                    ),
                    HistoryDecision::Held(HistoryHold::ListPaused)
                );
            }
        });
    }

    /// SOURCE h732 nit: every refused activation counts; the alarm fires on
    /// the first, then at most hourly.
    #[test]
    fn activation_refusal_alarms_at_most_hourly() {
        let start = std::time::Instant::now();
        let refused = local_count(LocalCount::ActivationRefused);
        let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
            assert!(!admit_activation_at(4, 2, start));
            assert!(!admit_activation_at(
                4,
                2,
                start + std::time::Duration::from_secs(60)
            ));
            assert!(!admit_activation_at(
                4,
                2,
                start + OWED_WITHOUT_LIST_ALARM_INTERVAL
            ));
            assert!(admit_activation_at(2, 2, start));
        });
        assert_eq!(alarms.len(), 2, "{alarms:?}");
        assert_eq!(local_count(LocalCount::ActivationRefused), refused + 3);
        assert_eq!(
            alarms[1]["counts"]["history_activation_refused"],
            refused + 3
        );
    }

    /// SOURCE h732 C2: the literal guard reads the active row, the list and
    /// the index, never this cycle's decisions; unknown sources fail closed.
    #[test]
    fn literal_guard_ignores_this_cycles_decisions() {
        with_max_gated_claude_revision(3, || {
            let item = |file: Option<&str>, literal: bool| {
                let mut item = crate::snapshots::tests::sample_session_artifact_item();
                item.source_file_fingerprint = file.map(Into::into);
                item.usage_accounting_contract =
                    literal.then(|| REQUEST_OWNED_USAGE_CONTRACT.into());
                item
            };
            let items = [item(Some("open"), true), item(Some("listed"), true)];
            let files = || {
                [
                    ("open.jsonl", "open"),
                    ("listed.jsonl", "listed"),
                    ("alias.jsonl", "open"),
                ]
                .into_iter()
            };
            let listed = |key: &str| key != "open.jsonl";
            let list = installed("");
            let guard = |revision: u64, list: &ReemissionExclusions| {
                LiteralGuard::for_items(&items, revision, list, files(), listed)
            };
            let populated = ReemissionExclusions::parse(format!("{}\n", "a".repeat(64)).as_bytes());
            // S-726-1: below revision 3 no literal passes, listed or not.
            for below in [&populated, &list, &ReemissionExclusions::default()] {
                assert_eq!(guard(2, below), LiteralGuard::DenyAll);
            }
            with_max_gated_claude_revision(2, || {
                assert_eq!(guard(3, &list), LiteralGuard::DenyAll, "rowless");
            });
            assert_eq!(guard(3, &list), LiteralGuard::Open, "nothing is listed");
            assert_eq!(
                guard(3, &ReemissionExclusions::default()),
                LiteralGuard::Open,
                "a list never installed lists nothing"
            );
            for paused in [
                ListState::Unreadable,
                ListState::MissingAfterInstall,
                ListState::MarkerUnwritable,
                ListState::ClosureOverflow,
            ] {
                let paused = ReemissionExclusions::default().with_state_for_test(paused);
                assert_eq!(guard(3, &paused), LiteralGuard::DenyAll);
            }
            let only = guard(3, &populated);
            assert_eq!(
                only,
                LiteralGuard::Only(BTreeSet::new()),
                "a source any listed key carries is denied, an alias included"
            );
            let only_open = LiteralGuard::for_items(&items, 3, &populated, files(), |key| {
                key == "listed.jsonl"
            });
            assert!(only_open.permits(&item(Some("open"), true)));
            assert!(!only_open.permits(&item(Some("listed"), true)));
            assert!(!only_open.permits(&item(Some("unindexed"), true)));
            assert!(!only_open.permits(&item(None, true)));
            assert!(
                only_open.permits(&item(Some("listed"), false)),
                "the body stays"
            );
            with_max_gated_claude_revision(2, || {
                assert!(
                    denies_request_owned_literal(3),
                    "a rowless revision fails closed"
                );
            });
            assert!(!denies_request_owned_literal(2));
        });
    }

    #[test]
    fn literal_denial_removes_only_request_owned_items() {
        let mut emission = HistoryEmission::default();
        emission.files.insert(
            "denied".into(),
            GatedHistory {
                literal_denied: true,
                ..GatedHistory::default()
            },
        );
        emission.files.insert(
            "held".into(),
            GatedHistory {
                held: Some(HistoryHold::Listed),
                ..GatedHistory::default()
            },
        );
        let item = |file: &str, literal: bool| {
            let mut item = crate::snapshots::tests::sample_session_artifact_item();
            item.source_file_fingerprint = Some(file.into());
            item.usage_accounting_contract = literal.then(|| REQUEST_OWNED_USAGE_CONTRACT.into());
            item
        };
        let open = LiteralGuard::Open;
        assert!(emission.permits(&item("denied", false), &open));
        assert!(!emission.permits(&item("denied", true), &open));
        assert!(!emission.permits(&item("held", false), &open));
        assert!(emission.permits(&item("other", true), &open));
        let mut ordinary = item("denied", false);
        ordinary.usage_accounting_contract = Some("session_exclusive_reported_usage:v1".into());
        assert!(
            emission.permits(&ordinary, &open),
            "session_exclusive v1 on the ordinary body keeps today's rules"
        );
        assert!(!emission.permits(&item("other", true), &LiteralGuard::DenyAll));
        assert!(emission.permits(&item("other", false), &LiteralGuard::DenyAll));
        assert!(emission.literal_denied("denied"));
        assert_eq!(
            emission.hold_permitted_for_latch(),
            0,
            "never latched as an upgrade"
        );
        assert!(emission.literal_denied("denied"));
    }

    #[test]
    fn re_owe_only_lowers_below_the_active_revision_and_counts() {
        with_max_gated_claude_revision(3, || {
            let before = local_count(LocalCount::Reowed);
            let mut stored = 3;
            assert!(!re_owe(&mut stored, 3, 3), "not a lowering");
            assert!(!re_owe(&mut stored, 4, 3), "never raises");
            let mut low = 1;
            assert!(!re_owe(&mut low, 2, 3), "never raises");
            let mut at_active = 3;
            assert!(
                !re_owe(&mut at_active, 2, 2),
                "must end below the active revision"
            );
            assert_eq!(at_active, 3);
            assert!(re_owe(&mut stored, 2, 3));
            assert_eq!(stored, 2);
            let mut decoded = 3;
            assert!(
                re_owe(&mut decoded, 2, 0),
                "before activation the bound is the highest revision with a row"
            );
            with_max_gated_claude_revision(2, || {
                let mut decoded = 3;
                assert!(!re_owe(&mut decoded, 2, 0));
            });
            assert_eq!(local_count(LocalCount::Reowed), before + 2);
        });
    }

    #[test]
    fn owed_history_passes_list_birth_latch_and_budget_in_order() {
        let not_installed = ReemissionExclusions::default();
        let mut page = HistoryPage::default();
        let mut old = inputs(&not_installed, false, 2);
        old.birth_unix_seconds = None;
        old.no_list_policy = NoListPolicy::HoldUnverified;
        assert_eq!(
            decide(HistoryKind::Owed, &old, &mut page, "a", 1),
            HistoryDecision::Held(HistoryHold::NoListBirth)
        );
        let paused = installed("not-a-digest\n");
        assert_eq!(
            decide(
                HistoryKind::Owed,
                &inputs(&paused, false, 2),
                &mut page,
                "a",
                1
            ),
            HistoryDecision::Held(HistoryHold::ListPaused)
        );
        let list = installed("");
        assert_eq!(
            decide(
                HistoryKind::Owed,
                &inputs(&list, true, 2),
                &mut page,
                "a",
                1
            ),
            HistoryDecision::Held(HistoryHold::Listed)
        );
        let mut latched = inputs(&list, false, 2);
        latched.latched = true;
        assert_eq!(
            decide(HistoryKind::Owed, &latched, &mut page, "a", 1),
            HistoryDecision::Held(HistoryHold::Latched)
        );
        assert_eq!(page.permitted, 0, "no held file spends the budget");
        super::super::with_body_witness_adoption_page_budget(1, || {
            assert_eq!(
                decide(
                    HistoryKind::Owed,
                    &inputs(&list, false, 2),
                    &mut page,
                    "a",
                    1
                ),
                HistoryDecision::Owed
            );
            assert_eq!(
                decide(
                    HistoryKind::Owed,
                    &inputs(&list, false, 2),
                    &mut page,
                    "a",
                    1
                ),
                HistoryDecision::Owed,
                "a file already reserved on this page is not charged twice"
            );
            assert_eq!(
                decide(
                    HistoryKind::Owed,
                    &inputs(&list, false, 2),
                    &mut page,
                    "b",
                    1
                ),
                HistoryDecision::Held(HistoryHold::Budget)
            );
        });
        assert_eq!(page.owed, 7);
        assert_eq!(page.denied_for(&[HistoryHold::Budget]), 1);
        assert!(page
            .denied_summary()
            .contains("no_list_birth:not_installed=1"));
    }

    #[test]
    fn the_byte_budget_has_no_first_file_exception() {
        let list = installed("");
        let mut page = HistoryPage::default();
        assert_eq!(
            decide(
                HistoryKind::Owed,
                &inputs(&list, false, 2),
                &mut page,
                "huge",
                HISTORY_UPGRADE_BYTES_PER_PAGE + 1
            ),
            HistoryDecision::Held(HistoryHold::Budget)
        );
        // Codex and Pi adoption-only pacing keeps progress for a transcript
        // above the byte budget: only a page's first file passes over it.
        let huge = HISTORY_UPGRADE_BYTES_PER_PAGE + 1;
        let mut codex = HistoryPage::default();
        assert!(codex.reserve_admitting_first_file("codex-huge", huge));
        assert!(!codex.reserve_admitting_first_file("codex-second", 1));
        let mut codex = HistoryPage::default();
        assert!(codex.reserve_admitting_first_file("codex-small", 1));
        assert!(!codex.reserve_admitting_first_file("codex-huge", huge));
    }

    #[test]
    fn owed_without_list_alarms_at_most_hourly() {
        let page = HistoryPage {
            owed: 3,
            ..HistoryPage::default()
        };
        let now = std::time::Instant::now();
        let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
            alarm_if_owed_without_list_at(&page, ListState::NotInstalled, now);
            alarm_if_owed_without_list_at(&page, ListState::NotInstalled, now);
            alarm_if_owed_without_list_at(&page, ListState::Installed, now);
        });
        assert_eq!(alarms.len(), 1);
        assert_eq!(
            alarms[0]["stage"],
            "claude_history_upgrade_owed_without_list"
        );
        assert_eq!(alarms[0]["counts"]["history_upgrade_owed"], 3);
        let ((), later) = crate::local_resource_diagnostics::capture(|| {
            alarm_if_owed_without_list_at(
                &page,
                ListState::NotInstalled,
                now + OWED_WITHOUT_LIST_ALARM_INTERVAL,
            );
        });
        assert_eq!(later.len(), 1);
    }

    fn twin_index(sizes: &[(&str, u64)]) -> super::super::ScanIndex {
        let mut index = super::super::ScanIndex::default();
        for (key, size) in sizes {
            let mut entry = super::super::tests::manifest_index_entry(None);
            entry.size_bytes = *size;
            index.files.insert((*key).to_owned(), entry);
        }
        index
    }

    const TWIN_A: &str = "/h/.claude/projects/-a/11111111-1111-4111-8111-111111111111.jsonl";
    const TWIN_B: &str = "/h/slot/projects/-b/11111111-1111-4111-8111-111111111111.jsonl";
    const OTHER: &str = "/h/.claude/projects/-a/22222222-2222-4222-8222-222222222222.jsonl";
    const AGENT: &str =
        "/h/.claude/projects/-a/11111111-1111-4111-8111-111111111111/subagents/agent-x.jsonl";

    /// E2 path twins: a pair is reserved both or neither, and a page's first
    /// group passes the file count, so under a budget of one or two files a
    /// pair held by another file's reservation settles on the next page.
    #[test]
    fn path_twins_reserve_both_or_neither_and_settle_within_two_pages() {
        let mut index = twin_index(&[(TWIN_A, 10), (TWIN_B, 12), (OTHER, 5), (AGENT, 7)]);
        let list = installed("");
        let mut staged = HistoryPage::default();
        index.stage_claude_history_twins(TWIN_A, &mut staged);
        assert_eq!(
            staged.staged_twins,
            Some((TWIN_A.to_owned(), vec![(TWIN_B.to_owned(), 12)])),
            "same member file under another project; the agent and other sessions are not twins"
        );
        index.stage_claude_history_twins(OTHER, &mut staged);
        assert_eq!(staged.staged_twins, Some((OTHER.to_owned(), Vec::new())));
        assert!(index.claude_money_birth_store.staged(TWIN_A));
        assert!(index.claude_money_birth_store.staged(TWIN_B));
        assert!(
            !index.claude_money_birth_store.staged(OTHER),
            "a lone root pays no metadata probe"
        );
        assert!(
            !index.claude_money_birth_store.staged(AGENT),
            "a lone agent pays no metadata probe"
        );
        let mut owed = |page: &mut HistoryPage, key: &str, size: u64| {
            index.stage_claude_history_twins(key, page);
            decide(HistoryKind::Owed, &inputs(&list, false, 2), page, key, size)
        };
        for budget in [1, 2] {
            super::super::with_body_witness_adoption_page_budget(budget, || {
                // Page 1: another owed file takes the page first.
                let mut page = HistoryPage::default();
                assert_eq!(owed(&mut page, OTHER, 5), HistoryDecision::Owed);
                assert_eq!(
                    owed(&mut page, TWIN_A, 10),
                    HistoryDecision::Held(HistoryHold::Budget),
                    "budget {budget}: a twin is never reserved without its sibling"
                );
                assert_eq!(
                    owed(&mut page, TWIN_B, 12),
                    HistoryDecision::Held(HistoryHold::Budget),
                    "budget {budget}: neither twin is reserved"
                );
                assert_eq!((page.files, page.bytes), (1, 5));
                // Page 2: the settled file is no longer owed; the pair goes first.
                let mut page = HistoryPage::default();
                assert_eq!(owed(&mut page, TWIN_A, 10), HistoryDecision::Owed);
                assert_eq!(owed(&mut page, TWIN_B, 12), HistoryDecision::Owed);
                assert_eq!((page.files, page.bytes), (2, 22), "budget {budget}");
                assert_eq!(page.permitted, 2);
            });
        }
        // Bytes stay strict even for a page's first group.
        super::super::with_body_witness_adoption_byte_budget(21, || {
            let mut page = HistoryPage::default();
            assert_eq!(
                owed(&mut page, TWIN_B, 12),
                HistoryDecision::Held(HistoryHold::Budget)
            );
            assert!(page.reserved.is_empty());
        });
        // A single file keeps the previous rule exactly (no group exception).
        super::super::with_body_witness_adoption_page_budget(1, || {
            let mut page = HistoryPage::default();
            assert!(page.reserve(OTHER, 5));
            assert!(!page.reserve(AGENT, 7));
            assert!(
                page.reserve(OTHER, 5),
                "a reserved file is not charged twice"
            );
        });
    }

    /// E2: a failed telemetry read holds every permitted owed upgrade of the
    /// cycle (it stays owed), never a held or literal-denied file's state.
    #[test]
    fn unread_telemetry_holds_permitted_upgrades_only() {
        let mut index = super::super::ScanIndex::default();
        let gated = |held: Option<HistoryHold>, literal_denied: bool| GatedHistory {
            index_key: "k".into(),
            held,
            permitted: held.is_none() && !literal_denied,
            literal_denied,
            previous: None,
            local: BTreeSet::new(),
        };
        let files = &mut index.claude_history_emission.files;
        files.insert("permitted".into(), gated(None, false));
        files.insert("budget".into(), gated(Some(HistoryHold::Budget), false));
        files.insert("denied".into(), gated(None, true));
        assert_eq!(index.hold_claude_history_for_unread_telemetry(), 1);
        let emission = &index.claude_history_emission;
        assert_eq!(
            emission.held("permitted"),
            Some(HistoryHold::TelemetryUnread)
        );
        assert_eq!(emission.held("budget"), Some(HistoryHold::Budget));
        assert_eq!(emission.held("denied"), None);
        assert!(emission.literal_denied("denied"));
        assert_eq!(HistoryHold::TelemetryUnread.as_str(), "telemetry_unread");
    }

    /// One literal owner: the predicate and the family root are typed reads
    /// of the item (no serialization), `None` for every other body.
    #[test]
    fn request_owned_family_root_is_typed_and_literal_only() {
        let mut item = crate::snapshots::tests::sample_session_artifact_item();
        item.attribution_facts.clear();
        item.source_session_id = "root-1_agent-x".into();
        assert!(!is_request_owned_literal(&item));
        assert_eq!(request_owned_family_root(&item), None);
        item.usage_accounting_contract = Some("session_exclusive_reported_usage:v1".into());
        assert_eq!(request_owned_family_root(&item), None);
        item.usage_accounting_contract = Some(REQUEST_OWNED_USAGE_CONTRACT.into());
        assert!(is_request_owned_literal(&item));
        assert_eq!(request_owned_family_root(&item), Some("root-1"));
        item.source_session_id = "root-1".into();
        assert_eq!(request_owned_family_root(&item), Some("root-1"));
    }
}
