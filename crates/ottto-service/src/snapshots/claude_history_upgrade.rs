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
//! the upgrade is skipped as before.
//!
//! The parse reason is a diagnostic only; no decision here reads it.

use super::claude_reemission_exclusions::{ListState, ReemissionExclusions};
use std::collections::{BTreeMap, BTreeSet};

/// Most history files one page may upgrade, for every revision (MONEY P2).
pub(super) const HISTORY_UPGRADE_FILES_PER_PAGE: usize = 2_000;
/// Bytes of history one page may upgrade (1 GiB), for every revision. No
/// file is admitted past it, including a page's first file.
pub(super) const HISTORY_UPGRADE_BYTES_PER_PAGE: u64 = 1024 * 1024 * 1024;
/// Highest Claude revision with the shared history gate composed through all
/// settlement paths. The live money gate remains independently disabled.
pub(crate) const MAX_GATED_CLAUDE_REVISION: u64 = 3;

/// At most one owed-without-list alarm an hour.
const OWED_WITHOUT_LIST_ALARM_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60 * 60);

/// What one active revision allows for a listed (protected) family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RevisionPolicy {
    /// A listed family whose transcript genuinely changed may emit its
    /// ordinary sync under this revision. Revision 2 adds only context
    /// numbers; revision 3 adds request-owned money, which listed roots must
    /// never emit, even on a genuine change.
    pub(super) listed_changed_may_emit: bool,
}

/// The per-revision policy table. An unknown revision has no row: every owed
/// upgrade and every listed change is held.
pub(super) fn revision_policy(revision: u64) -> Option<RevisionPolicy> {
    match revision {
        0..=2 => Some(RevisionPolicy {
            listed_changed_may_emit: true,
        }),
        3 => Some(RevisionPolicy {
            listed_changed_may_emit: false,
        }),
        _ => None,
    }
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
    let changed = entry.size_bytes != candidate.size_bytes
        || entry.modified_unix_seconds != candidate.modified_unix_seconds
        || entry
            .modified_unix_nanos
            .zip(candidate.modified_unix_nanos)
            .is_some_and(|(stored, current)| stored != current);
    if changed {
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
    /// Money custody is paused; every selection reason retains its old body.
    MoneyPaused,
    UnknownOutcome,
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
    /// The revision policy denies a listed family's genuine change.
    ListedChanged,
}

impl HistoryHold {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UngatedRevision => "ungated_revision",
            Self::MoneyPaused => "money_paused",
            Self::UnknownOutcome => "unknown_outcome",
            Self::ListPaused => "list_paused",
            Self::Listed => "listed",
            Self::NoListBirth => "no_list_birth",
            Self::MoveNotFull => "move_not_full",
            Self::Latched => "latched",
            Self::Budget => "budget",
            Self::ListedChanged => "listed_changed",
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
}

/// Inputs the policy reads besides the classification.
pub(super) struct PolicyInputs<'a> {
    pub(super) exclusions: &'a ReemissionExclusions,
    pub(super) listed: bool,
    pub(super) birth_unix_seconds: Option<u64>,
    pub(super) latched: bool,
    pub(super) money_paused: bool,
    pub(super) money_probe_due: bool,
    pub(super) unknown_outcome: bool,
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
    let policy = revision_policy(inputs.active_revision)
        .filter(|_| inputs.active_revision <= MAX_GATED_CLAUDE_REVISION);
    let money_held = inputs.money_paused
        && !inputs.unknown_outcome
        && !(inputs.money_probe_due && page.reserve_money_probe(index_key, size_bytes));
    let decision = if inputs.unknown_outcome {
        HistoryDecision::Held(HistoryHold::UnknownOutcome)
    } else if money_held {
        HistoryDecision::Held(HistoryHold::MoneyPaused)
    } else if inputs.active_revision == 3 && inputs.exclusions.pauses_adoption() {
        HistoryDecision::Held(HistoryHold::ListPaused)
    } else {
        match kind {
            HistoryKind::Settled | HistoryKind::Fresh => HistoryDecision::NotOwed,
            HistoryKind::Changed => {
                if inputs.listed && !policy.is_some_and(|policy| policy.listed_changed_may_emit) {
                    HistoryDecision::Held(HistoryHold::ListedChanged)
                } else {
                    HistoryDecision::NotOwed
                }
            }
            HistoryKind::Owed => {
                let hold = if policy.is_none() {
                    Some(HistoryHold::UngatedRevision)
                } else if inputs.exclusions.pauses_adoption() {
                    Some(HistoryHold::ListPaused)
                } else if inputs.listed {
                    Some(HistoryHold::Listed)
                } else if let Some(hold) = no_list_hold(inputs) {
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
        }
    };
    page.note(kind, decision, inputs.exclusions.state());
    decision
}

/// SOURCE F4a, narrowed by Amendment 16: where no list is intended and the
/// policy holds, owed history is held up to the later of the fixed no-list
/// cutoff and the saved history cutoff. Unknown birth is history. Under
/// `Pace` nothing is held here; the budget paces it.
pub(super) fn no_list_hold(inputs: &PolicyInputs<'_>) -> Option<HistoryHold> {
    let hold = match inputs.no_list_policy {
        NoListPolicy::Pace => return None,
        NoListPolicy::HoldUnverified => HistoryHold::NoListBirth,
        NoListPolicy::HoldMoveNotFull => HistoryHold::MoveNotFull,
    };
    (inputs
        .exclusions
        .holds_without_list(inputs.birth_unix_seconds)
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
    files: usize,
    bytes: u64,
    reserved: BTreeSet<String>,
    money_probe: Option<String>,
    /// Candidates classified as owed upgrades.
    pub(super) owed: u64,
    /// Owed upgrades permitted on this page.
    pub(super) permitted: u64,
    /// Held candidates by (reason, list state).
    pub(super) denied: BTreeMap<(&'static str, &'static str), u64>,
}

crate::heap_layout_bound::fields!(HistoryPage; files, bytes, reserved, money_probe, owed, permitted, denied);

impl HistoryPage {
    pub(super) fn owns_money_probe(&self, key: &str) -> bool {
        self.money_probe.as_deref() == Some(key)
    }

    fn reserve_money_probe(&mut self, key: &str, bytes: u64) -> bool {
        if self
            .money_probe
            .as_deref()
            .is_some_and(|probe| probe != key)
        {
            return false;
        }
        if !self.reserve(key, bytes) {
            return false;
        }
        self.money_probe = Some(key.to_owned());
        true
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
        if self.files >= super::body_witness_adoption_page_budget()
            || (self.bytes.saturating_add(size_bytes) > super::body_witness_adoption_byte_budget()
                && !(first_file && self.files == 0))
        {
            return false;
        }
        self.files += 1;
        self.bytes = self.bytes.saturating_add(size_bytes);
        self.reserved.insert(index_key.to_owned());
        true
    }

    fn note(&mut self, kind: HistoryKind, decision: HistoryDecision, list: ListState) {
        if kind == HistoryKind::Owed {
            self.owed = self.owed.saturating_add(1);
        }
        match decision {
            HistoryDecision::Owed => self.permitted = self.permitted.saturating_add(1),
            HistoryDecision::Held(hold) => self.note_denied(hold, list),
            HistoryDecision::NotOwed => {}
        }
    }

    pub(super) fn note_denied(&mut self, hold: HistoryHold, list: ListState) {
        let count = self
            .denied
            .entry((hold.as_str(), list.as_str()))
            .or_default();
        *count = count.saturating_add(1);
    }

    pub(super) fn denied_for(&self, holds: &[HistoryHold]) -> u64 {
        self.denied
            .iter()
            .filter(|((reason, _), _)| holds.iter().any(|hold| hold.as_str() == *reason))
            .map(|(_, count)| *count)
            .sum()
    }

    pub(super) fn any(&self) -> bool {
        self.owed > 0 || !self.denied.is_empty()
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
pub(super) struct HeldUploadTuple {
    pub(super) last_snapshot_fingerprint: Option<String>,
    pub(super) last_upload_body_witness: Option<String>,
    pub(super) revision: u64,
    pub(super) file_snapshot_fingerprints: Option<BTreeSet<String>>,
    pub(super) confirmed_empty: bool,
}

crate::heap_layout_bound::fields!(HeldUploadTuple; last_snapshot_fingerprint, last_upload_body_witness, revision, file_snapshot_fingerprints, confirmed_empty);

/// One gated Claude history file of this cycle, keyed by its source file
/// fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct GatedHistory {
    pub(super) index_key: String,
    /// `None` while permitted; a hold once denied.
    pub(super) held: Option<HistoryHold>,
    /// The entry's upload tuple before this parse; `None` for a new file.
    pub(super) previous: Option<HeldUploadTuple>,
    /// A held new file's local entity fingerprints. They name the file's
    /// semantic group only; they are never advertised as its membership.
    pub(super) local: BTreeSet<String>,
}

crate::heap_layout_bound::fields!(GatedHistory; index_key, held, previous, local);

/// Runtime-only gate state of one cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HistoryEmission {
    pub(super) files: BTreeMap<String, GatedHistory>,
}

crate::heap_layout_bound::fields!(HistoryEmission; files);

impl HistoryEmission {
    pub(super) fn held(&self, source_file_fingerprint: &str) -> Option<HistoryHold> {
        self.files
            .get(source_file_fingerprint)
            .and_then(|gated| gated.held)
    }

    /// Recheck the stop latch at the emission seam: a fold can latch after a
    /// candidate was permitted.
    pub(super) fn hold_permitted_for_latch(&mut self) -> usize {
        let mut held = 0;
        for gated in self.files.values_mut() {
            if gated.held.is_none() {
                gated.held = Some(HistoryHold::Latched);
                held += 1;
            }
        }
        held
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

#[cfg(test)]
mod tests {
    use super::*;

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
            money_paused: false,
            unknown_outcome: false,
            money_probe_due: false,
            active_revision: active,
            history_cutoff_unix_seconds: None,
            no_list_policy: NoListPolicy::Pace,
        }
    }

    #[test]
    fn unknown_scope_does_not_spend_the_unrelated_known_outcome_probe() {
        let list = installed("");
        let mut paused = inputs(&list, false, 3);
        paused.money_paused = true;
        paused.money_probe_due = true;
        paused.unknown_outcome = true;
        let mut page = HistoryPage::default();
        assert_eq!(
            decide(HistoryKind::Owed, &paused, &mut page, "unknown", 1),
            HistoryDecision::Held(HistoryHold::UnknownOutcome)
        );
        assert_eq!(
            page.files, 0,
            "held UNKNOWN reuses its original reservation"
        );
        paused.unknown_outcome = false;
        assert_eq!(
            decide(HistoryKind::Fresh, &paused, &mut page, "unrelated", 1),
            HistoryDecision::NotOwed
        );
        assert!(page.owns_money_probe("unrelated"));
        assert_eq!(
            decide(HistoryKind::Fresh, &paused, &mut page, "other", 1),
            HistoryDecision::Held(HistoryHold::MoneyPaused)
        );
        assert_eq!(page.files, 1);
    }

    #[test]
    fn money_pause_holds_every_classification_and_allows_one_bounded_probe() {
        let list = installed("");
        let mut paused = inputs(&list, false, 3);
        paused.money_paused = true;
        for kind in [
            HistoryKind::Settled,
            HistoryKind::Fresh,
            HistoryKind::Changed,
            HistoryKind::Owed,
        ] {
            let mut page = HistoryPage::default();
            assert_eq!(
                decide(kind, &paused, &mut page, "a", 1),
                HistoryDecision::Held(HistoryHold::MoneyPaused)
            );
            assert_eq!(page.files, 0);
        }
        paused.money_probe_due = true;
        let mut page = HistoryPage::default();
        assert_eq!(
            decide(HistoryKind::Changed, &paused, &mut page, "a", 1),
            HistoryDecision::NotOwed
        );
        assert_eq!(
            decide(HistoryKind::Fresh, &paused, &mut page, "b", 1),
            HistoryDecision::Held(HistoryHold::MoneyPaused)
        );
        assert_eq!(page.files, 1);
        let mut page = HistoryPage::default();
        assert_eq!(
            decide(
                HistoryKind::Fresh,
                &paused,
                &mut page,
                "huge",
                HISTORY_UPGRADE_BYTES_PER_PAGE + 1
            ),
            HistoryDecision::Held(HistoryHold::MoneyPaused)
        );
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
        let touched = FileExtent {
            modified_unix_nanos: Some(100_000_000_001),
            ..EXTENT
        };
        assert_eq!(
            classify(Some(EXTENT), touched, true, None, None),
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
        assert!(revision_policy(2).unwrap().listed_changed_may_emit);
        assert!(!revision_policy(3).unwrap().listed_changed_may_emit);
        assert_eq!(revision_policy(4), None);
        // The composed money paths use the shared gate; an unknown revision
        // still cannot adopt, independently of the live feature gate.
        assert_eq!(MAX_GATED_CLAUDE_REVISION, 3);
        let list = installed("");
        assert_eq!(
            decide(
                HistoryKind::Owed,
                &inputs(&list, false, 4),
                &mut HistoryPage::default(),
                "k",
                1
            ),
            HistoryDecision::Held(HistoryHold::UngatedRevision)
        );
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

    #[test]
    fn listed_change_emits_under_revision_two_and_is_denied_under_three() {
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
            HistoryDecision::Held(HistoryHold::ListedChanged)
        );
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
                &inputs(&list, false, MAX_GATED_CLAUDE_REVISION + 1),
                &mut page,
                "k",
                1
            ),
            HistoryDecision::Held(HistoryHold::UngatedRevision)
        );
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
}
