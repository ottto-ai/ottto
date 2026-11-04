//! Fixed, counts-only page observations. Scopes cover synchronous operations,
//! never a parked scan. The owner carries counts between cooperative steps;
//! nested/other-source work and concurrent threads cannot contaminate a page.
use super::cache_lifecycle;
use serde::Serialize;
use std::cell::Cell;

/// Full selections and completed native bytes, keyed only by the existing
/// CandidateParseReason labels. Stored in the existing per-probe page registry.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FullByParseReason(
    [super::rearm_cause::Total; crate::snapshots::CANDIDATE_PARSE_REASON_COUNT],
);
impl FullByParseReason {
    pub(crate) fn is_empty(&self) -> bool {
        self.0
            .iter()
            .all(|n| n.count == 0 && n.completed_native_bytes == 0)
    }
    pub(super) fn record(
        &mut self,
        reason: crate::snapshots::CandidateParseReason,
        count: u64,
        completed_native_bytes: u64,
    ) {
        let total = &mut self.0[reason as usize];
        total.count = total.count.saturating_add(count);
        total.completed_native_bytes = total
            .completed_native_bytes
            .saturating_add(completed_native_bytes);
    }
}
impl Serialize for FullByParseReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(
            crate::snapshots::CANDIDATE_PARSE_REASON_NAMES
                .iter()
                .zip(&self.0)
                .filter(|(_, n)| n.count != 0 || n.completed_native_bytes != 0),
        )
    }
}

/// Closed labels for the existing progress-blocking / restore branches.
#[derive(Clone, Copy)]
pub(crate) enum HeldReason {
    AuthorityUnboundRevision,
    AuthorityCorrectionPending,
    AccountHoldUnrecorded,
    NotRestorable,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct HeldReasons {
    #[serde(skip_serializing_if = "super::is_zero")]
    authority_unbound_revision: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    authority_correction_pending: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    account_hold_unrecorded: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    not_restorable: u64,
}
impl HeldReasons {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
    fn merge(&mut self, other: Self) {
        self.authority_unbound_revision = self
            .authority_unbound_revision
            .saturating_add(other.authority_unbound_revision);
        self.authority_correction_pending = self
            .authority_correction_pending
            .saturating_add(other.authority_correction_pending);
        self.account_hold_unrecorded = self
            .account_hold_unrecorded
            .saturating_add(other.account_hold_unrecorded);
        self.not_restorable = self.not_restorable.saturating_add(other.not_restorable);
    }
}
pub(crate) fn held_reason(reason: HeldReason) {
    update(|counts| {
        let reasons = &mut counts.claude_reread.held_reason;
        let counter = match reason {
            HeldReason::AuthorityUnboundRevision => &mut reasons.authority_unbound_revision,
            HeldReason::AuthorityCorrectionPending => &mut reasons.authority_correction_pending,
            HeldReason::AccountHoldUnrecorded => &mut reasons.account_hold_unrecorded,
            HeldReason::NotRestorable => &mut reasons.not_restorable,
        };
        *counter = counter.saturating_add(1);
    });
}

/// Why a family's locally reported usage evidence was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IgnoredVeto {
    EvidenceGap,
    InvalidRows,
    DuplicateRows,
    ClientMismatch,
    MultiRootClaims,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Rearm {
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) restored_empty_held: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) restored_nonempty_held: u64,
    #[serde(skip_serializing_if = "HeldReasons::is_empty")]
    pub(crate) held_reason: HeldReasons,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) restored_empty_sibling: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) restored_nonempty_sibling: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) sibling_exact_incidence_only: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) authority_normalization_cleared: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) history_permitted_not_stamped_not_accepted: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) history_permitted_not_stamped_telemetry_unread: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) history_permitted_not_stamped_held: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) history_permitted_not_stamped_other: u64,
}
impl Rearm {
    fn merge(&mut self, other: Self) {
        macro_rules! merge { ($($field:ident),+ $(,)?) => { $(
            self.$field = self.$field.saturating_add(other.$field);
        )+ }; }
        merge!(
            restored_empty_held,
            restored_nonempty_held,
            restored_empty_sibling,
            restored_nonempty_sibling,
            sibling_exact_incidence_only,
            authority_normalization_cleared,
            history_permitted_not_stamped_not_accepted,
            history_permitted_not_stamped_telemetry_unread,
            history_permitted_not_stamped_held,
            history_permitted_not_stamped_other
        );
        self.held_reason.merge(other.held_reason);
    }
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Counts {
    #[serde(skip_serializing_if = "LineageParentless::is_empty")]
    pub(crate) lineage_parentless_while_incomplete: LineageParentless,
    #[serde(skip_serializing_if = "DesktopMetadata::is_empty")]
    pub(crate) desktop_metadata: DesktopMetadata,
    #[serde(flatten)]
    pub(crate) absence: super::claude_absence::Counts,
    #[serde(flatten)]
    pub(crate) contract: super::claude_contract::Counts,
    #[serde(skip_serializing_if = "Rearm::is_empty")]
    pub(crate) claude_reread: Rearm,
    #[serde(skip_serializing_if = "CachePage::is_empty")]
    pub(crate) retained_cache_page_events: CachePage,
    /// Text the always-on link scrape tokenized: its cost is watched, not capped.
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) link_scrape_bytes: u64,
    /// Links left off an upload for the receiver's value length.
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) links_over_limit: u64,
}
/// Finalized file offers, not parses or stored-body acknowledgements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct LineageParentless {
    #[serde(skip_serializing_if = "super::is_zero")]
    files: u64,
}
impl LineageParentless {
    fn is_empty(&self) -> bool {
        self.files == 0
    }
    fn merge(&mut self, other: Self) {
        self.files = self.files.saturating_add(other.files);
    }
}
pub(crate) fn lineage_parentless_while_incomplete(files: u64) {
    update(|counts| {
        counts
            .lineage_parentless_while_incomplete
            .merge(LineageParentless { files })
    });
}

/// Counts only, on the existing page line. Revisions count actual body reads,
/// not selection, metadata IO, sample verification, or an unchanged RAM reuse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct DesktopMetadata {
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) inventory_restarts: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) source_revision_body_rereads: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) legacy_identity_body_rereads: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) lineage_window_read_attempts: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) recovered_hold_body_rereads: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) scoped_acquisition_attempts: u64,
}
impl DesktopMetadata {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
    fn merge(&mut self, other: Self) {
        self.inventory_restarts = self
            .inventory_restarts
            .saturating_add(other.inventory_restarts);
        self.source_revision_body_rereads = self
            .source_revision_body_rereads
            .saturating_add(other.source_revision_body_rereads);
        self.legacy_identity_body_rereads = self
            .legacy_identity_body_rereads
            .saturating_add(other.legacy_identity_body_rereads);
        self.lineage_window_read_attempts = self
            .lineage_window_read_attempts
            .saturating_add(other.lineage_window_read_attempts);
        self.recovered_hold_body_rereads = self
            .recovered_hold_body_rereads
            .saturating_add(other.recovered_hold_body_rereads);
        self.scoped_acquisition_attempts = self
            .scoped_acquisition_attempts
            .saturating_add(other.scoped_acquisition_attempts);
    }
}
// The inventory restart and scoped acquisition have no production caller until
// the full #851 re-land, so those two counters stay zero and absent.
#[cfg(test)]
pub(crate) fn desktop_inventory_restart() {
    update(|counts| {
        let n = &mut counts.desktop_metadata.inventory_restarts;
        *n = n.saturating_add(1);
    });
}
pub(crate) fn desktop_revision_body_read(legacy: bool) {
    update(|counts| {
        let n = if legacy {
            &mut counts.desktop_metadata.legacy_identity_body_rereads
        } else {
            &mut counts.desktop_metadata.source_revision_body_rereads
        };
        *n = n.saturating_add(1);
    });
}
pub(crate) fn desktop_lineage_window_read() {
    update(|counts| {
        let n = &mut counts.desktop_metadata.lineage_window_read_attempts;
        *n = n.saturating_add(1);
    });
}
pub(crate) fn desktop_recovered_hold_body_read() {
    update(|counts| {
        let n = &mut counts.desktop_metadata.recovered_hold_body_rereads;
        *n = n.saturating_add(1);
    });
}
pub(crate) fn desktop_scoped_acquisition() {
    update(|counts| {
        let n = &mut counts.desktop_metadata.scoped_acquisition_attempts;
        *n = n.saturating_add(1);
    });
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct CachePage {
    #[serde(flatten, serialize_with = "sparse_cache")]
    pub(crate) events: cache_lifecycle::Counts,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) insert_count_entries_evicted: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) insert_byte_entries_evicted: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) reinsert_failed: u64,
}
fn sparse_cache<S: serde::Serializer>(
    counts: &cache_lifecycle::Counts,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    cache_lifecycle::Sparse(*counts).serialize(serializer)
}
impl CachePage {
    fn is_empty(&self) -> bool {
        self.events.is_empty()
            && self.insert_count_entries_evicted == 0
            && self.insert_byte_entries_evicted == 0
            && self.reinsert_failed == 0
    }
    fn merge(&mut self, other: Self) {
        self.events.merge(other.events);
        self.insert_count_entries_evicted = self
            .insert_count_entries_evicted
            .saturating_add(other.insert_count_entries_evicted);
        self.insert_byte_entries_evicted = self
            .insert_byte_entries_evicted
            .saturating_add(other.insert_byte_entries_evicted);
        self.reinsert_failed = self.reinsert_failed.saturating_add(other.reinsert_failed);
    }
}
pub(crate) fn cache_capacity_eviction(count_pressure: bool) {
    update(|counts| {
        let cache = &mut counts.retained_cache_page_events;
        let n = if count_pressure {
            &mut cache.insert_count_entries_evicted
        } else {
            &mut cache.insert_byte_entries_evicted
        };
        *n = n.saturating_add(1);
    });
}
impl Counts {
    pub(crate) fn merge(&mut self, other: Self) {
        self.lineage_parentless_while_incomplete
            .merge(other.lineage_parentless_while_incomplete);
        self.desktop_metadata.merge(other.desktop_metadata);
        self.contract.merge(other.contract);
        self.claude_reread.merge(other.claude_reread);
        self.absence.0 =
            std::array::from_fn(|i| self.absence.0[i].saturating_add(other.absence.0[i]));
        self.retained_cache_page_events
            .merge(other.retained_cache_page_events);
        self.link_scrape_bytes = self
            .link_scrape_bytes
            .saturating_add(other.link_scrape_bytes);
        self.links_over_limit = self.links_over_limit.saturating_add(other.links_over_limit);
    }
    /// What a non-Claude page emits: the shared retained cache's events only.
    pub(super) fn retained_cache_only(self) -> Self {
        Self {
            retained_cache_page_events: self.retained_cache_page_events,
            ..Self::default()
        }
    }
    pub(crate) fn with_current(mut self) -> Self {
        CURRENT.with(|current| {
            if let Some(counts) = current.get() {
                self.merge(counts);
            }
        });
        self
    }
}
thread_local! {
    static CURRENT: Cell<Option<Counts>> = const { Cell::new(None) };
}
pub(crate) struct Scope {
    previous: Option<Counts>,
    restored: bool,
    report_at_finish: bool,
}
impl Scope {
    pub(crate) fn begin(claude: bool) -> Self {
        Self {
            previous: CURRENT.with(|current| current.replace(claude.then(Counts::default))),
            restored: false,
            report_at_finish: false,
        }
    }
    pub(crate) fn finish_decision(claude: bool, has_lease: bool) -> Self {
        let mut scope = Self::begin(claude);
        scope.report_at_finish = claude && !has_lease;
        scope
    }
    pub(crate) fn finish(mut self) -> Counts {
        let counts = CURRENT
            .with(|current| current.replace(self.previous))
            .unwrap_or_default();
        self.restored = true;
        counts
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if !self.restored {
            if self.report_at_finish && !std::thread::panicking() {
                emit_without_lease(Counts::default().with_current());
            }
            CURRENT.with(|current| current.set(self.previous));
        }
    }
}
pub(crate) fn emit_without_lease(counts: Counts) {
    if counts != Counts::default() {
        // The disabled-before-lease point has already reported the gate.
        // Reuse its stage at the end of work only when there are actual events.
        // Pass a plain decision to avoid merging the active TLS scope twice.
        #[derive(Serialize)]
        struct Row {
            #[serde(flatten)]
            decision: super::NativeComparisonDecision,
            #[serde(flatten)]
            counts: Counts,
        }
        super::traversal_point(
            "native_comparison_decision",
            "claude_code",
            &Row {
                decision: super::NativeComparisonDecision {
                    layout_supported: crate::heap_layout_bound::layout_supported(),
                    outcome: super::NativeDecisionOutcome::DisabledBeforeLease,
                    ..Default::default()
                },
                counts,
            },
        );
    }
}
pub(crate) fn active() -> bool {
    CURRENT.with(|current| current.get().is_some())
}
pub(super) fn update(f: impl FnOnce(&mut Counts)) {
    CURRENT.with(|current| {
        if let Some(mut counts) = current.get() {
            f(&mut counts);
            current.set(Some(counts));
        }
    });
}
pub(crate) fn link_scrape_bytes(bytes: u64) {
    if bytes > 0 {
        update(|counts| counts.link_scrape_bytes = counts.link_scrape_bytes.saturating_add(bytes));
    }
}
pub(crate) fn links_over_limit(links: u64) {
    if links > 0 {
        update(|counts| counts.links_over_limit = counts.links_over_limit.saturating_add(links));
    }
}
pub(crate) fn cache_event(event: cache_lifecycle::Event, amount: u64) {
    update(|counts| counts.retained_cache_page_events.events.add(event, amount));
}
pub(crate) fn restored(previous_empty: bool, held: bool, exact_only: bool) {
    update(|counts| {
        let c = &mut counts.claude_reread;
        let counter = match (previous_empty, held) {
            (true, true) => &mut c.restored_empty_held,
            (false, true) => &mut c.restored_nonempty_held,
            (true, false) => &mut c.restored_empty_sibling,
            (false, false) => &mut c.restored_nonempty_sibling,
        };
        *counter = counter.saturating_add(1);
        c.sibling_exact_incidence_only = c
            .sibling_exact_incidence_only
            .saturating_add(u64::from(exact_only));
    });
}
/// Why an upgrade the history gate permitted this page did not stamp.
pub(crate) enum NotStamped {
    NotAccepted,
    TelemetryUnread,
    Held,
    Other,
}
pub(crate) fn history_permitted_not_stamped(reason: NotStamped) {
    update(|counts| {
        let c = &mut counts.claude_reread;
        let n = match reason {
            NotStamped::NotAccepted => &mut c.history_permitted_not_stamped_not_accepted,
            NotStamped::TelemetryUnread => &mut c.history_permitted_not_stamped_telemetry_unread,
            NotStamped::Held => &mut c.history_permitted_not_stamped_held,
            NotStamped::Other => &mut c.history_permitted_not_stamped_other,
        };
        *n = n.saturating_add(1);
    });
}
pub(crate) fn authority_normalization(cleared: u64) {
    update(|counts| {
        let n = &mut counts.claude_reread.authority_normalization_cleared;
        *n = n.saturating_add(cleared);
    });
}

/// Follows a destructive hit through eligibility, parse and retention. Carries
/// no identity or state; disarmed only after a successful cache admission.
#[derive(Default)]
pub(crate) struct Reinsertion(Cell<bool>);
impl Reinsertion {
    pub(crate) fn new(hit: bool) -> Self {
        Self(Cell::new(hit && active()))
    }
    pub(crate) fn admitted(&self) {
        self.0.set(false);
    }
}
impl Drop for Reinsertion {
    fn drop(&mut self) {
        if self.0.get() {
            update(|counts| {
                let n = &mut counts.retained_cache_page_events.reinsert_failed;
                *n = n.saturating_add(1);
            });
        }
    }
}
crate::heap_layout_bound::no_heap!(false; Reinsertion);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_scope_isolates_sources_nested_work_threads_and_resumption() {
        let scope = Scope::begin(true);
        restored(true, false, false);
        {
            let other = Scope::begin(false);
            restored(true, false, false);
            cache_lifecycle::record(cache_lifecycle::Event::TakeHit);
            assert_eq!(other.finish(), Counts::default());
        }
        let nested = Scope::begin(true);
        restored(false, false, false);
        assert_eq!(nested.finish().claude_reread.restored_nonempty_sibling, 1);
        std::thread::spawn(|| restored(true, false, false))
            .join()
            .unwrap();
        let mut page = scope.finish();
        assert_eq!(page.claude_reread.restored_empty_sibling, 1);
        assert_eq!(page.claude_reread.restored_nonempty_sibling, 0);
        assert!(page.retained_cache_page_events.is_empty());
        let resumed = Scope::begin(true);
        restored(false, false, false);
        page.merge(resumed.finish());
        assert_eq!(page.claude_reread.restored_empty_sibling, 1);
        assert_eq!(page.claude_reread.restored_nonempty_sibling, 1);
        assert!(!active());
    }
    #[test]
    fn sparse_counts_saturate_and_count_failed_reinsertion_once() {
        assert_eq!(
            serde_json::to_value(Counts::default()).unwrap(),
            serde_json::json!({})
        );
        let scope = Scope::begin(true);
        desktop_inventory_restart();
        desktop_scoped_acquisition();
        {
            let _failed = Reinsertion::new(true);
            let success = Reinsertion::new(true);
            success.admitted();
            let _absent = Reinsertion::new(false);
        }
        authority_normalization(u64::MAX);
        authority_normalization(1);
        let counts = scope.finish();
        assert_eq!(counts.retained_cache_page_events.reinsert_failed, 1);
        assert_eq!(
            counts.claude_reread.authority_normalization_cleared,
            u64::MAX
        );
        let value = serde_json::to_value(counts).unwrap();
        assert_eq!(
            value["retained_cache_page_events"],
            serde_json::json!({"reinsert_failed": 1})
        );
        assert_eq!(value["claude_reread"].as_object().unwrap().len(), 1);
    }
}
