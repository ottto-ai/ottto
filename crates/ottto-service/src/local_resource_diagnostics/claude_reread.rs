//! Fixed, counts-only page observations. Scopes cover synchronous operations,
//! never a parked scan. The owner carries counts between cooperative steps;
//! nested/other-source work and concurrent threads cannot contaminate a page.
use super::cache_lifecycle;
use serde::Serialize;
use std::cell::Cell;

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

// Fixed reason names, shared by the window mask and sparse #799 counters.
macro_rules! ignored_vetoes {
    ($($kind:ident => $key:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum IgnoredVeto { $($kind),+ }
        impl IgnoredVeto {
            pub(crate) const ALL: &'static [(Self, &'static str)] = &[$((Self::$kind, $key)),+];
            pub(crate) fn bit(self) -> u16 { 1 << self as u16 }
        }
    };
}
ignored_vetoes! {
    WithheldAccount => "withheld_account", EvidenceGap => "evidence_gap",
    RequestsRefused => "requests_refused", IdentityRefusals => "identity_refusals",
    InvalidRows => "invalid_rows", DuplicateRows => "duplicate_rows",
    ClientMismatch => "client_mismatch", MultiRootClaims => "multi_root_claims",
    ProofFailure => "proof_failure", ReconstructionFailure => "reconstruction_failure",
    MissingInputs => "missing_inputs", RebuildFailure => "rebuild_failure",
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IgnoredVetoCounts([u64; 12]);
impl Serialize for IgnoredVetoCounts {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(IgnoredVeto::ALL.iter().filter_map(|(kind, key)| {
            let n = self.0[*kind as usize];
            (n != 0).then_some((*key, n))
        }))
    }
}
impl IgnoredVetoCounts {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
    fn merge(&mut self, other: Self) {
        self.0 = std::array::from_fn(|i| self.0[i].saturating_add(other.0[i]));
    }
}
pub(crate) fn ignored_vetoes(mask: u16, preserved: u64) {
    if mask == 0 {
        return;
    }
    update(|counts| {
        for (kind, _) in IgnoredVeto::ALL {
            let n = &mut counts.rearm_veto_ignored.0[*kind as usize];
            *n = n.saturating_add(u64::from(mask & kind.bit() != 0));
        }
        counts.rearm_fingerprints_preserved = counts
            .rearm_fingerprints_preserved
            .saturating_add(preserved);
    });
}

pub(crate) fn structural_native_duplicate() {
    update(|counts| {
        counts.rearm_structural_native_duplicate =
            counts.rearm_structural_native_duplicate.saturating_add(1)
    });
}

/// The terminal fold follows collection. Publish its delta on the same #799
/// page carrier, then retain it for scoped inspection (not comparison output).
pub(crate) fn terminal_rearm(mask: u16, preserved: u64, native_duplicate: bool) {
    if mask == 0 && !native_duplicate {
        return;
    }
    let scope = Scope::begin(true);
    ignored_vetoes(mask, preserved);
    if native_duplicate {
        structural_native_duplicate();
    }
    let counts = scope.finish();
    update(|page| page.merge(counts));
    super::rearm_collection(counts);
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
    pub(crate) owned_start_calls: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) owned_start_cleared: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) account_reproof_calls: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) account_reproof_cleared: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) retry_admission_offered: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) retry_admission_cleared: u64,
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
            owned_start_calls,
            owned_start_cleared,
            account_reproof_calls,
            account_reproof_cleared,
            retry_admission_offered,
            retry_admission_cleared,
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
    #[serde(skip_serializing_if = "IgnoredVetoCounts::is_empty")]
    pub(crate) rearm_veto_ignored: IgnoredVetoCounts,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) rearm_fingerprints_preserved: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) rearm_structural_native_duplicate: u64,
    #[serde(flatten)]
    pub(crate) absence: super::claude_absence::Counts,
    #[serde(flatten)]
    pub(crate) contract: super::claude_contract::Counts,
    #[serde(skip_serializing_if = "Rearm::is_empty")]
    pub(crate) claude_reread: Rearm,
    #[serde(skip_serializing_if = "CachePage::is_empty")]
    pub(crate) retained_cache_page_events: CachePage,
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
#[cfg(test)]
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
        self.rearm_veto_ignored.merge(other.rearm_veto_ignored);
        self.rearm_structural_native_duplicate = self
            .rearm_structural_native_duplicate
            .saturating_add(other.rearm_structural_native_duplicate);
        self.rearm_fingerprints_preserved = self
            .rearm_fingerprints_preserved
            .saturating_add(other.rearm_fingerprints_preserved);
        self.contract.merge(other.contract);
        self.claude_reread.merge(other.claude_reread);
        self.absence.0 =
            std::array::from_fn(|i| self.absence.0[i].saturating_add(other.absence.0[i]));
        self.retained_cache_page_events
            .merge(other.retained_cache_page_events);
    }
    pub(super) fn without_terminal_rearm(mut self) -> Self {
        self.rearm_veto_ignored = Default::default();
        self.rearm_fingerprints_preserved = 0;
        self.rearm_structural_native_duplicate = 0;
        self
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
    let counts = counts.without_terminal_rearm();
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
pub(crate) fn retry_offered() {
    update(|counts| {
        let n = &mut counts.claude_reread.retry_admission_offered;
        *n = n.saturating_add(1);
    });
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
pub(crate) enum ClearSite {
    OwnedStart,
    AccountReproof,
    RetryAdmission,
}
pub(crate) fn clear(site: ClearSite, nonempty: bool) {
    update(|counts| {
        let c = &mut counts.claude_reread;
        let count_call = !matches!(site, ClearSite::RetryAdmission);
        let (calls, cleared) = match site {
            ClearSite::OwnedStart => (&mut c.owned_start_calls, &mut c.owned_start_cleared),
            ClearSite::AccountReproof => {
                (&mut c.account_reproof_calls, &mut c.account_reproof_cleared)
            }
            ClearSite::RetryAdmission => (
                &mut c.retry_admission_offered,
                &mut c.retry_admission_cleared,
            ),
        };
        *calls = calls.saturating_add(u64::from(count_call));
        *cleared = cleared.saturating_add(u64::from(nonempty));
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
impl crate::heap_layout_bound::HeapLayoutBound for Reinsertion {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn desktop_metadata_counts_are_sparse_saturating_and_scope_local() {
        let scope = super::Scope::begin(true);
        super::desktop_inventory_restart();
        super::desktop_revision_body_read(false);
        super::desktop_revision_body_read(true);
        super::desktop_lineage_window_read();
        super::desktop_recovered_hold_body_read();
        super::desktop_scoped_acquisition();
        let mut counts = scope.finish();
        counts.desktop_metadata.inventory_restarts = u64::MAX;
        let scope = super::Scope::begin(true);
        super::desktop_inventory_restart();
        counts.merge(scope.finish());
        assert_eq!(
            serde_json::to_value(counts).unwrap()["desktop_metadata"],
            serde_json::json!({
                "inventory_restarts":u64::MAX, "source_revision_body_rereads":1,
                "legacy_identity_body_rereads":1, "lineage_window_read_attempts":1,
                "recovered_hold_body_rereads":1, "scoped_acquisition_attempts":1
            })
        );
        assert!(serde_json::to_value(super::Counts::default())
            .unwrap()
            .get("desktop_metadata")
            .is_none());
        let scope = super::Scope::begin(false);
        super::desktop_inventory_restart();
        assert_eq!(scope.finish(), super::Counts::default());
    }
    use super::*;
    #[test]
    fn held_reasons_are_sparse_saturating_and_merged_across_scopes() {
        let scope = Scope::begin(true);
        held_reason(HeldReason::AuthorityUnboundRevision);
        held_reason(HeldReason::AuthorityCorrectionPending);
        let mut counts = scope.finish();
        counts.claude_reread.held_reason.not_restorable = u64::MAX;
        let scope = Scope::begin(true);
        held_reason(HeldReason::AccountHoldUnrecorded);
        held_reason(HeldReason::NotRestorable);
        counts.merge(scope.finish());
        assert_eq!(
            serde_json::to_value(counts).unwrap()["claude_reread"]["held_reason"],
            serde_json::json!({
                "authority_unbound_revision": 1, "authority_correction_pending": 1,
                "account_hold_unrecorded": 1, "not_restorable": u64::MAX,
            })
        );
    }

    #[test]
    fn page_scope_isolates_sources_nested_work_threads_and_resumption() {
        let scope = Scope::begin(true);
        clear(ClearSite::OwnedStart, true);
        {
            let other = Scope::begin(false);
            clear(ClearSite::AccountReproof, true);
            cache_lifecycle::record(cache_lifecycle::Event::TakeHit);
            assert_eq!(other.finish(), Counts::default());
        }
        let nested = Scope::begin(true);
        clear(ClearSite::AccountReproof, false);
        assert_eq!(nested.finish().claude_reread.account_reproof_calls, 1);
        std::thread::spawn(|| clear(ClearSite::OwnedStart, true))
            .join()
            .unwrap();
        let mut page = scope.finish();
        assert_eq!(page.claude_reread.owned_start_calls, 1);
        assert_eq!(page.claude_reread.owned_start_cleared, 1);
        assert_eq!(page.claude_reread.account_reproof_calls, 0);
        assert!(page.retained_cache_page_events.is_empty());
        let resumed = Scope::begin(true);
        clear(ClearSite::OwnedStart, false);
        page.merge(resumed.finish());
        assert_eq!(page.claude_reread.owned_start_calls, 2);
        assert_eq!(page.claude_reread.owned_start_cleared, 1);
        assert!(!active());
    }
    #[test]
    fn sparse_counts_saturate_and_count_failed_reinsertion_once() {
        assert_eq!(
            serde_json::to_value(Counts::default()).unwrap(),
            serde_json::json!({})
        );
        let scope = Scope::begin(true);
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

#[cfg(test)]
mod ignored_tests {
    use super::*;
    #[test]
    fn ignored_keys_are_sparse_saturating_and_page_local() {
        assert_eq!(IgnoredVeto::ALL.len(), 12, "closed diagnostic cardinality");
        assert!(IgnoredVeto::ALL
            .iter()
            .all(|(kind, _)| kind.bit() < (1 << 12)));
        assert_eq!(
            serde_json::to_value(Counts::default()).unwrap(),
            serde_json::json!({})
        );
        let scope = Scope::begin(true);
        ignored_vetoes(
            IgnoredVeto::EvidenceGap.bit() | IgnoredVeto::EvidenceGap.bit(),
            u64::MAX,
        );
        let other = Scope::begin(false);
        ignored_vetoes(IgnoredVeto::WithheldAccount.bit(), 99);
        assert_eq!(other.finish(), Counts::default());
        let mut page = scope.finish();
        let resumed = Scope::begin(true);
        ignored_vetoes(IgnoredVeto::EvidenceGap.bit(), 1);
        page.merge(resumed.finish());
        assert_eq!(page.rearm_fingerprints_preserved, u64::MAX);
        assert_eq!(
            serde_json::to_value(page.rearm_veto_ignored).unwrap(),
            serde_json::json!({"evidence_gap": 2})
        );
        page.rearm_veto_ignored.0[IgnoredVeto::EvidenceGap as usize] = u64::MAX;
        let mut extra = Counts::default();
        extra.rearm_veto_ignored.0[IgnoredVeto::EvidenceGap as usize] = 1;
        page.merge(extra);
        assert_eq!(
            page.rearm_veto_ignored.0[IgnoredVeto::EvidenceGap as usize],
            u64::MAX
        );
        assert_eq!(Scope::begin(true).finish(), Counts::default());
        let scope = Scope::begin(true);
        structural_native_duplicate();
        let mut native = scope.finish();
        assert_eq!(
            serde_json::to_value(native).unwrap(),
            serde_json::json!({"rearm_structural_native_duplicate": 1})
        );
        native.rearm_structural_native_duplicate = u64::MAX;
        let extra = Counts {
            rearm_structural_native_duplicate: 1,
            ..Counts::default()
        };
        native.merge(extra);
        assert_eq!(native.rearm_structural_native_duplicate, u64::MAX);
    }
}
