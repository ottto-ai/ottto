//! Fixed, counts-only page observations. Scopes cover synchronous operations,
//! never a parked scan. The owner carries counts between cooperative steps;
//! nested/other-source work and concurrent threads cannot contaminate a page.
use super::cache_lifecycle;
use serde::Serialize;
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Rearm {
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) restored_empty_held: u64,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) restored_nonempty_held: u64,
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
    /// Gauge, not an event: Claude files carrying `STAMPED_WITHOUT_PERMIT`.
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) stamped_without_permit: u64,
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
        self.stamped_without_permit = self
            .stamped_without_permit
            .max(other.stamped_without_permit);
    }
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Counts {
    #[serde(flatten)]
    pub(crate) absence: super::claude_absence::Counts,
    #[serde(flatten)]
    pub(crate) contract: super::claude_contract::Counts,
    #[serde(skip_serializing_if = "Rearm::is_empty")]
    pub(crate) claude_reread: Rearm,
    #[serde(skip_serializing_if = "CachePage::is_empty")]
    pub(crate) retained_cache_page_events: CachePage,
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
        self.contract.merge(other.contract);
        self.claude_reread.merge(other.claude_reread);
        self.absence.0 =
            std::array::from_fn(|i| self.absence.0[i].saturating_add(other.absence.0[i]));
        self.retained_cache_page_events
            .merge(other.retained_cache_page_events);
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
pub(crate) fn stamped_without_permit(files: u64) {
    update(|counts| counts.claude_reread.stamped_without_permit = files);
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
    use super::*;
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
