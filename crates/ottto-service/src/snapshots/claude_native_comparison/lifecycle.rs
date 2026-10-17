//! Process-only bootstrap, owned by the daemon rather than the disk index or
//! parser cache. Every lease starts fail-closed; errors/drop cannot renew it.
use super::{Qualification, WindowEligibility};
use crate::source_rotation::{LocalRefusal, PaidReservation};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

/// Fixed process-only context: streamed formatting never constructs a scope
/// String before the first moving reservation can be admitted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scope {
    digest: [u8; 32],
}
impl Scope {
    pub(crate) fn from_arguments(arguments: std::fmt::Arguments<'_>) -> Self {
        struct Writer(Sha256);
        impl std::fmt::Write for Writer {
            fn write_str(&mut self, value: &str) -> std::fmt::Result {
                self.0.update(value.as_bytes());
                Ok(())
            }
        }
        let mut writer = Writer(Sha256::new());
        std::fmt::write(&mut writer, arguments).expect("hash writer is infallible");
        Self {
            digest: writer.0.finalize().into(),
        }
    }
}
impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeComparisonScope")
    }
}
crate::heap_layout_bound::fields!(Scope; digest);

#[derive(Debug, Default)]
pub(crate) struct Lifecycle {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    generation: u64,
    scope: Option<Scope>,
    valid: bool,
    window: Option<Box<WindowEligibility>>,
    admission_refused: bool,
    policy: FamilyPolicyState,
    published_policy: PolicySummary,
    policy_in_flight: bool,
}

pub(crate) struct Lease {
    owner: Arc<Lifecycle>,
    generation: Option<u64>,
    previous_scope: Option<Scope>,
    previous_valid: bool,
    scope: Option<Scope>,
    allowed: bool,
    selected_save: bool,
    native_save: bool,
    finished: bool,
    window: Option<Box<WindowEligibility>>,
    policy: FamilyPolicyState,
    policy_hit: bool,
}

impl Lifecycle {
    pub(crate) fn begin(self: &Arc<Self>) -> Lease {
        let mut lease = Lease {
            owner: self.clone(),
            generation: None,
            previous_scope: None,
            previous_valid: false,
            scope: None,
            allowed: false,
            selected_save: false,
            native_save: false,
            finished: false,
            window: None,
            policy: FamilyPolicyState::default(),
            policy_hit: false,
        };
        if let Ok(mut state) = self.state.lock() {
            lease.previous_valid = state.valid;
            lease.previous_scope = state.scope.take();
            lease.window = state.window.take();
            state.published_policy = state.policy.summary();
            state.policy_in_flight = true;
            lease.policy = std::mem::take(&mut state.policy);
            state.valid = false;
            if let Some(next) = state.generation.checked_add(1) {
                state.generation = next;
                lease.generation = Some(next);
            }
        }
        lease
    }

    /// Ordinary gate on the actual borrowed graph, under a known lock. Never
    /// use mutable Arc/Mutex completion sizing or a second rotation allowance.
    pub(crate) fn retained_bound(&self, limit: usize) -> Option<usize> {
        let state = self.state.try_lock().ok()?;
        if !crate::heap_layout_bound::layout_supported() {
            return (state.window.is_none() && state.policy.families.is_empty()).then_some(0);
        }
        let mut counter = crate::heap_layout_bound::Counter::new(limit);
        use crate::heap_layout_bound::HeapLayoutBound;
        state.window.heap_bound(&mut counter)?;
        state.policy.heap_bound(&mut counter)?;
        Some(counter.bytes)
    }

    #[cfg(test)]
    pub(crate) fn retained_valid_for_test(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.valid)
    }

    #[cfg(test)]
    pub(crate) fn with_state_locked_for_test(&self, check: impl FnOnce()) {
        let _state = self.state.lock().expect("synthetic lifecycle lock");
        check();
    }

    /// Scalar snapshot only: no index/corpus walk, I/O, IDs or body clones.
    pub(crate) fn status(&self) -> ottto_protocol::NativeComparisonStatus {
        let Ok(state) = self.state.try_lock() else {
            return ottto_protocol::NativeComparisonStatus {
                prior_process_debt_unknown: true,
                counts_are_upper_bounds: true,
                ..Default::default()
            };
        };
        let summary = state.published_policy;
        ottto_protocol::NativeComparisonStatus {
            observation_available: true,
            in_flight: state.policy_in_flight,
            deferred_family_count: Some(summary.deferred_families),
            withheld_candidate_count: Some(summary.withheld_candidates),
            withheld_new_local_candidate_count: Some(summary.new_local_candidates),
            oldest_deferred_age_millis: summary
                .first_seen_millis
                .map(|first| process_millis().saturating_sub(first)),
            unknown_age_family_count: summary.baseline_known.then_some(0),
            prior_process_debt_unknown: !summary.baseline_known,
            base_exit_family_count: Some(summary.base_exits),
            process_base_exit: state.admission_refused,
            counts_are_upper_bounds: true,
        }
    }

    pub(crate) fn discard_retained(&self) {
        // Poison may be recovered ONLY to destroy the graph and permission.
        // All lock holders perform bounded state moves, never I/O/callbacks.
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.window = None;
        // Dropping a remembered episode must not renew its per-process bound.
        // Forget the graph under pressure, keep one conservative BASE exit bit.
        state.admission_refused |=
            !state.policy.families.is_empty() || state.published_policy.episode_history;
        state.policy = FamilyPolicyState::default();
        state.published_policy = PolicySummary::default();
        state.policy_in_flight = false;
        state.scope = None;
        state.valid = false;
        state.generation = state.generation.saturating_add(1);
    }
}

impl Lease {
    pub(crate) fn early_evidence_roots(&self) -> impl Iterator<Item = &str> + Clone {
        self.window.as_ref().into_iter().flat_map(|window| {
            window.roots.keys().map(String::as_str).chain(
                window
                    .native_corrections
                    .values()
                    .map(|receipt| receipt.root()),
            )
        })
    }
    #[cfg(test)]
    pub(crate) fn bind(&mut self, scope: String) {
        self.bind_scope(Scope::from_arguments(format_args!("{scope}")));
    }
    pub(crate) fn bind_scope(&mut self, scope: Scope) {
        let same_context = self.previous_scope.as_ref() == Some(&scope);
        if let Ok(mut state) = self.owner.state.lock() {
            if self.generation == Some(state.generation) {
                self.allowed = !state.admission_refused
                    && self.previous_valid
                    && self.previous_scope.as_ref() == Some(&scope);
                state.scope = Some(scope);
                self.scope = Some(scope);
            }
        }
        // A C3 latch survives the intentional BASE page, but never a context
        // reset. It is not a permit and cannot restore any window certificate.
        if !same_context {
            self.policy = FamilyPolicyState::default();
        }
        // No alternate context or generation can later revive the old grant.
        self.previous_scope = None;
        self.previous_valid = false;
        if !self.allowed {
            self.window = None;
        }
        self.publish_policy();
    }

    pub(crate) fn allowed(&self) -> bool {
        self.allowed
            && self.owner.state.lock().is_ok_and(|state| {
                self.generation == Some(state.generation) && self.scope == state.scope
            })
    }

    pub(crate) fn revoke(&mut self) {
        self.allowed = false;
        self.selected_save = false;
        self.native_save = false;
        self.window = None;
    }

    /// A local retention refusal must not repeatedly re-read the same large
    /// target. Conservative BASE for this process lifecycle; no timer, retry
    /// grant or persisted suppression. Ordinary sources remain available.
    pub(crate) fn refuse_admission(&mut self) {
        self.revoke();
        if let Ok(mut state) = self.owner.state.lock() {
            if self.generation == Some(state.generation) {
                state.admission_refused = true;
                state.valid = false;
                state.window = None;
            }
        }
    }

    /// Remove ONLY latched/exited families from negative eligibility. Their
    /// current bodies and native comparison stay on the ordinary BASE path.
    pub(crate) fn family_can_optimize(&self, root: &str) -> bool {
        !self.policy.blocked(root)
    }

    pub(crate) fn apply_family_policy(&self, qualification: &mut Qualification) {
        qualification
            .families
            .retain(|root, _| !self.policy.blocked(root));
        qualification
            .native_corrections
            .retain(|_, receipt| !self.policy.blocked(receipt.root()));
    }

    pub(crate) fn defer_family(
        &mut self,
        root: &str,
        oversized: bool,
        counts: (usize, usize),
        credit: &mut Option<PaidReservation>,
    ) -> Result<bool, LocalRefusal> {
        let generation = self
            .generation
            .ok_or(LocalRefusal("native comparison latch has no process lease"))?;
        let was_blocked = self.policy.blocked(root);
        let decision = self
            .policy
            .decide_paid(root, oversized, counts, generation, credit)?;
        self.policy_hit |= !was_blocked;
        self.publish_policy();
        Ok(decision)
    }

    fn publish_policy(&self) {
        if let Ok(mut state) = self.owner.state.lock() {
            if self.generation == Some(state.generation) && self.scope == state.scope {
                state.published_policy = self.policy.summary();
            }
        }
    }

    /// Read-only page receipt, not evidence for S/ownership. A quiet clear is
    /// deliberately narrower than "comparison finished": the ENTIRE frozen
    /// census must have acquired no native files and then settle durably.
    pub(crate) fn observe_policy_page(&mut self, window: &str, native_files: usize) {
        self.policy.observe_page(window, native_files);
    }

    pub(crate) fn note_policy_settled(&mut self, complete: bool, settled: bool, invalid: bool) {
        if invalid {
            self.policy = FamilyPolicyState::default();
            self.policy_hit = false;
        } else if complete && settled {
            // A terminal selected save reconciles the known candidate debt.
            // It does NOT clear the latch merely because native comparison ran.
            self.policy.baseline_known = true;
            self.policy.reconcile_settled();
            if !self.policy.native_in_window && !self.policy_hit {
                self.policy.clear_quiet();
            }
        }
        self.publish_policy();
    }

    pub(crate) fn take_window(&mut self) -> Option<Box<WindowEligibility>> {
        if !self.allowed() {
            self.window = None;
        }
        self.window.take()
    }

    pub(crate) fn stage_window_after_save(
        &mut self,
        window: Option<Box<WindowEligibility>>,
        index: &super::ScanIndex,
        complete: bool,
    ) {
        self.window = None;
        if self.selected_save && self.allowed() && !complete {
            if let Some(mut window) = window {
                if !window.retain_current(index) {
                    self.revoke();
                    return;
                }
                self.window = Some(window);
            }
            if self.window.as_ref().is_some_and(|window| {
                crate::heap_layout_bound::bound(
                    window.as_ref(),
                    crate::source_rotation::PARKED_BUDGET,
                )
                .is_none()
            }) {
                // This is the existing rotation allowance, not another cache
                // or an alternate layout result. Unknown/pressure loses ALL
                // window history and permission, never a truncated receipt.
                self.revoke();
            }
        }
    }

    /// Call only AFTER the actual selected-index save, from the actual native
    /// conjunction receipt. A known saved bounded page may retain an existing
    /// permit, but cannot mint one. Envelopes/possible hits never mint one.
    pub(crate) fn note_selected_save(&mut self, native_conjunction: bool) {
        self.selected_save = true;
        self.native_save = native_conjunction;
        if let Some(generation) = self.generation {
            self.policy.selected_save(generation);
        }
        self.publish_policy();
    }

    pub(crate) fn finish(mut self, clean: bool) {
        if let Ok(mut state) = self.owner.state.lock() {
            if self.generation == Some(state.generation) && self.scope == state.scope {
                state.valid = !state.admission_refused
                    && clean
                    && self.scope.is_some()
                    && self.selected_save
                    && (self.native_save || self.allowed);
                state.window = if state.valid {
                    self.window.take()
                } else {
                    None
                };
                state.published_policy = self.policy.summary();
                state.policy_in_flight = false;
                state.policy = std::mem::take(&mut self.policy);
            }
        }
        self.finished = true;
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(mut state) = self.owner.state.lock() {
                if self.generation == Some(state.generation) {
                    state.valid = false;
                    state.window = None;
                    // Save/offer failure after C3 still requires the next page
                    // to be BASE. Other abandoned leases revoke all ephemeral
                    // state; their existing durable A rearm is authoritative.
                    state.policy = if self.policy_hit {
                        std::mem::take(&mut self.policy)
                    } else {
                        FamilyPolicyState::default()
                    };
                    state.published_policy = state.policy.summary();
                    state.policy_in_flight = false;
                }
            }
        }
    }
}

#[cfg(test)]
#[test]
fn native_comparison_local_refusal_latches_base_across_pages_and_cache_clear() {
    let owner = Arc::new(Lifecycle::default());
    let mut bootstrap = owner.begin();
    bootstrap.bind("scope".into());
    assert!(!bootstrap.allowed());
    bootstrap.note_selected_save(true); // logical conjunction control only
    bootstrap.finish(true);
    let mut lease = owner.begin();
    lease.bind("scope".into());
    assert!(lease.allowed());
    lease.refuse_admission();
    assert!(!lease.allowed());
    lease.finish(false);
    owner.discard_retained();
    for scope in ["scope", "scope", "another-context"] {
        let mut later = owner.begin();
        later.bind(scope.into());
        assert!(!later.allowed());
        later.note_selected_save(true);
        later.finish(true);
    }
    assert!(!owner.retained_valid_for_test());
    let fresh = Arc::new(Lifecycle::default());
    let mut restarted = fresh.begin();
    restarted.bind("scope".into());
    assert!(!restarted.allowed(), "restart grants no comparison read");
    restarted.finish(false);
}

crate::heap_layout_bound::fields!(Lifecycle; state);
crate::heap_layout_bound::fields!(State; generation, scope, valid, window, admission_refused, policy, published_policy, policy_in_flight);
crate::heap_layout_bound::fields!(Lease; owner, generation, previous_scope, previous_valid, scope, allowed, selected_save, native_save, finished, window, policy, policy_hit);

/// The latch is process-local progress policy, never upload/ownership evidence.
/// Retain the success counter after quiet clear so a proof refresh cannot renew
/// the existing two-successful-deferral bound for this process.
#[derive(Default)]
struct FamilyPolicyState {
    families: Vec<(String, FamilyPolicy)>,
    census: Option<[u8; 32]>,
    native_in_window: bool,
    baseline_known: bool,
}
impl std::fmt::Debug for FamilyPolicyState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FamilyPolicyState")
            .field("family_count", &self.families.len())
            .field("native_in_window", &self.native_in_window)
            .field("baseline_known", &self.baseline_known)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Default)]
struct FamilyPolicy {
    latched: bool,
    base_exit: bool,
    successful_deferrals: u8,
    awaiting_save: Option<u64>,
    deferred_candidates: u64,
    new_local_candidates: u64,
    first_seen_millis: Option<u64>,
}
impl FamilyPolicyState {
    fn blocked(&self, root: &str) -> bool {
        self.families
            .binary_search_by(|(key, _)| key.as_str().cmp(root))
            .ok()
            .is_some_and(|i| self.families[i].1.latched || self.families[i].1.base_exit)
    }
    fn decide_paid(
        &mut self,
        root: &str,
        oversized: bool,
        counts: (usize, usize),
        generation: u64,
        credit: &mut Option<PaidReservation>,
    ) -> Result<bool, LocalRefusal> {
        use crate::heap_layout_bound::{self, Counter, HeapLayoutBound};
        let refusal = LocalRefusal("native comparison family latch cannot be prepaid");
        let position = self
            .families
            .binary_search_by(|(key, _)| key.as_str().cmp(root));
        let i = match position {
            Ok(i) => i,
            Err(i) => {
                let paid = credit.as_mut().ok_or(refusal)?;
                let occupied = paid.allocated();
                let ceiling = paid.allocation_ceiling();
                let before = heap_layout_bound::completed_bound(self, usize::MAX)
                    .and_then(|bytes| bytes.checked_sub(std::mem::size_of_val(self)))
                    .ok_or(refusal)?;
                let mut extra = Counter::new(crate::source_rotation::PARKED_BUDGET);
                let next_capacity = if self.families.len() == self.families.capacity() {
                    let next = if self.families.capacity() == 0 {
                        1
                    } else {
                        self.families.capacity().checked_mul(2).ok_or(refusal)?
                    };
                    extra
                        .add(
                            next.checked_mul(std::mem::size_of::<(String, FamilyPolicy)>())
                                .ok_or(refusal)?,
                        )
                        .ok_or(refusal)?;
                    next
                } else {
                    self.families.capacity()
                };
                extra.add(root.len()).ok_or(refusal)?;
                if !occupied
                    .checked_add(extra.bytes)
                    .is_some_and(|peak| paid.grow_for(peak))
                {
                    return Err(refusal);
                }
                self.families
                    .try_reserve_exact(next_capacity - self.families.len())
                    .map_err(|_| refusal)?;
                self.families
                    .insert(i, (root.to_owned(), FamilyPolicy::default()));
                let mut actual = Counter::new(usize::MAX);
                self.completed_heap_bound(&mut actual).ok_or(refusal)?;
                if !actual
                    .bytes
                    .checked_sub(before)
                    .and_then(|delta| occupied.checked_add(delta))
                    .is_some_and(|owned| paid.record_allocated(owned))
                {
                    return Err(refusal);
                }
                paid.release_temporary_peak(ceiling);
                i
            }
        };
        let family = &mut self.families[i].1;
        if family.latched || family.base_exit {
            return Ok(false);
        }
        family.latched = true;
        if oversized || family.successful_deferrals >= 2 {
            family.base_exit = true;
            return Ok(false);
        }
        family.awaiting_save = Some(generation);
        family.deferred_candidates = counts.0 as u64;
        family.new_local_candidates = counts.1 as u64;
        family.first_seen_millis = Some(process_millis());
        Ok(true)
    }
    fn observe_page(&mut self, window: &str, native_files: usize) {
        let fingerprint = <[u8; 32]>::from(Sha256::digest(window.as_bytes()));
        if self.census != Some(fingerprint) {
            self.census = Some(fingerprint);
            self.native_in_window = false;
        }
        self.native_in_window |= native_files != 0;
    }
    fn selected_save(&mut self, generation: u64) {
        for (_, family) in &mut self.families {
            if family.awaiting_save == Some(generation) {
                family.awaiting_save = None;
                family.successful_deferrals = family.successful_deferrals.saturating_add(1);
                if family.successful_deferrals >= 2 {
                    family.base_exit = true;
                }
            }
        }
    }
    fn reconcile_settled(&mut self) {
        for (_, family) in &mut self.families {
            family.deferred_candidates = 0;
            family.new_local_candidates = 0;
            family.first_seen_millis = None;
        }
    }
    fn summary(&self) -> PolicySummary {
        let mut summary = PolicySummary {
            baseline_known: self.baseline_known,
            episode_history: !self.families.is_empty(),
            ..Default::default()
        };
        for (_, family) in &self.families {
            summary.base_exits += u64::from(family.base_exit);
            if family.deferred_candidates == 0 {
                continue;
            }
            summary.deferred_families += 1;
            summary.withheld_candidates = summary
                .withheld_candidates
                .saturating_add(family.deferred_candidates);
            summary.new_local_candidates = summary
                .new_local_candidates
                .saturating_add(family.new_local_candidates);
            if let Some(first) = family.first_seen_millis {
                summary.first_seen_millis = Some(
                    summary
                        .first_seen_millis
                        .map_or(first, |old| old.min(first)),
                );
            }
        }
        summary
    }
    fn clear_quiet(&mut self) {
        for (_, family) in &mut self.families {
            if !family.base_exit {
                family.latched = false;
                family.awaiting_save = None;
            }
        }
    }
}
#[derive(Debug, Default, Clone, Copy)]
struct PolicySummary {
    deferred_families: u64,
    withheld_candidates: u64,
    new_local_candidates: u64,
    first_seen_millis: Option<u64>,
    base_exits: u64,
    baseline_known: bool,
    episode_history: bool,
}
fn process_millis() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
crate::heap_layout_bound::fields!(FamilyPolicyState; families, census, native_in_window, baseline_known);
crate::heap_layout_bound::fields!(FamilyPolicy; latched, base_exit, successful_deferrals, awaiting_save, deferred_candidates, new_local_candidates, first_seen_millis);
crate::heap_layout_bound::fields!(PolicySummary; deferred_families, withheld_candidates, new_local_candidates, first_seen_millis, base_exits, baseline_known, episode_history);

#[cfg(test)]
#[test]
fn native_comparison_deferred_policy_one_hit_then_base_until_quiet_settled() {
    let expected = Sha256::digest(
        format!(
            "native_comparison:v1:{:?}:destination:context:replay:false:true",
            [7u8; 32]
        )
        .as_bytes(),
    );
    // Pure synchronous formatting spawns no work: thread-local accounting
    // excludes unrelated tests' allocations in parallel hosted runs.
    let (scope, allocated) = crate::retry_allocation_probe::measure(|| {
        Scope::from_arguments(format_args!(
            "native_comparison:v1:{:?}:destination:context:replay:false:true",
            [7u8; 32]
        ))
    });
    assert_eq!(
        scope.digest.as_slice(),
        expected.as_slice(),
        "same original formatted context digest"
    );
    assert_eq!(
        allocated.allocations, 0,
        "scope construction before reservation allocates nothing"
    );
    eprintln!("native_comparison_scope: fixed_bytes=32 streamed_same_digest=true construction_allocations=0 state_lease_copy_no_heap=true");
    fn credit() -> Option<PaidReservation> {
        PaidReservation::from_remainder(Some(crate::source_rotation::PARKED_BUDGET), 0, 0)
    }
    if !crate::heap_layout_bound::layout_supported() {
        let mut policy = FamilyPolicyState::default();
        assert!(policy
            .decide_paid("family", false, (1, 1), 1, &mut credit())
            .is_err());
        assert!(policy.families.is_empty());
        eprintln!(
            "native_comparison_deferred_policy: unsupported_refusal=true positive_latch=UNEXECUTED"
        );
        return;
    }
    let owner = Arc::new(Lifecycle::default());
    let mut first = owner.begin();
    first.bind("scope".into());
    first.observe_policy_page("window1", 1);
    let mut paid = credit();
    assert!(first
        .defer_family("family", false, (1, 1), &mut paid)
        .unwrap());
    assert!(first.policy.blocked("family"));
    let observed = owner.status();
    assert!(observed.observation_available && observed.in_flight);
    assert_eq!(observed.deferred_family_count, Some(1));
    assert_eq!(observed.withheld_candidate_count, Some(1));
    assert_eq!(observed.withheld_new_local_candidate_count, Some(1));
    assert!(observed.oldest_deferred_age_millis.is_some());
    assert!(observed.prior_process_debt_unknown);
    assert_eq!(observed.unknown_age_family_count, None);
    owner.with_state_locked_for_test(|| {
        let unknown = owner.status();
        assert!(!unknown.observation_available);
        assert_eq!(unknown.deferred_family_count, None);
    });
    first.revoke(); // C3 deliberately exits optimization, not its progress latch.
    first.note_selected_save(false);
    first.finish(false);
    for window in ["window2", "window3"] {
        let mut base = owner.begin();
        base.bind("scope".into());
        base.observe_policy_page(window, 1);
        assert!(!base
            .defer_family("family", false, (1, 1), &mut paid)
            .unwrap());
        base.note_policy_settled(true, true, false);
        assert!(
            base.policy.blocked("family"),
            "native comparison alone cannot clear the episode"
        );
        base.note_selected_save(true);
        base.finish(true);
    }
    // A partial or unsettled quiet page cannot clear. Native files on an
    // earlier page of the SAME window also forbid a terminal quiet clear.
    let mut partial = owner.begin();
    partial.bind("scope".into());
    partial.observe_policy_page("window3", 0);
    partial.note_policy_settled(true, true, false);
    assert!(partial.policy.blocked("family"));
    partial.observe_policy_page("quiet", 0);
    partial.note_policy_settled(false, true, false);
    partial.note_policy_settled(true, false, false);
    assert!(partial.policy.blocked("family"));
    partial.finish(false);
    let mut quiet = owner.begin();
    quiet.bind("scope".into());
    quiet.observe_policy_page("quiet", 0);
    quiet.note_policy_settled(true, true, false);
    assert!(!quiet.policy.blocked("family"));
    assert!(quiet
        .defer_family("family", false, (1, 1), &mut paid)
        .unwrap());
    quiet.note_selected_save(false); // Second successful eligible deferral.
    assert!(quiet.policy.families[0].1.base_exit);
    quiet.note_policy_settled(true, true, false);
    assert!(!quiet
        .defer_family("family", false, (1, 1), &mut paid)
        .unwrap());
    assert!(!quiet
        .defer_family("oversized", true, (1, 1), &mut paid)
        .unwrap());
    assert!(quiet.policy.blocked("oversized"));
    quiet.finish(false);
    let exited = owner.status();
    assert_eq!(exited.base_exit_family_count, Some(2));
    owner.discard_retained();
    assert!(owner.status().prior_process_debt_unknown);
    assert!(
        owner.status().process_base_exit,
        "discarded bounded episodes never renew in this process"
    );
    assert_eq!(owner.status().unknown_age_family_count, None);
    let mut reset = owner.begin();
    reset.bind("scope".into());
    assert!(!reset.allowed(), "reset/restart has no optimization grant");
    assert!(reset.policy.families.is_empty());
    reset.finish(false);
    // Save failure keeps the latch, but cannot manufacture a selected save.
    let mut failed_save = owner.begin();
    failed_save.bind("scope".into());
    assert!(failed_save
        .defer_family("save-failure", false, (1, 1), &mut paid)
        .unwrap());
    drop(failed_save);
    let mut next = owner.begin();
    next.bind("scope".into());
    assert!(!next.allowed());
    assert!(!next
        .defer_family("save-failure", false, (1, 1), &mut paid)
        .unwrap());
    assert_eq!(next.policy.families[0].1.successful_deferrals, 0);
    next.finish(false);
    let mut changed = owner.begin();
    changed.bind("different-context".into());
    assert!(changed.policy.families.is_empty());
    changed.finish(false);
    eprintln!("native_comparison_deferred_policy: three_hits=defer,BASE,BASE quiet_unsettled_no_clear=true native_comparison_not_clear=true whole_window_no_native_settled_clear=true success_bound=2 oversized_immediate_BASE=true failed_save_latched=true reset_BASE=true metadata_credit=shared");
}
