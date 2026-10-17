//! Process-only bootstrap, owned by the daemon rather than the disk index or
//! parser cache. Every lease starts fail-closed; errors/drop cannot renew it.
use super::WindowEligibility;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub(crate) struct Lifecycle {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    generation: u64,
    scope: Option<String>,
    valid: bool,
    window: Option<Box<WindowEligibility>>,
    admission_refused: bool,
}

pub(crate) struct Lease {
    owner: Arc<Lifecycle>,
    generation: Option<u64>,
    previous_scope: Option<String>,
    previous_valid: bool,
    scope: Option<String>,
    allowed: bool,
    selected_save: bool,
    native_save: bool,
    finished: bool,
    window: Option<Box<WindowEligibility>>,
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
        };
        if let Ok(mut state) = self.state.lock() {
            lease.previous_valid = state.valid;
            lease.previous_scope = state.scope.take();
            lease.window = state.window.take();
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
        match state.window.as_ref() {
            Some(window) => crate::heap_layout_bound::bound(window, limit),
            None => Some(0),
        }
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

    pub(crate) fn discard_retained(&self) {
        // Poison may be recovered ONLY to destroy the graph and permission.
        // All lock holders perform bounded state moves, never I/O/callbacks.
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.window = None;
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
    pub(crate) fn bind(&mut self, scope: String) {
        if let Ok(mut state) = self.owner.state.lock() {
            if self.generation == Some(state.generation) {
                self.allowed = !state.admission_refused
                    && self.previous_valid
                    && self.previous_scope.as_ref() == Some(&scope);
                state.scope = Some(scope.clone());
                self.scope = Some(scope);
            }
        }
        // No alternate context or generation can later revive the old grant.
        self.previous_scope = None;
        self.previous_valid = false;
        if !self.allowed {
            self.window = None;
        }
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
crate::heap_layout_bound::fields!(State; generation, scope, valid, window, admission_refused);
crate::heap_layout_bound::fields!(Lease; owner, generation, previous_scope, previous_valid, scope, allowed, selected_save, native_save, finished, window);
