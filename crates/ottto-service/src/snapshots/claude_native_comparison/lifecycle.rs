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
    pub(crate) fn bind(&mut self, scope: String) {
        if let Ok(mut state) = self.owner.state.lock() {
            if self.generation == Some(state.generation) {
                self.allowed = self.previous_valid && self.previous_scope.as_ref() == Some(&scope);
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
            self.window = window.map(|mut window| {
                window.retain_current(index);
                window
            });
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
                state.valid = clean
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

crate::heap_layout_bound::fields!(Lifecycle; state);
crate::heap_layout_bound::fields!(State; generation, scope, valid, window);
crate::heap_layout_bound::fields!(Lease; owner, generation, previous_scope, previous_valid, scope, allowed, selected_save, native_save, finished, window);
