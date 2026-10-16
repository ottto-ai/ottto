//! Process-only bootstrap, owned by the daemon rather than the disk index or
//! parser cache. Every lease starts fail-closed; errors/drop cannot renew it.
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
}

pub(crate) struct Lease {
    owner: Arc<Lifecycle>,
    generation: Option<u64>,
    previous_scope: Option<String>,
    previous_valid: bool,
    scope: Option<String>,
    allowed: bool,
    native_save: bool,
    finished: bool,
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
            native_save: false,
            finished: false,
        };
        if let Ok(mut state) = self.state.lock() {
            lease.previous_valid = state.valid;
            lease.previous_scope = state.scope.take();
            state.valid = false;
            if let Some(next) = state.generation.checked_add(1) {
                state.generation = next;
                lease.generation = Some(next);
            }
        }
        lease
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
    }

    pub(crate) fn allowed(&self) -> bool {
        self.allowed
            && self.owner.state.lock().is_ok_and(|state| {
                self.generation == Some(state.generation) && self.scope == state.scope
            })
    }

    pub(crate) fn revoke(&mut self) {
        self.allowed = false;
        self.native_save = false;
    }

    /// Call only AFTER the actual selected-index save, from the actual native
    /// conjunction receipt. Envelopes/possible hits never produce this input.
    pub(crate) fn note_native_save(&mut self, native_conjunction: bool) {
        self.native_save = native_conjunction;
    }

    pub(crate) fn finish(mut self, clean: bool) {
        if let Ok(mut state) = self.owner.state.lock() {
            if self.generation == Some(state.generation) && self.scope == state.scope {
                state.valid = clean && self.scope.is_some() && (self.native_save || self.allowed);
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
                }
            }
        }
    }
}

crate::heap_layout_bound::fields!(Lifecycle; state);
crate::heap_layout_bound::fields!(State; generation, scope, valid);
crate::heap_layout_bound::fields!(Lease; owner, generation, previous_scope, previous_valid, scope, allowed, native_save, finished);
