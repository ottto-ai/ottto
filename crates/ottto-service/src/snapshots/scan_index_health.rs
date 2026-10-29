//! Content-free, process-local collection posture. Never changes load policy.
use super::{lenient_decode, LoadOrigin, ScanIndex, SnapshotSource};

pub(crate) const CODE: &str = "scan_index_newer_than_app";
pub(crate) const LABEL: &str = "Not collecting: update Ottto";
pub(crate) const DETAIL: &str = "This source is not collecting because its local index needs a newer Ottto. Update Ottto; collection resumes after a compatible index loads. Keep the local index.";

#[derive(Clone, Default)]
struct State {
    since: Option<String>,
    transitions: u64,
}
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct Refusal {
    pub(crate) since: String,
}
#[cfg(not(test))]
fn with_states<T>(f: impl FnOnce(&mut [State; 3]) -> T) -> T {
    static STATES: std::sync::OnceLock<std::sync::Mutex<[State; 3]>> = std::sync::OnceLock::new();
    let mut states = STATES
        .get_or_init(|| std::sync::Mutex::new(std::array::from_fn(|_| State::default())))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut states)
}
#[cfg(test)]
fn with_states<T>(f: impl FnOnce(&mut [State; 3]) -> T) -> T {
    thread_local! {
        static STATES: std::cell::RefCell<[State; 3]> = std::cell::RefCell::new(std::array::from_fn(|_| State::default()));
    }
    STATES.with(|states| f(&mut states.borrow_mut()))
}
fn slot(source: SnapshotSource) -> usize {
    match source {
        SnapshotSource::ClaudeCode => 0,
        SnapshotSource::Codex => 1,
        SnapshotSource::Pi => 2,
    }
}
pub(crate) fn observations() -> [(Option<String>, u64); 3] {
    with_states(|states| std::array::from_fn(|i| (states[i].since.clone(), states[i].transitions)))
}
#[cfg(test)]
pub(crate) fn current(source: SnapshotSource) -> Option<Refusal> {
    with_states(|states| {
        states[slot(source)]
            .since
            .clone()
            .map(|since| Refusal { since })
    })
}
pub(crate) fn is_version_refusal(error: &anyhow::Error) -> bool {
    matches!(error.downcast_ref::<lenient_decode::Error>(),
        Some(lenient_decode::Error::Refused("schema_version" | "accepted-ledger version")))
        // The representation adapter is a separate private component. Its
        // fixed version refusal must survive context wrapping in integration.
        || error.chain().any(|cause| cause.to_string() == "scan_index_representation_refused")
}

pub(super) fn observe(source: SnapshotSource, loaded: &anyhow::Result<(ScanIndex, LoadOrigin)>) {
    let refused = match loaded {
        Ok((_, LoadOrigin::Loaded(_))) => false,
        Err(error) if is_version_refusal(error) => true,
        // Missing/quarantined state and other errors are not a good root load.
        // In particular, a failed read must not hide an existing update blocker.
        _ => return,
    };
    with_states(|states| {
        let state = &mut states[slot(source)];
        if state.since.is_some() == refused {
            return;
        }
        state.since = refused.then(crate::current_rfc3339_timestamp);
        state.transitions = state.transitions.saturating_add(1);
        // One bounded message per state change; no error strings, IDs or paths.
        eprintln!(
            "local source health: source={} reason={} collecting={} transitions={} {}",
            source.api_slug(),
            CODE,
            !refused,
            state.transitions,
            if refused {
                LABEL
            } else {
                "compatible index loaded"
            }
        );
    });
}

#[cfg(test)]
pub(crate) fn transitions(source: SnapshotSource) -> u64 {
    with_states(|states| states[slot(source)].transitions)
}
