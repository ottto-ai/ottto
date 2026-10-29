//! Content-free, process-local collection posture. Never changes load policy.
use super::{lenient_decode, LoadOrigin, ScanIndex, SnapshotSource};

pub(crate) const CODE: &str = "scan_index_newer_than_app";
pub(crate) const LABEL: &str = "Not collecting: update Ottto";
pub(crate) const DETAIL: &str = "This source is not collecting because its local index needs a newer Ottto. Update Ottto; collection resumes after a compatible index loads. Keep the local index.";

pub(crate) const SHARD_CODE: &str = "index_shard_unavailable";
pub(crate) const SHARD_LABEL: &str = "Not collecting: local data needs repair";
pub(crate) const SHARD_DETAIL: &str = "Ottto paused collection for this app because some saved local data is missing or damaged. Don't delete Ottto's data folder. Contact Ottto support to restore it; collection resumes once it's complete.";

#[derive(Clone, Copy)]
pub(crate) enum Reason {
    NewerApp,
    ShardUnavailable,
}
pub(crate) const REASONS: [Reason; 2] = [Reason::NewerApp, Reason::ShardUnavailable];
impl Reason {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::NewerApp => CODE,
            Self::ShardUnavailable => SHARD_CODE,
        }
    }
    pub(crate) fn detail(self) -> &'static str {
        match self {
            Self::NewerApp => DETAIL,
            Self::ShardUnavailable => SHARD_DETAIL,
        }
    }
    pub(crate) fn action(self) -> &'static str {
        match self {
            Self::NewerApp => "update_ottto",
            Self::ShardUnavailable => "contact_support",
        }
    }
    pub(crate) fn from_code(code: &str) -> Option<Self> {
        REASONS.into_iter().find(|reason| reason.code() == code)
    }
    fn offset(self) -> usize {
        match self {
            Self::NewerApp => 0,
            Self::ShardUnavailable => 3,
        }
    }
}

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
fn with_states<T>(f: impl FnOnce(&mut [State; 6]) -> T) -> T {
    static STATES: std::sync::OnceLock<std::sync::Mutex<[State; 6]>> = std::sync::OnceLock::new();
    let mut states = STATES
        .get_or_init(|| std::sync::Mutex::new(std::array::from_fn(|_| State::default())))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut states)
}
#[cfg(test)]
fn with_states<T>(f: impl FnOnce(&mut [State; 6]) -> T) -> T {
    thread_local! {
        static STATES: std::cell::RefCell<[State; 6]> = std::cell::RefCell::new(std::array::from_fn(|_| State::default()));
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
pub(crate) fn observations() -> [[(Option<String>, u64); 3]; 2] {
    with_states(|states| {
        std::array::from_fn(|reason| {
            std::array::from_fn(|source| {
                let state = &states[reason * 3 + source];
                (state.since.clone(), state.transitions)
            })
        })
    })
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
    match loaded {
        Ok((index, LoadOrigin::Loaded(_))) => {
            if index.persistence_available() {
                set(source, Reason::NewerApp, false, 0);
            }
            let unavailable = index
                .persistence_unavailable
                .iter()
                .filter(|v| v.is_some())
                .count();
            set(
                source,
                Reason::ShardUnavailable,
                unavailable != 0,
                unavailable,
            );
        }
        Err(error) if is_version_refusal(error) => set(source, Reason::NewerApp, true, 0),
        // Missing/quarantined state and IO/shape errors cannot prove recovery.
        _ => {}
    }
}
fn set(source: SnapshotSource, reason: Reason, blocked: bool, unavailable: usize) {
    with_states(|states| {
        let state = &mut states[reason.offset() + slot(source)];
        if state.since.is_some() == blocked {
            return;
        }
        state.since = blocked.then(crate::current_rfc3339_timestamp);
        state.transitions = state.transitions.saturating_add(1);
        if blocked && matches!(reason, Reason::ShardUnavailable) {
            // First occurrence of each episode, not each pass/map/cause.
            crate::local_resource_diagnostics::scan_index_shard_alarm(
                source.api_slug(),
                unavailable,
                state.transitions,
            );
        }
        eprintln!(
            "local source health: source={} reason={} collecting={} transitions={} {}",
            source.api_slug(),
            reason.code(),
            !blocked,
            state.transitions,
            if !blocked {
                "compatible index loaded"
            } else {
                match reason {
                    Reason::NewerApp => LABEL,
                    Reason::ShardUnavailable => SHARD_LABEL,
                }
            }
        );
    });
}
#[cfg(test)]
pub(crate) fn shard_transitions(source: SnapshotSource) -> u64 {
    with_states(|states| states[3 + slot(source)].transitions)
}
#[cfg(test)]
pub(crate) fn transitions(source: SnapshotSource) -> u64 {
    with_states(|states| states[slot(source)].transitions)
}
