//! Content-free, process-local collection posture. Never changes load policy.
use super::{lenient_decode, LoadOrigin, ScanIndex, SnapshotSource};

pub(crate) const CODE: &str = "scan_index_newer_than_app";
pub(crate) const LABEL: &str = "Not collecting: update Ottto";
pub(crate) const DETAIL: &str = "This source is not collecting because its local index needs a newer Ottto. Update Ottto; collection resumes after a compatible index loads. Keep the local index.";

pub(crate) const SHARD_CODE: &str = "index_shard_unavailable";
pub(crate) const SHARD_LABEL: &str = "Not collecting: local data needs repair";
pub(crate) const SHARD_DETAIL: &str = "Ottto paused collection for this app because some saved local data is missing or damaged. Don't delete Ottto's data folder. Contact Ottto support to restore it; collection resumes once it's complete.";

/// Fixed diagnostic causes only; these reuse the existing repair surface.
#[derive(Clone, Copy)]
pub(crate) enum RepairCause {
    PriorState,
    StorageGeneration,
    StateV2,
}
impl RepairCause {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::PriorState => "prior_state",
            Self::StorageGeneration => "storage_generation",
            Self::StateV2 => "state_v2",
        }
    }
    fn from_error(error: &anyhow::Error) -> Option<Self> {
        if error
            .downcast_ref::<super::state_v2::Hold>()
            .is_some_and(|cause| {
                !matches!(
                    cause,
                    super::state_v2::Hold::Future | super::state_v2::Hold::NewerSchema
                )
            })
        {
            return Some(Self::StateV2);
        }
        for cause in error.chain() {
            // The loader preserves this typed refusal after the representation
            // adapter fails closed. Do not classify arbitrary IO/shape errors.
            if matches!(
                cause.downcast_ref::<lenient_decode::Error>(),
                Some(lenient_decode::Error::Refused(
                    "storage generation requires repair"
                ))
            ) {
                return Some(Self::StorageGeneration);
            }
            match cause.to_string().as_str() {
                "scan_index_prior_state_requires_repair" => return Some(Self::PriorState),
                "scan_index_storage_generation_requires_repair" => {
                    return Some(Self::StorageGeneration);
                }
                _ => {}
            }
        }
        None
    }
}

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
        || error.chain().any(|cause| matches!(cause.to_string().as_str(), "scan_index_representation_refused" | "state_v2_newer_schema_refused"))
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
        Err(error) => {
            if let Some(cause) = RepairCause::from_error(error) {
                crate::local_resource_diagnostics::scan_index_repair_required(
                    source.api_slug(),
                    cause,
                );
                // The same source blocker and one-per-episode alarm as UNKNOWN.
                // Zero map count: no unavailable shard inventory was loaded.
                set(source, Reason::ShardUnavailable, true, 0);
            }
        }
        // Missing/quarantined state and unrelated errors cannot prove recovery.
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

#[cfg(test)]
mod repair_refusal_tests {
    use super::*;

    #[test]
    fn fixed_repair_causes_share_source_blocker_alarm_once_and_clear_on_good_load() {
        for source in [
            SnapshotSource::ClaudeCode,
            SnapshotSource::Codex,
            SnapshotSource::Pi,
        ] {
            for (label, error) in [
                (
                    "prior_state",
                    anyhow::anyhow!("scan_index_prior_state_requires_repair")
                        .context("opaque context"),
                ),
                (
                    "storage_generation",
                    anyhow::anyhow!("scan_index_storage_generation_requires_repair")
                        .context("opaque context"),
                ),
                (
                    "storage_generation",
                    anyhow::Error::new(lenient_decode::Error::Refused(
                        "storage generation requires repair",
                    ))
                    .context("opaque context"),
                ),
            ] {
                let scratch = crate::test_scratch::private_dir("repair-refusal-health");
                let root = scratch.join("index.json");
                std::fs::write(&root, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
                let good_load = || {
                    ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch)
                        .unwrap()
                };
                good_load();
                let before = observations();
                let failed = Err(error);
                let (_, records) = crate::local_resource_diagnostics::capture(|| {
                    observe(source, &failed);
                    observe(source, &failed);
                });
                let blocked = observations();
                assert!(blocked[1][slot(source)].0.is_some());
                assert_eq!(blocked[1][slot(source)].1, before[1][slot(source)].1 + 1);
                assert_eq!(blocked[0], before[0], "never update-app advice");
                for sibling in 0..3 {
                    if sibling != slot(source) {
                        assert_eq!(blocked[1][sibling], before[1][sibling]);
                    }
                }
                let alarms: Vec<_> = records
                    .iter()
                    .filter(|r| r["counts"]["index_shard_unavailable_alarm"] == 1)
                    .collect();
                assert_eq!(
                    alarms.len(),
                    1,
                    "one alarm per repair episode, not per load"
                );
                assert_eq!(alarms[0]["source"], source.api_slug());
                assert_eq!(alarms[0]["counts"]["unavailable_maps"], 0);
                let counters: Vec<_> = records
                    .iter()
                    .filter(|r| r["counts"].get("scan_index_repair_required").is_some())
                    .collect();
                assert_eq!(counters.len(), 2, "counter continues for each refused load");
                for row in counters {
                    assert_eq!(row["source"], source.api_slug());
                    assert_eq!(row["counts"]["scan_index_repair_required"]["cause"], label);
                    assert_eq!(row["counts"]["scan_index_repair_required"]["delta"], 1);
                    assert_eq!(
                        row["counts"]["scan_index_repair_required"]
                            .as_object()
                            .unwrap()
                            .len(),
                        3
                    );
                }
                let (_, records) = crate::local_resource_diagnostics::capture(|| {
                    good_load();
                });
                assert!(observations()[1][slot(source)].0.is_none());
                assert_eq!(
                    observations()[1][slot(source)].1,
                    before[1][slot(source)].1 + 2
                );
                assert!(records
                    .iter()
                    .all(|r| r["counts"].get("index_shard_unavailable_alarm").is_none()));
                let (_, records) = crate::local_resource_diagnostics::capture(|| {
                    observe(source, &failed);
                });
                assert_eq!(
                    records
                        .iter()
                        .filter(|r| r["counts"]["index_shard_unavailable_alarm"] == 1)
                        .count(),
                    1,
                    "restored then damaged is a new episode"
                );
                good_load();
                std::fs::remove_dir_all(scratch).unwrap();
            }
        }
    }

    #[test]
    fn unrelated_errors_and_code_lookalikes_do_not_create_repair_advice() {
        let source = SnapshotSource::ClaudeCode;
        let before = observations();
        let (_, records) = crate::local_resource_diagnostics::capture(|| {
            for error in [
                anyhow::anyhow!("scan_index_prior_state_requires_repair_extra"),
                anyhow::anyhow!("private/scan_index_prior_state_requires_repair"),
                anyhow::anyhow!("scan_index_storage_generation_requires_repair_extra"),
                anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
                anyhow::Error::new(lenient_decode::Error::Refused("unrelated shape")),
            ] {
                observe(source, &Err(error));
            }
        });
        assert_eq!(observations(), before);
        assert!(records.is_empty());
    }
}
