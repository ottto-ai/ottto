//! Lets a settled source skip repeated walks: a clean walk arms one in-memory
//! record per source, and until `WALK_GAP` after its first pass a pass whose
//! inputs match returns an empty page. A restart always walks.
use crate::snapshot_client::ActivityHintResponse;
use crate::snapshots::*;
use crate::transcript_acquisition::Scope;
use std::sync::Mutex;

/// The backstop, start to start.
pub(crate) const WALK_GAP: u64 = LISTING_INTERVAL_SECONDS;
/// Twice the longest cadence interval: a longer gap (sleep) walks.
pub(crate) const PASS_GAP: u64 = 2 * crate::snapshot_sync::MAX_CYCLE_INTERVAL.as_secs();

/// What one pass's walk would read, captured before the scan.
#[derive(Clone)]
pub(crate) struct Pass {
    key: [u8; 32],
    days: u64,
    covered: bool,
}

struct Record {
    pass: Pass,
    generation: u64,
    started_at: u64,
}

struct Slot {
    record: Option<Record>,
    /// The inputs and gate-clock time of the pass that began the walk.
    walk_start: Option<(Pass, u64)>,
    last_pass_at: Option<u64>,
}

impl Slot {
    const EMPTY: Self = Self {
        record: None,
        walk_start: None,
        last_pass_at: None,
    };
}

crate::local_resource_diagnostics::process_static!(
    fn with_slots: Mutex<[Slot; 3]> = Mutex::new([const { Slot::EMPTY }; 3])
);

fn with_slot<T>(source: SnapshotSource, run: impl FnOnce(&mut Slot) -> T) -> T {
    with_slots(|slots| {
        run(&mut slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[source.slot()])
    })
}

/// Whether `source` holds an armed record, so its next pass may idle.
pub(crate) fn armed(source: SnapshotSource) -> bool {
    with_slot(source, |slot| slot.record.is_some())
}

pub(crate) fn clear(source: SnapshotSource) {
    with_slot(source, |slot| slot.record = None);
}

impl Pass {
    /// Every input that decides a walk's reads and no hint announces.
    /// Codex home side files (state, thread history, session index, config)
    /// are not inputs: every walk reloads them and applies them to each
    /// rollout it reaches, so a side-only change waits for the next walk.
    #[expect(clippy::too_many_arguments, reason = "the inputs prepare holds")]
    pub(crate) fn new(
        source: SnapshotSource,
        roots: &[PathBuf],
        home: &Path,
        scope: &Scope,
        index_path: &Path,
        days: u64,
        replay_generation: &str,
        hint: &ActivityHintResponse,
        policy_bytes: &[u8],
        index: &ScanIndex,
    ) -> Self {
        let window = effective_backfill_window_days(days);
        let mut digest = Sha256::new();
        let mut add = |bytes: &[u8]| update_length_prefixed(&mut digest, bytes);
        add(scope.0.as_bytes());
        add(index_path.as_os_str().as_encoded_bytes());
        add(super::traversal::scan_traversal_context_fingerprint(source, roots, window).as_bytes());
        add(replay_generation.as_bytes());
        // The hint's volatile counts and its key are not serialized.
        add(&serde_json::to_vec(hint).expect("activity hint is serializable"));
        add(policy_bytes);
        add(format!(
            "{:?}:{}:{:?}:{:?}:{:?}:{:?}",
            index.active_upload_context_fingerprint,
            index.active_effective_upload_body_witness_revision,
            index.effective_upload_body_witness_revision_excluded_source_files,
            index.claude_reemission_exclusions,
            index.claude_no_list_policy,
            index.claude_history_cutoff_unix_seconds,
        )
        .as_bytes());
        if source == SnapshotSource::ClaudeCode {
            // Arrivals, and the drains that make them readable: a row that
            // arrives after the scan-start drain changes the next pass too.
            let (rows, drained) =
                crate::local_resource_diagnostics::cache_lifecycle::otlp_relay_rows();
            add(format!("{}:{rows}:{drained}", claude_reemission_stop_latched()).as_bytes());
        }
        for dir in crate::launch_events::inbox_dirs(home) {
            let modified = std::fs::metadata(dir).and_then(|meta| meta.modified());
            add(format!("{:?}", modified.ok()).as_bytes());
        }
        add(&crate::snapshot_watcher::sidecar_epoch(source).to_be_bytes());
        Self {
            key: digest.finalize().into(),
            days,
            covered: crate::snapshot_watcher::covers(roots),
        }
    }

    fn same(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

/// Whether this pass may skip its walk (the scan re-checks its sidecars).
pub(crate) fn gate(
    source: SnapshotSource,
    pass: &Pass,
    index: &ScanIndex,
    outside_owes_nothing: bool,
    now: u64,
) -> bool {
    with_slot(source, |slot| {
        let previous = slot.last_pass_at.replace(now);
        let walking = index.traversal.is_some();
        if !walking {
            slot.walk_start = Some((pass.clone(), now));
        }
        let idle = !walking
            && pass.covered
            && outside_owes_nothing
            && previous.is_some_and(|at| at <= now && now - at <= PASS_GAP)
            && slot.record.as_ref().is_some_and(|record| {
                record.pass.same(pass)
                    && record.generation == index.generation
                    && (record.started_at..record.started_at.saturating_add(WALK_GAP))
                        .contains(&now)
            })
            && owes_nothing(index, pass.days, now);
        if !idle {
            slot.record = None;
        }
        idle
    })
}

/// After a successful finish: arm on a clean walk whose inputs held still.
pub(crate) fn arm_after_finish(
    pass: Pass,
    index: &ScanIndex,
    index_path: &Path,
    scan: &SourceScanResult,
    outside_owes_nothing: bool,
) {
    let generation = store_generation(index, index_path);
    let settled = scan.settled_walk
        && outside_owes_nothing
        && index.traversal.is_none()
        && !index
            .claude_history_emission
            .files
            .values()
            .any(|gated| gated.held == Some(HistoryHold::TelemetryUnread))
        && owes_nothing(index, pass.days, crate::scan_clock::utc_seconds());
    with_slot(scan.source, |slot| {
        if scan.walk_idle {
            let record = slot
                .record
                .as_mut()
                .filter(|record| record.pass.same(&pass));
            if let Some((record, generation)) = record.zip(generation) {
                record.generation = generation;
            }
            return;
        }
        // The backstop runs from the walk's first pass, on the gate's clock.
        let started = (slot.walk_start.as_ref())
            .filter(|(start, _)| settled && start.same(&pass))
            .map(|&(_, at)| at);
        slot.record = started
            .zip(generation)
            .map(|(started_at, generation)| Record {
                pass,
                generation,
                started_at,
            });
    });
}

/// The generation the next prepare loads, after this pass's last commit (the
/// exit Tail commit follows the save). Another writer's stamp is `None`.
fn store_generation(index: &ScanIndex, path: &Path) -> Option<u64> {
    if index.v2().persistence_v2.is_none() {
        return Some(index.generation);
    }
    state_v2::confirmed_growth_stamp(index, path)
        .ok()
        .map(|(generation, _)| generation)
}

/// An idle page finishes without a save only while no walk has started.
pub(crate) fn idle_finish(index: &ScanIndex) -> bool {
    index.traversal.is_none()
}

/// Nothing in the index needs a walk (a due audit waits for the backstop).
pub(in crate::snapshots) fn owes_nothing(index: &ScanIndex, days: u64, now: u64) -> bool {
    index.persistence_available()
        && !index.bounded_sweep_had_unsettled_upload
        && index.decode_holds.is_empty()
        && index.claude_account_deferred_holds.is_empty()
        && !index
            .claude_usage_authority_quarantine
            .values()
            .any(|record| {
                record.disposition == ClaudeUsageAuthorityQuarantineDisposition::RetryPending
            })
        && !index.claude_authority_proof_correction_blocking().0
        && !sampled_audit::growth_claim_expired(index, now)
        && !index.files.iter().any(|(key, entry)| {
            is_recent_enough_at(entry.modified_unix_seconds, now, days)
                && stored_stamp_selects(index, key, entry, now)
        })
}

/// The walk's candidate decision for a file whose stamp has not moved.
pub(in crate::snapshots) fn stored_stamp_selects(
    index: &ScanIndex,
    key: &str,
    entry: &ScanIndexEntry,
    now: u64,
) -> bool {
    let candidate = stored_candidate(key, entry);
    let (decision, reason) = index.candidate_walk_debt(&candidate, now);
    // The walk skips a held member owed only a proof correction.
    decision != CandidateDecision::Skip
        && !(reason == Some(CandidateParseReason::AuthorityQuarantine)
            && index.claude_authority_correction_only(&candidate)
            && index.effective_upload_body_witness_revision_requires_adoption(key))
}

fn stored_candidate(key: &str, entry: &ScanIndexEntry) -> CandidateFile {
    CandidateFile {
        path: PathBuf::from(key),
        scan_root: PathBuf::new(),
        physical_identity: None,
        size_bytes: entry.size_bytes,
        modified_unix_seconds: entry.modified_unix_seconds,
        modified_unix_nanos: entry.modified_unix_nanos.unwrap_or_default(),
        source_file_fingerprint: entry.source_file_fingerprint.clone(),
        legacy_source_file_fingerprint: entry.source_file_fingerprint.clone(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: entry.opened_changed_nanos,
        fingerprint_birth_nanos: entry.opened_birth_nanos,
        withheld_content_stamp: None,
    }
}

/// A simulated process start: every source's record and clocks are gone.
#[cfg(test)]
pub(crate) fn restart_for_test() {
    with_slots(|slots| {
        *slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = [const { Slot::EMPTY }; 3];
    });
}

/// The armed record's (generation, walk start), if any.
#[cfg(test)]
pub(crate) fn armed_for_test(source: SnapshotSource) -> Option<(u64, u64)> {
    with_slot(source, |slot| {
        (slot.record.as_ref()).map(|record| (record.generation, record.started_at))
    })
}

/// An armed record, as a settled walk leaves one (lane clears drop it).
#[cfg(test)]
pub(crate) fn arm_for_test(source: SnapshotSource) {
    let pass = Pass {
        key: [0; 32],
        days: 0,
        covered: true,
    };
    with_slot(source, |slot| {
        slot.record = Some(Record {
            pass,
            generation: 0,
            started_at: 0,
        });
    });
}

/// As if `seconds` went by since this thread's last pass and armed walk.
#[cfg(test)]
pub(crate) fn age_for_test(source: SnapshotSource, seconds: u64) {
    with_slot(source, |slot| {
        if let Some(record) = slot.record.as_mut() {
            record.started_at -= seconds;
        }
        if let Some(at) = slot.last_pass_at.as_mut() {
            *at -= seconds;
        }
    });
}

/// Starts a walk in `index`, as a page that began one would.
#[cfg(test)]
pub(crate) fn start_walk_for_test(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
) {
    ensure_bounded_traversal(source, roots, index, "2026-11-01T10:00:00Z", 183);
    assert!(!idle_finish(index));
}

#[cfg(test)]
mod tests;
