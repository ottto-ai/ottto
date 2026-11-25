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

/// The gate key's inputs, in key order: a `walk_gate` point names the first
/// one that differs.
const KEY_PARTS: [&str; 10] = [
    "scope",
    "index_path",
    "context",
    "replay",
    "hint",
    "policy",
    "upload_context",
    "telemetry",
    "launch_inbox",
    "sidecar_epoch",
];

/// What one pass's walk would read, captured before the scan.
#[derive(Clone)]
pub(crate) struct Pass {
    key: [u8; 32],
    /// A short digest of each of `KEY_PARTS`, for the diagnostic only.
    parts: [u64; KEY_PARTS.len()],
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
    /// Why the record was last dropped outside the gate (`clear`).
    cleared: Option<&'static str>,
}

impl Slot {
    const EMPTY: Self = Self {
        record: None,
        walk_start: None,
        last_pass_at: None,
        cleared: None,
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

/// Drops the record; `reason` names the next walk-start pass's `rest_veto`.
pub(crate) fn clear(source: SnapshotSource, reason: &'static str) {
    with_slot(source, |slot| {
        if slot.record.take().is_some() {
            slot.cleared = Some(reason);
        }
    });
}

/// One counts-only `walk_gate` point: `rest_veto` on a pass that starts a walk
/// instead of resting, `arm` when a walk retires.
fn report(source: SnapshotSource, field: &str, value: &str) {
    crate::local_resource_diagnostics::traversal_point(
        "walk_gate",
        source.api_slug(),
        &serde_json::json!({ field: value }),
    );
}

/// The health check in the scan refused a rest the gate allowed.
pub(crate) fn report_health_veto(source: SnapshotSource) {
    report(source, "rest_veto", "health");
}

/// A finish that retires a walk but exits before arming (`why`) still
/// reports `arm`.
pub(crate) fn report_retired_unarmed(source: SnapshotSource, index: &ScanIndex, why: &str) {
    if index.traversal.is_none() {
        report(source, "arm", &format!("not:{why}"));
    }
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
        let mut parts = [0_u64; KEY_PARTS.len()];
        let mut add = |part: usize, bytes: &[u8]| {
            update_length_prefixed(&mut digest, bytes);
            let mut fold = Sha256::new();
            fold.update(parts[part].to_be_bytes());
            fold.update(bytes);
            parts[part] = u64::from_be_bytes(fold.finalize()[..8].try_into().expect("8 bytes"));
        };
        add(0, scope.0.as_bytes());
        add(1, index_path.as_os_str().as_encoded_bytes());
        add(
            2,
            super::traversal::scan_traversal_context_fingerprint(source, roots, window).as_bytes(),
        );
        add(3, replay_generation.as_bytes());
        // The hint's volatile counts and its key are not serialized.
        add(
            4,
            &serde_json::to_vec(hint).expect("activity hint is serializable"),
        );
        add(5, policy_bytes);
        add(
            6,
            format!(
                "{:?}:{}:{:?}:{:?}:{:?}:{:?}",
                index.active_upload_context_fingerprint,
                index.active_effective_upload_body_witness_revision,
                index.effective_upload_body_witness_revision_excluded_source_files,
                index.claude_reemission_exclusions,
                index.claude_no_list_policy,
                index.claude_history_cutoff_unix_seconds,
            )
            .as_bytes(),
        );
        if source == SnapshotSource::ClaudeCode {
            // Arrivals, and the drains that make them readable: a row that
            // arrives after the scan-start drain changes the next pass too.
            let (rows, drained) =
                crate::local_resource_diagnostics::cache_lifecycle::otlp_relay_rows();
            add(
                7,
                format!("{}:{rows}:{drained}", claude_reemission_stop_latched()).as_bytes(),
            );
        }
        for dir in crate::launch_events::inbox_dirs(home) {
            let modified = std::fs::metadata(dir).and_then(|meta| meta.modified());
            add(8, format!("{:?}", modified.ok()).as_bytes());
        }
        add(
            9,
            &crate::snapshot_watcher::sidecar_epoch(source).to_be_bytes(),
        );
        Self {
            key: digest.finalize().into(),
            parts,
            days,
            covered: crate::snapshot_watcher::covers(roots),
        }
    }

    fn same(&self, other: &Self) -> bool {
        self.key == other.key
    }

    /// The first key input that differs from `other`'s.
    fn differs(&self, other: &Self) -> &'static str {
        (self.parts.iter().zip(&other.parts))
            .position(|(a, b)| a != b)
            .map_or("unknown", |part| KEY_PARTS[part])
    }
}

/// Whether this pass may skip its walk (the scan re-checks its sidecars).
/// `outside_owes` names upload or cycle work that needs a walk. A pass that
/// starts a walk reports its first failing condition as `rest_veto`.
pub(crate) fn gate(
    source: SnapshotSource,
    pass: &Pass,
    index: &ScanIndex,
    outside_owes: Option<&'static str>,
    now: u64,
) -> bool {
    let veto = with_slot(source, |slot| {
        let previous = slot.last_pass_at.replace(now);
        if index.traversal.is_some() {
            slot.record = None;
            return None;
        }
        slot.walk_start = Some((pass.clone(), now));
        let veto = if !pass.covered {
            Some("uncovered".to_owned())
        } else if let Some(owed) = outside_owes {
            Some(format!("upload:{owed}"))
        } else if !previous.is_some_and(|at| at <= now && now - at <= PASS_GAP) {
            Some("gap".to_owned())
        } else if let Some(record) = slot.record.as_ref() {
            if !record.pass.same(pass) {
                Some(format!("key:{}", record.pass.differs(pass)))
            } else if record.generation != index.generation {
                Some("generation".to_owned())
            } else if !(record.started_at..record.started_at.saturating_add(WALK_GAP))
                .contains(&now)
            {
                Some("backstop".to_owned())
            } else {
                owes(index, pass.days, now).map(|owed| format!("owes:{owed}"))
            }
        } else {
            Some(
                slot.cleared
                    .map_or("no_record".to_owned(), |why| format!("cleared:{why}")),
            )
        };
        if veto.is_some() {
            slot.record = None;
            slot.cleared = None;
        }
        Some(veto)
    });
    match veto {
        Some(Some(veto)) => {
            report(source, "rest_veto", &veto);
            false
        }
        Some(None) => true,
        None => false,
    }
}

/// After a successful finish: arm on a clean walk whose inputs held still.
/// A finish that retires a walk reports `arm`: `armed`, or why not.
pub(crate) fn arm_after_finish(
    pass: Pass,
    index: &ScanIndex,
    index_path: &Path,
    scan: &SourceScanResult,
    outside_owes_nothing: bool,
) {
    let generation = store_generation(index, index_path);
    let unsettled = if !scan.settled_walk {
        Some("unsettled".to_owned())
    } else if !outside_owes_nothing {
        Some("upload".to_owned())
    } else if index.traversal.is_some() {
        Some("walking".to_owned())
    } else if index
        .claude_history_emission
        .files
        .values()
        .any(|gated| gated.held == Some(HistoryHold::TelemetryUnread))
    {
        Some("telemetry_unread".to_owned())
    } else {
        owes(index, pass.days, crate::scan_clock::utc_seconds()).map(|owed| format!("owes:{owed}"))
    };
    let reported = with_slot(scan.source, |slot| {
        if scan.walk_idle {
            let record = slot
                .record
                .as_mut()
                .filter(|record| record.pass.same(&pass));
            if let Some((record, generation)) = record.zip(generation) {
                record.generation = generation;
            }
            return None;
        }
        // The backstop runs from the walk's first pass, on the gate's clock.
        let outcome = match (unsettled, slot.walk_start.as_ref(), generation) {
            (Some(why), _, _) => Err(why),
            (None, None, _) => Err("no_start".to_owned()),
            (None, Some((start, _)), _) if !start.same(&pass) => {
                Err(format!("key:{}", start.differs(&pass)))
            }
            (None, Some(_), None) => Err("generation".to_owned()),
            (None, Some(&(_, started_at)), Some(generation)) => Ok((started_at, generation)),
        };
        let value = outcome
            .as_ref()
            .map_or_else(|why| format!("not:{why}"), |_| "armed".to_owned());
        slot.record = outcome.ok().map(|(started_at, generation)| Record {
            pass,
            generation,
            started_at,
        });
        if slot.record.is_some() {
            slot.cleared = None;
        }
        index.traversal.is_none().then_some(value)
    });
    if let Some(value) = reported {
        report(scan.source, "arm", &value);
    }
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

/// The first kind of index debt that needs a walk, if any (a due audit waits
/// for the backstop).
fn owes(index: &ScanIndex, days: u64, now: u64) -> Option<&'static str> {
    if !index.persistence_available() {
        Some("persistence")
    } else if index.bounded_sweep_had_unsettled_upload {
        Some("unsettled_upload")
    } else if !index.decode_holds.is_empty() {
        Some("decode_hold")
    } else if !index.claude_account_deferred_holds.is_empty() {
        Some("account_hold")
    } else if index
        .claude_usage_authority_quarantine
        .values()
        .any(|record| record.disposition == ClaudeUsageAuthorityQuarantineDisposition::RetryPending)
    {
        Some("authority_quarantine")
    } else if index.claude_authority_proof_correction_blocking().0 {
        Some("authority_correction")
    } else if sampled_audit::growth_claim_expired(index, now) {
        Some("growth_claim")
    } else if index.files.iter().any(|(key, entry)| {
        is_recent_enough_at(entry.modified_unix_seconds, now, days)
            && stored_stamp_selects(index, key, entry, now)
    }) {
        Some("file_debt")
    } else {
        None
    }
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
        parts: [0; KEY_PARTS.len()],
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
