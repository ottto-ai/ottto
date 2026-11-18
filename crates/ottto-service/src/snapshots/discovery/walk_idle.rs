//! The per-source record that lets a settled source skip repeated walks.
//!
//! A walk that retires cleanly with nothing owed arms one record per source.
//! Until the backstop, `WALK_GAP` after that walk's listing started, a pass
//! whose inputs all still match returns an empty, census-incomplete page
//! instead of walking. A watcher hint, a changed input, due work or a failed
//! pass clears or misses the record, and the pass walks as before. The record
//! lives in process memory only, so a restart always walks.
use crate::agent_status::CodexHomeBinding;
use crate::snapshot_client::ActivityHintResponse;
use crate::snapshots::*;
use crate::transcript_acquisition::{Scope, SourceStamp};
use std::sync::Mutex;

/// The backstop, measured start to start: a settled source walks at least
/// this long after its last walk's listing began, even with no wake.
pub(crate) const WALK_GAP: u64 = LISTING_INTERVAL_SECONDS;
/// Twice the longest cadence interval. A longer gap between passes (sleep,
/// a stalled process, a backward clock) walks.
pub(crate) const PASS_GAP: u64 = 2 * 30 * 60;

/// What one pass's walk would read, captured before the scan reads it.
#[derive(Clone)]
pub(crate) struct Pass {
    key: [u8; 32],
    codex_homes: Vec<Option<SourceStamp>>,
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
    walk_start: Option<Pass>,
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

pub(crate) fn clear(source: SnapshotSource) {
    with_slot(source, |slot| slot.record = None);
}

impl Pass {
    /// Binds the record to what decides a walk's reads: destination scope and
    /// index, roots and window, replay generation, the server's directives
    /// (not its activity counts), upload policy and context, Claude history
    /// policy, Codex logins, and the side inputs no transcript hint carries.
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
        codex_logins: &[CodexHomeBinding],
        index: &ScanIndex,
    ) -> Self {
        let window = effective_backfill_window_days(days);
        let mut digest = Sha256::new();
        let mut add = |bytes: &[u8]| update_length_prefixed(&mut digest, bytes);
        add(scope.0.as_bytes());
        add(index_path.as_os_str().as_encoded_bytes());
        add(scan_traversal_context_fingerprint(source, roots, window).as_bytes());
        add(replay_generation.as_bytes());
        add(&directives(hint));
        add(policy_bytes);
        add(format!(
            "{:?}:{}:{:?}",
            index.active_upload_context_fingerprint,
            index.active_effective_upload_body_witness_revision,
            index.effective_upload_body_witness_revision_excluded_source_files,
        )
        .as_bytes());
        if source == SnapshotSource::ClaudeCode {
            add(format!(
                "{:?}:{:?}:{:?}:{}",
                index.claude_reemission_exclusions,
                index.claude_no_list_policy,
                index.claude_history_cutoff_unix_seconds,
                claude_reemission_stop_latched(),
            )
            .as_bytes());
            add(
                &crate::local_resource_diagnostics::cache_lifecycle::otlp_appended_rows()
                    .to_be_bytes(),
            );
        }
        for login in codex_logins {
            add(format!(
                "{:?}:{:?}:{:?}:{:?}",
                login.home,
                login.account_identifier_hash,
                login.workspace_identifier_hash,
                login.auth_modified_at,
            )
            .as_bytes());
        }
        for dir in crate::launch_events::inbox_dirs(home) {
            let modified = std::fs::metadata(dir).and_then(|meta| meta.modified());
            add(format!("{:?}", modified.ok()).as_bytes());
        }
        add(&crate::snapshot_watcher::sidecar_epoch(source).to_be_bytes());
        let codex_homes = if source == SnapshotSource::Codex {
            let homes = roots
                .iter()
                .filter_map(|root| root.parent())
                .collect::<BTreeSet<_>>();
            homes
                .into_iter()
                .flat_map(|home| {
                    let [state, history, titles] = sources::codex::sidecar::facts::capture(home);
                    let config = SourceStamp::capture_file(&home.join("config.toml")).ok();
                    [state, history, titles, config]
                })
                .collect()
        } else {
            Vec::new()
        };
        Self {
            key: digest.finalize().into(),
            codex_homes,
            days,
            covered: crate::snapshot_watcher::covers(roots),
        }
    }

    /// The same inputs. A stamp that could not be taken either time is
    /// stable (an absent file is a stamp of its own).
    fn same(&self, other: &Self) -> bool {
        self.key == other.key
            && self.codex_homes.len() == other.codex_homes.len()
            && self
                .codex_homes
                .iter()
                .zip(&other.codex_homes)
                .all(|pair| match pair {
                    (Some(a), Some(b)) => a.same(b),
                    (a, b) => a.is_none() && b.is_none(),
                })
    }
}

/// The server's directives and capabilities, without its activity
/// observations (they move on every hint) or the attribution key itself.
fn directives(hint: &ActivityHintResponse) -> Vec<u8> {
    let mut value = serde_json::to_value(hint).expect("activity hint is serializable");
    if let Some(fields) = value.as_object_mut() {
        for field in [
            "server_time",
            "last_data_at",
            "record_count_15m",
            "record_count_24h",
            "recommended_scan_after",
            "session_attribution_hmac_key",
        ] {
            fields.remove(field);
        }
    }
    serde_json::to_vec(&(
        value,
        (hint.workspace_labels_explicit, hint.max_snapshot_item_bytes),
        &hint.claude_otel_only_sessions_contract,
        &hint.claude_otel_only_pairing_floor,
        &hint.claude_otel_only_pairing_ceiling,
        (
            hint.codex_cloud_tasks_enabled,
            &hint.codex_cloud_tasks_contract,
        ),
    ))
    .expect("activity hint is serializable")
}

/// Whether this pass may skip its walk: the armed record still binds every
/// input and the index generation, the backstop is not due, this pass
/// closely follows the last one, the watcher covers the roots, and nothing is
/// owed: `outside_owes_nothing` is the upload ledger's half, `owes_nothing`
/// the index's. The scan re-checks its side inputs before it idles.
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
            slot.walk_start = Some(pass.clone());
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

/// After a successful finish: arm the record when this page retired a clean
/// walk whose inputs did not move while it ran and nothing is owed, or, after
/// an idle pass, follow its own maintenance commits. Either way the record
/// binds the store generation after the pass's last commit.
pub(crate) fn arm_after_finish(
    pass: Pass,
    index: &ScanIndex,
    index_path: &Path,
    scan: &SourceScanResult,
    outside_owes_nothing: bool,
) {
    let generation = store_generation(index, index_path);
    let settled = scan.settled_walk_start.filter(|_| {
        outside_owes_nothing
            && scan.census_complete
            && index.traversal.is_none()
            && !index
                .claude_history_emission
                .files
                .values()
                .any(|gated| gated.held == Some(HistoryHold::TelemetryUnread))
            && owes_nothing(index, pass.days, crate::scan_clock::utc_seconds())
    });
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
        let unchanged = slot
            .walk_start
            .as_ref()
            .is_some_and(|start| start.same(&pass));
        slot.record =
            settled
                .zip(generation)
                .filter(|_| unchanged)
                .map(|(started_at, generation)| Record {
                    pass,
                    generation,
                    started_at,
                });
    });
}

/// The graph generation the next prepare loads: the store's stamp after this
/// pass's last commit, which can follow its save (staged Tail state commits
/// at exit). A stamp another writer moved is not this pass's: `None`.
fn store_generation(index: &ScanIndex, path: &Path) -> Option<u64> {
    if index.v2().persistence_v2.is_none() {
        return Some(index.generation);
    }
    state_v2::confirmed_growth_stamp(index, path)
        .ok()
        .map(|(generation, _)| generation)
}

/// An idle page finishes without a save only while no walk has started since
/// its gate; a finish step can start one (a side-call hint).
pub(crate) fn idle_finish(index: &ScanIndex) -> bool {
    index.traversal.is_none()
}

/// Nothing in the index needs a walk: no unsettled sweep, hold, authority
/// retry, blocking correction or expired growth claim, and no file in the
/// window whose stored stamp the walk's own decision would select. A due
/// sampled audit waits for the backstop walk.
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
    let candidate = CandidateFile {
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
    };
    let (decision, reason) = index.candidate_walk_debt(&candidate, now);
    // A held member owed only a proof correction is skipped by the walk too.
    // A migration is work as well: it rewrites the entry.
    decision != CandidateDecision::Skip
        && !(reason == Some(CandidateParseReason::AuthorityQuarantine)
            && index.claude_authority_correction_only(&candidate)
            && index.effective_upload_body_witness_revision_requires_adoption(key))
}
