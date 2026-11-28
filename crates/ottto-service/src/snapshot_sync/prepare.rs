//! move snapshot prepare into prepare.

use super::anyhow;

use super::claude_contract;

use super::continuation;
use super::current_historical_replay;
use super::current_rfc3339;
use super::current_unix_seconds;

use super::load_backfill_state;

use super::reason_reoffer;
use super::record_server_scan_directive;
use super::rfc3339_after_minutes;
use super::safe_error;

use super::scan_request_window_days;
use super::small_source_upload;
use super::snapshot_destination_scoped_index_path;
use super::snapshot_index_path;
use super::snapshot_upload_context_fingerprint;
use super::snapshot_upload_destination_namespace;
use super::snapshot_upload_progress_path;
use super::snapshot_v3_index_path;
use super::source_cadence_wait;
use super::source_kind;
use super::source_paced_due;
use super::source_upload_backoff_remaining;
use super::stale_owed;
#[cfg(test)]
use super::tests;
use super::upload_agent_status;
use super::validated_receipt_window_days;
use super::with_source_cadence;
use super::with_source_cadence_state;
use super::withdraw_and_report_policy_stop;
use super::AgentStatusCollection;
use super::BTreeSet;
use super::CollectorState;
use super::CollectorStatus;
#[cfg(test)]
use super::Context;
#[cfg(not(test))]
use super::Context as _;
use super::Digest;
#[cfg(test)]
use super::Duration;
use super::Instant;
use super::LocalDaemon;
use super::LocalDeviceBinding;
use super::Path;
use super::PathBuf;
use super::PlatformGates;
use super::Result;
use super::ScanIndex;
use super::SessionAttributionContext;
use super::Sha256;
use super::SnapshotApiClient;
use super::SnapshotProgressLock;
use super::SnapshotQuarantineWitness;
use super::SnapshotSource;
use super::SnapshotUploadPolicy;
use super::SnapshotUploadProgress;
use super::SourceScanResult;
use super::SyncCounts;
use super::UploadShed;
use super::Zeroize;
use super::AGENT_STATUS_SNAPSHOT_TTL_MINUTES;
use super::MAX_BACKFILL_FILES_PER_SOURCE;
use super::MAX_CYCLE_INTERVAL;
use super::SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE;
use super::SNAPSHOT_SYNC_INTERVAL;

use super::pending_backfill_sources_for_destination;
use super::upload_context_resend;
use super::SnapshotItem;
use super::SnapshotQuarantineDisposition;
use super::MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;

// Pinned with the replay strings in `backfill.rs`: a compiled history revision never
// triggers a re-read of existing history; new meaning ships forward via a rule epoch.
// Changing a pinned value needs owner approval (pin test: `history_revisions_are_pinned`).
pub(crate) const fn effective_upload_body_witness_revision(source: SnapshotSource) -> u64 {
    match source {
        SnapshotSource::ClaudeCode => 3,
        SnapshotSource::Codex | SnapshotSource::Pi => 1,
    }
}

// A Claude revision the history gate is not complete for does not
// build. Raise `MAX_GATED_CLAUDE_REVISION` only with its complete policy row.
const _: () = assert!(
    effective_upload_body_witness_revision(SnapshotSource::ClaudeCode)
        <= crate::snapshots::MAX_GATED_CLAUDE_REVISION
);

/// The revision a sync cycle activates: the compiled one.
pub(super) fn cycle_body_witness_revision(source: SnapshotSource) -> u64 {
    effective_upload_body_witness_revision(source)
}

/// Where this destination's Claude prior history comes from. A fresh install
/// is only a positively empty support state.
/// - `Unverified`: the backfill state is unreadable.
/// - `Here`: this destination's completed bootstrap; a server-attested record
///   in its upload ledger (an accepted, quarantined or refused body or
///   accepted cache evidence; a generation or replay claim alone is saved
///   before any upload, so it is not evidence); a quarantined (`.corrupt.`)
///   sibling of this index; or the re-emission seen-marker. Also, when the
///   history is not `Moved`, an unscoped pre-scoping `claude_code-scan-index*`
///   beside `destinations/`: it names no destination, so it
///   is not a move, but this Mac did index history, so a cutoff keeps that
///   history owed, list-gated and paced instead of resent ungated.
/// - `Moved`: only a Claude bootstrap completed for another destination or
///   recorded by a legacy state, or a Claude index, ledger or quarantined
///   copy another destination's directory holds (an interrupted bootstrap
///   before a re-pair). A leftover is another destination only when it sits
///   under a different namespace; unless a claim
///   recorded a different-user cutoff, which keeps that history excluded by
///   the cutoff, as before.
///
/// Read before scanning; none of it lives in the index, so it survives index
/// loss (fail closed).
pub(super) fn claude_prior_history(
    backfill_state: &crate::backfill::BackfillState,
    destination_namespace: &str,
    upload_progress: &SnapshotUploadProgress,
    index_path: &Path,
    support_dir: &Path,
) -> crate::snapshots::PriorHistory {
    use crate::snapshots::PriorHistory;
    if backfill_state.prior_history_unverified {
        return PriorHistory::Unverified;
    }
    let slug = SnapshotSource::ClaudeCode.api_slug();
    // Only a different namespace's directory is another destination. An
    // unscoped legacy `claude_code-scan-index*` beside `destinations/` names
    // no destination; it is usually this Mac's own pre-scoping index, so it
    // must not hold history as a move (I-r3-1). It is `Here` evidence below.
    let other_destination = || {
        let prefix = format!("{slug}-scan-index");
        let own = index_path.parent();
        let holds_claude_state =
            |directory: &Path| Some(directory) != own && dir_holds_prefixed(directory, &prefix);
        match std::fs::read_dir(support_dir.join("snapshots").join("destinations")) {
            Ok(mut destinations) => destinations.any(|destination| match destination {
                Ok(destination) => holds_claude_state(&destination.path()),
                Err(_) => true,
            }),
            Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        }
    };
    // Fails closed: only a positively missing marker is absent.
    let seen_marker = || match std::fs::symlink_metadata(
        crate::snapshots::claude_reemission_seen_marker_path(support_dir),
    ) {
        Ok(_) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    };
    if claude_destination_history_here(
        backfill_state,
        destination_namespace,
        upload_progress,
        index_path,
    ) || seen_marker()
    {
        return PriorHistory::Here;
    }
    // A claim that recorded a different-user cutoff keeps the other
    // destinations' history excluded by that cutoff, not by the gate, but
    // only on that claim's own destination: a later same-user re-claim keeps
    // the cutoff on a new destination.
    let other_user_cutoff = backfill_state.backfill_cutoff_at.is_some()
        && backfill_state
            .backfill_cutoff_destination_namespace
            .as_deref()
            == Some(destination_namespace);
    // Claude's own entries only: `last_completed_at` is stamped by any
    // source's bootstrap, so a Codex or Pi completion is not Claude history.
    let earlier_bootstrap = backfill_state
        .completed_destination_replays
        .contains_key(slug)
        || backfill_state
            .completed_destination_namespaces
            .contains_key(slug)
        || backfill_state.completed_parser_versions.contains_key(slug)
        || backfill_state.completed_replay_revisions.contains_key(slug);
    // A pre-scoping daemon's unscoped index.
    let unscoped_legacy_index = || {
        dir_holds_prefixed(
            &support_dir.join("snapshots"),
            &format!("{slug}-scan-index"),
        )
    };
    if !other_user_cutoff && (earlier_bootstrap || other_destination()) {
        PriorHistory::Moved
    } else if unscoped_legacy_index() {
        PriorHistory::Here
    } else {
        PriorHistory::None
    }
}

/// Evidence belongs to this destination, independent of the Mac-wide marker.
pub(super) fn claude_destination_history_here(
    backfill_state: &crate::backfill::BackfillState,
    destination_namespace: &str,
    upload_progress: &SnapshotUploadProgress,
    index_path: &Path,
) -> bool {
    let slug = SnapshotSource::ClaudeCode.api_slug();
    let here = backfill_state.destination_completed(slug, destination_namespace);
    // A quarantined copy of this index, of a legacy index or of this
    // destination's ledger. An unreadable directory fails closed; a missing
    // one is empty.
    let quarantined_sibling = || {
        let own_stem = index_path.file_stem().and_then(|stem| stem.to_str());
        let claude_prefix = format!("{slug}-scan-index");
        let Some(parent) = index_path.parent() else {
            return false;
        };
        match std::fs::read_dir(parent) {
            Ok(mut entries) => entries.any(|entry| match entry {
                Ok(entry) => entry.file_name().to_str().is_some_and(|name| {
                    name.contains(".corrupt.")
                        && (own_stem.is_some_and(|stem| name.starts_with(stem))
                            || name.starts_with(&claude_prefix))
                }),
                Err(_) => true,
            }),
            Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        }
    };
    here || upload_progress.records_server_attested_upload() || quarantined_sibling()
}

/// Narrow the corruption stop to loss of this destination's own history.
pub(super) fn note_claude_index_rebuild_for_destination(
    source: SnapshotSource,
    loaded_fresh: bool,
    backfill_state: &crate::backfill::BackfillState,
    destination_namespace: &str,
    upload_progress: &SnapshotUploadProgress,
    index_path: &Path,
    support_dir: &Path,
) {
    if source == SnapshotSource::ClaudeCode
        && loaded_fresh
        && claude_destination_history_here(
            backfill_state,
            destination_namespace,
            upload_progress,
            index_path,
        )
    {
        crate::snapshots::note_claude_index_rebuild_stop(support_dir);
    }
}

/// True when `directory` holds an entry named `{prefix}*`. An unreadable
/// directory or entry fails closed; a missing directory is empty.
pub(super) fn dir_holds_prefixed(directory: &Path, prefix: &str) -> bool {
    match std::fs::read_dir(directory) {
        Ok(mut entries) => entries.any(|entry| match entry {
            Ok(entry) => entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(prefix)),
            Err(_) => true,
        }),
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Claude only, before scanning: with prior history, a fresh index (missing
/// or quarantined), a replay that dropped entries or the first gated load of
/// an index without one records the history cutoff; see
/// `ScanIndex::note_claude_history_cutoff`.
pub(super) fn note_claude_history_cutoff_for_cycle(
    index: &mut ScanIndex,
    source: SnapshotSource,
    prior_history: crate::snapshots::PriorHistory,
    backfill_state: &crate::backfill::BackfillState,
    entries_lost: bool,
) {
    if source != SnapshotSource::ClaudeCode {
        return;
    }
    index.note_claude_history_cutoff(
        prior_history,
        backfill_state.claim_backfill_policy_full,
        entries_lost,
    );
}

/// Whether the source's bootstrap for this destination is pending, which arms
/// its historical replay (StateMissing H1, N2).
pub(super) fn backfill_replay_pending(
    source: SnapshotSource,
    backfill_state: &crate::backfill::BackfillState,
    destination_namespace: &str,
) -> bool {
    pending_backfill_sources_for_destination(backfill_state, destination_namespace)
        .contains(&source)
}

/// This source's first import for the destination is pending and no other
/// granted source's is: the same bootstrap predicate finish uses, so a replay
/// of a completed destination is not a first import. While another source
/// also imports, the shared sync thread keeps ordinary page sizes. A source
/// the device does not grant never syncs, so it never imports.
pub(super) fn first_import_alone(
    source: SnapshotSource,
    device: &LocalDeviceBinding,
    backfill_state: &crate::backfill::BackfillState,
    destination_namespace: &str,
) -> bool {
    let importing = |candidate| {
        crate::backfill::bootstrap_pending_for_destination(
            backfill_state,
            candidate,
            destination_namespace,
        )
    };
    importing(source)
        && super::lane::SNAPSHOT_SOURCES
            .into_iter()
            .filter(|other| *other != source && super::lane::source_granted(device, *other))
            .all(|other| !importing(other))
}

/// Claude only: the unreadable backfill state suppresses replays until a
/// Claude census under the history gate clears it (N2).
pub(super) fn claude_replay_suppressed(
    source: SnapshotSource,
    backfill_state: &crate::backfill::BackfillState,
) -> bool {
    source == SnapshotSource::ClaudeCode && backfill_state.prior_history_unverified
}

pub(super) fn exclude_held_effective_body_witness_revision(
    index: &mut ScanIndex,
    items: &[SnapshotItem],
    disposition: &crate::snapshots::ClaudeUsageAuthorityDisposition,
) {
    let held = disposition.quarantined_fingerprints(items);
    let source_files = items
        .iter()
        .filter(|item| held.contains(&item.snapshot_fingerprint))
        .filter_map(|item| item.source_file_fingerprint.clone())
        .collect();
    index.exclude_effective_upload_body_witness_revision_for_source_files(&source_files);
}

// Preparation stays owned by the existing cycle. No partially finalized body
// crosses a collection step.
pub(super) struct SourcePreparation {
    pub(super) source: SnapshotSource,
    /// Walk-gate inputs, and whether the cycle's own state owed no walk.
    pub(super) walk_idle_pass: Option<(crate::snapshots::walk_idle::Pass, bool)>,
    pub(super) claude_scan_roots: Option<Vec<PathBuf>>,
    pub(super) account_witness: [u8; 32],
    pub(super) scan_started_at: String,
    pub(super) activity_hint: crate::snapshot_client::ActivityHintResponse,
    pub(super) receipt_window_days: u64,
    pub(super) cache_observations_enabled: bool,
    /// `None` only on a continuation page's preparation, which never finishes.
    pub(super) scan_agent_status_collection: Option<std::sync::Arc<AgentStatusCollection>>,
    pub(super) attribution_context: Option<SessionAttributionContext>,
    pub(super) upload_policy: SnapshotUploadPolicy,
    pub(super) upload_destination_namespace: String,
    pub(super) receipt_client: SnapshotApiClient,
    pub(super) index_path: PathBuf,
    pub(super) upload_progress_path: PathBuf,
    pub(super) upload_progress: SnapshotUploadProgress,
    pub(super) committed_index: ScanIndex,
    pub(super) backfill_state: crate::backfill::BackfillState,
    pub(super) backfill_pending: bool,
    pub(super) scan: Option<crate::snapshots::OwnedSourceScan>,
}

#[allow(clippy::large_enum_variant, reason = "moves the owned context unboxed")]
pub(super) enum SourcePreparationStep {
    Pending(SourcePreparation),
    Refused(SourcePreparation, crate::source_rotation::LocalRefusal),
    Complete {
        preparation: SourcePreparation,
        index: ScanIndex,
        scan: SourceScanResult,
    },
}

impl SourcePreparation {
    pub(super) fn step(self) -> SourcePreparationStep {
        let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(
            self.source == SnapshotSource::ClaudeCode,
        );
        let result = self.step_inner();
        let counts = diagnostics.finish();
        crate::local_resource_diagnostics::claude_reread::emit_without_lease(counts);
        result
    }
    pub(super) fn step_inner(mut self) -> SourcePreparationStep {
        let state = self.scan.take().expect("active source preparation");
        match state.step_fallible(self.attribution_context.as_ref()) {
            Err(reason) => SourcePreparationStep::Refused(self, reason),
            Ok(crate::snapshots::OwnedSourceScanStep::Pending(next)) => {
                self.scan = Some(next);
                SourcePreparationStep::Pending(self)
            }
            Ok(crate::snapshots::OwnedSourceScanStep::Complete { index, scan }) => {
                SourcePreparationStep::Complete {
                    preparation: self,
                    index,
                    scan,
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) fn collect_preparation_with_rotation(
    frame: SourcePreparation,
) -> (SourcePreparation, ScanIndex, SourceScanResult) {
    try_collect_preparation_with_rotation(frame).expect("owned source completion")
}

#[cfg(test)]
pub(super) fn try_collect_preparation_with_rotation(
    frame: SourcePreparation,
) -> Result<(SourcePreparation, ScanIndex, SourceScanResult)> {
    struct Collect {
        frame: Option<SourcePreparation>,
        completed: Option<(SourcePreparation, ScanIndex, SourceScanResult)>,
        failure: Option<anyhow::Error>,
        started: Instant,
        steps: usize,
    }
    impl crate::source_rotation::Owner for Collect {
        type Source = SnapshotSource;
        type Frame = SourcePreparation;
        type Completed = (SourcePreparation, ScanIndex, SourceScanResult);
        fn prepare(
            &mut self,
            _: SnapshotSource,
            _remaining: Option<usize>,
        ) -> Result<Option<Self::Frame>> {
            Ok(self.frame.take())
        }
        fn validate(&mut self, _: &Self::Frame) -> Result<()> {
            Ok(())
        }
        fn step(
            &mut self,
            frame: Self::Frame,
            _remaining: Option<usize>,
        ) -> crate::source_rotation::Step<Self::Frame, Self::Completed> {
            self.steps += 1;
            assert!(
                self.steps <= 1024,
                "same owned scanner must finish within existing fixture steps"
            );
            match frame.step() {
                SourcePreparationStep::Pending(frame) => {
                    crate::source_rotation::Step::Pending(frame)
                }
                SourcePreparationStep::Refused(frame, reason) => {
                    drop(frame);
                    crate::source_rotation::Step::Refused(reason)
                }
                SourcePreparationStep::Complete {
                    preparation,
                    index,
                    scan,
                } => crate::source_rotation::Step::Complete((preparation, index, scan)),
            }
        }
        fn finish(&mut self, completed: Self::Completed, _remaining: Option<usize>) -> Result<()> {
            self.completed = Some(completed);
            Ok(())
        }
        fn outcome(&mut self, _: SnapshotSource, result: Result<()>) {
            if let Err(error) = result {
                self.failure = Some(error);
            }
        }
        fn monotonic(&self) -> Duration {
            self.started.elapsed()
        }
    }
    let source = frame.source;
    let mut owner = Collect {
        frame: Some(frame),
        completed: None,
        failure: None,
        started: Instant::now(),
        steps: 0,
    };
    // The original rotation calculates queue/retained deductions. No
    // independently fabricated full-budget argument reaches the collector.
    let budget =
        tests::permanent_finish_pipeline_tests::prior_index_lifetime_tests::rotation_budget();
    crate::source_rotation::run(&mut owner, &[source], budget);
    if let Some(error) = owner.failure {
        return Err(error);
    }
    owner.completed.context("owned source completion")
}

/// The upload-context fingerprint a cycle activates on its index (pure; the
/// ordinary prepare and a continuation page share it).
pub(super) fn cycle_upload_context(
    upload_policy: SnapshotUploadPolicy,
    checkpoint_namespace: Option<&str>,
    cache_observations_enabled: bool,
) -> String {
    let upload_context = snapshot_upload_context_fingerprint(upload_policy, checkpoint_namespace);
    if cache_observations_enabled {
        // Reuse the existing per-file upload context invalidation when a
        // backend upgrade admits cache evidence from previously scanned files.
        format!(
            "{:x}",
            Sha256::digest(format!("{upload_context}:session_cache_observations:v1"))
        )
    } else {
        upload_context
    }
}

/// Bind persisted retry pages to the Claude copy-prefix money mode; pages
/// persisted under the earlier context cannot replay old bodies.
pub(crate) fn resumed_prefix_upload_context(context: String, enabled: bool) -> String {
    if enabled {
        format!(
            "{:x}",
            Sha256::digest(format!("{context}:resumed-prefix:v1"))
        )
    } else {
        context
    }
}

/// Keep capability-qualified ACK contexts in the loader's 64-hex domain.
pub(crate) fn copy_unproven_upload_context(context: String, enabled: bool) -> String {
    if enabled {
        format!(
            "{:x}",
            Sha256::digest(format!("{context}:copy_unproven:v1"))
        )
    } else {
        context
    }
}

/// The replay generation of a cycle (pure; shared as above).
pub(super) fn cycle_replay_generation(
    source: SnapshotSource,
    upload_destination_namespace: &str,
) -> String {
    let replay = current_historical_replay(source);
    format!(
        "{}:{}:{}",
        source.api_slug(),
        replay.revision,
        upload_destination_namespace
    )
}

/// The sampled-acquisition scope of a cycle: the cursor and retained
/// namespace (pure; a continuation page must use the same bytes).
pub(crate) fn cycle_sampled_scope(
    account_witness: &[u8; 32],
    upload_destination_namespace: &str,
    index_path: &Path,
    request_identity_capture: bool,
) -> crate::transcript_acquisition::Scope {
    // The trailing `false` is the retired context-curve flag; the scope bytes
    // are unchanged.
    let mut sampled_scope = format!(
        "sampled_scan:v1:{account_witness:?}:{upload_destination_namespace}:{}:false",
        index_path.display(),
    );
    if request_identity_capture {
        // A retained parser never crosses capture modes; the dark scope bytes
        // are unchanged.
        sampled_scope.push_str(":request_identity");
    }
    crate::transcript_acquisition::Scope(format!("{:x}", Sha256::digest(sampled_scope.as_bytes())))
}

#[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
pub(super) fn prepare_sync_source(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    transport_cycle: &mut crate::net_resilience::TransportCycleOutcome,
    account_witness: [u8; 32],
) -> Result<Option<SourcePreparation>> {
    let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(
        source == SnapshotSource::ClaudeCode,
    );
    let result = crate::local_resource_diagnostics::source_prepare(
        source.api_slug(),
        || {
            prepare_sync_source_inner(
                client,
                device,
                device_secret,
                source,
                machine_id,
                home,
                support_dir,
                daemon,
                transport_cycle,
                account_witness,
            )
        },
        |result| {
            result
                .as_ref()
                .ok()
                .and_then(Option::as_ref)
                .is_some_and(|preparation| {
                    crate::snapshots::state_v2_growth_retention_active(&preparation.committed_index)
                })
        },
    );
    with_source_cadence_state(source, |cadence| {
        if let Some(pulse) = cadence.collection.as_mut() {
            pulse.prepare_outcome(result.as_ref().err());
        }
    });
    if result.is_err() {
        // A failed pass never holds the others' recency tier; it keeps its
        // owed work and rejoins when a pass records its census.
        let destination = snapshot_upload_destination_namespace(device, device_secret);
        if let Err(error) =
            crate::backfill::record_first_read_tier_stop(support_dir, source, &destination)
        {
            eprintln!(
                "local snapshot backfill tier save deferred for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
        }
    }
    let counts = diagnostics.finish();
    if source == SnapshotSource::ClaudeCode {
        crate::local_resource_diagnostics::claude_reread::emit_without_lease(counts);
    }
    result
}

/// Preserve main's progress admission before any v1 containment. Published
/// custody must instead authenticate the route before progress can be renamed.
pub(super) fn load_source_checkpoints(
    index_path: &Path,
    progress_path: &Path,
    source: SnapshotSource,
    support_dir: &Path,
    destination: &str,
    witness: SnapshotQuarantineWitness,
) -> Result<(
    ScanIndex,
    crate::snapshots::ScanIndexLoadOrigin,
    SnapshotUploadProgress,
)> {
    let custody = crate::snapshots::state_v2_custody_published(index_path)?;
    if custody {
        // Begin once at preparation admission. Claim-only nested loads must
        // preserve the pass's measurements rather than start another pass.
        crate::snapshots::state_v2_pass_start();
    }
    if !custody {
        // A busy progress owner refuses the pass before any v1 containment.
        drop(SnapshotProgressLock::acquire(progress_path)?);
    }
    let (index, origin) =
        ScanIndex::load_for_snapshot_source_with_custody(index_path, source, support_dir, custody)?;
    crate::snapshots::state_v2_before_collection(&index)?;
    index.require_persistence_available()?;
    // A first import may publish during this load: progress follows the index.
    let progress = SnapshotUploadProgress::load_for_index(
        &index,
        index_path,
        progress_path,
        destination,
        witness,
    )?;
    Ok((index, origin, progress))
}

#[allow(
    clippy::too_many_arguments,
    reason = "preparation retains the cycle transport, identity and resource inputs"
)]
pub(super) fn prepare_sync_source_inner(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    transport_cycle: &mut crate::net_resilience::TransportCycleOutcome,
    account_witness: [u8; 32],
) -> Result<Option<SourcePreparation>> {
    if let Some(remaining) = source_upload_backoff_remaining(source) {
        // The server asked for room and we said yes. Re-running the cycle now
        // would scan, re-derive and re-POST the same pages it just shed, which is
        // precisely the loop the backoff exists to break. No status receipt: the
        // last one still describes reality, and the check-in heartbeat keeps
        // freshness alive on its own clock.
        eprintln!(
            "local snapshot sync deferred for {}: backend backoff has {}s remaining",
            source.api_slug(),
            remaining.as_secs()
        );
        return Ok(None);
    }
    let mut scan_started_at = current_rfc3339();
    let relay_token = client.issue_status_relay_token(device, device_secret, source)?;
    let mut activity_hint = small_source_upload(source, || client.get_activity_hint(&relay_token))?;
    // Treat the activity hint as the only authority for the semantic evidence
    // window. Missing/malformed hints already fail JSON decoding; future
    // out-of-contract widths fail here before any scan or receipt can
    // manufacture a fallback policy. Zero is an explicit tombstone control.
    let receipt_window_days = validated_receipt_window_days(activity_hint.backfill_window_days)?;
    let cache_observations_enabled = source != SnapshotSource::Pi
        && activity_hint.session_cache_observations_contract.as_deref()
            == Some("session_cache_observations:v1");
    // Contract 5 is always on: every Claude cycle captures markers and keeps
    // the Desktop census witness; the hint's identity token is never read.
    let request_identity_capture = crate::snapshots::claude_request_identity::captures(source);
    // The server's scan directive was parsed and discarded before this. It is a
    // cost lever, so it may only lengthen the local cadence (see
    // `negotiated_wait`), never shorten it.
    record_server_scan_directive(source, &activity_hint.recommended_scan_after);
    with_source_cadence(source, |cadence| {
        cadence.record_backend_hint(
            Instant::now(),
            activity_hint.record_count_15m,
            false,
            activity_hint.local_usage_reconciliation_enabled,
        )
    });
    // Cache the raw workspace policy for status and tracking eligibility together.
    daemon
        .record_reconciliation_enabled(
            source_kind(source),
            activity_hint.local_usage_reconciliation_enabled,
            receipt_window_days,
        )
        .map_err(|_| anyhow!("tracking state unavailable"))?;
    if receipt_window_days == 0 {
        // The tombstone withdraws the server's census, which the armed
        // walk record stood for: the next pass at a real window walks.
        crate::snapshots::walk_idle::clear(source, "window_zero");
        // No pass retires a paced request while the window stays 0.
        continuation::drop_paced_request(source);
        withdraw_and_report_policy_stop(
            client,
            device,
            device_secret,
            support_dir,
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: &scan_started_at,
                counts: SyncCounts::for_policy(0),
                state: CollectorState::PolicyTombstone,
            },
        )?;
        return Ok(None);
    }
    let agent_status_captured_at = current_rfc3339();
    let agent_status_expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| agent_status_captured_at.clone());
    let scan_agent_status_collection = crate::agent_status_refresh::collection(
        &source_kind(source),
        agent_status_captured_at,
        agent_status_expires_at,
        false,
    )?;
    // Standalone/manual one-shot sync has no periodic daemon owner. Preserve
    // its original status upload without restoring the automatic duplicate.
    if !crate::agent_status_refresh::active() {
        if let Err(error) = upload_agent_status(
            client,
            &relay_token,
            machine_id,
            &scan_agent_status_collection.snapshots,
        ) {
            transport_cycle.note_error(&error);
            eprintln!("local agent status upload skipped: {}", safe_error(&error));
            if error.downcast_ref::<UploadShed>().is_some() {
                return Err(error);
            }
        }
    }

    // The configured-MCP context-footprint harvest runs on its own slower
    // schedule (run-at-start + every 6 h, `spawn_mcp_inventory_sync_for_daemon`),
    // NOT on the 5-minute snapshot sync: each harvest spawns every configured
    // MCP server's stdio process, so doing it every cycle would be needlessly
    // intrusive and re-POST unchanged inventories 12×/hour. See
    // `crate::mcp_inventory`.

    if !activity_hint.local_usage_reconciliation_enabled {
        crate::snapshots::walk_idle::clear(source, "disabled");
        withdraw_and_report_policy_stop(
            client,
            device,
            device_secret,
            support_dir,
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: &scan_started_at,
                counts: SyncCounts::for_policy(receipt_window_days),
                state: CollectorState::Disabled(Some("disabled_by_admin".to_string())),
            },
        )?;
        return Ok(None);
    }

    // Status acquisition/upload runs on its independent source owner. The
    // reconciliation policy cache and the
    // active-session projection are all cheap and all product-visible. The
    // negotiated cadence gates what is actually expensive — the local transcript
    // scan below, which re-reads every changed transcript on this machine.
    let power = continuation::MacPlatformSignals::default().power();
    let upload_destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    let destination_switch = continuation::request_on_destination_change(
        source,
        &upload_destination_namespace,
        power,
        || {
            backfill_replay_pending(
                source,
                &load_backfill_state(support_dir),
                &upload_destination_namespace,
            )
        },
    );
    let paced_due = source_paced_due(source).is_some_and(|due| due <= crate::scan_clock::now());
    let mut due = crate::local_resource_diagnostics::PrepareDue {
        due: if paced_due {
            "due_paced"
        } else {
            "due_ordinary"
        },
        destination_switch,
        power: continuation::power_label(power),
    };
    if let Some(remaining) = source_cadence_wait(source) {
        due.due = "due_deferred";
        crate::local_resource_diagnostics::prepare_due(due);
        eprintln!(
            "local snapshot scan deferred for {}: next scan in {}s on the negotiated cadence; power={:?} effective_interval={}s",
            source.api_slug(),
            remaining.as_secs(),
            power,
            with_source_cadence(source, |cadence| cadence.ordinary_interval().min(MAX_CYCLE_INTERVAL))
                .unwrap_or(SNAPSHOT_SYNC_INTERVAL).as_secs()
        );
        return Ok(None);
    }
    crate::local_resource_diagnostics::prepare_due(due);

    let roots = crate::snapshot_roots::scan_roots(
        source,
        home,
        &scan_agent_status_collection.codex_scan_homes,
    )?;
    let mut encoded_attribution_key = activity_hint.session_attribution_hmac_key.take();
    let attribution_context = SessionAttributionContext::from_activity_hint(
        source,
        home,
        activity_hint.session_attribution_enabled,
        encoded_attribution_key.as_deref(),
        activity_hint
            .session_attribution_hmac_key_version
            .as_deref(),
    );
    if let Some(encoded_key) = encoded_attribution_key.as_mut() {
        encoded_key.zeroize();
    }
    if source == SnapshotSource::ClaudeCode {
        // A key change is scrubbed where a stored reduction loads
        // (`tail_source::load`): every parse, cursor and count stays, so a
        // server hint never causes a re-read.
        crate::snapshots::claude_request_identity::bind_session_context_key(
            attribution_context.as_ref(),
        );
    }
    let upload_policy = SnapshotUploadPolicy::from_hint(&activity_hint);
    let receipt_client = client
        .clone()
        .with_receipt_destination_namespace(upload_destination_namespace.clone());
    let checkpoint_namespace = attribution_context
        .as_ref()
        .map(SessionAttributionContext::checkpoint_namespace);
    let upload_context = cycle_upload_context(
        upload_policy,
        checkpoint_namespace.as_deref(),
        cache_observations_enabled,
    );
    let base_upload_context = upload_context.clone();
    let claude = source == SnapshotSource::ClaudeCode;
    let copy_unproven_enabled =
        claude && activity_hint.copy_unproven_contract.as_deref() == Some("copy_unproven:v1");
    // Context adoption invalidates stale pending pages on capability downgrade.
    let upload_context = resumed_prefix_upload_context(upload_context, claude);
    let upload_context = copy_unproven_upload_context(upload_context, copy_unproven_enabled);
    let destination_index_path = snapshot_destination_scoped_index_path(
        &snapshot_index_path(support_dir, source),
        &upload_destination_namespace,
    );
    let index_path = snapshot_v3_index_path(&destination_index_path);
    let upload_progress_path = snapshot_upload_progress_path(&index_path);
    let (mut index, load_origin, mut upload_progress) = load_source_checkpoints(
        &index_path,
        &upload_progress_path,
        source,
        support_dir,
        &upload_destination_namespace,
        crate::snapshots::snapshot_quarantine_witness_for_context(source, &upload_context),
    )?;
    let first_census_end = crate::backfill::record_first_census(
        support_dir,
        source,
        &upload_destination_namespace,
        &scan_started_at,
        load_origin == crate::snapshots::ScanIndexLoadOrigin::Missing,
    )?;
    // Missing-index import stays at generation zero until the first collection save.
    // A restart after the anchor save must admit against that same census end.
    if index.generation == 0 {
        if let Some(anchor) = first_census_end {
            scan_started_at = anchor;
        }
    }
    if source == SnapshotSource::ClaudeCode {
        daemon.transcript_cache.bind_withheld(&mut index);
    }
    // Every save of this pass, the recovery's first, reconciles copy
    // ownership under the claim cutoff finish applies.
    let backfill_state = load_backfill_state(support_dir);
    index.backfill_cutoff_nanos = backfill_state.backfill_cutoff_nanos();
    upload_progress.recover_ack_retirement_handoff(
        &mut index,
        &index_path,
        &upload_progress_path,
    )?;
    upload_progress.configure_ack_capacity(&index);
    // Absent, quarantined or undecodable: every file would come back new. The
    // load origin decides it; an empty saved index counts too.
    let claude_index_loaded_fresh = load_origin.is_fresh(&index);
    if index_path.exists()
        && upload_progress.prune_pending_cache_head_orphans_from_loaded_index(&index)
    {
        upload_progress.save(&upload_progress_path)?;
    }
    // One serialization feeds both input digests: the traversal contract
    // (Claude) and the per-item proof's input record (every source).
    let policy_bytes = serde_json::to_vec(&upload_policy).expect("upload policy is serializable");
    if claude {
        claude_contract::prepare_context(
            &policy_bytes,
            checkpoint_namespace.as_deref(),
            cache_observations_enabled,
        );
    }
    continuation::observe(source, &upload_context, upload_policy);
    activate_source_upload_context(source, upload_context, &mut index, &mut upload_progress);
    index.copy_unproven_enabled = copy_unproven_enabled;
    index.set_copy_prefix_base_upload_context(claude.then_some(base_upload_context));
    index.note_upload_context_inputs(
        source,
        crate::snapshots::UploadContextInputs::new(
            &policy_bytes,
            checkpoint_namespace.as_deref(),
            cache_observations_enabled,
            copy_unproven_enabled,
            claude,
        ),
        upload_policy,
    );
    // Read before this cycle's replay claims a generation in the upload
    // ledger: only a generation an earlier cycle left there is evidence.
    let prior_claude_history = (source == SnapshotSource::ClaudeCode).then(|| {
        claude_prior_history(
            &backfill_state,
            &upload_destination_namespace,
            &upload_progress,
            &index_path,
            support_dir,
        )
    });
    note_claude_index_rebuild_for_destination(
        source,
        claude_index_loaded_fresh,
        &backfill_state,
        &upload_destination_namespace,
        &upload_progress,
        &index_path,
        support_dir,
    );
    if let Some(prior) = prior_claude_history {
        crate::snapshots::note_prior_history_unverified(
            prior == crate::snapshots::PriorHistory::Unverified,
        );
    }
    crate::local_resource_diagnostics::change_reason::index_loaded(
        source.api_slug(),
        claude_index_loaded_fresh,
        prior_claude_history,
    );
    let replay_generation = cycle_replay_generation(source, &upload_destination_namespace);
    // An unreadable backfill state arms no Claude replay and no replay-wide
    // scan window (StateMissing H1, N2).
    let backfill_pending =
        backfill_replay_pending(source, &backfill_state, &upload_destination_namespace);
    index.first_read_pending = backfill_pending;
    index.first_import_pending = backfill_pending
        && first_import_alone(
            source,
            device,
            &backfill_state,
            &upload_destination_namespace,
        );
    // Recency tier: the current tier gates this pass's first reads (order only).
    let tier = backfill_pending
        .then(|| backfill_state.first_read_tier(&upload_destination_namespace, source))
        .flatten();
    index.first_read_tier_cutoff = tier.map(|(_, cutoff)| cutoff);
    crate::local_resource_diagnostics::pass_outcomes(|outcomes| {
        outcomes.first_read_tier_days = tier.map(|(days, _)| days);
    });
    if !backfill_pending
        && index.prepare_snapshot_admission_reoffer(SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE)
    {
        // Persist the one-shot policy adoption before progress or scan can
        // advance. Existing generation CAS rejects overlapping stale writers.
        index.save(&index_path)?;
    }
    let admission_reoffer_pending =
        index.snapshot_admission_reoffer_pending_for_scan(source, receipt_window_days);
    // Due exact refusal re-offers are reserved from the loaded, committed
    // index and saved below before any lease reaches the scan or uploader.
    let reoffer_now = reason_reoffer::now_unix_seconds();
    let reoffer_scope = reason_reoffer::Scope {
        index: &index,
        now: reoffer_now,
        window_start_unix_seconds: reoffer_now
            .saturating_sub(receipt_window_days.saturating_mul(86_400)),
    };
    if prepare_upload_progress_for_cycle_with_reoffer(
        &mut upload_progress,
        &index,
        &replay_generation,
        backfill_pending,
        Some(&reoffer_scope),
    ) {
        // Claim the new generation before the potentially long historical
        // scan. This prevents ACKs from the prior revision from suppressing
        // identical entities and gives overlapping writers a CAS boundary.
        upload_progress.save(&upload_progress_path)?;
    }
    let quarantine_retry_paths =
        save_terminal_contract_claims_for_scan(&mut index, &upload_progress, &index_path)?;
    index.refusal_exposure = upload_progress.refusal_exposure(current_unix_seconds());
    index.refusal_exposure.held_terminal_entities = index.snapshot_unproven_terminal_count();
    if !quarantine_retry_paths.is_empty() {
        crate::local_resource_diagnostics::traversal_point(
            "quarantine_retry",
            source.api_slug(),
            &serde_json::json!({"action": "enqueued", "count": quarantine_retry_paths.len()}),
        );
    }
    // Under this pass's sync lock, before the scan is built. Every source
    // replays when one is pending; true when it reset the index.
    let replay_dropped_entries =
        backfill_pending && index.prepare_historical_replay(replay_generation.clone());
    if let Some(prior_history) = prior_claude_history {
        note_claude_history_cutoff_for_cycle(
            &mut index,
            source,
            prior_history,
            &backfill_state,
            claude_index_loaded_fresh || replay_dropped_entries,
        );
    }
    // The committed state, before the scan advances it. A partial commit needs
    // both: which entries this scan produced, and which ones the server was
    // already known to hold.
    index.activate_effective_upload_body_witness_revision(cycle_body_witness_revision(source));
    if source == SnapshotSource::ClaudeCode {
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.load_claude_reemission_exclusions(support_dir);
        crate::snapshots::claude_request_money::e2::apply_money_rules(&mut index);
        // Observe the always-on contract BEFORE the committed baseline, so an
        // unaccepted/shed page keeps it and its latch. It re-owes no history.
        index.observe_claude_request_identity_contract(true);
    }
    let scan_window_days = scan_request_window_days(
        receipt_window_days,
        backfill_pending || admission_reoffer_pending,
    );
    let copy_prefix_scope = if source == SnapshotSource::ClaudeCode {
        match crate::snapshots::claude_copy_prefix_reread::prepare(
            &mut index,
            support_dir,
            &roots,
            &scan_started_at,
            scan_window_days,
        ) {
            Ok(paths) => paths,
            Err(_) => {
                eprintln!("local Claude copy-prefix re-read: request_refused=1");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    // Before the scanner and its committed baseline: identity-503 custody
    // decides whether that cause still holds this walk unsettled.
    index.reconcile_isolated_503(&mut upload_progress.identity_503_pending);
    crate::local_resource_diagnostics::index_clone_start(source.api_slug());
    let mut committed_index = index.clone();
    let reoffer_paths =
        index.activate_reason_reoffer_retries(upload_progress.active_reason_reoffers.clone());
    let mut cooldowns = upload_progress.reason_reoffer_cooldowns(reoffer_now);
    if backfill_pending {
        cooldowns.retain(|_, cooldown| cooldown.input_change_only);
    }
    index.activate_reason_reoffer_cooldowns(cooldowns);
    stale_owed::rearm_held_probe_once(source, &upload_progress, &mut index);
    upload_progress.reselect_pending_cache_heads(&mut index, cache_observations_enabled);
    let mut watcher_hints = crate::snapshot_watcher::take_pending_snapshot_paths(source);
    // Leased unchanged files join the same bounded, revalidated hint queue.
    watcher_hints.paths.extend(reoffer_paths);
    watcher_hints.paths.extend(quarantine_retry_paths);
    if watcher_hints.overflowed {
        eprintln!(
            "local snapshot watcher hint queue overflowed for {}; durable traversal will reconcile",
            source.api_slug()
        );
    }
    // The initial hint/status relay token dies here; sends acquire fresh tokens.
    drop(relay_token);
    let sampled_scope = cycle_sampled_scope(
        &account_witness,
        &upload_destination_namespace,
        &index_path,
        request_identity_capture,
    );
    #[cfg(unix)]
    crate::snapshots::begin_source_pass(&daemon.transcript_cache, support_dir, source, &index_path);
    // A hint or listing request is a change: this pass walks.
    if !watcher_hints.paths.is_empty() {
        crate::snapshots::walk_idle::clear(source, "hint");
    } else if watcher_hints.overflowed || watcher_hints.list_all.requested() {
        crate::snapshots::walk_idle::clear(source, "listing");
    }
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_post_save_failure("after_hint_take")?;
    let walk_idle_pass = crate::snapshots::walk_idle::Pass::new(
        source,
        &roots,
        home,
        &sampled_scope,
        &index_path,
        scan_window_days,
        &replay_generation,
        &activity_hint,
        &policy_bytes,
        &index,
    );
    let cycle_owes = if backfill_pending {
        Some("backfill")
    } else if admission_reoffer_pending {
        Some("reoffer")
    } else if claude_index_loaded_fresh {
        Some("fresh_index")
    } else if !copy_prefix_scope.is_empty() {
        Some("copy_prefix")
    } else {
        None
    };
    let cycle_owes_nothing = cycle_owes.is_none();
    let now = crate::scan_clock::utc_seconds();
    let walk_idle = crate::snapshots::walk_idle::gate(
        source,
        &walk_idle_pass,
        &index,
        cycle_owes.or_else(|| {
            upload_owes(
                source,
                &upload_progress,
                support_dir,
                &activity_hint,
                &index,
                now,
            )
        }),
        now,
    );
    let mut scan = crate::snapshots::OwnedSourceScan::new_with_recovery_priority(
        source,
        &roots,
        index,
        &scan_started_at,
        scan_window_days,
        MAX_BACKFILL_FILES_PER_SOURCE,
        (source == SnapshotSource::ClaudeCode).then_some(support_dir),
        &watcher_hints.paths,
        watcher_hints.overflowed,
        &mut watcher_hints.list_all,
        request_identity_capture,
        &copy_prefix_scope,
        Some((daemon.transcript_cache.as_ref(), &sampled_scope)),
        walk_idle,
    )
    .with_sampled_acquisition(daemon.transcript_cache.clone(), sampled_scope.clone())
    .with_launch_events(home)
    .with_codex_versions(daemon.codex_versions.clone());
    // A walk already running keeps the request: the first pass after it lists.
    crate::snapshot_watcher::defer_listing(source, watcher_hints.list_all);
    scan.rehome_withheld_baseline(&mut committed_index)?;
    if source == SnapshotSource::ClaudeCode {
        scan = scan.with_line_observer("footprint", daemon.footprint_cwds.observer());
    } else if source == SnapshotSource::Codex {
        scan = scan.with_line_observer("codex_prelude", daemon.codex_preludes.observer(&roots));
    }
    Ok(Some(SourcePreparation {
        source,
        walk_idle_pass: Some((walk_idle_pass, cycle_owes_nothing)),
        claude_scan_roots: (source == SnapshotSource::ClaudeCode).then_some(roots),
        account_witness,
        scan_started_at,
        activity_hint,
        receipt_window_days,
        cache_observations_enabled,
        scan_agent_status_collection: Some(scan_agent_status_collection),
        attribution_context,
        upload_policy,
        upload_destination_namespace,
        receipt_client,
        index_path,
        upload_progress_path,
        upload_progress,
        committed_index,
        backfill_state,
        backfill_pending,
        scan: Some(scan),
    }))
}

/// The upload ledger's half of the walk gate (`walk_idle`).
pub(super) fn upload_owes_nothing(
    source: SnapshotSource,
    progress: &SnapshotUploadProgress,
    support: &Path,
    hint: &crate::snapshot_client::ActivityHintResponse,
    index: &ScanIndex,
    now: u64,
) -> bool {
    upload_owes(source, progress, support, hint, index, now).is_none()
}

/// The first kind of upload work that needs a walk, if any.
fn upload_owes(
    source: SnapshotSource,
    progress: &SnapshotUploadProgress,
    support: &Path,
    hint: &crate::snapshot_client::ActivityHintResponse,
    index: &ScanIndex,
    now: u64,
) -> Option<&'static str> {
    if progress.accepted_fingerprints.len() >= progress.ack_capacity {
        Some("ack_capacity")
    } else if !progress.pending_cache_heads.is_empty() {
        Some("cache_heads")
    } else if progress.context_resend.has_pending_ordinary() {
        Some("context_resend")
    } else if progress
        .head_conflict_challenges
        .keys()
        .any(|key| progress.accepted_cache_heads.contains_key(key))
    {
        Some("head_conflict")
    } else if !progress
        .identity_503_pending
        .as_ref()
        .is_none_or(BTreeSet::is_empty)
    {
        Some("identity_503")
    } else if !progress.active_quarantine_retries.is_empty() {
        Some("quarantine_retry")
    } else if !progress.active_reason_reoffers.is_empty() {
        Some("reason_reoffer")
    } else if progress.quarantined_fingerprints.values().any(|record| {
        record.disposition == SnapshotQuarantineDisposition::RetryPending
            && (1..=now).contains(&record.retry_after_unix_seconds)
    }) {
        Some("quarantine_due")
    } else if !with_source_cadence_state(source, |cadence| cadence.continuation_work().is_none())
        .unwrap_or(false)
    {
        Some("continuation")
    } else if progress.telemetry_owes_walk(support, hint, index) {
        Some("telemetry")
    } else {
        None
    }
}

pub(super) fn capture_codex_recovery_evidence(
    index: &mut ScanIndex,
    committed_index: &mut ScanIndex,
    scan_result: &mut SourceScanResult,
    index_path: &Path,
    progress_path: &Path,
    validate_authority: impl Fn() -> Result<()>,
) -> bool {
    let (mut captured, changed) =
        index.stage_codex_recovery_capture(committed_index, &scan_result.snapshots);
    let mut adopted = false;
    if !changed.is_empty() {
        let protected = scan_result
            .snapshots
            .iter()
            .filter(|item| changed.contains(&item.source_session_id))
            .cloned()
            .collect::<Vec<_>>();
        let saved = (|| -> Result<()> {
            // A state-store save runs its progress recovery under this owner,
            // as the partial checkpoint does: locking the progress file again
            // on a second descriptor would refuse this process's own lock.
            let progress_owner = SnapshotProgressLock::acquire(progress_path)?;
            let progress_owner = if crate::snapshots::state_v2_growth_retention_active(&captured) {
                progress_owner.for_v2(progress_path)
            } else {
                progress_owner
            };
            validate_authority()?;
            let validator = scan_result
                .codex_joining_validator()
                .context("Codex recovery capture lacks a source witness")?;
            validator.validate(&protected)?;
            captured.save_with_progress_owner(index_path, &progress_owner)
        })();
        match saved {
            Ok(()) => {
                index.generation = captured.generation;
                index.retain_persistence_baseline_from(&captured);
                *committed_index = captured;
                adopted = true;
            }
            Err(error) => scan_result.hold_codex_groups(
                index,
                committed_index,
                &changed,
                &format!(
                    "recovery capture could not durably publish ({})",
                    safe_error(&error)
                ),
            ),
        }
    }
    scan_result.finish_codex_capture_boundary(index);
    adopted
}

/// Progress claims were saved by the caller. Mirror claims and current-again
/// ordinary retries before source acquisition, then bind each retry to one file.
/// Ordinary offered/queued retries stay due; source-held ones use ordinary backoff.
pub(super) fn save_terminal_contract_claims_for_scan(
    index: &mut ScanIndex,
    progress: &SnapshotUploadProgress,
    index_path: &Path,
) -> Result<Vec<PathBuf>> {
    let mut changed = index.merge_terminal_contract_claims(&progress.quarantined_fingerprints);
    for (fingerprint, record) in &progress.quarantined_fingerprints {
        let current_again = progress.active_quarantine_retries.contains(fingerprint)
            && index
                .eligible_snapshot_fingerprint_refs()
                .any(|current| current == fingerprint)
            && !index.decode_holds_entity(fingerprint)
            && !progress.permanent_rejections.contains_key(fingerprint)
            && record.contract_retry_claims.is_none()
            && record.disposition == SnapshotQuarantineDisposition::RetryPending
            && record.failed_reconstruction_count < MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
            && index
                .quarantined_snapshot_fingerprints
                .get(fingerprint)
                .is_some_and(|old| {
                    let mut pending = old.clone();
                    pending.disposition = record.disposition;
                    pending.retry_after_unix_seconds = record.retry_after_unix_seconds;
                    pending.witness = record.witness.clone();
                    old.disposition == SnapshotQuarantineDisposition::SupersededTerminal
                        && old.witness.same_retry_contract(&record.witness)
                        && pending == *record
                });
        if (current_again
            || record
                .upload_body_witness
                .as_deref()
                .is_some_and(|body| progress.owed_stale_body(fingerprint, body)))
            && index.quarantined_snapshot_fingerprints.get(fingerprint) != Some(record)
        {
            index
                .quarantined_snapshot_fingerprints
                .insert(fingerprint.clone(), record.clone());
            changed = true;
        }
    }
    if changed {
        index.save(index_path)?;
    }
    let paths =
        index.activate_terminal_contract_retries(progress.active_quarantine_retries.clone());
    Ok(paths)
}

/// Prepare the disposable upload ledger against the durable scan-index replay.
///
/// The index owns both the replay generation and conflict quarantine after a
/// completed cycle clears upload progress. For a new generation, old index
/// quarantine must not be restored after progress is rearmed. For the same
/// generation, restore it only after progress has claimed that generation so a
/// clean follow-up cannot erase a replacement conflict before its retry.
#[cfg(test)]
pub(super) fn prepare_upload_progress_for_cycle(
    upload_progress: &mut SnapshotUploadProgress,
    index: &ScanIndex,
    replay_generation: &str,
    historical_replay_pending: bool,
) -> bool {
    prepare_upload_progress_for_cycle_with_reoffer(
        upload_progress,
        index,
        replay_generation,
        historical_replay_pending,
        None,
    )
}

/// Ordinary and continuation prepares bind both runtime witnesses together,
/// and mirror the open head-CAS challenge sessions into the index.
/// Neither retained body ACKs nor receipt candidates acquire new authority here.
pub(super) fn activate_source_upload_context(
    source: SnapshotSource,
    context: String,
    index: &mut ScanIndex,
    progress: &mut SnapshotUploadProgress,
) {
    progress.active_quarantine_witness = Some(
        crate::snapshots::snapshot_quarantine_witness_for_context(source, &context),
    );
    index.activate_file_upload_context(source, context.clone());
    // A session whose upload can carry a head-CAS answer reads natively, never
    // from Tail. The answer replaces a saved base (`attach_head_conflict_answers`);
    // a challenge without one never answers; only an ACK with a head clears it.
    index.activate_head_conflict_sessions(
        progress
            .head_conflict_challenges
            .keys()
            .filter(|key| progress.accepted_cache_heads.contains_key(*key))
            .cloned()
            .collect(),
    );
    progress.fresh_context_body_acks.clear();
    progress.context_receipt_candidates.clear();
    progress.request_contributions.clear();
    progress.context_resend = upload_context_resend::Cycle::new(context);
}

/// Production form of the above: outside a historical replay, due refusal
/// re-offers share the ordinary retry budget. A replay neither re-offers nor
/// resets a cooldown.
pub(super) fn prepare_upload_progress_for_cycle_with_reoffer(
    upload_progress: &mut SnapshotUploadProgress,
    index: &ScanIndex,
    replay_generation: &str,
    historical_replay_pending: bool,
    reoffer: Option<&reason_reoffer::Scope<'_>>,
) -> bool {
    if !historical_replay_pending {
        return upload_progress.prepare_quarantine_and_reason_retries(
            &index.quarantined_snapshot_fingerprints,
            reoffer,
        );
    }

    let same_index_replay = index.historical_replay_generation_matches(replay_generation);
    let mut progress_changed = upload_progress.prepare_historical_replay(replay_generation);
    if same_index_replay {
        // A terminal hold from before this replay stays in the index for its
        // disclosure until a page parses its entity; until then it must not
        // suppress that entity's re-entry, as it does not on the first page.
        let parsed = index
            .file_snapshot_fingerprints
            .values()
            .flatten()
            .collect::<BTreeSet<_>>();
        let holds = index
            .quarantined_snapshot_fingerprints
            .iter()
            .filter(|(fingerprint, record)| {
                parsed.contains(fingerprint)
                    || record.contract_retry_claims.is_some()
                    || record.disposition != SnapshotQuarantineDisposition::UnprovenTerminal
            })
            .map(|(fingerprint, record)| (fingerprint.clone(), record.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        progress_changed |= upload_progress.prepare_quarantine_retries(&holds);
    }
    progress_changed
}
