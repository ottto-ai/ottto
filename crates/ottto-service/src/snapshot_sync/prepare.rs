//! move snapshot prepare into prepare.

use super::activate_source_upload_context;
use super::adopt_legacy_checkpoint_file;
use super::anyhow;
use super::backfill_replay_pending;
use super::claude_contract;
use super::claude_prior_history;
use super::continuation;
use super::current_historical_replay;
use super::current_rfc3339;
use super::current_unix_seconds;
use super::cycle_body_witness_revision;
use super::legacy_policy_scoped_snapshot_index_path;
use super::live_snapshot_retry;
use super::load_backfill_state;
use super::note_claude_history_cutoff_for_cycle;
use super::note_claude_index_rebuild_for_destination;
use super::prepare_upload_progress_for_cycle_with_reoffer;
use super::reason_reoffer;
use super::record_server_scan_directive;
use super::rfc3339_after_minutes;
use super::safe_error;
use super::save_terminal_contract_claims_for_scan;
use super::scan_request_window_days;
use super::small_source_upload;
use super::snapshot_destination_scoped_index_path;
use super::snapshot_index_path;
use super::snapshot_upload_context_fingerprint;
use super::snapshot_upload_destination_namespace;
use super::snapshot_upload_progress_path;
use super::snapshot_v2_index_path;
use super::snapshot_v3_index_path;
use super::source_cadence_wait;
use super::source_kind;
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
use super::LEGACY_SETTLEMENT_RECONCILE_LIMIT_PER_CYCLE;
use super::MAX_BACKFILL_FILES_PER_SOURCE;
use super::MAX_CYCLE_INTERVAL;
use super::SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE;
use super::SNAPSHOT_SYNC_INTERVAL;

// Preparation stays owned by the existing cycle. No partially finalized body
// crosses a collection step.
pub(super) struct SourcePreparation {
    pub(super) retry_authority: Option<live_snapshot_retry::LiveAuthority>,
    pub(super) source: SnapshotSource,
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
    pub(super) legacy_reconciliation_pending: BTreeSet<String>,
    pub(super) active_legacy_reconciliation: BTreeSet<String>,
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
/// ordinary prepare and a Stage 1 continuation page share it).
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
/// namespace (pure; a continuation page must use the same bytes, K5).
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

#[expect(clippy::too_many_arguments, reason = "11 args; no options struct yet")]
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
    retry_enabled: bool,
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
                retry_enabled,
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
    retry_enabled: bool,
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
    if let Some(remaining) = source_cadence_wait(source) {
        eprintln!(
            "local snapshot scan deferred for {}: next scan in {}s on the negotiated cadence; power={:?} effective_interval={}s",
            source.api_slug(),
            remaining.as_secs(),
            continuation::MacPlatformSignals::default().power(),
            with_source_cadence(source, |cadence| cadence.ordinary_interval().min(MAX_CYCLE_INTERVAL))
                .unwrap_or(SNAPSHOT_SYNC_INTERVAL).as_secs()
        );
        return Ok(None);
    }

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
    let upload_destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
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
    let legacy_policy_index_path = legacy_policy_scoped_snapshot_index_path(
        support_dir,
        source,
        upload_policy,
        checkpoint_namespace.as_deref(),
    );
    let v1_index_path = snapshot_destination_scoped_index_path(
        &legacy_policy_index_path,
        &upload_destination_namespace,
    );
    // Adopt both the scan checkpoint and any in-flight accepted-page ledger
    // from the exact pre-v2 namespace. This keeps a normal upgrade—and an
    // upgrade after a partially acknowledged batch—from replaying history.
    if let Some(legacy_namespace) = attribution_context
        .as_ref()
        .map(SessionAttributionContext::legacy_cache_namespace)
    {
        let legacy_policy_index_path = legacy_policy_scoped_snapshot_index_path(
            support_dir,
            source,
            upload_policy,
            Some(&legacy_namespace),
        );
        let legacy_index_path = snapshot_destination_scoped_index_path(
            &legacy_policy_index_path,
            &upload_destination_namespace,
        );
        adopt_legacy_checkpoint_file(&legacy_index_path, &v1_index_path)?;
    }
    // State schema, resumable cursor, and CAS generation are v2-only. Keep the
    // old daemon's path immutable so an overlapping downgrade cannot clobber
    // a new daemon's proof or progress. Adopt the v1 scan checkpoint once, but
    // never adopt v1 upload progress: it lacks entity-grain ACK/quarantine.
    let v2_index_path = snapshot_v2_index_path(&v1_index_path);
    adopt_legacy_checkpoint_file(&v1_index_path, &v2_index_path)?;
    let destination_index_path = snapshot_destination_scoped_index_path(
        &snapshot_index_path(support_dir, source),
        &upload_destination_namespace,
    );
    let index_path = snapshot_v3_index_path(&destination_index_path);
    adopt_legacy_checkpoint_file(&v2_index_path, &index_path)?;
    let legacy_upload_progress_path = snapshot_upload_progress_path(&v2_index_path);
    let upload_progress_path = snapshot_upload_progress_path(&index_path);
    adopt_legacy_checkpoint_file(&legacy_upload_progress_path, &upload_progress_path)?;
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
    let backfill_state = load_backfill_state(support_dir);
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
    if !backfill_pending
        && index.prepare_snapshot_admission_reoffer(SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE)
    {
        // Persist the one-shot policy adoption before progress or scan can
        // advance. Existing generation CAS rejects overlapping stale writers.
        index.save(&index_path)?;
    }
    let admission_reoffer_pending =
        index.snapshot_admission_reoffer_pending_for_scan(source, receipt_window_days);
    let mut legacy_reconciliation_pending = BTreeSet::new();
    if !backfill_pending && index.legacy_settlement_ledger_needs_migration() {
        let (armed, changed) = index.prepare_legacy_settlement_reconciliation(
            source,
            LEGACY_SETTLEMENT_RECONCILE_LIMIT_PER_CYCLE,
        );
        legacy_reconciliation_pending =
            index.legacy_settlement_reconciliation_pending_fingerprints();
        if changed {
            // The bounded cursor and armed identities are durable before the
            // disposable upload ledger can lease this cycle's retry page.
            index.save(&index_path)?;
            if !armed.is_empty() {
                eprintln!(
                    "ottto-service: re-armed {} ambiguous legacy snapshot revision(s) through the existing entity-ACK contract for {}; remaining revisions resume on later source cycles",
                    armed.len(),
                    source.api_slug()
                );
            }
        }
    }
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
    let active_legacy_reconciliation = upload_progress
        .active_quarantine_retries
        .intersection(&legacy_reconciliation_pending)
        .cloned()
        .collect::<BTreeSet<_>>();
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
    let retry_authority = if retry_enabled
        && !index.legacy_settlement_ledger_needs_migration()
        && legacy_reconciliation_pending.is_empty()
        && active_legacy_reconciliation.is_empty()
    {
        live_snapshot_retry::LiveAuthority::capture(
            source,
            home,
            support_dir,
            &activity_hint,
            &upload_destination_namespace,
            &backfill_state,
            client.api_base_seal(),
        )
    } else {
        None
    };
    let sampled_scope = cycle_sampled_scope(
        &account_witness,
        &upload_destination_namespace,
        &index_path,
        request_identity_capture,
    );
    #[cfg(unix)]
    crate::snapshots::begin_source_pass(
        &daemon.transcript_cache,
        support_dir,
        source,
        &index_path,
        &sampled_scope,
        request_identity_capture,
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
        retry_authority,
        source,
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
        legacy_reconciliation_pending,
        active_legacy_reconciliation,
        scan: Some(scan),
    }))
}
