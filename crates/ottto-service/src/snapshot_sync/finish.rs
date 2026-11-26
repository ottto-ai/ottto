//! move snapshot finish into finish.

use super::ack_retention;
use super::anyhow;
use super::apply_backfill_cutoff;

use super::apply_bootstrapped_cache_heads;
use super::apply_claude_local_evidence_to_scan_with_ledger_and_budget;
use super::attach_head_conflict_answers;
use super::bootstrap_cache_heads_with_budget;
use super::cache_full_replacement_negotiated;
use super::cache_head_file_groups;
use super::cache_head_probe;
use super::capture_codex_recovery_evidence;
use super::capture_deferred_cache_head_identities;

use super::claude_evidence_session_ids;
use super::claude_replay_suppressed;
use super::clear_shed_streak;
use super::codex_scan_diagnostics;
use super::continuation;
use super::continuation::PlatformGates;
use super::current_rfc3339;
use super::current_unix_seconds;
use super::defer_source_uploads;
use super::effective_snapshot_upload_body_witness;
use super::exclude_held_effective_body_witness_revision;
use super::finalize_scan_after_policy_with_body_witness;

use super::identity_cache_wire_reserve;
use super::is_upload_outage;
use super::lane::ensure_snapshot_destination_current;
use super::lane::ensure_snapshot_scan_authority;
use super::log_retained_permanent_refusals;
use super::mark_backfill_complete_for_destination;
use super::note_shed_and_backoff;
use super::prepare_codex_recovery_diagnostics;
use super::prepare_snapshot_cache_for_upload;
use super::reason_reoffer;
use super::reconciliation_agent_status;
use super::refused_entity_state;
use super::report_status_with_fresh_relay_token;
use super::safe_error;

use super::shed_backoff;
use super::snapshot_batch_request;
use super::snapshot_entity_deferred;
use super::snapshot_manifest_window;
use super::snapshot_upload_batch_class;
use super::snapshot_upload_body_witness;
use super::snapshot_upload_error_class;
use super::source_kind;
#[cfg(test)]
use super::tests;
use super::update_backfill_state;
use super::update_detected_uses_cache;
use super::upload::cache_session_key;
use super::upload_failure_diagnostic;
use super::upload_resumable_batches_with_literal_families;
use super::with_bootstrap_deferred;
use super::with_retained_refusal_conflicts;
use super::with_source_cadence;
use super::with_source_cadence_state;

use super::BTreeMap;
use super::BTreeSet;
use super::BatchAuthorizationRejected;
use super::BatchRejected;
use super::CollectorState;
use super::CollectorStatus;
use super::Context;
use super::InplaceRetryBudget;
use super::Instant;
use super::LocalDaemon;
use super::LocalDeviceBinding;

use super::OffsetDateTime;
use super::Path;
use super::PermanentRefusalCounts;
use super::Result;
use super::ResumableUploadResult;
use super::Rfc3339;
use super::ScanIndex;

use super::SnapshotBatchPreflightRejected;
use super::SnapshotBatchRequest;
use super::SnapshotItem;
use super::SnapshotSource;
use super::SnapshotUploadErrorClass;
use super::SourcePreparation;
use super::SourceScanResult;
use super::SyncCounts;
use super::TerminalManifestSource;
use super::UnsettledUploadCause;
use super::CHECKPOINTED_PAGES_SETTLED_WITH_TERMINAL_BOUND_HOLDS;
use super::MAX_CYCLE_INTERVAL;
use super::SNAPSHOT_SCHEMA_VERSION;
use super::SNAPSHOT_SYNC_INTERVAL;

#[cfg(test)]
use super::snapshot_quarantine_witness;
use super::ErrorKind;
use super::Mutex;
use super::OnceLock;
use super::PathBuf;
use super::RefusedSnapshotIndexes;
use super::ShedSnapshotIndexes;
use super::SnapshotProgressLock;
use super::SnapshotQuarantineDisposition;
use super::SnapshotSourceManifest;
use super::SnapshotUploadPolicy;
use super::SnapshotUploadProgress;
use crate::local_resource_diagnostics::pass_outcomes;

/// Commit a `Completed` upload that left local holds. Every uploaded entity was
/// accepted or unchanged; only the held revisions are unsettled.
///
/// A hold that owes a clean follow-up (`progress_blocking`) keeps the
/// conservative partial commit and marks the sweep unsettled, so the
/// generation needs one clean follow-up. Otherwise every hold is
/// non-progressing (account deferrals and bound authority holds, including
/// bound RetryPending families under the path-(a) bridge): held keys keep their
/// committed revision, every other key commits as the no-hold save would, and
/// the traversal may settle. The caller keeps backfill and replay completion
/// pending, and the durable hold disclosure keeps health red.
///
/// A non-progressing hold in a Claude family that retains authority evidence
/// but has no committed entry to restore, as after a historical replay reset,
/// still blocks: settling it would let a later page of the same traversal
/// treat the still-present family as vanished. A never-committed member bound
/// by its committed family's terminal quarantine settles with a delivery-free
/// membership entry instead, so the family census stays complete.
pub(super) fn commit_completed_with_local_holds(
    index: ScanIndex,
    committed_index: &ScanIndex,
    upload_progress: &SnapshotUploadProgress,
    locally_held_fingerprints: &BTreeSet<String>,
    account_deferred_held_fingerprints: &BTreeSet<String>,
    progress_blocking: bool,
) -> ScanIndex {
    if !progress_blocking {
        if index.locally_held_keys_restorable(
            committed_index,
            locally_held_fingerprints,
            account_deferred_held_fingerprints,
        ) {
            return index.into_locally_held_keys_reverted(
                committed_index,
                locally_held_fingerprints,
                account_deferred_held_fingerprints,
            );
        }
        crate::local_resource_diagnostics::claude_reread::held_reason(
            crate::local_resource_diagnostics::claude_reread::HeldReason::NotRestorable,
        );
    }
    let mut index = index.committable_subset_for_upload(
        committed_index,
        &upload_progress.accepted_fingerprints,
        &upload_progress.quarantined_fingerprints,
        locally_held_fingerprints,
        true,
    );
    index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::CompletedBlockingHolds);
    index
}

/// Local holds classified once per page, after finalization and before upload.
/// Every upload outcome settles against this one classification.
pub(super) struct LocalHoldSettlement {
    /// Sessions held locally on this page.
    pub(super) held_entity_count: usize,
    /// RetryPending Claude authority families anywhere in the index. They keep
    /// full completion (backfill, replay) pending, but since the path-(a)
    /// bridge they no longer make an unrelated page progress-blocking.
    pub(super) retry_pending_family_count: usize,
    pub(super) held_fingerprints: BTreeSet<String>,
    pub(super) account_deferred_fingerprints: BTreeSet<String>,
    pub(super) progress_blocking: bool,
}

pub(super) struct AccountAuditRelease<'a> {
    pub(super) previous: &'a ScanIndex,
    pub(super) roots: &'a [PathBuf],
    pub(super) backfill_window_days: u64,
}

impl LocalHoldSettlement {
    /// Record the durable account-hold disclosure, classify which holds a
    /// later page could still change, and remove every held entity from the
    /// upload. The disclosure is durable before upload, so every checkpoint
    /// below carries it. Only Claude account deferrals are settled this way;
    /// other sources keep every account deferral progress-blocking.
    pub(super) fn classify(
        source: SnapshotSource,
        index: &mut ScanIndex,
        scan_result: &mut crate::snapshots::SourceScanResult,
        disposition: &crate::snapshots::ClaudeUsageAuthorityDisposition,
    ) -> Self {
        let held_entity_count = disposition.quarantined_entity_count();
        let held_fingerprints = disposition.quarantined_fingerprints(&scan_result.snapshots);
        let account_deferred_fingerprints =
            disposition.account_deferred_fingerprints(&scan_result.snapshots);
        let account_holds_recorded = source == SnapshotSource::ClaudeCode
            && index.record_claude_account_deferred_holds(
                scan_result.completed_parses(),
                &disposition.account_deferred_tokens(&scan_result.snapshots),
            );
        if held_entity_count > 0 {
            let counts = serde_json::json!({
                "request_owned": disposition.request_owned_hold_reasons,
                "account_binding": account_deferred_fingerprints.len(),
                "authority_demotion": disposition.context_file_birth.demotion_quarantined_session_count,
            });
            eprintln!(
                "local snapshot sync: hold disposition source={} held_entities={} counts={counts}",
                source.api_slug(),
                held_entity_count,
            );
        }
        scan_result.remember_withheld_content(index);
        let progress_blocking_held_fingerprints = disposition.progress_blocking_held_fingerprints(
            &scan_result.snapshots,
            index,
            account_holds_recorded,
        );
        disposition.retain_uploadable(&mut scan_result.snapshots);
        crate::snapshots::record_lineage_parentless_while_incomplete(
            source,
            &scan_result.snapshots,
            index,
        );
        let retry_pending_family_count = index.claude_usage_authority_pending_count();
        Self {
            held_entity_count,
            retry_pending_family_count,
            held_fingerprints,
            account_deferred_fingerprints,
            progress_blocking: !progress_blocking_held_fingerprints.is_empty(),
        }
    }

    pub(super) fn any(&self) -> bool {
        self.retry_pending_family_count > 0 || self.held_entity_count > 0
    }

    /// Whether this page itself held any entity.
    pub(super) fn page_held(&self) -> bool {
        self.held_entity_count > 0
    }
}

/// The index selected by an upload outcome, and its transport/local-hold
/// settlement. Authority corrections are finalized on that selected index.
pub(super) struct UploadIndexSettlement {
    pub(super) index: ScanIndex,
    pub(super) fully_settled: bool,
}

/// Settled for a recency tier: account holds wait outside the import.
pub(super) fn tier_settled(
    settled: bool,
    transport_settled: bool,
    holds: &LocalHoldSettlement,
) -> bool {
    settled
        || (transport_settled
            && holds.retry_pending_family_count == 0
            && holds
                .held_fingerprints
                .is_subset(&holds.account_deferred_fingerprints))
}

/// A persisted account hold was never uploaded, so the backfill and replay it
/// belongs to stay pending even on a page that did not revisit it.
pub(super) fn upload_settled_without_account_holds(index: &ScanIndex, settled: bool) -> bool {
    settled && index.claude_account_deferred_hold_count() == 0
}

/// Settle a `Completed` upload: every uploaded entity was accepted or
/// unchanged, and only local holds can remain unsettled.
pub(super) fn settle_completed_upload(
    index: ScanIndex,
    committed_index: &ScanIndex,
    upload_progress: &SnapshotUploadProgress,
    holds: &LocalHoldSettlement,
) -> UploadIndexSettlement {
    if !holds.page_held() {
        // RetryPending debt elsewhere settles this page as a no-hold page
        // would, and only keeps full completion pending.
        let fully_settled = upload_settled_without_account_holds(&index, !holds.any());
        return UploadIndexSettlement {
            index,
            fully_settled,
        };
    }
    let index = commit_completed_with_local_holds(
        index,
        committed_index,
        upload_progress,
        &holds.held_fingerprints,
        &holds.account_deferred_fingerprints,
        holds.progress_blocking,
    );
    eprintln!(
        "local snapshot sync retained {} Claude usage family/families and {} revised \
         entity/entities with unproven authority or session ownership; healthy siblings settled \
         and the retained revisions remain pending for bounded retry",
        holds.retry_pending_family_count, holds.held_entity_count
    );
    UploadIndexSettlement {
        index,
        fully_settled: false,
    }
}

#[cfg(test)]
pub(crate) fn classify_holds_for_test(
    source: SnapshotSource,
    index: &mut ScanIndex,
    scan: &mut SourceScanResult,
) {
    LocalHoldSettlement::classify(
        source,
        index,
        scan,
        &crate::snapshots::ClaudeUsageAuthorityDisposition::default(),
    );
}

#[cfg(test)]
pub(super) fn classify_account_release_for_test(
    index: &mut ScanIndex,
    scan: &mut SourceScanResult,
) -> (LocalHoldSettlement, SnapshotUploadProgress) {
    let source = SnapshotSource::ClaudeCode;
    let holds = LocalHoldSettlement::classify(
        source,
        index,
        scan,
        &crate::snapshots::ClaudeUsageAuthorityDisposition::default(),
    );
    assert!(!holds.page_held());
    let mut progress =
        SnapshotUploadProgress::new(format!("{:064x}", 99), snapshot_quarantine_witness(source));
    let groups = cache_head_file_groups(index);
    for item in &scan.snapshots {
        progress
            .record_pending_cache_head_identity(
                item.source_file_fingerprint.as_ref(),
                &item.snapshot_fingerprint,
                &cache_session_key(&item.source_session_id),
                &groups,
                true,
            )
            .unwrap();
    }
    assert!(
        !progress.pending_cache_heads.is_empty(),
        "required head bindings recorded"
    );
    (holds, progress)
}

#[cfg(test)]
pub(crate) fn accept_account_release_for_test(
    mut index: ScanIndex,
    previous: &ScanIndex,
    scan: &mut SourceScanResult,
    roots: &[PathBuf],
) -> ScanIndex {
    let (holds, mut progress) = classify_account_release_for_test(&mut index, scan);
    progress.accepted_fingerprints.extend(
        scan.snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone()),
    );
    index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    let mut settled = settle_completed_upload(index, previous, &progress, &holds);
    assert!(settled.fully_settled);
    scan.preserve_released_account_audits(
        &mut settled.index,
        previous,
        roots,
        crate::snapshots::BACKFILL_WINDOW_DAYS,
    );
    settled.index
}

#[cfg(test)]
pub(crate) fn checkpoint_account_release_for_test(
    mut index: ScanIndex,
    previous: &ScanIndex,
    scan: &mut SourceScanResult,
    roots: &[PathBuf],
    paths: (&Path, &Path),
) -> Result<ScanIndex> {
    let (holds, mut progress) = classify_account_release_for_test(&mut index, scan);
    progress.destination_namespace_hash =
        crate::snapshots::e2_pipeline_scan_fixture::binding_for_test(paths.0).1;
    let (progress_path, mut progress) = tests::routed_progress(previous, paths.0, progress);
    // Actual no-ACK partial save restores the prior accepted entry before
    // transferring retry custody. Head binding above still had to succeed.
    progress.save(&progress_path)?;
    checkpoint_partial_snapshot_index_with_audit_release(
        &index,
        previous,
        &progress,
        &scan.snapshots,
        Some(scan),
        &holds.held_fingerprints,
        paths.0,
        &progress_path,
        || Ok(()),
        Some(UnsettledUploadCause::UploadError),
        Some(AccountAuditRelease {
            previous,
            roots,
            backfill_window_days: crate::snapshots::BACKFILL_WINDOW_DAYS,
        }),
        Default::default(),
    )
}

/// The page items a server answer names: an indexed validation rejection
/// (422), an identity-deferral shed (503) or ACK refs that echoed another
/// body witness. `None` when nothing is named or a location falls outside
/// this page; that failure keeps its own path (a shed stays a whole-pass shed).
pub(super) fn server_named_items(
    error: &anyhow::Error,
    indices: &[usize],
) -> Option<BTreeSet<usize>> {
    let named = if let Some(named) = error.downcast_ref::<ShedSnapshotIndexes>() {
        &named.0
    } else if let Some(named) = error.downcast_ref::<RefusedSnapshotIndexes>() {
        &named.0
    } else {
        error
            .downcast_ref::<BatchRejected>()?
            .snapshot_indexes
            .as_ref()?
    };
    named
        .iter()
        .map(|index| indices.get(*index).copied())
        .collect()
}

/// Process-local, content-free count of records the attempt-count ladder made
/// `UnprovenTerminal` (all sources), apart from server verdicts, so a later
/// `unproven_terminal` rise can be attributed.
pub(super) static UNPROVEN_TERMINAL_ATTEMPT_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Settle a `Deferred` or `Rejected` upload. Retryable or locally unproven
/// entities keep replay pending and owe a clean follow-up. A validated
/// permanent refusal settles transport and traversal; its separate health
/// still discloses the rejected usage. Its holds settle exactly as on a
/// `Completed` page: when every hold on this page is non-progressing and
/// restorable, held keys keep their committed revision and the traversal may
/// settle; backfill and replay stay pending. A RetryPending family elsewhere
/// keeps only full completion pending (path-(a) bridge).
pub(super) fn settle_checkpointed_upload(
    index: ScanIndex,
    committed_index: &ScanIndex,
    upload_progress: &SnapshotUploadProgress,
    holds: &LocalHoldSettlement,
    resolved_permanent_rejections: bool,
    deferred: UnsettledUploadCause,
) -> UploadIndexSettlement {
    let terminal_bound_holds = resolved_permanent_rejections
        && holds.page_held()
        && !holds.progress_blocking
        && index.locally_held_keys_restorable(
            committed_index,
            &holds.held_fingerprints,
            &holds.account_deferred_fingerprints,
        );
    let mut index = if terminal_bound_holds {
        CHECKPOINTED_PAGES_SETTLED_WITH_TERMINAL_BOUND_HOLDS
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        index.into_locally_held_keys_reverted(
            committed_index,
            &holds.held_fingerprints,
            &holds.account_deferred_fingerprints,
        )
    } else if holds.page_held() || !resolved_permanent_rejections {
        // Refusals already have quarantine custody. Every entity that is not
        // held settles as on a clean page, semantic no-ops not resent here
        // included.
        index.committable_subset_for_upload(
            committed_index,
            &upload_progress.accepted_fingerprints,
            &upload_progress.quarantined_fingerprints,
            &holds.held_fingerprints,
            true,
        )
    } else {
        index
    };
    let settled = resolved_permanent_rejections && (!holds.page_held() || terminal_bound_holds);
    if !settled {
        index.mark_bounded_sweep_unsettled_by(if resolved_permanent_rejections {
            UnsettledUploadCause::RejectedWithHolds
        } else {
            deferred
        });
    }
    let fully_settled = upload_settled_without_account_holds(&index, settled && !holds.any());
    UploadIndexSettlement {
        index,
        fully_settled,
    }
}

/// Fold the upload ledger into the index after any outcome that reaches the
/// durable save.
pub(super) fn settle_index_after_upload(
    index: &mut ScanIndex,
    committed_index: &ScanIndex,
    upload_progress: &SnapshotUploadProgress,
) {
    index.reconcile_codex_recovery_settlement(
        committed_index,
        &upload_progress.accepted_fingerprints,
    );
    index.retain_quarantined_fingerprints(&upload_progress.quarantined_fingerprints);
    index.record_accepted_snapshot_fingerprints(&upload_progress.accepted_fingerprints);
}

/// Correction completion depends on the final selected file/empty facts. In
/// particular, the last no-body drain must precede the completion decision.
#[expect(
    clippy::too_many_arguments,
    reason = "the selected index, page facts, correction candidates and drain ledger"
)]
pub(super) fn settle_upload_corrections_after_selection(
    index: &mut ScanIndex,
    scan: &SourceScanResult,
    committed_index: &ScanIndex,
    progress: &SnapshotUploadProgress,
    candidates: &[crate::snapshots::ClaudeProofCorrectionCandidate],
    cutoff_candidates: &[crate::snapshots::ClaudeCutoffCorrectionCandidate],
    transport_fully_settled: bool,
    body_drains: &mut crate::snapshots::ClaudeProofBodyDrains,
) -> bool {
    // This drain is deliberately unavailable to partial/deferred/shed/error outcomes.
    // Both existing durable refusal carriers must bind the exact current body.
    // It settles against the selected entries, but a later account-audit
    // release can still clear one; its drains join the finish restore.
    if transport_fully_settled {
        let drains = index.settle_claude_proof_corrections_with_permanent(
            committed_index,
            candidates,
            &progress.accepted_fingerprints,
            &progress.accepted_body_witnesses,
            |fingerprint, body| {
                progress
                    .permanent_rejections
                    .get(fingerprint)
                    .is_some_and(|rejection| rejection.body_witness == body)
                    && progress
                        .quarantined_fingerprints
                        .get(fingerprint)
                        .is_some_and(|record| {
                            record.disposition == SnapshotQuarantineDisposition::UnprovenTerminal
                                && record.upload_body_witness.as_deref() == Some(body)
                        })
            },
        );
        body_drains.append(drains);
    }
    index.settle_cutoff_claude_proof_corrections(cutoff_candidates);
    index.settle_empty_claude_proof_corrections(scan);
    // Correction members the history gate holds wait for it; they are counted,
    // not blocking.
    let (blocking, deferred) = index.claude_authority_proof_correction_blocking();
    if deferred > 0 {
        eprintln!(
            "local snapshot proof corrections deferred to the history gate for {}: members={deferred}",
            scan.source.api_slug()
        );
        crate::local_resource_diagnostics::claude_history_proof_correction_deferred(deferred);
    }
    transport_fully_settled && !blocking
}

pub(super) struct SelectedSettlementInputs<'a> {
    pub(super) scan: &'a SourceScanResult,
    pub(super) committed_index: &'a ScanIndex,
    pub(super) progress: &'a SnapshotUploadProgress,
    pub(super) candidates: &'a [crate::snapshots::ClaudeProofCorrectionCandidate],
    pub(super) cutoff_candidates: &'a [crate::snapshots::ClaudeCutoffCorrectionCandidate],
    pub(super) transport_fully_settled: bool,
    pub(super) body_drains: crate::snapshots::ClaudeProofBodyDrains,
    pub(super) audit_release: Option<AccountAuditRelease<'a>>,
}

/// The finish order after save selection, shared with the proof-correction
/// pipeline harness so its regressions guard this order: correction settle,
/// account-audit release (which can clear a drained entry's revision), then the
/// body-drain restore. Returns whether the page is fully settled.
pub(super) fn finish_selected_settlement(
    index: &mut ScanIndex,
    inputs: SelectedSettlementInputs<'_>,
) -> bool {
    let SelectedSettlementInputs {
        scan,
        committed_index,
        progress,
        candidates,
        cutoff_candidates,
        transport_fully_settled,
        mut body_drains,
        audit_release,
    } = inputs;
    let mut fully_settled = settle_upload_corrections_after_selection(
        index,
        scan,
        committed_index,
        progress,
        candidates,
        cutoff_candidates,
        transport_fully_settled,
        &mut body_drains,
    );
    if let Some(release) = audit_release {
        scan.preserve_released_account_audits(
            index,
            release.previous,
            release.roots,
            release.backfill_window_days,
        );
    }
    // After every selected-entry restore and the account-audit release, which
    // can clear a drained entry's revision: a drain (pre-selection or settlement)
    // whose entry this save does not keep stays owed.
    if index.restore_unselected_claude_proof_body_drains(body_drains) {
        fully_settled = false;
    }
    fully_settled
}

pub(super) fn apply_backfill_cutoff_with_claude_corrections(
    scan: &mut SourceScanResult,
    index: &ScanIndex,
    disposition: &crate::snapshots::ClaudeUsageAuthorityDisposition,
    state: &crate::backfill::BackfillState,
) -> (
    usize,
    Vec<crate::snapshots::ClaudeCutoffCorrectionCandidate>,
) {
    let mut candidates = index.capture_claude_cutoff_corrections(scan, disposition);
    let removed = apply_backfill_cutoff(&mut scan.snapshots, state);
    ScanIndex::retain_fully_cutoff_corrections(&mut candidates, &scan.snapshots);
    (removed, candidates)
}

/// Last computed scan-index manifest per (upload destination, source).
///
/// The check-in heartbeat runs on its own clock and does not know which
/// policy/attribution/destination-scoped index path the sync cycle chose, so it
/// cannot load the index itself. The sync cycle publishes the manifest it
/// already computed from the index it already had open, and both receipt shapes
/// read it from here. Missing means "no scan has completed in this process yet
/// for this destination", which is reported as an absent manifest rather than a
/// zeroed one.
///
/// The destination is part of the key, not an afterthought: a setup or account
/// switch replaces the relay binding without restarting the daemon (which is why
/// `ensure_snapshot_destination_current` exists), and a manifest keyed by source
/// alone would report the previous account's entity count and rolling hash to the
/// new one — a wrong witness and a disclosure of the previous account's local
/// session set.
static SOURCE_MANIFESTS: OnceLock<Mutex<BTreeMap<(String, &'static str), SnapshotSourceManifest>>> =
    OnceLock::new();

type SourceManifestCache = Mutex<BTreeMap<(String, &'static str), SnapshotSourceManifest>>;

pub(super) fn source_manifests() -> &'static SourceManifestCache {
    SOURCE_MANIFESTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(super) fn publish_source_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
    manifest: SnapshotSourceManifest,
) {
    // These mutations preserve BTreeMap invariants even if an unrelated
    // consumer panics while holding the process-global cache. Recover poison
    // so one caught panic cannot permanently suppress every future manifest.
    let mut manifests = source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // One destination at a time: a machine that has moved is never coming
    // back to the old binding with the same secret, so retaining its
    // manifests would only risk reporting them.
    manifests.retain(|(namespace, _), _| namespace == destination_namespace);
    manifests.insert(
        (destination_namespace.to_string(), source.api_slug()),
        manifest,
    );
}

pub(super) fn withdraw_source_manifest(destination_namespace: &str, source: SnapshotSource) {
    source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&(destination_namespace.to_string(), source.api_slug()));
}

pub(super) fn save_index_and_publish_manifest(
    index: &mut ScanIndex,
    index_path: &Path,
    destination_namespace: &str,
    source: SnapshotSource,
    census_complete: bool,
    window_start: &str,
    window_end: &str,
) -> Result<()> {
    // The server may already hold this pass's new entities. Keep the previous
    // process-cache witness withdrawn until the exact replacement index is
    // durable; a failed CAS/save or manifest derivation must not let a
    // concurrent heartbeat repeat stale agreement.
    withdraw_source_manifest(destination_namespace, source);
    crate::local_resource_diagnostics::state_save_start(source.api_slug());
    index.save(index_path)?;
    if census_complete {
        publish_source_manifest(
            destination_namespace,
            source,
            index.manifest_for_window(source, window_start, window_end)?,
        );
    }
    Ok(())
}

// Exercise the real durable-save/publication boundary from decoder rescans.
#[cfg(test)]
pub(crate) fn decode_hold_manifest_published_for_test(
    index: &mut ScanIndex,
    path: &Path,
    source: SnapshotSource,
    complete: bool,
) -> Result<bool> {
    let namespace = "lenient-decode-rescan";
    save_index_and_publish_manifest(
        index,
        path,
        namespace,
        source,
        complete,
        "2026-01-01T00:00:00Z",
        "2026-10-22T00:00:00Z",
    )?;
    Ok(cached_source_manifest(namespace, source).is_some())
}

/// Freshness fixtures exercise the real returning-quarantine and exact ACK path.
#[cfg(test)]
pub(crate) fn ack_current_again_quarantines_for_test(
    index: &mut ScanIndex,
    items: &[SnapshotItem],
) -> BTreeMap<String, String> {
    use tests::claude_money_e2_pipeline_tests::{ack, upload_source_under};
    let source = SnapshotSource::ClaudeCode;
    let mut progress =
        SnapshotUploadProgress::new("a".repeat(64), snapshot_quarantine_witness(source));
    progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    assert!(progress.retain_current_quarantines(&index.current_snapshot_fingerprints(), index));
    assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
    let (status, batches, _) = upload_source_under(
        source,
        SnapshotUploadPolicy::default(),
        items,
        &mut progress,
        ack,
    );
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(batches.len(), 1);
    assert!(progress.quarantined_fingerprints.is_empty());
    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    progress.fresh_context_body_acks
}

#[cfg(test)]
pub(crate) fn checkpoint_unselected_for_test(
    index: &ScanIndex,
    committed: &ScanIndex,
    scan: &SourceScanResult,
    index_path: &Path,
    progress_path: &Path,
) -> Result<ScanIndex> {
    checkpoint_page_for_test(index, committed, scan, index_path, progress_path, false)
}

#[cfg(test)]
pub(crate) fn checkpoint_page_for_test(
    index: &ScanIndex,
    committed: &ScanIndex,
    scan: &SourceScanResult,
    index_path: &Path,
    progress_path: &Path,
    accept: bool,
) -> Result<ScanIndex> {
    let mut progress = SnapshotUploadProgress::load(
        progress_path,
        &format!("{:064x}", 588),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )?;
    if accept {
        use tests::claude_money_e2_pipeline_tests::{ack, upload_source_under};
        let mut index = index.clone();
        let mut scan = scan.clone();
        let holds = LocalHoldSettlement::classify(
            scan.source,
            &mut index,
            &mut scan,
            &crate::snapshots::ClaudeUsageAuthorityDisposition::default(),
        );
        assert!(!holds.any(), "the completed fixture page has no holds");
        let (result, _, _) = upload_source_under(
            scan.source,
            SnapshotUploadPolicy::default(),
            &scan.snapshots,
            &mut progress,
            ack,
        );
        anyhow::ensure!(
            result? == ResumableUploadResult::Completed,
            "fixture exact ACK"
        );
        progress.save_fixture(progress_path)?;
        index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        crate::snapshots::e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
            &mut index,
            &scan.snapshots,
            &progress.fresh_context_body_acks,
        );
        index.save(index_path)?;
        return Ok(index);
    }
    progress.save_fixture(progress_path)?;
    checkpoint_partial_snapshot_index_with_audit_release(
        index,
        committed,
        &progress,
        &scan.snapshots,
        Some(scan),
        &BTreeSet::new(),
        index_path,
        progress_path,
        || Ok(()),
        None,
        None,
        Default::default(),
    )
}

/// Preserve only delivery-owned file checkpoints on an unfinished upload.
/// Hold the progress lock through index CAS: neither an unsaved ACK nor a
/// racing ledger generation may certify the scan's new file/body witnesses.
#[expect(clippy::too_many_arguments, reason = "test helper, 9 case inputs")]
#[cfg(test)]
pub(super) fn checkpoint_partial_snapshot_index(
    index: &ScanIndex,
    committed_index: &ScanIndex,
    progress: &SnapshotUploadProgress,
    snapshots: &[SnapshotItem],
    correction_scan: Option<&SourceScanResult>,
    locally_held: &BTreeSet<String>,
    index_path: &Path,
    progress_path: &Path,
    validate_destination: impl FnOnce() -> Result<()>,
) -> Result<ScanIndex> {
    checkpoint_partial_snapshot_index_with_audit_release(
        index,
        committed_index,
        progress,
        snapshots,
        correction_scan,
        locally_held,
        index_path,
        progress_path,
        validate_destination,
        None,
        None,
        Default::default(),
    )
}

/// Fixed labels for the partial-checkpoint steps whose own error carries no
/// phrase `safe_error` knows. The checkpoint's other failures already carry
/// fixed messages naming the partial checkpoint (listed in
/// `PARTIAL_CHECKPOINT_FAILURES`).
pub(super) const CHECKPOINT_PROGRESS_LOCK: &str = "partial checkpoint: acquire progress lock";

pub(super) const CHECKPOINT_ACK_HANDOFF: &str = "partial checkpoint: stage ACK retirement handoff";

pub(super) const CHECKPOINT_VALIDATE_DESTINATION: &str = "partial checkpoint: validate destination";

pub(super) const CHECKPOINT_INDEX_SAVE: &str = "partial checkpoint: save scan index";

/// Every partial-checkpoint failure label `safe_error` may print, so a failed
/// checkpoint names its step instead of the bare "sync failed".
pub(super) const PARTIAL_CHECKPOINT_FAILURES: [&str; 9] = [
    CHECKPOINT_PROGRESS_LOCK,
    "read snapshot progress for partial checkpoint",
    "parse snapshot progress for partial checkpoint",
    "partial checkpoint lacks a source witness",
    "snapshot progress changed before partial checkpoint",
    "conflicting snapshot bodies before partial checkpoint",
    CHECKPOINT_ACK_HANDOFF,
    CHECKPOINT_VALIDATE_DESTINATION,
    CHECKPOINT_INDEX_SAVE,
];

#[allow(
    clippy::too_many_arguments,
    reason = "partial checkpoint keeps the selected body, audit and drain inputs together"
)]
pub(super) fn checkpoint_partial_snapshot_index_with_audit_release(
    index: &ScanIndex,
    committed_index: &ScanIndex,
    progress: &SnapshotUploadProgress,
    snapshots: &[SnapshotItem],
    correction_scan: Option<&SourceScanResult>,
    locally_held: &BTreeSet<String>,
    index_path: &Path,
    progress_path: &Path,
    validate_destination: impl FnOnce() -> Result<()>,
    cause: Option<UnsettledUploadCause>,
    audit_release: Option<AccountAuditRelease<'_>>,
    body_drains: crate::snapshots::ClaudeProofBodyDrains,
) -> Result<ScanIndex> {
    let progress_owner =
        SnapshotProgressLock::acquire(progress_path).context(CHECKPOINT_PROGRESS_LOCK)?;
    let progress_owner = if crate::snapshots::state_v2_growth_retention_active(index) {
        progress_owner.for_v2(progress_path)
    } else {
        progress_owner
    };
    let durable: SnapshotUploadProgress = if progress.rows.is_some() {
        progress.durable_rows(index_path, &progress_owner)?
    } else {
        match std::fs::read(progress_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(anyhow::Error::from)
                .context("parse snapshot progress for partial checkpoint")?,
            Err(error) if error.kind() == ErrorKind::NotFound && progress.generation == 0 => {
                SnapshotUploadProgress::new(
                    progress.destination_namespace_hash.clone(),
                    progress
                        .active_quarantine_witness
                        .clone()
                        .ok_or_else(|| anyhow!("partial checkpoint lacks a source witness"))?,
                )
            }
            Err(error) => {
                return Err(error).context("read snapshot progress for partial checkpoint")
            }
        }
    };
    // Refuse only a real concurrent writer, as `save()` does. The accepted
    // and quarantined sets and the upload-context stamp read `durable`.
    if !progress.same_writer(durable.stamp()) {
        return Err(anyhow!(
            "snapshot progress changed before partial checkpoint"
        ));
    }
    let mut current_bodies = BTreeMap::new();
    for item in snapshots {
        let witness = snapshot_upload_body_witness(item);
        if current_bodies
            .insert(item.snapshot_fingerprint.as_str(), witness.clone())
            .is_some_and(|previous| previous != witness)
        {
            return Err(anyhow!(
                "conflicting snapshot bodies before partial checkpoint"
            ));
        }
    }
    let accepted = durable
        .accepted_fingerprints
        .iter()
        .filter(|fingerprint| {
            durable.accepted_body_witnesses.get(*fingerprint)
                == current_bodies.get(fingerprint.as_str())
                && current_bodies.contains_key(fingerprint.as_str())
        })
        .cloned()
        .collect();
    let quarantined = durable
        .quarantined_fingerprints
        .iter()
        .filter(|(fingerprint, record)| {
            record.upload_body_witness.as_ref() == current_bodies.get(fingerprint.as_str())
                && current_bodies.contains_key(fingerprint.as_str())
        })
        .map(|(fingerprint, record)| (fingerprint.clone(), record.clone()))
        .collect();
    let mut committable = index.committable_subset_for_upload(
        committed_index,
        &accepted,
        &quarantined,
        locally_held,
        false,
    );
    if let Some(scan) = correction_scan {
        committable.requeue_unkept_scanned_keys(scan.source, index, locally_held);
    }
    if let Some(scan) = correction_scan {
        // Settle no-body grants only against the file/empty/map facts
        // actually selected for this save, after any old-entry restoration.
        committable.settle_empty_claude_proof_corrections(scan);
    }
    if let (Some(scan), Some(release)) = (correction_scan, audit_release) {
        scan.preserve_released_account_audits(
            &mut committable,
            release.previous,
            release.roots,
            release.backfill_window_days,
        );
    }
    // After every selected-entry restore above: a drain whose entry this
    // save does not keep stays owed.
    committable.restore_unselected_claude_proof_body_drains(body_drains);
    committable
        .mark_bounded_sweep_unsettled_by(cause.unwrap_or(UnsettledUploadCause::Unattributed));
    let census_absent = progress.complete_census_ack_retirements(
        index,
        correction_scan.is_some_and(|scan| scan.census_complete),
    );
    let scan_referenced = progress.ack_retirement_scan_references(committed_index, index);
    progress
        .stage_ack_retirement_handoff_with_scan(
            committed_index,
            &mut committable,
            &scan_referenced,
            locally_held,
            &census_absent,
        )
        .context(CHECKPOINT_ACK_HANDOFF)?;
    let context_rearms = committable.accept_file_upload_context_acks(
        &progress.split_context_receipt_candidates(),
        &progress.fresh_context_body_acks,
        &progress.covered_stale_bodies(),
    );
    committable.stamp_entity_upload_context_acks(
        &durable.destination_namespace_hash,
        &durable.accepted_body_witnesses,
        &durable.accepted_body_contexts,
    );
    committable.accept_request_contributions(progress);
    validate_destination().context(CHECKPOINT_VALIDATE_DESTINATION)?;
    committable
        .save_with_progress_owner(index_path, &progress_owner)
        .context(CHECKPOINT_INDEX_SAVE)?;
    if let Some(scan) = correction_scan {
        scan.report_discovery_growth_after_save(&committable);
        context_rearms.emit(scan.source);
    }
    Ok(committable)
}

impl ScanIndex {
    pub(super) fn accept_request_contributions(&mut self, progress: &SnapshotUploadProgress) {
        let covered = progress.covered_stale_bodies();
        let mut seen = BTreeSet::new();
        for (fp, (slot, rows)) in &progress.request_contributions {
            if progress.fresh_context_body_acks.get(fp) != Some(&rows.body_witness)
                || progress.quarantined_fingerprints.contains_key(fp)
                || covered.get(fp) == Some(&rows.body_witness)
            {
                continue;
            }
            if seen.insert(slot) {
                self.upload_context_proof
                    .request_contributions
                    .insert(slot.clone(), rows.clone());
            } else {
                self.upload_context_proof.request_contributions.remove(slot);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn accept_request_contributions_for_test(
    index: &mut ScanIndex,
    items: &[SnapshotItem],
    acks: &BTreeMap<String, String>,
) {
    let mut progress = SnapshotUploadProgress::new(
        "test".into(),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    );
    progress.fresh_context_body_acks = acks.clone();
    progress.request_contributions = items
        .iter()
        .filter(|item| {
            crate::snapshots::claude_request_money::request_owned_family_root(item).is_some()
        })
        .map(|item| {
            (
                item.snapshot_fingerprint.clone(),
                crate::snapshots::upload_context_receipt::SlotRows::capture(item),
            )
        })
        .collect();
    index.accept_request_contributions(&progress);
}

pub(super) fn cached_source_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
) -> Option<SnapshotSourceManifest> {
    source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(destination_namespace.to_string(), source.api_slug()))
        .cloned()
}

#[cfg(test)]
pub(super) fn clear_source_manifests_for_test() {
    source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}
/// Collection health: a pass that got past its authority fence scanned.
fn record_collection_complete(source: SnapshotSource, at: &str) {
    with_source_cadence_state(source, |cadence| {
        if let Some(pulse) = cadence.collection.as_mut() {
            pulse.complete(at);
        }
    });
}

/// What a finish reads and never changes from the local evidence fold on: fixed
/// values of the preparation and the caller's handles, built once before the fold.
#[derive(Clone, Copy)]
struct FinishEnv<'a> {
    source: SnapshotSource,
    client: &'a super::SnapshotApiClient,
    device: &'a LocalDeviceBinding,
    device_secret: &'a str,
    machine_id: &'a str,
    support_dir: &'a Path,
    index_path: &'a Path,
    activity_hint: &'a crate::snapshot_client::ActivityHintResponse,
    receipt_window_days: u64,
    backfill_pending: bool,
    backfill_state: &'a crate::backfill::BackfillState,
    upload_destination_namespace: &'a str,
    scan_started_at: &'a str,
    upload_progress_path: &'a Path,
    daemon: &'a LocalDaemon,
    claude_scan_roots: &'a Option<Vec<PathBuf>>,
    cache_observations_enabled: bool,
    scan_agent_status_collection: &'a crate::agent_status::AgentStatusCollection,
    upload_policy: SnapshotUploadPolicy,
    cache_full_replacement: bool,
    identity_item_cap: usize,
}

/// What the local evidence fold hands back to the finish: the backfill outcome so
/// far, the Claude usage authority disposition and the cutoff correction candidates.
struct LocalEvidence {
    backfill_succeeded: bool,
    claude_authority_disposition: crate::snapshots::ClaudeUsageAuthorityDisposition,
    claude_cutoff_corrections: Vec<crate::snapshots::ClaudeCutoffCorrectionCandidate>,
}

/// The pass's settled facts at the end of a finish, read by each step there.
#[derive(Clone, Copy)]
struct PassEnd<'a> {
    deferred_entity_count: Option<usize>,
    resolved_permanent_rejections: bool,
    permanent_refusals: PermanentRefusalCounts,
    upload_fully_settled: bool,
    isolated_only: bool,
    accepted: u64,
    terminal_scan_started_at: &'a str,
    fresh_offer: bool,
    upload_completed: bool,
    backfill_succeeded: bool,
}

/// What retiring this pass's upload progress consumes from the pass.
struct ProgressRetirement<'a> {
    locally_held_fingerprints: &'a BTreeSet<String>,
    projected_pending_head_file_witnesses: &'a BTreeMap<String, Option<String>>,
    current_entities: &'a BTreeSet<String>,
    retired_upload_acks: &'a mut ack_retention::AckRetirementPlan,
    walk_retired: bool,
    identity_503_this_pass: Option<BTreeSet<String>>,
}

#[expect(clippy::too_many_arguments, reason = "9 args; no options struct yet")]
pub(super) fn finish_sync_source(
    preparation: SourcePreparation,
    mut index: ScanIndex,
    mut scan_result: SourceScanResult,
    device: &LocalDeviceBinding,
    device_secret: &str,
    machine_id: &str,
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
) -> Result<()> {
    let _diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::finish_decision(
        preparation.source == SnapshotSource::ClaudeCode,
    );
    let SourcePreparation {
        source,
        walk_idle_pass,
        claude_scan_roots,
        account_witness,
        scan_started_at,
        activity_hint,
        receipt_window_days,
        cache_observations_enabled,
        scan_agent_status_collection,
        attribution_context,
        upload_policy,
        upload_destination_namespace,
        receipt_client,
        index_path,
        upload_progress_path,
        mut upload_progress,
        mut committed_index,
        backfill_state,
        backfill_pending,
        scan: _,
    } = preparation;
    let cache_full_replacement = cache_full_replacement_negotiated(source, &activity_hint);
    // Telemetry retention keeps the sessions this page names, read before any
    // page filter drops a snapshot.
    let telemetry_named = claude_scan_roots
        .as_ref()
        .map(|_| claude_evidence_session_ids(&scan_result.snapshots));
    let scan_agent_status_collection =
        scan_agent_status_collection.context("a continuation preparation reached its finish")?;
    let identity_item_cap = crate::snapshots::claude_request_identity::effective_item_cap(
        activity_hint.max_snapshot_item_bytes,
    );
    upload_progress
        .accepted_identity_buckets
        .bind_context(attribution_context.as_ref());
    upload_progress
        .accepted_identity_buckets
        .set_item_cap(identity_item_cap);
    let state_v2_baseline = crate::snapshots::state_v2_baseline_release(&index_path, &index);
    // Resets the census-wait count on every exit that is not a capacity stop.
    let mut census_wait = ack_retention::CapacityStopCensusCount::begin(source);
    let client = &receipt_client;
    let codex_join_validator = scan_result.codex_joining_validator();
    let validate_joined = |snapshots: &[&SnapshotItem]| -> Result<()> {
        if let Some(validator) = &codex_join_validator {
            validator.validate(snapshots)?;
        }
        Ok(())
    };
    let state_v2_guard = crate::snapshots::state_v2_side_effect_guard(&index_path, &index);
    let recovery_save_guard = crate::snapshots::state_v2_recovery_save_guard(&index_path, &index)?;
    let ensure_destination_authority = || {
        ensure_snapshot_scan_authority(device, source, client, &account_witness, daemon)?;
        ensure_snapshot_destination_current(&upload_destination_namespace)?;
        if let Some(roots) = &claude_scan_roots {
            crate::snapshot_roots::validate_claude_roots(home, roots)?;
        }
        Ok(())
    };
    let ensure_authority = || {
        state_v2_guard()?;
        ensure_destination_authority()
    };
    if let Some(validate_recovery_save) = recovery_save_guard.as_ref() {
        // The ordinary early census fence includes the external upload hold.
        // A held pass authenticates local recovery here before any upload IO.
        validate_recovery_save()?;
        ensure_destination_authority()?;
    } else if scan_result.walk_idle {
        // An idle pass took no census: the fenced one stays.
        ensure_authority()?;
    } else {
        codex_scan_diagnostics::after_existing_census_fence(
            source,
            support_dir,
            ensure_authority,
            || codex_scan_diagnostics::write_fenced_census(support_dir, &scan_result, &index),
        )?;
    }
    if scan_result.walk_idle && crate::snapshots::walk_idle::idle_finish(&index) {
        // Nothing was read: no body, save or receipt. The walk's terminal
        // receipt and manifest stand; check-in beats keep them fresh.
        if crate::snapshots::maintain_state_v2_idle(&index_path, &index, true).is_err() {
            eprintln!("local state maintenance deferred for {}", source.api_slug());
        }
        with_source_cadence(source, |cadence| {
            cadence.record_scan_success(Instant::now(), 0)
        });
        // The walk's census still stands, so this is a completed scan. Without
        // it a gated source reads stalled between listing walks.
        record_collection_complete(source, &current_rfc3339());
        let counts = SyncCounts::from_scan_result(&scan_result, 0, receipt_window_days);
        eprintln!("{}", counts.terminal_census_line(source.api_slug()));
        if let Some((pass, _)) = walk_idle_pass {
            crate::snapshots::walk_idle::arm_after_finish(
                pass,
                &index,
                &index_path,
                &scan_result,
                false,
            );
        }
        return Ok(());
    }
    let env = FinishEnv {
        source,
        client,
        device,
        device_secret,
        machine_id,
        support_dir,
        index_path: &index_path,
        activity_hint: &activity_hint,
        receipt_window_days,
        backfill_pending,
        backfill_state: &backfill_state,
        upload_destination_namespace: &upload_destination_namespace,
        scan_started_at: &scan_started_at,
        upload_progress_path: &upload_progress_path,
        daemon,
        claude_scan_roots: &claude_scan_roots,
        cache_observations_enabled,
        scan_agent_status_collection: &scan_agent_status_collection,
        upload_policy,
        cache_full_replacement,
        identity_item_cap,
    };
    // A pass that started a walk while finishing is an ordinary page.
    if std::mem::take(&mut scan_result.walk_idle) {
        crate::snapshots::walk_idle::clear(source, "idle_page_walked");
    }
    let LocalEvidence {
        mut backfill_succeeded,
        claude_authority_disposition,
        claude_cutoff_corrections,
    } = fold_local_evidence(&env, &mut index, &mut scan_result, &mut upload_progress)?;
    backfill_succeeded &= scan_result.census_complete;
    let deferred_cache_head_identities = capture_deferred_cache_head_identities(
        source,
        &scan_result.snapshots,
        &upload_progress,
        cache_observations_enabled,
        activity_hint.snapshot_head_cas_required,
        &claude_authority_disposition,
    );
    exclude_held_effective_body_witness_revision(
        &mut index,
        &scan_result.snapshots,
        &claude_authority_disposition,
    );
    prepare_codex_recovery_diagnostics(
        &mut scan_result,
        &index,
        &upload_progress.quarantined_fingerprints,
    );
    // Preserve current-proof/current-revision evidence before the finalizer
    // removes exact semantic no-ops. Held/account-filtered bodies are excluded.
    let claude_proof_correction_candidates = if source == SnapshotSource::ClaudeCode {
        index.capture_claude_proof_corrections(
            &mut scan_result,
            &claude_authority_disposition,
            |snapshot| {
                effective_snapshot_upload_body_witness(
                    snapshot,
                    &upload_progress,
                    cache_observations_enabled,
                    activity_hint.snapshot_head_cas_required,
                    &claude_authority_disposition,
                )
            },
        )
    } else {
        Vec::new()
    };
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::reason_reoffer_pipeline_tests::prepare_probe_for_test(
        &mut scan_result.snapshots,
        &mut upload_progress,
    );
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::prepare_counted_cap_body_for_test(
        source,
        upload_policy,
        &mut scan_result.snapshots,
    );
    finalize_scan_after_policy_with_body_witness(
        source,
        &mut scan_result,
        &mut index,
        |snapshot| {
            effective_snapshot_upload_body_witness(
                snapshot,
                &upload_progress,
                cache_observations_enabled,
                activity_hint.snapshot_head_cas_required,
                &claude_authority_disposition,
            )
        },
    );
    index.advance_empty_claude_proof_corrections(&scan_result);
    let mut capture_adopted = false;
    if source == SnapshotSource::Codex {
        capture_adopted = capture_codex_recovery_evidence(
            &mut index,
            &mut committed_index,
            &mut scan_result,
            &index_path,
            &upload_progress_path,
            ensure_authority,
        );
        backfill_succeeded &= scan_result.census_complete;
    }
    // An adopted capture moved this graph to the generation it saved, and the
    // guard built before it refuses that graph. Every later boundary takes a
    // new guard from the same constructor, as after any adopted save.
    let state_v2_guard = if capture_adopted {
        crate::snapshots::state_v2_side_effect_guard(&index_path, &index)
    } else {
        state_v2_guard
    };
    let ensure_authority = || {
        state_v2_guard()?;
        ensure_destination_authority()
    };
    // A long-lived poison item can keep upload progress around while unrelated
    // files continue changing. Drop quarantine revisions no longer represented
    // by the authoritative current index before any early upload error can
    // preserve them forever.
    let current_fingerprints = index.current_snapshot_fingerprints();
    if upload_progress.retain_current_quarantines_with_diagnostics(
        &current_fingerprints,
        &index,
        scan_result.local_codex_diagnostics.as_mut(),
    ) {
        upload_progress.save(&upload_progress_path)?;
    }
    if !scan_result.census_complete {
        // A stale prior manifest must not survive a lossy census. The healthy
        // siblings may still upload, but no source-wide agreement witness is
        // publishable until every discovered path was read completely.
        withdraw_source_manifest(&upload_destination_namespace, source);
    }
    let (manifest_window_start, manifest_window_end) =
        snapshot_manifest_window(&scan_result.census_window_end, receipt_window_days)?;
    // A bounded traversal may span process restarts. Its manifest is scoped to
    // the first tick's pinned census boundary, so every post-scan terminal
    // receipt must identify that same logical scan start rather than the later
    // resume attempt. This gives the backend an exact, restart-stable binding:
    // manifest.window_end == last_scan_started_at.
    let terminal_scan_started_at = manifest_window_end.as_str();

    // Persist the Companion-facing posture projection as soon as an
    // activity-hint-authorized local scan is complete and account-switch
    // filtering has been applied. This deliberately stays behind the master
    // `local_usage_reconciliation_enabled` collection switch: an unavailable
    // hint or explicit disable must not cause an offline bypass of user/org
    // policy. Once a scan is authorized, however, a later batch-upload failure
    // must not discard its machine-local evidence. Cache writes are best-effort
    // and never block usage sync; omit raw filesystem errors.
    if source == SnapshotSource::ClaudeCode
        && crate::context_posture::update_context_posture_cache(
            support_dir,
            &scan_result.snapshots,
            OffsetDateTime::now_utc(),
        )
        .is_err()
    {
        eprintln!(
            "local context-posture cache update skipped for {}",
            source.api_slug()
        );
    }

    // Keep the full local scan available to active-session/context-posture
    // consumers above, then remove only authority-demoting revisions at the
    // network boundary. They are not backend poison and are not counted as
    // accepted/quarantined upload settlement.
    let local_holds = LocalHoldSettlement::classify(
        source,
        &mut index,
        &mut scan_result,
        &claude_authority_disposition,
    );
    pass_outcomes(|counts| counts.selected = scan_result.snapshots.len() as u64);
    let locally_held_fingerprints = &local_holds.held_fingerprints;
    if let Some(validate_recovery_save) = recovery_save_guard {
        // Retry a consistent local delta before any upload/ACK. Reuse the
        // partial-checkpoint settlement rules: unACKed files stay owed, exact
        // durable receipts remain authoritative, and no manifest is published.
        withdraw_source_manifest(&upload_destination_namespace, source);
        checkpoint_partial_snapshot_index_with_audit_release(
            &index,
            &committed_index,
            &upload_progress,
            &scan_result.snapshots,
            Some(&scan_result),
            locally_held_fingerprints,
            &index_path,
            &upload_progress_path,
            || {
                validate_recovery_save()?;
                ensure_destination_authority()
            },
            Some(UnsettledUploadCause::UploadError),
            (source == SnapshotSource::ClaudeCode).then_some(AccountAuditRelease {
                previous: &committed_index,
                roots: claude_scan_roots.as_deref().unwrap_or_default(),
                backfill_window_days: receipt_window_days,
            }),
            // Pre-upload recovery: no proof corrections were drained yet.
            Default::default(),
        )?;
        // A new pass reconstructs external guards from the saved generation.
        return Err(anyhow!("state_v2_save_recovered_retry"));
    }
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_cache_probe_for_test(&mut scan_result.snapshots);

    let headless = |progress: &SnapshotUploadProgress, snapshot: &SnapshotItem| {
        snapshot.cache_observations.is_some()
            && !progress
                .accepted_cache_heads
                .contains_key(&cache_session_key(&snapshot.source_session_id))
    };
    let cache_head_groups = if cache_observations_enabled
        && (activity_hint.snapshot_head_cas_required
            || !upload_progress.pending_cache_heads.is_empty()
            || scan_result
                .snapshots
                .iter()
                .any(|snapshot| headless(&upload_progress, snapshot)))
    {
        cache_head_file_groups(&index)
    } else {
        BTreeMap::new()
    };
    let mut pending_cache_heads_changed = false;
    for identity in &deferred_cache_head_identities {
        pending_cache_heads_changed |= upload_progress.record_pending_cache_head_identity(
            identity.source_file_fingerprint.as_ref(),
            &identity.snapshot_fingerprint,
            &identity.session_key,
            &cache_head_groups,
            true,
        )?;
    }

    for snapshot in &mut scan_result.snapshots {
        if cache_observations_enabled && snapshot.cache_observations.is_some() {
            // Every headless patch is owed until its exact patched ACK with a
            // head is saved. Only a required head fails on a missing binding.
            let owed = headless(&upload_progress, snapshot);
            let required = activity_hint.snapshot_head_cas_required;
            pending_cache_heads_changed |=
                match upload_progress.record_pending_cache_head(snapshot, &cache_head_groups, owed)
                {
                    Err(_) if !required => false,
                    recorded => recorded?,
                };
        }
        prepare_snapshot_cache_for_upload(
            snapshot,
            &upload_progress,
            cache_observations_enabled,
            activity_hint.snapshot_head_cas_required,
        );
    }
    if pending_cache_heads_changed {
        // Durable before ordinary delivery can acquire a head or fail. The
        // obligation survives until both cache settlement and index save.
        upload_progress.save(&upload_progress_path)?;
    }
    upload_progress
        .reason_reoffer_counts
        .cooldown_conflict_deferred = index.reason_reoffer_cooldown_deferred_count();
    // One logical offer per leased refusal: its next deadline is at least
    // this first transmission + 24 h, and durable before it. A failed save
    // sends nothing.
    if upload_progress
        .extend_reason_reoffers_before_upload(&scan_result.snapshots, locally_held_fingerprints)
    {
        upload_progress.save(&upload_progress_path)?;
    }
    let attempted_reason_reoffers = upload_progress.active_reason_reoffers.clone();
    // Existing entities cannot authorize their first cache enrichment without
    // a producer-owned predecessor token. Probe the unchanged semantic body
    // through the existing CAS contract, omitting the additive cache patch.
    // Exact settled ACKs enter the same atomic progress ledger as normal pages.
    // Bootstrap and main upload must drain the same admitted subset. A larger
    // page stops through partial settlement only after those bodies can finish.
    let census_absent_upload_acks =
        upload_progress.complete_census_ack_retirements(&index, scan_result.census_complete);
    // Current scanner incidence grants live slots on a first install, too.
    // No absent ACK or unrelated entity borrows those slots.
    upload_progress.prepare_context_receipt_candidates(
        &index,
        &committed_index,
        &scan_result.snapshots,
    );
    scan_result.snapshots.sort_by_key(|item| {
        upload_progress
            .context_resend
            .is_catchup(&item.snapshot_fingerprint)
    });
    let ack_admission_limited =
        upload_progress.admit_upload_input(&mut scan_result.snapshots, &index);
    if matches!(source, SnapshotSource::ClaudeCode | SnapshotSource::Codex)
        && upload_progress.note_reprojected_context_refusals(&scan_result.snapshots)
    {
        upload_progress.save(&upload_progress_path)?;
    }
    upload_progress.request_contributions.extend(
        scan_result
            .snapshots
            .iter()
            .filter(|item| {
                crate::snapshots::claude_request_money::request_owned_family_root(item).is_some()
            })
            .map(|item| {
                (
                    item.snapshot_fingerprint.clone(),
                    crate::snapshots::upload_context_receipt::SlotRows::capture(item),
                )
            }),
    );
    upload_progress.context_receipt_candidates = index.file_upload_context_ack_candidates(
        &scan_result.snapshots,
        &upload_progress.covered_stale_bodies(),
    );
    upload_progress
        .context_resend
        .retain_candidates(&upload_progress.context_receipt_candidates);
    crate::local_resource_diagnostics::change_reason::propagate(source.api_slug(), &index);
    let probes = scan_result
        .snapshots
        .iter()
        .filter(|item| item.cache_observations.is_some() && item.cache_base_head_etag.is_none())
        .map(cache_head_probe)
        .collect::<Vec<_>>();
    let fresh_offer = scan_result.snapshots.iter().any(|item| {
        let fp = &item.snapshot_fingerprint;
        !upload_progress.quarantined_fingerprints.contains_key(fp)
            && !upload_progress.accepted_fingerprints.contains(fp)
    });
    let mut bootstrap_deferred = 0usize;
    let mut bootstrap_capacity_error = None;
    // One in-place resend budget for the whole source page: both bootstrap
    // stages and the main upload draw on it, so the page never waits more
    // than two resends and 10 s under the sync lock.
    let mut inplace_retry = InplaceRetryBudget::default();
    // One page upload, probe or main: preflight at the identity item cap
    // (counted request positions never refuse a body), authority around a
    // fresh relay token, Codex joins, then the exact ACK.
    let upload_checked = |request: &SnapshotBatchRequest<&SnapshotItem>,
                          enforce_head_cas: bool|
     -> Result<crate::snapshot_client::SnapshotBatchResponse> {
        super::upload::preflight_snapshot_request(
            request,
            identity_item_cap,
            |request, trimmed_items| {
                ensure_authority()?;
                let token = client.issue_relay_token(device, device_secret, source)?;
                ensure_authority()?;
                validate_joined(&request.snapshots)?;
                let response = client.upload_batch_with_item_cap(
                    &token,
                    request,
                    enforce_head_cas,
                    identity_item_cap,
                    trimmed_items,
                )?;
                response.validate_entity_ack_with_head_cas(request, enforce_head_cas)?;
                Ok(response)
            },
        )
    };
    if !probes.is_empty() {
        // These failures precede the main upload's diagnostic. Preserve only
        // the existing typed, content-free cause and the fixed failing role.
        let log_bootstrap_failure = |role: &'static str| {
            move |error: &anyhow::Error| {
                if snapshot_upload_error_class(error).is_some() {
                    eprintln!(
                        "ottto-service: local snapshot cache-head bootstrap did not settle for {} — role={role}, {}",
                        source.api_slug(),
                        upload_failure_diagnostic(error)
                    );
                }
            }
        };
        let bootstrap_result = bootstrap_cache_heads_with_budget(
            &probes,
            source.api_slug(),
            &mut upload_progress,
            &mut inplace_retry,
            |snapshots, enforce_head_cas| {
                let request = snapshot_batch_request(
                    source,
                    machine_id,
                    snapshots.to_vec(),
                    upload_policy,
                    crate::client_report::ClientReport::empty(),
                );
                upload_checked(&request, enforce_head_cas)
            },
            |progress| progress.save(&upload_progress_path),
        )
        .inspect_err(log_bootstrap_failure("probe"));
        match bootstrap_result {
            Ok(deferred) => bootstrap_deferred = deferred,
            Err(error)
                if error
                    .downcast_ref::<ack_retention::AckSettlementRequired>()
                    .is_some() =>
            {
                // A local probe stop owes the same partial-index retirement
                // and cadence handling as a stop in the main uploader.
                bootstrap_capacity_error =
                    Some(error.context("cache-head bootstrap ACK settlement pending"));
            }
            // A probe outage owes the main uploader's outage custody and
            // partial checkpoint below.
            Err(error) if is_upload_outage(&error) => bootstrap_capacity_error = Some(error),
            Err(error) => return Err(error),
        }
        if bootstrap_capacity_error.is_none() {
            // A paced-out probe has no head token yet. Keep its existing
            // selection debt for the next pass rather than failing healthy
            // ordinary uploads or fabricating a predecessor token.
            scan_result.snapshots.retain(|item| {
                !upload_progress
                    .context_resend
                    .deferred
                    .contains(&item.snapshot_fingerprint)
            });
            let held = apply_bootstrapped_cache_heads(
                source.api_slug(),
                &mut scan_result.snapshots,
                &upload_progress,
            )
            .inspect_err(log_bootstrap_failure("apply"))
            .inspect_err(|_| {
                upload_progress.finish_reason_reoffers(
                    &attempted_reason_reoffers,
                    false,
                    source.api_slug(),
                );
            })?;
            index.substitute_file_upload_context_bodies(
                &mut upload_progress.context_receipt_candidates,
                &held,
            );
            let held = held.len();
            if held > 0 {
                eprintln!(
                "local snapshot cache-head bootstrap carried {held} held probe(s) for {} as exact quarantined bodies; siblings continue",
                source.api_slug()
            );
            }
        }
    }
    // The same hook every resend path calls; nothing held is left by now.
    index.retain_claude_history_emission_permitted(&mut scan_result.snapshots);
    if upload_progress.defer_held_quarantine_retries(&scan_result.snapshots, &index, source) {
        upload_progress.save(&upload_progress_path)?;
    }
    // After bootstrap set each base, so an answer never borrows a fresh head.
    let head_conflict_answers = attach_head_conflict_answers(
        &mut scan_result.snapshots,
        &upload_progress,
        current_unix_seconds(),
        |key| cache_full_replacement && index.head_conflict_owed(key),
    );
    if head_conflict_answers > 0 {
        eprintln!(
            "local snapshot upload answers {head_conflict_answers} head-CAS conflict challenge(s) for {} through the rescan handshake",
            source.api_slug()
        );
    }
    upload_progress.bind_telemetry_bodies(support_dir, &mut scan_result.snapshots);
    if scan_result
        .snapshots
        .iter()
        .any(|item| item.evidence_basis == Some("otel_only"))
    {
        upload_progress.save(&upload_progress_path)?;
    }
    let projected_pending_head_file_witnesses =
        upload_progress.pending_cache_head_file_witnesses(&index);
    let mut accepted = 0;
    let bootstrap_offer_finished = bootstrap_capacity_error.is_some();
    let upload_result = if let Some(error) = bootstrap_capacity_error {
        Err(error)
    } else {
        // Only this main page upload records or drains identity-503 custody.
        upload_progress.identity_503_pass = Some(BTreeSet::new());
        upload_resumable_batches_with_literal_families(
            &scan_result.snapshots,
            source.api_slug(),
            &mut upload_progress,
            &mut accepted,
            |snapshot| snapshot.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |snapshot| Some(snapshot.source_session_id.as_str()),
            snapshot_upload_batch_class,
            crate::snapshots::claude_request_money::request_owned_family_root,
            &mut inplace_retry,
            |snapshots| {
                // A first Codex/Claude scan can spend several minutes parsing local
                // history and retroactive backfill before the first upload. Relay
                // tokens are intentionally short-lived, so mint them at the network
                // boundary instead of reusing the pre-scan activity-hint token.
                // Leased, not read: exactly one in-flight batch may claim the
                // counters, and dropping the lease on any failure below leaves the
                // losses owed instead of stranded.
                let client_report = crate::client_report::lease();
                let request = snapshot_batch_request(
                    source,
                    machine_id,
                    snapshots.to_vec(),
                    upload_policy,
                    client_report.report().clone(),
                );
                let mut response = upload_checked(&request, false)?;
                response.bind_conflict_rescans(&request);
                // Clear only what this accepted request carried. A failed upload
                // leaves the counters in place so the losses are reported on the
                // next batch instead of vanishing with the request that died.
                client_report.commit();
                Ok(response)
            },
            |progress| progress.save(&upload_progress_path),
        )
        .and_then(|result| {
            if matches!(
                result,
                ResumableUploadResult::Completed
                    | ResumableUploadResult::Deferred { .. }
                    | ResumableUploadResult::Rejected { .. }
            ) {
                // A setup/account switch can replace the relay binding while a
                // long historical scan is uploading. Never commit destination A's
                // delivery cursor after the machine has moved to destination B.
                ensure_authority()?;
            }
            // Never certify omitted files as a completed scan. Drain admitted
            // bodies, then enter partial settlement with its typed local counts.
            ack_retention::require_settlement(result, ack_admission_limited, &upload_progress)
        })
        .map(|result| {
            with_retained_refusal_conflicts(
                with_bootstrap_deferred(result, bootstrap_deferred),
                &index,
                &upload_progress,
                reason_reoffer::now_unix_seconds(),
            )
        })
    };
    pass_outcomes(|counts| counts.accepted = accepted);
    // Main-upload mode ends with it; retries never record or drain custody.
    let identity_503_this_pass = upload_progress.identity_503_pass.take();
    // The logical offer ends here; normal bounded HTTP retries happened inside.
    if !bootstrap_offer_finished {
        // Bootstrap already classified its failed logical offer. A routed
        // capacity stop must not count unattempted leases a second time.
        upload_progress.finish_reason_reoffers(
            &attempted_reason_reoffers,
            matches!(upload_result, Ok(ResumableUploadResult::Shed { .. })),
            source.api_slug(),
        );
    }
    // An outage (a transport failure, timeout or 5xx, or a plain shed) ends
    // the pass before the server answered for every body. Hold each body with
    // no exact ACK, hold or refusal in ordinary retryable custody, durably,
    // before the partial checkpoint below: its files and heads then commit,
    // and the next pass re-sends from the head instead of reading the file
    // again. No ACK, refusal or loss is recorded; the entities stay owed.
    let outage_retry_after = match &upload_result {
        Ok(ResumableUploadResult::Shed { retry_after }) => Some(*retry_after),
        Err(error) if is_upload_outage(error) => Some(None),
        _ => None,
    };
    if let Some(retry_after) = outage_retry_after {
        let before = upload_progress.clone();
        let retry_at = current_unix_seconds().saturating_add(shed_backoff(retry_after).as_secs());
        let held = upload_progress.hold_outage_bodies(&scan_result.snapshots, retry_at);
        if held > 0 {
            if upload_progress.save(&upload_progress_path).is_err() {
                // Nothing durable changed: the page stays owed as before.
                upload_progress = before;
            } else {
                crate::local_resource_diagnostics::traversal_point(
                    "quarantine_retry",
                    source.api_slug(),
                    &serde_json::json!({"reason": "outage", "count": held}),
                );
            }
        }
    }

    // Exact progress is durable before this seam. The same subsequent index
    // save carries settled file bodies and correction progress; local-state
    // errors cannot certify an uncertain ACK. UnACKed/held members stay owed.
    // Selection below may keep a drained member's committed entry; each save
    // then restores that member's debt (R2).
    let mut claude_proof_body_drains = crate::snapshots::ClaudeProofBodyDrains::default();
    if !upload_result.as_ref().err().is_some_and(|error| {
        snapshot_upload_error_class(error) == Some(SnapshotUploadErrorClass::LocalState)
    }) {
        claude_proof_body_drains = index.settle_claude_proof_corrections(
            &committed_index,
            &claude_proof_correction_candidates,
            &upload_progress.accepted_fingerprints,
            &upload_progress.accepted_body_witnesses,
        );
    }

    index.log_claude_proof_correction_debt();

    // The server may have accepted new entities even when the final result is a
    // timeout, a disabled response, or a later local-state failure. Withdraw
    // the pre-cycle cache for every outcome; completed/shed branches republish
    // only after their exact replacement index is durable.
    withdraw_source_manifest(&upload_destination_namespace, source);

    let mut upload_fully_settled = true;
    let mut deferred_entity_count = None;
    let mut resolved_permanent_rejections = false;
    let mut isolated_only = false;
    let mut deferred_cause = UnsettledUploadCause::DeferredConflict;
    let walk_retired = index.walk_retired_since(&committed_index);
    // Local-hold Completed/Deferred/Rejected subsets and selected-state
    // restoration below can omit a still-live file. Capture which retirement
    // obligations this full scan references before any selection.
    let ack_scan_referenced =
        upload_progress.ack_retirement_scan_references(&committed_index, &index);
    // Shed and upload-error partial checkpoint: save wholly settled files,
    // then release adopted ACK capacity against the full scan's references.
    // A failed save is logged and yields `None`; a failed
    // release fails the pass.
    let mut partial_checkpoint =
        |cause: UnsettledUploadCause, keep_adopted_for_retry: bool| -> Result<Option<ScanIndex>> {
            match checkpoint_partial_snapshot_index_with_audit_release(
                &index,
                &committed_index,
                &upload_progress,
                &scan_result.snapshots,
                Some(&scan_result),
                locally_held_fingerprints,
                &index_path,
                &upload_progress_path,
                || {
                    ensure_authority()?;
                    scan_result.validate_codex_checkpoint()
                },
                Some(cause),
                (source == SnapshotSource::ClaudeCode).then_some(AccountAuditRelease {
                    previous: &committed_index,
                    roots: claude_scan_roots.as_deref().unwrap_or_default(),
                    backfill_window_days: receipt_window_days,
                }),
                std::mem::take(&mut claude_proof_body_drains),
            ) {
                Ok(committable) => {
                    upload_progress.release_acks_after_partial_index_save_with_scan(
                        &upload_progress_path,
                        &committed_index,
                        &committable,
                        &ack_scan_referenced,
                        locally_held_fingerprints,
                        keep_adopted_for_retry,
                    )?;
                    Ok(Some(committable))
                }
                Err(error) => {
                    eprintln!(
                        "local snapshot partial scan checkpoint failed for {}: {}",
                        source.api_slug(),
                        safe_error(&error)
                    );
                    Ok(None)
                }
            }
        };
    // Telemetry retention follows only a completed upload: a rejected,
    // deferred, shed, disabled or failed page drops it even when it settles.
    let upload_completed = matches!(upload_result, Ok(ResumableUploadResult::Completed));
    match upload_result {
        Ok(ResumableUploadResult::Completed) => {
            clear_shed_streak(source);
            let settlement =
                settle_completed_upload(index, &committed_index, &upload_progress, &local_holds);
            index = settlement.index;
            if !settlement.fully_settled {
                backfill_succeeded = false;
                upload_fully_settled = false;
            }
        }
        Ok(
            outcome @ (ResumableUploadResult::Deferred { .. }
            | ResumableUploadResult::Rejected { .. }),
        ) => {
            let count = match outcome {
                ResumableUploadResult::Rejected { count } => {
                    resolved_permanent_rejections = true;
                    count
                }
                ResumableUploadResult::Deferred {
                    count,
                    isolated,
                    identity_503,
                } => {
                    isolated_only = count == isolated;
                    if count == identity_503 {
                        deferred_cause = UnsettledUploadCause::Isolated503;
                    }
                    count
                }
                _ => unreachable!(),
            };
            clear_shed_streak(source);
            let settlement = settle_checkpointed_upload(
                index,
                &committed_index,
                &upload_progress,
                &local_holds,
                resolved_permanent_rejections,
                deferred_cause,
            );
            index = settlement.index;
            if !settlement.fully_settled {
                backfill_succeeded = false;
                upload_fully_settled = false;
            }
            deferred_entity_count = Some(count);
            eprintln!(
                "local snapshot upload checkpointed accepted siblings but left {count} \
                 unsettled entity(ies) pending for {}; a clean follow-up scan is required \
                 ({} page(s) settled with terminal-bound holds)",
                source.api_slug(),
                CHECKPOINTED_PAGES_SETTLED_WITH_TERMINAL_BOUND_HOLDS
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
        }
        Ok(ResumableUploadResult::Shed { retry_after }) => {
            let retry_after = note_shed_and_backoff(source, retry_after);
            defer_source_uploads(source, retry_after);
            let committable =
                partial_checkpoint(UnsettledUploadCause::Shed, true)?.unwrap_or(committed_index);
            report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                support_dir,
                source,
                TerminalManifestSource::Withdraw,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: terminal_scan_started_at,
                    counts: SyncCounts::from_scan_result(
                        &scan_result,
                        accepted,
                        receipt_window_days,
                    )
                    .with_snapshot_terminal_counts(&committable),
                    // `server_error` is the closest code the receipt contract
                    // carries; the loss report is where the shed is named
                    // precisely.
                    state: CollectorState::Error {
                        code: "server_error",
                        message: "backend shed the snapshot upload; honouring backoff",
                    },
                },
            )?;
            return Ok(());
        }
        Ok(ResumableUploadResult::Disabled(disabled_reason)) => {
            // No scan success follows to retire a paced request.
            continuation::drop_paced_request(source);
            report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                support_dir,
                source,
                TerminalManifestSource::Withdraw,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: terminal_scan_started_at,
                    counts: SyncCounts::from_scan_result(
                        &scan_result,
                        accepted,
                        receipt_window_days,
                    )
                    .with_snapshot_terminal_counts(&index),
                    state: CollectorState::Disabled(
                        disabled_reason.or_else(|| Some("disabled_by_admin".to_string())),
                    ),
                },
            )?;
            return Ok(());
        }
        Err(error) => {
            // Earlier pages may have durable exact ACKs even though this pass
            // failed. Save their wholly settled files and release adopted ACK
            // capacity. Local-state failures leave durability
            // uncertain and must not certify an in-memory mutated ledger.
            if snapshot_upload_error_class(&error) != Some(SnapshotUploadErrorClass::LocalState) {
                if let Some(committable) =
                    partial_checkpoint(UnsettledUploadCause::UploadError, false)?
                {
                    index = committable;
                }
            }
            if snapshot_upload_error_class(&error).is_some() {
                eprintln!(
                    "ottto-service: local snapshot upload did not settle for {} — {}",
                    source.api_slug(),
                    upload_failure_diagnostic(&error)
                );
            }
            let (state, context) = classify_upload_failure(
                source,
                &error,
                &mut census_wait,
                scan_result.census_complete,
            );
            with_source_cadence(source, |cadence| {
                ack_retention::record_upload_error_cadence(
                    cadence,
                    Instant::now(),
                    accepted,
                    &error,
                )
            });
            let _ = report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                support_dir,
                source,
                TerminalManifestSource::Withdraw,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: terminal_scan_started_at,
                    counts: SyncCounts::from_scan_result(
                        &scan_result,
                        accepted,
                        receipt_window_days,
                    )
                    .with_snapshot_terminal_counts(&index),
                    state,
                },
            );
            return Err(error.context(context));
        }
    }

    settle_index_after_upload(&mut index, &committed_index, &upload_progress);
    // Completed/checkpointed outcomes have now selected their retained file
    // facts. No-body completion must share that exact durable checkpoint.
    upload_fully_settled = finish_selected_settlement(
        &mut index,
        SelectedSettlementInputs {
            scan: &scan_result,
            committed_index: &committed_index,
            progress: &upload_progress,
            candidates: &claude_proof_correction_candidates,
            cutoff_candidates: &claude_cutoff_corrections,
            transport_fully_settled: upload_fully_settled,
            body_drains: claude_proof_body_drains,
            audit_release: (source == SnapshotSource::ClaudeCode).then_some(AccountAuditRelease {
                previous: &committed_index,
                roots: claude_scan_roots.as_deref().unwrap_or_default(),
                backfill_window_days: receipt_window_days,
            }),
        },
    );
    let mut retired_upload_acks = upload_progress.stage_selected_ack_retirement(
        &committed_index,
        &mut index,
        &ack_scan_referenced,
        locally_held_fingerprints,
        &census_absent_upload_acks,
    )?;
    // Every selected-state restoration above has finished. Retire the Claude
    // prior index before the full disk-index CAS decode.
    let context_rearm_counts = index.accept_file_upload_context_acks(
        &upload_progress.split_context_receipt_candidates(),
        &upload_progress.fresh_context_body_acks,
        &upload_progress.covered_stale_bodies(),
    );
    index.stamp_entity_upload_context_acks(
        &upload_progress.destination_namespace_hash,
        &upload_progress.accepted_body_witnesses,
        &upload_progress.accepted_body_contexts,
    );
    index.accept_request_contributions(&upload_progress);
    let telemetry_removed = claude_scan_roots.as_ref().map(|_| {
        crate::snapshots::claude_telemetry_retention::removed_index_keys(&committed_index, &index)
    });
    let retire_prior_index = source == SnapshotSource::ClaudeCode;
    #[cfg(test)]
    let retire_prior_index = retire_prior_index
        && !tests::permanent_finish_pipeline_tests::prior_index_lifetime_tests::keep_prior();
    let _committed_index = if retire_prior_index {
        drop(committed_index);
        None
    } else {
        Some(committed_index)
    };
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::prior_index_lifetime_tests::after_retirement(
        _committed_index.is_some(),
    );
    backfill_succeeded &= upload_fully_settled;
    // A quiet/delta-only scan still discloses current permanent refusals even
    // though no body needed another upload. The committed census owns scope.
    let current_entities = index.current_snapshot_fingerprints();
    let retained_permanent = upload_progress
        .permanent_rejections
        .keys()
        .filter(|fingerprint| current_entities.contains(*fingerprint))
        .count();
    if deferred_entity_count.is_none() && retained_permanent > 0 {
        deferred_entity_count = Some(retained_permanent);
        resolved_permanent_rejections = true;
    }
    // The whole ledger, before the current-entity prune below: a refusal from
    // this page that is not current still keeps its reported reason.
    let permanent_refusals = PermanentRefusalCounts::of(&upload_progress);
    ensure_authority()?;
    scan_result.validate_codex_checkpoint()?;
    save_index_and_publish_manifest(
        &mut index,
        &index_path,
        &upload_destination_namespace,
        source,
        scan_result.census_complete,
        &manifest_window_start,
        &manifest_window_end,
    )?;
    scan_result.report_discovery_growth_after_save(&index);
    context_rearm_counts.emit(source);
    index.emit_upload_context_owed(source);
    #[cfg(unix)]
    crate::snapshots::after_source_save(
        &daemon.transcript_cache,
        support_dir,
        source,
        &mut index,
        &index_path,
    );
    if let Some(((roots, removed), named)) = claude_scan_roots
        .as_deref()
        .zip(telemetry_removed.as_ref())
        .zip(telemetry_named.as_deref())
        .filter(|_| upload_completed && upload_fully_settled)
    {
        crate::snapshots::claude_telemetry_retention::retire_claude_telemetry(
            support_dir,
            &index,
            roots,
            removed,
            named,
        );
    }
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_post_save_failure("selected_save")?;
    // Tail state staged after this pass's last full save commits here, once.
    // On error the guard's drop discards and counts it; the next read replays
    // from the previous head. Never print private engine errors.
    if state_v2_baseline.commit_tail().is_err() {
        eprintln!("local tail state commit deferred for {}", source.api_slug());
    }
    // Maintenance is advisory: privacy deadlines alarm without failing an
    // otherwise committed collection cycle. Never print private engine errors.
    if crate::snapshots::maintain_state_v2_idle(
        &index_path,
        &index,
        scan_result.snapshots.is_empty(),
    )
    .is_err()
    {
        eprintln!("local state maintenance deferred for {}", source.api_slug());
    }
    let end = PassEnd {
        deferred_entity_count,
        resolved_permanent_rejections,
        permanent_refusals,
        upload_fully_settled,
        isolated_only,
        accepted,
        terminal_scan_started_at,
        fresh_offer,
        upload_completed,
        backfill_succeeded,
    };
    settle_pass_and_markers(
        &env,
        &scan_result,
        &index,
        &upload_progress,
        &local_holds,
        end,
    )?;

    retire_upload_progress(
        &env,
        &mut upload_progress,
        &index,
        &scan_result,
        end,
        ProgressRetirement {
            locally_held_fingerprints,
            projected_pending_head_file_witnesses: &projected_pending_head_file_witnesses,
            current_entities: &current_entities,
            retired_upload_acks: &mut retired_upload_acks,
            walk_retired,
            identity_503_this_pass,
        },
    )?;

    report_and_arm(
        &env,
        &upload_progress,
        &index,
        &scan_result,
        walk_idle_pass,
        end,
    )
}

/// The first phase of a finish: turns local evidence into the bodies this pass may
/// upload. In order: Claude root accounts, the telemetry seed and accepted identity
/// rows, the local evidence fold and its re-read queue, the copy-derived ledger save,
/// the history-upgrade emission veto, session account binding, the active-session
/// cache and tracking confirmation, the upload policy and the account-switch cutoff.
/// It sends nothing over the network.
fn fold_local_evidence(
    env: &FinishEnv<'_>,
    index: &mut ScanIndex,
    scan_result: &mut SourceScanResult,
    upload_progress: &mut SnapshotUploadProgress,
) -> Result<LocalEvidence> {
    let FinishEnv {
        source,
        machine_id,
        support_dir,
        activity_hint,
        receipt_window_days,
        backfill_pending,
        backfill_state,
        scan_started_at,
        upload_progress_path,
        daemon,
        claude_scan_roots,
        cache_observations_enabled,
        scan_agent_status_collection,
        upload_policy,
        cache_full_replacement,
        identity_item_cap,
        ..
    } = *env;
    let scan_agent_status = reconciliation_agent_status(scan_agent_status_collection);
    // State advances only after the exact paged replay census and its upload
    // both finish. Incomplete pages persist their cursor in the destination
    // index and remain pending across restarts.
    let mut backfill_succeeded = backfill_pending && scan_result.census_complete;
    if backfill_pending && !backfill_succeeded {
        eprintln!(
            "local snapshot backfill remains pending for {}: census incomplete",
            source.api_slug(),
        );
    }

    // Backfill snapshots are appended after the live scan, so run the same
    // content-free effort enrichment over the combined set. Already-split live
    // buckets are naturally skipped because they now have multiple effort rows.
    // This must precede upload-policy stripping: parent/root references are
    // identity evidence needed locally even when the org disables attribution
    // labels on the wire.
    let mut claude_authority_disposition =
        crate::snapshots::ClaudeUsageAuthorityDisposition::default();
    if source == SnapshotSource::ClaudeCode {
        let evidence_started = Instant::now();
        crate::snapshots::claude_request_identity::retain_root_accounts(
            &mut scan_result.snapshots,
            index,
            machine_id,
        );
        let telemetry_window = upload_progress.seed_telemetry(
            support_dir,
            activity_hint,
            scan_result,
            index,
            upload_progress_path,
        )?;
        upload_progress.load_identity(
            (scan_result.snapshots.iter()).map(|item| item.source_session_id.as_str()),
        )?;
        let mut telemetry_ledger = upload_progress.telemetry_only.take();
        let reserve_cache_bytes = |item: &SnapshotItem| {
            if cache_observations_enabled || item.evidence_basis == Some("otel_only") {
                identity_cache_wire_reserve(item, upload_progress, cache_full_replacement)
            } else {
                0
            }
        };
        let (mut disposition, census_withheld, stats) =
            apply_claude_local_evidence_to_scan_with_ledger_and_budget(
                support_dir,
                scan_result,
                index,
                Some(&upload_progress.accepted_identity_buckets),
                crate::snapshots::claude_request_identity::WireBudget {
                    max_item_bytes: identity_item_cap,
                    reservation: Some(&reserve_cache_bytes),
                },
                telemetry_window.zip(telemetry_ledger.as_deref_mut()),
            );
        upload_progress.telemetry_only = telemetry_ledger;
        scan_result.queue_side_call_hints(
            index,
            claude_scan_roots.as_deref().unwrap_or_default(),
            receipt_window_days,
            &mut disposition,
        );
        // Copy-derived rows: the bodies just built treat these
        // rows as never accepted; the ledger records that durably before any
        // upload, so a lost reply or restart cannot restore their proof.
        if upload_progress
            .accepted_identity_buckets
            .invalidate_copy_derived(&std::mem::take(&mut disposition.copy_invalidated))
        {
            upload_progress.save(upload_progress_path)?;
        }
        if let Ok(counts) = serde_json::to_string(&stats) {
            eprintln!(
                "local snapshot sync: claude local evidence duration_ms={} cache_creation_rejected_interpretations_total={} counts={counts}",
                evidence_started.elapsed().as_millis(),
                crate::snapshots::claude_api_cache_creation_rejection_count(),
            );
        }
        if let Ok(counts) = serde_json::to_string(&stats.context_file_birth) {
            eprintln!("local snapshot sync: claude context basis counts={counts}");
        }
        claude_authority_disposition = disposition;
        if census_withheld {
            backfill_succeeded = false;
        }
    }
    // The history-upgrade emission seam: after the local evidence fold, before
    // every ordinary and correction upload path can see a held body.
    index.veto_claude_history_emission(source, &mut scan_result.snapshots);
    // Diagnostics only: counted from the finished bodies, borrowed.
    crate::local_resource_diagnostics::usage_gaps(source.api_slug(), &scan_result.snapshots);

    // Recheck after the potentially long scan, not only when status was
    // acquired. A cached login must not claim sessions created after a switch.
    let current_codex_bindings =
        crate::agent_status_refresh::current_codex_home_bindings(scan_agent_status_collection);
    let cached_codex_login_changed = source == SnapshotSource::Codex
        && current_codex_bindings.len() != scan_agent_status_collection.codex_home_bindings.len();
    let creator_slots = (source == SnapshotSource::Codex)
        .then(crate::agent_status::registered_codex_creator_slots)
        .unwrap_or_default();
    let codex_diagnostics = scan_result.local_codex_diagnostics.as_mut();
    let deferred_accounts = index.bind_session_accounts_with_mixed(
        source,
        machine_id,
        &mut scan_result.snapshots,
        &current_codex_bindings,
        (
            &creator_slots,
            codex_diagnostics.map_or(&mut [0; 9], |d| &mut d.creator_slot_naming),
        ),
        &claude_authority_disposition.mixed_uploads,
    );
    claude_authority_disposition.defer_sessions(deferred_accounts);

    // The Companion uses machine-local labels before upload policy clears them.
    let reconciliation_status = crate::agent_status_refresh::status_for_reconciliation(
        scan_agent_status,
        &current_codex_bindings,
        cached_codex_login_changed,
    );
    // Claude activity remains recent relative to the scan's observation
    // horizon, while future timestamps are bounded by the reconciliation clock.
    let tracking_read = daemon.read_tracking_episode(&source_kind(source));
    let tracking_episode = tracking_read.as_ref().ok().cloned().flatten();
    let reconciled_at = current_rfc3339();
    let since = tracking_episode
        .as_ref()
        .and_then(|(_, since)| OffsetDateTime::parse(since, &Rfc3339).ok());
    use crate::active_sessions::WatermarkPrune;
    // An unreadable state or episode start could hide a waiting Repair's
    // floor, so such a pass keeps every watermark.
    let prune = match (&tracking_read, since) {
        (Ok(None), _) => WatermarkPrune::Floor(None),
        (Ok(Some(_)), Some(since)) => WatermarkPrune::Floor(Some(since)),
        _ => WatermarkPrune::Skip,
    };
    let mut latest = None;
    let mut observe = |new, previous, within_ceiling| {
        latest = latest.max(crate::tracking_confirmation::parsed_activity_witness(
            since,
            new,
            previous,
            within_ceiling,
        ));
    };
    if crate::active_sessions::reconcile_with_registrations(
        support_dir,
        source,
        &scan_result.snapshots,
        Some(&reconciliation_status),
        (source == SnapshotSource::ClaudeCode).then_some(scan_started_at),
        &reconciled_at,
        Some("local"),
        with_source_cadence(source, |cadence| {
            cadence.ordinary_interval().min(MAX_CYCLE_INTERVAL)
        })
        .unwrap_or(SNAPSHOT_SYNC_INTERVAL),
        crate::agent_status::claude_session_registrations,
        tracking_episode
            .as_ref()
            .map(|_| &mut observe as &mut dyn FnMut(_, _, _)),
        prune,
    )
    .is_err()
    {
        eprintln!(
            "local active-session cache update skipped for {}",
            source.api_slug()
        );
    }

    // A scan completed even if the optional cache write failed or upload later fails.
    record_collection_complete(source, &reconciled_at);

    if let (Some((generation, _)), Some(at)) = (
        tracking_episode,
        latest.and_then(|at| at.format(&Rfc3339).ok()),
    ) {
        daemon
            .confirm_tracking_activity(&source_kind(source), generation, &at)
            .map_err(|_| anyhow!("tracking state unavailable"))?;
    }

    crate::snapshots::apply_upload_policy(source, &mut scan_result.snapshots, upload_policy);

    // Account-switch backfill cutoff (server-issued at claim completion): a
    // machine claimed by a different same-org user must not re-attribute the
    // previous owner's already-ingested history. Applies to everything headed
    // upstream this cycle — sessions whose activity ended strictly before the
    // cutoff are historical by definition, whichever scan produced them; live
    // sessions always have activity at/after the cutoff and pass untouched.
    let (skipped_before_cutoff, claude_cutoff_corrections) = if source == SnapshotSource::ClaudeCode
    {
        apply_backfill_cutoff_with_claude_corrections(
            scan_result,
            index,
            &claude_authority_disposition,
            backfill_state,
        )
    } else {
        (
            apply_backfill_cutoff(&mut scan_result.snapshots, backfill_state),
            Vec::new(),
        )
    };
    if skipped_before_cutoff > 0 {
        eprintln!(
            "ottto-service: skipped {} historical {} snapshot(s) that ended before the account-switch backfill cutoff",
            skipped_before_cutoff,
            source.api_slug(),
        );
    }
    Ok(LocalEvidence {
        backfill_succeeded,
        claude_authority_disposition,
        claude_cutoff_corrections,
    })
}

/// After the pass's saves: the source's cadence, the next resident scan and the
/// detected-uses cache, then the two backfill markers in order, each under its
/// own condition, with a best-effort first-read tier save between them. A
/// marker write failure fails the pass before upload progress is retired.
fn settle_pass_and_markers(
    env: &FinishEnv<'_>,
    scan_result: &SourceScanResult,
    index: &ScanIndex,
    upload_progress: &SnapshotUploadProgress,
    local_holds: &LocalHoldSettlement,
    end: PassEnd<'_>,
) -> Result<()> {
    let FinishEnv {
        source,
        device,
        support_dir,
        backfill_pending,
        backfill_state,
        upload_destination_namespace,
        scan_started_at,
        ..
    } = *env;
    let PassEnd {
        upload_fully_settled,
        resolved_permanent_rejections,
        accepted,
        fresh_offer,
        upload_completed,
        backfill_succeeded,
        ..
    } = end;
    // A completed cycle is what moves the tier: uploads keep a source warm, a
    // quiet cycle lets it fall to idle and then cold. A conflict pass durably
    // committed its accepted siblings and each held entity waits on its own
    // quarantine clock, so it is not a source failure; the failure ladder is
    // for upload errors. The sweep marker is stamped only for settled scans,
    // and the status below still reports the held entities.
    with_source_cadence(source, |cadence| {
        cadence.record_scan_success(Instant::now(), accepted)
    });
    let first_read_bootstrap = backfill_pending
        && crate::backfill::bootstrap_pending_for_destination(
            backfill_state,
            source,
            upload_destination_namespace,
        );
    let power = continuation::MacPlatformSignals::default().power();
    if let Some(first_import) = continuation::resident_scan_request_after_settlement(
        scan_result,
        first_read_bootstrap,
        power,
        index.runnable_walk_or_followup(
            scan_result,
            &local_holds.held_fingerprints,
            local_holds.progress_blocking,
            fresh_offer,
            &current_rfc3339(),
        ),
    ) {
        // The final tier runs gentler: background QoS at the same bootstrap pace.
        let first_import =
            first_import && !backfill_state.first_read_tier_final(upload_destination_namespace);
        let existing = continuation::resident_scan_requested(scan_result, first_read_bootstrap);
        pass_outcomes(|counts| {
            counts.paced_request_existing = u64::from(existing);
            counts.paced_request_bootstrap_runnable = u64::from(!existing);
            counts.paced_first_import = u64::from(first_import);
            counts.paced_power_allowed = u64::from(power == continuation::PlatformState::Allowed);
            counts.paced_power_battery = u64::from(power == continuation::PlatformState::Battery);
        });
        continuation::request_resident_scan_on_power(source, first_import, power);
    }

    // Refresh the per-source detected-uses cache the daemon health assembly
    // reads for the Companion's "Detected Uses" panel. The scan is incremental,
    // so this cycle's snapshots are a delta; the cache merge preserves
    // historical destinations. A failure here must never fail the sync, and the
    // error is not logged verbatim because it can embed a local filesystem path.
    if update_detected_uses_cache(support_dir, source, &scan_result.snapshots).is_err() {
        eprintln!(
            "local detected-uses cache update skipped for {}",
            source.api_slug()
        );
    }

    // A Claude census completed and settled under the history gate clears the
    // unverified marker. A fresh index recorded its cutoff this cycle and an
    // intact one keeps its entries, so the rebuilt history stays gated;
    // Claude's bootstrap and replays may then run.
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_post_save_failure("unverified_marker")?;
    if claude_replay_suppressed(source, backfill_state)
        && scan_result.census_complete
        && upload_fully_settled
    {
        clear_unverified_marker(source, support_dir)?;
    }

    // A tier waits only for work in flight inside the import; refusals and
    // account holds stay owed. Order only: a failed save retries later.
    let tier_finished = tier_settled(
        upload_fully_settled,
        upload_completed || resolved_permanent_rejections,
        local_holds,
    ) && index.first_read_tier_finished(source, |fingerprint| {
        upload_progress
            .permanent_rejections
            .get(fingerprint)
            .map(|rejection| rejection.body_witness.clone())
    });
    if tier_finished {
        match crate::backfill::record_first_read_tier_pass(
            support_dir,
            source,
            upload_destination_namespace,
            &super::enabled_snapshot_sources_in(device, support_dir),
        ) {
            // Every participant reads the next tier now; the final at background QoS.
            Ok(Some((wake, first_import))) => {
                for participant in wake {
                    continuation::request_resident_scan_on_power(participant, first_import, power);
                }
            }
            Ok(None) => {}
            Err(error) => eprintln!(
                "local snapshot backfill tier save deferred for {}: {}",
                source.api_slug(),
                safe_error(&error)
            ),
        }
    }

    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_post_save_failure("backfill_completion")?;
    if backfill_succeeded {
        record_backfill_completion(
            source,
            support_dir,
            upload_destination_namespace,
            scan_started_at,
        )?;
    }
    Ok(())
}

/// Retires this pass's upload progress after the index save and any marker
/// writes that were due: pending cache heads, stale refusals, the planned ACKs
/// and identity custody, then the durable ledger save, which can fail the pass.
fn retire_upload_progress(
    env: &FinishEnv<'_>,
    upload_progress: &mut SnapshotUploadProgress,
    index: &ScanIndex,
    scan_result: &SourceScanResult,
    end: PassEnd<'_>,
    retirement: ProgressRetirement<'_>,
) -> Result<()> {
    let FinishEnv {
        source,
        upload_progress_path,
        daemon,
        ..
    } = *env;
    let PassEnd {
        upload_fully_settled,
        ..
    } = end;
    let ProgressRetirement {
        locally_held_fingerprints,
        projected_pending_head_file_witnesses,
        current_entities,
        retired_upload_acks,
        walk_retired,
        identity_503_this_pass,
    } = retirement;
    // Final scan/backfill markers are durable before page progress is retired.
    // Accepted cache evidence and head tokens remain in this same ACK-owned
    // ledger across successful cycles so later corrections can retract safely.
    let exhausted_cache_heads = upload_progress.retire_pending_cache_heads(
        index,
        &scan_result.snapshots,
        locally_held_fingerprints,
        scan_result.census_complete,
        projected_pending_head_file_witnesses,
    );
    if exhausted_cache_heads > 0 {
        eprintln!(
            "local snapshot cache heads settled for {}: pending_cache_heads_retired_exhausted={exhausted_cache_heads}",
            source.api_slug()
        );
    }
    upload_progress
        .permanent_rejections
        .retain(|fingerprint, refusal| {
            refusal.has_stale_debt() || current_entities.contains(fingerprint)
        });
    // Before `finish_cycle` retires this cycle's quarantine records.
    let retained_refusals = PermanentRefusalCounts::of(upload_progress);
    let retained_downgrades = PermanentRefusalCounts::authority_downgrades(upload_progress);
    log_retained_permanent_refusals(
        source,
        retained_refusals,
        retained_downgrades,
        upload_fully_settled,
    );
    upload_progress.add_saved_handoff_retirements(retired_upload_acks, index);
    upload_progress.retire_planned_acks_after_index_save(
        index,
        retired_upload_acks,
        locally_held_fingerprints,
    );
    if walk_retired {
        upload_progress.retire_identity_503_custody(
            identity_503_this_pass.unwrap_or_default(),
            index.owes_isolated_503(),
        );
    }
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_post_save_failure("finish_cycle")?;
    upload_progress.finish_cycle(upload_progress_path)?;
    crate::local_resource_diagnostics::pass_retained(source.api_slug(), || {
        daemon.transcript_cache.retained_heap_bytes(index)
    });
    Ok(())
}

/// The terminal receipt and what follows it. Attempts the refusal receipt
/// without changing the refusal outcome on a send error; a failed success
/// receipt is returned before the walk gate is armed.
fn report_and_arm(
    env: &FinishEnv<'_>,
    upload_progress: &SnapshotUploadProgress,
    index: &ScanIndex,
    scan_result: &SourceScanResult,
    walk_idle_pass: Option<(crate::snapshots::walk_idle::Pass, bool)>,
    end: PassEnd<'_>,
) -> Result<()> {
    let FinishEnv {
        source,
        client,
        device,
        device_secret,
        machine_id,
        support_dir,
        index_path,
        activity_hint,
        receipt_window_days,
        ..
    } = *env;
    let PassEnd {
        deferred_entity_count,
        resolved_permanent_rejections,
        permanent_refusals,
        upload_fully_settled,
        isolated_only,
        accepted,
        terminal_scan_started_at,
        ..
    } = end;
    if let Some(count) = deferred_entity_count {
        let state = refused_entity_state(
            resolved_permanent_rejections,
            permanent_refusals,
            upload_fully_settled,
        );
        // The uploader drained its frozen, scan-capped queue before returning
        // `Deferred`, and the index above now owns both accepted siblings and
        // entity quarantine. Surface the conflict only after those
        // facts are durable: returning earlier would recreate the per-source
        // starvation wedge, while reporting success would hide the backend's
        // capacity condition from source-level isolation and cadence handling.
        let _ = report_status_with_fresh_relay_token(
            client,
            device,
            device_secret,
            support_dir,
            source,
            if scan_result.census_complete {
                TerminalManifestSource::CompleteCensus(index)
            } else {
                TerminalManifestSource::Withdraw
            },
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: terminal_scan_started_at,
                counts: SyncCounts::from_scan_result(scan_result, accepted, receipt_window_days)
                    .with_snapshot_terminal_counts(index),
                state,
            },
        );
        if isolated_only {
            // Each refused body keeps its own exact retry custody; the sweep
            // stays unsettled, but the refusal no longer fails the pass.
            eprintln!(
                "local snapshot upload completed with {count} refused entity(ies) held for retry for {}",
                source.api_slug()
            );
        } else if !resolved_permanent_rejections {
            crate::snapshots::walk_idle::report_retired_unarmed(source, index, "entity_deferred");
            return Err(snapshot_entity_deferred(count));
        }
        crate::snapshots::walk_idle::report_retired_unarmed(source, index, "entity_refused");
        // Permanent refusals remain disclosed after the durable save; a
        // reporting failure does not change the resolved transport outcome.
        return Ok(());
    } else {
        // This walk's loss blocks arming; standing terminal holds do not.
        let counts = SyncCounts::from_scan_result(scan_result, accepted, receipt_window_days)
            .with_snapshot_terminal_counts(index);
        let loss_free = !counts.has_walk_loss(index);
        let terminal_window_days = report_status_with_fresh_relay_token(
            client,
            device,
            device_secret,
            support_dir,
            source,
            if scan_result.census_complete {
                TerminalManifestSource::CompleteCensus(index)
            } else {
                TerminalManifestSource::Withdraw
            },
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: terminal_scan_started_at,
                counts,
                state: CollectorState::Success,
            },
        )
        .inspect_err(|_| {
            crate::snapshots::walk_idle::report_retired_unarmed(source, index, "receipt_failed");
        })?;
        if terminal_window_days == 0 {
            // The receipt went out as a tombstone: the server holds no census
            // for a record to stand for, so the next pass at a real window walks.
            crate::snapshots::walk_idle::clear(source, "window_zero");
            crate::snapshots::walk_idle::report_retired_unarmed(source, index, "window_zero");
        } else if let Some((pass, cycle_owed_nothing)) = walk_idle_pass {
            let now = crate::scan_clock::utc_seconds();
            let outside = cycle_owed_nothing
                && loss_free
                && upload_fully_settled
                && super::prepare::upload_owes_nothing(
                    source,
                    upload_progress,
                    support_dir,
                    activity_hint,
                    index,
                    now,
                );
            crate::snapshots::walk_idle::arm_after_finish(
                pass,
                index,
                index_path,
                scan_result,
                outside,
            );
        }
    }
    Ok(())
}

/// The state a failed upload's terminal receipt carries, and the context its
/// error is returned with. On the way it emits branch-specific diagnostics,
/// updates the capacity-stop streak for a pending ACK settlement, and records
/// the upload loss in the catch-all arm.
fn classify_upload_failure(
    source: SnapshotSource,
    error: &anyhow::Error,
    census_wait: &mut ack_retention::CapacityStopCensusCount,
    census_complete: bool,
) -> (CollectorState<'static>, &'static str) {
    // Distinguish local serializer drift, authorization failures, and
    // backend payload rejection. The resumable driver has already
    // checkpointed every accepted sibling before this terminal error.
    if let Some(settlement) = error.downcast_ref::<ack_retention::AckSettlementRequired>() {
        let incomplete_census_stops = census_wait.capacity_stop(census_complete);
        eprintln!(
            "ottto-service: local snapshot upload deferred for {} — {} consecutive_incomplete_census_stops={}",
            source.api_slug(),
            upload_failure_diagnostic(error),
            incomplete_census_stops
        );
        (
            settlement.collector_state(),
            "local snapshot ACK settlement pending",
        )
    } else if snapshot_upload_error_class(error) == Some(SnapshotUploadErrorClass::LocalState) {
        (
            CollectorState::Error {
                code: "scan_error",
                message: "local snapshot checkpoint or destination state failed",
            },
            "local snapshot state failed",
        )
    } else if snapshot_upload_error_class(error) == Some(SnapshotUploadErrorClass::BackendResponse)
    {
        (
            CollectorState::Error {
                code: "server_error",
                message: "backend snapshot response did not match the request",
            },
            "backend snapshot response was invalid",
        )
    } else if let Some(rejected) = error.downcast_ref::<SnapshotBatchPreflightRejected>() {
        eprintln!(
            "ottto-service: local snapshot batch failed daemon v{} contract preflight for {} — {}; usage/cost sync is NOT reaching the backend until the daemon serializer is fixed.",
            SNAPSHOT_SCHEMA_VERSION,
            source.api_slug(),
            rejected.reason,
        );
        (
            CollectorState::Error {
                code: "backend_validation_error",
                message: "local snapshot batch failed daemon/backend contract preflight",
            },
            "local snapshot batch failed daemon/backend contract preflight",
        )
    } else if let Some(rejected) = error.downcast_ref::<BatchAuthorizationRejected>() {
        eprintln!(
            "ottto-service: snapshot batch authorization rejected by backend (HTTP {}) \
                     for {}; start setup or sign in from the Ottto app before retrying \
                     local usage sync.",
            rejected.status,
            source.api_slug(),
        );
        (
            CollectorState::Error {
                code: "auth_error",
                message: "backend rejected snapshot batch authorization",
            },
            "backend rejected snapshot batch authorization",
        )
    } else if let Some(rejected) = error.downcast_ref::<BatchRejected>() {
        eprintln!("ottto-service: source={} {rejected}", source.api_slug());
        (
            CollectorState::Error {
                code: "backend_validation_error",
                message: "backend rejected snapshot batch payload validation",
            },
            "backend rejected snapshot batch payload validation",
        )
    } else {
        // A shed request is not a network failure. 429 is unambiguous in
        // the redacted diagnostics today; 503 joins it with the typed
        // `Retry-After` handling, which is where the backoff itself
        // lives. The collector status code stays `network_error` — that
        // string is a backend contract, and only the loss category is
        // being classified here.
        ack_retention::record_upload_failure_loss(error);
        // Everything above this arm names its own cause. This arm is
        // the catch-all, and it used to log the bare phrase "local
        // snapshot upload failed" with no status code, endpoint, or
        // body — which is undiagnosable from a log alone and cost a
        // full reverse-engineering pass to classify. Always emit the
        // redacted failure shape here: the typed transport/HTTP
        // diagnostic when the request reached the wire, and the
        // classified reason when it failed before that.
        eprintln!(
            "ottto-service: local snapshot upload failed for {} — {}; \
                     daemon SNAPSHOT_SCHEMA_VERSION={}.",
            source.api_slug(),
            upload_failure_diagnostic(error),
            SNAPSHOT_SCHEMA_VERSION,
        );
        (
            CollectorState::Error {
                code: "network_error",
                message: "local snapshot upload failed",
            },
            "upload local snapshots",
        )
    }
}

/// Clears the unverified-history marker after a settled Claude census.
fn clear_unverified_marker(source: SnapshotSource, support_dir: &Path) -> Result<()> {
    if let Err(error) = crate::backfill::clear_prior_history_unverified(support_dir) {
        eprintln!(
            "local snapshot backfill state save failed for {}: {}",
            source.api_slug(),
            safe_error(&error)
        );
        return Err(anyhow!("local snapshot backfill state save failed"));
    }
    Ok(())
}

/// Marks this destination's backfill complete and stores the supplied scan-start
/// timestamp.
fn record_backfill_completion(
    source: SnapshotSource,
    support_dir: &Path,
    upload_destination_namespace: &str,
    scan_started_at: &str,
) -> Result<()> {
    // Keep completion's reload, mutation and save atomic with claims,
    // list intent and deliberate installation reset.
    if let Err(error) = update_backfill_state(support_dir, |backfill_state| {
        mark_backfill_complete_for_destination(
            backfill_state,
            source,
            upload_destination_namespace,
        );
        backfill_state.last_completed_at = Some(scan_started_at.to_owned());
    }) {
        eprintln!(
            "local snapshot backfill state save failed for {}: {}",
            source.api_slug(),
            safe_error(&error)
        );
        return Err(anyhow!("local snapshot backfill state save failed"));
    }
    Ok(())
}
