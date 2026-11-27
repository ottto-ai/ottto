//! The steps of a source-sync finish that `finish_sync_source` calls: the local
//! evidence fold, then the pass settlement and backfill markers, upload-progress
//! retirement, and the terminal receipt with the walk gate, with the values they
//! share.

#[cfg(test)]
use super::tests;
use super::{
    ack_retention, anyhow, apply_backfill_cutoff, apply_backfill_cutoff_with_claude_corrections,
    apply_claude_local_evidence_to_scan_with_ledger_and_budget, claude_replay_suppressed,
    continuation, current_rfc3339, identity_cache_wire_reserve, log_retained_permanent_refusals,
    mark_backfill_complete_for_destination, pass_outcomes, reconciliation_agent_status,
    record_collection_complete, refused_entity_state, report_status_with_fresh_relay_token,
    safe_error, snapshot_entity_deferred, source_kind, tier_settled, update_backfill_state,
    update_detected_uses_cache, with_source_cadence, BTreeMap, BTreeSet, CollectorState,
    CollectorStatus, Instant, LocalDaemon, LocalDeviceBinding, LocalHoldSettlement, OffsetDateTime,
    Path, PathBuf, PermanentRefusalCounts, PlatformGates, Result, Rfc3339, ScanIndex, SnapshotItem,
    SnapshotSource, SnapshotUploadPolicy, SnapshotUploadProgress, SourceScanResult, SyncCounts,
    TerminalManifestSource, MAX_CYCLE_INTERVAL, SNAPSHOT_SYNC_INTERVAL,
};

/// What a finish reads and never changes from the local evidence fold on: fixed
/// values of the preparation and the caller's handles, built once before the fold.
#[derive(Clone, Copy)]
pub(super) struct FinishEnv<'a> {
    pub(super) source: SnapshotSource,
    pub(super) client: &'a crate::snapshot_sync::SnapshotApiClient,
    pub(super) device: &'a LocalDeviceBinding,
    pub(super) device_secret: &'a str,
    pub(super) machine_id: &'a str,
    pub(super) support_dir: &'a Path,
    pub(super) index_path: &'a Path,
    pub(super) activity_hint: &'a crate::snapshot_client::ActivityHintResponse,
    pub(super) receipt_window_days: u64,
    pub(super) backfill_pending: bool,
    pub(super) backfill_state: &'a crate::backfill::BackfillState,
    pub(super) upload_destination_namespace: &'a str,
    pub(super) scan_started_at: &'a str,
    pub(super) upload_progress_path: &'a Path,
    pub(super) daemon: &'a LocalDaemon,
    pub(super) claude_scan_roots: &'a Option<Vec<PathBuf>>,
    pub(super) cache_observations_enabled: bool,
    pub(super) scan_agent_status_collection: &'a crate::agent_status::AgentStatusCollection,
    pub(super) upload_policy: SnapshotUploadPolicy,
    pub(super) cache_full_replacement: bool,
    pub(super) identity_item_cap: usize,
}

/// What the local evidence fold hands back to the finish: the backfill outcome so
/// far, the Claude usage authority disposition and the cutoff correction candidates.
pub(super) struct LocalEvidence {
    pub(super) backfill_succeeded: bool,
    pub(super) claude_authority_disposition: crate::snapshots::ClaudeUsageAuthorityDisposition,
    pub(super) claude_cutoff_corrections: Vec<crate::snapshots::ClaudeCutoffCorrectionCandidate>,
}

/// The pass's settled facts at the end of a finish, read by each step there.
#[derive(Clone, Copy)]
pub(super) struct PassEnd<'a> {
    pub(super) deferred_entity_count: Option<usize>,
    pub(super) resolved_permanent_rejections: bool,
    pub(super) permanent_refusals: PermanentRefusalCounts,
    pub(super) upload_fully_settled: bool,
    pub(super) isolated_only: bool,
    pub(super) accepted: u64,
    pub(super) terminal_scan_started_at: &'a str,
    pub(super) fresh_offer: bool,
    pub(super) upload_completed: bool,
    pub(super) backfill_succeeded: bool,
}

/// What retiring this pass's upload progress consumes from the pass.
pub(super) struct ProgressRetirement<'a> {
    pub(super) locally_held_fingerprints: &'a BTreeSet<String>,
    pub(super) projected_pending_head_file_witnesses: &'a BTreeMap<String, Option<String>>,
    pub(super) current_entities: &'a BTreeSet<String>,
    pub(super) retired_upload_acks: &'a mut ack_retention::AckRetirementPlan,
    pub(super) walk_retired: bool,
    pub(super) identity_503_this_pass: Option<BTreeSet<String>>,
}

/// The first phase of a finish: turns local evidence into the bodies this pass may
/// upload. In order: Claude root accounts, the telemetry seed and accepted identity
/// rows, the local evidence fold and its re-read queue, the copy-derived ledger save,
/// the history-upgrade emission veto, session account binding, the active-session
/// cache and tracking confirmation, the upload policy and the account-switch cutoff.
/// It sends nothing over the network.
pub(super) fn fold_local_evidence(
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
pub(super) fn settle_pass_and_markers(
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
    // and the terminal receipt (`report_and_arm`) still reports the held
    // entities.
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
            &crate::snapshot_sync::enabled_snapshot_sources_in(device, support_dir),
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
pub(super) fn retire_upload_progress(
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
pub(super) fn report_and_arm(
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
        // `Deferred`, and the saved index now owns both accepted siblings and
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
                && crate::snapshot_sync::prepare::upload_owes_nothing(
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
