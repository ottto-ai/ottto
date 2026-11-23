//! move snapshot status reporting into status.

use super::aggregate_detected_uses;
use super::anyhow;
use super::cached_source_manifest;
use super::collector_version;
use super::current_rfc3339;
use super::current_unix_seconds;
use super::lane::enabled_snapshot_sources;
use super::lane::snapshot_api_base_url;
use super::lane::snapshot_machine_id;
use super::load_backfill_state;
use super::load_snapshot_device_credentials;
use super::local_cadence_phase_offset;
use super::merge_detected_uses;
use super::persist_machine_icon;
use super::publish_source_manifest;
use super::rejection_log;
use super::safe_error;
use super::small_source_upload;
use super::snapshot_upload_destination_namespace;
use super::withdraw_source_manifest;
use super::AgentStatusSnapshot;
use super::AgentStatusSnapshotUploadRequest;
use super::BTreeMap;
use super::BTreeSet;
use super::CensusBlockCause;
use super::CodexScanDiagnostics;
use super::Context;
use super::DetectedUse;
use super::LocalDeviceBinding;
use super::Mutex;
use super::OffsetDateTime;
use super::OnceLock;
use super::Path;
use super::PathBuf;
use super::PermanentSnapshotRejection;
use super::Result;
use super::Rfc3339;
use super::ScanIndex;
use super::SnapshotApiClient;
use super::SnapshotItem;
use super::SnapshotQuarantineDisposition;
use super::SnapshotSource;
use super::SnapshotSourceManifest;
use super::SnapshotStatusReportKind;
use super::SnapshotStatusRequest;
use super::SnapshotUploadProgress;
use super::SourceKind;
use super::SourceScanResult;
use super::StageWindow;
use super::TimeDuration;
use super::CENSUS_RESIDUE_ERROR_CODE;
use super::CENSUS_RESIDUE_STATUS_CONTRACT;
use super::COLLECTOR_CHECKIN_INTERVAL;
use super::DETECTED_USE_RETENTION_DAYS;
use super::MAX_BACKFILL_FILES_PER_SOURCE;
use super::MAX_SNAPSHOT_STATUS_WINDOW_DAYS;
use super::SNAPSHOT_STATUS_SCHEMA_VERSION;
use super::UNPROVEN_TERMINAL_ATTEMPT_COUNT;
use crate::locked_state_dir::{replace_small_file_if_changed, SmallFileClass};

/// Entity fingerprints already counted as a client-report poison loss.
///
/// Legacy validation failures are re-attempted every cycle because they have no
/// durable per-entity settlement. Counting each attempt would make one broken
/// session look like an unbounded stream of losses — and if the source has no
/// valid sibling, no request ever succeeds, so nothing commits the report and
/// the number only grows. Entity-ACK rejections and local corruption are counted
/// through the same ledger after their quarantine checkpoint is durable.
///
/// Pruned to the current scan on every upload pass, exactly like the accepted
/// fingerprint ledger, so it stays O(current scan) rather than O(all history).
///
/// Keyed by upload scope (the source) because the prune is per scan: a Codex pass
/// must not prune Claude's ledger, or the next Claude cycle would count its
/// already-counted poison a second time.
static COUNTED_POISON_FINGERPRINTS: OnceLock<Mutex<BTreeMap<String, BTreeSet<String>>>> =
    OnceLock::new();

pub(super) fn counted_poison_fingerprints() -> &'static Mutex<BTreeMap<String, BTreeSet<String>>> {
    COUNTED_POISON_FINGERPRINTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Rest-heap diagnostics: scopes and fingerprints held, or None while busy.
pub(super) fn counted_poison_entries() -> Option<(usize, usize)> {
    let ledger = counted_poison_fingerprints().try_lock().ok()?;
    Some((ledger.len(), ledger.values().map(BTreeSet::len).sum()))
}

pub(super) fn retain_counted_poison_fingerprints(scope: &str, current: &BTreeSet<String>) {
    if let Ok(mut counted) = counted_poison_fingerprints().lock() {
        if let Some(ledger) = counted.get_mut(scope) {
            ledger.retain(|value| current.contains(value));
            if ledger.is_empty() {
                counted.remove(scope);
            }
        }
    }
}

/// Record one poison loss for `fingerprint`, at most once per entity per scope.
pub(super) fn record_poison_loss_once(scope: &str, fingerprint: &str) {
    let first_time = match counted_poison_fingerprints().lock() {
        Ok(mut counted) => counted
            .entry(scope.to_string())
            .or_default()
            .insert(fingerprint.to_string()),
        // A poisoned lock must not silently stop the accounting; over-reporting
        // a loss is recoverable, losing the signal is not.
        Err(_) => true,
    };
    if first_time {
        crate::client_report::record(crate::client_report::ClientReportReason::Poisoned, 1);
    }
}

#[cfg(test)]
pub(super) fn counted_poison_fingerprints_for_test(scope: &str) -> BTreeSet<String> {
    counted_poison_fingerprints()
        .lock()
        .expect("poison ledger")
        .get(scope)
        .cloned()
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SyncCounts {
    pub(super) census_status: crate::snapshots::CensusStatus,
    /// The walk gate held this pass: no census was taken, and none is lost.
    pub(super) walk_idle: bool,
    pub(super) backfill_window_days: u64,
    pub(super) backfill_file_limit: u64,
    pub(super) discovered_file_count: u64,
    pub(super) skipped_file_count_due_to_limit: u64,
    pub(super) scan_cap_hit: bool,
    pub(super) scanned_file_count: u64,
    pub(super) scanned_session_count: u64,
    pub(super) semantic_noop_count: u64,
    pub(super) census_complete: bool,
    pub(super) symlink_rejected_count: u64,
    pub(super) unreadable_path_count: u64,
    pub(super) oversized_file_count: u64,
    pub(super) disappeared_file_count: u64,
    pub(super) malformed_json_line_count: u64,
    pub(super) invalid_utf8_line_count: u64,
    pub(super) over_line_cap_count: u64,
    pub(super) recognized_usage_drop_count: u64,
    pub(super) ownership_incomplete_file_count: u64,
    pub(super) causes: crate::snapshots::ownership_diagnostics::Summary,
    pub(super) snapshot_unproven_terminal_count: u64,
    pub(super) snapshot_superseded_terminal_count: u64,
    pub(super) cooldown_conflict_deferred: usize,
    pub(super) zero_snapshot_confirmed_count: u64,
    pub(super) zero_snapshot_usage_evidence_count: u64,
    pub(super) dropped_usage_record_count: u64,
    /// The scan's settled share of each public loss counter above; see
    /// `SourceScanResult`. `terminal <= public` in every class.
    pub(super) terminal_ownership_incomplete_file_count: u64,
    pub(super) terminal_zero_snapshot_usage_evidence_count: u64,
    pub(super) terminal_recognized_usage_drop_count: u64,
    pub(super) terminal_dropped_usage_record_count: u64,
    pub(super) terminal_over_line_cap_count: u64,
    /// Residue witness cardinalities, counts only.
    pub(super) census_residue_index_key_count: u64,
    pub(super) census_residue_archived_rollout_count: u64,
    pub(super) uploaded_count: u64,
    pub(super) sidecar_reads: Option<CodexScanDiagnostics>,
}

/// How the loss a completed cycle discloses reads on its terminal receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DisclosedLoss {
    /// No ownership-incomplete file, no usage evidence without an entity, no
    /// dropped usage record.
    None,
    /// The census completed, no retryable problem remains, and every loss
    /// class equals its terminal counterpart: the receipt can prove, class by
    /// class, that all the loss it discloses is loss no retry can change.
    Terminal,
    /// Loss the daemon has not proved non-progressing: an incomplete census,
    /// a retryable problem beside the residue, or a class it has not settled.
    Unsettled,
}

impl SyncCounts {
    /// Loss a later traversal can still change. Mirrors
    /// `ScanTraversalCounts::has_retryable_problems` on the receipt's own
    /// counters so the receipt can never claim a settled residue the scan did
    /// not: a walk that could not enter, open, read, or parse something may
    /// simply not have seen the file that would resolve a fork.
    pub(super) fn has_retryable_problems(&self) -> bool {
        self.symlink_rejected_count > 0
            || self.unreadable_path_count > 0
            || self.oversized_file_count > 0
            || self.disappeared_file_count > 0
            || self.malformed_json_line_count > 0
            || self.invalid_utf8_line_count > 0
            || self.over_line_cap_count > self.terminal_over_line_cap_count
    }

    /// The loss classes that have always turned a successful cycle's receipt
    /// into a `parse_error`. Unchanged, so the legacy shape is byte-identical.
    pub(super) fn has_disclosed_loss(&self) -> bool {
        self.ownership_incomplete_file_count > 0
            || self.zero_snapshot_usage_evidence_count > 0
            || self.dropped_usage_record_count > 0
    }

    /// This walk's own loss. Standing terminal holds are disclosed again by
    /// every receipt, idle ones included, so they do not count.
    pub(super) fn has_walk_loss(&self, index: &ScanIndex) -> bool {
        let standing = self.snapshot_unproven_terminal_count
            + index.claude_usage_authority_terminal_entity_count() as u64;
        self.ownership_incomplete_file_count
            .saturating_sub(standing)
            > 0
            || self.zero_snapshot_usage_evidence_count > 0
            || self.dropped_usage_record_count > 0
    }

    pub(super) fn disclosed_loss(&self) -> DisclosedLoss {
        // A partial census is itself unsettled evidence even when it has not
        // yet populated one of the public loss counters. In particular,
        // RetryPending Claude authority families deliberately lower
        // `census_complete` and raise the scan-cap latch without inventing a
        // per-file loss. Letting the zero-loss fast path win here would emit a
        // clean success that the backend classifies as terminal.
        if self.walk_idle {
            return DisclosedLoss::None;
        }
        if !self.census_complete {
            return DisclosedLoss::Unsettled;
        }
        if !self.has_disclosed_loss() {
            return DisclosedLoss::None;
        }
        let every_class_terminal = self.ownership_incomplete_file_count
            == self.terminal_ownership_incomplete_file_count
            && self.zero_snapshot_usage_evidence_count
                == self.terminal_zero_snapshot_usage_evidence_count
            && self.recognized_usage_drop_count == self.terminal_recognized_usage_drop_count
            && self.dropped_usage_record_count == self.terminal_dropped_usage_record_count
            && self.over_line_cap_count == self.terminal_over_line_cap_count;
        if !self.has_retryable_problems() && every_class_terminal {
            DisclosedLoss::Terminal
        } else {
            DisclosedLoss::Unsettled
        }
    }

    pub(super) fn for_policy(backfill_window_days: u64) -> Self {
        Self {
            backfill_window_days,
            backfill_file_limit: MAX_BACKFILL_FILES_PER_SOURCE as u64,
            ..Self::default()
        }
    }

    pub(super) fn from_scan_result(
        scan_result: &SourceScanResult,
        uploaded_count: u64,
        receipt_window_days: u64,
    ) -> Self {
        Self {
            // Scan coverage and receipt evidence are deliberately different
            // during replay. The counters below describe the wider traversal;
            // this field and the manifest describe only the server-negotiated
            // semantic activity window.
            backfill_window_days: receipt_window_days,
            census_status: scan_result.census_status,
            walk_idle: scan_result.walk_idle,
            backfill_file_limit: scan_result.backfill_file_limit as u64,
            discovered_file_count: scan_result.discovered_file_count as u64,
            skipped_file_count_due_to_limit: scan_result.skipped_file_count_due_to_limit as u64,
            scan_cap_hit: scan_result.scan_cap_hit,
            scanned_file_count: scan_result.scanned_file_count as u64,
            scanned_session_count: scan_result.scanned_session_count as u64,
            semantic_noop_count: scan_result.semantic_noop_count as u64,
            census_complete: scan_result.census_complete,
            symlink_rejected_count: scan_result.symlink_rejected_count as u64,
            unreadable_path_count: scan_result.unreadable_path_count as u64,
            oversized_file_count: scan_result.oversized_file_count as u64,
            disappeared_file_count: scan_result.disappeared_file_count as u64,
            malformed_json_line_count: scan_result.malformed_json_line_count as u64,
            invalid_utf8_line_count: scan_result.invalid_utf8_line_count as u64,
            over_line_cap_count: scan_result.over_line_cap_count as u64,
            recognized_usage_drop_count: scan_result.recognized_usage_drop_count as u64,
            ownership_incomplete_file_count: scan_result.ownership_incomplete_file_count as u64,
            causes: scan_result
                .causes
                .summary(scan_result.ownership_incomplete_file_count),
            snapshot_unproven_terminal_count: 0,
            snapshot_superseded_terminal_count: 0,
            cooldown_conflict_deferred: 0,
            zero_snapshot_confirmed_count: scan_result.zero_snapshot_confirmed_count as u64,
            zero_snapshot_usage_evidence_count: scan_result.zero_snapshot_usage_evidence_count
                as u64,
            dropped_usage_record_count: scan_result.dropped_usage_record_count,
            terminal_ownership_incomplete_file_count: scan_result
                .terminal_ownership_incomplete_file_count
                as u64,
            terminal_zero_snapshot_usage_evidence_count: scan_result
                .terminal_zero_snapshot_usage_evidence_count
                as u64,
            terminal_recognized_usage_drop_count: scan_result.terminal_recognized_usage_drop_count
                as u64,
            terminal_dropped_usage_record_count: scan_result.terminal_dropped_usage_record_count,
            terminal_over_line_cap_count: scan_result.terminal_over_line_cap_count as u64,
            census_residue_index_key_count: scan_result.census_residue_index_key_count as u64,
            census_residue_archived_rollout_count: scan_result.census_residue_archived_rollout_count
                as u64,
            uploaded_count,
            sidecar_reads: scan_result.local_codex_diagnostics,
        }
    }

    pub(super) fn terminal_census_line(&self, source: &str) -> String {
        let mut line = format!(
            "snapshot terminal_census source={source} census_complete={} scanned_files={} \
             uploaded={} unproven_terminal={} unproven_terminal_attempt_count={} superseded_terminal={} \
             ownership_incomplete_files={} zero_snapshot_usage_evidence_files={} \
             dropped_usage_records={} cooldown_conflict_deferred={} terminal_contract_retry={} terminal_contract_retry_exhausted={}",
            self.census_complete,
            self.scanned_file_count,
            self.uploaded_count,
            self.snapshot_unproven_terminal_count,
            UNPROVEN_TERMINAL_ATTEMPT_COUNT.load(std::sync::atomic::Ordering::Relaxed),
            self.snapshot_superseded_terminal_count,
            self.ownership_incomplete_file_count,
            self.zero_snapshot_usage_evidence_count,
            self.dropped_usage_record_count,
            self.cooldown_conflict_deferred,
            crate::snapshots::terminal_contract_retry::local_count(),
            crate::snapshots::terminal_contract_retry::exhausted_count(),
        );
        if source == "codex" {
            line.push_str(&crate::snapshots::ownership_diagnostics::line(self.causes));
            if let Some(d) = self.sidecar_reads {
                line.push_str(&format!(" state_5_reused={} state_5_reloaded={} thread_history_1_reused={} thread_history_1_reloaded={} session_index_reused={} session_index_reloaded={} absent_roots={} sidecar_facts_heap_bytes={}",
                    d.state_titles.reused_roots, d.state_titles.reloaded_roots,
                    d.rollout_extents.reused_roots, d.rollout_extents.reloaded_roots,
                    d.session_index.reused_roots, d.session_index.reloaded_roots,
                    d.state_titles.absent_roots, d.sidecar_facts_heap_bytes));
                let or_none = |cause: &'static str| if cause.is_empty() { "none" } else { cause };
                line.push_str(&format!(
                    " sidecar_reload_cause={} sidecar_keep_declined={}",
                    or_none(d.sidecar_reload_cause),
                    or_none(d.sidecar_keep_declined)
                ));
                for (input, homes) in ["state_5", "thread_history_1", "session_index"]
                    .iter()
                    .zip(d.sidecar_changed_homes)
                {
                    line.push_str(&format!(" {input}_changed={}", homes.count_ones()));
                    if homes != 0 {
                        let bits = (0..64u32).filter(|bit| homes & (1 << bit) != 0);
                        let bits = bits.map(|bit| bit.to_string()).collect::<Vec<_>>();
                        line.push_str(&format!(" {input}_changed_homes={}", bits.join(",")));
                    }
                }
            }
        }
        if self.walk_idle {
            line.push_str(" walk_idle=true");
        }
        line
    }

    pub(super) fn with_snapshot_terminal_counts(mut self, index: &ScanIndex) -> Self {
        self.cooldown_conflict_deferred = index.reason_reoffer_cooldown_deferred_count();
        self.snapshot_unproven_terminal_count = index.snapshot_unproven_terminal_count() as u64;
        self.snapshot_superseded_terminal_count = index.snapshot_superseded_terminal_count() as u64;
        // Follow the existing disclosed-loss convention: terminal unproven entities
        // also contribute to the established incomplete-evidence health scalar.
        self.ownership_incomplete_file_count = self
            .ownership_incomplete_file_count
            .saturating_add(self.snapshot_unproven_terminal_count);
        // They are terminal by disposition (the bounded reconstruction ladder
        // is exhausted), so the settled share grows by exactly the same
        // number: the ownership-incomplete class stays matched, and the
        // receipt keeps `terminal <= public`.
        self.terminal_ownership_incomplete_file_count = self
            .terminal_ownership_incomplete_file_count
            .saturating_add(self.snapshot_unproven_terminal_count);
        // Account-deferred holds are retried every generation, so they are
        // disclosed as incomplete ownership but never as settled residue: the
        // public count exceeds the terminal share and the receipt stays
        // unsettled for as long as any hold persists.
        self.ownership_incomplete_file_count = self
            .ownership_incomplete_file_count
            .saturating_add(index.claude_account_deferred_hold_count() as u64);
        self
    }
}

pub(super) fn validated_receipt_window_days(negotiated_window_days: u64) -> Result<u64> {
    if negotiated_window_days > MAX_SNAPSHOT_STATUS_WINDOW_DAYS {
        return Err(anyhow!(
            "snapshot status evidence window is outside the supported 0..={MAX_SNAPSHOT_STATUS_WINDOW_DAYS} day range"
        ));
    }
    Ok(negotiated_window_days)
}

pub(super) fn scan_request_window_days(receipt_window_days: u64, backfill_pending: bool) -> u64 {
    if backfill_pending {
        // The scanner applies its own local safety ceiling. `u64::MAX` means
        // "walk the complete replay range", not "claim this width upstream".
        u64::MAX
    } else {
        receipt_window_days
    }
}

pub(super) fn snapshot_manifest_window(
    census_window_end: &str,
    receipt_window_days: u64,
) -> Result<(String, String)> {
    let receipt_window_days = validated_receipt_window_days(receipt_window_days)?;
    if receipt_window_days == 0 {
        return Err(anyhow!(
            "zero-width snapshot status evidence must be manifest-free"
        ));
    }
    let window_end = OffsetDateTime::parse(census_window_end, &Rfc3339)
        .context("parse snapshot manifest window end")?;
    let window_start = window_end
        .checked_sub(TimeDuration::days(receipt_window_days as i64))
        .ok_or_else(|| anyhow!("snapshot manifest window overflow"))?;
    Ok((
        window_start
            .format(&Rfc3339)
            .context("format snapshot manifest window start")?,
        window_end
            .format(&Rfc3339)
            .context("format snapshot manifest window end")?,
    ))
}

pub(super) fn snapshot_manifest_window_days(manifest: &SnapshotSourceManifest) -> Result<u64> {
    let window_start = OffsetDateTime::parse(&manifest.window_start, &Rfc3339)
        .context("parse cached snapshot manifest window start")?;
    let window_end = OffsetDateTime::parse(&manifest.window_end, &Rfc3339)
        .context("parse cached snapshot manifest window end")?;
    let window_seconds = (window_end - window_start).whole_seconds();
    let day_seconds = 24 * 60 * 60;
    if window_seconds <= 0 || window_seconds % day_seconds != 0 {
        return Err(anyhow!(
            "cached snapshot manifest window is not a positive whole-day interval"
        ));
    }
    let window_days = u64::try_from(window_seconds / day_seconds)
        .context("convert cached snapshot manifest window days")?;
    validated_receipt_window_days(window_days)
}

pub(super) fn deferred_entity_state(permanent: bool) -> CollectorState<'static> {
    CollectorState::Error {
        code: if permanent {
            "backend_validation_error"
        } else {
            "server_error"
        },
        message: if permanent {
            "backend permanently rejected exact snapshot bodies; accepted siblings checkpointed"
        } else {
            "backend has unsettled snapshot entities; accepted siblings checkpointed"
        },
    }
}

/// Current permanent refusals in the upload ledger. Content-free: counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct PermanentRefusalCounts {
    pub(super) total: usize,
    /// Refusals the backend already dominates with an accepted record.
    pub(super) dominated: usize,
    pub(super) exposure: crate::local_resource_diagnostics::RefusalExposure,
}

impl PermanentRefusalCounts {
    /// A refusal counts as dominated only while its quarantine record is still
    /// the terminal record for the same refused body. A newer body of that
    /// entity with a pending outcome, such as a retryable conflict, owes its
    /// own result, so the older refusal then counts as other.
    pub(super) fn of(progress: &SnapshotUploadProgress) -> Self {
        progress.permanent_rejections.iter().fold(
            Self {
                exposure: progress.refusal_exposure(current_unix_seconds()),
                ..Self::default()
            },
            |mut counts, (fingerprint, refusal)| {
                counts.total += 1;
                if Self::is_dominated(progress, fingerprint, refusal) {
                    counts.dominated += 1;
                }
                counts
            },
        )
    }

    /// Dominated refusals whose reason is an authority downgrade. That guard
    /// has refused real growth before, so the local log keeps their own count.
    pub(super) fn authority_downgrades(progress: &SnapshotUploadProgress) -> usize {
        progress
            .permanent_rejections
            .iter()
            .filter(|(fingerprint, refusal)| {
                refusal.reason
                    == crate::upload_receipts::RejectedUsageReason::UsageAccountingAuthorityDowngrade
                    && Self::is_dominated(progress, fingerprint, refusal)
            })
            .count()
    }

    pub(super) fn is_dominated(
        progress: &SnapshotUploadProgress,
        fingerprint: &str,
        refusal: &PermanentSnapshotRejection,
    ) -> bool {
        (refusal.reason.is_dominated() || (refusal.is_stale() && refusal.exposure.is_some()))
            && !refusal
                .revisions
                .values()
                .any(PermanentSnapshotRejection::owed)
            && progress
                .quarantined_fingerprints
                .get(fingerprint)
                .is_some_and(|record| {
                    matches!(
                        record.disposition,
                        SnapshotQuarantineDisposition::UnprovenTerminal
                            | SnapshotQuarantineDisposition::SupersededTerminal
                    ) && record.upload_body_witness.as_deref()
                        == Some(refusal.body_witness.as_str())
                })
    }
}

/// Last retained-refusal log line per source. A quiet cycle that re-discloses
/// the same list does not log it again.
static SOURCE_REFUSAL_LOGS: Mutex<[Option<RefusalLogLine>; 3]> = Mutex::new([None, None, None]);

/// Retained refusal counts, the authority-downgrade share of the dominated
/// ones, and whether they were reported as settled residue.
pub(super) type RefusalLogLine = (PermanentRefusalCounts, usize, bool);

/// Content-free, local-only: counts of the refusals retained this cycle, with
/// the dominated ones split by reason, and whether the cycle reported them as
/// settled residue. Logs on change only; each refusal is also logged with its
/// reason when it arrives.
pub(super) fn log_retained_permanent_refusals(
    source: SnapshotSource,
    retained: PermanentRefusalCounts,
    authority_downgrades: usize,
    settled_residue: bool,
) {
    let line = (retained, authority_downgrades, settled_residue);
    let Some(previous) = rejection_log::changed(&SOURCE_REFUSAL_LOGS, source, line) else {
        return;
    };
    if previous.is_some_and(|p| retained.exposure.owed_entities > p.0.exposure.owed_entities) {
        eprintln!("ottto-service: refusal exposure alarm source={} reason=accepted_log_stale_older_upload owed_entities={} oldest_age_seconds={}", source.api_slug(), retained.exposure.owed_entities, retained.exposure.oldest_age_seconds);
    }
    eprintln!(
        "local snapshot sync retains {} dominated ({} usage_accounting_authority_downgrade) \
         and {} other permanent refusal(s) for {}{}; reason=accepted_log_stale_older_upload \
         owed_entities={} known_requests={} known_tokens={} unknown_request_entities={} \
         unknown_token_entities={} unknown_age_entities={} oldest_age_seconds={}",
        retained.dominated,
        authority_downgrades,
        retained.total - retained.dominated,
        source.api_slug(),
        if settled_residue {
            "; reported as settled residue the backend already owns"
        } else {
            ""
        },
        retained.exposure.owed_entities,
        retained.exposure.known_requests,
        retained.exposure.known_tokens,
        retained.exposure.unknown_request_entities,
        retained.exposure.unknown_token_entities,
        retained.exposure.unknown_age_entities,
        retained.exposure.oldest_age_seconds,
    );
}

/// Status only: an otherwise settled cycle with dominated or stale-owed
/// refusals remains successful. Existing residue counters keep their receipt
/// shape; stale debt remains owed in custody and diagnostics, never accepted.
/// Other refusals and unsettled transport retain their existing status.
pub(super) fn refused_entity_state(
    permanent: bool,
    refusals: PermanentRefusalCounts,
    upload_fully_settled: bool,
) -> CollectorState<'static> {
    if permanent
        && upload_fully_settled
        && refusals.total > 0
        && refusals.dominated + refusals.exposure.owed_entities == refusals.total
    {
        CollectorState::Success
    } else {
        deferred_entity_state(permanent)
    }
}

#[derive(Debug)]
pub(super) enum CollectorState<'a> {
    Success,
    /// A server-authoritative zero-width policy withdraws the prior census
    /// without claiming either a successful scan or a collector failure.
    PolicyTombstone,
    Disabled(Option<String>),
    Error {
        code: &'a str,
        message: &'a str,
    },
}

#[derive(Debug)]
pub(super) struct CollectorStatus<'a> {
    pub(super) source: SnapshotSource,
    pub(super) machine_id: &'a str,
    pub(super) scan_started_at: &'a str,
    pub(super) counts: SyncCounts,
    pub(super) state: CollectorState<'a>,
}

#[derive(Clone, Copy)]
pub(super) enum TerminalManifestSource<'a> {
    Withdraw,
    CompleteCensus(&'a ScanIndex),
}

/// Aggregate this cycle's snapshots into detected uses, merge them into the
/// persisted per-source cache, and write it back atomically (temp + rename,
/// skipped when the file already holds the bytes). The merge keeps historical
/// destinations that this incremental cycle did not re-scan.
pub(super) fn update_detected_uses_cache(
    support_dir: &Path,
    source: SnapshotSource,
    snapshots: &[SnapshotItem],
) -> Result<()> {
    let dir = support_dir.join("detected_uses");
    let path = detected_uses_cache_path(support_dir, source);
    let merged = merge_detected_uses(
        read_detected_uses_cache(&path),
        aggregate_detected_uses(snapshots),
        OffsetDateTime::now_utc(),
        TimeDuration::days(DETECTED_USE_RETENTION_DAYS),
    );

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create detected_uses dir {}", dir.display()))?;
    let payload = serde_json::to_vec_pretty(&merged).context("serialize detected uses to JSON")?;
    replace_small_file_if_changed(&path, &payload, SmallFileClass::PureCache)
        .with_context(|| format!("replace detected_uses cache {}", path.display()))?;
    Ok(())
}

/// Read the persisted detected-uses cache, or an empty list when it is missing
/// or unreadable (a fresh machine, or a malformed file we simply rebuild).
pub(crate) fn detected_uses_cache_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("detected_uses")
        .join(format!("{}.json", source.api_slug()))
}

pub(super) fn read_detected_uses_cache(path: &Path) -> Vec<DetectedUse> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub(super) fn upload_agent_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    machine_id: &str,
    snapshots: &[AgentStatusSnapshot],
) -> Result<usize> {
    if snapshots.is_empty() {
        return Ok(0);
    }
    let request = AgentStatusSnapshotUploadRequest {
        machine_id: machine_id.to_string(),
        snapshots: snapshots
            .iter()
            .cloned()
            .map(AgentStatusSnapshot::redacted_for_backend)
            .collect(),
    };
    let response = small_source_upload(snapshot_source_of_kind(&snapshots[0].source), || {
        client.upload_agent_status(relay_token, &request)
    })?;
    persist_machine_icon(&response);
    crate::net_resilience::note_upstream_upload_succeeded("agent_status");
    Ok(response.accepted as usize)
}

pub(crate) fn snapshot_source_of_kind(kind: &SourceKind) -> SnapshotSource {
    match kind {
        SourceKind::Codex => SnapshotSource::Codex,
        SourceKind::ClaudeCode => SnapshotSource::ClaudeCode,
        SourceKind::Pi => SnapshotSource::Pi,
    }
}

pub(super) fn source_kind(source: SnapshotSource) -> SourceKind {
    match source {
        SnapshotSource::Codex => SourceKind::Codex,
        SnapshotSource::ClaudeCode => SourceKind::ClaudeCode,
        SnapshotSource::Pi => SourceKind::Pi,
    }
}

/// Build the terminal collector receipt for a completed cycle.
///
/// Split from the send so tests can assert against the exact typed payload —
/// including its declared `report_kind` — rather than a hand-rolled lookalike.
pub(super) fn collector_status_request(
    destination_namespace: &str,
    status: CollectorStatus<'_>,
    census_residue_status_admitted: bool,
) -> Result<SnapshotStatusRequest> {
    let finished_at = current_rfc3339();
    let disclosed_loss = status.counts.disclosed_loss();
    let census_status_active = matches!(&status.state, CollectorState::Success)
        && !status.counts.census_complete
        && !status.counts.walk_idle;
    let (
        enabled,
        disabled_reason,
        mut last_error_code,
        last_error_message,
        mut consecutive_failures,
        terminal_succeeded,
    ) = match status.state {
        // A census that completed and whose every disclosed loss class is
        // exactly the loss the daemon settled as non-progressing. The scan
        // succeeded: the clock binds (`last_success_at`), nothing is retried,
        // and the code still names the residue so a consumer that needs a
        // fully clean receipt sees that loss was disclosed. Only under the
        // backend's explicit admission — its error-code set is closed, and an
        // unadmitted code would have the whole receipt rejected.
        CollectorState::Success
            if disclosed_loss == DisclosedLoss::Terminal && census_residue_status_admitted =>
        {
            (
                true,
                None,
                Some(CENSUS_RESIDUE_ERROR_CODE.to_string()),
                Some(census_residue_message(&status.counts)),
                0,
                true,
            )
        }
        // Loss the daemon has not proved non-progressing — or settled residue
        // that a backend predating the admission can only read in this legacy
        // shape. Byte-identical to every released daemon apart from the
        // additive residue counters, which such a backend ignores.
        CollectorState::Success if disclosed_loss != DisclosedLoss::None => (
            true,
            None,
            Some("parse_error".to_string()),
            Some("local usage evidence produced no session snapshot".to_string()),
            1,
            false,
        ),
        CollectorState::Success => (true, None, None, None, 0, true),
        CollectorState::PolicyTombstone => (true, None, None, None, 0, false),
        CollectorState::Disabled(disabled_reason) => (false, disabled_reason, None, None, 0, false),
        CollectorState::Error { code, message } => (
            true,
            None,
            Some(code.to_string()),
            Some(message.to_string()),
            1,
            false,
        ),
    };
    let mut block_cause = None;
    let mut next_retry_at = None;
    if census_status_active {
        let census = status.counts.census_status;
        // First failed gate wins; settled ownership does not block advancing discovery.
        block_cause = if status.counts.unreadable_path_count > 0 {
            Some(CensusBlockCause::UnreadableEvents)
        } else if status.counts.disappeared_file_count > 0 {
            Some(CensusBlockCause::DisappearedFiles)
        } else if census.state_loader_failed {
            Some(CensusBlockCause::StateLoader)
        } else if census.transport_reservation_refused {
            Some(CensusBlockCause::TransportReservation)
        } else if census.reconciliation_incomplete
            && status.counts.ownership_incomplete_file_count
                > status.counts.terminal_ownership_incomplete_file_count
        {
            Some(CensusBlockCause::OwnershipIncomplete)
        } else if !census.pending_work || census.retryable_problem {
            Some(CensusBlockCause::Other)
        } else {
            None
        };
        last_error_code = Some(
            if block_cause.is_some() {
                "census_blocked"
            } else {
                "census_incomplete"
            }
            .to_string(),
        );
        consecutive_failures = u64::from(census.retry_attempt);
        next_retry_at = census
            .retry_not_before_unix_seconds
            .and_then(|seconds| i64::try_from(seconds).ok())
            .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
            .and_then(|time| time.format(&Rfc3339).ok());
    }
    let manifest = cached_source_manifest(destination_namespace, status.source);
    if let Some(manifest) = manifest.as_ref() {
        if manifest.window_end != status.scan_started_at {
            return Err(anyhow!(
                "snapshot manifest window end does not match terminal scan start"
            ));
        }
        let manifest_window_days = snapshot_manifest_window_days(manifest)?;
        if manifest_window_days != status.counts.backfill_window_days {
            return Err(anyhow!(
                "snapshot manifest window does not match terminal receipt evidence window"
            ));
        }
    }
    let request = SnapshotStatusRequest {
        schema_version: SNAPSHOT_STATUS_SCHEMA_VERSION,
        source: status.source.api_slug().to_string(),
        machine_id: status.machine_id.to_string(),
        // This function has exactly one caller shape: a completed collector
        // cycle reporting its outcome. Success, parse failure, scan/upload
        // error, policy tombstone, and the disabled transition are all NEW
        // scan results, so the kind is a constant here rather than anything
        // derived from the fields below.
        report_kind: SnapshotStatusReportKind::ScanStatus,
        enabled,
        disabled_reason,
        last_scan_started_at: Some(status.scan_started_at.to_string()),
        last_scan_finished_at: Some(finished_at.clone()),
        last_success_at: terminal_succeeded.then_some(finished_at),
        last_error_code,
        last_error_message,
        last_uploaded_count: status.counts.uploaded_count,
        last_scanned_session_count: status.counts.scanned_session_count,
        last_scanned_file_count: status.counts.scanned_file_count,
        last_zero_snapshot_confirmed_count: status.counts.zero_snapshot_confirmed_count,
        last_zero_snapshot_usage_evidence_count: status.counts.zero_snapshot_usage_evidence_count,
        last_dropped_usage_record_count: status.counts.dropped_usage_record_count,
        last_ownership_incomplete_file_count: status.counts.ownership_incomplete_file_count,
        last_snapshot_unproven_terminal_count: status.counts.snapshot_unproven_terminal_count,
        last_snapshot_superseded_terminal_count: status.counts.snapshot_superseded_terminal_count,
        last_backfill_window_days: status.counts.backfill_window_days,
        first_read_cutoff: None,
        tier_ready_cutoff: None,
        last_backfill_file_limit: status.counts.backfill_file_limit,
        last_discovered_file_count: status.counts.discovered_file_count,
        last_skipped_file_count_due_to_limit: status.counts.skipped_file_count_due_to_limit,
        last_scan_cap_hit: status.counts.scan_cap_hit,
        last_semantic_noop_count: status.counts.semantic_noop_count,
        last_census_complete: Some(status.counts.census_complete),
        last_symlink_rejected_count: status.counts.symlink_rejected_count,
        last_unreadable_path_count: status.counts.unreadable_path_count,
        last_oversized_file_count: 0,
        last_disappeared_file_count: status.counts.disappeared_file_count,
        last_malformed_json_line_count: status.counts.malformed_json_line_count,
        last_invalid_utf8_line_count: status.counts.invalid_utf8_line_count,
        last_over_line_cap_count: status.counts.over_line_cap_count,
        last_recognized_usage_drop_count: status.counts.recognized_usage_drop_count,
        // Always sent, whichever error code the receipt carries: the settled
        // shares are scan evidence like the counters they decompose, and a
        // backend that declares them journals the disclosure even while the
        // code still reads `parse_error`. A backend that predates them ignores
        // them.
        last_terminal_ownership_incomplete_file_count: status
            .counts
            .terminal_ownership_incomplete_file_count,
        last_terminal_zero_snapshot_usage_evidence_count: status
            .counts
            .terminal_zero_snapshot_usage_evidence_count,
        last_terminal_recognized_usage_drop_count: status
            .counts
            .terminal_recognized_usage_drop_count,
        last_terminal_dropped_usage_record_count: status.counts.terminal_dropped_usage_record_count,
        last_terminal_over_line_cap_count: status.counts.terminal_over_line_cap_count,
        // A census verdict, so it is a function of the counts alone and not of
        // the admission: true exactly when every disclosed loss class was
        // settled this generation.
        last_census_residue_settled: disclosed_loss == DisclosedLoss::Terminal,
        last_census_residue_index_key_count: status.counts.census_residue_index_key_count,
        last_census_residue_archived_rollout_count: status
            .counts
            .census_residue_archived_rollout_count,
        last_census_pending_file_count: Some(status.counts.skipped_file_count_due_to_limit),
        last_census_block_cause: block_cause,
        consecutive_failures,
        next_retry_at,
        collector_version: Some(collector_version()),
        parser_version: Some(status.source.parser_version().to_string()),
        manifest,
        // A scan result, not a check-in: the field stays off this wire shape.
        control_plane: None,
    };
    Ok(request)
}

/// The residue a `census_residue` receipt names: classes and settled counts
/// only. Never a path, an index key, or a session id — the backend rejects a
/// path-shaped message outright, and the witness identifiers stay in the local
/// index.
pub(super) fn census_residue_message(counts: &SyncCounts) -> String {
    format!(
        "census completed with settled non-progressing residue: \
         ownership_incomplete_files={}, zero_snapshot_usage_evidence_files={}, \
         recognized_usage_drops={}, dropped_usage_records={}, over_line_cap_lines={}",
        counts.terminal_ownership_incomplete_file_count,
        counts.terminal_zero_snapshot_usage_evidence_count,
        counts.terminal_recognized_usage_drop_count,
        counts.terminal_dropped_usage_record_count,
        counts.terminal_over_line_cap_count,
    )
}

#[cfg(test)]
pub(super) fn report_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    destination_namespace: &str,
    status: CollectorStatus<'_>,
) -> Result<()> {
    let request = collector_status_request(destination_namespace, status, false)?;
    client.report_status(relay_token, &request)?;
    Ok(())
}

/// The terminal activity hint owns evidence width and admission of the census
/// residue code; both are read from the same fresh server answer.
#[derive(Debug, Clone, Copy)]
pub(super) struct TerminalReceiptPolicy {
    pub(super) receipt_window_days: u64,
    /// Exact match on `CENSUS_RESIDUE_STATUS_CONTRACT`, fail-closed: absent,
    /// null, and any other token keep the legacy receipt shape. The backend's
    /// error-code set is closed, so this is what keeps a daemon from having
    /// its entire terminal receipt rejected by a backend that predates the
    /// admission — whatever order the two are deployed in.
    pub(super) census_residue_status_admitted: bool,
}

pub(super) fn current_terminal_receipt_policy(
    client: &SnapshotApiClient,
    relay_token: &str,
    source: SnapshotSource,
) -> Result<TerminalReceiptPolicy> {
    let activity_hint = small_source_upload(source, || client.get_activity_hint(relay_token))?;
    Ok(TerminalReceiptPolicy {
        receipt_window_days: validated_receipt_window_days(activity_hint.backfill_window_days)?,
        census_residue_status_admitted: activity_hint.census_residue_status_contract.as_deref()
            == Some(CENSUS_RESIDUE_STATUS_CONTRACT),
    })
}

pub(super) fn current_receipt_window_days(
    client: &SnapshotApiClient,
    relay_token: &str,
    source: SnapshotSource,
) -> Result<u64> {
    Ok(current_terminal_receipt_policy(client, relay_token, source)?.receipt_window_days)
}

pub(super) fn refresh_terminal_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
    scan_started_at: &str,
    receipt_window_days: u64,
    manifest_source: TerminalManifestSource<'_>,
) -> Result<()> {
    // Withdraw first so a failed refresh cannot leave a stale-width witness for
    // the independent heartbeat to repeat. Zero has no v2 manifest by design.
    withdraw_source_manifest(destination_namespace, source);
    if receipt_window_days == 0 {
        return Ok(());
    }
    let TerminalManifestSource::CompleteCensus(index) = manifest_source else {
        return Ok(());
    };
    let (window_start, window_end) =
        snapshot_manifest_window(scan_started_at, receipt_window_days)?;
    publish_source_manifest(
        destination_namespace,
        source,
        index.manifest_for_window(source, &window_start, &window_end)?,
    );
    Ok(())
}

pub(super) fn report_status_with_fresh_relay_token(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    support_dir: &Path,
    source: SnapshotSource,
    manifest_source: TerminalManifestSource<'_>,
    mut status: CollectorStatus<'_>,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    // This is the single terminal report boundary. Every terminal outcome
    // reacquires its width here, after scanning/uploading and immediately
    // before deriving both the manifest and status scalar from that same hint
    // — and reads the census residue admission off that hint, so receipt
    // shape and evidence width are decided by one server answer.
    let TerminalReceiptPolicy {
        receipt_window_days,
        census_residue_status_admitted,
    } = current_terminal_receipt_policy(client, &relay_token, source)?;
    let destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    status.counts.backfill_window_days = receipt_window_days;
    if receipt_window_days == 0 {
        status.counts.census_complete = false;
        status.state = CollectorState::PolicyTombstone;
    }
    refresh_terminal_manifest(
        &destination_namespace,
        source,
        status.scan_started_at,
        receipt_window_days,
        manifest_source,
    )?;
    // Keep non-blocking cooldown debt beside the terminal census counters on
    // every report, even when the re-offer work summary is unchanged/quiet.
    eprintln!("{}", status.counts.terminal_census_line(source.api_slug()));
    let mut request = collector_status_request(
        &destination_namespace,
        status,
        census_residue_status_admitted,
    )?;
    (request.first_read_cutoff, request.tier_ready_cutoff) = load_backfill_state(support_dir)
        .first_read_cutoffs(&destination_namespace, source.api_slug());
    small_source_upload(source, || client.report_status(&relay_token, &request))?;
    // Content-free, after a successful send: the closed error-code slug and
    // enabled flag, once per change per source (and once after start).
    let line = (request.enabled, request.last_error_code);
    if rejection_log::changed(&SOURCE_STATUS_LOGS, source, line.clone()).is_some() {
        let code = line.1.as_deref().unwrap_or("none");
        eprintln!(
            "ottto-service: collector status source={} enabled={} code={code}",
            source.api_slug(),
            line.0
        );
    }
    Ok(())
}

/// Last reported status log line per source slot.
static SOURCE_STATUS_LOGS: Mutex<[Option<StatusLogLine>; 3]> = Mutex::new([None, None, None]);

/// Enabled flag and closed error-code slug of one terminal status report.
pub(super) type StatusLogLine = (bool, Option<String>);

/// A policy stop before scanning: withdraw this source's manifest, clear its
/// active sessions, then report `status` with the manifest withdrawn.
pub(super) fn withdraw_and_report_policy_stop(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    support_dir: &Path,
    status: CollectorStatus<'_>,
) -> Result<()> {
    let source = status.source;
    let destination = snapshot_upload_destination_namespace(device, device_secret);
    withdraw_source_manifest(&destination, source);
    // A stopped source never holds its destination's recency tiers.
    if crate::backfill::record_first_read_tier_stop(support_dir, source, &destination).is_err() {
        eprintln!(
            "local snapshot backfill tier save deferred for {}",
            source.api_slug()
        );
    }
    let _ =
        crate::active_sessions::clear_active_sessions(support_dir, source, status.scan_started_at);
    report_status_with_fresh_relay_token(
        client,
        device,
        device_secret,
        support_dir,
        source,
        TerminalManifestSource::Withdraw,
        status,
    )
}

/// Post a non-terminal collector check-in receipt.
///
/// The receipt declares `report_kind: checkin`: it says "the collector is
/// alive" and nothing else. The backend bumps the server-received freshness
/// marker (and the scan-start marker when a cycle-start one is carried) while
/// preserving the previous terminal report's success evidence, error state, and
/// counters. Terminal reports stay the source of truth for scan outcomes.
///
/// The declaration is honest by construction, not by convention: this function
/// has no access to any scan outcome. It takes a source, a machine id, an
/// optional cycle-start clock, and the server's own width hint; every
/// scan-result field below is a literal absence or zero — census completeness
/// included, which is `None` here so it never reaches the wire at all — and the
/// only evidence
/// it forwards is the manifest witness the backend already accepted from the
/// last completed terminal report. `last_scan_finished_at` stays deliberately
/// absent so a backend that predates `report_kind` still infers the same
/// liveness classification from the shape.
///
/// That absence is also why this body must stay byte-identical to the shape the
/// backend classifies as a check-in (`last_scan_finished_at is None && enabled
/// && last_error_code is None && next_retry_at is None && consecutive_failures
/// == 0`). Replaying the terminal receipt
/// `report_status_with_fresh_relay_token` posts here would silently retire
/// check-in receipts, make the cycle-start in-progress marker dead code, flip
/// manifest preservation to invalidation on every heartbeat while an error is
/// retained, and put a `scan_status` payload behind a `checkin` declaration.
pub(super) fn report_checkin_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    destination_namespace: &str,
    source: SnapshotSource,
    machine_id: &str,
    scan_started_at: Option<&str>,
    receipt_window_days: u64,
) -> Result<()> {
    let receipt_window_days = validated_receipt_window_days(receipt_window_days)?;
    let manifest = match cached_source_manifest(destination_namespace, source) {
        Some(manifest)
            if receipt_window_days > 0
                && snapshot_manifest_window_days(&manifest)? == receipt_window_days =>
        {
            Some(manifest)
        }
        Some(_) => {
            // A cached witness is usable only at the exact current hint width.
            // Withdrawing it prevents later heartbeats from repeating a stale
            // policy shape; the next complete terminal report can rebuild it.
            withdraw_source_manifest(destination_namespace, source);
            None
        }
        None => None,
    };
    let request = SnapshotStatusRequest {
        schema_version: SNAPSHOT_STATUS_SCHEMA_VERSION,
        source: source.api_slug().to_string(),
        machine_id: machine_id.to_string(),
        // Liveness only. Both callers — the independent heartbeat and the
        // cycle-start in-progress marker — reach this one construction site,
        // and neither can supply a scan outcome to contradict the claim.
        report_kind: SnapshotStatusReportKind::Checkin,
        enabled: true,
        disabled_reason: None,
        last_scan_started_at: scan_started_at.map(str::to_string),
        last_scan_finished_at: None,
        last_success_at: None,
        last_error_code: None,
        last_error_message: None,
        last_uploaded_count: 0,
        last_scanned_session_count: 0,
        last_scanned_file_count: 0,
        last_zero_snapshot_confirmed_count: 0,
        last_zero_snapshot_usage_evidence_count: 0,
        last_dropped_usage_record_count: 0,
        last_ownership_incomplete_file_count: 0,
        last_snapshot_unproven_terminal_count: 0,
        last_snapshot_superseded_terminal_count: 0,
        last_backfill_window_days: receipt_window_days,
        first_read_cutoff: None,
        tier_ready_cutoff: None,
        last_backfill_file_limit: 0,
        last_discovered_file_count: 0,
        last_skipped_file_count_due_to_limit: 0,
        last_scan_cap_hit: false,
        last_semantic_noop_count: 0,
        // ABSENT, not `false`. A beat has run no census, and the backend
        // resolves an explicitly declared `false` by lowering the completeness
        // it already accepted while resolving an omitted one by retaining it.
        // Sending `false` here would retract a complete census on every
        // heartbeat; sending `true` would assert one it never measured.
        last_census_complete: None,
        last_symlink_rejected_count: 0,
        last_unreadable_path_count: 0,
        last_oversized_file_count: 0,
        last_disappeared_file_count: 0,
        last_malformed_json_line_count: 0,
        last_invalid_utf8_line_count: 0,
        last_over_line_cap_count: 0,
        last_recognized_usage_drop_count: 0,
        // Census evidence like the loss counters above; a beat measured none.
        last_terminal_ownership_incomplete_file_count: 0,
        last_terminal_zero_snapshot_usage_evidence_count: 0,
        last_terminal_recognized_usage_drop_count: 0,
        last_terminal_dropped_usage_record_count: 0,
        last_terminal_over_line_cap_count: 0,
        last_census_residue_settled: false,
        last_census_residue_index_key_count: 0,
        last_census_residue_archived_rollout_count: 0,
        last_census_pending_file_count: None,
        last_census_block_cause: None,
        consecutive_failures: 0,
        next_retry_at: None,
        collector_version: Some(collector_version()),
        parser_version: Some(source.parser_version().to_string()),
        // The liveness-only shape carries the manifest deliberately: it is the
        // cheapest cadence the server gets it on, and a check-in that says
        // "alive" while the entity sets disagree is exactly the state the
        // manifest exists to expose.
        manifest,
        // Local control-plane health rides every check-in:
        // the beat proves uploads are alive, this says whether the socket/XPC
        // plane Setup, Repair, Verify and the Companion use is too. `None`
        // outside a serving daemon process.
        control_plane: crate::control_plane_health::snapshot(),
    };
    small_source_upload(source, || client.report_status(relay_token, &request))?;
    Ok(())
}

pub(super) fn report_checkin_status_with_fresh_relay_token(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    scan_started_at: Option<&str>,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let receipt_window_days = current_receipt_window_days(client, &relay_token, source)?;
    let destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    report_checkin_status(
        client,
        &relay_token,
        &destination_namespace,
        source,
        machine_id,
        scan_started_at,
        receipt_window_days,
    )
}

/// Spawn the periodic non-terminal collector check-in heartbeat.
///
/// Terminal receipts track cycle completion, not liveness: the sync loop
/// sleeps a fixed interval AFTER each cycle and scans sources sequentially, so
/// a source's receipt can age by cycle_duration + interval — past the
/// backend's five-minute sources.status freshness promise — while the daemon
/// is healthy and actively uploading. This loop posts a cheap in-progress
/// status per enabled source on its own clock, independent of the sync cycle,
/// so the server-received check-in stays comfortably inside that promise even
/// during a multi-hour backlog drain.
pub fn spawn_collector_checkin_heartbeat() -> Result<()> {
    let phase_offset = local_cadence_phase_offset(COLLECTOR_CHECKIN_INTERVAL);
    std::thread::Builder::new()
        .name("ottto-collector-checkin".to_string())
        .spawn(move || {
            std::thread::sleep(phase_offset);
            loop {
                if let Err(error) = collector_checkin_once() {
                    if !collector_checkin_can_wait_quietly(&error) {
                        eprintln!("collector check-in skipped: {}", safe_error(&error));
                    }
                }
                std::thread::sleep(COLLECTOR_CHECKIN_INTERVAL);
            }
        })
        .context("spawn collector check-in heartbeat")?;
    Ok(())
}

pub(super) fn collector_checkin_once() -> Result<()> {
    let _stage = StageWindow::begin("unknown", "offpass_collector_checkin");
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let enabled_sources = enabled_snapshot_sources(&device);
    if enabled_sources.is_empty() {
        return Err(anyhow!("registered device has no enabled sources"));
    }
    let client = SnapshotApiClient::new(snapshot_api_base_url()?);
    let mut failed_sources = Vec::new();
    for source in enabled_sources {
        if report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            None,
        )
        .is_err()
        {
            failed_sources.push(source.api_slug());
        }
    }
    if !failed_sources.is_empty() {
        return Err(anyhow!(
            "collector check-in failed for {} source(s)",
            failed_sources.len()
        ));
    }
    Ok(())
}

pub(super) fn collector_checkin_can_wait_quietly(error: &anyhow::Error) -> bool {
    let safe = safe_error(error);
    matches!(
        safe.as_str(),
        "relay device credentials are unavailable" | "machine identity is unavailable"
    ) || error
        .to_string()
        .contains("registered device has no enabled sources")
}
