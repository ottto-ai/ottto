//! The owned source scan: the resumable per-page scan state, the file it is
//! reading, the page step's result, the candidate preparation, and the
//! constructors that decide what a page selects.

mod step;

use crate::snapshots::*;

pub(in crate::snapshots) fn prepare_owned_scan_candidate(
    source: SnapshotSource,
    candidate: &mut CandidateFile,
    codex_title_metadata: &CodexTitleMetadata,
    claude_title_metadata: &ClaudeTitleMetadata,
    claude_effort_support_dir: Option<&Path>,
) {
    // Sidecar contribution is path-derived and can be computed before the
    // transcript opens. Transcript identity itself is filled from the
    // exact opened object below, never from discovery metadata.
    let legacy_sidecar_fingerprint = match source {
        SnapshotSource::Codex => codex_title_metadata.legacy_sidecar_fingerprint.as_str(),
        SnapshotSource::ClaudeCode => claude_title_metadata.legacy_sidecar_fingerprint.as_str(),
        SnapshotSource::Pi => "",
    };
    candidate.legacy_source_file_fingerprint = source_file_fingerprint_with_context(
        &candidate.path,
        candidate.size_bytes,
        candidate.modified_unix_seconds,
        source.parser_version(),
        legacy_sidecar_fingerprint,
    );
    candidate.legacy_config_reconciliation_required =
        source == SnapshotSource::Codex && codex_title_metadata.legacy_config_file_present;
    let sidecar_fingerprint = match source {
        SnapshotSource::Codex => codex_title_metadata.path_sidecar_fingerprint(&candidate.path),
        SnapshotSource::ClaudeCode => {
            // A subagent transcript at any depth under `subagents/` has no
            // desktop-store entry of its own: its file stem is an agent id,
            // never a session id, so looking one up would either miss or
            // (worse) collide with an unrelated session. Its NAMING
            // material lives elsewhere — the `meta.json` sidecar and the
            // Workflow run manifest — so those feed the scan fingerprint
            // instead: a label arriving AFTER the transcript was indexed
            // must still re-select the unchanged transcript for a title re-emit
            // (same late-sidecar rationale as claude_code v14).
            if let Some(identity) = claude_subagent_identity(&candidate.path) {
                claude_subagent_sidecar_fingerprint(
                    &candidate.path,
                    &identity,
                    claude_effort_support_dir,
                )
            } else {
                candidate
                    .path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .map(|session_id| {
                        let desktop_fingerprint =
                            claude_title_metadata.session_sidecar_fingerprint(session_id);
                        let effort_fingerprint = claude_effort_support_dir
                            .map(|support_dir| {
                                claude_usage_sidecars_fingerprint(support_dir, session_id)
                            })
                            .unwrap_or_default();
                        if effort_fingerprint.is_empty() {
                            desktop_fingerprint
                        } else {
                            sha256_hex(&[
                                // v2 re-selects roots alongside children
                                // once when family account attribution is
                                // introduced. Without the version change an
                                // already-complete sidecar would only move
                                // the child fingerprint on upgrade.
                                "claude_session_sidecars:v2",
                                desktop_fingerprint.as_str(),
                                effort_fingerprint.as_str(),
                            ])
                        }
                    })
                    .unwrap_or_default()
            }
        }
        SnapshotSource::Pi => String::new(),
    };
    // Temporarily retain the sidecar digest in the source fingerprint slot;
    // the exact opened-object fingerprint replaces it immediately before
    // candidate comparison and parsing.
    candidate.source_file_fingerprint = sidecar_fingerprint;
}

/// `e2`: this page's path-twin co-scheduling, transient (never persisted).
#[derive(Default)]
pub(in crate::snapshots) struct ClaudeTwinSchedule {
    /// Forced roots selected only for path-twin co-scheduling. Their owed
    /// adoption-only members keep the history gate (both or neither).
    family_roots: BTreeSet<String>,
    /// Index keys of every home of a root whose own seeds alone selected it:
    /// those homes fold together, and its children keep their own decisions.
    root_homes: BTreeSet<String>,
}
impl ClaudeTwinSchedule {
    /// Whether `path` folds as a co-scheduled member, and whether only for
    /// path twins (`Some(true)`). A root forced for any other reason wins.
    pub(in crate::snapshots) fn forced(
        &self,
        forced_roots: &BTreeSet<String>,
        path: &Path,
    ) -> Option<bool> {
        let (root, _) = claude_index_path_family_member(path)?;
        if forced_roots.contains(&root) {
            return Some(self.family_roots.contains(&root));
        }
        (!self.root_homes.is_empty() && self.root_homes.contains(&local_index_key(path)))
            .then_some(true)
    }
}

pub(crate) struct OwnedSourceScan {
    pub(in crate::snapshots) resource_probe: crate::local_resource_diagnostics::Probe,
    pub(in crate::snapshots) sampling: Option<sampled_scan::Context>,
    pub(in crate::snapshots) source: SnapshotSource,
    /// Configured scan roots, for a Codex census close that starts the next
    /// generation in the same page (G1 carry).
    pub(in crate::snapshots) roots: Vec<PathBuf>,
    pub(in crate::snapshots) index: ScanIndex,
    pub(in crate::snapshots) collected_at: String,
    /// One clock sample for this page's audit selection and retirement decisions.
    pub(in crate::snapshots) audit_now: u64,
    pub(in crate::snapshots) backfill_window_days: u64,
    pub(in crate::snapshots) file_limit: usize,
    pub(in crate::snapshots) page_file_limit_hit: bool,
    /// This scan's sync cycle holds a contract-5 permit.
    pub(in crate::snapshots) claude_request_identity_capture: bool,
    pub(in crate::snapshots) claude_effort_support_dir: Option<PathBuf>,
    pub(in crate::snapshots) codex_title_metadata: CodexTitleMetadata,
    pub(in crate::snapshots) claude_title_metadata: ClaudeTitleMetadata,
    pub(in crate::snapshots) state_census_complete: bool,
    pub(in crate::snapshots) sidecar_census_complete: bool,
    pub(in crate::snapshots) codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    pub(in crate::snapshots) codex_census_valid: bool,
    pub(in crate::snapshots) census_window_end: String,
    pub(in crate::snapshots) discovered_file_count: usize,
    pub(in crate::snapshots) census_unix_seconds: Option<u64>,
    pub(in crate::snapshots) census: ScanCensus,
    pub(in crate::snapshots) snapshots: Vec<SnapshotItem>,
    pub(in crate::snapshots) scanned_file_count: usize,
    pub(in crate::snapshots) scanned_session_count: usize,
    pub(in crate::snapshots) semantic_noop_count: usize,
    /// This page's resident charge, history-upgrade budget and gate diagnostics.
    pub(in crate::snapshots) history_upgrade: HistoryPage,
    pub(in crate::snapshots) context_read_budget: upload_context_read::Budget,
    pub(in crate::snapshots) residue_index_keys: BTreeSet<String>,
    pub(in crate::snapshots) settled_residue_index_keys: BTreeSet<String>,
    pub(in crate::snapshots) pending_finalization: Vec<PendingIndexFinalization>,
    pub(in crate::snapshots) claude_authority_preflight: bool,
    pub(in crate::snapshots) forced_claude_family_reparses: BTreeSet<String>,
    pub(in crate::snapshots) claude_twin_schedule: ClaudeTwinSchedule,
    /// The families this Claude page's selection touched, for the
    /// count-only per-family census shadow.
    pub(in crate::snapshots) claude_family_shadow:
        Option<Box<claude_family_census_shadow::Touched>>,
    pub(in crate::snapshots) identified_candidates: VecDeque<CandidateFile>,
    /// The active file and, while it is a paged cursor job, its slot lease.
    /// A dropped frame returns an intact job to the slot.
    pub(in crate::snapshots) active_file: sampled_scan::codex_cursor::ActiveFrame,
    pub(in crate::snapshots) codex_join_inventory: Option<codex_file_join::HeaderInventory>,
    pub(in crate::snapshots) codex_join_prepared: bool,
    pub(in crate::snapshots) codex_join_groups: VecDeque<codex_file_join::Group>,
    pub(in crate::snapshots) codex_join_active: Option<Box<codex_file_join::GroupBoot>>,
    pub(in crate::snapshots) codex_join_completed: Vec<codex_file_join::Group>,
    pub(in crate::snapshots) codex_legacy_join_baselines: Vec<codex_file_join::LegacyBaseline>,
    /// Decoded bytes this page consumed; the cursor job and ordinary Codex
    /// singleton reads have separate budgets.
    pub(in crate::snapshots) codex_page: sampled_scan::codex_cursor::PageBudget,
    /// Selection flags of all this page's candidates, so a budget deferral
    /// returns a file to `pending_candidates` with its original priority.
    pub(in crate::snapshots) selected_flags: BTreeMap<String, (bool, bool)>,
    /// Stage 1 hunk A: the ticket this page's pause minted, carried across
    /// `step` calls into the result.
    pub(in crate::snapshots) continuation_ticket:
        Option<sampled_scan::codex_cursor::CodexCursorTicket>,
    /// LD: this pass's line observer, if one is registered.
    pub(in crate::snapshots) line_delivery: Option<line_delivery::LineDelivery>,
    pub(in crate::snapshots) codex_versions: Option<Arc<codex_version::CodexVersionFeed>>,
    /// Launch evidence for the source fingerprint when no attribution context
    /// supplies it: a file's identity does not depend on the toggle.
    pub(in crate::snapshots) launch_events: Option<Arc<crate::launch_events::LaunchEventInventory>>,
}
pub(in crate::snapshots) struct OwnedActiveFile {
    pub(in crate::snapshots) first_read: Option<crate::local_resource_diagnostics::FirstRead>,
    pub(in crate::snapshots) sampling: Option<sampled_scan::Active>,
    pub(in crate::snapshots) candidate: CandidateFile,
    pub(in crate::snapshots) decision: CandidateDecision,
    pub(in crate::snapshots) parse_reason: Option<CandidateParseReason>,
    pub(in crate::snapshots) previous_snapshot_fingerprint: Option<String>,
    pub(in crate::snapshots) previous_upload_body_witness: Option<String>,
    pub(in crate::snapshots) projection_adoption_required: bool,
    pub(in crate::snapshots) source_file_fingerprint: String,
    pub(in crate::snapshots) parser: Box<OwnedJsonlParser>,
    pub(in crate::snapshots) aliases: Vec<CandidateFile>,
    pub(in crate::snapshots) applied_receipts:
        BTreeMap<String, Option<codex_file_join::AppliedTierReceipt>>,
    /// Present while this file is read as a paged cursor job.
    pub(in crate::snapshots) cursor: Option<sampled_scan::codex_cursor::JobMeta>,
    /// Reader bytes already charged to this page's budgets.
    pub(in crate::snapshots) charged_bytes: u64,
    /// End of the record after which a hold no append can cure first held.
    pub(in crate::snapshots) hold_offset: Option<u64>,
    /// Present while this job replays a Codex file group (P2).
    pub(in crate::snapshots) group: Option<Box<codex_file_join::GroupJob>>,
}
#[allow(clippy::large_enum_variant, reason = "one context moves between steps")]
pub(crate) enum OwnedSourceScanStep {
    Pending(OwnedSourceScan),
    Complete {
        index: ScanIndex,
        scan: SourceScanResult,
    },
}

impl OwnedSourceScan {
    #[cfg(test)]
    pub(crate) fn test_active_physical_lines(&self) -> usize {
        self.active_file
            .as_ref()
            .map(|file| file.parser.reader.report.physical_line_count)
            .unwrap_or(0)
    }

    #[expect(clippy::too_many_arguments, reason = "9 args; no options struct yet")]
    pub(crate) fn new(
        source: SnapshotSource,
        roots: &[PathBuf],
        owned_index: ScanIndex,
        collected_at: &str,
        requested_backfill_window_days: u64,
        file_limit: usize,
        claude_effort_support_dir: Option<&Path>,
        hinted_paths: &[PathBuf],
        watcher_overflowed: bool,
    ) -> Self {
        Self::new_with_identity_capture(
            source,
            roots,
            owned_index,
            collected_at,
            requested_backfill_window_days,
            file_limit,
            claude_effort_support_dir,
            hinted_paths,
            watcher_overflowed,
            cfg!(test) || claude_request_identity::captures(source),
        )
    }

    /// `claude_request_identity_capture`: this scan captures transcript
    /// markers and keeps the Desktop census witness (every Claude sync cycle;
    /// `claude_request_identity::captures`). Without it it does neither.
    #[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
    pub(crate) fn new_with_identity_capture(
        source: SnapshotSource,
        roots: &[PathBuf],
        owned_index: ScanIndex,
        collected_at: &str,
        requested_backfill_window_days: u64,
        file_limit: usize,
        claude_effort_support_dir: Option<&Path>,
        hinted_paths: &[PathBuf],
        watcher_overflowed: bool,
        claude_request_identity_capture: bool,
    ) -> Self {
        Self::new_selecting(
            source,
            roots,
            owned_index,
            collected_at,
            requested_backfill_window_days,
            file_limit,
            claude_effort_support_dir,
            hinted_paths,
            watcher_overflowed,
            &mut ListingRequest::default(),
            claude_request_identity_capture,
            &[],
            None,
        )
    }

    /// The daemon names its recovery files before the first bounded page.
    #[expect(clippy::too_many_arguments, reason = "12 args; no options struct yet")]
    pub(crate) fn new_with_recovery_priority(
        source: SnapshotSource,
        roots: &[PathBuf],
        owned_index: ScanIndex,
        collected_at: &str,
        requested_backfill_window_days: u64,
        file_limit: usize,
        claude_effort_support_dir: Option<&Path>,
        hinted_paths: &[PathBuf],
        watcher_overflowed: bool,
        list_all: &mut ListingRequest,
        claude_request_identity_capture: bool,
        recovery_priority: &[PathBuf],
        carry_cache: Option<(
            &sampled_scan::SharedCache,
            &crate::transcript_acquisition::Scope,
        )>,
    ) -> Self {
        Self::new_selecting(
            source,
            roots,
            owned_index,
            collected_at,
            requested_backfill_window_days,
            file_limit,
            claude_effort_support_dir,
            hinted_paths,
            watcher_overflowed,
            list_all,
            claude_request_identity_capture,
            recovery_priority,
            carry_cache,
        )
    }

    /// Performs no selection, inventory read or traversal update.
    pub(crate) fn new_continuation(
        roots: &[PathBuf],
        mut owned_index: ScanIndex,
        collected_at: &str,
        requested_backfill_window_days: u64,
        file_limit: usize,
        ordinary_equivalent: Option<std::time::Duration>,
        mut evidence: Option<CodexContinuationEvidence>,
    ) -> Self {
        owned_index.context_read_counts = Default::default();
        let codex_title_metadata = evidence
            .as_mut()
            .map(|e| std::mem::take(&mut e.codex))
            .unwrap_or_default();
        let codex_census_valid = owned_index
            .traversal
            .as_ref()
            .is_some_and(codex_frozen_census_valid);
        let census_window_end = owned_index
            .traversal
            .as_ref()
            .map_or_else(|| collected_at.to_owned(), |t| t.census_window_end.clone());
        let mut codex_page = sampled_scan::codex_cursor::PageBudget::default();
        codex_page.set_continuation(ordinary_equivalent);
        Self {
            resource_probe: crate::local_resource_diagnostics::Probe::page(),
            sampling: None,
            source: SnapshotSource::Codex,
            roots: roots.to_vec(),
            index: owned_index,
            collected_at: collected_at.to_owned(),
            audit_now: sampled_scan::now_seconds(),
            backfill_window_days: effective_backfill_window_days(requested_backfill_window_days),
            file_limit,
            page_file_limit_hit: false,
            claude_request_identity_capture: false,
            claude_effort_support_dir: None,
            claude_title_metadata: Default::default(),
            state_census_complete: !codex_title_metadata.state_census_incomplete,
            sidecar_census_complete: !codex_title_metadata.sidecar_census_incomplete,
            codex_title_metadata,
            codex_turn_traces: evidence.as_mut().and_then(|e| e.traces.take()),
            codex_census_valid,
            census_window_end,
            discovered_file_count: 0,
            census_unix_seconds: rfc3339_unix_seconds(collected_at),
            census: Default::default(),
            snapshots: Vec::new(),
            scanned_file_count: 0,
            scanned_session_count: 0,
            semantic_noop_count: 0,
            history_upgrade: HistoryPage::with_twin_groups(Default::default(), BTreeSet::new()),
            context_read_budget: upload_context_read::Budget::new(SnapshotSource::Codex),
            residue_index_keys: Default::default(),
            settled_residue_index_keys: Default::default(),
            pending_finalization: Vec::new(),
            claude_authority_preflight: false,
            forced_claude_family_reparses: Default::default(),
            claude_twin_schedule: Default::default(),
            claude_family_shadow: Default::default(),
            identified_candidates: Default::default(),
            active_file: Default::default(),
            codex_join_inventory: evidence.map(|e| e.inventory),
            codex_join_prepared: true,
            codex_join_groups: Default::default(),
            codex_join_active: None,
            codex_join_completed: Vec::new(),
            codex_legacy_join_baselines: Vec::new(),
            codex_page,
            selected_flags: Default::default(),
            continuation_ticket: None,
            line_delivery: None,
            launch_events: None,
            codex_versions: None,
        }
    }

    pub(crate) fn rehome_withheld_baseline(&self, baseline: &mut ScanIndex) -> Result<()> {
        // Prepare may have committed a representation move before selection.
        if self.source == SnapshotSource::Codex && baseline.generation != self.index.generation {
            *baseline = self.index.clone();
        }
        baseline.rehome_withheld_baseline(&self.index);
        Ok(())
    }

    /// Stage 1 (K6): the cooperative deadline of a continuation page, on the
    /// pace clock; ignored on an ordinary page. Past it the page pauses its
    /// job at the next `step()` return without minting a ticket.
    pub(crate) fn with_continuation_deadline(mut self, deadline: std::time::Instant) -> Self {
        self.codex_page.set_continuation_deadline(deadline);
        self
    }

    #[expect(clippy::too_many_arguments, reason = "14 args; no options struct yet")]
    pub(in crate::snapshots) fn new_selecting(
        source: SnapshotSource,
        roots: &[PathBuf],
        mut owned_index: ScanIndex,
        collected_at: &str,
        requested_backfill_window_days: u64,
        file_limit: usize,
        claude_effort_support_dir: Option<&Path>,
        hinted_paths: &[PathBuf],
        watcher_overflowed: bool,
        // Served here when no walk runs; otherwise left for the caller to defer.
        list_all: &mut ListingRequest,
        claude_request_identity_capture: bool,
        // Only changes native selection order, never ownership or settlement.
        recovery_priority: &[PathBuf],
        carry_cache: Option<(
            &sampled_scan::SharedCache,
            &crate::transcript_acquisition::Scope,
        )>,
    ) -> Self {
        let _jsonl_scope =
            crate::local_resource_diagnostics::jsonl::Scope::begin(source.api_slug());
        let _select_window = state_v2::state_v2_growth_retention_active(&owned_index)
            .then(|| state_v2::telemetry::Window::begin("select"))
            .flatten();
        let file_limit = state_v2::collection_page_limit(&owned_index, file_limit);
        if !owned_index.persistence_available() {
            // No inventory, selection or provider I/O for an unavailable index.
            let mut blocked = Self::new_continuation(
                &[],
                owned_index,
                collected_at,
                requested_backfill_window_days,
                0,
                None,
                None,
            );
            blocked.source = source;
            return blocked;
        }

        let audit_now = sampled_scan::now_seconds();
        // Every source: a non-Claude page emits only its retained-cache events.
        let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let mut resource_probe = crate::local_resource_diagnostics::Probe::page()
            .with_withheld_memo(owned_index.withheld_memo.clone());
        resource_probe.refusal_exposure = (owned_index.refusal_exposure != Default::default())
            .then_some(owned_index.refusal_exposure);
        let index = &mut owned_index;
        if source == SnapshotSource::ClaudeCode {
            // Restore population disclosure even before a restarted/evicted
            // memo has any token or content details to report.
            index
                .withheld_memo
                .retain_held(&index.claude_account_deferred_holds);
        }
        index.context_read_counts = Default::default();
        index.activate_quarantine_witness(source);
        let backfill_window_days = effective_backfill_window_days(requested_backfill_window_days);
        let codex_title_metadata = if source == SnapshotSource::Codex {
            let mut metadata = carry_cache.map_or_else(
                || CodexTitleMetadata::load_from_roots(roots),
                |(cache, scope)| {
                    cache.with_codex_sidecars(scope, |facts| {
                        CodexTitleMetadata::load_reused(roots, facts)
                    })
                },
            );
            metadata.scope_created_thread_census(index, roots);
            metadata
        } else {
            CodexTitleMetadata::default()
        };
        let claude_identity_census_was_complete = index.claude_desktop_identity_census_complete;
        let claude_sidecar_was_incomplete = source == SnapshotSource::ClaudeCode
            && (index
                .claude_desktop_store_retry_not_before_unix_seconds
                .is_some()
                || index.claude_desktop_store_cursor.is_some()
                || index.claude_desktop_store_sweep_had_errors);
        let mut claude_title_metadata = if source == SnapshotSource::ClaudeCode {
            let mut load = |facts: &mut _| {
                ClaudeTitleMetadata::load_from_roots_reusing(roots, index, collected_at, facts)
            };
            if let Some((cache, _)) = carry_cache {
                cache.with_desktop_titles(load)
            } else {
                load(&mut Default::default())
            }
        } else {
            ClaudeTitleMetadata::default()
        };
        if source == SnapshotSource::ClaudeCode
            && !claude_identity_census_was_complete
            && !claude_title_metadata.original_identity_census_incomplete
        {
            // Attribute the existing account-held retry reads to their recovered
            // metadata proof. This does not select, rearm or authorize any file.
            claude_title_metadata.note_completed_account_holds(index);
        }
        let state_census_complete =
            source != SnapshotSource::Codex || !codex_title_metadata.state_census_incomplete;
        let sidecar_census_complete = match source {
            SnapshotSource::Codex => !codex_title_metadata.sidecar_census_incomplete,
            SnapshotSource::ClaudeCode => !claude_title_metadata.sidecar_census_incomplete,
            SnapshotSource::Pi => true,
        };
        if (claude_sidecar_was_incomplete && sidecar_census_complete)
            || (source == SnapshotSource::ClaudeCode
                && claude_identity_census_was_complete
                && claude_title_metadata.original_identity_census_incomplete)
        {
            // The prior transcript generation was intentionally held red while
            // title discovery was partial. Start a fresh bounded transcript walk
            // now so sidecar additions/removals are folded into each affected
            // file fingerprint before a terminal manifest can publish. Actual identity
            // census loss also revisits consumed pages once to retract completeness.
            if let Some(traversal) = index.traversal.as_ref() {
                traversal_transition::restarting(source, index.generation, traversal);
            } else {
                traversal_transition::disarm_recensus(
                    source,
                    &scan_traversal_context_fingerprint(source, roots, backfill_window_days),
                );
            }
            index.traversal = None;
        }
        // Read the per-turn fast-mode signal once per cycle (logs_2 is large); share
        // it read-only across every session file via Arc.
        let codex_turn_traces = (source == SnapshotSource::Codex).then(|| {
            Arc::new(CodexTurnTraceMap::load_from_roots(
                roots,
                backfill_window_days,
            ))
        });
        if source == SnapshotSource::ClaudeCode {
            index.observe_claude_request_identity_contract(claude_request_identity_capture);
        }
        let progress =
            ensure_bounded_traversal(source, roots, index, collected_at, backfill_window_days);
        let growth_active =
            source == SnapshotSource::ClaudeCode && sampled_audit::growth_active(index);
        if growth_active {
            sampled_audit::prune_growth_retention(index, sampled_scan::now_seconds());
        }
        let hinted_paths = changed_watcher_hints(index, hinted_paths);
        let next_generation_hints;
        {
            refresh_retained_codex_roster(
                source,
                index,
                backfill_window_days,
                Some(&resource_probe.discovery_growth),
            );
            let traversal = index.traversal.as_mut().expect("traversal initialized");
            start_due_listing_pass(
                source,
                traversal,
                collected_at,
                progress == TraversalProgress::Started,
                list_all,
            );
            next_generation_hints =
                enqueue_watcher_hints(source, traversal, &hinted_paths, watcher_overflowed);
        }
        let unlisted = advance_bounded_directory_traversal_with_budget(
            source,
            index,
            backfill_window_days,
            directory_entries_per_tick(),
            Some(&resource_probe.discovery_growth),
        );
        let (carry_deferred, carry_held_owners) = if source == SnapshotSource::Codex {
            index.prepare_codex_carries(carry_cache.map(|(cache, scope)| (cache, Some(scope))))
        } else {
            Default::default()
        };
        release_codex_inventory_hold(source, index.traversal.as_mut().expect("traversal"));
        let codex_census_valid = source == SnapshotSource::Codex
            && index
                .traversal
                .as_ref()
                .is_some_and(codex_frozen_census_valid);
        let mut scoped_prefix_paths = Vec::new();
        if source == SnapshotSource::ClaudeCode {
            claude_copy_prefix_reread::select(
                index,
                recovery_priority,
                &mut scoped_prefix_paths,
                file_limit,
            );
        }
        let growth_wake = sampled_audit::expired_growth_claims(source, index, audit_now);
        let mut selection_traversal = index.traversal.take().expect("traversal initialized");
        let traversal = &mut selection_traversal;
        let census_window_end = traversal.census_window_end.clone();
        let discovered_file_count = traversal.counts.discovered_file_count;
        let mut pending_paths = scoped_prefix_paths;
        // Watcher freshness must not starve the durable census when callers use a
        // small page size. Production reserves almost the whole 10k page already,
        // but the explicit slot also makes liveness independent of that ratio.
        let ordinary_census_pending = traversal
            .pending_candidates
            .iter()
            .any(|candidate| candidate.census_member && !candidate.watcher_hint);
        let selection_limit =
            if source == SnapshotSource::Codex && codex_census_walk_pending(traversal) {
                0
            } else {
                file_limit
            };
        // A due quarantine retry of an unchanged file is neither fresh nor a
        // census member, so no dedicated turn below selects it and it would
        // wait for an ordinary page. It rides the next selecting page first.
        // Order only: its flags, budgets and retry backoff are unchanged.
        if selection_limit > 0 && !index.terminal_contract_retries.is_empty() {
            let due_retries = index
                .terminal_contract_retries
                .values()
                .map(Path::new)
                .collect::<BTreeSet<_>>();
            traversal.pending_candidates.retain(|candidate| {
                let due = pending_paths.len() < selection_limit
                    && due_retries.contains(candidate.path.as_path());
                if due {
                    pending_paths.push(candidate.clone());
                }
                !due
            });
        }
        // Fresh data gets a bounded page of its own, at most every other
        // ordinary page. Mixing it behind 64 MiB of census revalidation
        // starves it; always putting it first can starve the census instead.
        // Continuations never select new work. A hint alone does not trigger
        // a read: all selected paths still pass the unchanged candidate gate.
        // The turn a freshness page owes alternates census (C) and ordinary
        // (O) work while queued work neither of those selects waits: F C F O;
        // with no such work it stays F C F C. Fresh keeps its cadence. An
        // ordinary turn is dedicated too: due audits, then queued non-member,
        // non-fresh paths (archives, plain re-reads). Order only.
        let ordinary_turn = source == SnapshotSource::Codex
            && selection_limit > 0
            && traversal.codex_freshness_yield
            && codex_census_turn_was_last(&traversal.scan_roots)
            && traversal.pending_candidates.iter().any(|candidate| {
                !candidate.census_member && !codex_fresh_data_pending(candidate, index)
            });
        let freshness_page = source == SnapshotSource::Codex
            && selection_limit > 0
            && !traversal.codex_freshness_yield
            && traversal
                .pending_candidates
                .iter()
                .any(|candidate| codex_fresh_data_pending(candidate, index))
            && codex_selection_may_exhaust_page(traversal, selection_limit, &index.files);
        let census_page = source == SnapshotSource::Codex
            && selection_limit > 0
            && !ordinary_turn
            && traversal.codex_freshness_yield
            && traversal
                .pending_candidates
                .iter()
                .any(|candidate| candidate.census_member);
        if source == SnapshotSource::Codex && selection_limit > 0 {
            traversal.codex_freshness_yield = freshness_page;
            if !freshness_page {
                note_codex_census_turn(&traversal.scan_roots, census_page);
            }
        }
        if freshness_page || census_page || ordinary_turn {
            let limit = if freshness_page {
                selection_limit.min(MAX_WATCHER_HINTED_FILES_PER_TICK)
            } else {
                selection_limit
            };
            let ordinary_only = |candidate: &ScanTraversalPath| {
                !candidate.census_member && !codex_fresh_data_pending(candidate, index)
            };
            if ordinary_turn {
                traversal.pending_candidates.retain(|candidate| {
                    let due = pending_paths.len() < limit
                        && index
                            .files
                            .get(&local_index_key(&candidate.path))
                            .is_some_and(|entry| entry.audit_requires_full(audit_now))
                        && ordinary_only(candidate);
                    if due {
                        pending_paths.push(candidate.clone());
                    }
                    !due
                });
            }
            // A fresh page first gives up to half its slots to fresh plain
            // rollouts in queue order, so a hinted compressed backlog cannot
            // hold recent sessions back. The rest stays FIFO, archives included.
            if freshness_page {
                let reserve = (pending_paths.len() + limit / 2).min(limit);
                traversal.pending_candidates.retain(|candidate| {
                    let due = pending_paths.len() < reserve
                        && !codex_archive_path(&candidate.path)
                        && codex_fresh_data_pending(candidate, index);
                    if due {
                        pending_paths.push(candidate.clone());
                    }
                    !due
                });
            }
            // Rotate the original queue once without allocating another
            // backlog-sized container. Keep unselected paths in FIFO order.
            for _ in 0..traversal.pending_candidates.len() {
                let Some(candidate) = traversal.pending_candidates.pop_front() else {
                    break;
                };
                let eligible = pending_paths.len() < limit
                    && if freshness_page {
                        codex_fresh_data_pending(&candidate, index)
                    } else if census_page {
                        candidate.census_member && !codex_fresh_data_pending(&candidate, index)
                    } else {
                        ordinary_only(&candidate)
                    };
                if eligible {
                    pending_paths.push(candidate);
                } else {
                    traversal.pending_candidates.push_back(candidate);
                }
            }
            // Fill spare freshness/ordinary slots with cold census members, FIFO
            // after primary selection. An empty census turn may take fresh members.
            let census_fill = freshness_page || ordinary_turn;
            if census_fill || (census_page && pending_paths.is_empty()) {
                for _ in 0..traversal.pending_candidates.len() {
                    let Some(candidate) = traversal.pending_candidates.pop_front() else {
                        break;
                    };
                    if pending_paths.len() < limit
                        && candidate.census_member
                        && !(census_fill && codex_fresh_data_pending(&candidate, index))
                    {
                        pending_paths.push(candidate);
                    } else {
                        traversal.pending_candidates.push_back(candidate);
                    }
                }
            }
        }
        // Freeze dedicated primary work, retry riders and census fill here;
        // later hints and audits cannot displace the selected prefix.
        let selection_limit = if freshness_page || census_page || ordinary_turn {
            pending_paths.len()
        } else {
            selection_limit
        };
        let hinted_budget = selection_limit
            .min(MAX_WATCHER_HINTED_FILES_PER_TICK)
            .saturating_sub(usize::from(ordinary_census_pending && file_limit > 0));
        // A growth Full deferred by its claim left the queue; once the claim
        // expires, its queued path rides this page instead of waiting behind
        // the census FIFO. The claim still admits one Full per interval.
        if !growth_wake.is_empty() {
            traversal.pending_candidates.retain(|candidate| {
                let due = pending_paths.len() < selection_limit
                    && growth_wake.contains(candidate.path.as_path());
                if due {
                    pending_paths.push(candidate.clone());
                }
                !due
            });
        }
        while pending_paths.len() < selection_limit {
            let Some(position) = traversal.pending_candidates.iter().position(|candidate| {
                index
                    .files
                    .get(&local_index_key(&candidate.path))
                    .is_some_and(|entry| entry.audit_requires_full(audit_now))
            }) else {
                break;
            };
            if let Some(candidate) = traversal.pending_candidates.remove(position) {
                pending_paths.push(candidate);
            }
        }
        let audited = pending_paths.len();
        for _ in pending_paths.len()..hinted_budget {
            let Some(position) = traversal
                .pending_candidates
                .iter()
                .position(|candidate| candidate.watcher_hint)
            else {
                break;
            };
            if let Some(candidate) = traversal.pending_candidates.remove(position) {
                pending_paths.push(candidate);
            }
        }
        while pending_paths.len() < selection_limit {
            let Some(position) = traversal
                .pending_candidates
                .iter()
                .position(|candidate| candidate.census_member && !candidate.watcher_hint)
            else {
                break;
            };
            if let Some(candidate) = traversal.pending_candidates.remove(position) {
                pending_paths.push(candidate);
            }
        }
        while pending_paths.len() < selection_limit {
            let Some(candidate) = traversal.pending_candidates.pop_front() else {
                break;
            };
            pending_paths.push(candidate);
        }
        let page_file_limit_hit = file_limit > 0 && pending_paths.len() >= file_limit;
        if source == SnapshotSource::Codex {
            // G1 (fix 2): the same selection, read census members first. The
            // reserved census member and every other first read are charged
            // to the page's singleton budget before any re-read (a watcher
            // hint for a path this generation already processed), so each
            // page completes a first read and re-reads cannot starve one.
            // Audits keep their place; the order is otherwise unchanged.
            // Queued retry leases ride ahead of this order.
            let (members, rereads): (Vec<_>, Vec<_>) = pending_paths
                .split_off(audited)
                .into_iter()
                .partition(|candidate| candidate.census_member);
            pending_paths.extend(members);
            pending_paths.extend(rereads);
        }
        let census_unix_seconds = rfc3339_unix_seconds(&census_window_end);
        let causes = traversal.counts.causes.page(census_unix_seconds);
        index.traversal = Some(selection_traversal);
        let claude_queued_family_deferred_paths = if source == SnapshotSource::ClaudeCode {
            claude_request_money::e2::defer_roots_of_queued_families(
                &mut pending_paths,
                index.traversal.as_mut().expect("traversal initialized"),
            )
        } else {
            BTreeSet::new()
        };
        let pending_paths = pending_paths
            .into_iter()
            .filter_map(|pending| {
                if carry_deferred.contains(&local_index_key(&pending.path)) {
                    index
                        .traversal
                        .as_mut()
                        .expect("traversal")
                        .pending_candidates
                        .push_back(pending);
                    None
                } else {
                    Some(pending)
                }
            })
            .collect::<Vec<_>>();
        // Counts only, never a gate input.
        let owed_selected = pending_paths
            .iter()
            .filter(|pending| {
                index
                    .files
                    .get(&local_index_key(&pending.path))
                    .is_some_and(|entry| entry.source_file_fingerprint.is_empty())
            })
            .count();
        for (event, amount) in [
            (PageSelection::Selected, pending_paths.len()),
            (PageSelection::OwedSelected, owed_selected),
        ] {
            page_selection(source.api_slug(), event, amount as u64);
        }
        index.resume_census_window_end = Some(census_window_end.clone());
        let mut census = ScanCensus {
            causes,
            ..ScanCensus::default()
        };
        let claude_family_shadow = (source == SnapshotSource::ClaudeCode).then(|| {
            Box::new(claude_family_census_shadow::Touched::from_paths(
                pending_paths.iter().map(|pending| pending.path.as_path()),
            ))
        });
        let selected_flags = pending_paths
            .iter()
            .map(|pending| {
                (
                    local_index_key(&pending.path),
                    (pending.census_member, pending.watcher_hint),
                )
            })
            .collect();
        let mut candidate_discovery =
            CandidateDiscovery::new(index, Some(&resource_probe.discovery_growth));
        let mut files = pending_paths
            .into_iter()
            .filter_map(|pending| {
                candidate_from_traversal_path(
                    source,
                    pending,
                    &mut census,
                    census_unix_seconds,
                    backfill_window_days,
                    &mut candidate_discovery,
                )
            })
            .collect::<Vec<_>>();
        // A key missing from this page's directory reads and proven
        // securely absent is the same removal as a NotFound census member; the
        // page-end owner retires it. A custody move this page (the rekey seam)
        // leaves the old key unindexed, so it is dropped here. The proof is
        // newer than this page's candidate observations, so it clears them.
        for key in unlisted {
            if index.files.contains_key(&key)
                && sampled_audit::proven_absent(Path::new(&key), roots)
            {
                census.observed_index_keys.remove(&key);
                census.claude_vanished_index_keys.insert(key.clone());
                census.removed_index_keys.insert(key);
            }
        }

        for candidate in &files {
            sampled_audit::retain_candidate_growth(source, index, candidate);
        }
        let prepare_candidate_context = |candidate: &mut CandidateFile| {
            prepare_owned_scan_candidate(
                source,
                candidate,
                &codex_title_metadata,
                &claude_title_metadata,
                claude_effort_support_dir,
            );
        };
        for candidate in &mut files {
            prepare_candidate_context(candidate);
        }
        let snapshots = Vec::new();
        let scanned_file_count = 0;
        let scanned_session_count = 0;
        let semantic_noop_count = 0;
        let residue_index_keys = BTreeSet::new();
        let settled_residue_index_keys = BTreeSet::new();
        let pending_finalization = Vec::new();
        let claude_authority_preflight = source == SnapshotSource::ClaudeCode
            && !index.claude_usage_authority_quarantine.is_empty();
        let mut identified_candidates = if claude_authority_preflight {
            files
                .into_iter()
                .filter_map(|candidate| {
                    open_and_identify_scan_candidate_at(
                        source,
                        candidate,
                        &mut census,
                        CandidateWindow {
                            census_unix_seconds,
                            backfill_window_days,
                            retention: discovery_retention!(
                                index,
                                &resource_probe.discovery_growth
                            ),
                            growth: sampled_audit::growth_active(index)
                                .then_some(&index.v2().growth_retention),
                        },
                    )
                    .map(|(candidate, _)| candidate)
                })
                .collect::<Vec<_>>()
        } else {
            files
        };
        let mut forced_claude_family_reparses = if source == SnapshotSource::ClaudeCode {
            identified_candidates
                .iter()
                .filter_map(|candidate| {
                    index.claude_usage_authority_candidate_requires_family_reparse(candidate)
                })
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        let claude_family_membership_is_authoritative = source == SnapshotSource::ClaudeCode
            && index.traversal.as_ref().is_some_and(|traversal| {
                traversal.pending_directories.is_empty()
                    && traversal.counts.directory_entry_cap_exceeded_count == 0
                    && traversal.counts.symlink_rejected_count == 0
                    && traversal.counts.unreadable_path_count == 0
                    && traversal.counts.disappeared_file_count == 0
            });
        // The map's only consumer is the quarantine loop below.
        if claude_family_membership_is_authoritative
            && !index.claude_usage_authority_quarantine.is_empty()
        {
            let current_members_by_root = index
                .traversal
                .as_ref()
                .into_iter()
                .flat_map(|traversal| traversal.observed_index_keys.iter())
                .filter_map(|index_key| claude_index_path_family_member(Path::new(index_key)))
                .fold(
                    BTreeMap::<String, BTreeSet<String>>::new(),
                    |mut by_root, (root_session_id, source_session_id)| {
                        by_root
                            .entry(root_session_id)
                            .or_default()
                            .insert(source_session_id);
                        by_root
                    },
                );
            for (root_session_id, record) in &index.claude_usage_authority_quarantine {
                let current_members = current_members_by_root
                    .get(root_session_id)
                    .cloned()
                    .unwrap_or_default();
                if current_members
                    != record
                        .member_source_file_fingerprints
                        .keys()
                        .cloned()
                        .collect()
                {
                    forced_claude_family_reparses.insert(root_session_id.clone());
                }
            }
        }
        let mut forced_pending_entries = Vec::new();
        let mut claude_twin_schedule = ClaudeTwinSchedule::default();
        // `e2`: the page's path-twin groups, built at most once per page and
        // shared with twin staging and the parse-time birth context.
        let claude_twin_groups = std::cell::OnceCell::new();
        if source == SnapshotSource::ClaudeCode {
            let twin_groups = claude_twin_groups.get_or_init(|| {
                // A page file not known yet (a new copy) keeps its member's
                // single known path as its twin.
                let page_members = identified_candidates
                    .iter()
                    .filter_map(|candidate| claude_index_path_family_member(&candidate.path))
                    .map(|(_, member)| member)
                    .collect::<BTreeSet<_>>();
                claude_history_upgrade::claude_path_twin_groups(index, &page_members)
            });
            // Only a twin this page reads pulls its family in: every walk meets
            // each settled twin too, and pulling its family then re-read the
            // family on every walk (observed: 8 files and one upload batch per
            // walk). Outside the authority preflight a candidate still carries
            // its sidecar digest in the scan fingerprint slot, so each twin is
            // identified on a copy first: one more open per twin candidate. A
            // twin that cannot be identified pulls its family in, as before.
            // A twin whose growth Full is paced would only be deferred, so it
            // neither pulls its family nor stays on the page alone (where its
            // known twin would hold it as `absent_twin`); it waits with its debt.
            let growth_now = sampled_scan::now_seconds();
            let (paced_twins, read_twins): (Vec<_>, Vec<_>) = identified_candidates
                .iter()
                .filter_map(|candidate| {
                    let (root, member) = claude_index_path_family_member(&candidate.path)?;
                    let homes = claude_history_upgrade::path_twins(twin_groups, &member)?;
                    Some((candidate, root, member, homes))
                })
                .filter_map(|(candidate, root, member, homes)| {
                    let mut twin = candidate.clone();
                    prepare_candidate_context(&mut twin);
                    // A seed: its own Parse decision, or `None` when unidentified.
                    let seed = open_and_identify_scan_candidate_at(
                        source,
                        twin,
                        &mut ScanCensus::default(),
                        CandidateWindow {
                            census_unix_seconds,
                            backfill_window_days,
                            retention: discovery_retention!(
                                index,
                                &resource_probe.discovery_growth
                            ),
                            growth: sampled_audit::growth_active(index)
                                .then_some(&index.v2().growth_retention),
                        },
                    )
                    .map(|(twin, _)| index.candidate_decision_with_reason_at(&twin, audit_now));
                    seed.is_none_or(|(decision, _)| decision == CandidateDecision::Parse)
                        .then_some((
                            candidate.path.as_path(),
                            root,
                            member,
                            homes,
                            seed.map(|(_, reason)| reason),
                        ))
                })
                .partition(|(path, ..)| {
                    sampled_audit::growth_full_paced(index, &local_index_key(path), growth_now)
                });
            // An identified seed of the root itself, whose other homes are
            // unchanged and verified, reads just the root's homes: a root with
            // one home reads only itself too. Any other seed of that root (a
            // child, an unidentified twin, a changed or unverified other home)
            // forces the whole family, and so does any other forced cause.
            let settled = |key: &String| {
                let path = Path::new(key);
                std::fs::metadata(path).is_ok_and(|meta| index.listing_unchanged(path, &meta))
            };
            let mut scoped = BTreeMap::new();
            let mut seeds = Vec::new();
            for (path, root, member, homes, seed) in read_twins {
                let own = local_index_key(path);
                let root_member = member == root;
                let narrow = seed.is_some()
                    && root_member
                    && homes.iter().all(|(key, _)| *key == own || settled(key));
                scoped.entry(root).or_insert((true, homes)).0 &= narrow;
                seeds.push((seed, root_member));
            }
            let (scoped, roots): (Vec<_>, Vec<_>) = scoped.into_iter().partition(|(_, (n, _))| *n);
            for (root, _) in &roots {
                if forced_claude_family_reparses.insert(root.clone()) {
                    claude_twin_schedule.family_roots.insert(root.clone());
                }
            }
            let scoped = scoped
                .into_iter()
                .filter(|(root, _)| !forced_claude_family_reparses.contains(root))
                .map(|(_, (_, homes))| homes)
                .collect::<Vec<_>>();
            crate::local_resource_diagnostics::forced_family_seeds(
                seeds,
                roots.len(),
                scoped.len(),
            );
            claude_twin_schedule.root_homes = scoped
                .into_iter()
                .flatten()
                .map(|(key, _)| key.clone())
                .collect();
            let paced_twins = paced_twins
                .into_iter()
                .map(|(path, ..)| path.to_path_buf())
                .collect::<BTreeSet<_>>();
            identified_candidates.retain(|candidate| {
                let paced = paced_twins.contains(&candidate.path);
                if paced {
                    sampled_audit::defer_growth_read(index, &mut census, candidate);
                }
                !paced
            });
        }
        if !forced_claude_family_reparses.is_empty() || !claude_twin_schedule.root_homes.is_empty()
        {
            let already_identified = identified_candidates
                .iter()
                .map(|candidate| local_index_key(&candidate.path))
                .collect::<BTreeSet<_>>();
            let family_index_keys = if claude_family_membership_is_authoritative {
                index
                    .traversal
                    .as_ref()
                    .map(|traversal| (*traversal.observed_index_keys).clone())
                    .unwrap_or_default()
            } else {
                index.files.keys().cloned().collect()
            };
            let scan_roots = index
                .traversal
                .as_ref()
                .map(|traversal| traversal.scan_roots.clone())
                .unwrap_or_default();
            let missing_family_paths = claude_history_upgrade::claude_read_closure(
                std::iter::empty::<&Path>(),
                &family_index_keys,
                claude_twin_groups.get_or_init(Default::default),
                &forced_claude_family_reparses,
            )
            .into_iter()
            .inspect(|_| crate::local_resource_diagnostics::forced_family_member_pulled())
            .chain(claude_twin_schedule.root_homes.iter().map(PathBuf::from))
            .filter(|path| !already_identified.contains(&local_index_key(path)))
            .collect::<BTreeSet<_>>();
            if let Some(traversal) = index.traversal.as_mut() {
                traversal.pending_candidates.retain(|pending| {
                    if missing_family_paths.contains(&pending.path) {
                        forced_pending_entries.push(pending.clone());
                        false
                    } else {
                        true
                    }
                });
            }
            let move_sources = index.held_move_sources();
            for path in missing_family_paths {
                let mut candidate_discovery = CandidateDiscovery {
                    index,
                    sources: std::borrow::Cow::Borrowed(&move_sources),
                    growth: Some(&resource_probe.discovery_growth),
                };
                let Some(scan_root) = scan_roots
                    .iter()
                    .filter(|root| path.starts_with(root))
                    .max_by_key(|root| root.components().count())
                    .cloned()
                else {
                    continue;
                };
                let Some(mut candidate) = candidate_from_traversal_path_at(
                    source,
                    disappearance_diagnostics::Site::CandidateForcedIndex,
                    ScanTraversalPath {
                        scan_root,
                        path,
                        census_member: true,
                        watcher_hint: false,
                    },
                    &mut census,
                    census_unix_seconds,
                    backfill_window_days,
                    &mut candidate_discovery,
                ) else {
                    continue;
                };
                prepare_candidate_context(&mut candidate);
                if let Some(opened) = open_and_identify_scan_candidate_at(
                    source,
                    candidate,
                    &mut census,
                    CandidateWindow {
                        census_unix_seconds,
                        backfill_window_days,
                        retention: discovery_retention!(index, &resource_probe.discovery_growth),
                        growth: sampled_audit::growth_active(index)
                            .then_some(&index.v2().growth_retention),
                    },
                ) {
                    identified_candidates.push(opened.0);
                }
            }
        }

        // Only pure context debt moves behind ordinary work. Preserve relative
        // order of all authority, recovery, new and changed family members.
        identified_candidates.sort_by_cached_key(|candidate| index.context_only_read(candidate));
        let codex_join_inventory =
            (source == SnapshotSource::Codex && !identified_candidates.is_empty()).then(|| {
                let traversal = index
                    .traversal
                    .as_ref()
                    .expect("Codex traversal initialized");
                let mut inventory = codex_file_join::HeaderInventory::new(
                    &traversal.scan_roots,
                    &traversal.codex_rollout_paths,
                    traversal.codex_join_directory_census.as_ref(),
                );
                inventory
                    .pending
                    .retain(|path| !carry_deferred.contains(&local_index_key(path)));
                inventory.held_owners.extend(carry_held_owners);
                inventory.complete &= !codex_census_walk_pending(traversal);
                inventory
            });
        resource_probe.page_events.merge(diagnostics.finish());
        Self {
            resource_probe,
            sampling: None,
            source,
            roots: roots.to_vec(),
            index: owned_index,
            collected_at: collected_at.to_owned(),
            audit_now,
            backfill_window_days,
            file_limit,
            page_file_limit_hit,
            claude_request_identity_capture,
            claude_effort_support_dir: claude_effort_support_dir.map(Path::to_path_buf),
            codex_title_metadata,
            claude_title_metadata,
            state_census_complete,
            sidecar_census_complete,
            codex_turn_traces,
            codex_census_valid,
            census_window_end,
            discovered_file_count,
            census_unix_seconds,
            census,
            snapshots,
            scanned_file_count,
            scanned_session_count,
            semantic_noop_count,
            history_upgrade: HistoryPage::with_twin_groups(
                claude_twin_groups,
                claude_queued_family_deferred_paths,
            )
            .with_forced_pending(forced_pending_entries),
            context_read_budget: upload_context_read::Budget::new(source),
            residue_index_keys,
            settled_residue_index_keys,
            pending_finalization,
            claude_authority_preflight,
            forced_claude_family_reparses,
            claude_twin_schedule,
            claude_family_shadow,
            identified_candidates: identified_candidates.into(),
            active_file: Default::default(),
            codex_join_inventory,
            codex_join_prepared: false,
            codex_join_groups: VecDeque::new(),
            codex_join_active: None,
            codex_join_completed: Vec::new(),
            codex_legacy_join_baselines: Vec::new(),
            codex_page: sampled_scan::codex_cursor::PageBudget::with_next_generation_hints(
                next_generation_hints,
            ),
            selected_flags,
            continuation_ticket: None,
            line_delivery: None,
            launch_events: None,
            codex_versions: None,
        }
    }
    pub(crate) fn with_launch_events(mut self, home: &Path) -> Self {
        self.launch_events = Some(Arc::new(
            crate::launch_events::LaunchEventInventory::cached(home),
        ));
        self
    }
    pub(crate) fn with_codex_versions(
        mut self,
        feed: Arc<codex_version::CodexVersionFeed>,
    ) -> Self {
        self.codex_versions = Some(feed);
        self
    }
}

crate::heap_layout_bound::fields!(OwnedActiveFile; first_read, sampling, candidate, decision, previous_snapshot_fingerprint, previous_upload_body_witness, projection_adoption_required, source_file_fingerprint, parser, aliases, applied_receipts, cursor, charged_bytes, hold_offset, group, parse_reason);

/// `requeue` for every member of a group in one pass over the pending
/// paths (round 4, L2): O(P + n), not O(P) per member, and no pending path
/// is cloned.
pub(in crate::snapshots) fn requeue_members<'a>(
    index: &mut ScanIndex,
    flags: &BTreeMap<String, (bool, bool)>,
    members: impl IntoIterator<Item = &'a CandidateFile>,
) {
    let Some(traversal) = index.traversal.as_mut() else {
        return;
    };
    let members = members.into_iter().collect::<Vec<_>>();
    // The members not pending yet; a repeated member is pushed once.
    let mut absent = members
        .iter()
        .copied()
        .map(|member| member.path.as_path())
        .collect::<std::collections::HashSet<_>>();
    for pending in &traversal.pending_candidates {
        if absent.is_empty() {
            break;
        }
        absent.remove(pending.path.as_path());
    }
    for candidate in members {
        if !absent.remove(candidate.path.as_path()) {
            continue;
        }
        let (census_member, watcher_hint) = flags
            .get(&local_index_key(&candidate.path))
            .copied()
            .unwrap_or((true, false));
        traversal.pending_candidates.push_back(ScanTraversalPath {
            scan_root: candidate.scan_root.clone(),
            path: candidate.path.clone(),
            census_member,
            watcher_hint,
        });
    }
}
