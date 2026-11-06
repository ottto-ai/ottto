//! Discovery traversal state: the queued scan paths, the per-generation
//! counts and the residue they settle, terminal JSONL loss, the checkpoint a
//! walk resumes from, the Codex inventory hold and the durable residue
//! witness, beside the per-source pass hooks, the Codex continuation
//! evidence, the upload ACK retirement handoff and the reason re-offer
//! cooldown.

use crate::snapshots::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::snapshots) struct ScanTraversalPath {
    pub(in crate::snapshots) scan_root: PathBuf,
    pub(in crate::snapshots) path: PathBuf,
    #[serde(default = "default_true")]
    pub(in crate::snapshots) census_member: bool,
    #[serde(default)]
    pub(in crate::snapshots) watcher_hint: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(in crate::snapshots) struct ScanTraversalCounts {
    #[serde(skip)]
    pub(in crate::snapshots) max_unread_bytes: u64,
    pub(in crate::snapshots) discovered_file_count: usize,
    pub(in crate::snapshots) directory_entry_cap_exceeded_count: usize,
    pub(in crate::snapshots) symlink_rejected_count: usize,
    pub(in crate::snapshots) unreadable_path_count: usize,
    pub(in crate::snapshots) unreadable_causes: UnreadableCauses,
    #[serde(rename = "parent_unresolvable", default, skip_serializing)]
    pub(in crate::snapshots) retired_parent_unresolvable: serde::de::IgnoredAny,
    pub(in crate::snapshots) oversized_file_count: usize,
    pub(in crate::snapshots) disappeared_file_count: usize,
    pub(in crate::snapshots) malformed_json_line_count: usize,
    pub(in crate::snapshots) invalid_utf8_line_count: usize,
    pub(in crate::snapshots) over_line_cap_count: usize,
    pub(in crate::snapshots) recognized_usage_drop_count: usize,
    pub(in crate::snapshots) ownership_incomplete_file_count: usize,
    pub(in crate::snapshots) zero_snapshot_usage_evidence_count: usize,
    pub(in crate::snapshots) dropped_usage_record_count: u64,
    /// Subset of the public loss counters above that has a durable terminal
    /// disposition. These remain disclosed but do not make an exhausted
    /// traversal retryable.
    #[serde(default)]
    pub(in crate::snapshots) terminal_over_line_cap_count: usize,
    #[serde(default)]
    pub(in crate::snapshots) terminal_recognized_usage_drop_count: usize,
    #[serde(default)]
    pub(in crate::snapshots) terminal_dropped_usage_record_count: u64,
    /// Non-progressing residue promoted to terminal by the generation that
    /// re-derived it. Ownership-incomplete Codex rollouts whose parent
    /// resolution is not pending, files with usage evidence but no entity, and
    /// the usage records those files drop are deterministic functions of their
    /// unchanged bytes, sidecar and parent evidence. Their files are never
    /// checkpointed, so every generation parses them again and reaches the
    /// same counts; retrying the traversal cannot change them. Once discovery
    /// finishes without any retryable problem they are settled here so the
    /// census can complete with the loss named, instead of holding every
    /// downstream completeness gate red for as long as those files exist.
    /// See `settle_non_progressing_residue`.
    #[serde(default)]
    pub(in crate::snapshots) terminal_ownership_incomplete_file_count: usize,
    #[serde(default)]
    pub(in crate::snapshots) terminal_zero_snapshot_usage_evidence_count: usize,
    // Persisted positional slots: diagnostic additions must remain last.
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    #[serde(rename = "unchanged_reread_admitted", default, skip_serializing)]
    pub(in crate::snapshots) retired_unchanged_reread_admitted: serde::de::IgnoredAny,
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    #[serde(rename = "reread_budget_refused", default, skip_serializing)]
    pub(in crate::snapshots) retired_reread_budget_refused: serde::de::IgnoredAny,
    #[serde(skip_serializing_if = "ownership::Counts::is_empty")]
    pub(in crate::snapshots) causes: ownership::Counts,
    #[serde(
        skip_serializing_if = "CapCounts::is_empty",
        deserialize_with = "deserialize_lenient_default"
    )]
    pub(in crate::snapshots) caps: CapCounts,
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    #[serde(rename = "codex_roster_refresh_visited", default, skip_serializing)]
    pub(in crate::snapshots) retired_codex_roster_refresh_visited: serde::de::IgnoredAny,
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    #[serde(rename = "codex_roster_growth_enqueued", default, skip_serializing)]
    pub(in crate::snapshots) retired_codex_roster_growth_enqueued: serde::de::IgnoredAny,
    /// Re-listing passes this generation started; zero while its first walk
    /// runs.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub(in crate::snapshots) listing_generations: u64,
    /// Files a re-listing pass queued that no watcher hint or earlier walk
    /// had already queued: what the watcher missed.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub(in crate::snapshots) listing_changes_without_hint: u64,
    /// Owed files with an unchanged stamp a re-listing pass queued, at most
    /// once per file per `LISTING_OWED_PACE_SECONDS`.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub(in crate::snapshots) listing_owed_requeued: u64,
    /// Diagnostic only: paced growth reads deferred until their claim ages
    /// out. Never an unreadable path, a retryable problem or an error.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub(in crate::snapshots) growth_deferred: u64,
}

/// Residue a generation disclosed as terminal after settling. Counts exclude
/// the over-line-cap loss that already carried its own terminal disposition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct SettledScanResidue {
    pub(in crate::snapshots) ownership_incomplete_file_count: usize,
    pub(in crate::snapshots) zero_snapshot_usage_evidence_count: usize,
    pub(in crate::snapshots) dropped_usage_record_count: u64,
}

impl ScanTraversalCounts {
    #[track_caller]
    pub(in crate::snapshots) fn record_unreadable(&mut self, cause: UnreadableCause, count: usize) {
        // Preserve the existing public count and operational predicates.
        self.unreadable_path_count += count;
        self.unreadable_causes
            .record_sampled(cause, count as u64, None);
    }

    /// Loss that a later traversal can still change: a directory the walk
    /// could not enter or finish, an object it could not open or read, a root
    /// that vanished, or a line the parser rejected. These keep their retry
    /// semantics: the census stays red and the bounded retry latch re-walks.
    pub(in crate::snapshots) fn has_retryable_problems(&self) -> bool {
        self.symlink_rejected_count > 0
            || self.directory_entry_cap_exceeded_count > 0
            || self.unreadable_path_count > 0
            || self.disappeared_file_count > 0
            || self.malformed_json_line_count > 0
            || self.invalid_utf8_line_count > 0
            || self.over_line_cap_count > self.terminal_over_line_cap_count
    }

    /// Non-progressing residue this generation has not yet disclosed as
    /// terminal.
    pub(in crate::snapshots) fn has_unsettled_residue(&self) -> bool {
        self.ownership_incomplete_file_count > self.terminal_ownership_incomplete_file_count
            || self.zero_snapshot_usage_evidence_count
                > self.terminal_zero_snapshot_usage_evidence_count
            || self.recognized_usage_drop_count > self.terminal_recognized_usage_drop_count
            || self.dropped_usage_record_count > self.terminal_dropped_usage_record_count
    }

    pub(in crate::snapshots) fn has_errors(&self) -> bool {
        self.has_retryable_problems() || self.has_unsettled_residue()
    }

    /// Promote the non-progressing residue to terminal for this generation.
    ///
    /// Only a generation that has finished discovery and carries no retryable
    /// problem may settle: a walk that could not enter a directory or read an
    /// object may simply not have seen the file that would resolve a fork, so
    /// its residue is not yet known to be non-progressing. The promotion is an
    /// assignment, not an accumulation, so a retained traversal that parses
    /// further pages settles again from the counts it actually re-derived.
    /// Returns true when something was newly settled.
    pub(in crate::snapshots) fn settle_non_progressing_residue(&mut self) -> bool {
        if self.has_retryable_problems() || !self.has_unsettled_residue() {
            return false;
        }
        self.terminal_ownership_incomplete_file_count = self.ownership_incomplete_file_count;
        self.terminal_zero_snapshot_usage_evidence_count = self.zero_snapshot_usage_evidence_count;
        self.terminal_recognized_usage_drop_count = self.recognized_usage_drop_count;
        self.terminal_dropped_usage_record_count = self.dropped_usage_record_count;
        true
    }

    /// The residue this generation settled, including all terminal drops.
    pub(in crate::snapshots) fn settled_residue(&self) -> Option<SettledScanResidue> {
        let dropped_usage_record_count = self.terminal_dropped_usage_record_count;
        (self.terminal_ownership_incomplete_file_count > 0
            || self.terminal_zero_snapshot_usage_evidence_count > 0
            || dropped_usage_record_count > 0)
            .then_some(SettledScanResidue {
                ownership_incomplete_file_count: self.terminal_ownership_incomplete_file_count,
                zero_snapshot_usage_evidence_count: self
                    .terminal_zero_snapshot_usage_evidence_count,
                dropped_usage_record_count,
            })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub(in crate::snapshots) struct TerminalJsonlLoss {
    #[serde(skip_serializing_if = "crate::local_resource_diagnostics::is_zero")]
    pub(in crate::snapshots) malformed_json_line_count: usize,
    #[serde(skip_serializing_if = "crate::local_resource_diagnostics::is_zero")]
    pub(in crate::snapshots) invalid_utf8_line_count: usize,
    pub(in crate::snapshots) recognized_usage_drop_count: usize,
    pub(in crate::snapshots) dropped_usage_record_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::snapshots) struct TerminalJsonlDisposition {
    pub(in crate::snapshots) source_file_fingerprint: String,
    pub(in crate::snapshots) parser_generation: String,
    pub(in crate::snapshots) loss: TerminalJsonlLoss,
}

/// Debt facts kept across traversals and per-file erasure; a traversal
/// checkpoint is dropped when its walk ends, so they cannot live there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TailDiscovery {
    /// Unix milliseconds when a discovery walk last covered every root.
    pub(crate) last_complete_discovery_at: Option<u64>,
    /// Cumulative files erased while they still held unaccepted usage.
    pub(crate) deleted_unaccepted_files: u64,
    /// Oldest known unaccepted change among those erased files, in Unix milliseconds.
    pub(crate) deleted_unaccepted_oldest_at: Option<u64>,
}
crate::heap_layout_bound::fields!(TailDiscovery; last_complete_discovery_at, deleted_unaccepted_files, deleted_unaccepted_oldest_at);
impl TailDiscovery {
    pub(in crate::snapshots) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::snapshots) struct ScanTraversalCheckpoint {
    pub(in crate::snapshots) context_fingerprint: String,
    pub(in crate::snapshots) census_window_end: String,
    pub(in crate::snapshots) scan_roots: Vec<PathBuf>,
    pub(in crate::snapshots) pending_directories: VecDeque<ScanTraversalPath>,
    pub(in crate::snapshots) pending_candidates: VecDeque<ScanTraversalPath>,
    pub(in crate::snapshots) observed_index_keys: Shared<BTreeSet<String>>,
    /// Complete current Codex rollout population, including files outside the
    /// usage lookback. Parent-prefix uniqueness cannot ignore an older
    /// duplicate source-session id merely because it is not a usage candidate.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(in crate::snapshots) codex_rollout_paths: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::snapshots) codex_join_directory_census: Option<codex_file_join::DirectoryCensus>,
    pub(in crate::snapshots) reconciliation_upper_bound: Option<String>,
    pub(in crate::snapshots) reconciliation_after: Option<String>,
    pub(in crate::snapshots) reconciliation_started: bool,
    #[serde(default)]
    pub(in crate::snapshots) watcher_hint_seen: bool,
    /// Scheduling only: a freshness page owes the next ordinary page to the
    /// census. Persist across restart so continuous appends cannot starve it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub(in crate::snapshots) codex_freshness_yield: bool,
    #[serde(
        rename = "codex_parent_resolution_retry_required",
        default,
        skip_serializing
    )]
    pub(in crate::snapshots) retired_codex_parent_resolution_retry_required: serde::de::IgnoredAny,
    #[serde(default)]
    pub(in crate::snapshots) unhealthy_retry_attempt: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::snapshots) unhealthy_retry_not_before_unix_seconds: Option<u64>,
    // Retained for exact v1/v2 decoding; ordinary post-load mutation retires it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::snapshots) oversized_discovery: BTreeMap<String, oversized_discovery::Debt>,
    pub(in crate::snapshots) counts: ScanTraversalCounts,
    /// Files this generation parsed cleanly but could not checkpoint because
    /// their content yields non-progressing residue. Recorded so the settled
    /// counts name their files instead of silently folding them into totals.
    #[serde(default, skip_serializing_if = "ScanTraversalResidue::is_empty")]
    pub(in crate::snapshots) residue: ScanTraversalResidue,
    /// When this generation's latest walk started. An older checkpoint
    /// without it starts the re-listing clock at its next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::snapshots) listing_started_unix_seconds: Option<u64>,
    /// Owed files with an unchanged stamp that a re-listing pass queued,
    /// with that pass's start. Stamps older than the pace are pruned.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::snapshots) listing_owed_requeued_unix_seconds: BTreeMap<String, u64>,
}

// A candidate's scan root is not only where its no-follow open starts: it is
// hashed into the `sampled_native_reduction:v1` scope (`sampled_scan`'s
// `file_scope`), and a scope change makes `ReadPlan::select_mode` take
// `Full(ScopeChanged)`. Under nested roots the two lookups below can differ,
// so each call site keeps the rule it already had; switching one changes later
// Full/Tail decisions. Without nesting at most one root matches and they agree.
impl ScanTraversalCheckpoint {
    /// The deepest configured scan root containing `path`, independent of
    /// `scan_roots` order.
    pub(in crate::snapshots) fn owning_scan_root(&self, path: &Path) -> Option<&PathBuf> {
        self.scan_roots
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
    }
}

/// Per-generation bookkeeping behind `ScanTraversalCounts::settle_non_progressing_residue`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(in crate::snapshots) struct ScanTraversalResidue {
    /// Local index keys of the residue files (the same key space as `files`).
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub(in crate::snapshots) index_keys: BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::snapshots) codex_inventory_hold: Option<CodexInventoryHold>,
}

impl ScanTraversalResidue {
    fn is_empty(&self) -> bool {
        self.index_keys.is_empty() && self.codex_inventory_hold.is_none()
    }
}

/// Codex candidates a page held only because its header inventory was
/// incomplete, with the evidence that made it incomplete.
///
/// Such a page holds every candidate, including sessions whose own ownership
/// is fine: an unreadable first record may belong to any of them. Those
/// candidates leave the traversal queue, so without this record they waited
/// for their next write or the next walk. They are queued again once the
/// recorded evidence moves (see `release_codex_inventory_hold`), and pass the
/// unchanged inventory and ownership gates like any other candidate. While the
/// evidence stays put nothing is re-read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(in crate::snapshots) struct CodexInventoryHold {
    /// Local index keys of the held candidates.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub(in crate::snapshots) owed: BTreeSet<String>,
    /// Roster files whose first record was refused, with their metadata
    /// witness at the refusal.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::snapshots) refused_headers: BTreeMap<String, Option<String>>,
    /// Held candidates outside the roster, with their metadata witness.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::snapshots) outside_roster: BTreeMap<String, Option<String>>,
    /// The walk still had directories to visit. Released once it has none.
    pub(in crate::snapshots) awaiting_directories: bool,
}

/// Durable record of the residue disclosed by the last census that completed
/// with named, non-progressing loss. Written when a generation completes and
/// cleared when a generation completes clean, so an operator reading the index
/// can see which files the machine cannot checkpoint, rather than inferring it
/// from per-cycle log lines.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(in crate::snapshots) struct ScanResidueWitness {
    pub(in crate::snapshots) census_window_end: String,
    pub(in crate::snapshots) ownership_incomplete_file_count: usize,
    pub(in crate::snapshots) zero_snapshot_usage_evidence_count: usize,
    pub(in crate::snapshots) dropped_usage_record_count: u64,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub(in crate::snapshots) index_keys: BTreeSet<String>,
}

impl ScanResidueWitness {
    /// Same residue, ignoring the census clock that advances every cycle.
    pub(in crate::snapshots) fn same_residue(&self, other: &Self) -> bool {
        self.ownership_incomplete_file_count == other.ownership_incomplete_file_count
            && self.zero_snapshot_usage_evidence_count == other.zero_snapshot_usage_evidence_count
            && self.dropped_usage_record_count == other.dropped_usage_record_count
            && self.index_keys == other.index_keys
    }

    /// Residue files that live under an archived Codex sessions root. An
    /// archived rollout is still inside the configured scan roots, so it is
    /// parsed like any other; the distinction only names where the residue
    /// sits so a report can say so without printing a local path.
    pub(in crate::snapshots) fn archived_residue_file_count(&self) -> usize {
        self.index_keys
            .iter()
            .filter(|key| {
                Path::new(key)
                    .components()
                    .any(|component| component.as_os_str() == "archived_sessions")
            })
            .count()
    }
}

/// Starts `source`'s pass: the context quiet retirements bind to, and removal
/// of the retired record directory beside `index_path` when this process
/// holds the state-directory lock.
#[cfg(unix)]
pub(crate) fn begin_source_pass(
    cache: &sampled_scan::SharedCache,
    support_dir: &Path,
    source: SnapshotSource,
    index_path: &Path,
    namespace: &crate::transcript_acquisition::Scope,
    identity_capture: bool,
) {
    cache.quiet_begin_pass(source, index_path, namespace, identity_capture);
    if crate::locked_state_dir::held_for(support_dir).is_some() {
        cache.remove_retired_records(source, index_path);
    }
}

/// After the pass's final index save: this source's quiet retirements commit
/// their marker through a second index save. A crash or a process without the
/// state-directory lock leaves them scheduled.
#[cfg(unix)]
pub(crate) fn after_source_save(
    cache: &sampled_scan::SharedCache,
    support_dir: &Path,
    source: SnapshotSource,
    index: &mut ScanIndex,
    index_path: &Path,
) {
    cache.quiet_reconcile(support_dir, source, index, index_path);
}

#[cfg(test)]
pub(crate) fn take_continuation_read_ranges_for_test() -> Vec<std::ops::Range<u64>> {
    sampled_scan::codex_cursor::tests::NATIVE_RANGES
        .with(|v| v.borrow_mut().take().unwrap_or_default())
}
#[cfg(test)]
pub(crate) fn begin_continuation_read_ranges_for_test() {
    sampled_scan::codex_cursor::tests::NATIVE_RANGES.with(|v| *v.borrow_mut() = Some(Vec::new()));
}
#[derive(Debug)]
pub(crate) struct CodexContinuationEvidence {
    // The page's roster; a minted ticket keeps only the paused job's share.
    pub(in crate::snapshots) inventory: codex_file_join::HeaderInventory,
    pub(in crate::snapshots) codex: CodexTitleMetadata,
    pub(in crate::snapshots) traces: Option<Arc<CodexTurnTraceMap>>,
}
crate::heap_layout_bound::fields!(CodexContinuationEvidence; inventory, codex, traces);
impl CodexContinuationEvidence {
    pub(crate) fn content_unchanged(&self) -> bool {
        self.inventory.content_unchanged()
    }
    /// The paused singleton's share of its page's evidence: the rows its
    /// path's reduction fingerprint reads and its owner's headers. Traces stay whole
    /// for turns not yet read. None, counted `not_mintable`, unless the share
    /// gives the resume check the full fingerprint, so a continuation never
    /// fails a check its page's evidence would pass.
    pub(in crate::snapshots) fn for_paused_job(
        mut self,
        cache: Option<&sampled_scan::SharedCache>,
        ticket: &sampled_scan::codex_cursor::CodexCursorTicket,
    ) -> Option<Self> {
        let job = cache.and_then(|cache| cache.paused_singleton(ticket));
        let narrowed = job.and_then(|(path, owner, _decided)| {
            let codex = self.codex.narrowed_to(&path);
            #[cfg(test)]
            let codex = {
                let mut codex = codex;
                sampled_scan::codex_cursor::tests::constrain_narrowed(&mut codex, &path);
                codex
            };
            if codex.path_reduction_fingerprint(&path)
                != self.codex.path_reduction_fingerprint(&path)
            {
                return None;
            }
            self.inventory.keep_job_share(|header| {
                Some(&header.owner) == owner.as_ref() || header.candidate.path == path
            });
            Some(Self {
                inventory: self.inventory,
                codex,
                traces: self.traces,
            })
        });
        if narrowed.is_none() {
            crate::local_resource_diagnostics::codex_continuation_mint("not_mintable");
        }
        narrowed
    }
}
/// Hash-only cleanup obligation atomically committed with incidence retirement.
/// The generation is the commit that first authorizes these exact ACK bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UploadAckRetirementHandoff {
    pub destination_namespace_hash: String,
    pub committed_generation: u64,
    pub bodies: BTreeMap<String, String>,
    /// Exact obligations blocked by opaque incidence or a hold. Only a later
    /// selected index commit can promote these to cleanup authority.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pending_bodies: BTreeMap<String, String>,
}

/// Runtime refusal custody; stale debt permits acquisition only after input changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReasonReofferCooldown {
    pub(crate) body_witness: String,
    pub(crate) input_change_only: bool,
}
impl From<String> for ReasonReofferCooldown {
    fn from(body_witness: String) -> Self {
        Self {
            body_witness,
            input_change_only: false,
        }
    }
}
crate::heap_layout_bound::fields!(ReasonReofferCooldown; body_witness, input_change_only);

crate::heap_layout_bound::fields!(ScanResidueWitness; census_window_end, ownership_incomplete_file_count, zero_snapshot_usage_evidence_count, dropped_usage_record_count, index_keys);
crate::heap_layout_bound::fields!(ScanTraversalCheckpoint; oversized_discovery, context_fingerprint, census_window_end, scan_roots, pending_directories, pending_candidates, observed_index_keys, codex_rollout_paths, codex_join_directory_census, reconciliation_upper_bound, reconciliation_after, reconciliation_started, watcher_hint_seen, codex_freshness_yield, retired_codex_parent_resolution_retry_required, unhealthy_retry_attempt, unhealthy_retry_not_before_unix_seconds, counts, residue, listing_started_unix_seconds, listing_owed_requeued_unix_seconds);
crate::heap_layout_bound::fields!(ScanTraversalCounts; max_unread_bytes, caps, causes, retired_unchanged_reread_admitted, retired_reread_budget_refused, retired_codex_roster_refresh_visited, retired_codex_roster_growth_enqueued, discovered_file_count, directory_entry_cap_exceeded_count, symlink_rejected_count, unreadable_path_count, unreadable_causes, retired_parent_unresolvable, oversized_file_count, disappeared_file_count, malformed_json_line_count, invalid_utf8_line_count, over_line_cap_count, recognized_usage_drop_count, ownership_incomplete_file_count, zero_snapshot_usage_evidence_count, dropped_usage_record_count, terminal_over_line_cap_count, terminal_recognized_usage_drop_count, terminal_dropped_usage_record_count, terminal_ownership_incomplete_file_count, terminal_zero_snapshot_usage_evidence_count, listing_generations, listing_changes_without_hint, listing_owed_requeued, growth_deferred);
crate::heap_layout_bound::fields!(ScanTraversalPath; scan_root, path, census_member, watcher_hint);
crate::heap_layout_bound::fields!(ScanTraversalResidue; index_keys, codex_inventory_hold);
crate::heap_layout_bound::fields!(CodexInventoryHold; owed, refused_headers, outside_roster, awaiting_directories);
crate::heap_layout_bound::fields!(TerminalJsonlDisposition; source_file_fingerprint, parser_generation, loss);
crate::heap_layout_bound::fields!(TerminalJsonlLoss; malformed_json_line_count, invalid_utf8_line_count, recognized_usage_drop_count, dropped_usage_record_count);
