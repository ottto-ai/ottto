//! Discovery candidates: the candidate file a walk yields and the
//! opened-object stat behind its identity, the page census that counts each
//! candidate and its losses, the candidate decision and the count-only parse
//! reason and Codex selection diagnostics, and the admission that turns one
//! queued traversal path into a candidate.

use crate::snapshots::*;

#[derive(Debug, Clone)]
pub(in crate::snapshots) struct CandidateFile {
    pub(in crate::snapshots) physical_identity: Option<[u64; 2]>,
    pub(in crate::snapshots) scan_root: PathBuf,
    pub(in crate::snapshots) path: PathBuf,
    pub(in crate::snapshots) size_bytes: u64,
    pub(in crate::snapshots) modified_unix_seconds: u64,
    pub(in crate::snapshots) modified_unix_nanos: u64,
    pub(in crate::snapshots) source_file_fingerprint: String,
    pub(in crate::snapshots) legacy_source_file_fingerprint: String,
    pub(in crate::snapshots) legacy_config_reconciliation_required: bool,
    pub(in crate::snapshots) opened_object_identity: String,
    /// The ctime (unix nanos) in the opened-object identity that
    /// `source_file_fingerprint` used: the live one, or the entry's stored
    /// one when size, mtime and birth are unchanged.
    pub(in crate::snapshots) fingerprint_changed_nanos: u64,
    /// The live file birth (unix nanos) of that open; zero if unavailable.
    pub(in crate::snapshots) fingerprint_birth_nanos: u64,
    /// A withheld-account held key's re-read stamp: content and account
    /// evidence only, never mtime or ctime (`withheld_account.rs`).
    pub(in crate::snapshots) withheld_content_stamp: Option<String>,
}

/// The object inputs of one opened-object identity (unix device, inode and
/// ctime), plus the birth and mtime the content-only re-read rule checks.
/// Never persisted: entries keep only the ctime and birth. A later open of
/// the same object rebuilds
/// the identity from its live device and inode, that stored ctime and fresh
/// content samples, so a ctime-only change (chmod, xattr, hard link,
/// Spotlight, backup) reproduces the stored identity and never triggers a
/// re-read on its own. A wrong or missing stored ctime only causes a read.
/// Device and inode stay triggers (they are hashed live); birth binds the
/// stored ctime to its object generation (a reused inode, even after a clock
/// rollback, has another birth; an unavailable birth never adopts); mtime
/// stays a trigger: it moves only on content writes (truncate/regrow too).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) struct OpenedObjectStat {
    pub(in crate::snapshots) device: u64,
    pub(in crate::snapshots) inode: u64,
    pub(in crate::snapshots) changed_seconds: i64,
    pub(in crate::snapshots) changed_nanos: i64,
    pub(in crate::snapshots) birth_nanos: Option<u64>,
    pub(in crate::snapshots) modified_nanos: Option<u64>,
}

impl OpenedObjectStat {
    /// The ctime as unix nanos; zero (no stored ctime) if not representable.
    pub(in crate::snapshots) fn changed_unix_nanos(&self) -> u64 {
        u64::try_from(self.changed_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .zip(u64::try_from(self.changed_nanos).ok())
            .and_then(|(seconds, nanos)| seconds.checked_add(nanos))
            .unwrap_or_default()
    }

    /// This object with the ctime of a stored `changed_unix_nanos`.
    pub(in crate::snapshots) fn with_changed_unix_nanos(self, changed_unix_nanos: u64) -> Self {
        Self {
            changed_seconds: (changed_unix_nanos / 1_000_000_000) as i64,
            changed_nanos: (changed_unix_nanos % 1_000_000_000) as i64,
            ..self
        }
    }

    /// A stored ctime belongs to this object generation only if its stored
    /// birth is known and exactly the live one. Ordering against ctime is no
    /// binding (clock rollback, reused inodes); unavailable never binds.
    pub(in crate::snapshots) fn same_birth(&self, stored_birth_nanos: u64) -> bool {
        stored_birth_nanos != 0 && self.birth_nanos == Some(stored_birth_nanos)
    }
}

#[derive(Debug, Default)]
pub(in crate::snapshots) struct ScanCensus {
    pub(in crate::snapshots) causes: ownership::Counts,
    #[cfg(test)]
    pub(in crate::snapshots) discovered_file_count: usize,
    pub(in crate::snapshots) directory_entry_cap_exceeded_count: usize,
    pub(in crate::snapshots) symlink_rejected_count: usize,
    pub(in crate::snapshots) unreadable_path_count: usize,
    pub(in crate::snapshots) unreadable_causes: UnreadableCauses,

    pub(in crate::snapshots) oversized_file_count: usize,
    pub(in crate::snapshots) disappeared_file_count: usize,
    pub(in crate::snapshots) malformed_json_line_count: usize,
    pub(in crate::snapshots) invalid_utf8_line_count: usize,
    pub(in crate::snapshots) over_line_cap_count: usize,
    pub(in crate::snapshots) recognized_usage_drop_count: usize,
    pub(in crate::snapshots) ownership_incomplete_file_count: usize,
    pub(in crate::snapshots) zero_snapshot_usage_evidence_count: usize,
    pub(in crate::snapshots) dropped_usage_record_count: u64,
    pub(in crate::snapshots) terminal_over_line_cap_count: usize,
    pub(in crate::snapshots) terminal_recognized_usage_drop_count: usize,
    pub(in crate::snapshots) terminal_dropped_usage_record_count: u64,
    pub(in crate::snapshots) observed_index_keys: BTreeSet<String>,
    pub(in crate::snapshots) removed_index_keys: BTreeSet<String>,
    /// The subset of `removed_index_keys` that are Claude census members
    /// found absent beneath a still-present parent (N). Only these may drop
    /// their unverified audit debt with their entry at the page merge.
    pub(in crate::snapshots) claude_vanished_index_keys: BTreeSet<String>,
    /// Count-only parse-selection reasons for this page's candidates. A scan
    /// object has one source; Claude and Codex count here, nothing else does.
    pub(in crate::snapshots) parse_reasons: [usize; CANDIDATE_PARSE_REASON_COUNT],
    /// Count-only Codex selections that carry no `CandidateParseReason`.
    pub(in crate::snapshots) codex_selections: [usize; CODEX_SELECTION_COUNT],
    /// Local-only V2 counting receipts of this scan's finished parses. Boxed
    /// so the census moved through every scan step stays small; allocated
    /// only once a configured counting parse finishes.
    pub(in crate::snapshots) codex_counting_v2:
        Option<Box<crate::codex_scan_diagnostics::CountingV2Receipts>>,
    /// Count-only: parsed Claude compaction summaries on this page whose
    /// `parentUuid` chain never reached a boundary. Logged, never a decision.
    pub(in crate::snapshots) claude_compaction_unlinked_parent_count: usize,
    /// Count-only: this page's paced growth reads (see `ScanTraversalCounts`).
    pub(in crate::snapshots) growth_deferred: u64,
}

/// Preserve the old scope/open/object short-circuit and its one existing open.
pub(in crate::snapshots) fn sampled_revalidation_cause(
    scope_matches: bool,
    revalidate: impl FnOnce() -> std::io::Result<bool>,
) -> Option<UnreadableCause> {
    if !scope_matches {
        return Some(UnreadableCause::ScopeObject);
    }
    match revalidate() {
        Ok(true) => None,
        Ok(false) => Some(UnreadableCause::ScopeObject),
        Err(_) => Some(UnreadableCause::OpenRead),
    }
}

impl ScanCensus {
    /// Count-only: one Codex selection outcome. An override names why a
    /// skipped candidate was parsed; otherwise a parse counts its reason.
    pub(in crate::snapshots) fn note_codex_selection(
        &mut self,
        decision: CandidateDecision,
        reason: Option<CandidateParseReason>,
        selected_by: Option<CodexSelection>,
    ) {
        let count = match (decision, selected_by, reason) {
            (_, Some(selection), _) => &mut self.codex_selections[selection as usize],
            (CandidateDecision::Parse, None, Some(reason)) => {
                &mut self.parse_reasons[reason as usize]
            }
            (CandidateDecision::Parse, None, None) => {
                &mut self.codex_selections[CodexSelection::ComparisonTarget as usize]
            }
            (CandidateDecision::Skip, None, _) => {
                &mut self.codex_selections[CodexSelection::Skip as usize]
            }
            (CandidateDecision::Migrate, None, _) => {
                &mut self.codex_selections[CodexSelection::Migrate as usize]
            }
            (CandidateDecision::ReconcileLegacy, None, _) => {
                &mut self.codex_selections[CodexSelection::ReconcileLegacy as usize]
            }
        };
        *count = count.saturating_add(1);
    }

    pub(in crate::snapshots) fn note_codex_group(
        &mut self,
        selection: CodexSelection,
        members: usize,
    ) {
        let count = &mut self.codex_selections[selection as usize];
        *count = count.saturating_add(members);
    }

    /// The local census line attributing this page's Codex selections, or
    /// `None` when nothing was decided. Counts only: no path or identifier.
    pub(in crate::snapshots) fn codex_parse_reasons_line(&self) -> Option<String> {
        if self.parse_reasons.iter().all(|count| *count == 0)
            && self.codex_selections.iter().all(|count| *count == 0)
        {
            return None;
        }
        Some(format!(
            "local snapshot census codex parse reasons: {} {}",
            census_count_fields(&CANDIDATE_PARSE_REASON_NAMES, &self.parse_reasons),
            census_count_fields(&CODEX_SELECTION_NAMES, &self.codex_selections),
        ))
    }

    #[track_caller]
    pub(in crate::snapshots) fn record_unreadable(&mut self, cause: UnreadableCause, count: usize) {
        self.record_unreadable_sampled(cause, count, None);
    }

    /// One unreadable file: its root class, kind and key digest join the
    /// cause's bounded sample, never its path.
    #[track_caller]
    pub(in crate::snapshots) fn record_unreadable_file(
        &mut self,
        cause: UnreadableCause,
        path: &Path,
    ) {
        let key = local_index_key(path);
        self.record_unreadable_sampled(cause, 1, Some((path, key.as_str())));
    }

    #[track_caller]
    fn record_unreadable_sampled(
        &mut self,
        cause: UnreadableCause,
        count: usize,
        file: Option<(&Path, &str)>,
    ) {
        // Preserve the existing public count and operational predicates.
        self.unreadable_path_count += count;
        self.unreadable_causes
            .record_sampled(cause, count as u64, file);
        #[cfg(test)]
        sampled_scan::test_hooks::record_unreadable(cause as usize);
    }

    pub(in crate::snapshots) fn add_terminal_jsonl_loss(&mut self, loss: &TerminalJsonlLoss) {
        self.malformed_json_line_count = self
            .malformed_json_line_count
            .saturating_add(loss.malformed_json_line_count);
        self.invalid_utf8_line_count = self
            .invalid_utf8_line_count
            .saturating_add(loss.invalid_utf8_line_count);
        self.recognized_usage_drop_count = self
            .recognized_usage_drop_count
            .saturating_add(loss.recognized_usage_drop_count);
        self.dropped_usage_record_count = self
            .dropped_usage_record_count
            .saturating_add(loss.dropped_usage_record_count);
        self.terminal_recognized_usage_drop_count = self
            .terminal_recognized_usage_drop_count
            .saturating_add(loss.recognized_usage_drop_count);
        self.terminal_dropped_usage_record_count = self
            .terminal_dropped_usage_record_count
            .saturating_add(loss.dropped_usage_record_count);
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(in crate::snapshots) struct BoundedCandidateSelection {
    cursor: Option<String>,
    upper_bound: Option<String>,
    limit: usize,
    selected: BTreeMap<String, CandidateFile>,
    observed_max: Option<String>,
}

#[cfg(test)]
impl BoundedCandidateSelection {
    pub(in crate::snapshots) fn new(
        cursor: Option<String>,
        upper_bound: Option<String>,
        limit: usize,
    ) -> Self {
        // Legacy indexes carried a cursor without a frozen ceiling. Restart a
        // fresh bounded generation once rather than inheriting its starvation
        // semantics.
        let cursor = cursor.filter(|_| upper_bound.is_some());
        Self {
            cursor,
            upper_bound,
            limit,
            selected: BTreeMap::new(),
            observed_max: None,
        }
    }

    pub(in crate::snapshots) fn insert(&mut self, candidate: CandidateFile) {
        let key = local_index_key(&candidate.path);
        if self
            .observed_max
            .as_ref()
            .map_or(true, |maximum| key > *maximum)
        {
            self.observed_max = Some(key.clone());
        }
        if self.limit == 0 {
            return;
        }
        if self
            .upper_bound
            .as_ref()
            .is_some_and(|upper_bound| key > *upper_bound)
            || self.cursor.as_ref().is_some_and(|cursor| key <= *cursor)
        {
            return;
        }
        self.selected.insert(key, candidate);
        if self.selected.len() > self.limit {
            self.selected.pop_last();
        }
    }

    pub(in crate::snapshots) fn finish(
        self,
        discovered: usize,
    ) -> (Vec<CandidateFile>, bool, Option<String>, Option<String>) {
        let upper_bound = self.upper_bound.or(self.observed_max);
        let selected = self.selected.into_values().collect::<Vec<_>>();
        let next_cursor = selected
            .last()
            .map(|candidate| local_index_key(&candidate.path));
        let reached_upper_bound = next_cursor
            .as_ref()
            .zip(upper_bound.as_ref())
            .is_some_and(|(cursor, upper_bound)| cursor >= upper_bound);
        let complete = if self.limit == 0 {
            discovered == 0
        } else {
            selected.len() < self.limit || reached_upper_bound
        };
        (
            selected,
            complete,
            (!complete).then_some(next_cursor).flatten(),
            (!complete).then_some(upper_bound).flatten(),
        )
    }
}

/// Mutable candidate-boundary owner plus the same bounded member view used by
/// discovery. Built once per selection batch; no filesystem work or move authority.
pub(in crate::snapshots) struct CandidateDiscovery<'a> {
    pub(in crate::snapshots) index: &'a mut ScanIndex,
    pub(in crate::snapshots) sources: std::borrow::Cow<'a, BTreeMap<String, Option<String>>>,
    pub(in crate::snapshots) growth: Option<&'a discovery_growth::Page>,
}
impl<'a> CandidateDiscovery<'a> {
    pub(in crate::snapshots) fn new(
        index: &'a mut ScanIndex,
        growth: Option<&'a discovery_growth::Page>,
    ) -> Self {
        let sources = index.held_move_sources();
        Self {
            index,
            sources: std::borrow::Cow::Owned(sources),
            growth,
        }
    }
}

pub(in crate::snapshots) fn candidate_from_traversal_path(
    source: SnapshotSource,
    pending: ScanTraversalPath,
    census: &mut ScanCensus,
    census_unix_seconds: Option<u64>,
    backfill_window_days: u64,
    discovery: &mut CandidateDiscovery<'_>,
) -> Option<CandidateFile> {
    candidate_from_traversal_path_at(
        source,
        disappearance_diagnostics::Site::CandidateWalk,
        pending,
        census,
        census_unix_seconds,
        backfill_window_days,
        discovery,
    )
}

/// Open-admission inputs: census clock, backfill window, main's owed-key
/// retention and v2 growth debt (None for a v1 graph).
#[derive(Clone, Copy)]
pub(in crate::snapshots) struct CandidateWindow<'a> {
    pub(in crate::snapshots) census_unix_seconds: Option<u64>,
    pub(in crate::snapshots) backfill_window_days: u64,
    pub(in crate::snapshots) retention: DiscoveryRetention<'a>,
    pub(in crate::snapshots) growth: Option<&'a BTreeMap<String, sampled_audit::GrowthRetention>>,
}

pub(in crate::snapshots) fn candidate_from_traversal_path_at(
    source: SnapshotSource,
    site: disappearance_diagnostics::Site,
    pending: ScanTraversalPath,
    census: &mut ScanCensus,
    census_unix_seconds: Option<u64>,
    backfill_window_days: u64,
    discovery: &mut CandidateDiscovery<'_>,
) -> Option<CandidateFile> {
    let metadata = match fs::symlink_metadata(&pending.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if pending.watcher_hint {
                // Remove/rename events legitimately name an object that no
                // longer exists. They are not lossy census failures; remove an
                // earlier observation so terminal reconciliation can delete
                // the stale entry exactly.
                census
                    .removed_index_keys
                    .insert(local_index_key(&pending.path));
            } else if pending.census_member {
                let parent = claude_absence_is_removal(source, &pending.path);
                if parent.is_removal(&pending.path) {
                    // The same exact retirement as a remove hint, whichever
                    // order the hint and the queued member arrived in.
                    disappearance_diagnostics::not_found_removal(source, site);
                    let index_key = local_index_key(&pending.path);
                    census.claude_vanished_index_keys.insert(index_key.clone());
                    census.removed_index_keys.insert(index_key);
                } else {
                    disappearance_diagnostics::not_found(
                        &mut census.disappeared_file_count,
                        source,
                        site,
                    );
                }
            }
            return None;
        }
        Err(_) => {
            if pending.census_member {
                census.record_unreadable(UnreadableCause::Metadata, 1);
            }
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        if pending.census_member && metadata.file_type().is_symlink() {
            census.symlink_rejected_count += 1;
        }
        return None;
    }
    if source == SnapshotSource::ClaudeCode {
        if let Some(mut walk) = discovery.index.traversal.take() {
            discovery.index.rehome_discovered_account_hold(
                &mut walk,
                &discovery.sources,
                &pending.path,
                &metadata,
            );
            discovery.index.traversal = Some(walk);
        }
    }
    let recovery = DiscoveryRecovery::from(&discovery.index.files);
    let retention = DiscoveryRetention {
        growth: discovery.growth,
        ..discovery_retention!(discovery.index)
    };
    retention.observe_stamped_growth(
        &pending.path,
        metadata.len(),
        metadata
            .modified()
            .ok()
            .and_then(unix_seconds)
            .unwrap_or_default(),
        codex_fragment::Stamp::metadata(&metadata),
    );

    let modified_unix_seconds = metadata
        .modified()
        .ok()
        .and_then(unix_seconds)
        .unwrap_or_default();
    let aged = census_unix_seconds
        .is_some_and(|now| !is_recent_enough_at(modified_unix_seconds, now, backfill_window_days));
    let owes_stamped = aged
        && retention.owes_stamped(
            source,
            &pending.path,
            metadata.len(),
            codex_fragment::Stamp::metadata(&metadata),
        );
    let requires_recovery = recovery.requires(source, &pending.path, metadata.len());
    if !requires_recovery
        && aged
        && !owes_stamped
        && !sampled_audit::growth_selectable(
            source,
            &pending.path,
            sampled_audit::growth_active(discovery.index)
                .then(|| &discovery.index.v2().growth_retention),
        )
    {
        // Watcher hints must not widen the configured activity window. The
        // same revalidation also handles an ordinary candidate whose mtime was
        // restored behind the cutoff after directory discovery.
        if pending.census_member {
            census
                .removed_index_keys
                .insert(local_index_key(&pending.path));
        }
        return None;
    }
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(unix_nanos)
        .unwrap_or_else(|| modified_unix_seconds.saturating_mul(1_000_000_000));
    if pending.census_member {
        census
            .observed_index_keys
            .insert(local_index_key(&pending.path));
    }
    Some(CandidateFile {
        physical_identity: None,
        scan_root: pending.scan_root,
        source_file_fingerprint: String::new(),
        path: pending.path,
        size_bytes: metadata.len(),
        modified_unix_seconds,
        modified_unix_nanos,
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) enum CandidateDecision {
    Skip,
    Migrate,
    ReconcileLegacy,
    Parse,
}

/// Count-only diagnostic: the first gate that selected a candidate for parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateParseReason {
    TerminalDisposition,
    NewFile,
    AuthorityQuarantine,
    Audit,
    BodyWitnessAdoption,
    UploadContext,
    ActivityOrQuarantineRetry,
    TranscriptChanged,
    CodexCapture,
    UnknownOutcome,
    LegacyActivity,
    LegacyIdentity,
    Rearmed,
    SourceChanged,
    ForcedFamily,
}

pub(crate) const CANDIDATE_PARSE_REASON_COUNT: usize = 15;
pub(crate) const CANDIDATE_PARSE_REASON_NAMES: [&str; CANDIDATE_PARSE_REASON_COUNT] = [
    "terminal_disposition",
    "new_file",
    "authority_quarantine",
    "audit",
    "body_witness_adoption",
    "upload_context",
    "activity_or_quarantine_retry",
    "transcript_changed",
    "codex_capture",
    "unknown_outcome",
    "legacy_activity",
    "legacy_identity",
    "rearmed",
    "source_changed",
    "forced_family",
];

/// Count-only diagnostic: a Codex selection outcome that carries no
/// `CandidateParseReason` (final non-parse decisions, Skip-to-Parse
/// overrides, and joined groups decided before the candidate loop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) enum CodexSelection {
    Skip,
    Migrate,
    ReconcileLegacy,
    ComparisonTarget,
    GroupUnchanged,
    GroupSelected,
}

const CODEX_SELECTION_COUNT: usize = 6;
const CODEX_SELECTION_NAMES: [&str; CODEX_SELECTION_COUNT] = [
    "skip",
    "migrate",
    "reconcile_legacy",
    "comparison_target",
    "group_unchanged",
    "group_selected",
];

/// `name=count` pairs for a fixed counter array, in declaration order.
pub(in crate::snapshots) fn census_count_fields(names: &[&str], counts: &[usize]) -> String {
    names
        .iter()
        .zip(counts)
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

crate::heap_layout_bound::fields!(CandidateFile; physical_identity, scan_root, path, size_bytes, modified_unix_seconds, modified_unix_nanos, source_file_fingerprint, legacy_source_file_fingerprint, legacy_config_reconciliation_required, opened_object_identity, fingerprint_changed_nanos, fingerprint_birth_nanos, withheld_content_stamp);
crate::heap_layout_bound::fields!(ScanCensus; causes, #[cfg(test)] discovered_file_count, directory_entry_cap_exceeded_count, symlink_rejected_count, unreadable_path_count, unreadable_causes, oversized_file_count, disappeared_file_count, malformed_json_line_count, invalid_utf8_line_count, over_line_cap_count, recognized_usage_drop_count, ownership_incomplete_file_count, zero_snapshot_usage_evidence_count, dropped_usage_record_count, terminal_over_line_cap_count, terminal_recognized_usage_drop_count, terminal_dropped_usage_record_count, observed_index_keys, removed_index_keys, claude_vanished_index_keys, parse_reasons, codex_selections, codex_counting_v2, claude_compaction_unlinked_parent_count, growth_deferred);
