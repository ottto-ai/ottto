//! Private, default-inactive native comparison preparation. Nothing here is
//! ownership, coverage, a settled body, or permission to suppress a rearm.
use super::*;
pub(crate) mod lifecycle;
mod metadata;
mod settlement;
use metadata::{Map as DescriptorMap, Set as DescriptorSet};
use settlement::NativeCorrection;
pub(crate) use settlement::{Completion, SelectedFallback};

#[cfg(test)]
thread_local! {
    static TARGET_UNKNOWN_ALLOWANCE_TEST: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(crate) struct TargetUnknownAllowanceTest;
#[cfg(test)]
pub(crate) fn target_unknown_allowance_for_test() -> TargetUnknownAllowanceTest {
    TARGET_UNKNOWN_ALLOWANCE_TEST.with(|state| assert!(state.replace(Some(0)).is_none()));
    TargetUnknownAllowanceTest
}
#[cfg(test)]
impl TargetUnknownAllowanceTest {
    pub(crate) fn hits(&self) -> usize {
        TARGET_UNKNOWN_ALLOWANCE_TEST.with(|state| state.get().expect("active refusal fixture"))
    }
}
#[cfg(test)]
impl Drop for TargetUnknownAllowanceTest {
    fn drop(&mut self) {
        TARGET_UNKNOWN_ALLOWANCE_TEST.with(|state| state.set(None));
    }
}

/// Borrow the same process lease at the final rearm decision, rather than
/// turning its earlier allowed() result into a durable permission bit.
pub(crate) struct NegativeView<'a> {
    window: &'a WindowEligibility,
    lease: &'a lifecycle::Lease,
}
/// Borrow actual native completion independently of upload settlement. Neither
/// a lease nor a possible-owner envelope can manufacture this moving owner.
pub(crate) struct FoldView<'a> {
    pub(super) negatives: Option<NegativeView<'a>>,
    native_window: Option<&'a str>,
}
impl FoldView<'_> {
    pub(super) fn native_census_complete(&self, scan: &SourceScanResult) -> bool {
        self.native_window.is_some_and(|window| {
            scan.source == SnapshotSource::ClaudeCode
                && window == scan.census_window_end
                && scan.state_census_complete
                && scan.sidecar_census_complete
        })
    }
}
impl Completion {
    pub(crate) fn fold_view<'a>(&'a self, lease: Option<&'a lifecycle::Lease>) -> FoldView<'a> {
        FoldView {
            negatives: self.negatives(lease),
            native_window: self.native_window(),
        }
    }
    pub(crate) fn negatives<'a>(
        &'a self,
        lease: Option<&'a lifecycle::Lease>,
    ) -> Option<NegativeView<'a>> {
        let lease = lease.filter(|lease| lease.allowed())?;
        Some(NegativeView {
            window: self.window.as_deref()?,
            lease,
        })
    }
}
impl<'a> NegativeView<'a> {
    pub(super) fn keys(
        &self,
        index: &ScanIndex,
        demoting: &BTreeMap<String, BTreeSet<String>>,
        members: &BTreeMap<String, BTreeSet<String>>,
    ) -> BTreeSet<&'a str> {
        if !self.lease.allowed() || !self.window.accounted() {
            return BTreeSet::new();
        }
        let mut keys: BTreeSet<&'a str> = self
            .window
            .roots
            .iter()
            .filter(|(root, saved)| {
                !demoting.contains_key(*root)
                    && !self.window.revoked_roots.contains(*root)
                    && WindowEligibility::root_is_current(root, saved, index)
                    && index
                        .claude_usage_family_witnesses
                        .get(*root)
                        .is_some_and(|witness| {
                            members.get(*root).is_some_and(|actual| {
                                actual
                                    .iter()
                                    .eq(witness.member_request_id_fingerprints.keys())
                            })
                        })
            })
            .flat_map(|(_, saved)| saved.certified.keys().map(String::as_str))
            .collect();
        keys.extend(
            self.window
                .native_corrections
                .iter()
                .filter(|(key, receipt)| {
                    !demoting.contains_key(receipt.root())
                        && !self
                            .window
                            .correction_forbidden_roots
                            .contains(receipt.root())
                        && !self.window.correction_revoked_keys.contains(*key)
                        && receipt.current(key, index)
                        && index
                            .claude_usage_family_witnesses
                            .get(receipt.root())
                            .is_some_and(|witness| {
                                members.get(receipt.root()).is_some_and(|actual| {
                                    actual
                                        .iter()
                                        .eq(witness.member_request_id_fingerprints.keys())
                                })
                            })
                })
                .map(|(key, _)| key.as_str()),
        );
        keys
    }
}

pub(crate) fn actual_native_conjunction(disposition: &ClaudeUsageAuthorityDisposition) -> bool {
    let census = &disposition.duplicate_census;
    census.census_complete
        && census.coverage_complete
        && !census.census_invalid
        && !census.fence_after
        && census.pending_occurrence_count > 0
        && disposition.transcript_ownership_complete
}

/// Retaining a previously bootstrapped permit across a bounded page requires
/// known clean native history and the actual selected-save marker in Lease.
/// This predicate cannot mint a permit or certify an unchanged member.
pub(crate) fn selected_page_is_clean(
    scan: &SourceScanResult,
    index: &ScanIndex,
    disposition: &ClaudeUsageAuthorityDisposition,
) -> bool {
    scan.source == SnapshotSource::ClaudeCode
        && scan.state_census_complete
        && scan.sidecar_census_complete
        && scan.directory_entry_cap_exceeded_count == 0
        && scan.symlink_rejected_count == 0
        && scan.unreadable_path_count == 0
        && scan.oversized_file_count == 0
        && scan.disappeared_file_count == 0
        && scan.malformed_json_line_count == 0
        && scan.invalid_utf8_line_count == 0
        && scan.over_line_cap_count == 0
        && scan.recognized_usage_drop_count == 0
        && scan.ownership_incomplete_file_count == 0
        && scan.zero_snapshot_usage_evidence_count == 0
        && scan.dropped_usage_record_count == 0
        && !index.bounded_sweep_had_unsettled_upload
        && !index.claude_duplicate_request_witness_overflowed
        && !disposition.duplicate_census.census_invalid
        && !disposition.duplicate_census.fence_after
        && (scan.census_complete
            || index.traversal.as_ref().is_some_and(|traversal| {
                traversal.census_window_end == scan.census_window_end
                    && !traversal.counts.has_errors()
                    && !traversal.watcher_hint_seen
            }))
}

pub(crate) struct PairedRows<'a> {
    pub(crate) api: &'a BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>>,
    pub(crate) trace:
        &'a BTreeMap<String, Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence>>,
    /// Only complete, same-opened-generation pairs from this preparation.
    pub(crate) healthy_roots: &'a BTreeSet<String>,
}

pub(crate) fn early_root_is_eligible(index: &ScanIndex, root: &str) -> bool {
    !index.claude_usage_authority_quarantine.contains_key(root)
        && index
            .claude_usage_family_witnesses
            .get(root)
            .is_some_and(|witness| {
                witness.legacy_excluded_request_id_hashes.is_empty()
                    && witness.legacy_owner_roots.is_empty()
                    && witness.legacy_exclusion_evidence_fingerprint.is_none()
            })
}

/// A single moving owner for the actual completed native traversal. It never
/// enters SourceScanResult (which is Clone) or a disk record. It qualifies only
/// native census completion, never uniqueness, a permit or upload settlement.
/// Selected-state fallback validates context before restoring it.
pub(crate) struct TerminalTraversal {
    traversal: ScanTraversalCheckpoint,
}
/// Only the completed window is needed by the final native fold. This receipt
/// can only consume the actual terminal owner; it cannot be minted from a flag,
/// a negative certificate or a restored traversal. Selected recovery keeps the
/// original full owner instead, until its durable save.
struct NativeCensusCompletion {
    census_window_end: String,
}
impl TerminalTraversal {
    fn into_native_census(self: Box<Self>) -> NativeCensusCompletion {
        let Self { traversal } = *self;
        NativeCensusCompletion {
            census_window_end: traversal.census_window_end,
        }
    }

    pub(super) fn take(
        index: &mut ScanIndex,
        source: SnapshotSource,
        comparison_active: bool,
        native_census_complete: bool,
        census_window_end: &str,
    ) -> Option<Box<Self>> {
        if source != SnapshotSource::ClaudeCode
            || !comparison_active
            || !native_census_complete
            || !index.traversal.as_ref().is_some_and(|traversal| {
                traversal.census_window_end == census_window_end
                    && !traversal.context_fingerprint.is_empty()
                    && traversal.pending_directories.is_empty()
                    && traversal.pending_candidates.is_empty()
                    && !traversal.counts.has_errors()
                    && !traversal.watcher_hint_seen
                    && !traversal.codex_parent_resolution_retry_required
            })
        {
            return None;
        }
        // Move the original object, not the diagnostic traversal_snapshot clone.
        index
            .traversal
            .take()
            .map(|traversal| Box::new(Self { traversal }))
    }

    #[cfg(test)]
    pub(super) fn context_pointer_for_test(&self) -> usize {
        self.traversal.context_fingerprint.as_ptr() as usize
    }
    #[cfg(test)]
    pub(super) fn contains_observed_for_test(&self, key: &str) -> bool {
        self.traversal.observed_index_keys.contains(key)
    }
}
crate::heap_layout_bound::fields!(TerminalTraversal; traversal);
crate::heap_layout_bound::fields!(NativeCensusCompletion; census_window_end);

/// Select only caller-known recovery paths already in this traversal queue and
/// still carrying durable rearm debt. The queue retains its allocation and all
/// unselected entries in their prior order. Clone only selected path records;
/// there is no index/parser/snapshot clone or separate traversal.
///
/// Missing paths stay missing: the controller must use base fallback rather
/// than interpreting this narrow seam as proof of cross-generation liveness.
pub(super) fn select_recovery_before_audits(
    queue: &mut VecDeque<ScanTraversalPath>,
    selected: &mut Vec<ScanTraversalPath>,
    files: &BTreeMap<String, ScanIndexEntry>,
    recovery_paths: &[PathBuf],
    limit: usize,
) {
    if recovery_paths.is_empty() || selected.len() >= limit {
        return;
    }
    let requested = recovery_paths.iter().collect::<BTreeSet<_>>();
    queue.retain(|candidate| {
        let eligible = selected.len() < limit
            && requested.contains(&candidate.path)
            && files
                .get(&local_index_key(&candidate.path))
                .is_some_and(|entry| entry.source_file_fingerprint.is_empty());
        if eligible {
            selected.push(candidate.clone());
        }
        !eligible
    });
}

#[derive(Debug, Clone)]
struct NormalSkip {
    root: String,
    member: String,
    revision: String,
    census_window_end: String,
    upload_context: Option<String>,
    candidate: CandidateFile,
}

/// Ephemeral index membership, borrowing the canonical path identities. The
/// sorted view validates the same complete physical universe as the ordinary
/// owned membership map; it is neither request coverage nor a durable witness.
pub(super) struct MembershipView<'a> {
    members: Vec<ClaudeIndexPathMemberRef<'a>>,
}
impl<'a> MembershipView<'a> {
    pub(super) fn selected_count(
        index: &ScanIndex,
        selected: impl Fn(&str) -> bool,
    ) -> Option<usize> {
        index
            .files
            .keys()
            .filter_map(|key| claude_index_path_member_ref(Path::new(key)))
            .filter(|identity| selected(identity.root))
            .try_fold(0usize, |count, _| count.checked_add(1))
    }
    pub(super) fn capture(index: &'a ScanIndex, selected: impl Fn(&str) -> bool) -> Option<Self> {
        let count = Self::selected_count(index, &selected)?;
        let mut members = Vec::new();
        members.try_reserve_exact(count).ok()?;
        for key in index.files.keys() {
            let Some(identity) = claude_index_path_member_ref(Path::new(key)) else {
                continue;
            };
            if selected(identity.root) {
                members.push(identity);
            }
        }
        // slice::sort_unstable uses no heap workspace. Root then optional stem
        // orders members exactly as root or root+'_'+stem in the owned map.
        members.sort_unstable();
        Some(Self { members })
    }
    pub(super) fn matches(&self, root: &str, witness: &ClaudeUsageFamilyWitness) -> bool {
        let start = self.members.partition_point(|member| member.root < root);
        let end = self.members.partition_point(|member| member.root <= root);
        let members = &self.members[start..end];
        members.len() == witness.member_request_id_fingerprints.len()
            && members.iter().any(|member| member.subagent_stem.is_none())
            && members.windows(2).all(|pair| pair[0] != pair[1])
            && members
                .iter()
                .zip(witness.member_request_id_fingerprints.keys())
                .all(|(actual, expected)| actual.matches_member(expected))
    }
}

/// Eligibility descriptors only. No Clone, rows, assigned request sets or
/// envelope graph survive the page. A later page must reconstruct P again.
#[derive(Debug)]
pub(crate) struct WindowEligibility {
    census_window_end: String,
    roots: DescriptorMap<WindowRoot>,
    revoked_roots: DescriptorSet,
    native_corrections: DescriptorMap<NativeCorrection>,
    correction_revoked_keys: DescriptorSet,
    correction_forbidden_roots: DescriptorSet,
}
#[derive(Debug)]
struct WindowRoot {
    proof: String,
    certified: DescriptorMap<NormalSkip>,
}
impl WindowEligibility {
    fn accounted(&self) -> bool {
        self.roots.accounted()
            && self.revoked_roots.accounted()
            && self.native_corrections.accounted()
            && self.correction_revoked_keys.accounted()
            && self.correction_forbidden_roots.accounted()
    }

    #[cfg(test)]
    pub(super) fn native_correction_count_for_test(&self) -> usize {
        self.native_corrections.len()
    }
    fn membership_scratch_peak(&self, index: &ScanIndex) -> Option<usize> {
        if !crate::heap_layout_bound::layout_supported() || !self.accounted() {
            return None;
        }
        // Exact one-buffer capacity; path strings remain borrowed from index.
        // No owned intermediate/final membership trees or sorting Vec exists.
        MembershipView::selected_count(index, |root| self.roots.contains_key(root))?
            .checked_mul(std::mem::size_of::<ClaudeIndexPathMemberRef<'_>>())?
            // Canonical SHA formatter: old32/new64 ASCII hex buffer overlap.
            .checked_add(96)
    }
    fn root_is_current(root: &str, saved: &WindowRoot, index: &ScanIndex) -> bool {
        let Some(witness) = index.claude_usage_family_witnesses.get(root) else {
            return false;
        };
        !index.claude_usage_authority_quarantine.contains_key(root)
            && claude_usage_family_witness_fingerprint(witness) == saved.proof
            && saved.certified.iter().all(|(key, skip)| {
                index.files.get(key).is_some_and(|entry| {
                    entry.source_file_fingerprint == skip.revision
                        && entry.scan_identity_version.as_deref()
                            == Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
                        && entry.last_snapshot_fingerprint.is_some()
                }) && skip.upload_context == index.active_upload_context_fingerprint
                    && index.upload_context_fingerprint == index.active_upload_context_fingerprint
                    && !index.confirmed_empty_files.contains(key)
                    && !index.terminal_jsonl_dispositions.contains_key(key)
                    && !index.claude_account_deferred_holds.contains_key(key)
            })
    }

    /// Recheck after the authoritative fold/selected rollback, before retention.
    /// Current-page reconstruction is still required before any later use.
    pub(crate) fn retain_current(&mut self, index: &ScanIndex) -> bool {
        let Some(members) = MembershipView::capture(index, |root| self.roots.contains_key(root))
        else {
            return false;
        };
        self.roots.retain(|root, saved| {
            let current = !self.revoked_roots.contains(root)
                && Self::root_is_current(root, saved, index)
                && index
                    .claude_usage_family_witnesses
                    .get(root)
                    .is_some_and(|witness| members.matches(root, witness));
            if !current {
                self.revoked_roots.insert(root.clone());
            }
            current
        });
        self.native_corrections.retain(|key, receipt| {
            !self.correction_revoked_keys.contains(key)
                && !self.correction_forbidden_roots.contains(receipt.root())
                && receipt.current(key, index)
        });
        true
    }

    #[cfg(test)]
    pub(super) fn certified_member_count(&self) -> usize {
        self.roots.values().map(|root| root.certified.len()).sum()
    }
    #[cfg(test)]
    pub(super) fn first_key_for_test(&self) -> Option<&str> {
        self.roots
            .values()
            .find_map(|root| root.certified.keys().next().map(String::as_str))
    }
    #[cfg(test)]
    pub(super) fn root_revoked_for_test(&self, root: &str) -> bool {
        self.revoked_roots.contains(root)
    }
}

#[derive(Default)]
pub(crate) struct NativePhase {
    disabled: bool,
    retained_target_bytes: usize,
    parsed_keys: DescriptorSet,
    native_corrections: DescriptorMap<NativeCorrection>,
    correction_revoked_keys: DescriptorSet,
    correction_forbidden_roots: DescriptorSet,
    paused: bool,
    prepared: bool,
    // Actual page Skips plus moved same-window descriptors. Retention uses the
    // shared rotation budget; positive target reads still obey the page limit.
    skips: DescriptorMap<NormalSkip>,
    // Eligibility is revoked by the actual parse attempt, including a parse
    // that later fails or produces no body. Body lists cannot recover this.
    parsed_roots: DescriptorSet,
    target_revisions: DescriptorMap<String>,
    attempted_targets: DescriptorSet,
}

struct WindowImportPlan {
    roots: usize,
    corrections: usize,
    members: usize,
    parsed_roots: usize,
    revoked_keys: usize,
    extra: usize,
}

impl NativePhase {
    #[cfg(test)]
    pub(super) fn capture_count_for_test(&self) -> usize {
        self.skips.len()
    }
    pub(super) fn early_evidence_roots<'a>(
        &'a self,
        native: &'a [SnapshotItem],
    ) -> impl Iterator<Item = &'a str> + Clone {
        self.skips
            .values()
            .map(|skip| skip.root.as_str())
            .chain(self.native_corrections.values().map(NativeCorrection::root))
            .chain(native.iter().map(claude_snapshot_family_root_ref))
    }
    pub(super) fn capture_active(&self) -> bool {
        !self.disabled
            && self.parsed_keys.accounted()
            && self.native_corrections.accounted()
            && self.correction_revoked_keys.accounted()
            && self.correction_forbidden_roots.accounted()
            && self.skips.accounted()
            && self.parsed_roots.accounted()
            && self.target_revisions.accounted()
            && self.attempted_targets.accounted()
    }

    pub(super) fn owned_capture_bytes(&self) -> Option<usize> {
        use crate::heap_layout_bound::{Counter, HeapLayoutBound};
        if !crate::heap_layout_bound::layout_supported() {
            return None;
        }
        let mut counter = Counter::new(usize::MAX);
        self.heap_bound(&mut counter)?;
        counter.add(self.retained_target_bytes)?;
        Some(counter.bytes)
    }

    /// The current canonical file-finish slot is ordinary serial work. Before
    /// its body outlives that slot, pay all additional retention and any new
    /// destination buffer while its old buffer/earlier target bodies coexist.
    /// No pricing clone or second projection is constructed.
    pub(super) fn retain_target_output(
        &mut self,
        parsed: &ParsedJsonlFile,
        snapshots: &mut Vec<SnapshotItem>,
        credit: &mut Option<crate::source_rotation::PaidReservation>,
    ) -> Result<(), crate::source_rotation::LocalRefusal> {
        let refuse = || {
            crate::source_rotation::LocalRefusal(
                "native comparison target retention refused before source offer",
            )
        };
        let plan = (|| {
            let paid = credit.as_mut()?;
            #[cfg(test)]
            TARGET_UNKNOWN_ALLOWANCE_TEST.with(|state| {
                if let Some(hits) = state.get() {
                    state.set(Some(hits + 1));
                    paid.at_turn(None); // failure injection can only REMOVE admission
                }
            });
            let finished = crate::heap_layout_bound::completed_bound(
                &parsed.snapshots,
                crate::source_rotation::PARKED_BUDGET,
            )?;
            let slot = std::mem::size_of::<SnapshotItem>();
            let source_buffer = parsed.snapshots.capacity().checked_mul(slot)?;
            let payload = finished
                .checked_sub(std::mem::size_of::<Vec<SnapshotItem>>())?
                .checked_sub(source_buffer)?;
            let length = snapshots.len().checked_add(parsed.snapshots.len())?;
            let capacity = snapshots.capacity().max(length);
            let new_buffer = if length > snapshots.capacity() {
                capacity.checked_mul(slot)?
            } else {
                0
            };
            let retained_buffer = capacity
                .checked_sub(snapshots.capacity())?
                .checked_mul(slot)?;
            let retained = payload.checked_add(retained_buffer)?;
            let peak = paid
                .allocated()
                .checked_add(payload)?
                .checked_add(new_buffer)?;
            paid.grow_for(peak).then_some((retained, length))
        })()
        .ok_or_else(refuse)?;
        if plan.1 > snapshots.capacity() {
            snapshots
                .try_reserve_exact(plan.1 - snapshots.len())
                .map_err(|_| refuse())?;
        }
        let paid = credit.as_mut().ok_or_else(refuse)?;
        let allocated = paid.allocated().checked_add(plan.0).ok_or_else(refuse)?;
        let retained = self
            .retained_target_bytes
            .checked_add(plan.0)
            .ok_or_else(refuse)?;
        if !paid.record_allocated(allocated) {
            return Err(refuse());
        }
        self.retained_target_bytes = retained;
        paid.retire_speculation();
        Ok(())
    }

    fn prepay_capture(
        &self,
        candidate: &CandidateFile,
        skip_context: Option<(&ScanIndex, &str)>,
        credit: &mut Option<crate::source_rotation::PaidReservation>,
    ) -> Option<(usize, bool)> {
        use crate::heap_layout_bound::{Counter, HeapLayoutBound};
        let paid = credit.as_mut()?;
        let before = self.owned_capture_bytes()?;
        let external = paid.allocated().checked_sub(before)?;
        let mut extra = Counter::new(usize::MAX);
        let path = candidate.path.to_str()?; // no lossy-path allocation in this optional mode
        let length = path.len();
        // Canonical subagent resolution builds one Vec<&str>. Include its
        // old/replacement capacity while collecting the path components.
        let components = candidate.path.components().count().max(4);
        extra.add(components.checked_mul(std::mem::size_of::<&str>())?)?;
        extra.add(
            components
                .checked_mul(2)?
                .checked_mul(std::mem::size_of::<&str>())?,
        )?;
        // local key; stored key clone; subagent field strings; formatted
        // source-id's old/new buffers; returned root/member scratch. These are
        // separate owners in the canonical path helper, each <= path length.
        for _ in 0..7 {
            extra.add(length)?;
        }
        if let Some((index, window)) = skip_context {
            extra.add(self.skips.growth_peak()?)?;
            candidate.completed_heap_bound(&mut extra)?;
            extra.add(candidate.source_file_fingerprint.len())?;
            extra.add(window.len())?;
            extra.add(
                index
                    .active_upload_context_fingerprint
                    .as_ref()
                    .map_or(0, String::len),
            )?;
        } else {
            // Parsed key, revoked correction key, parsed root: each compact
            // buffer is paid at its old-plus-new replacement peak.
            extra.add(self.parsed_keys.growth_peak()?)?;
            extra.add(self.correction_revoked_keys.growth_peak()?)?;
            extra.add(self.parsed_roots.growth_peak()?)?;
        }
        let admitted = paid.grow_for(paid.allocated().checked_add(extra.bytes)?);
        Some((external, admitted))
    }

    fn finish_paid_capture(
        &mut self,
        credit: &mut Option<crate::source_rotation::PaidReservation>,
        external: usize,
    ) -> bool {
        let recorded = self
            .owned_capture_bytes()
            .and_then(|owned| external.checked_add(owned))
            .is_some_and(|owned| {
                credit
                    .as_mut()
                    .is_some_and(|paid| paid.record_allocated(owned))
            });
        if !recorded {
            self.disable();
            if let Some(paid) = credit.as_mut() {
                // No descriptor eligibility survives. Keep all already-paid
                // future recovery credit in the enclosing moving owner.
                let _ = paid.record_allocated(external);
            }
        }
        recorded
    }

    pub(super) fn record_parse_attempt_paid(
        &mut self,
        candidate: &CandidateFile,
        credit: &mut Option<crate::source_rotation::PaidReservation>,
    ) -> bool {
        if self.disabled {
            return false;
        }
        let Some((external, true)) = self.prepay_capture(candidate, None, credit) else {
            self.disable();
            return false;
        };
        self.record_parse_attempt(candidate);
        self.finish_paid_capture(credit, external)
    }

    pub(super) fn record_actual_skip_paid(
        &mut self,
        index: &ScanIndex,
        candidate: &CandidateFile,
        window: &str,
        credit: &mut Option<crate::source_rotation::PaidReservation>,
    ) {
        if self.disabled {
            return;
        }
        let Some((external, admitted)) =
            self.prepay_capture(candidate, Some((index, window)), credit)
        else {
            self.disable();
            return;
        };
        if !admitted {
            // A new optional Skip descriptor has no effect if omitted. Keep
            // previously paid certificates; the missing member takes BASE.
            // Unknown accounting (above) and unrecordable parse revocation
            // (record_parse_attempt_paid) still disable the entire phase.
            return;
        }
        self.record_actual_skip(index, candidate, window);
        self.finish_paid_capture(credit, external);
    }

    fn window_import_plan(
        &self,
        previous: &WindowEligibility,
        index: &ScanIndex,
    ) -> Option<WindowImportPlan> {
        use crate::heap_layout_bound::Counter;
        let roots = previous.roots.len();
        let corrections = previous.native_corrections.len();
        let members = previous
            .roots
            .values()
            .try_fold(0usize, |n, root| n.checked_add(root.certified.len()))?;
        let revoked = previous.revoked_roots.len().checked_add(roots)?;
        let correction_revoked = previous
            .correction_revoked_keys
            .len()
            .checked_add(corrections)?;
        let mut extra = Counter::new(usize::MAX);
        extra.add(previous.membership_scratch_peak(index)?)?;
        extra.add(previous.revoked_roots.merge_buffer_peak(roots)?)?;
        extra.add(self.parsed_roots.merge_buffer_peak(revoked)?)?;
        extra.add(
            self.correction_revoked_keys
                .merge_buffer_peak(correction_revoked)?,
        )?;
        extra.add(
            self.correction_forbidden_roots
                .merge_buffer_peak(previous.correction_forbidden_roots.len())?,
        )?;
        extra.add(self.native_corrections.merge_buffer_peak(corrections)?)?;
        extra.add(self.skips.merge_buffer_peak(members)?)?;
        // retain_current may add a tombstone for every root before moving
        // these same keys into parsed_roots. Only this clone is new.
        for root in previous.roots.keys() {
            extra.add(root.len())?;
        }
        Some(WindowImportPlan {
            roots,
            corrections,
            members,
            parsed_roots: revoked,
            revoked_keys: correction_revoked,
            extra: extra.bytes,
        })
    }
    #[cfg(test)]
    pub(super) fn window_import_extra_for_test(
        &self,
        previous: &WindowEligibility,
        index: &ScanIndex,
    ) -> Option<usize> {
        self.window_import_plan(previous, index)
            .map(|plan| plan.extra)
    }
    /// Pay membership scratch and all destination slot buffers while the old
    /// window remains owned. No provider rows, index facts or permission change
    /// before this reservation. The ordinary membership validator remains the
    /// authority, including unexpected paths and duplicate physical members.
    pub(super) fn import_window_paid(
        &mut self,
        previous: Option<Box<WindowEligibility>>,
        index: &ScanIndex,
        census_window_end: &str,
        credit: &mut Option<crate::source_rotation::PaidReservation>,
    ) -> bool {
        use crate::heap_layout_bound::{Counter, HeapLayoutBound};
        let Some(mut previous) = previous else {
            return true;
        };
        let occupied = (|| {
            let mut old = Counter::new(usize::MAX);
            previous.heap_bound(&mut old)?;
            credit
                .as_ref()?
                .allocated()
                .checked_sub(self.owned_capture_bytes()?)?
                .checked_sub(old.bytes)
        })();
        let prepared = (|| {
            let external = occupied?;
            if !self.capture_active()
                || !previous.accounted()
                || previous.census_window_end != census_window_end
            {
                return None;
            }
            let plan = self.window_import_plan(&previous, index)?;
            let paid = credit.as_mut()?;
            if !paid.grow_for(paid.allocated().checked_add(plan.extra)?) {
                return None;
            }
            previous.revoked_roots.reserve_merge(plan.roots)?;
            self.parsed_roots.reserve_merge(plan.parsed_roots)?;
            self.correction_revoked_keys
                .reserve_merge(plan.revoked_keys)?;
            self.correction_forbidden_roots
                .reserve_merge(previous.correction_forbidden_roots.len())?;
            self.native_corrections.reserve_merge(plan.corrections)?;
            self.skips.reserve_merge(plan.members)?;
            Some(external)
        })();
        let accepted = if prepared.is_some() {
            self.import_window(Some(previous), index, census_window_end)
        } else {
            drop(previous);
            false
        };
        if !accepted {
            self.disable();
        }
        let reconciled = occupied
            .and_then(|external| external.checked_add(self.owned_capture_bytes()?))
            .is_some_and(|owned| {
                credit
                    .as_mut()
                    .is_some_and(|paid| paid.record_allocated(owned))
            });
        if !reconciled {
            // No target/controller exists at import. Unknown ownership cannot
            // expose an optional certificate; the actual caller revokes lease.
            self.disable();
            return false;
        }
        if let Some(paid) = credit.as_mut() {
            paid.retire_speculation();
        }
        accepted
    }

    pub(super) fn import_window(
        &mut self,
        previous: Option<Box<WindowEligibility>>,
        index: &ScanIndex,
        census_window_end: &str,
    ) -> bool {
        let Some(mut previous) = previous else {
            return true;
        };
        if !self.capture_active()
            || !previous.accounted()
            || previous.census_window_end != census_window_end
        {
            return false;
        }
        if !previous.retain_current(index) {
            return false;
        }
        self.correction_revoked_keys
            .extend(previous.correction_revoked_keys);
        self.correction_forbidden_roots
            .extend(previous.correction_forbidden_roots);
        for (key, receipt) in previous.native_corrections {
            if self.parsed_keys.contains(&key) {
                self.correction_revoked_keys.insert(key);
            } else {
                self.native_corrections.insert(key, receipt);
            }
        }
        self.parsed_roots.extend(previous.revoked_roots);
        for (root, saved) in previous.roots {
            if self.parsed_roots.contains(&root) {
                continue;
            }
            let conflict = saved.certified.iter().any(|(key, skip)| {
                self.skips
                    .get(key)
                    .is_some_and(|current| current.revision != skip.revision)
            });
            if conflict {
                self.parsed_roots.insert(root);
            } else {
                // Move the old descriptors, never a second provider/S graph.
                self.skips.extend(saved.certified);
            }
        }
        self.skips
            .retain(|_, skip| !self.parsed_roots.contains(&skip.root));
        true
    }
    pub(super) fn record_parse_attempt(&mut self, candidate: &CandidateFile) {
        if self.disabled {
            return;
        }
        self.record_parse_key(&candidate.path);
    }

    fn record_parse_key(&mut self, path: &Path) {
        let key = local_index_key(path);
        self.parsed_keys.insert(key.clone());
        if self.native_corrections.remove(&key).is_some() {
            self.correction_revoked_keys.insert(key);
        }
        if let Some((root, _)) = claude_index_path_family_member(path) {
            self.skips.retain(|_, skip| skip.root != root);
            self.parsed_roots.insert(root);
        }
    }

    /// Logical-page unit adapter: the caller actually parsed each controlled
    /// source revision. No physical opened-file, layout or Skip claim is made.
    /// The full SourcePreparation oracle separately covers those boundaries.
    #[cfg(test)]
    pub(super) fn primitive_completion_for_test(
        scan: &SourceScanResult,
        index: &ScanIndex,
        rows: PairedRows<'_>,
        lease: &mut lifecycle::Lease,
    ) -> Completion {
        let mut phase = Self::default();
        for pending in &scan.pending_finalization {
            phase.record_parse_key(Path::new(&pending.index_key));
        }
        assert!(phase.import_window(lease.take_window(), index, &scan.census_window_end));
        assert!(phase.pause_before_finalization());
        let mut qualification =
            phase.qualify(index, &scan.snapshots, &scan.census_window_end, rows);
        let (targets, selection) = qualification.take_target_candidates(&scan.snapshots, 0);
        assert!(targets.is_empty() && selection.unresolved_sources.is_empty());
        assert_eq!(
            selection.matched_roots, 0,
            "this unit oracle has no cross-family targets"
        );
        Controller::new(qualification)
            .complete(scan, None, lease.allowed())
            .unwrap()
    }

    pub(super) fn record_actual_skip(
        &mut self,
        index: &ScanIndex,
        candidate: &CandidateFile,
        census_window_end: &str,
    ) {
        if self.disabled {
            return;
        }
        let Some((root, member)) = claude_index_path_family_member(&candidate.path) else {
            return;
        };
        let key = local_index_key(&candidate.path);
        let Some(entry) = index.files.get(&key) else {
            return;
        };
        // Called ONLY from the actual candidate Skip branch, after safe open,
        // canonical identity, sidecars and launcher context were prepared.
        // Held/empty/policy/legacy/terminal skips are not normal Skip evidence.
        if index.claude_usage_authority_quarantine.contains_key(&root)
            || self.parsed_roots.contains(&root)
            || index.claude_account_deferred_holds.contains_key(&key)
            || index.confirmed_empty_files.contains(&key)
            || index.terminal_jsonl_dispositions.contains_key(&key)
            || entry.scan_identity_version.as_deref() != Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
            || entry.last_snapshot_fingerprint.is_none()
            || entry.source_file_fingerprint.is_empty()
            || entry.source_file_fingerprint != candidate.source_file_fingerprint
            || index.active_upload_context_fingerprint.is_none()
            || index.upload_context_fingerprint != index.active_upload_context_fingerprint
        {
            return;
        }
        self.skips.insert(
            key,
            NormalSkip {
                root,
                member,
                revision: candidate.source_file_fingerprint.clone(),
                census_window_end: census_window_end.to_owned(),
                upload_context: index.active_upload_context_fingerprint.clone(),
                candidate: candidate.clone(),
            },
        );
    }

    pub(super) fn pause_before_finalization(&mut self) -> bool {
        if !self.capture_active() || self.prepared {
            return false;
        }
        self.paused = true;
        true
    }

    pub(super) fn ready(&self) -> bool {
        self.capture_active() && self.paused && !self.prepared
    }
    pub(super) fn resume(&mut self) {
        self.prepared = true;
        self.paused = false;
        // Qualification now owns its selected path certificates. Do not keep
        // a second copy of their path/stat graph in the moving scan phase.
        self.skips.clear();
    }

    pub(super) fn disable(&mut self) {
        *self = Self {
            disabled: true,
            retained_target_bytes: self.retained_target_bytes,
            prepared: true,
            ..Self::default()
        };
        // Keep only the fact that this owner must MOVE its terminal traversal
        // to the selected fallback seam. No eligibility survives this state.
    }

    #[cfg(test)]
    pub(super) fn disabled_for_test(&self) -> bool {
        self.disabled
            && !self.ready()
            && self.skips.is_empty()
            && self.native_corrections.is_empty()
            && self.target_revisions.is_empty()
    }

    pub(super) fn start_targets(&mut self, candidates: &[CandidateFile]) {
        for candidate in candidates {
            let key = local_index_key(&candidate.path);
            assert!(
                self.attempted_targets.insert(key.clone()),
                "one target attempt per pass"
            );
            self.target_revisions
                .insert(key, candidate.source_file_fingerprint.clone());
        }
        self.prepared = false;
        self.paused = false;
    }

    /// Candidate selection already has its own construction boundary. At this
    /// seam, pay the extra queued ownership and both capture maps BEFORE any
    /// enqueue makes the target eligible for physical acquisition. Retained
    /// candidate storage is conservatively charged until this phase retires.
    pub(super) fn start_targets_paid(
        &mut self,
        candidates: &[CandidateFile],
        queue: &mut VecDeque<CandidateFile>,
        credit: &mut Option<crate::source_rotation::PaidReservation>,
    ) -> Result<(), crate::source_rotation::LocalRefusal> {
        use crate::heap_layout_bound::{Counter, HeapLayoutBound};
        let refuse = || {
            crate::source_rotation::LocalRefusal(
                "native comparison queued target metadata cannot be prepaid",
            )
        };
        let plan = (|| {
            let paid = credit.as_mut()?;
            let mut cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
            cost.add(self.target_revisions.merge_buffer_peak(candidates.len())?)?;
            cost.add(self.attempted_targets.merge_buffer_peak(candidates.len())?)?;
            let mut retained_extra = 0usize;
            let length = queue.len().checked_add(candidates.len())?;
            if length > queue.capacity() {
                retained_extra = length.checked_mul(std::mem::size_of::<CandidateFile>())?;
                cost.add(retained_extra)?;
            }
            for candidate in candidates {
                // local_index_key is borrowed for UTF-8 paths; non-UTF-8 is
                // optional BASE rather than an unpriced lossy conversion.
                let key = candidate.path.to_str()?;
                cost.add(key.len().checked_mul(2)?)?;
                cost.add(candidate.source_file_fingerprint.len())?;
                let mut candidate_cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
                candidate.completed_heap_bound(&mut candidate_cost)?;
                cost.add(candidate_cost.bytes)?;
                retained_extra = retained_extra.checked_add(candidate_cost.bytes)?;
            }
            let before = self.owned_capture_bytes()?;
            let external = paid.allocated().checked_sub(before)?;
            let retained = self.retained_target_bytes.checked_add(retained_extra)?;
            if !paid.grow_for(paid.allocated().checked_add(cost.bytes)?) {
                return None;
            }
            // Each buffer was priced at old-plus-new overlap. reserve_exact
            // prevents the per-insert geometric growth from adding workspace.
            self.target_revisions.reserve_merge(candidates.len())?;
            self.attempted_targets.reserve_merge(candidates.len())?;
            if length > queue.capacity() {
                queue.try_reserve_exact(candidates.len()).ok()?;
            }
            self.start_targets(candidates);
            self.retained_target_bytes = retained;
            let owned = external.checked_add(self.owned_capture_bytes()?)?;
            paid.record_allocated(owned).then_some(())
        })();
        plan.ok_or_else(refuse)
    }

    pub(super) fn target_revision_matches(&self, candidate: &CandidateFile) -> Option<bool> {
        self.target_revisions
            .get(&local_index_key(&candidate.path))
            .map(|expected| expected == &candidate.source_file_fingerprint)
    }

    /// Only the global qualification workspace: grouping, selected/candidate
    /// roots, borrowed physical membership and revoked-root growth. Per-family
    /// ledger/transform construction is a separate boundary, not inferred from
    /// this reservation. All loops here borrow existing input; no probe clone.
    pub(super) fn prepay_qualification_workspace(
        &self,
        index: &ScanIndex,
        native: &[SnapshotItem],
        credit: &mut Option<crate::source_rotation::PaidReservation>,
    ) -> bool {
        use crate::heap_layout_bound::{self, Counter, HeapLayoutBound};
        (|| {
            let paid = credit.as_mut()?;
            let roots = self
                .skips
                .len()
                .checked_add(native.len())?
                .checked_add(self.native_corrections.len())?;
            let mut cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
            heap_layout_bound::tree_nodes::<String, Vec<&SnapshotItem>>(native.len(), &mut cost)?;
            heap_layout_bound::tree_nodes::<&str, ()>(self.native_corrections.len(), &mut cost)?;
            heap_layout_bound::tree_nodes::<String, ()>(roots, &mut cost)?; // selected roots
            heap_layout_bound::tree_nodes::<String, ()>(roots, &mut cost)?; // candidate clone
            heap_layout_bound::tree_nodes::<String, ()>(roots, &mut cost)?; // controller roots
                                                                            // Native grouping's per-root Vec starts at four; total retained
                                                                            // slots <=4N, with <=2N additional replacement slots overlapping.
            cost.add(
                native
                    .len()
                    .checked_mul(6)?
                    .checked_mul(std::mem::size_of::<&SnapshotItem>())?,
            )?;
            let selected_strings = self
                .skips
                .values()
                .map(|skip| skip.root.len())
                .chain(
                    native
                        .iter()
                        .map(|item| claude_snapshot_family_root_ref(item).len()),
                )
                .chain(
                    self.native_corrections
                        .values()
                        .map(|receipt| receipt.root().len()),
                )
                .try_fold(0usize, |n, bytes| n.checked_add(bytes))?;
            // Selected roots + candidate clone + controller required roots.
            cost.add(selected_strings.checked_mul(3)?)?;
            cost.add(native.iter().try_fold(0usize, |n, item| {
                n.checked_add(claude_snapshot_family_root_ref(item).len())
            })?)?;
            // The canonical membership capture selects a subset of physical
            // paths. Price the complete borrowed index-key universe without
            // constructing an owned universe or a roots-times-files walk.
            cost.add(
                index
                    .files
                    .len()
                    .checked_mul(std::mem::size_of::<ClaudeIndexPathMemberRef<'_>>())?,
            )?;
            self.parsed_roots.completed_heap_bound(&mut cost)?;
            let revoked = roots.checked_add(self.parsed_roots.len())?;
            if revoked != 0 {
                let capacity = revoked.checked_next_power_of_two()?;
                cost.add(
                    capacity
                        .checked_add(capacity / 2)?
                        .checked_mul(std::mem::size_of::<(String, ())>())?,
                )?;
            }
            paid.grow_for(paid.allocated().checked_add(cost.bytes)?)
                .then_some(())
        })()
        .is_some()
    }

    #[cfg(test)]
    pub(super) fn qualify(
        &mut self,
        index: &ScanIndex,
        native: &[SnapshotItem],
        census_window_end: &str,
        rows: PairedRows<'_>,
    ) -> Qualification {
        self.qualify_with_credit(index, native, census_window_end, rows, None)
    }

    pub(super) fn qualify_with_credit(
        &mut self,
        index: &ScanIndex,
        native: &[SnapshotItem],
        census_window_end: &str,
        rows: PairedRows<'_>,
        mut credit: Option<&mut Option<crate::source_rotation::PaidReservation>>,
    ) -> Qualification {
        assert!(self.ready(), "preflight must precede native finalization");
        let native_by_root = group_native_by_root(native);
        let correction_roots = self
            .native_corrections
            .values()
            .map(NativeCorrection::root)
            .collect::<BTreeSet<_>>();
        let mut selected_roots = self
            .skips
            .values()
            .map(|skip| skip.root.clone())
            .chain(native_by_root.keys().cloned())
            // The terminal page may contain neither a parse nor a Skip for a
            // root corrected on an earlier page. Reconstruct its frozen P too;
            // retaining this receipt never certifies an unchanged member.
            .chain(correction_roots.iter().map(|root| (*root).to_owned()))
            .collect::<BTreeSet<_>>();
        let candidate_roots = selected_roots.clone();
        selected_roots.retain(|root| {
            rows.healthy_roots.contains(root)
                && index.claude_usage_family_witnesses.contains_key(root)
                && !index.claude_usage_authority_quarantine.contains_key(root)
        });
        if selected_roots.is_empty() {
            return Qualification {
                revoked_roots: self
                    .parsed_roots
                    .iter()
                    .chain(candidate_roots.iter())
                    .cloned()
                    .collect(),
                ..Default::default()
            };
        }
        let Some(indexed_members) =
            MembershipView::capture(index, |root| selected_roots.contains(root))
        else {
            self.disable();
            return Qualification::default();
        };
        let needs_legacy_owners = selected_roots.iter().any(|root| {
            index
                .claude_usage_family_witnesses
                .get(root)
                .is_some_and(|witness| !witness.legacy_excluded_request_id_hashes.is_empty())
        });
        let owners = if needs_legacy_owners {
            claude_legacy_request_owners_from_rows(
                rows.api
                    .iter()
                    .filter(|(root, _)| rows.healthy_roots.contains(*root)),
                rows.trace,
            )
        } else {
            // The shared validator's empty-E branch does not read owners.
            // Avoid constructing a global request-owner graph for that case.
            None
        };
        // Phase::resume used to discard this graph after cloning every valid
        // descriptor into a family. Consume its existing buffer once instead;
        // sorted root/key order needs no sort workspace or second path/stat
        // graph. Invalid roots are discarded, never certified by a miss.
        let mut captured = std::mem::take(&mut self.skips).into_entries();
        captured.sort_unstable_by(|(a_key, a), (b_key, b)| {
            a.root.cmp(&b.root).then_with(|| a_key.cmp(b_key))
        });
        let mut captured = captured.into_iter().peekable();
        let mut families = BTreeMap::new();
        let mut retained_family_heap = 0usize;
        for (root, retained) in &index.claude_usage_family_witnesses {
            while captured
                .peek()
                .is_some_and(|(_, skip)| skip.root.as_str() < root.as_str())
            {
                drop(captured.next());
            }
            // Freeze/reconstruct P from retained state. Never substitute a new
            // proof or mutate the index while deciding negative eligibility.
            if !selected_roots.contains(root)
                || !rows.healthy_roots.contains(root)
                || index.claude_usage_authority_quarantine.contains_key(root)
                || !indexed_members.matches(root, retained)
            {
                continue;
            }
            let current_native = native_by_root
                .get(root)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let Some(api) = rows.api.get(root) else {
                continue;
            };
            let Some(trace) = rows.trace.get(root) else {
                continue;
            };
            let Some(ledger) = reconstruct_claude_usage_ledger_borrowed(
                root,
                retained,
                api,
                trace,
                owners.as_ref(),
            ) else {
                continue;
            };
            // Compute held constructor inputs once per family with current
            // native members, never once per evidence row or growing bucket.
            let held_prepare_workspace = if credit.is_some() && !current_native.is_empty() {
                (|| {
                    let mut held = crate::heap_layout_bound::Counter::new(
                        crate::source_rotation::PARKED_BUDGET,
                    );
                    crate::heap_layout_bound::tree_nodes::<String, FrozenFamily>(
                        families.len(),
                        &mut held,
                    )?;
                    held.add(retained_family_heap)?;
                    held.add(borrowed_claude_ledger_workspace(&ledger)?)?;
                    Some(held.bytes)
                })()
            } else {
                Some(0)
            };
            // Current members that would fail the exact authoritative rebuild
            // make this family ineligible. Shared checks include native set and
            // occurrence fingerprints, selectors, totals, clocks and overflow.
            if current_native.iter().any(|item| {
                let Some((rows, excluded)) =
                    claude_reported_usage_inputs_from_rows(item, retained, &ledger.rows_by_member)
                else {
                    return true;
                };
                match credit.as_deref_mut() {
                    Some(credit) => {
                        credit.as_mut().and_then(|paid| {
                            validate_claude_reported_usage_paid(
                                item,
                                rows,
                                &excluded,
                                held_prepare_workspace?,
                                paid,
                            )
                        }) != Some(true)
                    }
                    None => {
                        // Only the explicit logical test adapter is unpriced;
                        // production SourcePreparation always supplies credit.
                        #[cfg(test)]
                        {
                            prepare_claude_reported_usage(item, rows, &excluded, None).is_none()
                        }
                        #[cfg(not(test))]
                        {
                            true
                        }
                    }
                }
            }) {
                continue;
            }
            let mut certified = DescriptorMap::default();
            if !self.parsed_roots.contains(root)
                && captured.peek().is_some_and(|(_, skip)| skip.root == *root)
            {
                // Complete physical membership bounds the captured leaves.
                // Pay the new buffer before moving existing descriptors; a
                // refusal leaves all earlier qualified roots intact.
                let members = retained.member_request_id_fingerprints.len();
                if let Some(credit) = credit.as_deref_mut() {
                    let admitted = credit.as_mut().is_some_and(|paid| {
                        members
                            .checked_mul(std::mem::size_of::<(String, NormalSkip)>())
                            .and_then(|bytes| paid.allocation_ceiling().checked_add(bytes))
                            .is_some_and(|peak| paid.grow_for(peak))
                    });
                    if !admitted {
                        continue;
                    }
                }
                if certified.reserve_merge(members).is_none() {
                    continue;
                }
            }
            while captured.peek().is_some_and(|(_, skip)| skip.root == *root) {
                let (key, skip) = captured.next().expect("peeked captured certificate");
                if !self.parsed_roots.contains(root)
                    && skip.census_window_end == census_window_end
                    && index.files.get(&key).is_some_and(|entry| {
                        entry.source_file_fingerprint == skip.revision
                            && skip.upload_context == index.active_upload_context_fingerprint
                    })
                    && retained
                        .member_request_id_fingerprints
                        .contains_key(&skip.member)
                {
                    certified.insert(key, skip);
                }
            }
            let certified_members = certified
                .values()
                .map(|skip| skip.member.as_str())
                .collect::<BTreeSet<_>>();
            let native_members = current_native
                .iter()
                .map(|item| item.source_session_id.as_str())
                .collect::<Vec<_>>();
            if certified_members.len() != certified.len()
                || native_members
                    .iter()
                    .any(|member| certified_members.contains(*member))
                || native_members
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != native_members.len()
            {
                continue; // Ambiguous physical member paths cannot certify negatives.
            }
            let mut assigned = ledger.assigned_request_id_hashes;
            let prior_native = current_native
                .iter()
                // Q5 initially covers only exact pre-mutation P with E empty.
                // Full request-set/occurrence/projection checks ran above.
                .filter(|item| {
                    retained
                        .legacy_excluded_request_id_hashes
                        .get(&item.source_session_id)
                        .map_or(true, BTreeSet::is_empty)
                })
                .filter_map(|item| {
                    item.source_file_fingerprint
                        .as_ref()
                        .filter(|revision| !revision.is_empty())
                        .map(|revision| {
                            let member = &item.source_session_id;
                            (
                                member.clone(),
                                FrozenNativePrior {
                                    revision: revision.clone(),
                                    request_fingerprint: retained
                                        .member_request_id_fingerprints
                                        .get(member)
                                        .cloned(),
                                    occurrence_fingerprint: retained
                                        .member_occurrence_fingerprints
                                        .get(member)
                                        .cloned(),
                                    assigned: assigned.remove(member),
                                },
                            )
                        })
                })
                .collect::<BTreeMap<_, _>>();
            if !certified.is_empty()
                || !prior_native.is_empty()
                || correction_roots.contains(root.as_str())
            {
                // Retain only S for actual Skip members and the precise Q5
                // fields for current native members. The canonical proof was
                // fully reconstructed above; its rows and whole witness are
                // not needed by the controller or the terminal window.
                let mut envelope = BTreeSet::new();
                for skip in certified.values() {
                    if let Some(hashes) = assigned.remove(&skip.member) {
                        envelope.extend(hashes);
                    }
                    if let Some(hashes) =
                        retained.legacy_excluded_request_id_hashes.get(&skip.member)
                    {
                        envelope.extend(hashes.iter().cloned());
                    }
                }
                let paired_roots = std::iter::once(root.clone())
                    // The shared reconstruction above verified these exact
                    // predecessor roots against the excluded-request owners.
                    .chain(retained.legacy_owner_roots.iter().cloned())
                    .collect();
                let frozen = FrozenFamily {
                    proof: claude_usage_family_witness_fingerprint(retained),
                    members: retained
                        .member_request_id_fingerprints
                        .keys()
                        .cloned()
                        .collect(),
                    envelope,
                    certified,
                    prior_native,
                    paired_roots,
                };
                use crate::heap_layout_bound::HeapLayoutBound;
                let mut retained = crate::heap_layout_bound::Counter::new(usize::MAX);
                if frozen.completed_heap_bound(&mut retained).is_none() {
                    continue; // An unaccountable family never enters S.
                }
                let Some(total) = retained_family_heap
                    .checked_add(retained.bytes)
                    .and_then(|bytes| bytes.checked_add(root.len()))
                else {
                    continue;
                };
                retained_family_heap = total;
                families.insert(root.clone(), frozen);
            }
            // ledger.rows_by_member drops here; no retained API row graph.
        }
        let mut qualification = Qualification::from_frozen_families(families);
        qualification.correction_revoked_keys = std::mem::take(&mut self.correction_revoked_keys);
        qualification.correction_forbidden_roots =
            std::mem::take(&mut self.correction_forbidden_roots);
        qualification.native_corrections = std::mem::take(&mut self.native_corrections);
        qualification.native_corrections.retain(|key, receipt| {
            rows.healthy_roots.contains(receipt.root())
                && qualification.families.contains_key(receipt.root())
                && !qualification.correction_revoked_keys.contains(key)
                && !qualification
                    .correction_forbidden_roots
                    .contains(receipt.root())
                && receipt.current(key, index)
        });
        qualification.revoked_roots = self.parsed_roots.clone();
        qualification
            .revoked_roots
            .extend(candidate_roots.into_iter().filter(|root| {
                !qualification
                    .families
                    .get(root)
                    .is_some_and(|family| !family.certified.is_empty())
            }));
        qualification
    }
}

struct FrozenFamily {
    proof: String,
    members: BTreeSet<String>,
    envelope: BTreeSet<String>,
    certified: DescriptorMap<NormalSkip>,
    prior_native: BTreeMap<String, FrozenNativePrior>,
    paired_roots: BTreeSet<String>,
}
struct FrozenNativePrior {
    revision: String,
    request_fingerprint: Option<String>,
    occurrence_fingerprint: Option<String>,
    assigned: Option<BTreeSet<String>>,
}

/// Moves the one frozen qualification through native continuation. A target
/// is attempted once; only newly acquired native bodies extend the frontier.
/// This controller does not filter emission, restore selected state, or
/// suppress any rearm. An unavailable comparison stays on the base path.
pub(crate) struct Controller {
    qualification: Qualification,
    required_roots: BTreeSet<String>,
    native_frontier: usize,
    awaiting_targets: bool,
    failed: bool,
    acquisition: TargetAcquisition,
}

pub(crate) struct RecoveryBudget<'a> {
    pub(crate) previous: &'a ScanIndex,
    pub(crate) credit: &'a mut Option<crate::source_rotation::PaidReservation>,
}

impl Controller {
    pub(crate) fn new(qualification: Qualification) -> Self {
        let required_roots = qualification
            .families
            .values()
            .flat_map(|family| family.paired_roots.iter().cloned())
            .chain(
                qualification
                    .native_corrections
                    .values()
                    .map(|receipt| receipt.root().to_owned()),
            )
            .collect();
        Self {
            qualification,
            required_roots,
            native_frontier: 0,
            awaiting_targets: false,
            failed: false,
            acquisition: TargetAcquisition::default(),
        }
    }

    pub(crate) fn required_roots(&self) -> &BTreeSet<String> {
        &self.required_roots
    }

    pub(crate) fn into_window(self, census_window_end: &str) -> Option<Box<WindowEligibility>> {
        if self.failed || self.awaiting_targets || !self.acquisition.unresolved_sources.is_empty() {
            return None;
        }
        self.qualification.into_window(census_window_end)
    }

    /// Called at the initial preparation pause and each subsequent target
    /// pause. False requires revoking the process lease; all actual native
    /// bodies remain available to the unchanged authoritative base fold.
    #[cfg(test)]
    pub(crate) fn advance(&mut self, scan: &mut OwnedSourceScan, current: bool) -> bool {
        self.advance_with_budget(scan, current, None)
            .expect("logical native comparison adapter")
    }

    pub(crate) fn advance_paid(
        &mut self,
        scan: &mut OwnedSourceScan,
        current: bool,
        previous: &ScanIndex,
        credit: &mut Option<crate::source_rotation::PaidReservation>,
    ) -> Result<bool, crate::source_rotation::LocalRefusal> {
        self.advance_with_budget(scan, current, Some(RecoveryBudget { previous, credit }))
    }

    fn advance_with_budget(
        &mut self,
        scan: &mut OwnedSourceScan,
        current: bool,
        recovery: Option<RecoveryBudget<'_>>,
    ) -> Result<bool, crate::source_rotation::LocalRefusal> {
        if self.failed
            || !current
            || !scan.native_comparison_is_healthy()
            || self.native_frontier > scan.snapshots.len()
        {
            self.failed = true;
            scan.disable_native_comparison();
            return Ok(false);
        }
        if self.awaiting_targets {
            let acquired = scan.take_native_comparison_acquisition(&mut self.qualification);
            self.awaiting_targets = false;
            let unresolved = !acquired.unresolved_sources.is_empty();
            self.acquisition.merge(acquired);
            if unresolved {
                self.failed = true;
                scan.disable_native_comparison();
                return Ok(false);
            }
        }
        scan.resume_native_comparison_base();
        let next_frontier = scan.snapshots.len();
        let selection = scan.acquire_native_comparison_targets_after(
            &mut self.qualification,
            self.native_frontier,
            recovery,
            &self.acquisition.known_rearm_candidates,
        )?;
        self.native_frontier = next_frontier;
        self.awaiting_targets = selection.queued > 0;
        if !selection.unresolved_sources.is_empty() {
            self.failed = true;
            self.acquisition
                .unresolved_sources
                .extend(selection.unresolved_sources);
            scan.disable_native_comparison();
            return Ok(false);
        }
        Ok(true)
    }

    #[cfg(test)]
    pub(super) fn receipt_for_test(&self) -> (&TargetAcquisition, usize) {
        (&self.acquisition, self.native_frontier)
    }
}

#[derive(Default)]
pub(crate) struct Qualification {
    families: BTreeMap<String, FrozenFamily>,
    envelope_roots: Vec<String>,
    envelope_by_hash: Vec<EnvelopeMember>,
    pending: BTreeMap<String, PendingComparison>,
    unknown_native_sources: BTreeSet<String>,
    revoked_roots: DescriptorSet,
    native_corrections: DescriptorMap<NativeCorrection>,
    correction_revoked_keys: DescriptorSet,
    correction_forbidden_roots: DescriptorSet,
}

/// Exact SHA-256 bytes, not a probabilistic filter or uniqueness evidence.
/// Sorted (digest, root slot) pairs replace one owned hex key/tree node and
/// slot vector per possible hash. These closed fields own no heap allocation.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct EnvelopeMember {
    digest: [u8; 32],
    slot: usize,
}
impl crate::heap_layout_bound::HeapLayoutBound for EnvelopeMember {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self { digest, slot } = self;
        let digest: &[u8; 32] = digest;
        let slot: &usize = slot;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(digest, c)?;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(slot, c)
    }
}
fn envelope_digest(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut digest = [0; 32];
    for (pair, out) in bytes.chunks_exact(2).zip(&mut digest) {
        *out = nibble(pair[0])?
            .checked_mul(16)?
            .checked_add(nibble(pair[1])?)?;
    }
    Some(digest)
}

struct PendingComparison {
    sources: BTreeSet<String>,
    required_revisions: BTreeMap<String, String>,
    candidates: Vec<CandidateFile>,
    available: bool,
}

/// Native acquisition only: not an owner, an accepted body, or a promise that
/// the final exact fold can offer these sources. No Clone/serialization.
#[derive(Default)]
pub(crate) struct TargetAcquisition {
    pub(crate) completed_target_files: usize,
    pub(crate) acquired_roots: BTreeSet<String>,
    pub(crate) ready_for_fold_sources: BTreeSet<String>,
    pub(crate) unresolved_sources: BTreeSet<String>,
    pub(crate) rearm_roots: BTreeSet<String>,
    pub(super) known_rearm_candidates: Vec<CandidateFile>,
}

#[derive(Default)]
pub(crate) struct TargetSelection {
    pub(crate) queued: usize,
    pub(crate) matched_roots: usize,
    pub(crate) unresolved_sources: BTreeSet<String>,
}

impl Qualification {
    pub(super) fn recovery_targets(&self) -> impl Iterator<Item = &CandidateFile> + Clone {
        self.pending
            .values()
            .flat_map(|plan| plan.candidates.iter())
    }

    fn metadata_accounted(&self) -> bool {
        self.families
            .values()
            .all(|family| family.certified.accounted())
            && self.revoked_roots.accounted()
            && self.native_corrections.accounted()
            && self.correction_revoked_keys.accounted()
            && self.correction_forbidden_roots.accounted()
    }
    fn into_window(self, census_window_end: &str) -> Option<Box<WindowEligibility>> {
        let mut roots = DescriptorMap::default();
        for (root, family) in self.families {
            if family.certified.is_empty() || self.revoked_roots.contains(&root) {
                continue;
            }
            if family
                .certified
                .values()
                .any(|skip| skip.census_window_end != census_window_end)
            {
                return None;
            }
            roots.insert(
                root,
                WindowRoot {
                    proof: family.proof,
                    certified: family.certified,
                },
            );
        }
        Some(Box::new(WindowEligibility {
            census_window_end: census_window_end.to_owned(),
            roots,
            revoked_roots: self.revoked_roots,
            native_corrections: self.native_corrections,
            correction_revoked_keys: self.correction_revoked_keys,
            correction_forbidden_roots: self.correction_forbidden_roots,
        }))
    }
    fn from_frozen_families(mut families: BTreeMap<String, FrozenFamily>) -> Self {
        let mut envelope_roots = Vec::new();
        let Some(entries) = families.values().try_fold(0usize, |count, family| {
            count.checked_add(family.envelope.len())
        }) else {
            return Self::default();
        };
        let mut envelope_by_hash = Vec::new();
        if envelope_by_hash.try_reserve_exact(entries).is_err() {
            return Self::default();
        }
        for (root, family) in &mut families {
            if family.certified.is_empty() {
                continue;
            }
            let slot = envelope_roots.len();
            envelope_roots.push(root.clone());
            for hash in std::mem::take(&mut family.envelope) {
                let Some(digest) = envelope_digest(&hash) else {
                    return Self::default(); // Invalid input is BASE, never a negative.
                };
                envelope_by_hash.push(EnvelopeMember { digest, slot });
            }
        }
        envelope_by_hash.sort_unstable();
        envelope_by_hash.dedup();
        Self {
            families,
            envelope_roots,
            envelope_by_hash,
            ..Default::default()
        }
    }

    #[cfg(test)]
    pub(super) fn take_target_candidates(
        &mut self,
        native: &[SnapshotItem],
        remaining_files: usize,
    ) -> (Vec<CandidateFile>, TargetSelection) {
        self.take_target_candidates_after(native, 0, remaining_files)
    }

    pub(super) fn take_target_candidates_after(
        &mut self,
        native: &[SnapshotItem],
        frontier: usize,
        remaining_files: usize,
    ) -> (Vec<CandidateFile>, TargetSelection) {
        let mut sources_by_root = BTreeMap::<String, BTreeSet<String>>::new();
        let mut result = TargetSelection::default();
        for item in &native[frontier..] {
            match self.possible_targets(item) {
                Some(roots) => {
                    for root in roots {
                        sources_by_root
                            .entry(root)
                            .or_default()
                            .insert(item.source_session_id.clone());
                    }
                }
                None => {
                    self.unknown_native_sources
                        .insert(item.source_session_id.clone());
                    result
                        .unresolved_sources
                        .insert(item.source_session_id.clone());
                }
            }
        }
        // No hit, no repeated whole-page grouping. Only actual target roots
        // need current native siblings to establish acquisition completeness.
        let mut native_by_root = BTreeMap::<String, Vec<&SnapshotItem>>::new();
        if !sources_by_root.is_empty() {
            for item in native {
                let root = claude_snapshot_family_root(item);
                if sources_by_root.contains_key(&root) {
                    native_by_root.entry(root).or_default().push(item);
                }
            }
        }
        let mut candidates = Vec::new();
        for (root, sources) in sources_by_root {
            // A possible hit withdraws S before any native attempt. It never
            // becomes an exact owner or renews the frozen prior-P shortcut.
            let Some(family) = self.families.remove(&root) else {
                continue;
            };
            self.revoked_roots.insert(root.clone());
            self.correction_forbidden_roots.insert(root.clone());
            self.native_corrections
                .retain(|_, receipt| receipt.root() != root);
            result.matched_roots += 1;
            let mut required_revisions = family
                .certified
                .values()
                .map(|skip| (skip.member.clone(), skip.revision.clone()))
                .collect::<BTreeMap<_, _>>();
            for item in native_by_root.get(&root).into_iter().flatten() {
                if let Some(revision) = item
                    .source_file_fingerprint
                    .as_ref()
                    .filter(|fp| !fp.is_empty())
                {
                    required_revisions.insert(item.source_session_id.clone(), revision.clone());
                }
            }
            let complete_selected_family = family
                .members
                .iter()
                .all(|member| required_revisions.contains_key(member));
            let available = complete_selected_family
                && candidates.len().saturating_add(family.certified.len()) <= remaining_files;
            let targets = family
                .certified
                .into_values()
                .map(|skip| skip.candidate)
                .collect::<Vec<_>>();
            if available {
                candidates.extend(targets.iter().cloned());
            } else {
                result.unresolved_sources.extend(sources.iter().cloned());
            }
            assert!(
                self.pending
                    .insert(
                        root,
                        PendingComparison {
                            sources,
                            required_revisions,
                            candidates: targets,
                            available,
                        }
                    )
                    .is_none(),
                "withdrawn roots cannot acquire a second plan"
            );
        }
        result.queued = candidates.len();
        (candidates, result)
    }

    pub(super) fn take_native_acquisition(
        &mut self,
        native: &[SnapshotItem],
        pending: &[PendingIndexFinalization],
        healthy: bool,
    ) -> TargetAcquisition {
        let mut native_revisions = BTreeMap::<String, BTreeMap<&str, Option<&str>>>::new();
        for item in native {
            native_revisions
                .entry(claude_snapshot_family_root(item))
                .or_default()
                .entry(&item.source_session_id)
                .and_modify(|revision| *revision = None)
                .or_insert(
                    item.source_file_fingerprint
                        .as_deref()
                        .filter(|fp| !fp.is_empty()),
                );
        }
        let mut completed_by_key = BTreeMap::<&str, Option<&PendingIndexFinalization>>::new();
        for read in pending {
            completed_by_key
                .entry(&read.index_key)
                .and_modify(|read| *read = None)
                .or_insert(Some(read));
        }
        let mut outcome = TargetAcquisition {
            unresolved_sources: std::mem::take(&mut self.unknown_native_sources),
            ..Default::default()
        };
        for (root, plan) in std::mem::take(&mut self.pending) {
            // Queueing, a restored entry or a cached snapshot cannot stand in
            // for this pass's completed full native read at the expected fp.
            let completed = plan
                .candidates
                .iter()
                .filter(|candidate| {
                    completed_by_key
                        .get(local_index_key(&candidate.path).as_str())
                        .and_then(|read| *read)
                        .is_some_and(|read| {
                            read.parse_complete
                                && read.source_file_fingerprint == candidate.source_file_fingerprint
                        })
                })
                .count();
            outcome.completed_target_files =
                outcome.completed_target_files.saturating_add(completed);
            let acquired = plan.available
                && healthy
                && completed == plan.candidates.len()
                && plan.required_revisions.iter().all(|(member, revision)| {
                    native_revisions
                        .get(&root)
                        .and_then(|members| members.get(member.as_str()))
                        .is_some_and(|actual| *actual == Some(revision.as_str()))
                });
            if acquired {
                outcome.acquired_roots.insert(root);
                outcome.ready_for_fold_sources.extend(plan.sources);
            } else {
                outcome.rearm_roots.insert(root);
                outcome.unresolved_sources.extend(plan.sources);
                outcome.known_rearm_candidates.extend(plan.candidates);
            }
        }
        // One source can depend on several families. A successful sibling
        // comparison cannot release it while another dependency is unresolved.
        outcome
            .ready_for_fold_sources
            .retain(|source| !outcome.unresolved_sources.contains(source));
        outcome
    }

    /// Q5 novelty is a read-only subtraction from the frozen PRE-MUTATION P.
    /// A changed revision, missing occurrence, E != empty, unknown member, or
    /// changed native set uses ALL actual native IDs. No post-fold proof lookup.
    pub(crate) fn new_native_hashes(&self, item: &SnapshotItem) -> Option<BTreeSet<String>> {
        let hashes = claude_snapshot_request_id_hashes(item)?;
        let Some(family) = self.families.get(&claude_snapshot_family_root(item)) else {
            return Some(hashes);
        };
        let member = &item.source_session_id;
        // Only E-empty native members enter this frozen prior map. Its exact
        // pre-mutation proof and fingerprints cannot be replaced by P_new.
        let Some(prior) = family.prior_native.get(member) else {
            return Some(hashes);
        };
        if Some(&prior.revision) != item.source_file_fingerprint.as_ref()
            || prior.request_fingerprint.as_ref()
                != Some(&claude_request_id_set_fingerprint(&hashes))
        {
            return Some(hashes);
        }
        let occurrences = item
            .claude_usage_occurrences
            .iter()
            .map(|(id, occurrence)| {
                (
                    format!("{:x}", Sha256::digest(id.as_bytes())),
                    ClaudeTranscriptUsageOccurrenceWitness::from(occurrence),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if prior.occurrence_fingerprint.as_ref()
            != Some(&claude_occurrence_map_fingerprint(&occurrences))
        {
            return Some(hashes);
        }
        let Some(prior_s) = prior.assigned.as_ref() else {
            return Some(hashes);
        };
        Some(hashes.difference(prior_s).cloned().collect())
    }

    /// Roots hit by actual native novelty. A hit is only a request for native
    /// comparison. It never changes duplicate ownership, coverage or posture.
    pub(crate) fn possible_targets(&self, item: &SnapshotItem) -> Option<BTreeSet<String>> {
        let novel = self.new_native_hashes(item)?;
        let mut roots = BTreeSet::new();
        for hash in novel {
            let digest = envelope_digest(&hash)?;
            let start = self
                .envelope_by_hash
                .partition_point(|entry| entry.digest < digest);
            for entry in self.envelope_by_hash[start..]
                .iter()
                .take_while(|entry| entry.digest == digest)
            {
                let root = &self.envelope_roots[entry.slot];
                if self.families.contains_key(root) {
                    roots.insert(root.clone());
                }
            }
        }
        Some(roots)
    }

    /// Count-only preparation receipt; not a bootstrap or reuse permit.
    #[cfg(test)]
    pub(crate) fn certified_member_count(&self) -> usize {
        self.families
            .values()
            .map(|family| {
                // Keep the frozen proof together with its exact certified keys.
                // Later target selection must use this proof, never the live map.
                family
                    .certified
                    .values()
                    .filter(|skip| family.members.contains(&skip.member))
                    .count()
            })
            .sum()
    }
}

impl TargetAcquisition {
    fn merge(&mut self, next: Self) {
        self.completed_target_files = self
            .completed_target_files
            .saturating_add(next.completed_target_files);
        self.acquired_roots.extend(next.acquired_roots);
        self.ready_for_fold_sources
            .extend(next.ready_for_fold_sources);
        self.unresolved_sources.extend(next.unresolved_sources);
        self.rearm_roots.extend(next.rearm_roots);
        self.known_rearm_candidates
            .extend(next.known_rearm_candidates);
        self.ready_for_fold_sources
            .retain(|source| !self.unresolved_sources.contains(source));
    }
}

// There is deliberately no runtime flag, API or environment opt-in.
pub(crate) fn enabled() -> bool {
    #[cfg(test)]
    {
        ENABLED.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

#[cfg(test)]
thread_local! { static ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

#[cfg(test)]
pub(crate) struct TestScope(bool);
#[cfg(test)]
pub(crate) fn enable_for_test() -> TestScope {
    TestScope(ENABLED.with(|enabled| enabled.replace(true)))
}
#[cfg(test)]
impl Drop for TestScope {
    fn drop(&mut self) {
        ENABLED.with(|enabled| enabled.set(self.0));
    }
}

crate::heap_layout_bound::fields!(NormalSkip; root, member, revision, census_window_end, upload_context, candidate);
crate::heap_layout_bound::fields!(NativePhase; disabled, retained_target_bytes, parsed_keys, native_corrections, correction_revoked_keys, correction_forbidden_roots, paused, prepared, skips, parsed_roots, target_revisions, attempted_targets);
crate::heap_layout_bound::fields!(FrozenFamily; proof, members, envelope, certified, prior_native, paired_roots);
crate::heap_layout_bound::fields!(FrozenNativePrior; revision, request_fingerprint, occurrence_fingerprint, assigned);
crate::heap_layout_bound::fields!(Controller; qualification, required_roots, native_frontier, awaiting_targets, failed, acquisition);
crate::heap_layout_bound::fields!(Qualification; families, envelope_roots, envelope_by_hash, pending, unknown_native_sources, revoked_roots, native_corrections, correction_revoked_keys, correction_forbidden_roots);
crate::heap_layout_bound::fields!(WindowEligibility; census_window_end, roots, revoked_roots, native_corrections, correction_revoked_keys, correction_forbidden_roots);
crate::heap_layout_bound::fields!(WindowRoot; proof, certified);

crate::heap_layout_bound::fields!(TargetSelection; queued, matched_roots, unresolved_sources);

crate::heap_layout_bound::fields!(PendingComparison; sources, required_revisions, candidates, available);
crate::heap_layout_bound::fields!(TargetAcquisition; completed_target_files, acquired_roots, ready_for_fold_sources, unresolved_sources, rearm_roots, known_rearm_candidates);

fn group_native_by_root(native: &[SnapshotItem]) -> BTreeMap<String, Vec<&SnapshotItem>> {
    let mut groups = BTreeMap::<String, Vec<&SnapshotItem>>::new();
    for item in native {
        groups
            .entry(claude_snapshot_family_root(item))
            .or_default()
            .push(item);
    }
    groups
}
