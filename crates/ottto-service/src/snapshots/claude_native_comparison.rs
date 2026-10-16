//! Private, default-inactive native comparison preparation. Nothing here is
//! ownership, coverage, a settled body, or permission to suppress a rearm.
use super::*;
pub(crate) mod lifecycle;

pub(crate) fn actual_native_conjunction(disposition: &ClaudeUsageAuthorityDisposition) -> bool {
    let census = &disposition.duplicate_census;
    census.census_complete
        && census.coverage_complete
        && !census.census_invalid
        && !census.fence_after
        && census.pending_occurrence_count > 0
        && disposition.transcript_ownership_complete
}

pub(crate) struct PairedRows<'a> {
    pub(crate) api: &'a BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>>,
    pub(crate) trace:
        &'a BTreeMap<String, Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence>>,
    /// Only complete, same-opened-generation pairs from this preparation.
    pub(crate) healthy_roots: &'a BTreeSet<String>,
}

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

#[derive(Default)]
pub(crate) struct NativePhase {
    paused: bool,
    prepared: bool,
    // At most the candidates selected under the existing native page limit.
    skips: BTreeMap<String, NormalSkip>,
    target_revisions: BTreeMap<String, String>,
    attempted_targets: BTreeSet<String>,
}

impl NativePhase {
    pub(super) fn record_actual_skip(
        &mut self,
        index: &ScanIndex,
        candidate: &CandidateFile,
        census_window_end: &str,
    ) {
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
        if self.prepared {
            return false;
        }
        self.paused = true;
        true
    }

    pub(super) fn ready(&self) -> bool {
        self.paused && !self.prepared
    }
    pub(super) fn resume(&mut self) {
        self.prepared = true;
        self.paused = false;
        // Qualification now owns its selected path certificates. Do not keep
        // a second copy of their path/stat graph in the moving scan phase.
        self.skips.clear();
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

    pub(super) fn target_revision_matches(&self, candidate: &CandidateFile) -> Option<bool> {
        self.target_revisions
            .get(&local_index_key(&candidate.path))
            .map(|expected| expected == &candidate.source_file_fingerprint)
    }

    pub(super) fn qualify(
        &self,
        index: &ScanIndex,
        native: &[SnapshotItem],
        census_window_end: &str,
        rows: PairedRows<'_>,
    ) -> Qualification {
        assert!(self.ready(), "preflight must precede native finalization");
        let native_by_root = group_native_by_root(native);
        let mut selected_roots = self
            .skips
            .values()
            .map(|skip| skip.root.clone())
            .chain(native_by_root.keys().cloned())
            .collect::<BTreeSet<_>>();
        selected_roots.retain(|root| {
            rows.healthy_roots.contains(root)
                && index.claude_usage_family_witnesses.contains_key(root)
                && !index.claude_usage_authority_quarantine.contains_key(root)
        });
        if selected_roots.is_empty() {
            return Qualification::default();
        }
        let indexed_members = complete_claude_usage_family_members(index);
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
        let mut families = BTreeMap::new();
        for (root, retained) in &index.claude_usage_family_witnesses {
            // Freeze/reconstruct P from retained state. Never substitute a new
            // proof or mutate the index while deciding negative eligibility.
            if !selected_roots.contains(root)
                || !rows.healthy_roots.contains(root)
                || index.claude_usage_authority_quarantine.contains_key(root)
                || !indexed_members.get(root).is_some_and(|members| {
                    members
                        .iter()
                        .eq(retained.member_request_id_fingerprints.keys())
                })
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
            let Some(ledger) = reconstruct_claude_usage_ledger_from_rows(
                root,
                retained,
                api,
                trace,
                owners.as_ref(),
            ) else {
                continue;
            };
            let family = ProvenClaudeUsageFamily {
                witness: retained.clone(),
                rows_by_member: ledger.rows_by_member,
            };
            // Current members that would fail the exact authoritative rebuild
            // make this family ineligible. Shared checks include native set and
            // occurrence fingerprints, selectors, totals, clocks and overflow.
            if current_native.iter().any(|item| {
                let Some((rows, excluded)) = claude_reported_usage_inputs(item, &family) else {
                    return true;
                };
                prepare_claude_reported_usage(item, rows, &excluded, None).is_none()
            }) {
                continue;
            }
            let certified = self
                .skips
                .iter()
                .filter(|(key, skip)| {
                    skip.root == *root
                        && skip.census_window_end == census_window_end
                        && index.files.get(*key).is_some_and(|entry| {
                            entry.source_file_fingerprint == skip.revision
                                && skip.upload_context == index.active_upload_context_fingerprint
                        })
                        && retained
                            .member_request_id_fingerprints
                            .contains_key(&skip.member)
                })
                .map(|(key, skip)| (key.clone(), skip.clone()))
                .collect::<BTreeMap<_, _>>();
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
            let prior_native_revisions = current_native
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
                        .map(|revision| (item.source_session_id.clone(), revision.clone()))
                })
                .collect::<BTreeMap<_, _>>();
            if !certified.is_empty() || !prior_native_revisions.is_empty() {
                families.insert(
                    root.clone(),
                    FrozenFamily {
                        witness: family.witness,
                        assigned: ledger.assigned_request_id_hashes,
                        certified,
                        prior_native_revisions,
                    },
                );
            }
            // family.rows_by_member is dropped here; no retained API row graph.
        }
        Qualification::from_frozen_families(families)
    }
}

struct FrozenFamily {
    witness: ClaudeUsageFamilyWitness,
    assigned: BTreeMap<String, BTreeSet<String>>,
    certified: BTreeMap<String, NormalSkip>,
    prior_native_revisions: BTreeMap<String, String>,
}

#[derive(Default)]
pub(crate) struct Qualification {
    families: BTreeMap<String, FrozenFamily>,
    envelope_roots: Vec<String>,
    envelope_by_hash: BTreeMap<String, Vec<usize>>,
    pending: BTreeMap<String, PendingComparison>,
    unknown_native_sources: BTreeSet<String>,
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
    fn from_frozen_families(mut families: BTreeMap<String, FrozenFamily>) -> Self {
        let mut envelope_roots = Vec::new();
        let mut envelope_by_hash = BTreeMap::<String, Vec<usize>>::new();
        for (root, family) in &mut families {
            if family.certified.is_empty() {
                continue;
            }
            let slot = envelope_roots.len();
            envelope_roots.push(root.clone());
            let mut record_root = |hash: String| {
                let slots = envelope_by_hash
                    .entry(hash)
                    .or_insert_with(|| Vec::with_capacity(1));
                // Roots are visited monotonically. Usually one slot; avoid a
                // tree allocation per hash while deduplicating assigned + E.
                if slots.last() != Some(&slot) {
                    slots.push(slot);
                }
            };
            for skip in family.certified.values() {
                // A certified member is not a current native prior. Move its
                // hashes, avoiding a duplicate retained S graph per family.
                if let Some(assigned) = family.assigned.remove(&skip.member) {
                    for hash in assigned {
                        record_root(hash);
                    }
                }
                if let Some(excluded) = family
                    .witness
                    .legacy_excluded_request_id_hashes
                    .get(&skip.member)
                {
                    for hash in excluded {
                        record_root(hash.clone());
                    }
                }
            }
        }
        Self {
            families,
            envelope_roots,
            envelope_by_hash,
            ..Default::default()
        }
    }

    pub(super) fn take_target_candidates(
        &mut self,
        native: &[SnapshotItem],
        remaining_files: usize,
    ) -> (Vec<CandidateFile>, TargetSelection) {
        let native_by_root = group_native_by_root(native);
        let mut sources_by_root = BTreeMap::<String, BTreeSet<String>>::new();
        let mut result = TargetSelection::default();
        for item in native {
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
        let mut candidates = Vec::new();
        for (root, sources) in sources_by_root {
            // A possible hit withdraws S before any native attempt. It never
            // becomes an exact owner or renews the frozen prior-P shortcut.
            let Some(family) = self.families.remove(&root) else {
                continue;
            };
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
                .witness
                .member_request_id_fingerprints
                .keys()
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
        let prior = family.prior_native_revisions.get(member);
        if prior.is_none()
            || prior != item.source_file_fingerprint.as_ref()
            || family
                .witness
                .legacy_excluded_request_id_hashes
                .get(member)
                .is_some_and(|excluded| !excluded.is_empty())
            || family.witness.member_request_id_fingerprints.get(member)
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
        if family.witness.member_occurrence_fingerprints.get(member)
            != Some(&claude_occurrence_map_fingerprint(&occurrences))
        {
            return Some(hashes);
        }
        let Some(prior_s) = family.assigned.get(member) else {
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
            if let Some(slots) = self.envelope_by_hash.get(&hash) {
                for &slot in slots {
                    let root = &self.envelope_roots[slot];
                    if self.families.contains_key(root) {
                        roots.insert(root.clone());
                    }
                }
            }
        }
        Some(roots)
    }

    /// Count-only preparation receipt; not a bootstrap or reuse permit.
    pub(crate) fn certified_member_count(&self) -> usize {
        self.families
            .values()
            .map(|family| {
                // Keep the frozen proof together with its exact certified keys.
                // Later target selection must use this proof, never the live map.
                family
                    .certified
                    .values()
                    .filter(|skip| {
                        family
                            .witness
                            .member_request_id_fingerprints
                            .contains_key(&skip.member)
                    })
                    .count()
            })
            .sum()
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
crate::heap_layout_bound::fields!(NativePhase; paused, prepared, skips, target_revisions, attempted_targets);
crate::heap_layout_bound::fields!(FrozenFamily; witness, assigned, certified, prior_native_revisions);
crate::heap_layout_bound::fields!(Qualification; families, envelope_roots, envelope_by_hash, pending, unknown_native_sources);

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
