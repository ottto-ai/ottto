//! Private, default-inactive native comparison preparation. Nothing here is
//! ownership, coverage, a settled body, or permission to suppress a rearm.
use super::*;
pub(crate) mod lifecycle;
mod settlement;
use settlement::NativeCorrection;
pub(crate) use settlement::{Completion, SelectedFallback};

/// Borrow the same process lease at the final rearm decision, rather than
/// turning its earlier allowed() result into a durable permission bit.
pub(crate) struct NegativeView<'a> {
    window: &'a WindowEligibility,
    lease: &'a lifecycle::Lease,
}
impl Completion {
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
        if !self.lease.allowed() {
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

/// A single moving owner for the actual completed native traversal. It never
/// enters SourceScanResult (which is Clone), a disk record, or a proof/permit.
/// The future selected-state fallback must validate context before restoring it.
/// Until that callback exists, finish simply drops this unused owner.
pub(crate) struct TerminalTraversal {
    traversal: ScanTraversalCheckpoint,
}
impl TerminalTraversal {
    pub(super) fn take(
        index: &mut ScanIndex,
        source: SnapshotSource,
        comparison_active: bool,
        census_complete: bool,
        census_window_end: &str,
    ) -> Option<Box<Self>> {
        if source != SnapshotSource::ClaudeCode
            || !comparison_active
            || !census_complete
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

/// Eligibility descriptors only. No Clone, rows, assigned request sets or
/// envelope graph survive the page. A later page must reconstruct P again.
#[derive(Debug)]
pub(crate) struct WindowEligibility {
    census_window_end: String,
    roots: BTreeMap<String, WindowRoot>,
    revoked_roots: BTreeSet<String>,
    native_corrections: BTreeMap<String, NativeCorrection>,
    correction_revoked_keys: BTreeSet<String>,
    correction_forbidden_roots: BTreeSet<String>,
}
#[derive(Debug)]
struct WindowRoot {
    proof: String,
    certified: BTreeMap<String, NormalSkip>,
}
impl WindowEligibility {
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
    pub(crate) fn retain_current(&mut self, index: &ScanIndex) {
        let members = complete_claude_usage_family_members(index);
        self.roots.retain(|root, saved| {
            let current = !self.revoked_roots.contains(root)
                && Self::root_is_current(root, saved, index)
                && index
                    .claude_usage_family_witnesses
                    .get(root)
                    .is_some_and(|witness| {
                        members.get(root).is_some_and(|actual| {
                            actual
                                .iter()
                                .eq(witness.member_request_id_fingerprints.keys())
                        })
                    });
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
    parsed_keys: BTreeSet<String>,
    native_corrections: BTreeMap<String, NativeCorrection>,
    correction_revoked_keys: BTreeSet<String>,
    correction_forbidden_roots: BTreeSet<String>,
    paused: bool,
    prepared: bool,
    // Actual page Skips plus moved same-window descriptors. Retention uses the
    // shared rotation budget; positive target reads still obey the page limit.
    skips: BTreeMap<String, NormalSkip>,
    // Eligibility is revoked by the actual parse attempt, including a parse
    // that later fails or produces no body. Body lists cannot recover this.
    parsed_roots: BTreeSet<String>,
    target_revisions: BTreeMap<String, String>,
    attempted_targets: BTreeSet<String>,
}

impl NativePhase {
    pub(super) fn import_window(
        &mut self,
        previous: Option<Box<WindowEligibility>>,
        index: &ScanIndex,
        census_window_end: &str,
    ) -> bool {
        let Some(mut previous) = previous else {
            return true;
        };
        if previous.census_window_end != census_window_end {
            return false;
        }
        previous.retain_current(index);
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
        let key = local_index_key(&candidate.path);
        self.parsed_keys.insert(key.clone());
        if self.native_corrections.remove(&key).is_some() {
            self.correction_revoked_keys.insert(key);
        }
        if let Some((root, _)) = claude_index_path_family_member(&candidate.path) {
            self.skips.retain(|_, skip| skip.root != root);
            self.parsed_roots.insert(root);
        }
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
        if self.disabled || self.prepared {
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

    pub(super) fn disable(&mut self) {
        *self = Self {
            disabled: true,
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

    pub(super) fn target_revision_matches(&self, candidate: &CandidateFile) -> Option<bool> {
        self.target_revisions
            .get(&local_index_key(&candidate.path))
            .map(|expected| expected == &candidate.source_file_fingerprint)
    }

    pub(super) fn qualify(
        &mut self,
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
        let candidate_roots = selected_roots.clone();
        selected_roots.retain(|root| {
            rows.healthy_roots.contains(root)
                && index.claude_usage_family_witnesses.contains_key(root)
                && !index.claude_usage_authority_quarantine.contains_key(root)
        });
        if selected_roots.is_empty() {
            return Qualification {
                revoked_roots: self.parsed_roots.union(&candidate_roots).cloned().collect(),
                ..Default::default()
            };
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
                        && !self.parsed_roots.contains(root)
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
                let paired_roots = std::iter::once(root.clone())
                    // The shared reconstruction above verified these exact
                    // predecessor roots against the excluded-request owners.
                    .chain(retained.legacy_owner_roots.iter().cloned())
                    .collect();
                families.insert(
                    root.clone(),
                    FrozenFamily {
                        witness: family.witness,
                        assigned: ledger.assigned_request_id_hashes,
                        certified,
                        prior_native_revisions,
                        paired_roots,
                    },
                );
            }
            // family.rows_by_member is dropped here; no retained API row graph.
        }
        let mut qualification = Qualification::from_frozen_families(families);
        qualification.correction_revoked_keys = std::mem::take(&mut self.correction_revoked_keys);
        qualification.correction_forbidden_roots =
            std::mem::take(&mut self.correction_forbidden_roots);
        qualification.native_corrections = std::mem::take(&mut self.native_corrections);
        qualification.native_corrections.retain(|key, receipt| {
            rows.healthy_roots.contains(receipt.root())
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
    witness: ClaudeUsageFamilyWitness,
    assigned: BTreeMap<String, BTreeSet<String>>,
    certified: BTreeMap<String, NormalSkip>,
    prior_native_revisions: BTreeMap<String, String>,
    paired_roots: BTreeSet<String>,
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
    pub(crate) fn advance(&mut self, scan: &mut OwnedSourceScan, current: bool) -> bool {
        if self.failed
            || !current
            || !scan.native_comparison_is_healthy()
            || self.native_frontier > scan.snapshots.len()
        {
            self.failed = true;
            scan.disable_native_comparison();
            return false;
        }
        if self.awaiting_targets {
            let acquired = scan.take_native_comparison_acquisition(&mut self.qualification);
            self.awaiting_targets = false;
            let unresolved = !acquired.unresolved_sources.is_empty();
            self.acquisition.merge(acquired);
            if unresolved {
                self.failed = true;
                scan.disable_native_comparison();
                return false;
            }
        }
        scan.resume_native_comparison_base();
        let next_frontier = scan.snapshots.len();
        let selection = scan
            .acquire_native_comparison_targets_after(&mut self.qualification, self.native_frontier);
        self.native_frontier = next_frontier;
        self.awaiting_targets = selection.queued > 0;
        if !selection.unresolved_sources.is_empty() {
            self.failed = true;
            self.acquisition
                .unresolved_sources
                .extend(selection.unresolved_sources);
            scan.disable_native_comparison();
            return false;
        }
        true
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
    envelope_by_hash: BTreeMap<String, Vec<usize>>,
    pending: BTreeMap<String, PendingComparison>,
    unknown_native_sources: BTreeSet<String>,
    revoked_roots: BTreeSet<String>,
    native_corrections: BTreeMap<String, NativeCorrection>,
    correction_revoked_keys: BTreeSet<String>,
    correction_forbidden_roots: BTreeSet<String>,
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
    fn into_window(self, census_window_end: &str) -> Option<Box<WindowEligibility>> {
        let mut roots = BTreeMap::new();
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
                    proof: claude_usage_family_witness_fingerprint(&family.witness),
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
crate::heap_layout_bound::fields!(NativePhase; disabled, parsed_keys, native_corrections, correction_revoked_keys, correction_forbidden_roots, paused, prepared, skips, parsed_roots, target_revisions, attempted_targets);
crate::heap_layout_bound::fields!(FrozenFamily; witness, assigned, certified, prior_native_revisions, paired_roots);
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
