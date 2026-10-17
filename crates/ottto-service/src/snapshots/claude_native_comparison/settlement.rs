//! Ephemeral comparison deferral at the existing selected-index save seams.
//! No refusal, account row, persisted hold or alternate ACK ledger is created.
use super::*;

pub(crate) struct Completion {
    pub(crate) window: Option<Box<WindowEligibility>>,
    pub(crate) fallback: Option<SelectedFallback>,
    native_plans: BTreeMap<String, NativePlan>,
    pending_corrections: Vec<PendingNativeCorrection>,
}

pub(super) struct NativePlan {
    root: String,
    proof: String,
    revision: String,
}
pub(super) struct NativeCorrection {
    root: String,
    proof: String,
    revision: String,
    fingerprint: String,
    body_witness: String,
    selected_fingerprint: String,
    selected_body_witness: String,
}
impl std::fmt::Debug for NativeCorrection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DurableNativeCorrection")
    }
}
struct PendingNativeCorrection {
    key: String,
    plan: NativePlan,
    fingerprint: String,
    body_witness: String,
}

impl NativeCorrection {
    pub(super) fn root(&self) -> &str {
        &self.root
    }
    pub(super) fn current(&self, key: &str, index: &ScanIndex) -> bool {
        !index
            .claude_usage_authority_quarantine
            .contains_key(&self.root)
            && !index.claude_account_deferred_holds.contains_key(key)
            && index
                .claude_usage_family_witnesses
                .get(&self.root)
                .is_some_and(|witness| {
                    claude_usage_family_witness_fingerprint(witness) == self.proof
                })
            && index.files.get(key).is_some_and(|entry| {
                entry.source_file_fingerprint == self.revision
                    && entry.scan_identity_version.as_deref()
                        == Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
                    && entry.last_snapshot_fingerprint.as_ref() == Some(&self.selected_fingerprint)
                    && entry.last_upload_body_witness.as_ref() == Some(&self.selected_body_witness)
            })
            && index
                .file_snapshot_fingerprints
                .get(key)
                .is_some_and(|fps| fps.len() == 1 && fps.contains(&self.fingerprint))
            && index
                .accepted_snapshot_fingerprints
                .contains(&self.fingerprint)
            && !index
                .quarantined_snapshot_fingerprints
                .contains_key(&self.fingerprint)
            && !index.confirmed_empty_files.contains(key)
            && !index.terminal_jsonl_dispositions.contains_key(key)
    }
}

impl Completion {
    #[cfg(test)]
    pub(crate) fn native_correction_count_for_test(&self) -> usize {
        self.window
            .as_ref()
            .map_or(0, |window| window.native_corrections.len())
    }
    /// Capture from the actual native result before the finalizer removes
    /// semantic no-ops. This is a candidate, never an ACK/Skip/coverage fact.
    pub(crate) fn capture_native_corrections(
        &mut self,
        scan: &mut SourceScanResult,
        previous: &ScanIndex,
        disposition: &ClaudeUsageAuthorityDisposition,
        body_witness: impl Fn(&SnapshotItem) -> String,
    ) {
        self.pending_corrections.clear();
        let Some(window) = self.window.as_ref() else {
            return;
        };
        for item in &mut scan.snapshots {
            let Some(plan) = self.native_plans.get(&item.source_session_id) else {
                continue;
            };
            if item.usage_accounting_contract.as_deref()
                != Some("session_exclusive_reported_usage:v1")
                || disposition
                    .quarantined_source_session_ids
                    .contains(&item.source_session_id)
                || window.correction_forbidden_roots.contains(&plan.root)
            {
                continue;
            }
            let Some(pending) = scan.pending_finalization.iter().find(|pending| {
                pending.parse_complete
                    && pending.parsed_snapshot_count == 1
                    && !pending.sampled_audit_verified
                    && pending.source_file_fingerprint == plan.revision
                    && item.source_file_fingerprint.as_ref() == Some(&plan.revision)
                    && claude_index_path_family_member(Path::new(&pending.index_key)).is_some_and(
                        |(root, member)| root == plan.root && member == item.source_session_id,
                    )
                    && previous
                        .files
                        .get(&pending.index_key)
                        .is_some_and(|entry| entry.source_file_fingerprint.is_empty())
            }) else {
                continue;
            };
            if window.correction_revoked_keys.contains(&pending.index_key) {
                continue;
            }
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
            self.pending_corrections.push(PendingNativeCorrection {
                key: pending.index_key.clone(),
                plan: NativePlan {
                    root: plan.root.clone(),
                    proof: plan.proof.clone(),
                    revision: plan.revision.clone(),
                },
                fingerprint: item.snapshot_fingerprint.clone(),
                body_witness: body_witness(item),
            });
        }
    }

    /// Called only after the actual normal selected save succeeds. Partial,
    /// shed, error and pending-ACK paths never call this minting seam.
    pub(crate) fn note_native_corrections_after_save(
        &mut self,
        index: &ScanIndex,
        previous: &ScanIndex,
        // None is refused/unknown; false permits ONLY the bound accepted no-op.
        acknowledged: impl Fn(&str, &str) -> Option<bool>,
    ) {
        let Some(window) = self.window.as_mut() else {
            return;
        };
        for candidate in self.pending_corrections.drain(..) {
            let Some(exact_ack) = acknowledged(&candidate.fingerprint, &candidate.body_witness)
            else {
                continue;
            };
            if window
                .correction_forbidden_roots
                .contains(&candidate.plan.root)
                || window.correction_revoked_keys.contains(&candidate.key)
            {
                continue;
            }
            let Some(entry) = index.files.get(&candidate.key) else {
                continue;
            };
            let Some(selected_fingerprint) = entry.last_snapshot_fingerprint.clone() else {
                continue;
            };
            let Some(selected_body_witness) = entry.last_upload_body_witness.clone() else {
                continue;
            };
            let exact_noop = !previous
                .quarantined_snapshot_fingerprints
                .contains_key(&candidate.fingerprint)
                && previous
                    .accepted_snapshot_fingerprints
                    .contains(&candidate.fingerprint)
                && previous
                    .file_snapshot_fingerprints
                    .get(&candidate.key)
                    .is_some_and(|fps| fps.len() == 1 && fps.contains(&candidate.fingerprint))
                && previous.files.get(&candidate.key).is_some_and(|old| {
                    old.last_snapshot_fingerprint.as_ref() == Some(&selected_fingerprint)
                        && old.last_upload_body_witness.as_ref() == Some(&selected_body_witness)
                });
            if !exact_ack && !exact_noop {
                continue;
            }
            let receipt = NativeCorrection {
                root: candidate.plan.root,
                proof: candidate.plan.proof,
                revision: candidate.plan.revision,
                fingerprint: candidate.fingerprint,
                body_witness: candidate.body_witness,
                selected_fingerprint,
                selected_body_witness,
            };
            if receipt.current(&candidate.key, index) {
                window.native_corrections.insert(candidate.key, receipt);
            }
        }
        self.native_plans.clear();
    }
}

pub(crate) struct SelectedFallback {
    withheld_sources: BTreeSet<String>,
    withheld_keys: BTreeSet<String>,
    targets: Vec<CandidateFile>,
    census_window_end: String,
    terminal: Option<Box<TerminalTraversal>>,
}

impl Controller {
    /// Consume pending plans even when a target could not be queued. Disabling
    /// the optimization must not discard the dependency that caused fallback.
    pub(crate) fn complete(
        mut self,
        scan: &SourceScanResult,
        terminal: Option<Box<TerminalTraversal>>,
        current: bool,
    ) -> Result<Completion, &'static str> {
        if !current || self.failed || self.awaiting_targets {
            for (_, plan) in std::mem::take(&mut self.qualification.pending) {
                self.acquisition.unresolved_sources.extend(plan.sources);
                self.acquisition
                    .known_rearm_candidates
                    .extend(plan.candidates);
            }
        }
        let mut withheld_keys = BTreeSet::new();
        let mut resolved_sources = BTreeSet::new();
        for pending in &scan.pending_finalization {
            if let Some((_, member)) =
                claude_index_path_family_member(Path::new(&pending.index_key))
            {
                if self.acquisition.unresolved_sources.contains(&member) {
                    withheld_keys.insert(pending.index_key.clone());
                    resolved_sources.insert(member);
                }
            }
        }
        // A missing key cannot be represented by a fake hold or successful
        // checkpoint. Refuse before constructing or offering any new body.
        if !self
            .acquisition
            .unresolved_sources
            .is_subset(&resolved_sources)
        {
            return Err("native comparison fallback lacks an exact source key");
        }
        if !withheld_keys.is_empty() {
            return Ok(Completion {
                window: None,
                native_plans: BTreeMap::new(),
                pending_corrections: Vec::new(),
                fallback: Some(SelectedFallback {
                    withheld_sources: self.acquisition.unresolved_sources,
                    withheld_keys,
                    targets: self.acquisition.known_rearm_candidates,
                    census_window_end: scan.census_window_end.clone(),
                    terminal,
                }),
            });
        }
        let native_plans = self
            .qualification
            .families
            .iter()
            .flat_map(|(root, family)| {
                family
                    .prior_native_revisions
                    .iter()
                    .map(|(member, revision)| {
                        (
                            member.clone(),
                            NativePlan {
                                root: root.clone(),
                                proof: claude_usage_family_witness_fingerprint(&family.witness),
                                revision: revision.clone(),
                            },
                        )
                    })
            })
            .collect();
        Ok(Completion {
            native_plans,
            pending_corrections: Vec::new(),
            window: if current {
                self.into_window(&scan.census_window_end)
            } else {
                None
            },
            fallback: None,
        })
    }
}

impl SelectedFallback {
    /// Called only after raw native observations have been recorded. A
    /// deferred file cannot be finalized as an empty or semantic-no-op file.
    pub(crate) fn withhold(&self, scan: &mut SourceScanResult) {
        eprintln!("local snapshot comparison deferred: reason=native_comparison_unavailable sources={} target_files={}; prior accepted bodies unchanged", self.withheld_sources.len(), self.targets.len());
        scan.snapshots
            .retain(|item| !self.withheld_sources.contains(&item.source_session_id));
    }

    pub(crate) fn after_native_fold(&self, scan: &mut SourceScanResult, index: &mut ScanIndex) {
        scan.pending_finalization
            .retain(|pending| !self.withheld_keys.contains(&pending.index_key));
        scan.census_complete = false;
        index.mark_bounded_sweep_unsettled();
    }

    /// Restore only selected B/C facts. Queue known A first and B/C after A in
    /// the SAME traversal. A terminal traversal is moved, never reconstructed
    /// from a scratch index or duplicated into SourceScanResult::clone.
    pub(crate) fn restore_selected(
        &mut self,
        index: &mut ScanIndex,
        previous: &ScanIndex,
    ) -> Result<(), &'static str> {
        let empty_advances = index.claude_empty_map_advances(previous);
        let mut affected_fingerprints = BTreeSet::new();
        for key in &self.withheld_keys {
            if let Some(entry) = index.files.get(key) {
                affected_fingerprints.extend(entry.last_snapshot_fingerprint.iter().cloned());
            }
            affected_fingerprints.extend(
                index
                    .file_snapshot_fingerprints
                    .remove(key)
                    .unwrap_or_default(),
            );
            match previous.files.get(key) {
                Some(entry) => {
                    index.files.insert(key.clone(), entry.clone());
                }
                None => {
                    index.files.remove(key);
                }
            }
            if let Some(fps) = previous.file_snapshot_fingerprints.get(key) {
                index
                    .file_snapshot_fingerprints
                    .insert(key.clone(), fps.clone());
                for fp in fps {
                    if let Some(activity) = previous.snapshot_activity_at.get(fp) {
                        index
                            .snapshot_activity_at
                            .insert(fp.clone(), activity.clone());
                    }
                    if previous.accepted_snapshot_fingerprints.contains(fp) {
                        index.accepted_snapshot_fingerprints.insert(fp.clone());
                    }
                }
            }
            if let Some(fp) = previous
                .files
                .get(key)
                .and_then(|entry| entry.last_snapshot_fingerprint.as_ref())
            {
                if let Some(activity) = previous.snapshot_activity_at.get(fp) {
                    index
                        .snapshot_activity_at
                        .insert(fp.clone(), activity.clone());
                }
                if previous.accepted_snapshot_fingerprints.contains(fp) {
                    index.accepted_snapshot_fingerprints.insert(fp.clone());
                }
            }
            if previous.confirmed_empty_files.contains(key) {
                index.confirmed_empty_files.insert(key.clone());
            } else {
                index.confirmed_empty_files.remove(key);
            }
            match previous.terminal_jsonl_dispositions.get(key) {
                Some(value) => {
                    index
                        .terminal_jsonl_dispositions
                        .insert(key.clone(), value.clone());
                }
                None => {
                    index.terminal_jsonl_dispositions.remove(key);
                }
            }
            if let Some((_, member)) = claude_index_path_family_member(Path::new(key)) {
                match previous.claude_owned_start_census.get(&member) {
                    Some(value) => {
                        index
                            .claude_owned_start_census
                            .insert(member, value.clone());
                    }
                    None => {
                        index.claude_owned_start_census.remove(&member);
                    }
                }
            }
        }
        index.restore_claude_empty_map_advances(empty_advances);
        let current = index.current_snapshot_fingerprints();
        for fp in affected_fingerprints {
            if !current.contains(&fp) {
                index.accepted_snapshot_fingerprints.remove(&fp);
                index.snapshot_activity_at.remove(&fp);
            }
        }
        if index.traversal.is_none() {
            index.traversal = self.terminal.take().map(|terminal| terminal.traversal);
        }
        let traversal = index
            .traversal
            .as_mut()
            .ok_or("native comparison lost its traversal")?;
        if traversal.census_window_end != self.census_window_end
            || traversal.context_fingerprint.is_empty()
        {
            return Err("native comparison traversal context changed");
        }
        // Only paths already observed in this frozen window may be requeued.
        // A missing path remains debt; a later native read decides disappearance.
        let mut priority = VecDeque::new();
        let mut keys = BTreeSet::new();
        for path in self
            .targets
            .iter()
            .map(|target| target.path.as_path())
            .chain(self.withheld_keys.iter().map(Path::new))
        {
            let key = local_index_key(path);
            if !keys.insert(key.clone()) {
                continue;
            }
            if !traversal.observed_index_keys.contains(&key) {
                return Err("native comparison recovery path was not observed in this window");
            }
            let root = traversal
                .scan_roots
                .iter()
                .filter(|root| path.starts_with(root))
                .max_by_key(|root| root.components().count())
                .ok_or("native comparison recovery path left its roots")?;
            priority.push_back(ScanTraversalPath {
                scan_root: root.clone(),
                path: path.to_path_buf(),
                census_member: true,
                watcher_hint: false,
            });
        }
        traversal
            .pending_candidates
            .retain(|candidate| !keys.contains(&local_index_key(&candidate.path)));
        priority.append(&mut traversal.pending_candidates);
        traversal.pending_candidates = priority;
        for target in &self.targets {
            if let Some(entry) = index.files.get_mut(&local_index_key(&target.path)) {
                entry.source_file_fingerprint.clear();
            }
        }
        index.mark_bounded_sweep_unsettled();
        Ok(())
    }
}

crate::heap_layout_bound::fields!(Completion; window, fallback, native_plans, pending_corrections);
crate::heap_layout_bound::fields!(NativePlan; root, proof, revision);
crate::heap_layout_bound::fields!(NativeCorrection; root, proof, revision, fingerprint, body_witness, selected_fingerprint, selected_body_witness);
crate::heap_layout_bound::fields!(PendingNativeCorrection; key, plan, fingerprint, body_witness);
crate::heap_layout_bound::fields!(SelectedFallback; withheld_sources, withheld_keys, targets, census_window_end, terminal);
