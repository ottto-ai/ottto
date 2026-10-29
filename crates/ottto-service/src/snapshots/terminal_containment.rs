// Emergency containment. Admission never reads sidecar content and never
// interprets a withheld cohort as empty. Paging is deliberately a separate fix.
const CLAUDE_TERMINAL_MAX_ROOTS: usize = 64;
pub(crate) const CLAUDE_TERMINAL_MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const CLAUDE_TERMINAL_MAX_EST_DECODED_BYTES: u64 = 512 * 1024 * 1024;
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ClaudeTerminalFoldDeferred {
    pub cause: &'static str,
    pub roots: usize,
    pub est_bytes: u64,
    pub sidecar_bytes: u64,
    /// Root refusal skips all stats; byte fields are unknown (u64::MAX).
    pub stat_skipped: bool,
}

crate::heap_layout_bound::fields!(ClaudeTerminalFoldDeferred; cause, roots, est_bytes, sidecar_bytes, stat_skipped);

pub(crate) fn claude_terminal_cohort(index: &ScanIndex, snapshots: &[SnapshotItem]) -> BTreeSet<String> {
    let mut roots = claude_pending_family_session_ids(index)
        .into_iter()
        .collect::<BTreeSet<_>>();
    for item in snapshots {
        // Include both consumer cohorts: API attachment's session/parent/root
        // and usage's root (including the subagent naming fallback).
        roots.insert(item.source_session_id.clone());
        for fact in &item.attribution_facts {
            if matches!(
                fact.field.as_str(),
                "parent_session_ref" | "root_session_ref"
            ) {
                roots.insert(fact.value.clone());
            }
        }
        if let Some((root, _)) = item.source_session_id.split_once("_agent-") {
            roots.insert(root.to_owned());
        }
    }
    roots
}

fn claude_terminal_budget(roots: usize, sidecar_bytes: u64) -> Option<ClaudeTerminalFoldDeferred> {
    // Conservative estimate, not a decoded heap certificate: 32x input for
    // owned strings/rows/joins plus 8 KiB per root for empty read witnesses.
    // Both this estimate and the input have independent admission ceilings.
    let est_bytes = sidecar_bytes
        .saturating_mul(32)
        .saturating_add((roots as u64).saturating_mul(8192));
    (roots > CLAUDE_TERMINAL_MAX_ROOTS
        || sidecar_bytes > CLAUDE_TERMINAL_MAX_INPUT_BYTES
        || est_bytes > CLAUDE_TERMINAL_MAX_EST_DECODED_BYTES)
        .then_some(ClaudeTerminalFoldDeferred {
            cause: "preflight",
            roots,
            est_bytes,
            sidecar_bytes,
            stat_skipped: false,
        })
}

impl ScanIndex {
    pub(crate) fn claude_terminal_fold_deferred(&self) -> Option<ClaudeTerminalFoldDeferred> {
        self.claude_full_rearm_progress.terminal_fold_deferred
    }

    pub(crate) fn claude_terminal_fold_checked(&self) -> bool {
        self.claude_full_rearm_progress.terminal_fold_checked
    }

    pub(crate) fn preflight_claude_terminal_fold(
        &mut self,
        support: Option<&Path>,
        snapshots: &[SnapshotItem],
    ) {
        self.claude_full_rearm_progress.terminal_fold_checked = support.is_some();
        if support.is_none() {
            // Standalone native scans have no terminal sidecar consumer.
            self.claude_full_rearm_progress.terminal_fold_deferred = None;
            return;
        }
        let roots = claude_terminal_cohort(self, snapshots);
        // Root admission is independent: never stat thousands of sidecars
        // when cardinality alone already refuses the whole offer.
        let bytes = if roots.len() > CLAUDE_TERMINAL_MAX_ROOTS {
            u64::MAX // Unknown, not zero or a measured byte estimate.
        } else {
            roots.iter()
            .try_fold(0_u64, |bytes, root| {
                let size = match support {
                    Some(support) => {
                        crate::claude_local_otel::claude_terminal_sidecar_bytes(support, root)?
                    }
                    None => 0, // No sidecar consumer in scanner-only callers.
                };
                bytes.checked_add(size)
            })
            .unwrap_or(u64::MAX) // Unknown stat/overflow fails closed, never absent.
        };
        let deferred = claude_terminal_budget(roots.len(), bytes).map(|mut counts| {
            counts.stat_skipped = roots.len() > CLAUDE_TERMINAL_MAX_ROOTS;
            counts
        });
        self.claude_full_rearm_progress.terminal_fold_deferred = deferred;
        if let Some(counts) = deferred {
            self.claude_full_rearm_progress.terminal_effects = None;
            self.claude_full_rearm_progress.complete_rebuild_read = None;
            crate::local_resource_diagnostics::traversal_point(
                "terminal_fold_deferred",
                "claude_code",
                &counts,
            );
            eprintln!("ALARM terminal_fold_deferred cause=preflight roots={} est_bytes={} sidecar_bytes={}: terminal offer incomplete; all witnesses retained", counts.roots, counts.est_bytes, counts.sidecar_bytes);
        }
    }

    pub(crate) fn note_claude_terminal_fold_offer(&mut self, deferred: bool) {
        // Process-local diagnostic only: reload/downgrade adds no state field.
        #[cfg(not(test))]
        static PASSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        #[cfg(test)]
        thread_local! {
            static PASSES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        }
        #[cfg(not(test))]
        let passes = {
            use std::sync::atomic::Ordering;
            PASSES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(if deferred { value.saturating_add(1) } else { 0 })
            }).unwrap_or_else(|value| value)
                .saturating_add(u64::from(deferred))
        };
        #[cfg(test)]
        let passes = PASSES.with(|counter| {
            let passes = if deferred { counter.get().saturating_add(1) } else { 0 };
            counter.set(passes);
            passes
        });
        if deferred {
            crate::local_resource_diagnostics::traversal_point(
                "terminal_fold_deferred_consecutive",
                "claude_code",
                &serde_json::json!({"passes": passes}),
            );
            if passes >= 3 {
                eprintln!("ALARM terminal_fold_deferred_consecutive passes={passes}: ordinary uploads continue; terminal census remains parked pending paged fold");
            }
        }
    }

}

/// Process-local transaction plan. No witness/index map is cloned for rollback,
/// and no plan is serialized: the existing traversal is the parked checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaudeTerminalEffects {
    removals: Vec<(String, bool)>,
    reconcile: bool,
    raw_complete: bool,
    effective_complete: bool,
    needs_clean_followup: bool,
    restart_after_hints: bool,
    cursor_scope: String,
}
crate::heap_layout_bound::fields!(ClaudeTerminalEffects; removals, reconcile, raw_complete, effective_complete, needs_clean_followup, restart_after_hints, cursor_scope);

impl ScanIndex {
    pub(crate) fn claude_terminal_effects_staged(&self) -> bool {
        self.claude_full_rearm_progress.terminal_effects.is_some()
    }

    pub(crate) fn defer_claude_terminal_read(&mut self, snapshots: &[SnapshotItem]) {
        let roots = claude_terminal_cohort(self, snapshots).len();
        let counts = ClaudeTerminalFoldDeferred {
            cause: "read_allowance",
            roots,
            est_bytes: u64::MAX,
            sidecar_bytes: u64::MAX,
            stat_skipped: false,
        };
        self.claude_full_rearm_progress.terminal_effects = None;
        self.claude_full_rearm_progress.complete_rebuild_read = None;
        self.claude_full_rearm_progress.terminal_fold_deferred = Some(counts);
        crate::local_resource_diagnostics::traversal_point("terminal_fold_deferred", "claude_code", &counts);
        eprintln!("ALARM terminal_fold_deferred cause=read_allowance roots={roots}: bounded terminal read refused; ordinary page continues with parked traversal");
    }

    /// Called only after ALL terminal API/trace reads (including fallbacks)
    /// have finished within one shared reader allowance. Consumers thereafter
    /// use the frozen owned readset, so no late reread can follow this commit.
    pub(crate) fn commit_claude_terminal_effects(
        &mut self,
        scan: &mut SourceScanResult,
        comparison_active: bool,
    ) -> Option<Box<claude_native_comparison::TerminalTraversal>> {
        let effects = self.claude_full_rearm_progress.terminal_effects.take()?;
        // A caller may have lowered the provisional effective flag after scan
        // (for example a capacity/settlement gate). Raw commit cannot undo it.
        let completion_veto = effects.effective_complete && !scan.census_complete;
        for (key, vanished) in &effects.removals {
            if let Some(traversal) = self.traversal.as_mut() {
                traversal.observed_index_keys.remove(key);
            }
            if !(*vanished && self.retire_vanished_claude_audit_debt_entry(key)) {
                self.remove_file_entry_unless_held(key, *vanished);
            }
        }
        let reconciled = effects.reconcile && reconcile_missing_index_entries_bounded(self, None);
        self.prune_terminal_jsonl_dispositions();
        let raw_complete = effects.raw_complete && reconciled;
        if !raw_complete && !effects.restart_after_hints {
            scan.census_complete = false;
            scan.scan_cap_hit = true;
            return None;
        }
        let traversal = self.traversal.as_ref()?.clone();
        if raw_complete {
            if let Err(refusal) = self.retire_positively_absent_claude_families(&traversal, &effects.cursor_scope) {
                eprintln!("local snapshot census kept RetryPending families: absence retirement refused ({})", refusal.as_str());
            }
            self.drain_claude_retired_family_tombstone_fence(&traversal);
            scan.census_complete = !completion_veto && !effects.needs_clean_followup
                && self.claude_usage_authority_pending_count() == 0
                && self.decode_holds.is_empty();
            if scan.census_complete {
                scan.claude_request_census_shadow = Some(
                    claude_request_census::settle_claude_request_census_terminal(
                        self, &traversal.observed_index_keys, &traversal.residue.index_keys,
                        &scan.census_window_end,
                    ));
                self.accepted_rebuild_incidence.retain(|key, _| {
                    key.is_empty() || traversal.observed_index_keys.contains(key)
                        || traversal.residue.index_keys.contains(key) || self.files.contains_key(key)
                });
                self.accepted_incidence_pending_census = !self.accepted_rebuild_incidence.is_empty();
            }
            self.record_scan_residue_witness(SnapshotSource::ClaudeCode, &traversal);
            if let Some(witness) = self.scan_residue_witness.as_ref() {
                scan.census_residue_index_key_count = witness.index_keys.len();
                scan.census_residue_archived_rollout_count = witness.archived_residue_file_count();
                scan.census_residue_blocked_session_count = witness.codex_state_only_blocked_session_ids.len();
            }
            scan.zero_snapshot_confirmed_count = self.confirmed_empty_files.len();
            self.retain_observed_claude_account_deferred_holds(&traversal.observed_index_keys);
        }
        scan.scan_cap_hit |= !scan.census_complete;
        traversal_transition::retiring(
            SnapshotSource::ClaudeCode, self.generation, &traversal, raw_complete,
            self.unsettled_cause_bits(),
            Some((with_claude_absence_counters(|counts| *counts), self.claude_retired_family_tombstones_uncertain)),
            CensusGates {
                discovery_done: true, traversal_healthy: true,
                frozen_generation: !traversal.watcher_hint_seen,
                state_complete: scan.state_census_complete,
                sidecar_complete: scan.sidecar_census_complete,
                reconciliation_complete: reconciled, parent_restart: false,
                clean_followup: effects.needs_clean_followup,
                census_complete: scan.census_complete,
            },
        );
        let terminal = claude_native_comparison::TerminalTraversal::take(
            self, SnapshotSource::ClaudeCode, comparison_active, raw_complete, &scan.census_window_end,
        );
        self.traversal = None;
        self.resume_after_path = None;
        self.resume_upper_bound_path = None;
        self.resume_census_window_end = None;
        terminal
    }
}

impl ScanIndex {
    fn retain_deferred_page_retries(&self, previous: &ScanIndex, safe_keys: &BTreeSet<String>, selected: &mut ScanIndex) {
        if self.claude_terminal_fold_deferred().is_none() { return; }
        let Some(traversal) = selected.traversal.as_mut() else { return; };
        for (key, working) in &self.files {
            if safe_keys.contains(key) || self.decode_holds_file(key) { continue; }
            if previous.files.get(key).is_some_and(|old| {
                old.source_file_fingerprint == working.source_file_fingerprint
                    && old.last_snapshot_fingerprint == working.last_snapshot_fingerprint
                    && old.last_upload_body_witness == working.last_upload_body_witness
            }) { continue; }
            enqueue_parked_claude_retry(traversal, key);

        }
    }
}

fn enqueue_parked_claude_retry(traversal: &mut ScanTraversalCheckpoint, key: &str) {
    let path = Path::new(key);
    if path.extension().and_then(|extension| extension.to_str()) != Some("jsonl") { return; }
    let Some(root) = traversal.scan_roots.iter().filter(|root| path.starts_with(root))
        .max_by_key(|root| root.components().count()) else { return; };
    if !traversal.pending_candidates.iter().any(|candidate| candidate.path == path) {
        // Existing queue demand only. The scanner still revalidates the file;
        // no fingerprint clear, replay/ownership grant or durable field.
        traversal.pending_candidates.push_back(ScanTraversalPath {
            scan_root: root.clone(), path: path.to_path_buf(), census_member: true, watcher_hint: false,
        });
    }
}

impl ScanIndex {
    fn retain_deferred_local_hold_retries(&mut self, held_keys: &BTreeSet<String>) {
        if self.claude_terminal_fold_deferred().is_none() { return; }
        let Some(traversal) = self.traversal.as_mut() else { return; };
        for key in held_keys { enqueue_parked_claude_retry(traversal, key); }
    }
}
