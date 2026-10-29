// Emergency containment. Admission never reads sidecar content and never
// interprets a withheld cohort as empty. Paging is deliberately a separate fix.
const CLAUDE_TERMINAL_MAX_ROOTS: usize = 64;
const CLAUDE_TERMINAL_MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const CLAUDE_TERMINAL_MAX_EST_DECODED_BYTES: u64 = 512 * 1024 * 1024;
const CLAUDE_SCOPED_REARM_MAX_FILES: usize = 32;
const CLAUDE_SCOPED_REARM_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// An armed clear must survive evidence processing until ordinary traversal
/// selection owns its reparse. The bit is scheduling only, never authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ClaudeScopedRearmDebt {
    fingerprint: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    armed: bool,
}
impl From<String> for ClaudeScopedRearmDebt {
    fn from(fingerprint: String) -> Self {
        Self {
            fingerprint,
            armed: false,
        }
    }
}
crate::heap_layout_bound::fields!(ClaudeScopedRearmDebt; fingerprint, armed);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ClaudeTerminalFoldDeferred {
    pub roots: usize,
    pub est_bytes: u64,
    pub sidecar_bytes: u64,
    /// Root refusal skips all stats; byte fields are unknown (u64::MAX).
    pub stat_skipped: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ClaudeScopedRearmCounts {
    pub families: usize,
    pub files: usize,
    pub bytes: u64,
    pub deferred: usize,
}

crate::heap_layout_bound::fields!(ClaudeTerminalFoldDeferred; roots, est_bytes, sidecar_bytes, stat_skipped);
crate::heap_layout_bound::fields!(ClaudeScopedRearmCounts; families, files, bytes, deferred);

fn claude_terminal_cohort(index: &ScanIndex, snapshots: &[SnapshotItem]) -> BTreeSet<String> {
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

    pub(crate) fn claude_scoped_rearm_counts(&self) -> ClaudeScopedRearmCounts {
        self.claude_full_rearm_progress.rearm_scoped
    }

    pub(crate) fn ensure_claude_evidence_offer(&mut self) {
        if !self.claude_full_rearm_progress.rearm_offer_started {
            self.begin_claude_evidence_offer();
        }
    }

    pub(crate) fn begin_claude_evidence_offer(&mut self) {
        self.claude_full_rearm_progress.rearm_offer_started = true;
        self.claude_full_rearm_progress.rearm_scoped = Default::default();
        self.claude_full_rearm_progress.scoped_rearm_cleared.clear();
        self.claude_full_rearm_progress
            .rearm_scoped_families
            .clear();
    }

    pub(crate) fn preflight_claude_terminal_fold(
        &mut self,
        support: Option<&Path>,
        snapshots: &[SnapshotItem],
    ) {
        self.claude_full_rearm_progress.terminal_fold_checked = support.is_some();
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
            crate::local_resource_diagnostics::traversal_point(
                "terminal_fold_deferred",
                "claude_code",
                &counts,
            );
            eprintln!("ALARM terminal_fold_deferred roots={} est_bytes={} sidecar_bytes={}: terminal offer incomplete; all witnesses retained", counts.roots, counts.est_bytes, counts.sidecar_bytes);
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

    /// Re-derive deferred need from the exact source revision which incurred
    /// the correction. Changed/already-cleared/removed files retire only this
    /// scheduling debt, never account/usage/ACK evidence. No cursor or grant.
    fn drain_claude_scoped_rearms(&mut self) -> ClaudeScopedRearmCounts {
        if self.claude_terminal_fold_deferred().is_some() {
            return self.claude_full_rearm_progress.rearm_scoped;
        }
        let progress = &mut self.claude_full_rearm_progress;

        let mut files = progress.rearm_scoped.files;
        let mut bytes = progress.rearm_scoped.bytes;
        progress.scoped_rearm_pending.retain(|key, debt| {
            let Some(entry) = self.files.get_mut(key) else {
                return false;
            };
            let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
                return false;
            };
            if debt.armed {
                return true; // Awaiting a one-time transfer to ordinary selection.
            }
            if entry.source_file_fingerprint.is_empty() {
                debt.armed = true;
                return true;
            }
            if entry.source_file_fingerprint != debt.fingerprint {
                return false;
            }
            if files >= CLAUDE_SCOPED_REARM_MAX_FILES
                || entry.size_bytes > CLAUDE_SCOPED_REARM_MAX_BYTES.saturating_sub(bytes)
            {
                return true;
            }
            files += 1;
            bytes = bytes.saturating_add(entry.size_bytes);
            progress
                .rearm_scoped_families
                .insert(member.root.to_owned());
            progress
                .scoped_rearm_cleared
                .insert(key.clone(), debt.fingerprint.clone());
            entry.source_file_fingerprint.clear();
            debt.armed = true;
            true
        });
        // All entry points in one offer share the same count/byte allowance.
        progress.rearm_scoped.families = progress.rearm_scoped_families.len();
        progress.rearm_scoped.files = files;
        progress.rearm_scoped.bytes = bytes;
        progress.rearm_scoped.deferred = progress
            .scoped_rearm_pending
            .values()
            .filter(|debt| !debt.armed)
            .count();
        progress.rearm_scoped
    }
}
