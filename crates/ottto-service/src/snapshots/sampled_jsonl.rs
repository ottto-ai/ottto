//! Native reduction adapter for the shared acquisition/cache mechanism. The
//! existing parser step and finish remain the only semantic implementation.
use super::*;
use crate::transcript_acquisition::{AuditDebt, Checkpoint, ReadMode, ReadPlan, Scope};
use crate::transcript_cache::Retained;

// Cache-only dependency witnesses. A native full reader keeps no extra map;
// excessive or nonstandard identifiers decline reuse without cloning them.
pub(super) const MAX_PRIORITY_WITNESSES: usize = 256;
pub(super) const MAX_PRIORITY_WITNESS_ID_BYTES: usize = 128;

/// Disclosed terminal loss can settle native output, but cannot verify source
/// history. Both acquisition certificates and ordinary full completion use
/// this same rule; settlement's intentionally broader predicate stays native.
pub(super) fn loss_free_source_report(
    report: &JsonlReadReport,
    recognized_usage_drop_count: usize,
    dropped_usage_record_count: u64,
) -> bool {
    report.complete() && recognized_usage_drop_count == 0 && dropped_usage_record_count == 0
}

#[derive(Clone)]
pub(crate) struct CachedJsonlReduction {
    accumulator: SnapshotAccumulator,
    report: JsonlReadReport,
    recognized_usage_drop_count: usize,
    positive_recognized_usage_count: usize,
    positive_usage_evidence: bool,
}
crate::heap_layout_bound::fields!(CachedJsonlReduction; accumulator, report,
    recognized_usage_drop_count, positive_recognized_usage_count, positive_usage_evidence);
impl crate::transcript_cache::FrozenCacheState for CachedJsonlReduction {
    fn supports_frozen_charge(&self) -> bool {
        // retain_reduction removes these live, shared inputs from the copy.
        // Refuse frozen accounting if an adapter ever forgets that boundary.
        self.accumulator.codex_turn_traces.is_none()
            && self.accumulator.codex_parent_ownership_ledgers.is_none()
    }
}

pub(super) struct CompletedNativeAcquisition {
    pub(super) checkpoint: Checkpoint,
    pub(super) reduction: Option<CachedJsonlReduction>,
}
crate::heap_layout_bound::fields!(CompletedNativeAcquisition; checkpoint, reduction);

impl OwnedJsonlParser {
    /// Invoked on a fresh safely-opened parser before any fill/read. Scope and
    /// durable debt must be supplied by the existing source/index authority.
    pub(super) fn prepare_acquisition(
        &mut self,
        old: Option<Retained<CachedJsonlReduction>>,
        scope: &Scope,
        debt: Option<AuditDebt>,
        now: u64,
    ) -> Result<ReadMode> {
        anyhow::ensure!(
            self.reader.reader.buffer().is_empty() && !self.reader.finished,
            "acquisition must begin before native parsing"
        );
        let old = old.filter(|old| {
            old.state.accumulator.source == self.source
                && (self.source != SnapshotSource::Codex
                    || old
                        .state
                        .accumulator
                        .codex_observed_priority_turns
                        .as_ref()
                        .is_some_and(|observed| {
                            observed.iter().all(|(turn, priority)| {
                                *priority
                                    == self
                                        .accumulator
                                        .codex_turn_traces
                                        .as_ref()
                                        .is_some_and(|traces| traces.is_priority_turn(turn))
                            })
                        }))
        });
        let plan = ReadPlan::prepare(
            self.reader.reader.get_mut(),
            old.as_ref().map(|old| &old.checkpoint),
            scope,
            debt,
            now,
        )?;
        let mode = plan.mode();
        if matches!(mode, ReadMode::Full(_)) && self.source == SnapshotSource::Codex {
            self.accumulator.codex_observed_priority_turns = Some(BTreeMap::new());
        }
        if !matches!(mode, ReadMode::Full(_)) {
            let CachedJsonlReduction {
                accumulator,
                report,
                recognized_usage_drop_count,
                positive_recognized_usage_count,
                positive_usage_evidence,
            } = old
                .expect("reusable acquisition requires native reduction")
                .state;
            // These are live native inputs, not immutable retained history.
            // Known prior trace decisions were compared above; fresh suffixes
            // use this cycle's traces. Projected EOF advances with appends.
            let mut accumulator = accumulator;
            accumulator.codex_turn_traces = self.accumulator.codex_turn_traces.take();
            accumulator.codex_parent_ownership_ledgers =
                self.accumulator.codex_parent_ownership_ledgers.take();
            accumulator.codex_sidecar_projected_next_ordinal =
                self.accumulator.codex_sidecar_projected_next_ordinal;
            self.accumulator = accumulator;
            self.reader.report = report;
            self.recognized_usage_drop_count = recognized_usage_drop_count;
            self.positive_recognized_usage_count = positive_recognized_usage_count;
            self.positive_usage_evidence = positive_usage_evidence;
            self.reader.finished = mode == ReadMode::Unchanged;
        }
        self.reader.acquisition = Some(plan);
        Ok(mode)
    }

    /// Returns the actual requested-layout charge of a native retained copy,
    /// before allocation. Caller must include cache, current/parked scan state
    /// and the finalization copy in the common process budget.
    pub(super) fn retention_bound(&mut self, limit: usize) -> Option<usize> {
        if !sampled_scan::compatible_reduction(&self.accumulator) {
            return None;
        }
        // These live dependencies are refreshed before every reuse and are not
        // retained in the copy. Their unchanged source-scan lifetime is baseline.
        let traces = self.accumulator.codex_turn_traces.take();
        let parents = self.accumulator.codex_parent_ownership_ledgers.take();
        let bound = (|| {
            let state = crate::heap_layout_bound::bound(&self.accumulator, limit)?;
            let checkpoint = crate::heap_layout_bound::bound(
                self.reader.acquisition.as_ref()?,
                limit.checked_sub(state)?,
            )?;
            let inline = std::mem::size_of::<CachedJsonlReduction>()
                .checked_sub(std::mem::size_of::<SnapshotAccumulator>())?;
            let total = state.checked_add(checkpoint)?.checked_add(inline)?;
            (total <= limit).then_some(total)
        })();
        self.accumulator.codex_turn_traces = traces;
        self.accumulator.codex_parent_ownership_ledgers = parents;
        bound
    }

    /// Take the acquisition certificate only after EOF. This does not authorize
    /// publication/index clearing: the host must also complete native finish,
    /// ownership/loss/source/dependency validation and its existing CAS boundary.
    pub(super) fn retain_reduction(
        &mut self,
        scope: &Scope,
        now: u64,
        remaining_copy_budget: usize,
    ) -> Result<Option<CompletedNativeAcquisition>> {
        if !self.reader.finished
            || self.reader.failure.is_some()
            || !loss_free_source_report(
                &self.reader.report,
                self.recognized_usage_drop_count,
                self.accumulator.dropped_usage_record_count,
            )
        {
            self.reader.acquisition = None;
            return Ok(None);
        }
        let admitted_copy = sampled_scan::compatible_reduction(&self.accumulator)
            && self
                .retention_bound(remaining_copy_budget.min(crate::transcript_cache::ENTRY_BYTES))
                .is_some();
        let Some(plan) = self.reader.acquisition.take() else {
            return Ok(None);
        };
        let checkpoint =
            plan.commit_after_native_completion(self.reader.reader.get_ref(), scope, now)?;
        // Native EOF may apply an unterminated valid JSON row. Its reduction is
        // not the reduction through the sealed byte pointer. Conservatively
        // decline retention; keep the existing full-parser EOF output unchanged.
        if checkpoint.sealed_offset() != self.reader.reader.get_ref().metadata()?.len()
            || !admitted_copy
        {
            return Ok(Some(CompletedNativeAcquisition {
                checkpoint,
                reduction: None,
            }));
        }
        let mut accumulator = self.accumulator.clone();
        // Extend no source-wide trace/ownership allocation's lifetime in RAM.
        // prepare_acquisition always installs this cycle's real dependencies.
        accumulator.codex_turn_traces = None;
        accumulator.codex_parent_ownership_ledgers = None;
        let reduction = CachedJsonlReduction {
            accumulator,
            report: self.reader.report,
            recognized_usage_drop_count: self.recognized_usage_drop_count,
            positive_recognized_usage_count: self.positive_recognized_usage_count,
            positive_usage_evidence: self.positive_usage_evidence,
        };
        let reduction = crate::heap_layout_bound::bound(
            &reduction,
            remaining_copy_budget.min(crate::transcript_cache::ENTRY_BYTES),
        )
        .map(|_| reduction);
        Ok(Some(CompletedNativeAcquisition {
            checkpoint,
            reduction,
        }))
    }
}
