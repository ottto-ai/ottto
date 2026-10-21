//! Native reduction adapter for the shared acquisition/cache mechanism. The
//! existing parser step and finish remain the only semantic implementation.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle::{record, Event};
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
    /// Native EOF applied bytes past the sealed offset (an unterminated final
    /// row), so the reduction is not the reduction through `checkpoint`. A
    /// cursor certificate does not compute it and reports `true` (fail-closed);
    /// its own bit is the job's `eof_applied` or `fragment`.
    pub(super) unsealed: bool,
}
crate::heap_layout_bound::fields!(CompletedNativeAcquisition; checkpoint, reduction, unsealed);

/// A side read's certificate (U1a-2a): no retained copy and no cache event.
#[cfg_attr(not(test), allow(dead_code))] // first production caller is the side exit
#[allow(clippy::large_enum_variant)] // Moved once to the side exit; never stored.
pub(super) enum SideCertificate {
    /// `len` is the held file's length when the certificate was committed.
    Certified {
        completed: CompletedNativeAcquisition,
        len: u64,
    },
    /// Data loss in the source report: the same bytes give the same loss.
    Lossy,
    /// No certificate for any other reason.
    Uncertified,
}

// Source-scan dependencies are refreshed on reuse and never retained in a
// checkpoint. Keep the same exclusion for active-copy and retained-copy charges.
pub(super) struct LiveReductionInputs {
    traces: Option<Arc<CodexTurnTraceMap>>,
    parents: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
}

impl OwnedJsonlParser {
    pub(super) fn take_live_reduction_inputs(&mut self) -> LiveReductionInputs {
        LiveReductionInputs {
            traces: self.accumulator.codex_turn_traces.take(),
            parents: self.accumulator.codex_parent_ownership_ledgers.take(),
        }
    }

    pub(super) fn restore_live_reduction_inputs(&mut self, inputs: LiveReductionInputs) {
        self.accumulator.codex_turn_traces = inputs.traces;
        self.accumulator.codex_parent_ownership_ledgers = inputs.parents;
    }

    /// Invoked on a fresh safely-opened parser before any fill/read. Scope and
    /// durable debt must be supplied by the existing source/index authority.
    pub(super) fn prepare_acquisition(
        &mut self,
        old: Option<Retained<CachedJsonlReduction>>,
        scope: &Scope,
        debt: Option<AuditDebt>,
        now: u64,
    ) -> Result<ReadMode> {
        // Checkpoints, samples and resume offsets are physical-file bytes. A
        // compressed stream has none, so it is never sampled or resumed.
        anyhow::ensure!(
            !self.reader.reader.is_compressed(),
            "compressed input has no physical acquisition offsets"
        );
        anyhow::ensure!(
            self.reader.reader.buffer().is_empty() && !self.reader.finished,
            "acquisition must begin before native parsing"
        );
        let old = old.filter(|old| {
            old.state.accumulator.source == self.source
                // Marker state covers the whole file only in the capture mode
                // it was built in: a non-capture prefix holds no markers, which
                // is not the same as a prefix without markers.
                && old.state.accumulator.claude_request_identity_capture
                    == self.accumulator.claude_request_identity_capture
                // A retained reduction continues only under the counting rule
                // this parse's own evidence selects. Both unset while inactive.
                && codex_counting_version::reusable(
                    old.state.accumulator.codex_counting.as_deref(),
                    self.accumulator.codex_counting.as_deref(),
                )
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
        let inputs = self.take_live_reduction_inputs();
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
        self.restore_live_reduction_inputs(inputs);
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
            record(Event::RetentionIncompleteOrLossy);
            return Ok(None);
        }
        let admitted_copy = if !sampled_scan::compatible_reduction(&self.accumulator) {
            record(Event::RetentionIncompatible);
            false
        } else if self
            .retention_bound(remaining_copy_budget.min(crate::transcript_cache::ENTRY_BYTES))
            .is_some()
        {
            true
        } else {
            record(Event::RetentionBoundRefused);
            false
        };
        let Some(plan) = self.reader.acquisition.take() else {
            record(Event::RetentionNoPlan);
            return Ok(None);
        };
        let checkpoint =
            plan.commit_after_native_completion(self.reader.reader.get_ref(), scope, now)?;
        // Native EOF may apply an unterminated valid JSON row. Its reduction is
        // not the reduction through the sealed byte pointer. Conservatively
        // decline retention; keep the existing full-parser EOF output unchanged.
        let unsealed = checkpoint.sealed_offset() != self.reader.reader.get_ref().metadata()?.len();
        if unsealed {
            record(Event::RetentionUnsealedEof);
        }
        if unsealed || !admitted_copy {
            return Ok(Some(CompletedNativeAcquisition {
                checkpoint,
                reduction: None,
                unsealed,
            }));
        }
        // Extend no source-wide trace/ownership allocation's lifetime in RAM.
        // prepare_acquisition always installs this cycle's real dependencies.
        let inputs = self.take_live_reduction_inputs();
        let accumulator = self.accumulator.clone();
        self.restore_live_reduction_inputs(inputs);
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
        record(if reduction.is_some() {
            Event::RetentionProduced
        } else {
            Event::RetentionCloneBoundRefused
        });
        Ok(Some(CompletedNativeAcquisition {
            checkpoint,
            reduction,
            unsealed,
        }))
    }

    /// A side read's certificate: `retain_reduction`'s completion gate and
    /// commit, without a retained copy or any `cache_lifecycle` event. It never
    /// touches main's cache; the caller mints the side seal from it.
    #[cfg_attr(not(test), allow(dead_code))] // first production caller is the side exit
    pub(super) fn certify_without_retention(
        &mut self,
        scope: &Scope,
        now: u64,
    ) -> Result<SideCertificate> {
        if !self.reader.finished || self.reader.failure.is_some() {
            self.reader.acquisition = None;
            return Ok(SideCertificate::Uncertified);
        }
        if !loss_free_source_report(
            &self.reader.report,
            self.recognized_usage_drop_count,
            self.accumulator.dropped_usage_record_count,
        ) {
            self.reader.acquisition = None;
            return Ok(SideCertificate::Lossy);
        }
        let Some(plan) = self.reader.acquisition.take() else {
            return Ok(SideCertificate::Uncertified);
        };
        let checkpoint =
            plan.commit_after_native_completion(self.reader.reader.get_ref(), scope, now)?;
        let len = self.reader.reader.get_ref().metadata()?.len();
        Ok(SideCertificate::Certified {
            completed: CompletedNativeAcquisition {
                unsealed: checkpoint.sealed_offset() != len,
                checkpoint,
                reduction: None,
            },
            len,
        })
    }

    /// Pair a cursor job's prefix certificate (`ReadPlan::commit_sealed_prefix`)
    /// with a copy of its reduction. The caller passes a zero budget unless
    /// every applied byte is inside the certified prefix `[0, s)`; the
    /// certificate alone then still publishes without retention.
    pub(super) fn retain_sealed_prefix(
        &mut self,
        checkpoint: Checkpoint,
        remaining_copy_budget: usize,
    ) -> CompletedNativeAcquisition {
        let budget = remaining_copy_budget.min(crate::transcript_cache::ENTRY_BYTES);
        // The job kept every turn witness (K1); a retained copy keeps the
        // cache-only caps that govern every other retained reduction.
        let witnesses_retainable = self
            .accumulator
            .codex_observed_priority_turns
            .as_ref()
            .map_or(true, |observed| {
                observed.len() <= MAX_PRIORITY_WITNESSES
                    && observed
                        .keys()
                        .all(|turn| turn.len() <= MAX_PRIORITY_WITNESS_ID_BYTES)
            });
        if budget == 0
            || !witnesses_retainable
            || !sampled_scan::compatible_reduction(&self.accumulator)
        {
            return CompletedNativeAcquisition {
                checkpoint,
                reduction: None,
                unsealed: true,
            };
        }
        // The certificate consumed the acquisition plan, so charge the
        // certificate itself where `retention_bound` charges the plan.
        let inputs = self.take_live_reduction_inputs();
        let admitted = (|| {
            let state = crate::heap_layout_bound::bound(&self.accumulator, budget)?;
            let certificate =
                crate::heap_layout_bound::bound(&checkpoint, budget.checked_sub(state)?)?;
            let inline = std::mem::size_of::<CachedJsonlReduction>()
                .checked_sub(std::mem::size_of::<SnapshotAccumulator>())?;
            let total = state.checked_add(certificate)?.checked_add(inline)?;
            (total <= budget).then_some(())
        })();
        let accumulator = admitted.map(|()| {
            let mut copy = self.accumulator.clone();
            copy.codex_priority_witnesses_uncapped = false;
            copy
        });
        self.restore_live_reduction_inputs(inputs);
        let Some(accumulator) = accumulator else {
            return CompletedNativeAcquisition {
                checkpoint,
                reduction: None,
                unsealed: true,
            };
        };
        let reduction = CachedJsonlReduction {
            accumulator,
            report: self.reader.report,
            recognized_usage_drop_count: self.recognized_usage_drop_count,
            positive_recognized_usage_count: self.positive_recognized_usage_count,
            positive_usage_evidence: self.positive_usage_evidence,
        };
        let reduction = crate::heap_layout_bound::bound(&reduction, budget).map(|_| reduction);
        CompletedNativeAcquisition {
            checkpoint,
            reduction,
            unsealed: true,
        }
    }
}
