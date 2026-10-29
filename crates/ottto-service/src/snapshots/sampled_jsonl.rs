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
crate::durable_tail_codec::durable_struct!(CachedJsonlReduction {
    D accumulator: SnapshotAccumulator,
    D report: JsonlReadReport,
    N recognized_usage_drop_count: usize,
    N positive_recognized_usage_count: usize,
    N positive_usage_evidence: bool,
});

/// M1 durable warm-cache reuse: the record body and its re-derivation.
#[cfg(unix)]
pub(super) mod durable;
impl CachedJsonlReduction {
    /// The copy's usage witness (`SnapshotAccumulator::usage_witness`), kept
    /// beside a taken copy for P1-RETAIN R0's Q-PR15 guard.
    pub(super) fn usage_witness(&self) -> u64 {
        self.accumulator.usage_witness()
    }
    /// The copy's source (M1: a durable record is written per source).
    #[cfg(unix)]
    pub(super) fn source(&self) -> SnapshotSource {
        self.accumulator.source
    }
}
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
    /// `Some(rank)`: this completion's deferred release ran (P1-RETAIN R0)
    /// against `rank`, the copy's re-admission rank, so the copy is admitted
    /// at exactly that rank and its finalization copy is limited by its
    /// peak-reserved `budget_after`, not the pre-release budget
    /// (`sampled_scan::RetainBudget::released_budget`).
    pub(super) released: Option<(i64, i64)>,
    /// Native EOF applied bytes past the sealed offset (an unterminated final
    /// row), so the reduction is not the reduction through `checkpoint`. A
    /// cursor certificate does not compute it and reports `true` (fail-closed);
    /// its own bit is the job's `eof_applied` or `fragment`.
    pub(super) unsealed: bool,
}
crate::heap_layout_bound::fields!(CompletedNativeAcquisition; checkpoint, reduction, released, unsealed);

/// A side read's certificate (U1a-2a): no retained copy and no cache event.
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
    pub(super) fn restore_archive_reduction(
        &mut self,
        old: Retained<CachedJsonlReduction>,
    ) -> Result<()> {
        anyhow::ensure!(
            self.reader.reader.is_compressed()
                && old.checkpoint.is_compressed()
                && old.state.accumulator.source == self.source,
            "archive retained source mismatch"
        );
        anyhow::ensure!(
            old.state
                .accumulator
                .codex_observed_priority_turns
                .as_ref()
                .is_some_and(|observed| observed.iter().all(|(turn, priority)| *priority
                    == self
                        .accumulator
                        .codex_turn_traces
                        .as_ref()
                        .is_some_and(|traces| traces.is_priority_turn(turn)))),
            "archive priority dependencies changed"
        );
        anyhow::ensure!(
            codex_counting_version::reusable(
                old.state.accumulator.codex_counting.as_deref(),
                self.accumulator.codex_counting.as_deref()
            ),
            "archive counting dependencies changed"
        );
        let inputs = self.take_live_reduction_inputs();
        let CachedJsonlReduction {
            accumulator,
            report,
            recognized_usage_drop_count,
            positive_recognized_usage_count,
            positive_usage_evidence,
        } = old.state;
        self.accumulator = accumulator;
        self.restore_live_reduction_inputs(inputs);
        self.reader.report = report;
        self.recognized_usage_drop_count = recognized_usage_drop_count;
        self.positive_recognized_usage_count = positive_recognized_usage_count;
        self.positive_usage_evidence = positive_usage_evidence;
        self.archive_checkpoint = Some(old.checkpoint);
        self.reader.finished = true;
        Ok(())
    }

    /// The source mtime this read's checkpoint will carry
    /// (`ReadPlan::modified_hint`); `None` without a plan.
    pub(super) fn planned_modified_hint(&self) -> Option<(i64, i64)> {
        self.reader
            .acquisition
            .as_ref()
            .map(crate::transcript_acquisition::ReadPlan::modified_hint)
    }
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
        refuse_compressed_codex(
            None,
            Some(&self.reader.reader),
            CodexZstCause::PhysicalOffsetUnsupported,
        )?;
        anyhow::ensure!(
            !self.reader.reader.is_compressed(),
            "compressed input has no physical acquisition offsets"
        );
        anyhow::ensure!(
            self.reader.reader.buffer().is_empty() && !self.reader.finished,
            "acquisition must begin before native parsing"
        );
        let old = old.filter(|old| {
            // Capture is a function of the source (contract 5 always on,
            // `claude_request_identity::captures`), so the same source keeps
            // the capture mode its markers were built in.
            !old.checkpoint.is_compressed()
                && old.state.accumulator.source == self.source
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
            accumulator
                .claude_file_birth
                .refresh_opened(&self.accumulator.claude_file_birth);
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
            let checkpoint = if let Some(archive) = self.archive_checkpoint.as_ref() {
                crate::heap_layout_bound::bound(archive, limit.checked_sub(state)?)?
            } else {
                crate::heap_layout_bound::bound(
                    self.reader.acquisition.as_ref()?,
                    limit.checked_sub(state)?,
                )?
            };
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
        budget: sampled_scan::RetainBudget,
    ) -> Result<Option<CompletedNativeAcquisition>> {
        #[cfg(test)]
        sampled_scan::test_hooks::record_budget(&budget);
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
        if let sampled_scan::RetainBudget::Deferred {
            budget_after,
            release,
            ..
        } = budget
        {
            return self.retain_after_release(scope, now, budget_after, release);
        }
        let remaining_copy_budget = budget.admission_budget();
        let admitted_copy = if !sampled_scan::compatible_reduction(&self.accumulator) {
            record(Event::RetentionIncompatible);
            false
        } else if matches!(
            budget,
            sampled_scan::RetainBudget::TierOrJoinExcluded { .. }
                | sampled_scan::RetainBudget::Unsealed { .. }
        ) {
            // Never retained, and not a budget refusal (packet).
            false
        } else if self
            .retention_bound(remaining_copy_budget.min(crate::transcript_cache::ENTRY_BYTES))
            .is_some()
        {
            true
        } else {
            record(Event::RetentionBoundRefused);
            #[cfg(test)]
            {
                let charge = self.retention_bound(usize::MAX);
                sampled_scan::test_hooks::record_bucket(classify_refusal(
                    RefusalView::of(&budget),
                    Refusal::Admission { charge },
                ));
            }
            false
        };
        if let Some(checkpoint) = self.archive_checkpoint.take() {
            anyhow::ensure!(
                checkpoint.stamp_matches(self.reader.reader.get_ref())?
                    && checkpoint.scope() == scope,
                "archive changed before retention"
            );
            let reduction = admitted_copy.then(|| self.reduction_copy()).filter(|r| {
                crate::heap_layout_bound::bound(
                    r,
                    remaining_copy_budget.min(crate::transcript_cache::ENTRY_BYTES),
                )
                .is_some()
            });
            return Ok(Some(CompletedNativeAcquisition {
                checkpoint,
                reduction,
                released: None,
                unsealed: false,
            }));
        }
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
                released: None,
                unsealed,
            }));
        }
        let limit = remaining_copy_budget.min(crate::transcript_cache::ENTRY_BYTES);
        let reduction = self.reduction_copy();
        let charge = crate::heap_layout_bound::bound(&reduction, limit);
        #[cfg(test)]
        if charge.is_none() {
            sampled_scan::test_hooks::record_bucket(classify_refusal(
                RefusalView::of(&budget),
                Refusal::Clone {
                    charge: crate::heap_layout_bound::bound(&reduction, usize::MAX),
                },
            ));
        }
        let reduction = charge.map(|_| reduction);
        record(if reduction.is_some() {
            Event::RetentionProduced
        } else {
            Event::RetentionCloneBoundRefused
        });
        Ok(Some(CompletedNativeAcquisition {
            checkpoint,
            reduction,
            released: None,
            unsealed,
        }))
    }

    /// The copy a retained reduction holds: the accumulator without this
    /// cycle's live, shared inputs, plus the report scalars.
    fn reduction_copy(&mut self) -> CachedJsonlReduction {
        // Extend no source-wide trace/ownership allocation's lifetime in RAM.
        // prepare_acquisition always installs this cycle's real dependencies.
        let inputs = self.take_live_reduction_inputs();
        let accumulator = self.accumulator.clone();
        self.restore_live_reduction_inputs(inputs);
        CachedJsonlReduction {
            accumulator,
            report: self.reader.report,
            recognized_usage_drop_count: self.recognized_usage_drop_count,
            positive_recognized_usage_count: self.positive_recognized_usage_count,
            positive_usage_evidence: self.positive_usage_evidence,
        }
    }

    /// Offline durable-record controls need a real reduction even when this
    /// platform cannot admit a retained RAM copy.
    #[cfg(test)]
    pub(super) fn durable_test_reduction_copy(&mut self) -> CachedJsonlReduction {
        self.reduction_copy()
    }

    /// The charge of a copy beside its committed `checkpoint` (state,
    /// certificate and inline bytes), if it fits `limit`.
    fn certified_charge(&mut self, checkpoint: &Checkpoint, limit: usize) -> Option<usize> {
        let inputs = self.take_live_reduction_inputs();
        let charge = (|| {
            let state = crate::heap_layout_bound::bound(&self.accumulator, limit)?;
            let certificate =
                crate::heap_layout_bound::bound(checkpoint, limit.checked_sub(state)?)?;
            let inline = std::mem::size_of::<CachedJsonlReduction>()
                .checked_sub(std::mem::size_of::<SnapshotAccumulator>())?;
            let total = state.checked_add(certificate)?.checked_add(inline)?;
            (total <= limit).then_some(total)
        })();
        self.restore_live_reduction_inputs(inputs);
        charge
    }

    /// P1-RETAIN R0, shape F with a feasible release: every non-budget gate
    /// first, then the commit, the checkpoint-charged admission at
    /// `budget_after` (within the insert's entry limit), the stamp gate, and
    /// only then the release. Any refusal before `execute` evicts nothing.
    fn retain_after_release(
        &mut self,
        scope: &Scope,
        now: u64,
        budget_after: usize,
        release: sampled_scan::DeferredRelease,
    ) -> Result<Option<CompletedNativeAcquisition>> {
        let compatible = sampled_scan::compatible_reduction(&self.accumulator);
        if !compatible {
            record(Event::RetentionIncompatible);
        }
        let Some(plan) = self.reader.acquisition.take() else {
            record(Event::RetentionNoPlan);
            return Ok(None);
        };
        let checkpoint =
            plan.commit_after_native_completion(self.reader.reader.get_ref(), scope, now)?;
        let unsealed = checkpoint.sealed_offset() != self.reader.reader.get_ref().metadata()?.len();
        if unsealed {
            record(Event::RetentionUnsealedEof);
        }
        let declined = |checkpoint: Checkpoint| -> Result<Option<CompletedNativeAcquisition>> {
            Ok(Some(CompletedNativeAcquisition {
                checkpoint,
                reduction: None,
                released: None,
                unsealed,
            }))
        };
        if unsealed || !compatible {
            return declined(checkpoint);
        }
        let limit = budget_after.min(release.entry_limit);
        if self.certified_charge(&checkpoint, limit).is_none() {
            record(Event::RetentionBoundRefused);
            #[cfg(test)]
            {
                let charge = self.certified_charge(&checkpoint, usize::MAX);
                sampled_scan::test_hooks::record_bucket(classify_refusal(
                    RefusalView::deferred(budget_after, release.entry_limit),
                    Refusal::Admission { charge },
                ));
            }
            return declined(checkpoint);
        }
        #[cfg(test)]
        sampled_scan::test_hooks::fire(sampled_scan::test_hooks::Point::BeforeStampGate);
        // The sealed checkpoint is not the current source: an unterminated
        // final row, or the source changed after the commit; or it is not the
        // mtime the release was ranked from. Conservatively decline retention.
        if !checkpoint.stamp_matches(self.reader.reader.get_ref())?
            || checkpoint.modified_hint() != release.modified
        {
            record(Event::RetentionUnsealedEof);
            return declined(checkpoint);
        }
        #[cfg(test)]
        let entry_limit = release.entry_limit;
        let rank = release.rank;
        let outcome = release.execute();
        if outcome != sampled_scan::ReleaseOutcome::Released {
            record(Event::RetentionBoundRefused);
            #[cfg(test)]
            sampled_scan::test_hooks::record_bucket(classify_refusal(
                RefusalView::deferred(budget_after, entry_limit),
                Refusal::Release(outcome),
            ));
            return declined(checkpoint);
        }
        let reduction = self.reduction_copy();
        let charge = crate::heap_layout_bound::bound(&reduction, limit);
        #[cfg(test)]
        if charge.is_none() {
            sampled_scan::test_hooks::record_bucket(classify_refusal(
                RefusalView::deferred(budget_after, entry_limit),
                Refusal::Clone {
                    charge: crate::heap_layout_bound::bound(&reduction, usize::MAX),
                },
            ));
        }
        // Proven empty after a release (the clone charges at most its
        // source); kept as the guard against a future layout impl.
        let reduction = charge.map(|_| reduction);
        record(if reduction.is_some() {
            Event::RetentionProduced
        } else {
            Event::RetentionCloneBoundRefused
        });
        Ok(Some(CompletedNativeAcquisition {
            checkpoint,
            reduction,
            released: Some(rank),
            unsealed,
        }))
    }

    /// A side read's certificate: `retain_reduction`'s completion gate and
    /// commit, without a retained copy or any `cache_lifecycle` event. It never
    /// touches main's cache; the caller mints the side seal from it.
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
                released: None,
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
        budget: sampled_scan::RetainBudget,
    ) -> CompletedNativeAcquisition {
        #[cfg(test)]
        sampled_scan::test_hooks::record_budget(&budget);
        // Never `Deferred` here: no deferred release runs on a sealed prefix,
        // so every caller strips it first (`RetainBudget::without_release`).
        debug_assert!(
            !matches!(budget, sampled_scan::RetainBudget::Deferred { .. }),
            "never Deferred after without_release"
        );
        let remaining_copy_budget = budget.without_release().admission_budget();
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
                released: None,
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
                released: None,
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
            released: None,
            unsealed: true,
        }
    }
}

/// The packet's refusal buckets: disjoint, and together every refused
/// singleton retention (`RetentionBoundRefused` or `RetentionCloneBoundRefused`).
/// No production counter reads them; C2 may adopt them.
#[cfg(test)] // C2's buckets; tests only for now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Bucket {
    /// Both walks measured, and no room.
    BudgetZero,
    /// A walk did not measure (layout, visit limit, overflow, lock).
    Walk,
    /// The charge exceeds the budget.
    OverBudget,
    /// The charge fits the budget but not the entry limit.
    OverEntry,
}

/// The budget a refused pass was admitted against.
#[cfg(test)] // C2's buckets; tests only for now.
#[derive(Clone, Copy)]
pub(super) struct RefusalView {
    granted: bool,
    resident_measured: bool,
    active_measured: bool,
    /// `budget` for `Granted`, `budget_after` for `Deferred`.
    budget: usize,
    /// `ENTRY_BYTES` for `Granted`, the release's `entry_limit` for
    /// `Deferred`.
    entry_limit: usize,
}
#[cfg(test)] // C2's buckets; tests only for now.
impl RefusalView {
    pub(super) fn of(budget: &sampled_scan::RetainBudget) -> Self {
        match budget {
            sampled_scan::RetainBudget::Granted {
                budget,
                resident_measured,
                active_measured,
            } => Self {
                granted: true,
                resident_measured: *resident_measured,
                active_measured: *active_measured,
                budget: *budget,
                entry_limit: crate::transcript_cache::ENTRY_BYTES,
            },
            sampled_scan::RetainBudget::Deferred {
                budget_after,
                release,
                ..
            } => Self::deferred(*budget_after, release.entry_limit),
            // Never classified (packet §2.1); a zero budget files as such.
            sampled_scan::RetainBudget::TierOrJoinExcluded { .. }
            | sampled_scan::RetainBudget::Unsealed { .. } => Self {
                granted: true,
                resident_measured: true,
                active_measured: true,
                budget: 0,
                entry_limit: crate::transcript_cache::ENTRY_BYTES,
            },
        }
    }
    pub(super) fn deferred(budget_after: usize, entry_limit: usize) -> Self {
        Self {
            granted: false,
            resident_measured: true,
            active_measured: true,
            budget: budget_after,
            entry_limit,
        }
    }
}

/// What refused the pass.
#[cfg(test)] // C2's buckets; tests only for now.
#[derive(Clone, Copy)]
pub(super) enum Refusal {
    /// The admission check refused; `charge` is one walk at `usize::MAX`,
    /// charged as the refusing check did.
    Admission { charge: Option<usize> },
    /// A deferred release did not run.
    Release(sampled_scan::ReleaseOutcome),
    /// The clone's bound refused; `charge` walks the refused clone.
    Clone { charge: Option<usize> },
}

/// One bucket per refused pass (packet §2.2). Pure.
#[cfg(test)] // C2's buckets; tests only for now.
pub(super) fn classify_refusal(view: RefusalView, refusal: Refusal) -> Bucket {
    let by_charge = |charge: Option<usize>| {
        // A refused charge that fits both limits cannot happen; in a release
        // build it files as `Walk`.
        debug_assert!(
            charge.map_or(true, |charge| charge > view.budget.min(view.entry_limit)),
            "a refused charge fits its budget and entry limit"
        );
        match charge {
            Some(charge) if charge > view.budget => Bucket::OverBudget,
            Some(charge) if charge > view.entry_limit => Bucket::OverEntry,
            _ => Bucket::Walk,
        }
    };
    match refusal {
        Refusal::Clone { charge } => by_charge(charge),
        _ if view.granted && !view.resident_measured => Bucket::Walk,
        _ if view.granted && !view.active_measured => Bucket::Walk,
        _ if view.budget == 0 => Bucket::BudgetZero,
        Refusal::Release(sampled_scan::ReleaseOutcome::Race) => Bucket::OverBudget,
        Refusal::Release(_) => Bucket::Walk,
        Refusal::Admission { charge } => by_charge(charge),
    }
}
