//! Native reduction adapter for the shared acquisition/cache mechanism. The
//! existing parser step and finish remain the only semantic implementation.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle::{record, Event};
use crate::transcript_acquisition::{AuditDebt, Checkpoint, FullReason, ReadMode, ReadPlan, Scope};
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
crate::durable_tail_codec::durable_struct!(borrowed CachedJsonlReduction {
    D accumulator: SnapshotAccumulator,
    D report: JsonlReadReport,
    N recognized_usage_drop_count: usize,
    N positive_recognized_usage_count: usize,
    N positive_usage_evidence: bool,
});

/// M1 durable warm-cache reuse: the record body and its re-derivation.
#[cfg(unix)]
pub(super) mod durable;
#[cfg(test)]
pub(super) mod preparation_tests {
    use super::*;
    type Hook = Box<dyn FnMut(&crate::transcript_cache::Taken<CachedJsonlReduction>) -> Result<()>>;
    thread_local! {
        static FAULT: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) };
        pub(super) static HEAP_REFUSAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    pub(super) fn check(
        taken: &crate::transcript_cache::Taken<CachedJsonlReduction>,
    ) -> Result<()> {
        FAULT.with(|fault| {
            fault
                .borrow_mut()
                .as_mut()
                .map_or(Ok(()), |fault| fault(taken))
        })
    }
    pub(in crate::snapshots) fn set(hook: Option<Hook>) {
        FAULT.with(|fault| *fault.borrow_mut() = hook);
    }
    pub(in crate::snapshots) fn refuse_heap(value: bool) {
        HEAP_REFUSAL.with(|flag| flag.set(value));
    }
    pub(in crate::snapshots) fn heap_refused() -> bool {
        HEAP_REFUSAL.with(|flag| flag.get())
    }
}

impl CachedJsonlReduction {
    #[cfg(test)]
    pub(in crate::snapshots) fn accumulator_for_test(&mut self) -> &mut SnapshotAccumulator {
        &mut self.accumulator
    }
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
    /// The borrowed PRE-finalization fields an M3 record stages from, in the
    /// body's field order; the live finish seam passes the same five.
    #[cfg(unix)]
    pub(super) fn finish_view(
        &self,
    ) -> (&SnapshotAccumulator, &JsonlReadReport, (usize, usize, bool)) {
        (
            &self.accumulator,
            &self.report,
            (
                self.recognized_usage_drop_count,
                self.positive_recognized_usage_count,
                self.positive_usage_evidence,
            ),
        )
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
    pub(super) durable: super::DurableCustody,
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
crate::heap_layout_bound::fields!(CompletedNativeAcquisition; durable, checkpoint, reduction, released, unsealed);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum PreparationRefusal {
    Transient,
    NonTransient(&'static str),
}

pub(in crate::snapshots) struct PrepareRejected {
    pub(in crate::snapshots) refusal: PreparationRefusal,
    pub(in crate::snapshots) error: anyhow::Error,
    pub(in crate::snapshots) taken:
        Option<Box<crate::transcript_cache::Taken<CachedJsonlReduction>>>,
}

impl OwnedJsonlParser {
    /// The read's custody, retail attempt ended; also the uncertified M3 owner.
    pub(super) fn completed_durable(&mut self) -> super::DurableCustody {
        let durable = self.reader.reader.take_durable();
        #[cfg(unix)]
        let mut durable = durable;
        #[cfg(unix)]
        if let Some(attempt) = durable.take_retail() {
            attempt.finish();
        }
        durable
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
        let taken = old.map(|retained| {
            Box::new(crate::transcript_cache::Taken {
                retained,
                durable: Default::default(),
                modified_hint: (0, 0),
                finalization_charge: 0,
                e2_held_new_file: false,
            })
        });
        self.prepare_acquisition_inner(taken, scope, debt, now, (false, None), |_, _| Ok(true))
            .map_err(|rejected| rejected.error)
    }

    pub(in crate::snapshots) fn prepare_acquisition_owned(
        &mut self,
        taken: Option<Box<crate::transcript_cache::Taken<CachedJsonlReduction>>>,
        scope: &Scope,
        debt: Option<AuditDebt>,
        now: u64,
    ) -> std::result::Result<ReadMode, PrepareRejected> {
        self.prepare_acquisition_owned_planned(taken, scope, debt, now, None)
    }

    /// The restore caller may plan under its paid transfer lease before Q11.
    /// Reuse that same held-FD/checkpoint/scope plan; never repeat sample I/O.
    pub(in crate::snapshots) fn prepare_acquisition_owned_planned(
        &mut self,
        taken: Option<Box<crate::transcript_cache::Taken<CachedJsonlReduction>>>,
        scope: &Scope,
        debt: Option<AuditDebt>,
        now: u64,
        planned: Option<ReadPlan>,
    ) -> std::result::Result<ReadMode, PrepareRejected> {
        #[cfg(test)]
        if let Some(original) = taken.as_ref() {
            if let Err(error) = preparation_tests::check(original) {
                return Err(PrepareRejected {
                    error,
                    taken,
                    refusal: PreparationRefusal::Transient,
                });
            }
        }
        self.prepare_acquisition_inner(taken, scope, debt, now, (true, planned), |_, _| Ok(true))
    }
    #[cfg(test)]
    pub(super) fn prepare_acquisition_with_reuse_gate(
        &mut self,
        old: Option<Retained<CachedJsonlReduction>>,
        scope: &Scope,
        debt: Option<AuditDebt>,
        now: u64,
        reuse: impl FnMut(&Checkpoint, &File) -> Result<bool>,
    ) -> Result<ReadMode> {
        let taken = old.map(|retained| {
            Box::new(crate::transcript_cache::Taken {
                retained,
                durable: Default::default(),
                modified_hint: (0, 0),
                finalization_charge: 0,
                e2_held_new_file: false,
            })
        });
        self.prepare_acquisition_inner(taken, scope, debt, now, (false, None), reuse)
            .map_err(|rejected| rejected.error)
    }

    fn prepare_acquisition_inner(
        &mut self,
        mut taken: Option<Box<crate::transcript_cache::Taken<CachedJsonlReduction>>>,
        scope: &Scope,
        debt: Option<AuditDebt>,
        now: u64,
        (preserve, planned): (bool, Option<ReadPlan>),
        mut reuse: impl FnMut(&Checkpoint, &File) -> Result<bool>,
    ) -> std::result::Result<ReadMode, PrepareRejected> {
        let preserve = preserve && restart_restore::enabled();
        let checked = (|| -> Result<()> {
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
            anyhow::ensure!(
                self.reader.reader.accepts_durable(),
                "native custody occupied"
            );
            Ok(())
        })();
        if let Err(error) = checked {
            if restart_restore::enabled() {
                crate::local_resource_diagnostics::durable_tail_alarm(
                    self.source.api_slug(),
                    &serde_json::json!({"prepare_invariant": 1}),
                );
            }
            return Err(PrepareRejected {
                error,
                taken,
                refusal: PreparationRefusal::Transient,
            });
        }
        let reusable = taken
            .as_ref()
            .map(|taken| &taken.retained)
            .map_or(true, |old| {
                // Capture is a function of the source (contract 5 always on,
                // `claude_request_identity::captures`), so the same source keeps
                // the capture mode its markers were built in.
                old.state.accumulator.source == self.source
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
        if !reusable {
            if preserve {
                return Err(PrepareRejected {
                    error: anyhow::anyhow!("incompatible acquisition"),
                    refusal: PreparationRefusal::NonTransient("prepare_incompatible"),
                    taken,
                });
            }
            taken = None;
        }
        if preserve
            && taken
                .as_ref()
                .is_some_and(|taken| taken.retained.checkpoint.scope() != scope)
        {
            return Err(PrepareRejected {
                error: anyhow::anyhow!("incompatible acquisition scope"),
                refusal: PreparationRefusal::NonTransient("prepare_scope"),
                taken,
            });
        }
        let old = taken.as_ref().map(|taken| &taken.retained);
        let mut plan = match planned.map_or_else(
            || {
                ReadPlan::prepare(
                    self.reader.reader.get_mut(),
                    old.as_ref().map(|old| &old.checkpoint),
                    scope,
                    debt,
                    now,
                )
            },
            Ok,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                return Err(PrepareRejected {
                    error: error.into(),
                    // An old checkpoint's metadata/sample/seek failure may
                    // persist. Returning it must allow MAIN's zero-based Full.
                    refusal: if old.is_some() {
                        PreparationRefusal::NonTransient("prepare_io")
                    } else {
                        PreparationRefusal::Transient
                    },
                    taken,
                });
            }
        };
        if plan.mode() == ReadMode::Tail {
            match reuse(
                &taken
                    .as_ref()
                    .expect("Tail requires retained state")
                    .retained
                    .checkpoint,
                self.reader.reader.get_ref(),
            ) {
                Ok(true) => {}
                Ok(false) => {
                    plan = match ReadPlan::prepare(
                        self.reader.reader.get_mut(),
                        None,
                        scope,
                        debt,
                        now,
                    ) {
                        Ok(plan) => plan,
                        Err(error) => {
                            return Err(PrepareRejected {
                                error: error.into(),
                                taken,
                                refusal: PreparationRefusal::Transient,
                            })
                        }
                    };
                }
                Err(error) => {
                    return Err(PrepareRejected {
                        error,
                        taken,
                        refusal: PreparationRefusal::Transient,
                    })
                }
            }
        }
        let mode = plan.mode();
        // A proved physical edit supersedes receipt debt and its old graph.
        // Keep the actual counted edit cause and its already-created byte-zero
        // plan; returning the old graph here would hold the changed key forever.
        if matches!(
            mode,
            ReadMode::Full(
                FullReason::Replaced
                    | FullReason::Shrunk
                    | FullReason::SameSizeEdit
                    | FullReason::HeadChanged
                    | FullReason::BoundaryChanged
            )
        ) {
            taken = None;
        }
        if preserve
            && matches!(mode, ReadMode::Full(_))
            && taken
                .as_ref()
                .is_some_and(|taken| !taken.durable.is_empty())
        {
            return Err(PrepareRejected {
                error: anyhow::anyhow!("retained acquisition refused"),
                refusal: PreparationRefusal::NonTransient("prepare_full"),
                taken,
            });
        }
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
            } = {
                let taken = taken.take().expect("continued acquisition");
                self.reader.reader.put_durable(taken.durable);
                taken.retained.state
            };
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
                durable: self.completed_durable(),
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
            durable: self.completed_durable(),
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
        let declined = |checkpoint: Checkpoint,
                        durable: super::DurableCustody|
         -> Result<Option<CompletedNativeAcquisition>> {
            Ok(Some(CompletedNativeAcquisition {
                durable,
                checkpoint,
                reduction: None,
                released: None,
                unsealed,
            }))
        };
        if unsealed || !compatible {
            return declined(checkpoint, self.completed_durable());
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
            return declined(checkpoint, self.completed_durable());
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
            return declined(checkpoint, self.completed_durable());
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
            return declined(checkpoint, self.completed_durable());
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
            durable: self.completed_durable(),
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
                durable: self.completed_durable(),
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
                durable: self.completed_durable(),
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
                durable: self.completed_durable(),
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
            durable: self.completed_durable(),
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
