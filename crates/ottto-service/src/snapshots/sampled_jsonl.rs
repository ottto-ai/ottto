//! Native reduction adapter for the shared acquisition mechanism. The
//! existing parser step and finish remain the only semantic implementation.
use super::*;
use crate::transcript_acquisition::{AuditDebt, Checkpoint, FullReason, ReadMode, ReadPlan, Scope};
use crate::transcript_cache::Retained;

// Dependency witnesses: an excessive or nonstandard identifier drops the
// witness set, which declines continuation without cloning it.
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

/// Durable warm-cache reuse: the record body and its re-derivation.
#[cfg(unix)]
pub(super) mod durable;

impl CachedJsonlReduction {
    /// A reduction rebuilt from stored Tail state.
    #[cfg(unix)]
    pub(in crate::snapshots) fn stored(
        accumulator: SnapshotAccumulator,
        report: JsonlReadReport,
        (recognized_usage_drop_count, positive_recognized_usage_count, positive_usage_evidence): (
            usize,
            usize,
            bool,
        ),
    ) -> Self {
        Self {
            accumulator,
            report,
            recognized_usage_drop_count,
            positive_recognized_usage_count,
            positive_usage_evidence,
        }
    }
    /// Only Claude parses hold markers; Codex and Pi have none to change.
    pub(super) fn scrub_context_digest(&mut self) {
        if let Some(markers) = self.accumulator.claude_org_markers.as_deref_mut() {
            markers.scrub_context_digest();
        }
    }
    #[cfg(test)]
    pub(in crate::snapshots) fn accumulator_for_test(&mut self) -> &mut SnapshotAccumulator {
        &mut self.accumulator
    }
    /// The borrowed PRE-finalization fields, for tests.
    #[cfg(test)]
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
pub(super) struct CompletedNativeAcquisition {
    pub(super) checkpoint: Checkpoint,
    /// Native EOF applied bytes past the sealed offset (an unterminated final
    /// row), so the reduction is not the reduction through `checkpoint`. A
    /// cursor certificate does not compute it and reports `true` (fail-closed);
    /// its own bit is the job's `eof_applied` or `fragment`.
    pub(super) unsealed: bool,
}
crate::heap_layout_bound::fields!(CompletedNativeAcquisition; checkpoint, unsealed);

/// A completion certificate (test fixtures only).
#[cfg(test)]
#[allow(clippy::large_enum_variant, reason = "moved once to the caller")]
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
// checkpoint or a paused job's charge.
pub(super) struct LiveReductionInputs {
    traces: Option<Arc<CodexTurnTraceMap>>,
}

impl OwnedJsonlParser {
    pub(super) fn take_live_reduction_inputs(&mut self) -> LiveReductionInputs {
        LiveReductionInputs {
            traces: self.accumulator.codex_turn_traces.take(),
        }
    }

    pub(super) fn restore_live_reduction_inputs(&mut self, inputs: LiveReductionInputs) {
        self.accumulator.codex_turn_traces = inputs.traces;
    }

    /// Invoked on a fresh safely-opened parser before any fill/read. Scope and
    /// durable debt must be supplied by the existing source/index authority.
    pub(super) fn prepare_acquisition(
        &mut self,
        mut old: Option<Box<Retained<CachedJsonlReduction>>>,
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
        let reusable = old.as_deref().map_or(true, |old| {
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
            old = None;
        }
        let plan = ReadPlan::prepare(
            self.reader.reader.get_mut(),
            old.as_deref().map(|old| &old.checkpoint),
            scope,
            debt,
            now,
        )?;
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
            old = None;
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
            } = old.take().expect("continued acquisition").state;
            // These are live native inputs, not immutable retained history.
            // Known prior trace decisions were compared above; fresh suffixes
            // use this cycle's traces. Projected EOF advances with appends.
            let mut accumulator = accumulator;
            accumulator
                .claude_file_birth
                .refresh_opened(&self.accumulator.claude_file_birth);
            accumulator.codex_turn_traces = self.accumulator.codex_turn_traces.take();
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

    /// Take the acquisition certificate only after EOF. This does not authorize
    /// publication/index clearing: the host must also complete native finish,
    /// ownership/loss/source/dependency validation and its existing CAS boundary.
    pub(super) fn retain_reduction(
        &mut self,
        scope: &Scope,
        now: u64,
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
        let Some(plan) = self.reader.acquisition.take() else {
            return Ok(None);
        };
        let checkpoint =
            plan.commit_after_native_completion(self.reader.reader.get_ref(), scope, now)?;
        // Native EOF may apply an unterminated valid JSON row. Its reduction is
        // not the reduction through the sealed byte pointer.
        let unsealed = checkpoint.sealed_offset() != self.reader.reader.get_ref().metadata()?.len();
        Ok(Some(CompletedNativeAcquisition {
            checkpoint,
            unsealed,
        }))
    }

    /// Offline durable-record controls need a real reduction: the
    /// accumulator without this cycle's live, shared inputs, plus the report
    /// scalars.
    #[cfg(test)]
    pub(super) fn durable_test_reduction_copy(&mut self) -> CachedJsonlReduction {
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

    /// `retain_reduction`'s completion gate and commit, without a retained
    /// copy or any `cache_lifecycle` event; it never touches the cache. Test
    /// fixtures certify a native completion through it.
    #[cfg(test)]
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
            },
            len,
        })
    }
}
