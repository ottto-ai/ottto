//! The native JSONL file parser: the per-source parse wrappers, the owned
//! parser that steps one physical line at a time and finalizes the file, the
//! parsed file it yields, the bounded physical-line reader beneath it, and the
//! usage-shape checks it applies to each parsed line.

use crate::snapshots::*;

#[cfg(test)]
pub fn parse_codex_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
) -> Result<Vec<SnapshotItem>> {
    parse_codex_jsonl_file_with_title_metadata(
        path,
        collected_at,
        source_file_fingerprint,
        &CodexTitleMetadata::default(),
        None,
    )
}

#[cfg(test)]
pub(in crate::snapshots) fn parse_codex_jsonl_file_with_title_metadata(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &CodexTitleMetadata,
    codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
) -> Result<Vec<SnapshotItem>> {
    parse_codex_jsonl_file_with_title_metadata_and_attribution(
        path,
        collected_at,
        source_file_fingerprint,
        title_metadata,
        codex_turn_traces,
        None,
    )
}

#[cfg(test)]
pub(in crate::snapshots) fn parse_codex_jsonl_file_with_title_metadata_and_attribution(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &CodexTitleMetadata,
    codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<Vec<SnapshotItem>> {
    parse_codex_jsonl_file_with_diagnostics(
        path,
        collected_at,
        source_file_fingerprint,
        title_metadata,
        codex_turn_traces,
        attribution_context,
    )
    .map(|parsed| parsed.snapshots)
}

#[cfg(test)]
fn parse_codex_jsonl_file_with_diagnostics(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &CodexTitleMetadata,
    codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<ParsedSnapshotFile> {
    refuse_compressed_codex(Some(path), None, CodexZstCause::CompatibilityUnfunded)?;
    parse_jsonl_file(
        path,
        collected_at,
        source_file_fingerprint,
        SnapshotSource::Codex,
        apply_codex_line,
        Some(title_metadata),
        None,
        codex_turn_traces,
        attribution_context,
    )
}

#[cfg(test)]
pub fn parse_claude_code_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
) -> Result<Vec<SnapshotItem>> {
    parse_claude_code_jsonl_file_with_title_metadata(
        path,
        collected_at,
        source_file_fingerprint,
        &ClaudeTitleMetadata::default(),
    )
}

/// Full production form with the desktop-store title metadata threaded in; the
/// scan path loads the store once per cycle and shares it across every session
/// file.
#[cfg(test)]
pub(in crate::snapshots) fn parse_claude_code_jsonl_file_with_title_metadata(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &ClaudeTitleMetadata,
) -> Result<Vec<SnapshotItem>> {
    parse_claude_code_jsonl_file_with_title_metadata_and_attribution(
        path,
        collected_at,
        source_file_fingerprint,
        title_metadata,
        None,
    )
}

#[cfg(test)]
pub(in crate::snapshots) fn parse_claude_code_jsonl_file_with_title_metadata_and_attribution(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &ClaudeTitleMetadata,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<Vec<SnapshotItem>> {
    parse_claude_code_jsonl_file_with_diagnostics(
        path,
        collected_at,
        source_file_fingerprint,
        title_metadata,
        attribution_context,
    )
    .map(|parsed| parsed.snapshots)
}

#[cfg(test)]
fn parse_claude_code_jsonl_file_with_diagnostics(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &ClaudeTitleMetadata,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<ParsedSnapshotFile> {
    parse_jsonl_file(
        path,
        collected_at,
        source_file_fingerprint,
        SnapshotSource::ClaudeCode,
        apply_claude_code_line,
        None,
        Some(title_metadata),
        None,
        attribution_context,
    )
}

#[cfg(test)]
pub fn parse_pi_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
) -> Result<Vec<SnapshotItem>> {
    parse_jsonl_file(
        path,
        collected_at,
        source_file_fingerprint,
        SnapshotSource::Pi,
        apply_pi_line,
        None,
        None,
        None,
        None,
    )
    .map(|parsed| parsed.snapshots)
}

#[cfg(test)]
#[derive(Debug)]
struct ParsedSnapshotFile {
    snapshots: Vec<SnapshotItem>,
}

#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "test seam preserves file identity, window and parser inputs"
)]
fn parse_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    source: SnapshotSource,
    apply_line: fn(&Value, &mut SnapshotAccumulator),
    codex_title_metadata: Option<&CodexTitleMetadata>,
    claude_title_metadata: Option<&ClaudeTitleMetadata>,
    codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<ParsedSnapshotFile> {
    let mut file = File::open(path).with_context(|| format!("open JSONL {}", path.display()))?;
    let opened_identity = opened_object_identity(source, &mut file)
        .with_context(|| format!("fingerprint opened JSONL {}", path.display()))?;
    let parsed = parse_opened_jsonl_file(
        file,
        &opened_identity,
        path,
        collected_at,
        source_file_fingerprint,
        source,
        apply_line,
        codex_title_metadata,
        claude_title_metadata,
        codex_turn_traces,
        attribution_context,
    )?;
    Ok(ParsedSnapshotFile {
        snapshots: parsed.snapshots,
    })
}

#[derive(Debug)]
pub(in crate::snapshots) struct ParsedJsonlFile {
    pub(in crate::snapshots) snapshots: Vec<SnapshotItem>,
    pub(in crate::snapshots) report: JsonlReadReport,
    pub(in crate::snapshots) recognized_usage_drop_count: usize,
    pub(in crate::snapshots) ownership_incomplete_file_count: usize,
    pub(in crate::snapshots) cause: usize,
    pub(in crate::snapshots) zero_snapshot_usage_evidence: bool,
    pub(in crate::snapshots) dropped_usage_record_count: u64,
    /// Local diagnostic only: Claude compaction summaries that name a
    /// `parentUuid` whose chain never reached a boundary (each counts as its
    /// own event). Counted before ownership filtering.
    pub(in crate::snapshots) claude_compaction_unlinked_parent_count: usize,
    pub(in crate::snapshots) codex_parent_session_ref: Option<String>,
    /// Whether the parser observed a provider session id. Unstored.
    source_session_id_seen: bool,
}

impl ParsedJsonlFile {
    /// Complete physical records may be discarded. Only classified native
    /// ownership/conflict holds prevent publication and committed progress.
    pub(in crate::snapshots) fn progress_complete(&self) -> bool {
        self.ownership_incomplete_file_count == 0
            && !(self.snapshots.is_empty()
                && (self.zero_snapshot_usage_evidence || self.terminal_loss().is_some()))
    }

    pub(in crate::snapshots) fn non_progressing_residue(&self) -> bool {
        !self.progress_complete()
    }

    pub(in crate::snapshots) fn terminal_loss(&self) -> Option<TerminalJsonlLoss> {
        let loss = TerminalJsonlLoss {
            malformed_json_line_count: self.report.malformed_json_line_count,
            invalid_utf8_line_count: self.report.invalid_utf8_line_count,
            recognized_usage_drop_count: self.recognized_usage_drop_count,
            dropped_usage_record_count: self.dropped_usage_record_count,
        };
        (loss != TerminalJsonlLoss::default()).then_some(loss)
    }
}

// The native file parser owns all state needed between physical-line steps.
// Finalization is separate: a line step is never file or upload authority.
/// The reader `OwnedJsonlParser` owns (named once for `with_line_sink`).
type ParserReader = BoundedJsonlReader<OpenedInput>;
/// The parser's one per-line sink, as `with_line_sink` lends it.
type LineSink<'a> = &'a mut dyn FnMut(&Value);

#[derive(Default)]
struct ParserPending {
    /// The committed Tail head this read continues, from its load to the
    /// PRE seam's encode.
    #[cfg(unix)]
    tail_base: Option<tail_source::seam::TailBase>,
}
crate::heap_layout_bound::fields!(ParserPending; #[cfg(unix)] tail_base);

pub(in crate::snapshots) struct OwnedJsonlParser {
    #[cfg(test)]
    source_read_probe: Option<PathBuf>,
    pub(in crate::snapshots) reader: BoundedJsonlReader<OpenedInput>,
    pub(in crate::snapshots) accumulator: SnapshotAccumulator,
    pub(in crate::snapshots) source: SnapshotSource,
    apply_line: fn(&Value, &mut SnapshotAccumulator),
    pub(in crate::snapshots) recognized_usage_drop_count: usize,
    pub(in crate::snapshots) positive_recognized_usage_count: usize,
    pub(in crate::snapshots) positive_usage_evidence: bool,
    /// Ledger birth from the same open-time read as `claude_file_birth`.
    pub(in crate::snapshots) claude_opened_birth: Option<claude_request_census::ClaudeRequestBirth>,
    pending: Option<Box<ParserPending>>,
}
impl OwnedJsonlParser {
    #[cfg(unix)]
    pub(in crate::snapshots) fn set_tail_base(&mut self, base: tail_source::seam::TailBase) {
        self.pending.get_or_insert_with(Default::default).tail_base = Some(base);
    }
    #[cfg(unix)]
    pub(in crate::snapshots) fn take_tail_base(&mut self) -> Option<tail_source::seam::TailBase> {
        self.pending.as_mut()?.tail_base.take()
    }
    pub(in crate::snapshots) fn new(
        file: File,
        path: &Path,
        source: SnapshotSource,
        apply_line: fn(&Value, &mut SnapshotAccumulator),
        codex_title_metadata: Option<&CodexTitleMetadata>,
        codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    ) -> Result<Self> {
        if source == SnapshotSource::Codex {
            refuse_compressed_codex(Some(path), None, CodexZstCause::CompatibilityUnfunded)?;
        }
        Self::new_opened(
            OpenedInput::plain(file),
            path,
            source,
            apply_line,
            codex_title_metadata,
            codex_turn_traces,
        )
    }
    /// Every input kind reaches the same line parser through one opened
    /// object. Its File was opened and identified by the caller; a compressed
    /// input arrives with its decoder credit already paid.
    pub(in crate::snapshots) fn new_opened(
        reader: OpenedInput,
        path: &Path,
        source: SnapshotSource,
        apply_line: fn(&Value, &mut SnapshotAccumulator),
        codex_title_metadata: Option<&CodexTitleMetadata>,
        codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    ) -> Result<Self> {
        // Snapshot semantics come from provider-native session evidence. Mutable
        // current config defaults are useful for live status display, but applying
        // today's defaults to cumulative historical usage would retroactively
        // rewrite old sessions and make a config edit a global replay trigger.
        let mut accumulator = SnapshotAccumulator::new(source);
        accumulator.codex_turn_traces = codex_turn_traces;
        if source == SnapshotSource::Codex {
            if let Some(metadata) = codex_title_metadata {
                let file_metadata = match reader.get_ref().metadata() {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        reader.close();
                        return Err(error).with_context(|| {
                            format!("read opened JSONL metadata {}", path.display())
                        });
                    }
                };
                accumulator.seed_codex_sidecar_parent(path, &file_metadata, metadata);
            }
        }
        let mut claude_opened_birth = None;
        if source == SnapshotSource::ClaudeCode {
            // Birth of the opened object itself; a later path lookup could
            // describe a replacement file. One read, shared by the birth rule
            // (this open only) and the ledger (first-seen birth).
            let opened = reader.get_ref().metadata().ok();
            accumulator.claude_file_birth = ClaudeFileBirth::observe(path, opened.as_ref());
            claude_opened_birth = opened.as_ref().and_then(claude_opened_file_birth);
        }

        let reader = BoundedJsonlReader::new(reader);
        Ok(Self {
            pending: None,
            #[cfg(test)]
            source_read_probe: Some(path.to_owned()),
            reader,
            accumulator,
            source,
            apply_line,
            recognized_usage_drop_count: 0,
            positive_recognized_usage_count: 0,
            positive_usage_evidence: false,
            claude_opened_birth,
        })
    }
    pub(in crate::snapshots) fn step(&mut self) -> Result<bool> {
        self.step_delivering(None)
    }
    pub(in crate::snapshots) fn step_delivering(
        &mut self,
        on_line: Option<line_delivery::LineTap<'_>>,
    ) -> Result<bool> {
        #[cfg(test)]
        transcript_io_allowed()?;
        #[cfg(test)]
        if let Some(path) = self.source_read_probe.take() {
            terminal_contract_retry::record_source_acquisition(&path);
        }
        self.step_observed(|_| {}, on_line)
    }
    pub(in crate::snapshots) fn step_with_observer(
        &mut self,
        observe: impl FnMut(&Value),
    ) -> Result<bool> {
        self.step_observed(observe, None)
    }
    fn step_observed(
        &mut self,
        observe: impl FnMut(&Value),
        on_line: Option<line_delivery::LineTap<'_>>,
    ) -> Result<bool> {
        let step = self.with_line_sink(observe, |reader, sink| reader.step_lines(sink, on_line));
        Ok(matches!(step?, JsonlReaderStep::Complete(_)))
    }

    /// Apply one record another parser's reader produced (a group's legacy
    /// tee, P2) through this parser's line sink; this reader is not read.
    pub(in crate::snapshots) fn tee_line(&mut self, value: &Value) {
        self.with_line_sink(|_| {}, |_, sink| sink(value))
    }

    /// FE1: certify a complete traversal of a grown Claude frozen extent.
    /// The checkpoint is deliberately dropped. The existing audit obligation
    /// remains prepared; FE2's sample-preserving rewrite residual is bounded
    /// by the quiet Full audit and its sampled_audit_comparison diagnostics.
    pub(in crate::snapshots) fn commit_claude_grown_prefix(
        &mut self,
        path: &Path,
        scope: &crate::transcript_acquisition::Scope,
        last_committed_size: u64,
    ) -> Option<
        std::result::Result<
            sampled_scan::codex_cursor::FinishGrant,
            crate::transcript_acquisition::PrefixRefusal,
        >,
    > {
        use crate::transcript_acquisition::{FullReason, PrefixRefusal, ReadMode};
        let plan = self.reader.acquisition.as_ref()?;
        let frozen = plan.frozen_length();
        let start = plan.start_offset();
        let consumed = start.checked_add(self.reader.consumed_bytes())?;
        let held = self.reader.reader.get_ref().metadata().ok()?;
        if self.source != SnapshotSource::ClaudeCode
            // Only H1c-admitted reads may take H3c. Forced/comparison and
            // other ineligible native reads retain strict completion.
            || self.reader.extent_limit != Some(frozen.checked_sub(start)?)
            || !matches!(plan.mode(), ReadMode::Full(_) | ReadMode::Tail)
            || held.len() <= frozen
            || consumed != frozen
            || !self.reader.finished
            || self.reader.failure.is_some()
            // An unterminated row was already applied at EOF: it lies beyond the
            // sealed newline, so later growth must keep strict identity.
            || (!self.reader.sealed_fragment()
                && self.reader.consumed_bytes() != self.reader.last_complete_line_end())
        {
            return None;
        }
        // A committed unterminated row may extend beyond the last newline.
        // Never replace it with a weaker complete-row prefix.
        if start.checked_add(self.reader.last_complete_line_end())? < last_committed_size {
            return Some(Err(PrefixRefusal::Invalidated(
                FullReason::InvalidCheckpoint,
            )));
        }
        let path_same_object = fs::symlink_metadata(path)
            .is_ok_and(|current| metadata_describes_same_file(&held, &current));
        let plan = self.reader.acquisition.take().expect("checked acquisition");
        let now = sampled_scan::now_seconds();
        Some(
            plan.commit_sealed_prefix(
                self.reader.reader.get_mut(),
                path_same_object,
                scope,
                now,
                now,
                false,
                consumed,
            )
            .map(|_discarded_checkpoint| {
                sampled_scan::codex_cursor::FinishGrant::certified(held.dev(), held.ino(), frozen)
            }),
        )
    }

    /// At a genuine unchanged EOF (proved by the caller), apply a
    /// withheld final record through the same line sink as every other line.
    pub(in crate::snapshots) fn apply_sealed_fragment(&mut self) -> bool {
        self.with_line_sink(|_| {}, |reader, sink| reader.apply_sealed_fragment(sink))
    }

    /// Run `drive` with the parser's one line sink (observer, tier replay,
    /// usage-shape counters, `apply_line`).
    pub(in crate::snapshots) fn with_line_sink<T>(
        &mut self,
        mut observe: impl FnMut(&Value),
        drive: impl FnOnce(&mut ParserReader, LineSink<'_>) -> T,
    ) -> T {
        let source = self.source;
        let accumulator = &mut self.accumulator;
        let recognized_usage_drop_count = &mut self.recognized_usage_drop_count;
        let positive_recognized_usage_count = &mut self.positive_recognized_usage_count;
        let positive_usage_evidence = &mut self.positive_usage_evidence;
        let apply_line = self.apply_line;
        let mut sink = |value: &Value| {
            observe(value);
            if let Some(replay) = accumulator.codex_tier_replay.as_mut() {
                replay.observe(value);
            }
            let inherited = (source == SnapshotSource::ClaudeCode
                && claude_fork_line_provenance(value) == ClaudeForkLineProvenance::Inherited)
                || (source == SnapshotSource::Pi
                    && pi_usage_event(value)
                    && accumulator.seen_pi_usage_keys.is_fork_copy(value));
            if !inherited && recognized_usage_shape_was_dropped(source, value) {
                *recognized_usage_drop_count += 1;
            }
            if !inherited && recognized_positive_usage_shape(source, value) {
                *positive_recognized_usage_count += 1;
            }
            if !inherited {
                *positive_usage_evidence |= json_has_positive_usage_evidence(value);
            }
            apply_line(value, accumulator);
        };
        drive(&mut self.reader, &mut sink)
    }
    #[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
    pub(in crate::snapshots) fn finish(
        self,
        expected_opened_object_identity: &str,
        path: &Path,
        collected_at: &str,
        source_file_fingerprint: String,
        codex_title_metadata: Option<&CodexTitleMetadata>,
        claude_title_metadata: Option<&ClaudeTitleMetadata>,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<ParsedJsonlFile> {
        self.finish_with_repository_identity(
            expected_opened_object_identity,
            path,
            collected_at,
            source_file_fingerprint,
            codex_title_metadata,
            claude_title_metadata,
            attribution_context,
            None,
            None,
        )
    }

    /// `finish`, with a caller-supplied repository identity. `Some` is used
    /// as-is, so the finished item never re-resolves (IO) it.
    #[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
    pub(in crate::snapshots) fn finish_with_repository_identity(
        self,
        expected_opened_object_identity: &str,
        path: &Path,
        collected_at: &str,
        source_file_fingerprint: String,
        codex_title_metadata: Option<&CodexTitleMetadata>,
        claude_title_metadata: Option<&ClaudeTitleMetadata>,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
        repository_identity: Option<crate::context_footprint::RepositoryIdentity>,
        money_context: Option<claude_request_money::e2::ReadContext<'_>>,
    ) -> Result<ParsedJsonlFile> {
        self.finish_native(
            FinishRequest {
                expected_opened_object_identity,
                path,
                collected_at,
                source_file_fingerprint,
                codex_title_metadata,
                claude_title_metadata,
                attribution_context,
                repository_identity,
                money_context,
            },
            None,
        )
    }

    // Keep the consumed parser off the caller's scan-step frame as well as
    // while it is retained in OwnedActiveFile. Unboxing belongs to this frame.
    #[inline(never)]
    pub(in crate::snapshots) fn finish_boxed_native(
        self: Box<Self>,
        request: FinishRequest<'_>,
        pre: Option<&mut dyn FnMut(PreFinalization<'_>)>,
    ) -> Result<ParsedJsonlFile> {
        self.finish_native(request, pre)
    }

    /// The one native finish. `pre` runs exactly once, only on the path that
    /// reached the PRE-finalization seam; every earlier error returns first.
    pub(in crate::snapshots) fn finish_native(
        self,
        request: FinishRequest<'_>,
        pre: Option<&mut dyn FnMut(PreFinalization<'_>)>,
    ) -> Result<ParsedJsonlFile> {
        let FinishRequest {
            expected_opened_object_identity,
            path,
            collected_at,
            source_file_fingerprint,
            codex_title_metadata,
            claude_title_metadata,
            attribution_context,
            repository_identity,
            money_context,
        } = request;
        if !self.reader.finished || self.reader.failure.is_some() {
            self.reader.reader.close();
            anyhow::bail!("incomplete parser cannot finalize a file");
        }
        if let Some(context) = attribution_context {
            let workers = launch_workers_for_parsed(
                self.source,
                self.accumulator.source_session_id.as_deref(),
                path,
            );
            if !context.launch_events().prepared(&workers) {
                self.reader.reader.close();
                anyhow::bail!("launch evidence lookup incomplete");
            }
        }
        let Self {
            reader: bounded,
            mut accumulator,
            source,
            mut recognized_usage_drop_count,
            positive_recognized_usage_count,
            positive_usage_evidence,
            ..
        } = self;
        let mut reader = bounded.reader;
        let report = bounded.report;
        // The retained reduction's own count; a live body must equal it.
        let reduction_drop_count = recognized_usage_drop_count;
        // Present for a cursor job or Claude in-page read whose prefix
        // certificate passed (S12/FE1)
        // or whose lossy job holds the same-object identity proof.
        let sealed_prefix = bounded.sealed_prefix;
        // A cursor read withheld an unterminated final record (N2).
        let sealed_fragment = bounded.sealed_fragment.is_some();
        let mut ownership_incomplete_file_count = 0;
        let (observed_after_read, _observed_stat) =
            match opened_object_identity_and_stat(source, reader.get_mut()) {
                Ok(observed) => observed,
                Err(error) => {
                    reader.close();
                    return Err(error)
                        .with_context(|| format!("revalidate opened JSONL {}", path.display()));
                }
            };
        // A cursor job read only up to its frozen extent; appended bytes
        // belong to the next tail, so its object may have grown. Only a job
        // whose prefix certificate passed against the held FD carries
        // `Certified` (same dev/ino, no shrink, no same-size edit, held-FD
        // samples, scope), and the held FD must still be that dev/ino and at
        // least the frozen extent long. A lossy job carries only
        // its same-object proof, revalidated here against the held FD (no
        // shrink, same covered samples) and the selected path; it publishes
        // uncertified. Every other read keeps exact equality.
        let grown_identity_holds = sealed_prefix
            .as_ref()
            .is_some_and(|grant| grant.holds(reader.get_mut(), path));
        if observed_after_read != expected_opened_object_identity && !grown_identity_holds {
            reader.close();
            return Err(anyhow::anyhow!(
                "opened snapshot candidate changed while it was parsed"
            ));
        }
        let _plain_reader = if reader.is_compressed() {
            reader.close();
            None
        } else {
            Some(reader)
        };
        // Resolve before PRE stages the session facts, outside the store's
        // transactions. Only positive repository evidence is permanent;
        // non-Git and unavailable lookups retry on ordinary selected work.
        let repository_identity = accumulator
            .repository_binding
            .clone()
            .or(repository_identity)
            .or_else(|| {
                accumulator
                    .workspace_path
                    .as_deref()
                    .map(cached_repository_identity)
            });
        if let Some(identity) = &repository_identity {
            if identity.is_repository() {
                accumulator.repository_binding = Some(identity.clone());
            }
        }
        // PRE-finalization seam. The live scan-shared inputs are
        // detached exactly as a retained copy excludes them, then restored
        // before any finalization reads them; no early exit lies between.
        if let Some(pre) = pre {
            let traces = accumulator.codex_turn_traces.take();
            pre(PreFinalization::new(
                &accumulator,
                &report,
                (
                    reduction_drop_count,
                    positive_recognized_usage_count,
                    positive_usage_evidence,
                ),
            ));
            accumulator.codex_turn_traces = traces;
        }
        if source == SnapshotSource::Codex {
            if let Some(metadata) = codex_title_metadata {
                accumulator.apply_codex_title_metadata(path, metadata);
            }
            accumulator.apply_first_prompt_fallback();
        }
        if source == SnapshotSource::ClaudeCode {
            claude_request_money::e2::timed("claude.finalize", || {
                accumulator.finalize_claude_responses_e2(money_context)
            });
            if let Some(metadata) = claude_title_metadata {
                accumulator.apply_claude_title_metadata(path, metadata);
            }
            // A subagent transcript's "first user prompt" is the Task/Workflow
            // prompt BODY the parent injected, not a human-authored title. Agent
            // sessions are named from label material only (`agent_label` above);
            // prompt content must never become their display name. The captured
            // first-prompt MATERIAL still feeds attribution grouping unchanged.
            if claude_subagent_identity(path).is_none() {
                accumulator.apply_first_prompt_fallback();
            }
        }
        if source == SnapshotSource::Pi {
            accumulator.apply_first_prompt_fallback();
            let conflicts = accumulator
                .seen_pi_usage_keys
                .usage_keys()
                .values()
                .filter(|state| state.has_cross_shape_conflict())
                .count();
            ownership_incomplete_file_count = usize::from(conflicts > 0);
            recognized_usage_drop_count += conflicts;
        }
        let accumulator_dropped_usage_record_count =
            accumulator.dropped_usage_record_count as usize;
        recognized_usage_drop_count =
            recognized_usage_drop_count.saturating_add(accumulator_dropped_usage_record_count);
        // A parentless created thread is proven only by its complete physical
        // stream. Record an unread line before the ownership decision so the file
        // is held as ownership-incomplete (the generic marking below is too late).
        // A withheld final record is unread too: the prefix is not that stream.
        if source == SnapshotSource::Codex
            && (!report.complete() || sealed_fragment)
            && accumulator.codex_parentless_created_thread()
        {
            accumulator.codex_creator_evidence_conflicted = true;
        }
        let codex_ownership_incomplete =
            source == SnapshotSource::Codex && !accumulator.codex_usage_accounting_complete();
        if codex_ownership_incomplete {
            // Keep the candidate retryable even when the ambiguous/incomplete
            // rollout contains no recognized positive usage. Otherwise it could be
            // indexed as confirmed-empty and fall through to inclusive SQLite state
            // on the next scan generation.
            ownership_incomplete_file_count = 1;
        }
        let codex_parent_session_ref = accumulator.codex_parent_session_ref.clone();
        let source_session_id_seen = accumulator.source_session_id.is_some();
        let cause = if accumulator.codex_created_thread_native_only {
            ownership::CREATED
        } else {
            ownership::PARSER
        };
        // Missing physical request/boundary records cannot certify cache order or
        // complete coverage. Existing cache consumers withhold observations and
        // preserve accepted rows when this completeness bit is false. Usage loss
        // and terminal oversized-line settlement retain their existing meaning.
        if !report.complete() {
            accumulator.cache_requests_complete = false;
        }
        // An unread physical record could contain an earlier/copied/conflicting
        // header. Preserve legacy partial usage behavior, but do not certify the
        // optional original creator witness from an incomplete physical stream.
        if source == SnapshotSource::Codex && !report.complete() {
            accumulator.codex_creator_evidence_conflicted = true;
        }
        if source == SnapshotSource::ClaudeCode
            && (!report.complete() || recognized_usage_drop_count > 0)
        {
            if let Some(evidence) = &mut accumulator.claude_desktop_identity {
                if evidence.identity_disposition == Some("complete") {
                    evidence.identity_disposition = Some("missing");
                }
            }
        }
        // A new Claude Code record type inside the boundary-to-summary chain
        // would surface here first, before counts double on the page.
        let claude_compaction_unlinked_parent_count = accumulator
            .claude_compaction_observations
            .iter()
            .filter(|observation| {
                observation.kind == ClaudeCompactionKind::LegacySummary
                    && observation.has_parent_link
                    && observation.pair_key.is_none()
            })
            .count();
        // A fully read Pi fork whose positive usage was all copied must
        // publish zero too: an earlier accepted revision can be inflated.
        let (has_parent, header_nanos) = accumulator.seen_pi_usage_keys.fork_parts();
        let emit_empty_pi_fork = has_parent
            && header_nanos.is_some()
            && report.complete()
            && recognized_usage_drop_count == 0
            && accumulator_dropped_usage_record_count == 0
            && !positive_usage_evidence;
        let snapshots = claude_request_money::e2::timed("native.into_items", || {
            accumulator.into_items_with_repository_identity(
                path,
                collected_at,
                source_file_fingerprint,
                attribution_context,
                repository_identity,
                emit_empty_pi_fork,
            )
        });
        // A syntactically valid, positive provider usage record that yields no
        // entity is still loss. Typical causes are an absent/unparseable activity
        // timestamp or an identity shape the accumulator cannot settle. Treat the
        // whole file as retryable instead of persisting it as confirmed-empty.
        let zero_snapshot_usage_evidence = snapshots.is_empty() && positive_usage_evidence;
        if snapshots.is_empty() {
            recognized_usage_drop_count = recognized_usage_drop_count.saturating_add(
                positive_recognized_usage_count
                    .saturating_sub(accumulator_dropped_usage_record_count),
            );
            if positive_usage_evidence && positive_recognized_usage_count == 0 {
                recognized_usage_drop_count = recognized_usage_drop_count.saturating_add(1);
            }
        }
        Ok(ParsedJsonlFile {
            snapshots,
            report,
            recognized_usage_drop_count,
            ownership_incomplete_file_count,
            cause,
            zero_snapshot_usage_evidence,
            dropped_usage_record_count: recognized_usage_drop_count as u64,
            claude_compaction_unlinked_parent_count,
            codex_parent_session_ref,
            source_session_id_seen,
        })
    }
}

/// Native finish inputs, shared by the legacy and the prepared wrapper.
pub(in crate::snapshots) struct FinishRequest<'a> {
    pub(in crate::snapshots) expected_opened_object_identity: &'a str,
    pub(in crate::snapshots) path: &'a Path,
    pub(in crate::snapshots) collected_at: &'a str,
    pub(in crate::snapshots) source_file_fingerprint: String,
    pub(in crate::snapshots) codex_title_metadata: Option<&'a CodexTitleMetadata>,
    pub(in crate::snapshots) claude_title_metadata: Option<&'a ClaudeTitleMetadata>,
    pub(in crate::snapshots) attribution_context:
        Option<&'a crate::session_attribution::SessionAttributionContext>,
    pub(in crate::snapshots) repository_identity:
        Option<crate::context_footprint::RepositoryIdentity>,
    pub(in crate::snapshots) money_context: Option<claude_request_money::e2::ReadContext<'a>>,
}

/// The live parser state at the PRE-finalization seam, scan-shared inputs
/// detached; the same fields a retained reduction copies.
pub(in crate::snapshots) struct PreFinalization<'a> {
    pub(in crate::snapshots) accumulator: &'a SnapshotAccumulator,
    pub(in crate::snapshots) report: &'a JsonlReadReport,
    pub(in crate::snapshots) recognized_usage_drop_count: usize,
    pub(in crate::snapshots) positive_recognized_usage_count: usize,
    pub(in crate::snapshots) positive_usage_evidence: bool,
}

impl<'a> PreFinalization<'a> {
    pub(in crate::snapshots) fn new(
        accumulator: &'a SnapshotAccumulator,
        report: &'a JsonlReadReport,
        scalars: (usize, usize, bool),
    ) -> Self {
        Self {
            accumulator,
            report,
            recognized_usage_drop_count: scalars.0,
            positive_recognized_usage_count: scalars.1,
            positive_usage_evidence: scalars.2,
        }
    }
}

/// `created()` of an opened file with its device and inode, or None when the
/// file system cannot report it. Never a default (0, mtime or now).
fn claude_opened_file_birth(
    metadata: &fs::Metadata,
) -> Option<claude_request_census::ClaudeRequestBirth> {
    #[cfg(unix)]
    {
        let created = metadata.created().ok()?.duration_since(UNIX_EPOCH).ok()?;
        Some(claude_request_census::ClaudeRequestBirth {
            unix_seconds: claude_birth_seconds(created.as_secs())?,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// A birth (whole seconds) at or before 2020-01-01T00:00:00Z, the epoch or
/// zero included, is a file system's placeholder: unknown, never the
/// earliest owner.
pub(in crate::snapshots) fn claude_birth_seconds(created_unix_seconds: u64) -> Option<u64> {
    const CLAUDE_BIRTH_FLOOR_UNIX_SECONDS: u64 = 1_577_836_800;
    (created_unix_seconds > CLAUDE_BIRTH_FLOOR_UNIX_SECONDS).then_some(created_unix_seconds)
}

#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "test seam preserves opened-file identity and parser inputs"
)]
pub(in crate::snapshots) fn parse_opened_jsonl_file(
    file: File,
    expected_opened_object_identity: &str,
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    source: SnapshotSource,
    apply_line: fn(&Value, &mut SnapshotAccumulator),
    codex_title_metadata: Option<&CodexTitleMetadata>,
    claude_title_metadata: Option<&ClaudeTitleMetadata>,
    codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<ParsedJsonlFile> {
    let mut parser = OwnedJsonlParser::new(
        file,
        path,
        source,
        apply_line,
        codex_title_metadata,
        codex_turn_traces,
    )?;
    while !parser
        .step()
        .with_context(|| format!("read JSONL {}", path.display()))?
    {}
    if let Some(context) = attribution_context {
        let workers = launch_workers_for_parsed(
            source,
            parser.accumulator.source_session_id.as_deref(),
            path,
        );
        // This compatibility reader already synchronously drains the transcript.
        // Production OwnedSourceScan prepares in its resumable step before finish.
        while !context
            .launch_events()
            .prepare_step(&workers)
            .map_err(|()| anyhow::anyhow!("launch evidence lookup incomplete"))?
        {}
    }
    parser.finish(
        expected_opened_object_identity,
        path,
        collected_at,
        source_file_fingerprint,
        codex_title_metadata,
        claude_title_metadata,
        attribution_context,
    )
}

crate::heap_layout_bound::fields!(ParsedJsonlFile; snapshots, report, recognized_usage_drop_count, claude_compaction_unlinked_parent_count,
    ownership_incomplete_file_count, cause, zero_snapshot_usage_evidence, dropped_usage_record_count,
    codex_parent_session_ref,
    source_session_id_seen);
crate::heap_layout_bound::fields!(OwnedJsonlParser; #[cfg(test)] source_read_probe, reader, accumulator, source, apply_line, recognized_usage_drop_count, positive_recognized_usage_count, positive_usage_evidence, claude_opened_birth; optional pending);

pub(in crate::snapshots) fn recognized_positive_usage_shape(
    source: SnapshotSource,
    value: &Value,
) -> bool {
    match source {
        SnapshotSource::Codex => codex_total_usage(value)
            .map(|usage| !usage.is_zero())
            .unwrap_or(false),
        SnapshotSource::ClaudeCode => claude_code_delta_usage(value)
            .map(|usage| !usage.is_zero())
            .unwrap_or(false),
        SnapshotSource::Pi => {
            pi_usage_event(value)
                && pi_message_usage(value)
                    .map(|usage| !usage.is_zero())
                    .unwrap_or(false)
        }
    }
}

pub(in crate::snapshots) fn recognized_usage_shape_was_dropped(
    source: SnapshotSource,
    value: &Value,
) -> bool {
    match source {
        SnapshotSource::Codex => {
            let recognized = value
                .pointer("/token_count/info/total_token_usage")
                .is_some()
                || value.pointer("/payload/info/total_token_usage").is_some()
                || value.pointer("/payload/total_token_usage").is_some()
                || value.pointer("/total_token_usage").is_some();
            recognized && codex_total_usage(value).is_none()
        }
        SnapshotSource::ClaudeCode => {
            let recognized = value.pointer("/message/usage").is_some()
                || value.pointer("/usage").is_some()
                || value.pointer("/payload/usage").is_some();
            recognized && claude_code_delta_usage(value).is_none()
        }
        SnapshotSource::Pi => {
            pi_usage_event(value)
                && pi_usage_value(value).is_some()
                && pi_message_usage(value).is_none()
        }
    }
}

fn json_has_positive_usage_evidence(value: &Value) -> bool {
    match value {
        Value::Object(values) => {
            let object_kind = json_usage_object_kind(values);
            values.iter().any(|(name, value)| {
                let normalized = normalized_usage_key(name);
                if json_usage_child_is_opaque(&normalized, object_kind) {
                    return false;
                }
                (is_recognized_usage_container(&normalized)
                    && usage_container_has_positive_consumption(value, false))
                    || json_has_positive_usage_evidence(value)
            })
        }
        Value::Array(values) => values.iter().any(json_has_positive_usage_evidence),
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonUsageObjectKind {
    ProviderEnvelope,
    AssistantMessage,
    OpaqueAuthored,
}

fn json_usage_object_kind(values: &serde_json::Map<String, Value>) -> JsonUsageObjectKind {
    let normalized = |key| {
        values
            .get(key)
            .and_then(Value::as_str)
            .map(normalized_usage_key)
    };
    if normalized("role").is_some_and(|role| matches!(role.as_str(), "assistant" | "model"))
        || normalized("type")
            .is_some_and(|kind| matches!(kind.as_str(), "assistantmessage" | "modelmessage"))
    {
        return JsonUsageObjectKind::AssistantMessage;
    }
    if normalized("role").is_some_and(|role| {
        matches!(
            role.as_str(),
            "user" | "human" | "system" | "developer" | "tool"
        )
    }) || normalized("type").is_some_and(|kind| {
        matches!(
            kind.as_str(),
            "user"
                | "human"
                | "system"
                | "developer"
                | "usermessage"
                | "tool"
                | "text"
                | "inputtext"
                | "outputtext"
                | "thinking"
                | "redactedthinking"
                | "tooluse"
                | "toolresult"
                | "toolcall"
                | "function"
                | "functioncall"
                | "functionresult"
                | "image"
                | "document"
        )
    }) {
        return JsonUsageObjectKind::OpaqueAuthored;
    }
    JsonUsageObjectKind::ProviderEnvelope
}

fn json_usage_child_is_opaque(name: &str, object_kind: JsonUsageObjectKind) -> bool {
    (object_kind == JsonUsageObjectKind::OpaqueAuthored && is_recognized_usage_container(name))
        || (object_kind != JsonUsageObjectKind::ProviderEnvelope
            && matches!(
                name,
                "content"
                    | "contents"
                    | "text"
                    | "prompt"
                    | "prompts"
                    | "argument"
                    | "arguments"
                    | "args"
                    | "toolinput"
                    | "tooloutput"
                    | "toolresult"
                    | "message"
                    | "payload"
                    | "data"
                    | "input"
                    | "output"
                    | "result"
            ))
}

fn normalized_usage_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_recognized_usage_container(name: &str) -> bool {
    matches!(
        name,
        "usage"
            | "tokenusage"
            | "totalusage"
            | "totaltokenusage"
            | "lasttokenusage"
            | "billingusage"
    )
}

fn is_consumption_metric(name: &str) -> bool {
    matches!(
        name,
        "input"
            | "output"
            | "inputtokens"
            | "outputtokens"
            | "prompttokens"
            | "completiontokens"
            | "cachedinputtokens"
            | "cacheread"
            | "cachereadtokens"
            | "cachereadinputtokens"
            | "cachewrite"
            | "cachewritetokens"
            | "cachecreationtokens"
            | "cachecreationinputtokens"
            | "reasoning"
            | "reasoningtokens"
            | "reasoningoutputtokens"
            | "unattributedtotaltokens"
            | "totaltokens"
            | "requestcount"
            | "requests"
    )
}

fn is_cost_container(name: &str) -> bool {
    matches!(
        name,
        "cost" | "costs" | "usagecost" | "usagecosts" | "billingcost" | "billingcosts"
    )
}

fn is_cost_metric(name: &str) -> bool {
    matches!(
        name,
        "total"
            | "amount"
            | "usd"
            | "totalcost"
            | "inputcost"
            | "outputcost"
            | "cachereadcost"
            | "cachewritecost"
            | "reasoningcost"
    )
}

fn is_nonconsumption_metadata(name: &str) -> bool {
    matches!(
        name,
        "version"
            | "schemaversion"
            | "usageversion"
            | "limit"
            | "limits"
            | "usagelimit"
            | "usagelimits"
            | "ratelimit"
            | "ratelimits"
            | "budget"
            | "budgets"
            | "quota"
            | "quotas"
            | "reset"
            | "resetsat"
            | "timestamp"
            | "createdat"
            | "updatedat"
            | "maxtokens"
    )
}

fn usage_container_has_positive_consumption(value: &Value, inside_cost: bool) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(name, value)| {
            let normalized = normalized_usage_key(name);
            if is_nonconsumption_metadata(&normalized) {
                return false;
            }
            if is_consumption_metric(&normalized) || (inside_cost && is_cost_metric(&normalized)) {
                return json_is_positive_number(value);
            }
            let child_inside_cost = inside_cost || is_cost_container(&normalized);
            usage_container_has_positive_consumption(value, child_inside_cost)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| usage_container_has_positive_consumption(value, inside_cost)),
        _ => false,
    }
}

fn json_is_positive_number(value: &Value) -> bool {
    let Value::Number(value) = value else {
        return false;
    };
    value.as_u64().is_some_and(|value| value > 0)
        || value.as_i64().is_some_and(|value| value > 0)
        || value.as_f64().is_some_and(|value| value > 0.0)
}

/// Existing parser report, including historical loss decoded from saved reductions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct JsonlReadReport {
    pub(in crate::snapshots) physical_line_count: usize,
    pub(in crate::snapshots) parsed_json_line_count: usize,
    pub(in crate::snapshots) malformed_json_line_count: usize,
    pub(in crate::snapshots) invalid_utf8_line_count: usize,
    pub(in crate::snapshots) over_line_cap_count: usize,
}

impl JsonlReadReport {
    pub(in crate::snapshots) fn complete(self) -> bool {
        self.malformed_json_line_count == 0 && self.invalid_utf8_line_count == 0
    }
}

pub(in crate::snapshots) fn read_bounded_jsonl_lines(
    reader: impl BufRead,
    on_value: impl FnMut(&Value),
) -> std::io::Result<JsonlReadReport> {
    read_bounded_jsonl_lines_impl(reader, on_value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) enum JsonlReaderStep {
    Line,
    Complete(JsonlReadReport),
}

/// The line-buffer release point, and the former maximum line size. It is not
/// an admission cap: a record of any size is read whole. Only the allocation of
/// a completed record above it is freed; at or below it, capacity is retained.
pub(crate) const LINE_BUFFER_RELEASE_BYTES: usize = 16 * 1024 * 1024;

/// End one physical record's buffer, for every JSONL line reader.
pub(crate) fn release_line_buffer(buf: &mut Vec<u8>) {
    if buf.len() > LINE_BUFFER_RELEASE_BYTES {
        *buf = Vec::new();
    } else {
        buf.clear();
    }
}

// Own the existing reader/buffer/report so a caller can move work between
// physical lines. No decoded row or transcript history crosses a step.
// This bounds work units, not blocking I/O or individual JSON parsing time.
pub(in crate::snapshots) struct BoundedJsonlReader<R> {
    pub(in crate::snapshots) reader: R,
    pub(in crate::snapshots) buf: Vec<u8>,
    pub(in crate::snapshots) report: JsonlReadReport,
    pub(in crate::snapshots) finished: bool,
    pub(in crate::snapshots) failure: Option<std::io::ErrorKind>,
    pub(in crate::snapshots) acquisition: Option<crate::transcript_acquisition::ReadPlan>,
    /// Resumable reads and sampled in-page Claude Full/Tail reads: never
    /// consume past this reader-relative frozen extent.
    pub(in crate::snapshots) extent_limit: Option<u64>,
    /// Physical bytes consumed from `reader`, including skipped bytes.
    consumed: u64,
    last_line_end: u64,
    /// Unterminated bytes at the frozen extent, awaiting unchanged-EOF proof.
    sealed_fragment: Option<()>,
    /// Set by `finish_job` or the in-page grown route: the identity `finish` may
    /// accept for a grown object. `Certified` after its prefix certificate
    /// passed (S12); `LossySameObject` is not a sealed-prefix
    /// certificate and permits only an uncertified publication.
    pub(in crate::snapshots) sealed_prefix: Option<sampled_scan::codex_cursor::FinishGrant>,
}

impl<R: BufRead> BoundedJsonlReader<R> {
    pub(in crate::snapshots) fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            report: JsonlReadReport::default(),
            finished: false,
            failure: None,
            acquisition: None,
            extent_limit: None,
            consumed: 0,
            last_line_end: 0,
            sealed_fragment: None,
            sealed_prefix: None,
        }
    }

    /// Freeze the readable extent (sealed-live mode). Bytes appended after
    /// the extent belong to a later read; an unterminated record at the
    /// extent is withheld, never parsed or counted, whether or not bytes past
    /// the extent are visible yet.
    pub(in crate::snapshots) fn set_extent_limit(&mut self, limit: u64) {
        self.extent_limit = Some(limit.max(self.consumed));
    }

    pub(in crate::snapshots) fn consumed_bytes(&self) -> u64 {
        self.consumed
    }

    /// End offset of the last newline-terminated record consumed.
    pub(in crate::snapshots) fn last_complete_line_end(&self) -> u64 {
        self.last_line_end
    }

    pub(in crate::snapshots) fn sealed_fragment(&self) -> bool {
        self.sealed_fragment.is_some()
    }

    /// Genuine unchanged EOF only (the caller proves it): apply the
    /// withheld final record from the bytes already buffered, exactly as a
    /// read without an extent applies its trailing line. No byte is read.
    pub(in crate::snapshots) fn apply_sealed_fragment(
        &mut self,
        mut on_value: impl FnMut(&Value),
    ) -> bool {
        if self.sealed_fragment.is_none()
            || !apply_physical_line(&self.buf, &mut self.report, None, &mut on_value, false)
        {
            return false;
        }
        self.sealed_fragment = None;
        release_line_buffer(&mut self.buf);
        true
    }

    pub(in crate::snapshots) fn step(
        &mut self,
        on_value: impl FnMut(&Value),
    ) -> std::io::Result<JsonlReaderStep> {
        self.step_lines(on_value, None)
    }

    pub(in crate::snapshots) fn step_lines(
        &mut self,
        on_value: impl FnMut(&Value),
        on_line: Option<line_delivery::LineTap<'_>>,
    ) -> std::io::Result<JsonlReaderStep> {
        if let Some(kind) = self.failure {
            return Err(std::io::Error::new(
                kind,
                "failed JSONL reader cannot resume",
            ));
        }
        if self.finished {
            return Ok(JsonlReaderStep::Complete(self.report));
        }
        self.buf.clear();
        let result = self.read_step(on_value, on_line);
        // Values have been consumed synchronously and dropped. Retain only the
        // existing buffer capacity; no logical raw row survives this return.
        // A withheld final record keeps its bytes until unchanged-EOF proof.
        if self.sealed_fragment.is_none() {
            release_line_buffer(&mut self.buf);
        }
        if let Err(error) = &result {
            // A partial physical line may already have been consumed. Resuming
            // after an I/O error would reinterpret its suffix or lose the row.
            self.failure = Some(error.kind());
        }
        result
    }

    fn read_step(
        &mut self,
        mut on_value: impl FnMut(&Value),
        on_line: Option<line_delivery::LineTap<'_>>,
    ) -> std::io::Result<JsonlReaderStep> {
        // Where this physical record started.
        let line_start = self.last_line_end;
        let reader = &mut self.reader;
        let buf = &mut self.buf;
        let report = &mut self.report;
        // Finish a whole physical record. `line_complete`
        // tracks whether we reached a newline (vs. EOF) so we can stop the
        // outer loop on a trailing partial line.
        let mut line_complete = false;
        let reached_eof = loop {
            let raw = reader.fill_buf()?;
            let allowed = self.extent_limit.map_or(raw.len(), |limit| {
                usize::try_from(limit.saturating_sub(self.consumed))
                    .unwrap_or(usize::MAX)
                    .min(raw.len())
            });
            if allowed == 0 {
                break true;
            }
            let available = &raw[..allowed];
            match available.iter().position(|&byte| byte == b'\n') {
                Some(offset) => {
                    buf.extend_from_slice(&available[..offset]);
                    if let Some(acquisition) = self.acquisition.as_mut() {
                        acquisition.observe_record_fragment(&available[..offset + 1], true)?;
                    }
                    reader.consume(offset + 1);
                    #[cfg(all(test, unix))]
                    sampled_scan::transition_fixture::record_consumed((offset + 1) as u64);
                    #[cfg(test)]
                    sampled_scan::codex_cursor::tests::NATIVE_RANGES.with(|v| {
                        if let Some(ranges) = v.borrow_mut().as_mut() {
                            ranges.push(self.consumed..self.consumed + (offset + 1) as u64);
                        }
                    });
                    self.consumed += (offset + 1) as u64;
                    self.last_line_end = self.consumed;
                    line_complete = true;
                    break false;
                }
                None => {
                    let len = available.len();
                    buf.extend_from_slice(available);
                    if let Some(acquisition) = self.acquisition.as_mut() {
                        acquisition.observe_record_fragment(available, false)?;
                    }
                    reader.consume(len);
                    #[cfg(all(test, unix))]
                    sampled_scan::transition_fixture::record_consumed(len as u64);
                    #[cfg(test)]
                    sampled_scan::codex_cursor::tests::NATIVE_RANGES.with(|v| {
                        if let Some(ranges) = v.borrow_mut().as_mut() {
                            ranges.push(self.consumed..self.consumed + len as u64);
                        }
                    });
                    self.consumed += len as u64;
                }
            }
        };
        crate::local_resource_diagnostics::jsonl::line_buffer(buf.capacity());
        if reached_eof && self.extent_limit.is_some() && !buf.is_empty() && !line_complete {
            // Sealed cursor completion (S5): a record without its newline at
            // or before the frozen extent is unfinished for this read, even if
            // no byte beyond the extent is visible yet. It is never parsed,
            // counted or certified. Reads without an extent keep the normal
            // trailing-line behavior below, byte-identical to before.
            self.sealed_fragment = Some(());
            self.finished = true;
            return Ok(JsonlReaderStep::Complete(*report));
        }
        if !line_complete && buf.is_empty() {
            // Clean EOF with no pending bytes.
            self.finished = true;
            return Ok(JsonlReaderStep::Complete(*report));
        }

        if !apply_physical_line(
            buf,
            report,
            // An unterminated trailing line reaches money only, never LD.
            on_line.filter(|_| line_complete).map(|tap| {
                (
                    self.consumed - line_start,
                    self.acquisition
                        .as_ref()
                        .map_or(0, |plan| plan.start_offset())
                        .saturating_add(self.consumed),
                    tap,
                )
            }),
            &mut on_value,
            line_complete,
        ) {
            // A paused compatibility writer has the same pending suffix as
            // an extent-bound read. Valid JSON/blank EOF keeps its semantics.
            self.sealed_fragment = Some(());
        }
        self.finished = reached_eof;
        Ok(JsonlReaderStep::Line)
    }
}

/// Count and apply one physical line held in `buf` (newline-terminated, or a
/// trailing line at EOF). Shared by every read path; `deliver` is LD's tap.
fn apply_physical_line(
    buf: &[u8],
    report: &mut JsonlReadReport,
    deliver: Option<(u64, u64, line_delivery::LineTap<'_>)>,
    on_value: &mut impl FnMut(&Value),
    terminal: bool,
) -> bool {
    #[cfg(test)]
    codex_zst_refusal_tests::jsonl_parse_attempted();
    let decoded = match jsonl_line_text(buf) {
        JsonlLineText::Blank => Ok(None),
        JsonlLineText::Text(line) => serde_json::from_str(line).map(Some).map_err(|_| false),
        JsonlLineText::InvalidUtf8 => Err(true),
    };
    // Unchanged EOF proves no growth, not that a paused writer finished JSON.
    if !terminal && decoded.is_err() {
        return false;
    }
    report.physical_line_count += 1;
    crate::local_resource_diagnostics::jsonl::line(buf.len());
    let value = match decoded {
        Ok(Some(value)) => {
            report.parsed_json_line_count += 1;
            Some(value)
        }
        Ok(None) => None,
        Err(utf8) => {
            report.invalid_utf8_line_count += usize::from(utf8);
            report.malformed_json_line_count += usize::from(!utf8);
            None
        }
    };
    if let Some((length, end, tap)) = deliver {
        let value = value.as_ref();
        tap(length, &line_delivery::PhysicalLine { end, value });
    }
    if let Some(value) = value {
        on_value(&value);
    }
    true
}

fn read_bounded_jsonl_lines_impl(
    reader: impl BufRead,
    mut on_value: impl FnMut(&Value),
) -> std::io::Result<JsonlReadReport> {
    let mut state = BoundedJsonlReader::new(reader);
    loop {
        match state.step(&mut on_value)? {
            JsonlReaderStep::Line => {}
            JsonlReaderStep::Complete(report) => return Ok(report),
        }
    }
}

// Content projection shared with growth-only durable replay. Keep native N/U
// processing at its existing call sites; these helpers never publish usage.
enum JsonlLineText<'a> {
    Blank,
    InvalidUtf8,
    Text(&'a str),
}
fn jsonl_line_text(mut bytes: &[u8]) -> JsonlLineText<'_> {
    if bytes.last() == Some(&b'\r') {
        bytes = &bytes[..bytes.len() - 1];
    }
    match std::str::from_utf8(bytes) {
        Ok(line) if line.trim().is_empty() => JsonlLineText::Blank,
        Ok(line) => JsonlLineText::Text(line),
        Err(_) => JsonlLineText::InvalidUtf8,
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for BoundedJsonlReader<OpenedInput> {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            reader,
            buf,
            report,
            finished,
            failure,
            acquisition,
            extent_limit,
            consumed,
            last_line_end,
            sealed_fragment,
            sealed_prefix,
        } = self;
        c.add(reader.capacity())?;
        buf.heap_bound(c)?;
        report.heap_bound(c)?;
        finished.heap_bound(c)?;
        // ErrorKind is inline; File holds the existing OS handle, no new Rust buffer.
        let _ = failure;
        extent_limit.heap_bound(c)?;
        consumed.heap_bound(c)?;
        last_line_end.heap_bound(c)?;
        sealed_fragment.heap_bound(c)?;
        sealed_prefix.heap_bound(c)?;
        acquisition.heap_bound(c)
    }
}

crate::heap_layout_bound::fields!(JsonlReadReport; physical_line_count, parsed_json_line_count, malformed_json_line_count, invalid_utf8_line_count, over_line_cap_count);
crate::durable_tail_codec::durable_struct!(JsonlReadReport {
    N physical_line_count: usize,
    N parsed_json_line_count: usize,
    N malformed_json_line_count: usize,
    N invalid_utf8_line_count: usize,
    N over_line_cap_count: usize,
});
