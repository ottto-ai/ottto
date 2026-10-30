//! Growth-only replay of native content projection. The caller owns the active
//! lease, certificate, pacing and input admission; scratch never publishes money.
use super::bounded_value::{BoundedValue, LineMeter, LINE_VALUE_CREDIT};
use super::*;
use serde::de::DeserializeSeed;
use std::os::unix::fs::FileExt;

pub(crate) struct RederivePlan {
    pub(crate) end: u64,
    pub(crate) title: Option<(u64, u64)>,
    pub(crate) charge: u64,
}
impl RederivePlan {
    pub(crate) fn input_bytes(&self) -> u64 {
        self.end + self.title.map_or(0, |(_, n)| n)
    }
}

// Isolate construction's debug temporary from the recursive JSON visitor frame.
#[inline(never)]
fn scratch(source: SnapshotSource) -> Box<SnapshotAccumulator> {
    Box::new(SnapshotAccumulator::new(source))
}

impl Decoded {
    #[cfg(test)]
    pub(crate) fn content_charge(&self) -> Result<u64, RederiveUnfunded> {
        self.rederive_plan()
            .map(|p| p.charge)
            .map_err(|_| RederiveUnfunded)
    }
    #[cfg(test)]
    pub(crate) fn rederive_content(
        self,
        file: &File,
    ) -> Result<(CachedJsonlReduction, RederiveReceipt), Refuse> {
        let plan = self.rederive_plan().map_err(Refuse::NotRederivable)?;
        self.rederive_content_planned(file, &plan)
            .map(|(r, receipt, _)| (r, receipt))
    }
    pub(crate) fn content_classes(&self) -> [bool; 5] {
        let r = &self.rederive;
        [
            r.first_prompt.is_some(),
            r.title.is_some(),
            r.agent_label.is_some(),
            r.session_start.is_some(),
            r.workspace.is_some(),
        ]
    }
    pub(crate) fn has_content(&self) -> bool {
        self.rederive != Rederive::default()
    }

    pub(crate) fn rederive_plan(&self) -> Result<RederivePlan, &'static str> {
        if !self.has_content() {
            return Ok(RederivePlan {
                end: 0,
                title: None,
                charge: 0,
            });
        }
        let acc = &self.reduction.accumulator;
        if acc.source == SnapshotSource::Codex {
            match acc.codex_ownership_boundary {
                CodexOwnershipBoundary::AllLocal => {
                    if acc.codex_legacy_trigger_seen {
                        return Err("legacy");
                    }
                    if acc.codex_parent_ledger_consulted
                        || acc.codex_parent_signature_index != 0
                        || acc.codex_parent_prefix_decided.is_some()
                    {
                        return Err("parent");
                    }
                }
                CodexOwnershipBoundary::Ordinal { .. }
                | CodexOwnershipBoundary::NativeCreatedThread => {}
                CodexOwnershipBoundary::AwaitingLegacyTrigger => return Err("legacy"),
                CodexOwnershipBoundary::AwaitingParentPrefix => return Err("parent"),
                CodexOwnershipBoundary::AmbiguousFork => return Err("ambiguous"),
                CodexOwnershipBoundary::Undetermined => return Err("undetermined"),
            }
            if acc.codex_proof_decision_only {
                return Err("parent");
            }
        }
        let end = self.head_end().map_err(|_| "mark")?;
        let title = self.title_line(end).map_err(|_| "title")?;
        let t = title.map_or(0, |(_, n)| n);
        if title.is_some_and(|(offset, n)| {
            n == 0 || n > TITLE_LINE_BOUND || offset.checked_add(n).is_none()
        }) {
            return Err("title");
        }
        let input = end.checked_add(t).ok_or("charge")?;
        let line = end.max(t);
        // Requested-allocation ledger, simultaneous replay phase:
        // input + serde scratch (2L) + Value (8 MiB) + fold string temporaries
        // (4L) + retained X (2 input) + response keys (end+64) + SS (512 KiB).
        // An independent 8 MiB covers reference-vector old/new backing while
        // Value arrays are live; it is never double-spent as Value credit.
        // Reducer includes closed filter/ring and capped native ids. Copying
        // source_session_id has its own term. Fixed errors/frames: 64 KiB.
        let charge = input
            .checked_mul(3)
            .and_then(|n| n.checked_add(line.checked_mul(6)?))
            .and_then(|n| n.checked_add(2 * LINE_VALUE_CREDIT))
            .and_then(|n| n.checked_add(end.checked_add(64)?))
            .and_then(|n| n.checked_add(524_288 + 65_536))
            .and_then(|n| n.checked_add(codex_usage_occurrence::max_fixed_heap_bytes() as u64))
            .and_then(|n| {
                n.checked_add(acc.source_session_id.as_ref().map_or(0, |s| s.len() as u64))
            })
            .ok_or("charge")?;
        const _: () =
            assert!(size_of::<SnapshotAccumulator>() + size_of::<RederiveReceipt>() < 65_536);
        Ok(RederivePlan { end, title, charge })
    }

    /// All fences precede every X move. Errors carry fixed class names only.
    pub(crate) fn rederive_content_planned(
        mut self,
        file: &File,
        plan: &RederivePlan,
    ) -> Result<(CachedJsonlReduction, RederiveReceipt, u64), Refuse> {
        if !self.has_content() {
            return Ok((self.reduction, RederiveReceipt::default(), 0));
        }
        let source = self.reduction.accumulator.source;
        let mut fresh = scratch(source);
        let stored = &self.reduction.accumulator;
        fresh.source_session_id = stored.source_session_id.clone();
        fresh.codex_counting = stored
            .codex_counting
            .as_ref()
            .map(|c| Box::new(c.content_scratch()));
        let boundary = stored.codex_ownership_boundary;
        let session_end = stored.session_start.durable_content_end().unwrap_or(0);
        let mut head = vec![0; plan.end as usize];
        read_at(file, source, &mut head, 0)?;
        let mut window = ClaudeResponseWindow::default();
        let mut offset = 0;
        let mut peak = 0;
        for line in head.split_inclusive(|b| *b == b'\n') {
            if line.last() != Some(&b'\n') {
                return Err(Refuse::NotRederivable("head_line"));
            }
            offset += line.len() as u64;
            replay_line(
                source,
                &line[..line.len() - 1],
                &mut peak,
                |value, meter| {
                    let opening = self.rederive.session_start.is_some() && offset <= session_end;
                    let shell_line = match source {
                        SnapshotSource::ClaudeCode => value
                            .pointer("/message/content")
                            .and_then(Value::as_array)
                            .is_some_and(|items| {
                                items.iter().any(|item| {
                                    string_eq_at(item, &["type"], "tool_use")
                                        && string_eq_at(item, &["name"], "Bash")
                                })
                            }),
                        SnapshotSource::Codex => string_at(value, &["payload", "type"])
                            .or_else(|| string_at(value, &["type"]))
                            .is_some_and(|kind| {
                                matches!(kind.as_str(), "exec_command_end" | "item_completed")
                            }),
                        SnapshotSource::Pi => false,
                    };
                    if opening && fresh.session_start.content_window_open() && shell_line {
                        // Shell token fan-out is derived from a string, not from a
                        // charged Value array. Pay it separately before the fold.
                        let separators = line
                            .iter()
                            .filter(|b| {
                                b.is_ascii_whitespace()
                                    || matches!(
                                        **b,
                                        b'\\'
                                            | b'\''
                                            | b'"'
                                            | b';'
                                            | b'|'
                                            | b'&'
                                            | b'('
                                            | b')'
                                            | b'<'
                                            | b'>'
                                            | b'`'
                                    )
                                    || **b >= 128
                            })
                            .count() as u64;
                        meter.charge::<serde_json::Error>(separators.checked_mul(48))?;
                    }
                    match source {
                        SnapshotSource::ClaudeCode => {
                            match claude_fork_line_provenance(value) {
                                ClaudeForkLineProvenance::Inherited => {
                                    fresh.session_start.note_inherited_prefix();
                                    return Ok(());
                                }
                                ClaudeForkLineProvenance::Invalid => return Ok(()),
                                ClaudeForkLineProvenance::None => {}
                            }
                            claude_prompt_content(value, &mut fresh);
                            claude_workspace_content(value, &mut fresh);
                            window.observe(value);
                            if opening {
                                fresh.session_start.observe_claude_line(
                                    value,
                                    window.sequence,
                                    fresh.workspace_path.as_deref(),
                                );
                            }
                        }
                        SnapshotSource::Codex => {
                            if let Some(meta) = codex_session_meta_payload(value) {
                                if !fresh.codex_session_meta_seen {
                                    if let Some(src) = meta.get("source").filter(|v| v.is_object())
                                    {
                                        codex_agent_content(src, &mut fresh);
                                    }
                                    codex_header_workspace_content(meta, &mut fresh);
                                    fresh.codex_session_meta_seen = true;
                                    fresh.codex_ownership_boundary = boundary;
                                }
                            }
                            if opening && string_eq_at(value, &["type"], "session_meta") {
                                fresh.session_start.note_codex_session_meta(value);
                            }
                            if !fresh.codex_record_is_owned(value) {
                                return Ok(());
                            }
                            if opening {
                                codex_opening_content(value, &mut fresh);
                            }
                            if string_eq_at(value, &["payload", "type"], "task_started") {
                                codex_user_turn_content(value, &mut fresh);
                            }
                            codex_prompt_content(value, &mut fresh);
                            codex_workspace_content(value, &mut fresh);
                            fresh.observe_codex_content_counting(value);
                            if let Some(usage) = codex_total_usage(value) {
                                let last = codex_last_usage(value);
                                let identity = codex_usage_event_identity(value);
                                let count =
                                    (!codex_total_usage_has_request_count(value)).then_some(1);
                                let admitted = if fresh.codex_counting_v2() {
                                    fresh
                                        .decide_codex_usage(
                                            None,
                                            usage,
                                            last.clone(),
                                            identity,
                                            count,
                                        )
                                        .is_some()
                                } else {
                                    fresh
                                        .decide_codex_legacy_usage(
                                            None,
                                            usage,
                                            last.clone(),
                                            identity,
                                            count,
                                        )
                                        .is_some()
                                };
                                if opening && admitted {
                                    if let Some(last) = last {
                                        fresh.session_start.note_codex_request(&last);
                                    }
                                }
                            }
                        }
                        SnapshotSource::Pi => {
                            if string_eq_at(value, &["type"], "session") {
                                pi_workspace_content(value, &mut fresh);
                            }
                            if string_eq_at(value, &["type"], "message") {
                                pi_prompt_content(
                                    value,
                                    pi_message_role(value).as_deref(),
                                    &mut fresh,
                                );
                            }
                        }
                    }
                    Ok(())
                },
            )?;
        }
        if let Some((offset, len)) = plan.title {
            let mut line = vec![0; len as usize];
            read_at(file, source, &mut line, offset)?;
            replay_line(
                source,
                line.strip_suffix(b"\n").unwrap_or(&line),
                &mut peak,
                |value, _| {
                    match source {
                        SnapshotSource::ClaudeCode
                            if matches!(
                                claude_fork_line_provenance(value),
                                ClaudeForkLineProvenance::None
                            ) =>
                        {
                            claude_title_content(value, &mut fresh)
                        }
                        SnapshotSource::Codex => {
                            fresh.set_title(codex_transcript_title(value), "transcript_title")
                        }
                        _ => {}
                    }
                    Ok(())
                },
            )?;
        }
        sampled_scan::durable_tail::record_rederive_line_peak(source, peak);
        let r = &self.rederive;
        let matches = [
            r.first_prompt
                .map(|h| first_prompt_digest(&fresh).map(|got| got == h))
                .transpose()?,
            r.title
                .map(|h| title_digest(&fresh).map(|got| got == h))
                .transpose()?,
            r.agent_label
                .map(|h| agent_label_digest(&fresh).map(|got| got == h))
                .transpose()?,
            r.session_start
                .map(|h| {
                    fresh
                        .session_start
                        .durable_content_hash()
                        .map(|got| got == h)
                })
                .transpose()?,
            r.workspace
                .map(|h| workspace_digest(&fresh).map(|got| got == h))
                .transpose()?,
        ];
        if matches.contains(&Some(false)) {
            sampled_scan::durable_tail::record_rederive_fence(
                source,
                matches.map(|m| m == Some(false)),
            );
            return Err(Refuse::NotRederivable("content_fence"));
        }
        let acc = &mut self.reduction.accumulator;
        if r.first_prompt.is_some() {
            acc.first_prompt_material = fresh.first_prompt_material.take();
            acc.first_prompt_title = fresh.first_prompt_title.take();
        }
        if r.title.is_some() {
            acc.title = fresh.title.take();
        }
        if r.workspace.is_some() {
            acc.workspace_path = fresh.workspace_path.take();
        }
        if r.agent_label.is_some() {
            acc.codex_agent_label = fresh.codex_agent_label.take();
        }
        if r.session_start.is_some() {
            acc.session_start
                .adopt_durable_content(&mut fresh.session_start);
        }
        // Keep a conservative retained-X charge; everything else drops before
        // the caller refunds. Includes copied SS graph and string ownership.
        let retained = 2 * plan.input_bytes() + 524_288;
        Ok((
            self.reduction,
            RederiveReceipt {
                head_bytes: plan.end,
                named_lines: u64::from(plan.title.is_some()),
                line_bytes: plan.title.map_or(0, |(_, n)| n),
            },
            retained,
        ))
    }
}

#[derive(Default)]
struct ClaudeResponseWindow {
    keys: Vec<String>,
    sequence: u64,
}
impl ClaudeResponseWindow {
    fn observe(&mut self, value: &Value) {
        if self.sequence >= 3 || claude_code_delta_usage(value).is_none() {
            return;
        }
        let key = claude_response_key(value, self.sequence);
        if !self.keys.contains(&key) {
            self.keys.push(key);
            self.sequence += 1;
        }
    }
}
#[cfg(test)]
type ContentReadHook = Option<Box<dyn FnMut(u64)>>;
#[cfg(test)]
thread_local! {
    static AFTER_CONTENT_READ: std::cell::RefCell<ContentReadHook> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn with_read_hook<T>(hook: impl FnMut(u64) + 'static, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            AFTER_CONTENT_READ.with(|slot| slot.borrow_mut().take());
        }
    }
    AFTER_CONTENT_READ.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Box::new(hook));
    });
    let _reset = Reset;
    run()
}

fn read_at(file: &File, source: SnapshotSource, bytes: &mut [u8], at: u64) -> Result<(), Refuse> {
    let mut offset = 0;
    while offset < bytes.len() {
        #[cfg(test)]
        sampled_scan::durable_tail::record_rederive_read_call();
        let n = match file.read_at(&mut bytes[offset..], at + offset as u64) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(0) | Err(_) => return Err(Refuse::NotRederivable("content_read")),
            Ok(n) => n,
        };
        sampled_scan::durable_tail::record_rederive_input(source, n as u64);
        #[cfg(test)]
        AFTER_CONTENT_READ.with(|slot| {
            if let Some(hook) = slot.borrow_mut().as_mut() {
                hook(at + offset as u64);
            }
        });
        offset += n;
    }
    Ok(())
}
fn replay_line(
    source: SnapshotSource,
    bytes: &[u8],
    peak: &mut u64,
    fold: impl FnOnce(&Value, &mut LineMeter) -> Result<(), serde_json::Error>,
) -> Result<(), Refuse> {
    let JsonlLineText::Text(text) = jsonl_line_text(bytes) else {
        return Ok(());
    };
    let mut meter = LineMeter::new();
    let mut d = serde_json::Deserializer::from_str(text);
    let folded = if let Ok(value) = BoundedValue(&mut meter)
        .deserialize(&mut d)
        .and_then(|value| {
            d.end()?;
            Ok(value)
        }) {
        fold(&value, &mut meter).map_err(|_| Refuse::NotRederivable("content_credit"))
    } else {
        Ok(())
    };
    *peak = (*peak).max(meter.used());
    sampled_scan::durable_tail::record_rederive_line_peak(source, *peak);
    folded?;
    if let Some(reason) = meter.stop {
        return Err(Refuse::NotRederivable(reason));
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::snapshots) fn test_codex_content_scratch(
    stored: &SnapshotAccumulator,
) -> Box<SnapshotAccumulator> {
    let mut fresh = scratch(SnapshotSource::Codex);
    fresh.source_session_id = stored.source_session_id.clone();
    fresh.codex_counting = stored
        .codex_counting
        .as_ref()
        .map(|c| Box::new(c.content_scratch()));
    fresh
}
