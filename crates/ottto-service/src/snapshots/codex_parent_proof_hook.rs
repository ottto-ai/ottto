//! U1a-2a row 31 (rev 3 §2.4–§2.6, rev 9 §6.1–§6.2, rev 11 §5.3–§6.1): the
//! proof hook. Once per Codex page, after the page's candidates, on the
//! singleton budget main left: prune, take the process-wide proof holder,
//! visit the owed entries, start, step, suspend or finish one proof job.
//! Main's candidates, slot, rotation and budgets are never touched; a job
//! reads only what main left this page.
use super::*;
use crate::local_resource_diagnostics::codex_side_lifecycle::{record as count, Event};
use sampled_scan::codex_cursor::{Limits, OpenStamp, PageBudget, ProofJob, ProofLease, ProofTake};

/// Owed entries one visit reads, in key order after the cursor (rev 2 R2-B1).
const CODEX_PROOF_VISIT_KEYS: usize = 64;
/// The head and at most three later due children of the head's parent.
const CODEX_PROOF_BATCH: usize = 4;
// A retired job keeps every entry's `seq` (owner note 3).
const _: () = assert!(CODEX_PROOF_BATCH <= sampled_scan::codex_cursor::RETIRED_PROOF_ENTRIES);

/// What a visit hands the hook.
#[derive(Debug, Default)]
pub(super) struct ProofVisit {
    /// The head's parent and every batched (child key, `seq`).
    pub(super) batch: Option<(String, Vec<(String, u64)>)>,
    /// The cursor to restore when the batch does not start (rev 2 R2-B1:
    /// "when nothing starts, the cursor stops before the head").
    pub(super) before_head: Option<String>,
    /// Kept proofs re-fenced (each re-read P's two samples).
    pub(super) refenced: u64,
    /// Fix round 4 (AutoReview #2): entries a re-fence made `Proven` again
    /// (at most the visit's keys), whose hold memos the hook ends.
    pub(super) reproven: Vec<String>,
}

/// The change that can cure an outcome (rev 3 §1.6), before its stamps.
#[derive(Clone, Debug)]
enum WakeOf {
    ParentChanged,
    ChildChanged,
    Rewritten {
        parent: bool,
    },
    Census(String),
    /// Boxed: the error side of the finish's checks stays small.
    Held(Box<ProofWake>),
    Backoff,
}

/// The wake an outcome keeps, from P's and the child's stamps now. A
/// missing stamp it needs: `Backoff` (time only).
fn proof_wake(of: &WakeOf, parent: Option<&OpenStamp>, child: Option<&OpenStamp>) -> ProofWake {
    let both = parent.cloned().zip(child.cloned());
    match of {
        WakeOf::ParentChanged => both.map_or(ProofWake::Backoff, |(parent, child)| {
            ProofWake::ParentChanged { parent, child }
        }),
        WakeOf::ChildChanged => both.map_or(ProofWake::Backoff, |(parent, child)| {
            ProofWake::ChildChanged { parent, child }
        }),
        WakeOf::Rewritten { parent: true } => {
            both.map_or(ProofWake::Backoff, |(parent, child)| ProofWake::Rewritten {
                parent: Some(parent),
                child,
            })
        }
        WakeOf::Rewritten { parent: false } => {
            child
                .cloned()
                .map_or(ProofWake::Backoff, |child| ProofWake::Rewritten {
                    parent: None,
                    child,
                })
        }
        WakeOf::Census(matches) => {
            child
                .cloned()
                .map_or(ProofWake::Backoff, |child| ProofWake::Census {
                    matches: matches.clone(),
                    child,
                })
        }
        WakeOf::Held(wake) => (**wake).clone(),
        WakeOf::Backoff => ProofWake::Backoff,
    }
}

/// The census fingerprint of P's resolved id (a `Census` wake's `matches`):
/// which key the frozen census resolves it to, if exactly one.
fn codex_parent_census_fingerprint(census: CodexParentCensus<'_>, parent: &str) -> String {
    match codex_parent_census_matches(census, &[parent])[0] {
        CodexCensusMatch::Absent => "absent".to_owned(),
        CodexCensusMatch::Duplicated => "duplicated".to_owned(),
        CodexCensusMatch::One(key) => format!("one:{key}"),
    }
}

fn held_stamp(reader: &CodexProofReader) -> Option<OpenStamp> {
    OpenStamp::capture(reader.parser.reader.reader.get_ref()).ok()
}

/// The proof hook (rev 3 §2.4). `pass` is the page's C14 pass, `now` the
/// hook's clock. Every byte it reads is charged to `page`'s singleton
/// budget.
pub(super) fn codex_parent_proof_step(
    index: &mut ScanIndex,
    context: &sampled_scan::Context,
    pass: &CodexSidePass,
    identities: &CodexParentIdentities,
    page: &mut PageBudget,
    now: u64,
) {
    // Stage 1 (parent r79): a continuation page runs no part of the hook,
    // not even a held job's step or suspend.
    if !pass.proof_hook_allowed() {
        return;
    }
    let side = Some((&*context.cache, pass.ns));
    let census_valid = identities.census_valid();
    // R2-M1: a pass the side gate closes (the outage after a failed save;
    // with Stage 1, a continuation page) starts and finishes no proof. A
    // held job only steps fd-only and suspends.
    let side_allowed = pass.gate.side_allowed;
    // Step 1: prune first, metadata only, whatever the holder or budget.
    if pass.sweep_allowed() {
        index.sweep_codex_parent_side(census_valid, side, now);
    }
    // A job never binds to an unminted index (row 35). Only proof work
    // adopts the incarnation (its first binding use).
    let incarnation = if index.codex_parent_prefix_proofs.is_empty() {
        index.codex_proof_index_incarnation.clone()
    } else {
        index.codex_proof_incarnation_in_use().to_owned()
    };
    if incarnation.is_empty() {
        return;
    }
    // Owner note 3 (r79): a job of this index that main retired (or another
    // index dropped) while suspended backs every entry off before the visit,
    // so main's retirements pace restarts instead of repeating them. Only on
    // a side-allowed page (fix round 2, R2-L3): on a save outage the ring
    // entry waits, so a failed save cannot lose the backoff (no Free start
    // happens before the gate opens).
    let retired = if side_allowed {
        context
            .cache
            .take_retired_proof_seqs(&context.namespace, &pass.index_path, &incarnation)
    } else {
        Vec::new()
    };
    if !retired.is_empty() {
        let entries = index
            .codex_parent_prefix_proofs
            .iter()
            .filter_map(|(key, state)| match state {
                CodexParentProofState::Owed(owed) if retired.contains(&owed.seq) => {
                    Some((key.clone(), owed.seq))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for (key, seq) in entries {
            index.finish_codex_parent_proof_entry(
                &key,
                seq,
                &incarnation,
                ProofFinish::Attempt {
                    outcome: ProofOutcome::MemoryRefused,
                    wake: ProofWake::Backoff,
                },
                now,
            );
        }
    }
    let reserve = codex_proof_step_reserve();
    let mut lease =
        match context
            .cache
            .proof_take(&context.namespace, &pass.index_path, &incarnation)
        {
            ProofTake::Busy => {
                context.cache.note_proof_hook(&context.namespace, false);
                return;
            }
            ProofTake::Mine(mut lease) => {
                context.cache.note_proof_hook(&context.namespace, true);
                let job = lease.job();
                let valid = job.readers.as_deref().is_some_and(|readers| {
                    codex_proof_job_still_valid(&*index, identities, readers)
                });
                if !valid {
                    // Revalidation failed: every entry records `Invalidated`.
                    let entries = std::mem::take(&mut job.entries);
                    for (key, seq) in entries {
                        index.finish_codex_parent_proof_entry(
                            &key,
                            seq,
                            &incarnation,
                            ProofFinish::Attempt {
                                outcome: ProofOutcome::Invalidated,
                                wake: ProofWake::Backoff,
                            },
                            now,
                        );
                    }
                    lease.finish();
                    return;
                }
                lease
            }
            ProofTake::Free => {
                // Visit and start wait for a valid, side-allowed page (rev 9
                // §6.2, R2-M1).
                if !census_valid || !side_allowed {
                    context.cache.note_proof_hook(&context.namespace, false);
                    return;
                }
                let leftover = page.singleton_remaining(Limits::current());
                let visit = index.visit_codex_parent_proofs(identities, now, side, leftover);
                // R1-M1: each re-fence is P's side fence and the proof seal.
                page.charge(false, visit.refenced.saturating_mul(PROOF_FENCE_READ_BYTES));
                forget_proven_hold_memos(index, context, &visit.reproven);
                let Some((parent, entries)) = visit.batch else {
                    context.cache.note_proof_hook(&context.namespace, false);
                    return;
                };
                context.cache.note_proof_hook(&context.namespace, true);
                if page.singleton_remaining(Limits::current()) < reserve {
                    // No leftover for one step: nothing starts (counted).
                    index.codex_parent_proof_cursor = visit.before_head;
                    count(Event::ProofDrop);
                    return;
                }
                // R1-L4: P's side fence once (charged) before P is read; the
                // finish fence stays authoritative.
                page.charge(false, SIDE_FENCE_READ_BYTES);
                if let Some((outcome, wake)) =
                    codex_proof_parent_prefence(index, identities, &parent, now, side)
                {
                    for (key, seq) in entries {
                        index.finish_codex_parent_proof_entry(
                            &key,
                            seq,
                            &incarnation,
                            ProofFinish::Attempt {
                                outcome,
                                wake: wake.clone(),
                            },
                            now,
                        );
                    }
                    return;
                }
                let (readers, started, refused) =
                    start_codex_proof_job(index, identities, &parent, entries, now);
                for (key, seq, outcome, of, child) in refused {
                    index.finish_codex_parent_proof_entry(
                        &key,
                        seq,
                        &incarnation,
                        ProofFinish::Attempt {
                            outcome,
                            wake: proof_wake(&of, None, child.as_ref()),
                        },
                        now,
                    );
                }
                let Some(readers) = readers else {
                    return;
                };
                ProofLease::new(
                    &context.cache,
                    Box::new(ProofJob {
                        namespace: context.namespace.0.clone(),
                        index_path: pass.index_path.clone(),
                        incarnation: incarnation.clone(),
                        entries: started,
                        next_row_end: reserve,
                        touched_page: 0,
                        readers: Some(Box::new(readers)),
                    }),
                )
            }
        };
    // Memory (R2-B1, rev 5/6 §5.1): every step must fit the proof's room
    // less the rest of the job (`run` re-checks the readers before each).
    let room = codex_proof_readers_room(context, lease.job());
    let mut budget = page.singleton_remaining(Limits::current());
    let before = budget;
    let run = match lease.job().readers.as_deref_mut() {
        Some(readers) => readers.run(&mut budget, room),
        None => CodexProofRun::Done,
    };
    page.charge(false, before.saturating_sub(budget));
    // R2-B2: a job dropped for memory or the holder backs every entry off
    // (`after_attempt` paces the restart).
    let entries = lease.job().entries.clone();
    let back_off = |index: &mut ScanIndex, outcome: ProofOutcome| {
        for (key, seq) in &entries {
            index.finish_codex_parent_proof_entry(
                key,
                *seq,
                &incarnation,
                ProofFinish::Attempt {
                    outcome,
                    wake: ProofWake::Backoff,
                },
                now,
            );
        }
    };
    match run {
        CodexProofRun::Memory => {
            count(Event::ProofDrop);
            lease.finish();
            back_off(index, ProofOutcome::StepRefusedMemory);
        }
        CodexProofRun::Done if census_valid && side_allowed => {
            // R2-L3: P's side fence and the commit's samples.
            page.charge(false, PROOF_FENCE_READ_BYTES);
            finish_codex_proof_job(index, identities, lease.job(), now, side);
            forget_proven_hold_memos(index, context, entries.iter().map(|(key, _)| key));
            lease.finish();
        }
        // The budget ended the page, or finish waits for a valid,
        // side-allowed page (a RAM job keeps its FDs meanwhile).
        CodexProofRun::Budget | CodexProofRun::Done => {
            if !lease.suspend() {
                back_off(index, ProofOutcome::MemoryRefused);
            }
        }
    }
}

/// U1a-2a (fix round 4, AutoReview #2): each of `keys` whose entry is now
/// `Proven` ends its child's singleton hold memo in this namespace
/// (`memo_forget`, the memo's own custody), so the child's next page parses
/// and reaches `install_codex_parent_proof` instead of replaying the hold
/// the memo recorded before the proof existed. Other memos are untouched.
fn forget_proven_hold_memos<'a>(
    index: &ScanIndex,
    context: &sampled_scan::Context,
    keys: impl IntoIterator<Item = &'a String>,
) {
    for key in keys {
        if matches!(
            index.codex_parent_prefix_proofs.get(key),
            Some(CodexParentProofState::Proven(_))
        ) {
            context
                .cache
                .memo_forget(&sampled_scan::codex_cursor::memo_key(
                    &context.namespace,
                    key,
                ));
        }
    }
}

/// R2-B1: the room `run` checks the readers against: `proof_room` less the
/// job's walk outside its readers. None fits: 0 (no step).
fn codex_proof_readers_room(context: &sampled_scan::Context, job: &ProofJob) -> usize {
    let walked = crate::heap_layout_bound::bound(job, usize::MAX);
    let readers = job.readers.as_deref().map_or(Some(0), |readers| {
        crate::heap_layout_bound::bound(readers, usize::MAX)
    });
    sampled_scan::codex_cursor::proof_room(context)
        .zip(walked.zip(readers))
        .and_then(|(room, (walked, readers))| room.checked_sub(walked.saturating_sub(readers)))
        .unwrap_or(0)
}

/// The outcome a P side fence that did not admit gives every entry.
fn codex_proof_held_outcome(fenced: SideFence) -> ProofOutcome {
    match fenced {
        SideFence::FileCapHeld => ProofOutcome::FileCapHeld,
        SideFence::Unreadable => ProofOutcome::SideUnreadable,
        SideFence::Stale => ProofOutcome::SideStale,
        SideFence::Held { lineage: true, .. } => ProofOutcome::LineageHeld,
        _ => ProofOutcome::ParentHeld,
    }
}

/// R1-L4: P's side fence at P's current size, before P is read. `Some`:
/// the outcome and wake every entry records with no read, when P's record
/// neither admits nor is only behind P's growth (`Stale`, which a main
/// parse may cure before the finish). A P that does not locate is left to
/// the start (`Identity`).
fn codex_proof_parent_prefence(
    index: &mut ScanIndex,
    identities: &CodexParentIdentities,
    parent: &str,
    now: u64,
    side: Option<(&sampled_scan::SharedCache, u128)>,
) -> Option<(ProofOutcome, ProofWake)> {
    let (p_key, mut file) = codex_parent_locate(identities.census(index), parent).ok()?;
    let size = file.metadata().ok()?.len();
    let fenced = index.codex_parent_side_fence(&p_key, &mut file, size, now, side);
    if matches!(fenced, SideFence::Admitted | SideFence::Stale) {
        return None;
    }
    let wake = index.codex_parent_held_wake(&p_key, &file, fenced, size);
    Some((codex_proof_held_outcome(fenced), wake))
}

/// A resumed job's held FDs are append-compatible with their open stamps
/// and, on a valid page, P still locates to the same key and object
/// (rev 3 §2.4 step 3). Invalid pages step fd-only (rev 9 §6.2).
fn codex_proof_job_still_valid(
    index: &ScanIndex,
    identities: &CodexParentIdentities,
    readers: &CodexProofReaders,
) -> bool {
    let compatible = |reader: &CodexProofReader| {
        if index
            .files
            .get(&reader.key)
            .is_some_and(|e| e.codex_compressed_hold.is_some())
        {
            return false;
        }
        held_stamp(reader).is_some_and(|now| reader.stamp_open.append_compatible(&now))
    };
    if !compatible(&readers.parent)
        || !readers
            .children
            .iter()
            .all(|child| compatible(&child.reader))
    {
        return false;
    }
    if !identities.census_valid() {
        return true;
    }
    match codex_parent_locate(identities.census(index), &readers.parent_id) {
        Ok((key, file)) => {
            key == readers.parent.key
                && file.metadata().is_ok_and(|metadata| {
                    (metadata.dev(), metadata.ino()) == readers.parent.stamp_open.dev_ino()
                })
        }
        Err(_) => false,
    }
}

/// A refused start's entry: (key, `seq`, outcome, wake, child stamp).
type ProofRefused = (String, u64, ProofOutcome, WakeOf, Option<OpenStamp>);

/// Open P's ledger-only reader and each child's decision-only reader
/// (rev 2 §2.2), frozen at open. P that does not locate refuses the batch
/// as `Identity`; a child that does not open (or has no scan root) is
/// `Invalidated` alone.
fn start_codex_proof_job(
    index: &ScanIndex,
    identities: &CodexParentIdentities,
    parent: &str,
    entries: Vec<(String, u64)>,
    now: u64,
) -> (
    Option<CodexProofReaders>,
    Vec<(String, u64)>,
    Vec<ProofRefused>,
) {
    let census = identities.census(index);
    let child_stamp = |key: &str| OpenStamp::of_path(Path::new(key));
    let refuse_all = |outcome: ProofOutcome, of: WakeOf| {
        entries
            .iter()
            .map(|(key, seq)| (key.clone(), *seq, outcome, of.clone(), child_stamp(key)))
            .collect::<Vec<_>>()
    };
    let (p_key, p_file) = match codex_parent_locate(census, parent) {
        Ok(located) => located,
        Err(_) => {
            let matches = codex_parent_census_fingerprint(census, parent);
            return (
                None,
                Vec::new(),
                refuse_all(ProofOutcome::Identity, WakeOf::Census(matches)),
            );
        }
    };
    let Ok(parent_reader) =
        CodexProofReader::parent(p_key.clone(), PathBuf::from(&p_key), p_file, now)
    else {
        return (
            None,
            Vec::new(),
            refuse_all(ProofOutcome::Invalidated, WakeOf::Backoff),
        );
    };
    let mut children = Vec::new();
    let mut started = Vec::new();
    let mut refused = Vec::new();
    for (key, seq) in entries {
        let path = PathBuf::from(&key);
        let reader = census
            .scan_roots
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .cloned()
            .filter(|_| {
                !index
                    .files
                    .get(&key)
                    .is_some_and(|e| e.codex_compressed_hold.is_some())
            })
            .and_then(|scan_root| {
                open_candidate_beneath_root(&CandidateFile {
                    physical_identity: None,
                    scan_root,
                    path: path.clone(),
                    size_bytes: 0,
                    modified_unix_seconds: 0,
                    modified_unix_nanos: 0,
                    source_file_fingerprint: String::new(),
                    legacy_source_file_fingerprint: String::new(),
                    legacy_config_reconciliation_required: false,
                    opened_object_identity: String::new(),
                    fingerprint_changed_nanos: 0,
                    fingerprint_birth_nanos: 0,
                    withheld_content_stamp: None,
                })
                .ok()
            })
            .and_then(|file| CodexProofReader::child(key.clone(), path, file).ok());
        match reader {
            Some(reader) => {
                children.push(reader);
                started.push((key, seq));
            }
            None => {
                let stamp = child_stamp(&key);
                refused.push((key, seq, ProofOutcome::Invalidated, WakeOf::Backoff, stamp));
            }
        }
    }
    if children.is_empty() {
        return (None, started, refused);
    }
    let readers = CodexProofReaders::new(parent.to_owned(), parent_reader, now, children);
    (Some(readers), started, refused)
}

/// P's checks for the whole batch (rev 3 §2.6 steps 1–3): identity, the
/// certificate under the proof scope, the session id. `Ok`: P's key, the
/// seal, P's start offset, and P's freshly located FD.
fn codex_proof_parent_checks(
    index: &ScanIndex,
    identities: &CodexParentIdentities,
    readers: &mut CodexProofReaders,
    held: Option<&OpenStamp>,
    now: u64,
) -> Result<(String, crate::transcript_acquisition::PrefixSeal, u64, File), (ProofOutcome, WakeOf)>
{
    let census = identities.census(index);
    let (p_key, file) = codex_parent_locate(census, &readers.parent_id).map_err(|_| {
        (
            ProofOutcome::Identity,
            WakeOf::Census(codex_parent_census_fingerprint(census, &readers.parent_id)),
        )
    })?;
    let path_same_object = p_key == readers.parent.key
        && file
            .metadata()
            .ok()
            .zip(held)
            .is_some_and(|(metadata, held)| (metadata.dev(), metadata.ino()) == held.dev_ino());
    let parser = &mut readers.parent.parser;
    // P1's rule (cc `finish_job`); it contains PR-P's `ParentLossy` rule.
    let lossy = parser.reader.lossy_prefix()
        || parser.reader.failure.is_some()
        || !sampled_jsonl::loss_free_source_report(
            &parser.reader.report,
            parser.recognized_usage_drop_count,
            parser.accumulator.dropped_usage_record_count,
        );
    let plan = parser
        .reader
        .acquisition
        .take()
        .ok_or((ProofOutcome::Invalidated, WakeOf::Backoff))?;
    let start = plan.start_offset();
    let consumed = start.saturating_add(parser.reader.consumed_bytes());
    let checkpoint = plan
        .commit_sealed_prefix(
            parser.reader.reader.get_mut(),
            path_same_object,
            &codex_parent_proof_scope(),
            readers.started,
            now,
            lossy,
            consumed,
        )
        .map_err(|refusal| match refusal {
            crate::transcript_acquisition::PrefixRefusal::Lossy => {
                (ProofOutcome::ParentLossy, WakeOf::ParentChanged)
            }
            _ => (ProofOutcome::Invalidated, WakeOf::Backoff),
        })?;
    let seal = checkpoint.seal(now);
    if parser
        .accumulator
        .source_session_id
        .as_deref()
        .map(resolve_codex_identity)
        .as_deref()
        != Some(readers.parent_id.as_str())
    {
        return Err((ProofOutcome::NoLedger, WakeOf::Rewritten { parent: true }));
    }
    Ok((p_key, seal, start, file))
}

/// The finish (rev 3 §2.6): P's checks decide the whole batch, then P's
/// side record and each child's result. R2-M2 (owner choice (a)): a
/// `Held{lineage}` P owes nothing in 2a; the lineage owe is a 2b row with
/// the proof memo wake, since no 2a path consumes P's own proof.
fn finish_codex_proof_job(
    index: &mut ScanIndex,
    identities: &CodexParentIdentities,
    job: &mut ProofJob,
    now: u64,
    side: Option<(&sampled_scan::SharedCache, u128)>,
) {
    let Some(mut readers) = job.readers.take() else {
        return;
    };
    let parent_stamp = held_stamp(&readers.parent);
    let child_stamps = readers
        .children
        .iter()
        .map(|child| held_stamp(&child.reader))
        .collect::<Vec<_>>();
    let finish_all =
        |index: &mut ScanIndex, outcome: ProofOutcome, of: &WakeOf, entries: &[(String, u64)]| {
            for ((key, seq), child) in entries.iter().zip(&child_stamps) {
                index.finish_codex_parent_proof_entry(
                    key,
                    *seq,
                    &job.incarnation,
                    ProofFinish::Attempt {
                        outcome,
                        wake: proof_wake(of, parent_stamp.as_ref(), child.as_ref()),
                    },
                    now,
                );
            }
        };
    let checked =
        codex_proof_parent_checks(index, identities, &mut readers, parent_stamp.as_ref(), now);
    let (p_key, seal, start, mut file) = match checked {
        Ok(checked) => checked,
        Err((outcome, of)) => {
            finish_all(index, outcome, &of, &job.entries);
            return;
        }
    };
    // Step 4: P's side record must admit at the seal's offset.
    let needed = seal.sealed_offset();
    let fenced = index.codex_parent_side_fence(&p_key, &mut file, needed, now, side);
    if fenced != SideFence::Admitted {
        let outcome = codex_proof_held_outcome(fenced);
        let wake = index.codex_parent_held_wake(&p_key, &file, fenced, needed);
        finish_all(index, outcome, &WakeOf::Held(Box::new(wake)), &job.entries);
        return;
    }
    // Step 6: each child's result.
    for ((child, (key, seq)), stamp) in readers.children.iter().zip(&job.entries).zip(&child_stamps)
    {
        let attempt = |outcome: ProofOutcome, of: WakeOf| ProofFinish::Attempt {
            outcome,
            wake: proof_wake(&of, parent_stamp.as_ref(), stamp.as_ref()),
        };
        let finish = match child.result {
            Some(ChildResult::Decided {
                matched,
                digest,
                owned,
                at,
            }) if start.saturating_add(at) <= needed => {
                ProofFinish::Proven(CodexParentPrefixProof {
                    parent: readers.parent_id.clone(),
                    parent_seal: seal.clone(),
                    matched,
                    child_digest: codex_digest_hex(&digest),
                    owned,
                    published: false,
                })
            }
            Some(ChildResult::Decided { .. }) => {
                attempt(ProofOutcome::BeyondSeal, WakeOf::ParentChanged)
            }
            Some(ChildResult::ParentExhausted) => {
                attempt(ProofOutcome::ParentExhausted, WakeOf::ParentChanged)
            }
            Some(ChildResult::ChildExhausted) => {
                attempt(ProofOutcome::ChildExhausted, WakeOf::ChildChanged)
            }
            Some(ChildResult::Undecidable) => attempt(
                ProofOutcome::Undecidable,
                WakeOf::Rewritten { parent: true },
            ),
            Some(ChildResult::NotAFork) => {
                attempt(ProofOutcome::NotAFork, WakeOf::Rewritten { parent: false })
            }
            Some(ChildResult::Unreadable) | None => {
                attempt(ProofOutcome::Invalidated, WakeOf::Backoff)
            }
        };
        index.finish_codex_parent_proof_entry(key, *seq, &job.incarnation, finish, now);
    }
}

impl ScanIndex {
    /// The visit (rev 2 §2.4 step 4, rev 3 §2.4 step 4): ≤ 64 proof entries
    /// in key order after `codex_parent_proof_cursor`, wrapping, one census
    /// pass, ≤ 2 path stats per entry. A child absent from `files` and the
    /// valid census is dropped. Due = the wake fires and the entry is not
    /// backed off (`Due` always fires). A due `Owed{kept}` is re-fenced
    /// first: admitted → `Proven` again (no job). The batch is the first
    /// due entry and ≤ 3 later due entries of the same parent; the head
    /// becomes the cursor. A re-fence runs only within `leftover`, the
    /// page's singleton budget (R2-L3, `PROOF_FENCE_READ_BYTES` each): an
    /// unaffordable due head stops the visit before it. A wrap over a non-empty map bumps
    /// `codex_parent_proof_wrap_epoch`; each visited entry's parent record
    /// takes the epoch.
    pub(super) fn visit_codex_parent_proofs(
        &mut self,
        identities: &CodexParentIdentities,
        now: u64,
        side: Option<(&sampled_scan::SharedCache, u128)>,
        leftover: u64,
    ) -> ProofVisit {
        use std::ops::Bound::{Excluded, Included, Unbounded};
        let cursor = self.codex_parent_proof_cursor.take();
        let after = cursor.clone().map_or(Unbounded, Excluded);
        let mut keys = self
            .codex_parent_prefix_proofs
            .range::<String, _>((after, Unbounded))
            .map(|(key, _)| key.clone())
            .take(CODEX_PROOF_VISIT_KEYS)
            .collect::<Vec<_>>();
        if keys.len() < CODEX_PROOF_VISIT_KEYS {
            if let Some(cursor) = cursor.clone() {
                let room = CODEX_PROOF_VISIT_KEYS - keys.len();
                keys.extend(
                    self.codex_parent_prefix_proofs
                        .range::<String, _>((Unbounded, Included(cursor)))
                        .map(|(key, _)| key.clone())
                        .take(room),
                );
            }
            if !keys.is_empty() {
                self.codex_parent_proof_wrap_epoch =
                    self.codex_parent_proof_wrap_epoch.saturating_add(1);
            }
        }
        let epoch = self.codex_parent_proof_wrap_epoch;
        // One census pass for every visited parent id.
        let mut wanted = keys
            .iter()
            .filter_map(|key| match self.codex_parent_prefix_proofs.get(key) {
                Some(CodexParentProofState::Owed(owed)) => Some(owed.parent.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        wanted.sort_unstable();
        wanted.dedup();
        let census = identities.census(self);
        let parents = {
            let ids = wanted.iter().map(String::as_str).collect::<Vec<_>>();
            codex_parent_census_matches(census, &ids)
                .into_iter()
                .map(|found| match found {
                    CodexCensusMatch::Absent => ("absent".to_owned(), None),
                    CodexCensusMatch::Duplicated => ("duplicated".to_owned(), None),
                    CodexCensusMatch::One(key) => (format!("one:{key}"), Some(key.to_owned())),
                })
                .collect::<Vec<_>>()
        };
        let absent = keys
            .iter()
            .map(|key| !self.files.contains_key(key) && !census.paths.contains(key))
            .collect::<Vec<_>>();
        let mut visit = ProofVisit {
            before_head: cursor,
            ..Default::default()
        };
        let mut previous = visit.before_head.clone();
        let mut stopped = false;
        for (key, absent) in keys.iter().zip(absent) {
            let parent = match self.codex_parent_prefix_proofs.get(key) {
                Some(CodexParentProofState::Owed(owed)) => owed.parent.clone(),
                _ => {
                    if visit.batch.is_none() {
                        previous = Some(key.clone());
                    }
                    continue;
                }
            };
            if absent {
                self.drop_codex_proof_items(key, side);
                continue;
            }
            let (matches, p_key) = wanted
                .binary_search(&parent)
                .ok()
                .map_or(("absent".to_owned(), None), |at| parents[at].clone());
            if let Some(record) = p_key
                .as_ref()
                .and_then(|p_key| self.codex_parent_side.get_mut(p_key))
            {
                record.referenced_epoch = epoch;
            }
            let Some(CodexParentProofState::Owed(owed)) = self.codex_parent_prefix_proofs.get(key)
            else {
                continue;
            };
            let due = owed.wake == ProofWake::Due
                || (!owed.backed_off(now)
                    && self.codex_proof_wake_fires(
                        &owed.wake,
                        key,
                        &matches,
                        p_key.as_deref(),
                        now,
                    ));
            let excluded = visit.batch.as_ref().is_some_and(|(head_parent, entries)| {
                *head_parent != parent || entries.len() >= CODEX_PROOF_BATCH
            });
            if !due || excluded {
                if visit.batch.is_none() {
                    previous = Some(key.clone());
                }
                continue;
            }
            let (seq, kept) = (owed.seq, owed.kept.as_deref().cloned());
            if let Some(kept) = kept {
                if leftover / PROOF_FENCE_READ_BYTES <= visit.refenced {
                    if visit.batch.is_none() {
                        stopped = true;
                        break;
                    }
                    continue;
                }
                visit.refenced += 1;
                if self.refence_kept_codex_parent_proof(identities, &kept, now, side) {
                    self.remove_codex_parent_proof(key);
                    self.codex_parent_prefix_proofs
                        .insert(key.clone(), CodexParentProofState::Proven(kept));
                    visit.reproven.push(key.clone());
                    if visit.batch.is_none() {
                        previous = Some(key.clone());
                    }
                    continue;
                }
            }
            match visit.batch.as_mut() {
                Some((_, entries)) => entries.push((key.clone(), seq)),
                None => {
                    visit.before_head = previous.clone();
                    visit.batch = Some((parent, vec![(key.clone(), seq)]));
                }
            }
        }
        self.codex_parent_proof_cursor = match &visit.batch {
            Some((_, entries)) => entries.first().map(|(head, _)| head.clone()),
            None if stopped => previous,
            None => keys.last().cloned(),
        };
        visit
    }

    /// Whether `wake` fires now (rev 3 §1.6): `child_key`'s and P's path
    /// stamps (no-follow stats; no byte is read), P's census fingerprint,
    /// P's side generation and P's own proof entry. Fix round 4 (AutoReview
    /// #3): a `ParentHeld` wake also fires when P's settled record now
    /// covers `needed_extent` with a seal inside its horizon
    /// (`admits_in_time`), so a side read that refreshes the seal under the
    /// same verdict and generation wakes it; an unchanged expired or short
    /// seal does not. Backoff is checked before (`backed_off`).
    fn codex_proof_wake_fires(
        &self,
        wake: &ProofWake,
        child_key: &str,
        census: &str,
        p_key: Option<&str>,
        now: u64,
    ) -> bool {
        let child_now = OpenStamp::of_path(Path::new(child_key));
        let parent_now = || p_key.and_then(|p_key| OpenStamp::of_path(Path::new(p_key)));
        // Exact stamps (E1 S3, C1): raw path stamps carry no birth witness.
        let grown = |then: &OpenStamp, now: Option<&OpenStamp>| {
            now.is_some_and(|now| then.wake_compatible(now))
        };
        match wake {
            ProofWake::Due | ProofWake::Backoff => true,
            ProofWake::ParentChanged { parent, child } => {
                parent_now().as_ref() != Some(parent) || !grown(child, child_now.as_ref())
            }
            ProofWake::ChildChanged { parent, child } => {
                child_now.as_ref() != Some(child) || !grown(parent, parent_now().as_ref())
            }
            ProofWake::Rewritten { parent, child } => {
                !grown(child, child_now.as_ref())
                    || parent
                        .as_ref()
                        .is_some_and(|parent| !grown(parent, parent_now().as_ref()))
            }
            ProofWake::Census { matches, child } => {
                matches != census || !grown(child, child_now.as_ref())
            }
            ProofWake::ParentHeld {
                parent_key,
                generation,
                parent_entry,
                parent,
                needed_extent,
                ..
            } => {
                let record = self.codex_parent_side.get(parent_key);
                record.map_or(0, |record| record.generation) != *generation
                    || self.codex_parent_entry_fingerprint(parent_key) != *parent_entry
                    || OpenStamp::of_path(Path::new(parent_key)).as_ref() != Some(parent)
                    || record.is_some_and(|record| {
                        record.verdict == SideVerdict::Settled
                            && record.seal.sealed_offset() >= *needed_extent
                            && record.seal.admits_in_time(&codex_parent_side_scope(), now)
                    })
            }
        }
    }

    /// A kept proof's re-fence (rev 3 §2.4 step 4; §1.4 without a parse):
    /// the install's checks on P now. Admitted: the kept proof is current.
    fn refence_kept_codex_parent_proof(
        &mut self,
        identities: &CodexParentIdentities,
        kept: &CodexParentPrefixProof,
        now: u64,
        side: Option<(&sampled_scan::SharedCache, u128)>,
    ) -> bool {
        let scope = codex_parent_proof_scope();
        if kept.installable(&scope).is_none() {
            return false;
        }
        let Ok((p_key, mut file)) = codex_parent_locate(identities.census(self), &kept.parent)
        else {
            return false;
        };
        let needed = kept.parent_seal.sealed_offset();
        self.codex_parent_side_fence(&p_key, &mut file, needed, now, side) == SideFence::Admitted
            && kept
                .parent_seal
                .admits(&mut file, &scope, now, false)
                .is_ok()
    }
}
