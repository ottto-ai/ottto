//! Hybrid codec/resume proxy. E/X/I slots move unchanged; encodable fields
//! are encoded individually, their originals dropped, then decoded. No DB Tail
//! implementation exists yet. No proxy state is published or uploaded.
use super::*;
use crate::durable_tail_codec::Dec;
use crate::transcript_acquisition::Scope;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

fn footprint() -> u64 {
    crate::local_resource_diagnostics::state_v2_memory()
        .phys_footprint_bytes
        .unwrap_or(0)
}
fn measure<T>(f: impl FnOnce() -> T) -> (T, u64, u128) {
    let stop = AtomicBool::new(false);
    let now = Instant::now();
    let (result, peak, work_ms) = std::thread::scope(|s| {
        let sampler = s.spawn(|| {
            let mut n = footprint();
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(10));
                n = n.max(footprint());
            }
            n
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        let work_ms = now.elapsed().as_millis();
        stop.store(true, Ordering::Relaxed);
        (result, sampler.join().unwrap_or(0), work_ms)
    });
    (
        result.unwrap_or_else(|e| std::panic::resume_unwind(e)),
        peak,
        work_ms,
    )
}
#[derive(Default)]
struct Coverage {
    encoded: u64,
    moved_fields: u64,
    decoded_fields: u64,
    encoded_peak: u64,
    head_moved_bytes: u64,
}
macro_rules! round_field {
 (E,$f:ident,$ty:ty,$stats:ident)=>{{ $stats.moved_fields+=1;$stats.head_moved_bytes+=layout_bytes(&$f).unwrap_or(0) as u64;$f }};
 (X,$f:ident,$ty:ty,$stats:ident)=>{round_field!(E,$f,$ty,$stats)};
 (I,$f:ident,$ty:ty,$stats:ident)=>{round_field!(E,$f,$ty,$stats)};
 ($class:ident,$f:ident,$ty:ty,$stats:ident)=>{{
 let bytes=Enc::count_write(usize::MAX,|e|{
 let value=&$f;
 crate::durable_tail_codec::durable_field!(put $class,e,value,$ty,stringify!($f));Ok(())
 }).map_err(|_|stringify!($f))?;
 $stats.encoded+=bytes.len() as u64;
 $stats.encoded_peak=$stats.encoded_peak.max(bytes.len() as u64);$stats.decoded_fields+=1;
 drop($f);let mut decoder=Dec::new(&bytes);
 let value=(||->std::result::Result<$ty,crate::durable_tail_codec::Corrupt>{
 let d=&mut decoder;
 Ok(crate::durable_tail_codec::durable_field!(take $class,d,$ty))
 })().map_err(|_|stringify!($f))?;
 decoder.finish().map_err(|_|stringify!($f))?;value
 }};
}
macro_rules! round_acc {
 ($acc:ident,$stats:ident; $($class:ident $f:ident:$ty:ty),* $(,)?)=>{{
 let SnapshotAccumulator{$($f),*}=$acc;
 SnapshotAccumulator{$($f:round_field!($class,$f,$ty,$stats)),*}
 }};
}
fn roundtrip(
    acc: SnapshotAccumulator,
    stats: &mut Coverage,
) -> std::result::Result<SnapshotAccumulator, &'static str> {
    Ok(round_acc!(acc,stats;
    N source:SnapshotSource,
    H cache_configuration_witness:Option<String>,
    N cache_task_complete_at:Option<String>,
    N cache_pending_idle:Option<u64>,
    L cache_active_turns:BTreeSet<String>,
    N context_curve_enabled:bool,
    U source_session_id:Option<String>,
    U account_identifier_hash:Option<String>,
    X title:Option<String>,
    N title_source:Option<String>,
    X first_prompt_title:Option<String>,
    X first_prompt_material:Option<String>,
    PL provider_skills:BTreeSet<String>,
    N started_at:Option<String>,
    N ended_at:Option<String>,
    N last_activity_at:Option<String>,
    U workspace_hash:Option<String>,
    X workspace_path:Option<PathBuf>,
    U latest_model:Option<String>,
    U latest_reasoning_effort:Option<String>,
    L latest_turn_id:Option<String>,
    I codex_turn_traces:Option<Arc<CodexTurnTraceMap>>,
    L codex_observed_priority_turns:Option<BTreeMap<String, bool>>,
    N codex_priority_witnesses_uncapped:bool,
    E codex_tier_replay:Option<codex_file_join::TierReplay>,
    D codex_counting:Option<Box<codex_usage_occurrence::CodexCounting>>,
    D current_selector:SelectorCapture,
    D session_cumulative_usage:Option<UsageTotals>,
    N codex_session_meta_seen:bool,
    N codex_record_seen:bool,
    U codex_creator_header_id:Option<String>,
    D codex_creator_evidence:Option<SessionAccountEvidence>,
    N codex_creator_evidence_conflicted:bool,
    E claude_desktop_identity:Option<SessionAccountEvidence>,
    E claude_desktop_spawn_lineage:Option<ClaudeDesktopSpawnLineage>,
    N claude_owned_session_id_observed:bool,
    N claude_owned_session_id_conflicted:bool,
    D codex_ownership_boundary:CodexOwnershipBoundary,
    N codex_legacy_trigger_seen:bool,
    N codex_legacy_bootstrap_valid:bool,
    I codex_parent_ownership_ledgers:Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    N codex_sidecar_created_thread:bool,
    D codex_path_sidecar_candidates:Vec<CodexPathSidecarCandidate>,
    U codex_resolved_path_identity:Option<String>,
    N codex_sidecar_identity_ambiguous:bool,
    U codex_sidecar_parent:Option<(String, String)>,
    N codex_sidecar_child_created_at_nanos:Option<i128>,
    N codex_bind_seed_len:Option<u64>,
    I codex_sidecar_projected_next_ordinal:Option<u64>,
    U codex_parent_session_ref:Option<String>,
    E codex_parent_signatures:Option<CodexParentPrefix>,
    H codex_parent_prefix_digest:PrefixDigest,
    D codex_parent_prefix_decided:Option<(u64, PrefixDigest, bool)>,
    E codex_parent_prefix_proof:Option<(CodexParentPrefixProof, PrefixDigest)>,
    E codex_parent_proof_used:Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
    N codex_parent_proof_mismatch:bool,
    E codex_parent_proof_refusal:Option<ProofRefusal>,
    N codex_proof_decision_only:bool,
    N codex_boundary_buffer_count:u8,
    H codex_proof_ledger_row:Option<String>,
    H codex_parent_ledger_identity_used:Option<String>,
    D codex_parent_unresolvable:Option<CodexParentUnresolvable>,
    N codex_parent_ledger_consulted:bool,
    N codex_parent_signature_index:usize,
    N codex_native_created_thread_valid:bool,
    N codex_created_thread_native_only:bool,
    N codex_native_created_thread_header_nanos:Option<i128>,
    N codex_native_created_thread_last_nanos:Option<i128>,
    L codex_native_created_thread_task_turn_id:Option<String>,
    N codex_native_created_thread_first_turn_bound:bool,
    H codex_physical_signatures:crate::owned_heap::OwnedVec<String>,
    N codex_physical_signatures_complete:bool,
    N codex_ordinal_expected:Option<u64>,
    N codex_ordinal_sequence_valid:bool,
    N codex_owned_record_seen:bool,
    N codex_is_fork:bool,
    N codex_inherited_usage_records_skipped:u64,
    N codex_duplicate_usage_records_skipped:u64,
    N codex_cumulative_reset_count:u64,
    D codex_context_curve_candidates:crate::owned_heap::OwnedVec<ContextCurveCandidatePoint>,
    D codex_context_curve_boundaries:crate::owned_heap::OwnedVec<ContextCurveCandidateBoundary>,
    N codex_context_curve_exact_supported:bool,
    H codex_last_usage_event_identity:Option<String>,
    E codex_legacy_bootstrap_buffer:Vec<Value>,
    D accepted_usage_totals:UsageTotals,
    D usage_buckets:BTreeMap<String, UsageBucketState>,
    D origin:SnapshotOrigin,
    U codex_root_session_ref:Option<String>,
    N codex_spawn_depth:Option<u64>,
    X codex_agent_label:Option<String>,
    U activity_tool_counts:BTreeMap<String, u64>,
    D activity_call_tools:BTreeMap<ActivityCallId, ActivityCallTool>,
    U activity_mcp_tool_counts:BTreeMap<String, u64>,
    U activity_mcp_tool_usage_counts:BTreeMap<String, u64>,
    L activity_mcp_call_ids:BTreeMap<String, bool>,
    U activity_capability_buckets:BTreeMap<(String, String, String), u64>,
    L seen_claude_capability_tool_uses:crate::owned_heap::OwnedMap<String, ()>,
    PL activity_skills:BTreeSet<String>,
    N skill_detector_incomplete:bool,
    H activity_changed_file_hashes:BTreeSet<String>,
    N activity_patch_operations:u64,
    N activity_lines_added:u64,
    N activity_lines_deleted:u64,
    N activity_web_searches:u64,
    N activity_mcp_calls:u64,
    N activity_subagent_spawns:u64,
    E artifacts:Vec<SessionArtifact>,
    N artifacts_enabled:bool,
    N latency_duration_ms_sum:u64,
    N latency_duration_ms_count:u64,
    N latency_ttft_ms_sum:u64,
    N latency_ttft_ms_count:u64,
    N latency_duration_ms_max:u64,
    N latency_ttft_ms_max:u64,
    D claude_responses:ClaudeResponseBook,
    N claude_response_sequence:u64,
    N claude_response_record_count:usize,
    E claude_usage_request_ids:BTreeSet<String>,
    E claude_usage_occurrences:BTreeMap<String, ClaudeTranscriptUsageOccurrence>,
    N claude_request_identity_capture:bool,
    D claude_org_markers:Option<Box<claude_request_identity::OrgMarkers>>,
    E cache_observations:Option<CacheObservations>,
    D cache_requests:crate::owned_heap::OwnedVec<OwnedRequest>,
    N cache_requests_complete:bool,
    N claude_context_curve_identity_complete:bool,
    N claude_context_curve_request_index_complete:bool,
    N claude_context_curve_owned_start_proven:bool,
    D claude_file_birth:ClaudeFileBirth,
    E claude_fork_parent:Option<String>,
    E claude_money:Option<Box<claude_request_money::e2::FileFold>>,
    U tool_usage_counts:BTreeMap<String, u64>,
    N tool_usage_truncated:bool,
    E seen_pi_usage_keys:BTreeMap<String, PiUsageDedupState>,
    N dropped_usage_record_count:u64,
    N claude_last_user_ts:Option<String>,
    N peak_context_fill_tokens:u64,
    N first_turn_context_tokens:Option<u64>,
    N last_turn_context_tokens:Option<u64>,
    N first_turn_context_window_tokens:Option<u64>,
    N peak_context_fill_window_tokens:Option<u64>,
    N last_turn_context_window_tokens:Option<u64>,
    N compaction_count:u64,
    N compaction_timestamps:crate::owned_heap::OwnedVec<String>,
    D codex_compaction_sizes:CodexCompactionSizes,
    D local_context_points:LocalContextPoints,
    D claude_compaction_observations:crate::owned_heap::OwnedVec<ClaudeCompactionObservation>,
    L claude_compaction_link_tip:Option<(u64, String)>,
    D session_start:Box<session_start::SessionStartState>,
    D durable_marks:crate::durable_tail_codec::DurableMarks,
    ))
}
fn native(path: &Path, source: SnapshotSource, artifacts: bool) -> Result<OwnedJsonlParser> {
    let apply = match source {
        SnapshotSource::ClaudeCode => apply_claude_code_line,
        SnapshotSource::Codex => apply_codex_line,
        SnapshotSource::Pi => apply_pi_line,
    };
    OwnedJsonlParser::new(
        File::open(path)?,
        path,
        source,
        apply,
        None,
        None,
        None,
        artifacts,
    )
}
fn read(path: &Path, source: SnapshotSource, artifacts: bool) -> Result<OwnedJsonlParser> {
    let mut p = native(path, source, artifacts)?;
    p.prepare_acquisition(
        None,
        &Scope("copied-proxy".into()),
        None,
        sampled_scan::now_seconds(),
    )?;
    while !p.step()? {}
    Ok(p)
}
fn heap(acc: &SnapshotAccumulator) -> (u64, u64) {
    let f = fields(acc);
    (
        f.iter().filter_map(|v| v.decoded).sum(),
        f.iter().filter(|v| v.decoded.is_none()).count() as u64,
    )
}
fn finish(p: OwnedJsonlParser, path: &Path, source: SnapshotSource) -> Result<(u64, u64)> {
    let identity = opened_object_identity(source, &mut File::open(path)?)?;
    let parsed = p.finish(
        &identity,
        path,
        &crate::backfill::now_rfc3339(),
        "copied-proxy".into(),
        None,
        None,
        None,
    )?;
    let heap = layout_bytes(&parsed.snapshots).unwrap_or(0) as u64;
    Ok((parsed.snapshots.len() as u64, heap))
}
fn compare_toggles(path: &Path, source: SnapshotSource) -> Value {
    let baseline = match read(path, source, false) {
        Ok(p) => fields(&p.accumulator),
        Err(_) => return json!({"error":true}),
    };
    let mut out = BTreeMap::new();
    for name in [
        "session_titles_enabled",
        "workspace_labels_enabled",
        "session_artifacts_enabled",
        "session_attribution_enabled",
        "session_attribution_labels_enabled",
    ] {
        let mut flags = SnapshotUploadPolicy::default();
        match name {
            "session_titles_enabled" => {
                flags.session_titles_enabled = !flags.session_titles_enabled
            }
            "workspace_labels_enabled" => {
                flags.workspace_labels_enabled = !flags.workspace_labels_enabled
            }
            "session_artifacts_enabled" => flags.session_artifacts_enabled = true,
            "session_attribution_enabled" => flags.session_attribution_enabled = true,
            _ => flags.session_attribution_labels_enabled = true,
        }
        // The only policy input to this parser is artifacts. Other toggles apply
        // after the native seam. This experiment holds all source metadata fixed.
        let result = read(path, source, flags.session_artifacts_enabled);
        match result {
            Err(_) => {
                out.insert(name, json!({"parse_failed":1}));
            }
            Ok(p) => {
                let sample = fields(&p.accumulator);
                let mut diffs = BTreeMap::new();
                let mut unknown = 0;
                for (a, b) in baseline.iter().zip(&sample) {
                    match (a.hash, b.hash) {
                        (Some(a), Some(b)) if a == b => {}
                        (Some(_), Some(_)) => {
                            diffs.insert(a.name, 1);
                        }
                        _ => unknown += 1,
                    }
                }
                out.insert(name,json!({"equal_known":diffs.is_empty(),"unknown_fields":unknown,"different_fields":diffs}));
            }
        }
    }
    json!(out)
}
fn one(dir: &Path, path: &Path, source: SnapshotSource, label: &str) -> Value {
    let size = std::fs::metadata(path).map_or(0, |m| m.len());
    let full_floor = footprint();
    let ((full, full_heap), full_peak, full_ms) = measure(|| {
        let p = read(path, source, false);
        match p {
            Ok(p) => {
                let h = heap(&p.accumulator);
                (finish(p, path, source).ok(), Some(h))
            }
            Err(_) => (None, None),
        }
    });
    let copied = dir.join("proxy-input.jsonl");
    let mut input = match File::open(path) {
        Ok(f) => f,
        Err(_) => return json!({"error":"open"}),
    };
    let target = size.saturating_sub((size / 100).clamp(1, 65536));
    if input.seek(SeekFrom::Start(target)).is_err() {
        return json!({"error":"seek"});
    }
    let mut tail = Vec::new();
    let _ = input.read_to_end(&mut tail);
    let cut = tail
        .iter()
        .position(|b| *b == b'\n')
        .map(|i| target + i as u64 + 1)
        .unwrap_or(size);
    if input.seek(SeekFrom::Start(0)).is_err() {
        return json!({"error":"seek"});
    }
    let mut output = match File::create(&copied) {
        Ok(f) => f,
        Err(_) => return json!({"error":"create"}),
    };
    if std::io::copy(&mut (&mut input).take(cut), &mut output).is_err() {
        return json!({"error":"copy"});
    }
    drop(output);
    let prepared = read(&copied, source, false);
    let Ok(mut p) = prepared else {
        return json!({"error":"prefix_parse"});
    };
    let response_records = p
        .accumulator
        .claude_responses
        .values()
        .map(|r| r.records.len())
        .max()
        .unwrap_or(0);
    let checkpoint = match p
        .certify_without_retention(&Scope("copied-proxy".into()), sampled_scan::now_seconds())
    {
        Ok(sampled_jsonl::SideCertificate::Certified { completed, .. }) => completed.checkpoint,
        _ => {
            return json!({"source":source.api_slug(),"transcript_bytes":size,"prefix_uncertified":1,"full_peak":full_peak,"full_ms":full_ms})
        }
    };
    let acc = std::mem::replace(&mut p.accumulator, SnapshotAccumulator::new(source));
    let report = p.reader.report;
    let scalars = (
        p.recognized_usage_drop_count,
        p.positive_recognized_usage_count,
        p.positive_usage_evidence,
    );
    drop(p);
    if input.seek(SeekFrom::Start(cut)).is_err() {
        return json!({"error":"seek"});
    }
    let mut output = match std::fs::OpenOptions::new().append(true).open(&copied) {
        Ok(f) => f,
        Err(_) => return json!({"error":"append"}),
    };
    if std::io::copy(&mut input, &mut output).is_err() {
        return json!({"error":"append"});
    }
    drop(output);
    let mut coverage = Coverage::default();
    let decode_floor = footprint();
    let (restored, decode_peak, decode_ms) = measure(|| roundtrip(acc, &mut coverage));
    let restored = match restored {
        Ok(a) => a,
        Err(field) => {
            return json!({"source":source.api_slug(),"transcript_bytes":size,"proxy":true,"codec_refused_field":field,"full_heap":full_heap,"full_peak":full_peak,"full_ms":full_ms})
        }
    };
    let decoded_heap = heap(&restored);
    let resume_floor = footprint();
    let ((resume, mode), resume_peak, resume_ms) = measure(|| {
        let result = (|| -> Result<_> {
            let mut p = native(&copied, source, false)?;
            let mode = p.prepare_acquisition(
                Some(crate::transcript_cache::Retained {
                    checkpoint,
                    state: sampled_jsonl::s0_reduction(restored, report, scalars),
                }),
                &Scope("copied-proxy".into()),
                None,
                sampled_scan::now_seconds(),
            )?;
            while !p.step()? {}
            let out = finish(p, &copied, source)?;
            Ok((out, format!("{mode:?}")))
        })();
        match result {
            Ok((a, b)) => (Some(a), b),
            Err(_) => (None, "failed".into()),
        }
    });
    let _ = std::fs::remove_file(&copied);
    json!({"label":label,"source":source.api_slug(),"transcript_bytes":size,"proxy":true,
 "full_output":full,"full_heap":full_heap,"full_floor":full_floor,"full_peak":full_peak,"full_ms":full_ms,
 "decoded_heap":decoded_heap,"encoded_bytes":coverage.encoded,"max_field_buffer":coverage.encoded_peak,
 "decoded_fields":coverage.decoded_fields,"moved_E_X_I_fields":coverage.moved_fields,"moved_heap":coverage.head_moved_bytes,
 "decode_floor":decode_floor,"decode_peak":decode_peak,"decode_ms":decode_ms,"resume_output":resume,"resume_mode":mode,
 "resume_floor":resume_floor,"resume_peak":resume_peak,"resume_ms":resume_ms,"suffix_bytes":size-cut,"max_response_records":response_records})
}
pub(super) fn run(dir: &Path) -> Value {
    // Choose largest files from the copied corpus even if cache/record
    // admission never admitted their main-arm reduction.
    fn files(path: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                files(&entry.path(), out);
            } else if entry.file_type().is_ok_and(|t| t.is_file())
                && entry.path().extension().is_some_and(|e| e == "jsonl")
            {
                out.push(entry.path());
            }
        }
    }
    let mut largest: BTreeMap<String, (PathBuf, u64)> = BTreeMap::new();
    for line in std::fs::read_to_string(dir.join("manifest.tsv"))
        .unwrap_or_default()
        .lines()
    {
        let parts: Vec<_> = line.split('\t').collect();
        if parts.len() != 3 || parts[1] != "root" {
            continue;
        }
        let mut found = Vec::new();
        files(&dir.join("run").join(parts[2]), &mut found);
        for path in found {
            let size = std::fs::metadata(&path).map_or(0, |m| m.len());
            if largest.get(parts[0]).is_none_or(|(_, n)| size > *n) {
                largest.insert(parts[0].into(), (path, size));
            }
        }
    }
    let mut keys: Vec<_> = largest
        .into_iter()
        .filter(|(source, _)| source == "claude_code" || source == "codex")
        .map(|(source, (path, _))| {
            (
                path.to_string_lossy().into_owned(),
                source,
                "largest_corpus",
            )
        })
        .collect();
    with(|r| {
        if let Some((key, _)) = r
            .files
            .iter()
            .filter(|(_, f)| f.source == "claude_code" && f.bytes >= 10_000_000)
            .max_by_key(|(_, f)| f.records_per_response_peak)
        {
            if !keys.iter().any(|(k, _, _)| k == key) {
                keys.push((key.clone(), "claude_code".into(), "large_multiblock"));
            }
        }
    });
    let was = ENABLED.swap(false, Ordering::Relaxed);
    let mut rows = Vec::new();
    let mut toggles = Value::Null;
    for (key, source, label) in keys {
        let source = if source == "codex" {
            SnapshotSource::Codex
        } else {
            SnapshotSource::ClaudeCode
        };
        rows.push(one(dir, Path::new(&key), source, label));
        if source == SnapshotSource::ClaudeCode && toggles.is_null() {
            toggles = compare_toggles(Path::new(&key), source);
        }
    }
    let mut headers = Vec::new();
    for entry in std::fs::read_dir(dir.join("installed-db"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if entry.path().extension().is_some_and(|e| e == "sqlite") {
            headers.push(
                state_v2::s0_header_scan(&entry.path())
                    .unwrap_or_else(|_| json!({"header_scan_failed":1})),
            );
        }
    }
    ENABLED.store(was, Ordering::Relaxed);
    json!({"hybrid_codec_resume_proxy":rows,"upload_toggle_reparse_proxy":toggles,"database_headers":headers})
}
