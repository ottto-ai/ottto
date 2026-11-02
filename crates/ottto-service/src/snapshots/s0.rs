//! Count-only instrumentation for the ignored copied-corpus harness.
//! No keys, digests, field values or provider identities leave this recorder.
use super::*;
use crate::durable_tail_codec::{Enc, Refuse};
use serde_json::{json, Value};
use std::cell::Cell;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
static ENABLED: AtomicBool = AtomicBool::new(false);
static REC: Mutex<Option<Recorder>> = Mutex::new(None);
thread_local! { static SUFFIX: Cell<bool> = const { Cell::new(false) }; }
pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}
pub(crate) fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}
#[derive(Clone)]
struct Field {
    name: &'static str,
    encoded: Option<u64>,
    decoded: Option<u64>,
    hash: Option<[u8; 32]>,
}
#[derive(Default)]
struct FileCount {
    source: String,
    bytes: u64,
    fields: Vec<Field>,
    completions: u64,
    decoded_peak: u64,
    decode_scratch_peak: u64,
    response_records_peak: u64,
    records_per_response_peak: u64,
    footprint_peak: u64,
    dropped: u64,
    unsealed: u64,
    last_projection: Option<[u8; 32]>,
    projection_fields: BTreeMap<String, [u8; 32]>,
    last_reason: String,
    ever_written: bool,
    cap: bool,
    noncap_dropped: u64,
    pass: u64,
    phase: String,
    full: bool,
    not_persisted: String,
    reasons: BTreeSet<String>,
    grew: bool,
}
#[derive(Default)]
struct Recorder {
    files: BTreeMap<String, FileCount>,
    contexts: BTreeMap<String, Context>,
    phase: String,
    pass: u64,
    source: String,
    rows: BTreeMap<String, u64>,
    touches: BTreeMap<String, u64>,
    diffs: BTreeMap<String, BTreeMap<String, u64>>,
    events: Vec<Value>,
    missing: BTreeMap<String, u64>,
    full_growth: BTreeMap<String, Vec<[u64; 2]>>,
    projection: BTreeMap<String, BTreeMap<String, u64>>,
    clears: BTreeMap<String, String>,
    current_key: String,
    entity_causes: BTreeMap<String, String>,
    wire_diffs: BTreeMap<String, BTreeMap<String, u64>>,
    settled: Option<bool>,
    restored_siblings: BTreeMap<String, u64>,
    completions_by_phase: BTreeMap<String, u64>,
}
struct Context {
    mode: String,
    reason: String,
    bytes: u64,
    native: u64,
    accepted: u64,
}
fn with(f: impl FnOnce(&mut Recorder)) {
    if !enabled() {
        return;
    }
    let mut r = REC.lock().unwrap_or_else(|e| e.into_inner());
    f(r.get_or_insert_with(Recorder::default));
}
pub(crate) fn begin(phase: &str, pass: u64, source: &str) {
    with(|r| {
        r.phase = phase.into();
        r.pass = pass;
        r.source = source.into();
        r.rows.clear();
        r.events.clear();
        r.settled = None;
        r.restored_siblings.clear();
    });
}
pub(crate) fn context(key: &str, mode: &str, reason: &str, bytes: u64, native: u64, accepted: u64) {
    with(|r| {
        r.contexts.insert(
            key.into(),
            Context {
                mode: mode.into(),
                reason: reason.into(),
                bytes,
                native,
                accepted,
            },
        );
    });
}
pub(crate) struct Suffix(bool);
impl Drop for Suffix {
    fn drop(&mut self) {
        SUFFIX.with(|s| s.set(self.0));
    }
}
pub(crate) fn suffix(tail: bool) -> Suffix {
    Suffix(SUFFIX.with(|s| s.replace(enabled() && tail)))
}
pub(super) fn is_suffix() -> bool {
    SUFFIX.with(Cell::get)
}
pub(super) fn touch(entries: usize, encoded_after: Option<u64>) {
    with(|r| {
        let e = match entries {
            0 => "0",
            1..=15 => "1-15",
            16..=255 => "16-255",
            256..=4095 => "256-4095",
            _ => "4096+",
        };
        *r.touches.entry(format!("entries.{e}")).or_default() += 1;
        let p = encoded_after.map(|n| n / 65536);
        let p = match p {
            Some(0) => "0",
            Some(1) => "1",
            Some(2..=15) => "2-15",
            Some(16..=255) => "16-255",
            Some(_) => "256+",
            None => "unknown",
        };
        *r.touches.entry(format!("pages64k.{p}")).or_default() += 1;
    });
}
pub(crate) fn event(class: &str, counts: Value) {
    with(|r| r.events.push(json!({"class":class,"counts":counts})));
}
pub(crate) fn not_persisted(key: &str, reason: &str) {
    with(|r| {
        let f = r.files.entry(key.into()).or_default();
        if reason != "wa.Codec" || !f.not_persisted.starts_with("wa.codec_leaf.") {
            f.not_persisted = reason.into();
        }
        f.reasons.insert(f.not_persisted.clone());
    });
}
pub(crate) fn written(key: &str) {
    with(|r| {
        r.files.entry(key.into()).or_default().ever_written = true;
    });
}
pub(crate) fn grew(path: &Path) {
    with(|r| r.files.entry(local_index_key(path)).or_default().grew = true);
}
pub(crate) fn missing(key: &str, bytes: u64) {
    with(|r| {
        let f = r.files.entry(key.into()).or_default();
        let k = format!(
            "{}|{}|{}|{}",
            r.phase,
            bucket(bytes),
            if f.ever_written {
                "written_then_missing"
            } else {
                "never_written"
            },
            if f.not_persisted.is_empty() {
                "no_observed_reason"
            } else {
                &f.not_persisted
            }
        );
        *r.missing.entry(k).or_default() += 1;
    });
}
pub(crate) fn leaf(reason: &str) {
    with(|r| {
        *r.rows.entry(format!("wa.codec_leaf.{reason}")).or_default() += 1;
        let f = r.files.entry(r.current_key.clone()).or_default();
        f.not_persisted = format!("wa.codec_leaf.{reason}");
        f.reasons.insert(f.not_persisted.clone());
    });
}
pub(crate) fn cleared(key: &str, cause: &str, was_nonempty: bool, is_empty: bool) {
    with(|r| {
        *r.rows.entry(format!("clear_calls.{cause}")).or_default() += 1;
        if was_nonempty && is_empty {
            r.clears.insert(key.into(), cause.into());
            *r.rows
                .entry(format!("fingerprints_cleared.{cause}"))
                .or_default() += 1;
        }
    });
}
pub(crate) fn pass_peak(peak: Option<u64>) {
    with(|r| {
        for f in r
            .files
            .values_mut()
            .filter(|f| f.pass == r.pass && f.phase == r.phase && f.source == r.source && f.full)
        {
            f.footprint_peak = f.footprint_peak.max(peak.unwrap_or(0));
        }
    });
}
pub(crate) fn settled(fully: bool) {
    with(|r| r.settled = Some(fully));
}
pub(crate) fn restored(path: &str) {
    with(|r| {
        *r.restored_siblings.entry(path.into()).or_default() += 1;
    });
}
thread_local! {static CACHE:std::cell::RefCell<Option<std::sync::Weak<sampled_scan::SharedCache>>>=const{std::cell::RefCell::new(None)};}
pub(crate) fn bind_cache(cache: &std::sync::Arc<sampled_scan::SharedCache>) {
    if enabled() {
        CACHE.with(|c| *c.borrow_mut() = Some(std::sync::Arc::downgrade(cache)));
    }
}
pub(super) fn probe(site: &str, index: &ScanIndex, key: &str) {
    if !enabled() {
        return;
    }
    let held = index.claude_account_deferred_holds.contains_key(key);
    let owed = held
        && CACHE
            .with(|c| c.borrow().as_ref().and_then(std::sync::Weak::upgrade))
            .is_some_and(|c| c.owes_discovery(SnapshotSource::ClaudeCode, key));
    let absent = owed
        && std::fs::symlink_metadata(key).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
    with(|r| {
        for (name, yes) in [
            ("calls", true),
            ("account_held", held),
            ("held_and_owes", owed),
            ("held_owes_absent", absent),
        ] {
            if yes {
                *r.rows.entry(format!("X3_R4.{site}.{name}")).or_default() += 1;
            }
        }
    });
}
pub(crate) fn audits(index: &ScanIndex) {
    let now = sampled_scan::now_seconds();
    let mut n = 0;
    for (key, entry) in index.files.iter() {
        if let Some(due) = entry.unverified_deadline().filter(|due| *due <= now) {
            if !entry.has_prefix_provenance()
                && index
                    .claude_request_census
                    .get(key)
                    .is_some_and(|c| !c.unverified_or_twin() && c.window() >= due)
            {
                n += 1;
            }
        }
    }
    with(|r| {
        r.rows
            .insert("overdue_class_c_census_verified_post_due".into(), n);
    });
}

fn bucket(bytes: u64) -> &'static str {
    match bytes {
        0..=999_999 => "<1",
        1_000_000..=9_999_999 => "1-10",
        10_000_000..=49_999_999 => "10-50",
        50_000_000..=99_999_999 => "50-100",
        100_000_000..=300_000_000 => "100-300",
        _ => ">300",
    }
}
fn metric<T: crate::heap_layout_bound::HeapLayoutBound>(
    name: &'static str,
    value: &T,
    put: impl Fn(&mut Enc) -> Result<(), Refuse>,
) -> Field {
    let mut enc = Enc::count(usize::MAX);
    let encoded = put(&mut enc).ok().map(|_| enc.counted() as u64);
    let mut hash = Enc::hash("copied-corpus-field");
    let hash = put(&mut hash).ok().map(|_| hash.finish_hash());
    let decoded = crate::heap_layout_bound::completed_bound(value, usize::MAX).map(|n| n as u64);
    Field {
        name,
        encoded,
        decoded,
        hash,
    }
}
macro_rules! measure_fields {
    ($acc:ident; $($class:ident $field:ident: $ty:ty),* $(,)?) => {{
        // Exhaustive: additions to the accumulator must update the count inventory.
        let SnapshotAccumulator { $($field),* } = $acc;
        vec![$(metric(stringify!($field),$field,|e| {
            crate::durable_tail_codec::durable_field!(put $class,e,$field,$ty,
                concat!("SnapshotAccumulator.",stringify!($field)));
            Ok(())
        })),*]
    }};
}
fn fields(acc: &SnapshotAccumulator) -> Vec<Field> {
    measure_fields!(acc;
        N source: SnapshotSource,
        H cache_configuration_witness: Option<String>,
        N cache_task_complete_at: Option<String>,
        N cache_pending_idle: Option<u64>,
        L cache_active_turns: BTreeSet<String>,
        N context_curve_enabled: bool,
        U source_session_id: Option<String>,
        U account_identifier_hash: Option<String>,
        X title: Option<String>,
        N title_source: Option<String>,
        X first_prompt_title: Option<String>,
        X first_prompt_material: Option<String>,
        PL provider_skills: BTreeSet<String>,
        N started_at: Option<String>,
        N ended_at: Option<String>,
        N last_activity_at: Option<String>,
        U workspace_hash: Option<String>,
        X workspace_path: Option<PathBuf>,
        U latest_model: Option<String>,
        U latest_reasoning_effort: Option<String>,
        L latest_turn_id: Option<String>,
        I codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
        L codex_observed_priority_turns: Option<BTreeMap<String, bool>>,
        N codex_priority_witnesses_uncapped: bool,
        E codex_tier_replay: Option<codex_file_join::TierReplay>,
        D codex_counting: Option<Box<codex_usage_occurrence::CodexCounting>>,
        D current_selector: SelectorCapture,
        D session_cumulative_usage: Option<UsageTotals>,
        N codex_session_meta_seen: bool,
        N codex_record_seen: bool,
        U codex_creator_header_id: Option<String>,
        D codex_creator_evidence: Option<SessionAccountEvidence>,
        N codex_creator_evidence_conflicted: bool,
        E claude_desktop_identity: Option<SessionAccountEvidence>,
        E claude_desktop_spawn_lineage: Option<ClaudeDesktopSpawnLineage>,
        N claude_owned_session_id_observed: bool,
        N claude_owned_session_id_conflicted: bool,
        D codex_ownership_boundary: CodexOwnershipBoundary,
        N codex_legacy_trigger_seen: bool,
        N codex_legacy_bootstrap_valid: bool,
        I codex_parent_ownership_ledgers: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
        N codex_sidecar_created_thread: bool,
        D codex_path_sidecar_candidates: Vec<CodexPathSidecarCandidate>,
        U codex_resolved_path_identity: Option<String>,
        N codex_sidecar_identity_ambiguous: bool,
        U codex_sidecar_parent: Option<(String, String)>,
        N codex_sidecar_child_created_at_nanos: Option<i128>,
        N codex_bind_seed_len: Option<u64>,
        I codex_sidecar_projected_next_ordinal: Option<u64>,
        U codex_parent_session_ref: Option<String>,
        E codex_parent_signatures: Option<CodexParentPrefix>,
        H codex_parent_prefix_digest: PrefixDigest,
        D codex_parent_prefix_decided: Option<(u64, PrefixDigest, bool)>,
        E codex_parent_prefix_proof: Option<(CodexParentPrefixProof, PrefixDigest)>,
        E codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
        N codex_parent_proof_mismatch: bool,
        E codex_parent_proof_refusal: Option<ProofRefusal>,
        N codex_proof_decision_only: bool,
        N codex_boundary_buffer_count: u8,
        H codex_proof_ledger_row: Option<String>,
        H codex_parent_ledger_identity_used: Option<String>,
        D codex_parent_unresolvable: Option<CodexParentUnresolvable>,
        N codex_parent_ledger_consulted: bool,
        N codex_parent_signature_index: usize,
        N codex_native_created_thread_valid: bool,
        N codex_created_thread_native_only: bool,
        N codex_native_created_thread_header_nanos: Option<i128>,
        N codex_native_created_thread_last_nanos: Option<i128>,
        L codex_native_created_thread_task_turn_id: Option<String>,
        N codex_native_created_thread_first_turn_bound: bool,
        H codex_physical_signatures: crate::owned_heap::OwnedVec<String>,
        N codex_physical_signatures_complete: bool,
        N codex_ordinal_expected: Option<u64>,
        N codex_ordinal_sequence_valid: bool,
        N codex_owned_record_seen: bool,
        N codex_is_fork: bool,
        N codex_inherited_usage_records_skipped: u64,
        N codex_duplicate_usage_records_skipped: u64,
        N codex_cumulative_reset_count: u64,
        D codex_context_curve_candidates: crate::owned_heap::OwnedVec<ContextCurveCandidatePoint>,
        D codex_context_curve_boundaries: crate::owned_heap::OwnedVec<ContextCurveCandidateBoundary>,
        N codex_context_curve_exact_supported: bool,
        H codex_last_usage_event_identity: Option<String>,
        E codex_legacy_bootstrap_buffer: Vec<Value>,
        D accepted_usage_totals: UsageTotals,
        D usage_buckets: BTreeMap<String, UsageBucketState>,
        D origin: SnapshotOrigin,
        U codex_root_session_ref: Option<String>,
        N codex_spawn_depth: Option<u64>,
        X codex_agent_label: Option<String>,
        U activity_tool_counts: BTreeMap<String, u64>,
        D activity_call_tools: BTreeMap<ActivityCallId, ActivityCallTool>,
        U activity_mcp_tool_counts: BTreeMap<String, u64>,
        U activity_mcp_tool_usage_counts: BTreeMap<String, u64>,
        L activity_mcp_call_ids: BTreeMap<String, bool>,
        U activity_capability_buckets: BTreeMap<(String, String, String), u64>,
        L seen_claude_capability_tool_uses: crate::owned_heap::OwnedMap<String, ()>,
        PL activity_skills: BTreeSet<String>,
        N skill_detector_incomplete: bool,
        H activity_changed_file_hashes: BTreeSet<String>,
        N activity_patch_operations: u64,
        N activity_lines_added: u64,
        N activity_lines_deleted: u64,
        N activity_web_searches: u64,
        N activity_mcp_calls: u64,
        N activity_subagent_spawns: u64,
        E artifacts: Vec<SessionArtifact>,
        N artifacts_enabled: bool,
        N latency_duration_ms_sum: u64,
        N latency_duration_ms_count: u64,
        N latency_ttft_ms_sum: u64,
        N latency_ttft_ms_count: u64,
        N latency_duration_ms_max: u64,
        N latency_ttft_ms_max: u64,
        D claude_responses: ClaudeResponseBook,
        N claude_response_sequence: u64,
        N claude_response_record_count: usize,
        E claude_usage_request_ids: BTreeSet<String>,
        E claude_usage_occurrences: BTreeMap<String, ClaudeTranscriptUsageOccurrence>,
        N claude_request_identity_capture: bool,
        D claude_org_markers: Option<Box<claude_request_identity::OrgMarkers>>,
        E cache_observations: Option<CacheObservations>,
        D cache_requests: crate::owned_heap::OwnedVec<OwnedRequest>,
        N cache_requests_complete: bool,
        N claude_context_curve_identity_complete: bool,
        N claude_context_curve_request_index_complete: bool,
        N claude_context_curve_owned_start_proven: bool,
        D claude_file_birth: ClaudeFileBirth,
        E claude_fork_parent: Option<String>,
        E claude_money: Option<Box<claude_request_money::e2::FileFold>>,
        U tool_usage_counts: BTreeMap<String, u64>,
        N tool_usage_truncated: bool,
        E seen_pi_usage_keys: BTreeMap<String, PiUsageDedupState>,
        N dropped_usage_record_count: u64,
        N claude_last_user_ts: Option<String>,
        N peak_context_fill_tokens: u64,
        N first_turn_context_tokens: Option<u64>,
        N last_turn_context_tokens: Option<u64>,
        N first_turn_context_window_tokens: Option<u64>,
        N peak_context_fill_window_tokens: Option<u64>,
        N last_turn_context_window_tokens: Option<u64>,
        N compaction_count: u64,
        N compaction_timestamps: crate::owned_heap::OwnedVec<String>,
        D codex_compaction_sizes: CodexCompactionSizes,
        D local_context_points: LocalContextPoints,
        D claude_compaction_observations: crate::owned_heap::OwnedVec<ClaudeCompactionObservation>,
        L claude_compaction_link_tip: Option<(u64, String)>,
        D session_start: Box<session_start::SessionStartState>,
        D durable_marks: crate::durable_tail_codec::DurableMarks,
    )
}

pub(super) fn state(
    path: &Path,
    acc: &SnapshotAccumulator,
    report: &JsonlReadReport,
    drops: u64,
    sealed_fragment: bool,
    consumed: u64,
    last_end: u64,
) {
    if !enabled() {
        return;
    }
    let samples = fields(acc);
    let key = local_index_key(path);
    let footprint = crate::local_resource_diagnostics::state_v2_memory()
        .phys_footprint_bytes
        .unwrap_or(0);
    with(|r| {
        let ctx = r.contexts.remove(&key);
        let (mode, reason, bytes, native, accepted) = ctx
            .map(|c| (c.mode, c.reason, c.bytes, c.native, c.accepted))
            .unwrap_or_else(|| ("unobserved".into(), "unobserved".into(), 0, 0, 0));
        let reason = r
            .clears
            .remove(&key)
            .map(|c| format!("rearm_cleared.{c}"))
            .unwrap_or(reason);
        let reason = format!("{}|{}", r.source, reason);
        r.current_key = key.clone();
        let f = r.files.entry(key).or_default();
        let table = r.diffs.entry(reason.clone()).or_default();
        *table.entry("completions".into()).or_default() += 1;
        *table.entry("native_bytes".into()).or_default() += native;
        if mode.starts_with("Full") {
            *table.entry("fulls".into()).or_default() += 1;
            *table.entry("full_native_bytes".into()).or_default() += native;
        }
        if f.completions > 0 && mode.starts_with("Full") {
            let mut different = false;
            let mut unknown = false;
            for (old, new) in f.fields.iter().zip(&samples) {
                match (old.hash, new.hash) {
                    (Some(a), Some(b)) if a != b => {
                        different = true;
                        *table.entry(format!("field.{}", new.name)).or_default() += 1;
                    }
                    (None, _) | (_, None) => {
                        unknown = true;
                        *table
                            .entry(format!("uncomparable.{}", new.name))
                            .or_default() += 1;
                    }
                    _ => {}
                }
            }
            *table
                .entry(
                    if different {
                        "different"
                    } else if unknown {
                        "equal_observable_unknown_rest"
                    } else {
                        "equal"
                    }
                    .into(),
                )
                .or_default() += 1;
        } else if mode.starts_with("Full") {
            *table.entry("no_prior".into()).or_default() += 1;
        }
        let decoded = samples.iter().filter_map(|f| f.decoded).sum::<u64>();
        f.decoded_peak = f.decoded_peak.max(decoded);
        f.decode_scratch_peak = f.decode_scratch_peak.max(
            acc.claude_responses
                .decode_peak_bound(usize::MAX)
                .unwrap_or(0) as u64,
        );
        f.response_records_peak = f
            .response_records_peak
            .max(acc.claude_response_record_count as u64);
        f.records_per_response_peak = f.records_per_response_peak.max(
            acc.claude_responses
                .values()
                .map(|v| v.records.len() as u64)
                .max()
                .unwrap_or(0),
        );
        *r.completions_by_phase
            .entry(format!("{}|{}", r.source, r.phase))
            .or_default() += 1;
        f.footprint_peak = f.footprint_peak.max(footprint);
        if bytes > f.bytes && f.completions > 0 {
            f.grew = true;
        }
        f.bytes = f.bytes.max(bytes);
        f.source = r.source.clone();
        f.last_reason = reason.clone();
        if let Some(entity) = &acc.source_session_id {
            r.entity_causes.insert(entity.clone(), reason);
        }
        f.completions += 1;
        f.pass = r.pass;
        f.phase = r.phase.clone();
        f.full = mode.starts_with("Full");
        f.cap = acc.claude_response_record_count >= 65_536
            || acc
                .claude_responses
                .values()
                .any(|x| x.record_limit_exceeded);
        if drops + acc.dropped_usage_record_count > 0 {
            f.dropped += 1;
        }
        if consumed != last_end && !sealed_fragment {
            f.unsealed += 1;
        }
        // Keep one sample per file: field sizes are completion maxima, digest is latest.
        if f.fields.is_empty() {
            f.fields = samples;
        } else {
            for (old, new) in f.fields.iter_mut().zip(samples) {
                old.encoded = old.encoded.zip(new.encoded).map(|(a, b)| a.max(b));
                old.decoded = old.decoded.zip(new.decoded).map(|(a, b)| a.max(b));
                old.hash = new.hash;
            }
        }
        *r.rows.entry("completions".into()).or_default() += 1;
        *r.rows
            .entry("oversize_line_observations".into())
            .or_default() += report.over_line_cap_count as u64;
        *r.rows
            .entry("decoded_completion_bytes_sum".into())
            .or_default() += decoded;
        if r.phase == "growth" && mode.starts_with("Full") {
            r.full_growth
                .entry(format!("{}|{}", r.source, bucket(bytes)))
                .or_default()
                .push([native, bytes.saturating_sub(accepted)]);
        }
    });
}
pub(crate) fn wire(old: Option<&Value>, new: &Value) {
    with(|r| {
        let entity = new["source_session_id"].as_str().unwrap_or_default();
        let reason = r
            .entity_causes
            .get(entity)
            .map(String::as_str)
            .unwrap_or("unobserved");
        let row = r.wire_diffs.entry(reason.into()).or_default();
        let Some(old) = old else {
            *row.entry("no_prior_server_body".into()).or_default() += 1;
            return;
        };
        *row.entry(
            if old == new {
                "byte_identical"
            } else {
                "changed"
            }
            .into(),
        )
        .or_default() += 1;
        if let (Some(a), Some(b)) = (old.as_object(), new.as_object()) {
            let fields: BTreeSet<_> = a.keys().chain(b.keys()).collect();
            for field in fields {
                if a.get(field) != b.get(field) {
                    *row.entry(format!("field.{field}")).or_default() += 1;
                }
            }
        }
    });
}

pub(super) fn projection(path: &Path, items: &[SnapshotItem], drops: u64, oversize: u64) {
    if !enabled() {
        return;
    }
    // All bytes remain in the process; only equality counts leave it.
    let mut v = serde_json::to_value(items).unwrap_or(Value::Null);
    if let Some(items) = v.as_array_mut() {
        for item in items {
            if let Some(o) = item.as_object_mut() {
                o.remove("collected_at");
                o.remove("snapshot_fingerprint");
                o.remove("source_file_fingerprint");
            }
        }
    }
    use sha2::Digest;
    let hash: [u8; 32] = sha2::Sha256::digest(serde_json::to_vec(&v).unwrap_or_default()).into();
    let mut projection_fields = BTreeMap::new();
    if let Some(items) = v.as_array() {
        let names: BTreeSet<_> = items
            .iter()
            .flat_map(|v| v.as_object().into_iter().flat_map(|o| o.keys().cloned()))
            .collect();
        for name in names {
            let values: Vec<_> = items
                .iter()
                .map(|v| v.get(&name).unwrap_or(&Value::Null))
                .collect();
            projection_fields.insert(
                name,
                sha2::Sha256::digest(serde_json::to_vec(&values).unwrap_or_default()).into(),
            );
        }
    }
    with(|r| {
        let f = r.files.entry(local_index_key(path)).or_default();
        let row = r.projection.entry(f.last_reason.clone()).or_default();
        if f.last_projection.is_some() {
            let names: BTreeSet<_> = f
                .projection_fields
                .keys()
                .chain(projection_fields.keys())
                .collect();
            for name in names {
                if f.projection_fields.get(name) != projection_fields.get(name) {
                    *row.entry(format!("field.{name}")).or_default() += 1;
                }
            }
        }
        f.projection_fields = projection_fields;
        if let Some(old) = f.last_projection {
            *row.entry(if old == hash { "identical" } else { "changed" }.into())
                .or_default() += 1;
        } else {
            *row.entry("no_prior".into()).or_default() += 1;
        }
        f.last_projection = Some(hash);
        if drops > 0 && !f.cap {
            f.noncap_dropped += 1;
        }
        if drops > oversize {
            *r.rows
                .entry("post_finish_non_line_drop_completions".into())
                .or_default() += 1;
        }
    });
}
fn stats(mut v: Vec<u64>) -> Value {
    if v.is_empty() {
        return Value::Null;
    }
    v.sort_unstable();
    let n = v.len();
    json!({"n":n,"sum":v.iter().sum::<u64>(),"p50":v[(n-1)/2],"p95":v[(n*95).div_ceil(100)-1],"max":v[n-1]})
}
pub(crate) fn row() -> Value {
    let mut out = Value::Null;
    with(|r| {
        out = json!({"counts":r.rows,"events":r.events,"restored_siblings":r.restored_siblings,"upload_fully_settled":r.settled});
    });
    out
}
pub(crate) fn end() -> Value {
    let mut out = Value::Null;
    with(|r| {
        let mut groups: BTreeMap<String, Vec<&FileCount>> = BTreeMap::new();
        for f in r.files.values().filter(|f| f.completions > 0) {
            groups
                .entry(format!("{}|{}", f.source, bucket(f.bytes)))
                .or_default()
                .push(f);
        }
        let mut sizes = BTreeMap::new();
        let mut heads = BTreeMap::new();
        let mut peaks = BTreeMap::new();
        for (bucket, files) in groups {
            let mut fields_out = BTreeMap::new();
            for (i, field) in files[0].fields.iter().enumerate() {
                fields_out.insert(field.name,json!({
 "encoded":stats(files.iter().filter_map(|f|f.fields.get(i).and_then(|s|s.encoded)).collect()),
 "decoded":stats(files.iter().filter_map(|f|f.fields.get(i).and_then(|s|s.decoded)).collect()),
 "encoded_unknown":files.iter().filter(|f|f.fields.get(i).is_none_or(|s|s.encoded.is_none())).count(),
 "decoded_unknown":files.iter().filter(|f|f.fields.get(i).is_none_or(|s|s.decoded.is_none())).count(),
 }));
            }
            heads.insert(
                bucket.clone(),
                stats(
                    files
                        .iter()
                        .map(|f| {
                            f.fields
                                .iter()
                                .filter(|s| s.name != "claude_responses")
                                .filter_map(|s| s.encoded)
                                .sum()
                        })
                        .collect(),
                ),
            );
            peaks.insert(bucket.clone(),json!({"decoded":stats(files.iter().map(|f|f.decoded_peak).collect()),"footprint_pass_upper_bound":files.iter().map(|f|f.footprint_peak).max(),"decode_scratch":stats(files.iter().map(|f|f.decode_scratch_peak).collect()),"response_records_max":files.iter().map(|f|f.response_records_peak).max(),"records_per_response_max":files.iter().map(|f|f.records_per_response_peak).max()}));
            sizes.insert(bucket, json!(fields_out));
        }
        let mut np: BTreeMap<&str, [u64; 2]> = BTreeMap::new();
        for f in r.files.values() {
            for reason in &f.reasons {
                let c = np.entry(reason).or_default();
                c[0] += 1;
                c[1] += u64::from(f.grew);
            }
        }
        let mut largest: Vec<_> = r.files.values().filter(|f| f.completions > 0).collect();
        largest.sort_by_key(|f| std::cmp::Reverse(f.bytes));
        let largest:Vec<_>=largest.into_iter().take(12).map(|f|json!({"source":f.source,
            "transcript_bytes":f.bytes,"decoded_bytes":f.decoded_peak,"decode_scratch":f.decode_scratch_peak,
            "footprint_pass_upper_bound":f.footprint_peak})).collect();
        let head_unknown_files = r
            .files
            .values()
            .filter(|f| {
                f.completions > 0
                    && f.fields
                        .iter()
                        .any(|s| s.name != "claude_responses" && s.encoded.is_none())
            })
            .count();
        out = json!({"head_unknown_files":head_unknown_files,"largest_files":largest,"sizes":sizes,"heads_encoded_known_subtotal":heads,"peaks":peaks,"touches":r.touches,
        "state_diffs":r.diffs,"projection_diffs":r.projection,"wire_diffs":r.wire_diffs,"missing":r.missing,
        "growth_full":r.full_growth.iter().map(|(k,v)|(k,json!({"read":stats(v.iter().map(|x|x[0]).collect()),"appended":stats(v.iter().map(|x|x[1]).collect())}))).collect::<BTreeMap<_,_>>(),
        "not_persisted_files_and_later_grew":np,
        "recurring_dropped_files":r.files.values().filter(|f|f.noncap_dropped>1).count(),
        "unsealed_completions":r.files.values().map(|f|f.unsealed).sum::<u64>(),
        "unsealed_files":r.files.values().filter(|f|f.unsealed>0).count(),
        "completions":r.files.values().map(|f|f.completions).sum::<u64>(),
        "completions_by_phase":r.completions_by_phase,
        "instrument_field_slots":r.files.values().map(|f|f.fields.len()).sum::<usize>(),
        "instrument_field_slot_bytes":std::mem::size_of::<Field>(),
        });
    });
    out
}
