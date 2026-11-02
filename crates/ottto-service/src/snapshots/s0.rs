//! Count-only instrumentation for the ignored copied-corpus harness.
//! No keys, digests, field values or provider identities leave this recorder.
use super::*;
use crate::durable_tail_codec::{Durable, Enc, Refuse};
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
    elements: u64,
    class: &'static str,
    nonempty: bool,
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
    last_native_bytes: u64,
    last_forced_drain_pass: u64,
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
    stage: BTreeMap<String, [u64; 4]>,
    stage_peak: [u64; 4],
    page_plans: BTreeMap<String, Vec<u64>>,
    touched_slots: BTreeMap<String, BTreeSet<usize>>,
    reading_key: String,
    completion_geometry: BTreeMap<String, Vec<u64>>,
    e_fields: BTreeMap<String, u64>,
    finish_fields: BTreeMap<String, u64>,
    toggle_diffs: BTreeMap<String, BTreeMap<String, u64>>,
    no_save: BTreeMap<String, u64>,
    exit_cause: String,
    forced_origins: BTreeMap<String, BTreeSet<String>>,
    forced_loop: BTreeMap<String, [u64; 2]>,
    forced_loop_files: BTreeMap<String, BTreeSet<String>>,
    forced_loop_fields: BTreeMap<String, u64>,
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
        r.stage.clear();
        r.stage_peak = [0; 4];
        r.exit_cause = "not_reached".into();
        r.forced_origins.clear();
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
pub(super) fn touch(slot: usize, entries: usize, encoded_after: Option<u64>) {
    with(|r| {
        r.touched_slots
            .entry(r.reading_key.clone())
            .or_default()
            .insert(slot);
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
    elements: u64,
    class: &'static str,
    nonempty: bool,
    put: impl Fn(&mut Enc) -> Result<(), Refuse>,
) -> Field {
    let mut enc = Enc::count(usize::MAX);
    let encoded = put(&mut enc).ok().map(|_| enc.counted() as u64);
    let mut hash = Enc::hash("copied-corpus-field");
    let hash = put(&mut hash).ok().map(|_| hash.finish_hash());
    let decoded = layout_bytes(value).map(|n| n as u64);
    Field {
        elements,
        class,
        nonempty,
        name,
        encoded,
        decoded,
        hash,
    }
}
macro_rules! measure_fields {
    ($acc:ident; $($class:ident $field:ident: $ty:ty => $elements:expr,$nonempty:expr),* $(,)?) => {{
        let SnapshotAccumulator { $($field),* } = $acc;
        vec![$(metric(stringify!($field),$field,$elements,stringify!($class),$nonempty,|e| {
            crate::durable_tail_codec::durable_field!(put $class,e,$field,$ty,
                concat!("SnapshotAccumulator.",stringify!($field)));
            Ok(())
        })),*]
    }};
}
fn fields(acc: &SnapshotAccumulator) -> Vec<Field> {
    let mut result = measure_fields!(acc;
        N source: SnapshotSource => 1,1 != 0,
        H cache_configuration_witness: Option<String> => u64::from(cache_configuration_witness.is_some()),u64::from(cache_configuration_witness.is_some()) != 0,
        N cache_task_complete_at: Option<String> => u64::from(cache_task_complete_at.is_some()),u64::from(cache_task_complete_at.is_some()) != 0,
        N cache_pending_idle: Option<u64> => u64::from(cache_pending_idle.is_some()),u64::from(cache_pending_idle.is_some()) != 0,
        L cache_active_turns: BTreeSet<String> => cache_active_turns.len() as u64,cache_active_turns.len() as u64 != 0,
        N context_curve_enabled: bool => 1,1 != 0,
        U source_session_id: Option<String> => u64::from(source_session_id.is_some()),u64::from(source_session_id.is_some()) != 0,
        U account_identifier_hash: Option<String> => u64::from(account_identifier_hash.is_some()),u64::from(account_identifier_hash.is_some()) != 0,
        X title: Option<String> => u64::from(title.is_some()),u64::from(title.is_some()) != 0,
        N title_source: Option<String> => u64::from(title_source.is_some()),u64::from(title_source.is_some()) != 0,
        X first_prompt_title: Option<String> => u64::from(first_prompt_title.is_some()),u64::from(first_prompt_title.is_some()) != 0,
        X first_prompt_material: Option<String> => u64::from(first_prompt_material.is_some()),u64::from(first_prompt_material.is_some()) != 0,
        PL provider_skills: BTreeSet<String> => provider_skills.len() as u64,provider_skills.len() as u64 != 0,
        N started_at: Option<String> => u64::from(started_at.is_some()),u64::from(started_at.is_some()) != 0,
        N ended_at: Option<String> => u64::from(ended_at.is_some()),u64::from(ended_at.is_some()) != 0,
        N last_activity_at: Option<String> => u64::from(last_activity_at.is_some()),u64::from(last_activity_at.is_some()) != 0,
        U workspace_hash: Option<String> => u64::from(workspace_hash.is_some()),u64::from(workspace_hash.is_some()) != 0,
        X workspace_path: Option<PathBuf> => u64::from(workspace_path.is_some()),u64::from(workspace_path.is_some()) != 0,
        U latest_model: Option<String> => u64::from(latest_model.is_some()),u64::from(latest_model.is_some()) != 0,
        U latest_reasoning_effort: Option<String> => u64::from(latest_reasoning_effort.is_some()),u64::from(latest_reasoning_effort.is_some()) != 0,
        L latest_turn_id: Option<String> => u64::from(latest_turn_id.is_some()),u64::from(latest_turn_id.is_some()) != 0,
        I codex_turn_traces: Option<Arc<CodexTurnTraceMap>> => u64::from(codex_turn_traces.is_some()),u64::from(codex_turn_traces.is_some()) != 0,
        L codex_observed_priority_turns: Option<BTreeMap<String, bool>> => u64::from(codex_observed_priority_turns.is_some()),u64::from(codex_observed_priority_turns.is_some()) != 0,
        N codex_priority_witnesses_uncapped: bool => 1,1 != 0,
        E codex_tier_replay: Option<codex_file_join::TierReplay> => u64::from(codex_tier_replay.is_some()),!crate::durable_tail_codec::DurableEmpty::durable_empty(codex_tier_replay),
        D codex_counting: Option<Box<codex_usage_occurrence::CodexCounting>> => u64::from(codex_counting.is_some()),u64::from(codex_counting.is_some()) != 0,
        D current_selector: SelectorCapture => 1,1 != 0,
        D session_cumulative_usage: Option<UsageTotals> => u64::from(session_cumulative_usage.is_some()),u64::from(session_cumulative_usage.is_some()) != 0,
        N codex_session_meta_seen: bool => 1,1 != 0,
        N codex_record_seen: bool => 1,1 != 0,
        U codex_creator_header_id: Option<String> => u64::from(codex_creator_header_id.is_some()),u64::from(codex_creator_header_id.is_some()) != 0,
        D codex_creator_evidence: Option<SessionAccountEvidence> => u64::from(codex_creator_evidence.is_some()),u64::from(codex_creator_evidence.is_some()) != 0,
        N codex_creator_evidence_conflicted: bool => 1,1 != 0,
        E claude_desktop_identity: Option<SessionAccountEvidence> => u64::from(claude_desktop_identity.is_some()),!crate::durable_tail_codec::DurableEmpty::durable_empty(claude_desktop_identity),
        E claude_desktop_spawn_lineage: Option<ClaudeDesktopSpawnLineage> => u64::from(claude_desktop_spawn_lineage.is_some()),!crate::durable_tail_codec::DurableEmpty::durable_empty(claude_desktop_spawn_lineage),
        N claude_owned_session_id_observed: bool => 1,1 != 0,
        N claude_owned_session_id_conflicted: bool => 1,1 != 0,
        D codex_ownership_boundary: CodexOwnershipBoundary => 1,1 != 0,
        N codex_legacy_trigger_seen: bool => 1,1 != 0,
        N codex_legacy_bootstrap_valid: bool => 1,1 != 0,
        I codex_parent_ownership_ledgers: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>> => u64::from(codex_parent_ownership_ledgers.is_some()),u64::from(codex_parent_ownership_ledgers.is_some()) != 0,
        N codex_sidecar_created_thread: bool => 1,1 != 0,
        D codex_path_sidecar_candidates: Vec<CodexPathSidecarCandidate> => codex_path_sidecar_candidates.len() as u64,codex_path_sidecar_candidates.len() as u64 != 0,
        U codex_resolved_path_identity: Option<String> => u64::from(codex_resolved_path_identity.is_some()),u64::from(codex_resolved_path_identity.is_some()) != 0,
        N codex_sidecar_identity_ambiguous: bool => 1,1 != 0,
        U codex_sidecar_parent: Option<(String, String)> => u64::from(codex_sidecar_parent.is_some()),u64::from(codex_sidecar_parent.is_some()) != 0,
        N codex_sidecar_child_created_at_nanos: Option<i128> => u64::from(codex_sidecar_child_created_at_nanos.is_some()),u64::from(codex_sidecar_child_created_at_nanos.is_some()) != 0,
        N codex_bind_seed_len: Option<u64> => u64::from(codex_bind_seed_len.is_some()),u64::from(codex_bind_seed_len.is_some()) != 0,
        I codex_sidecar_projected_next_ordinal: Option<u64> => u64::from(codex_sidecar_projected_next_ordinal.is_some()),u64::from(codex_sidecar_projected_next_ordinal.is_some()) != 0,
        U codex_parent_session_ref: Option<String> => u64::from(codex_parent_session_ref.is_some()),u64::from(codex_parent_session_ref.is_some()) != 0,
        E codex_parent_signatures: Option<CodexParentPrefix> => u64::from(codex_parent_signatures.is_some()),!crate::durable_tail_codec::DurableEmpty::durable_empty(codex_parent_signatures),
        H codex_parent_prefix_digest: PrefixDigest => 1,1 != 0,
        D codex_parent_prefix_decided: Option<(u64, PrefixDigest, bool)> => u64::from(codex_parent_prefix_decided.is_some()),u64::from(codex_parent_prefix_decided.is_some()) != 0,
        E codex_parent_prefix_proof: Option<(CodexParentPrefixProof, PrefixDigest)> => u64::from(codex_parent_prefix_proof.is_some()),!crate::durable_tail_codec::DurableEmpty::durable_empty(codex_parent_prefix_proof),
        E codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)> => u64::from(codex_parent_proof_used.is_some()),!crate::durable_tail_codec::DurableEmpty::durable_empty(codex_parent_proof_used),
        N codex_parent_proof_mismatch: bool => 1,1 != 0,
        E codex_parent_proof_refusal: Option<ProofRefusal> => u64::from(codex_parent_proof_refusal.is_some()),!crate::durable_tail_codec::DurableEmpty::durable_empty(codex_parent_proof_refusal),
        N codex_proof_decision_only: bool => 1,1 != 0,
        N codex_boundary_buffer_count: u8 => 1,1 != 0,
        H codex_proof_ledger_row: Option<String> => u64::from(codex_proof_ledger_row.is_some()),u64::from(codex_proof_ledger_row.is_some()) != 0,
        H codex_parent_ledger_identity_used: Option<String> => u64::from(codex_parent_ledger_identity_used.is_some()),u64::from(codex_parent_ledger_identity_used.is_some()) != 0,
        D codex_parent_unresolvable: Option<CodexParentUnresolvable> => u64::from(codex_parent_unresolvable.is_some()),u64::from(codex_parent_unresolvable.is_some()) != 0,
        N codex_parent_ledger_consulted: bool => 1,1 != 0,
        N codex_parent_signature_index: usize => 1,1 != 0,
        N codex_native_created_thread_valid: bool => 1,1 != 0,
        N codex_created_thread_native_only: bool => 1,1 != 0,
        N codex_native_created_thread_header_nanos: Option<i128> => u64::from(codex_native_created_thread_header_nanos.is_some()),u64::from(codex_native_created_thread_header_nanos.is_some()) != 0,
        N codex_native_created_thread_last_nanos: Option<i128> => u64::from(codex_native_created_thread_last_nanos.is_some()),u64::from(codex_native_created_thread_last_nanos.is_some()) != 0,
        L codex_native_created_thread_task_turn_id: Option<String> => u64::from(codex_native_created_thread_task_turn_id.is_some()),u64::from(codex_native_created_thread_task_turn_id.is_some()) != 0,
        N codex_native_created_thread_first_turn_bound: bool => 1,1 != 0,
        H codex_physical_signatures: crate::owned_heap::OwnedVec<String> => codex_physical_signatures.len() as u64,codex_physical_signatures.len() as u64 != 0,
        N codex_physical_signatures_complete: bool => 1,1 != 0,
        N codex_ordinal_expected: Option<u64> => u64::from(codex_ordinal_expected.is_some()),u64::from(codex_ordinal_expected.is_some()) != 0,
        N codex_ordinal_sequence_valid: bool => 1,1 != 0,
        N codex_owned_record_seen: bool => 1,1 != 0,
        N codex_is_fork: bool => 1,1 != 0,
        N codex_inherited_usage_records_skipped: u64 => 1,1 != 0,
        N codex_duplicate_usage_records_skipped: u64 => 1,1 != 0,
        N codex_cumulative_reset_count: u64 => 1,1 != 0,
        D codex_context_curve_candidates: crate::owned_heap::OwnedVec<ContextCurveCandidatePoint> => codex_context_curve_candidates.len() as u64,codex_context_curve_candidates.len() as u64 != 0,
        D codex_context_curve_boundaries: crate::owned_heap::OwnedVec<ContextCurveCandidateBoundary> => codex_context_curve_boundaries.len() as u64,codex_context_curve_boundaries.len() as u64 != 0,
        N codex_context_curve_exact_supported: bool => 1,1 != 0,
        H codex_last_usage_event_identity: Option<String> => u64::from(codex_last_usage_event_identity.is_some()),u64::from(codex_last_usage_event_identity.is_some()) != 0,
        E codex_legacy_bootstrap_buffer: Vec<Value> => codex_legacy_bootstrap_buffer.len() as u64,!crate::durable_tail_codec::DurableEmpty::durable_empty(codex_legacy_bootstrap_buffer),
        D accepted_usage_totals: UsageTotals => 1,1 != 0,
        D usage_buckets: BTreeMap<String, UsageBucketState> => usage_buckets.len() as u64,usage_buckets.len() as u64 != 0,
        D origin: SnapshotOrigin => 1,1 != 0,
        U codex_root_session_ref: Option<String> => u64::from(codex_root_session_ref.is_some()),u64::from(codex_root_session_ref.is_some()) != 0,
        N codex_spawn_depth: Option<u64> => u64::from(codex_spawn_depth.is_some()),u64::from(codex_spawn_depth.is_some()) != 0,
        X codex_agent_label: Option<String> => u64::from(codex_agent_label.is_some()),u64::from(codex_agent_label.is_some()) != 0,
        U activity_tool_counts: BTreeMap<String, u64> => activity_tool_counts.len() as u64,activity_tool_counts.len() as u64 != 0,
        D activity_call_tools: BTreeMap<ActivityCallId, ActivityCallTool> => activity_call_tools.len() as u64,activity_call_tools.len() as u64 != 0,
        U activity_mcp_tool_counts: BTreeMap<String, u64> => activity_mcp_tool_counts.len() as u64,activity_mcp_tool_counts.len() as u64 != 0,
        U activity_mcp_tool_usage_counts: BTreeMap<String, u64> => activity_mcp_tool_usage_counts.len() as u64,activity_mcp_tool_usage_counts.len() as u64 != 0,
        L activity_mcp_call_ids: BTreeMap<String, bool> => activity_mcp_call_ids.len() as u64,activity_mcp_call_ids.len() as u64 != 0,
        U activity_capability_buckets: BTreeMap<(String, String, String), u64> => activity_capability_buckets.len() as u64,activity_capability_buckets.len() as u64 != 0,
        L seen_claude_capability_tool_uses: crate::owned_heap::OwnedMap<String, ()> => seen_claude_capability_tool_uses.len() as u64,seen_claude_capability_tool_uses.len() as u64 != 0,
        PL activity_skills: BTreeSet<String> => activity_skills.len() as u64,activity_skills.len() as u64 != 0,
        N skill_detector_incomplete: bool => 1,1 != 0,
        H activity_changed_file_hashes: BTreeSet<String> => activity_changed_file_hashes.len() as u64,activity_changed_file_hashes.len() as u64 != 0,
        N activity_patch_operations: u64 => 1,1 != 0,
        N activity_lines_added: u64 => 1,1 != 0,
        N activity_lines_deleted: u64 => 1,1 != 0,
        N activity_web_searches: u64 => 1,1 != 0,
        N activity_mcp_calls: u64 => 1,1 != 0,
        N activity_subagent_spawns: u64 => 1,1 != 0,
        E artifacts: Vec<SessionArtifact> => artifacts.len() as u64,!crate::durable_tail_codec::DurableEmpty::durable_empty(artifacts),
        N artifacts_enabled: bool => 1,1 != 0,
        N latency_duration_ms_sum: u64 => 1,1 != 0,
        N latency_duration_ms_count: u64 => 1,1 != 0,
        N latency_ttft_ms_sum: u64 => 1,1 != 0,
        N latency_ttft_ms_count: u64 => 1,1 != 0,
        N latency_duration_ms_max: u64 => 1,1 != 0,
        N latency_ttft_ms_max: u64 => 1,1 != 0,
        D claude_responses: ClaudeResponseBook => 1,1 != 0,
        N claude_response_sequence: u64 => 1,1 != 0,
        N claude_response_record_count: usize => 1,1 != 0,
        E claude_usage_request_ids: BTreeSet<String> => claude_usage_request_ids.len() as u64,!crate::durable_tail_codec::DurableEmpty::durable_empty(claude_usage_request_ids),
        E claude_usage_occurrences: BTreeMap<String, ClaudeTranscriptUsageOccurrence> => claude_usage_occurrences.len() as u64,!crate::durable_tail_codec::DurableEmpty::durable_empty(claude_usage_occurrences),
        N claude_request_identity_capture: bool => 1,1 != 0,
        D claude_org_markers: Option<Box<claude_request_identity::OrgMarkers>> => u64::from(claude_org_markers.is_some()),u64::from(claude_org_markers.is_some()) != 0,
        E cache_observations: Option<CacheObservations> => u64::from(cache_observations.is_some()),!crate::durable_tail_codec::DurableEmpty::durable_empty(cache_observations),
        D cache_requests: crate::owned_heap::OwnedVec<OwnedRequest> => cache_requests.len() as u64,cache_requests.len() as u64 != 0,
        N cache_requests_complete: bool => 1,1 != 0,
        N claude_context_curve_identity_complete: bool => 1,1 != 0,
        N claude_context_curve_request_index_complete: bool => 1,1 != 0,
        N claude_context_curve_owned_start_proven: bool => 1,1 != 0,
        D claude_file_birth: ClaudeFileBirth => 1,1 != 0,
        E claude_fork_parent: Option<String> => u64::from(claude_fork_parent.is_some()),!crate::durable_tail_codec::DurableEmpty::durable_empty(claude_fork_parent),
        E claude_money: Option<Box<claude_request_money::e2::FileFold>> => u64::from(claude_money.is_some()),!crate::durable_tail_codec::DurableEmpty::durable_empty(claude_money),
        U tool_usage_counts: BTreeMap<String, u64> => tool_usage_counts.len() as u64,tool_usage_counts.len() as u64 != 0,
        N tool_usage_truncated: bool => 1,1 != 0,
        E seen_pi_usage_keys: BTreeMap<String, PiUsageDedupState> => seen_pi_usage_keys.len() as u64,!crate::durable_tail_codec::DurableEmpty::durable_empty(seen_pi_usage_keys),
        N dropped_usage_record_count: u64 => 1,1 != 0,
        N claude_last_user_ts: Option<String> => u64::from(claude_last_user_ts.is_some()),u64::from(claude_last_user_ts.is_some()) != 0,
        N peak_context_fill_tokens: u64 => 1,1 != 0,
        N first_turn_context_tokens: Option<u64> => u64::from(first_turn_context_tokens.is_some()),u64::from(first_turn_context_tokens.is_some()) != 0,
        N last_turn_context_tokens: Option<u64> => u64::from(last_turn_context_tokens.is_some()),u64::from(last_turn_context_tokens.is_some()) != 0,
        N first_turn_context_window_tokens: Option<u64> => u64::from(first_turn_context_window_tokens.is_some()),u64::from(first_turn_context_window_tokens.is_some()) != 0,
        N peak_context_fill_window_tokens: Option<u64> => u64::from(peak_context_fill_window_tokens.is_some()),u64::from(peak_context_fill_window_tokens.is_some()) != 0,
        N last_turn_context_window_tokens: Option<u64> => u64::from(last_turn_context_window_tokens.is_some()),u64::from(last_turn_context_window_tokens.is_some()) != 0,
        N compaction_count: u64 => 1,1 != 0,
        N compaction_timestamps: crate::owned_heap::OwnedVec<String> => compaction_timestamps.len() as u64,compaction_timestamps.len() as u64 != 0,
        D codex_compaction_sizes: CodexCompactionSizes => 1,1 != 0,
        D local_context_points: LocalContextPoints => 1,1 != 0,
        D claude_compaction_observations: crate::owned_heap::OwnedVec<ClaudeCompactionObservation> => claude_compaction_observations.len() as u64,claude_compaction_observations.len() as u64 != 0,
        L claude_compaction_link_tip: Option<(u64, String)> => u64::from(claude_compaction_link_tip.is_some()),u64::from(claude_compaction_link_tip.is_some()) != 0,
        D session_start: Box<session_start::SessionStartState> => 1,1 != 0,
        D durable_marks: crate::durable_tail_codec::DurableMarks => 1,1 != 0,
    );
    if let Some(book) = result.iter_mut().find(|f| f.name == "claude_responses") {
        book.elements = acc.claude_responses.values().len() as u64;
        book.nonempty = book.elements > 0;
    }
    result
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
    let geometry = acc.claude_responses.s0_geometry();
    let pages = page_collections(acc);
    let toggles: Vec<(String, Vec<String>)> = Vec::new();
    let footprint = crate::local_resource_diagnostics::state_v2_memory()
        .phys_footprint_bytes
        .unwrap_or(0);
    with(|r| {
        let ctx = r.contexts.remove(&key);
        let (mode, reason, bytes, native, accepted) = ctx
            .map(|c| (c.mode, c.reason, c.bytes, c.native, c.accepted))
            .unwrap_or_else(|| ("unobserved".into(), "unobserved".into(), 0, 0, 0));
        let forced =
            reason.contains("ForcedFamily") && mode.starts_with("Full") && r.phase == "drain";
        let origin = claude_index_path_family_member(path)
            .and_then(|(root, _)| r.forced_origins.get(&root))
            .map(|set| set.iter().map(String::as_str).collect::<Vec<_>>().join("+"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".into());
        let reason = r
            .clears
            .remove(&key)
            .map(|c| format!("rearm_cleared.{c}"))
            .unwrap_or(reason);
        let reason = format!("{}|{}", r.source, reason);
        r.current_key = key.clone();
        for (field, count) in acc.session_start.s0_counts() {
            if field == "OpeningCall.files" && count > 0 {
                *r.e_fields
                    .entry(format!("{}|{field}", r.source))
                    .or_default() += 1;
            }
            r.completion_geometry
                .entry(format!("{}|HEAD.{field}.elements", r.source))
                .or_default()
                .push(count);
        }
        if let Some(markers) = acc.claude_org_markers.as_ref() {
            let (entries, home) = markers.s0_counts();
            r.completion_geometry
                .entry(format!("{}|HEAD.OrgMarkers.entries.elements", r.source))
                .or_default()
                .push(entries);
            *r.finish_fields
                .entry(format!(
                    "{}|OrgMarkers.home|{}",
                    r.source,
                    if home { "nonempty" } else { "empty" }
                ))
                .or_default() += 1;
            if home {
                *r.e_fields
                    .entry(format!("{}|OrgMarkers.home", r.source))
                    .or_default() += 1;
            }
        }
        for field in &samples {
            if field.class == "E" && field.nonempty {
                *r.e_fields
                    .entry(format!("{}|{}", r.source, field.name))
                    .or_default() += 1;
            }
            let finish = acc.source == SnapshotSource::ClaudeCode
                && matches!(
                    field.name,
                    "claude_usage_request_ids"
                        | "claude_usage_occurrences"
                        | "claude_money"
                        | "cache_observations"
                        | "cache_requests"
                        | "usage_buckets"
                        | "accepted_usage_totals"
                        | "session_cumulative_usage"
                );
            let empty = match field.name {
                "accepted_usage_totals" => acc.accepted_usage_totals.is_zero(),
                _ => !field.nonempty,
            };
            if finish {
                *r.finish_fields
                    .entry(format!(
                        "{}|{}|{}",
                        r.source,
                        field.name,
                        if empty { "empty" } else { "nonempty" }
                    ))
                    .or_default() += 1;
            }
        }
        for (toggle, different) in toggles {
            let cell = r.toggle_diffs.entry(toggle).or_default();
            *cell
                .entry(
                    if different.is_empty() {
                        "equal"
                    } else {
                        "different"
                    }
                    .into(),
                )
                .or_default() += 1;
            for name in different {
                *cell.entry(format!("field.{name}")).or_default() += 1;
            }
        }
        if acc.source == SnapshotSource::Codex {
            *r.rows.entry("codex.completions".into()).or_default() += 1;
            if acc.codex_parent_prefix_proof.is_some() && acc.codex_parent_prefix_decided.is_none()
            {
                *r.rows.entry("codex.undecided_proof".into()).or_default() += 1;
            }
            *r.rows
                .entry("codex.bootstrap_buffer_elements".into())
                .or_default() += acc.codex_legacy_bootstrap_buffer.len() as u64;
            if !acc.codex_legacy_bootstrap_buffer.is_empty() {
                *r.rows.entry("codex.bootstrap_nonempty".into()).or_default() += 1;
            }
        }
        let touched = r.touched_slots.remove(&key).unwrap_or_default();
        let book_count = geometry.elements;
        let newest_n = touched
            .first()
            .map(|s| book_count.saturating_sub(*s))
            .unwrap_or(0);
        r.completion_geometry
            .entry(format!("{}|k_newest_n", r.source))
            .or_default()
            .push(newest_n as u64);
        let prior_count = r
            .files
            .get(&key)
            .and_then(|f| f.fields.iter().find(|f| f.name == "claude_responses"))
            .map_or(0, |f| f.elements as usize);
        r.completion_geometry
            .entry(format!("{}|old_slots", r.source))
            .or_default()
            .push(touched.iter().filter(|slot| **slot < prior_count).count() as u64);
        let mut estimates = [0u64; 4];
        let head = estimated_head(&samples, acc) + geometry.head_bytes;
        for (gi, g) in CANDIDATE_G.into_iter().enumerate() {
            let mut dirty: BTreeSet<usize> = touched.iter().map(|slot| slot / g).collect();
            let old_count = r
                .files
                .get(&key)
                .map(|f| {
                    f.fields
                        .iter()
                        .find(|f| f.name == "claude_responses")
                        .map_or(0, |f| f.elements as usize)
                })
                .unwrap_or(0);
            if book_count > old_count {
                for slot in old_count..book_count {
                    dirty.insert(slot / g);
                }
            }
            let book_pages = &geometry.pages[gi];
            if mode.starts_with("Full") {
                dirty.extend(0..book_pages.len());
            }
            let dirty_bytes = dirty.iter().filter_map(|p| book_pages.get(*p)).sum::<u64>();
            let other_pages = pages
                .iter()
                .map(|(_, lengths)| lengths.iter().sum::<u64>())
                .sum::<u64>();
            estimates[gi] = head.saturating_add(dirty_bytes).saturating_add(other_pages);
            r.completion_geometry
                .entry(format!(
                    "{}|G{g}|logical_completion_bytes_estimate",
                    r.source
                ))
                .or_default()
                .push(estimates[gi]);
            r.completion_geometry
                .entry(format!("{}|G{g}|dirty_pages", r.source))
                .or_default()
                .push(dirty.len() as u64);
            r.completion_geometry
                .entry(format!("{}|G{g}|response_dirty_bytes", r.source))
                .or_default()
                .push(dirty_bytes);
            for (j, size) in book_pages.iter().enumerate() {
                r.page_plans
                    .entry(format!("{}|responses|G{g}|bytes", r.source))
                    .or_default()
                    .push(*size);
                r.page_plans
                    .entry(format!("{}|responses|G{g}|elements", r.source))
                    .or_default()
                    .push((book_count - j * g).min(g) as u64);
            }
            for (name, lengths) in &pages {
                for chunk in lengths.chunks(if name.ends_with("_hours") { 1 } else { g }) {
                    r.page_plans
                        .entry(format!("{}|{name}|G{g}|bytes", r.source))
                        .or_default()
                        .push(chunk.iter().sum());
                    r.page_plans
                        .entry(format!("{}|{name}|G{g}|elements", r.source))
                        .or_default()
                        .push(chunk.len() as u64);
                }
            }
        }
        let eligible = report.complete()
            && drops == 0
            && acc.dropped_usage_record_count == 0
            && consumed == last_end
            && !sealed_fragment;
        if eligible {
            r.stage.insert(key.clone(), estimates);
            for gi in 0..4 {
                let sum = r.stage.values().map(|x| x[gi]).sum();
                r.stage_peak[gi] = r.stage_peak[gi].max(sum);
            }
        }
        *r.rows
            .entry(
                if eligible {
                    "stage_eligible_completions"
                } else {
                    "stage_ineligible_completions"
                }
                .into(),
            )
            .or_default() += 1;
        *r.rows.entry("estimated_head_bytes_sum".into()).or_default() += head;
        *r.rows.entry("appended_bytes_sum".into()).or_default() += bytes.saturating_sub(accepted);
        let f = r.files.entry(key).or_default();
        if forced {
            let class = format!(
                "pass{}|{}|{}|{}",
                r.pass,
                origin,
                bucket(bytes),
                if f.not_persisted.is_empty() {
                    "no_observed_reason"
                } else {
                    &f.not_persisted
                }
            );
            let cell = r.forced_loop.entry(class).or_default();
            cell[0] += 1;
            cell[1] += native;
            r.forced_loop_files
                .entry(origin.clone())
                .or_default()
                .insert(r.current_key.clone());
            if f.last_forced_drain_pass > 0 {
                r.completion_geometry
                    .entry("drain_forcedfamily.recurrence_gap".into())
                    .or_default()
                    .push(r.pass - f.last_forced_drain_pass);
            }
            f.last_forced_drain_pass = r.pass;
            for (old, new) in f.fields.iter().zip(&samples) {
                if old.hash.zip(new.hash).is_some_and(|(a, b)| a != b) {
                    *r.forced_loop_fields.entry(new.name.into()).or_default() += 1;
                }
            }
        }
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
        f.last_native_bytes = native;
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
                old.elements = old.elements.max(new.elements);
                old.nonempty |= new.nonempty;
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
            if f.full {
                *row.entry(
                    if old == hash {
                        "identical_full_native_bytes"
                    } else {
                        "changed_full_native_bytes"
                    }
                    .into(),
                )
                .or_default() += f.last_native_bytes;
            }
            *row.entry(if old == hash { "identical" } else { "changed" }.into())
                .or_default() += 1;
        } else {
            *row.entry("no_prior".into()).or_default() += 1;
        }
        f.last_projection = Some(hash);
        if drops > oversize && !f.cap {
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
        out = json!({"counts":r.rows,"events":r.events,"restored_siblings":r.restored_siblings,"upload_fully_settled":r.settled,"stage_T_peak_proxy":r.stage_peak,"stage_files_unsaved":r.stage.len(),"exit_cause":r.exit_cause});
    });
    out
}
pub(crate) fn end() -> Value {
    let mut out = Value::Null;
    let unresolved = crate::on_proof::unresolved_keys();
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
 "elements":stats(files.iter().filter_map(|f|f.fields.get(i).map(|s|s.elements)).collect()),"class":field.class,

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
        let mut unresolved_join: BTreeMap<String, u64> = BTreeMap::new();
        for (key, class) in &unresolved {
            let f = r.files.get(key);
            let joined = format!(
                "{}|{}|{}|{}",
                class,
                f.map(|f| f.source.as_str()).unwrap_or("unobserved"),
                f.map(|f| bucket(f.bytes)).unwrap_or("unknown"),
                f.map(|f| if f.not_persisted.is_empty() {
                    "no_observed_reason"
                } else {
                    &f.not_persisted
                })
                .unwrap_or("no_observed_reason")
            );
            *unresolved_join.entry(joined).or_default() += 1;
        }
        out = json!({"on_unresolved_join":unresolved_join,"forced_drain_loop":r.forced_loop,
        "forced_drain_unique_files":r.forced_loop_files.iter().map(|(k,v)|(k,v.len())).collect::<BTreeMap<_,_>>(),"forced_drain_field_diffs":r.forced_loop_fields,
        "v2": {"candidate_G":CANDIDATE_G,"E_nonempty":r.e_fields,"FINISH":r.finish_fields,"toggle_state_diffs":r.toggle_diffs,
        "page_plans":r.page_plans.iter().map(|(k,v)|(k,stats(v.clone()))).collect::<BTreeMap<_,_>>(),
        "completion_geometry":r.completion_geometry.iter().map(|(k,v)|(k,stats(v.clone()))).collect::<BTreeMap<_,_>>(),"no_save_passes":r.no_save},
        "head_unknown_files":head_unknown_files,"largest_files":largest,"sizes":sizes,"heads_encoded_known_subtotal":heads,"peaks":peaks,"touches":r.touches,
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

/// Candidate geometry, not a cap; v2 leaves G unchosen.
pub(super) const CANDIDATE_G: [usize; 4] = [16, 64, 256, 1024];
pub(super) struct BookGeometry {
    pub(super) elements: usize,
    pub(super) pages: [Vec<u64>; 4],
    pub(super) head_bytes: u64,
}
pub(super) fn estimate_elements<'a, T: crate::durable_tail_codec::Durable + 'a>(
    values: impl Iterator<Item = &'a T>,
) -> Vec<u64> {
    values
        .map(|v| {
            let mut e = Enc::count(usize::MAX);
            match v.put(&mut e) {
                Ok(()) => e.counted() as u64,
                Err(_) => {
                    page_encode_unknown();
                    0
                }
            }
        })
        .collect()
}
fn entry_lengths<
    'a,
    K: crate::durable_tail_codec::Durable + 'a,
    V: crate::durable_tail_codec::Durable + 'a,
>(
    values: impl Iterator<Item = (&'a K, &'a V)>,
) -> Vec<u64> {
    values
        .map(|(key, value)| {
            let mut e = Enc::count(usize::MAX);
            if key.put(&mut e).and_then(|_| value.put(&mut e)).is_ok() {
                e.counted() as u64
            } else {
                page_encode_unknown();
                0
            }
        })
        .collect()
}
fn page_collections(acc: &SnapshotAccumulator) -> Vec<(&'static str, Vec<u64>)> {
    let mut p = vec![
        (
            "tool_uses",
            estimate_elements(acc.seen_claude_capability_tool_uses.keys()),
        ),
        (
            "changed_files",
            estimate_elements(acc.activity_changed_file_hashes.iter()),
        ),
        (
            "compactions",
            estimate_elements(acc.claude_compaction_observations.iter()),
        ),
        (
            "cap_hours",
            entry_lengths(acc.activity_capability_buckets.iter()),
        ),
    ];
    if acc.source == SnapshotSource::Codex {
        p.extend([
            (
                "signatures",
                estimate_elements(acc.codex_physical_signatures.iter()),
            ),
            ("requests", estimate_elements(acc.cache_requests.iter())),
            (
                "compaction_times",
                estimate_elements(acc.compaction_timestamps.iter()),
            ),
            ("compaction_sizes", acc.codex_compaction_sizes.s0_lengths()),
            ("usage_hours", entry_lengths(acc.usage_buckets.iter())),
            (
                "priority_turns",
                acc.codex_observed_priority_turns
                    .as_ref()
                    .map(|m| entry_lengths(m.iter()))
                    .unwrap_or_default(),
            ),
        ]);
    }
    p
}
fn estimated_head(samples: &[Field], acc: &SnapshotAccumulator) -> u64 {
    samples
        .iter()
        .filter(|f| {
            !matches!(
                f.name,
                "claude_responses"
                    | "seen_claude_capability_tool_uses"
                    | "activity_changed_file_hashes"
                    | "activity_capability_buckets"
                    | "claude_compaction_observations"
            ) && !(acc.source == SnapshotSource::Codex
                && matches!(
                    f.name,
                    "codex_physical_signatures"
                        | "codex_observed_priority_turns"
                        | "usage_buckets"
                        | "cache_requests"
                        | "compaction_timestamps"
                        | "codex_compaction_sizes"
                ))
        })
        .filter_map(|f| f.encoded)
        .sum()
}
pub(crate) fn upload_exit(cause: &str) {
    with(|r| r.exit_cause = cause.into());
}
pub(crate) fn saved() {
    with(|r| {
        *r.rows
            .entry("graph_save_calls_after_stage".into())
            .or_default() += 1;
        r.stage.clear();
    });
}
pub(crate) fn end_pass() {
    with(|r| {
        *r.rows
            .entry(format!("pass_exit.{}", r.exit_cause))
            .or_default() += 1;
        if !r.stage.is_empty() {
            *r.no_save.entry(r.exit_cause.clone()).or_default() += 1;
        }
    });
}
pub(crate) fn cursor_loss(count: u64) {
    with(|r| {
        r.rows.insert("codex.jobs_lost_delta".into(), count);
    });
}

pub(crate) fn reading(key: &str) {
    with(|r| r.reading_key = key.into());
}
mod proxy;
pub(crate) fn proxy_measurements(dir: &Path) -> Value {
    proxy::run(dir)
}

pub(crate) fn cursor_snapshot(cache: &sampled_scan::SharedCache) -> u64 {
    cache.counters_for_test().jobs_lost
}

thread_local! {static MEASURING_HEAP:Cell<bool>=const{Cell::new(false)};}
pub(crate) fn measuring_heap() -> bool {
    MEASURING_HEAP.with(Cell::get)
}
fn layout_bytes<T: crate::heap_layout_bound::HeapLayoutBound>(value: &T) -> Option<usize> {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            MEASURING_HEAP.with(|v| v.set(self.0));
        }
    }
    let _reset = Reset(MEASURING_HEAP.with(|v| v.replace(true)));
    crate::heap_layout_bound::bound(value, usize::MAX)
}

pub(crate) fn cursor_restart(cache: &sampled_scan::SharedCache) -> Value {
    let [lost, paused, proof, bootstrap] = cache.s0_cursor_state();
    json!({"jobs_lost_lifetime":lost,"paused_jobs_lost_on_owner_drop":paused,"proof_jobs_lost_on_owner_drop":proof,"paused_bootstrap_elements":bootstrap})
}

pub(super) fn page_encode_unknown() {
    with(|r| {
        *r.rows
            .entry("page_encode_unknown_elements".into())
            .or_default() += 1;
    });
}

pub(crate) fn forced_origin(root: &str, cause: &str) {
    with(|r| {
        r.forced_origins
            .entry(root.into())
            .or_default()
            .insert(cause.into());
    });
}
