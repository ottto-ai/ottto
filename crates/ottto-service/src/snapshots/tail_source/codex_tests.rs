//! The Codex Tail codec on real parses of synthetic rollouts: every field home
//! round-trips across page boundaries, dictionary slots keep their place through
//! removal and reinsertion, content comes back from the session facts, damaged
//! state is a classified reconstruction, the finish-field list is Codex's own,
//! and live installation waits or rebuilds as its evidence says.
use super::super::seam::tests::{copy, load, parse_lines, stage_full, stage_reduction, NOW};
use super::super::{encode, page_bytes};
use super::*;
use crate::snapshots::sampled_jsonl::CachedJsonlReduction;
use crate::snapshots::state_v2::StagedFile;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(in crate::snapshots) const SESSION: &str = "019a0c2a-8e11-7222-8333-944445555777";

fn at(minute: usize) -> String {
    format!("2026-10-18T{:02}:{:02}:00Z", 10 + minute / 60, minute % 60)
}

fn header() -> String {
    json!({"timestamp":at(0),"type":"session_meta","payload":{"id":SESSION,
        "timestamp":at(0),"source":"cli","cwd":"/tmp/tail-codex"}})
    .to_string()
}

fn event(minute: usize, payload: serde_json::Value) -> String {
    json!({"timestamp":at(minute),"type":"event_msg","payload":payload}).to_string()
}

fn tokens(scale: usize) -> serde_json::Value {
    json!({"input_tokens":100 * scale,"cached_input_tokens":0,"cache_write_input_tokens":0,
        "output_tokens":10 * scale,"reasoning_output_tokens":0,"total_tokens":110 * scale})
}

/// One turn: start, context, a tool call (every fifth stays open), a usage
/// record, its completion, and every fourth turn a compaction and a patch.
fn turn(i: usize) -> Vec<String> {
    let id = format!("turn-{i:04}");
    let mut lines = vec![
        event(i, json!({"type":"task_started","turn_id":id})),
        json!({"timestamp":at(i),"type":"turn_context","payload":{"turn_id":id,"model":"gpt-5"}})
            .to_string(),
        json!({"timestamp":at(i),"type":"response_item","payload":{"type":"function_call",
            "name":format!("tool_{}", i % 3),"call_id":format!("call-{i:04}"),"arguments":"{}"}})
        .to_string(),
    ];
    if i % 5 != 4 {
        lines.push(
            json!({"timestamp":at(i),"type":"response_item","payload":{
                "type":"function_call_output","call_id":format!("call-{i:04}")}})
            .to_string(),
        );
    }
    lines.push(event(
        i,
        json!({"type":"token_count","info":{"last_token_usage":tokens(1),
            "total_token_usage":tokens(i + 1),"model":"gpt-5"}}),
    ));
    if i % 4 == 3 {
        lines.push(event(
            i,
            json!({"type":"patch_apply_end","changes":{format!("src/{i}.rs"):{"unified_diff":"+a"}}}),
        ));
        lines.push(json!({"type":"compacted","timestamp":at(i)}).to_string());
    }
    lines.push(event(i, json!({"type":"task_complete","turn_id":id})));
    lines
}

/// A rollout of `turns` closed turns. Each count's lines are a prefix of the next.
pub(in crate::snapshots) fn lines(turns: usize) -> Vec<String> {
    std::iter::once(header())
        .chain((0..turns).flat_map(turn))
        .collect()
}

/// A cold positioned Full read: the PRE-finalization reduction and the
/// checkpoint's certificate.
fn parse(lines: &[String]) -> (CachedJsonlReduction, DurableCertificate) {
    parse_lines(
        SnapshotSource::Codex,
        apply_codex_line,
        lines,
        &format!("rollout-2026-10-18T10-00-00-{SESSION}.jsonl"),
    )
}

fn identity() -> HeadIdentity {
    let root = Path::new("/home/sessions");
    HeadIdentity::new(
        Path::new("/state/scan-index.json"),
        SnapshotSource::Codex,
        root,
        &root.join("rollout.jsonl"),
        false,
    )
}

fn loaded(staged: &StagedFile) -> SnapshotAccumulator {
    let mut into = SnapshotAccumulator::new(SnapshotSource::Codex);
    assert_eq!(load::<Codex>(staged, &mut into).err(), None);
    into
}

fn cause(staged: &StagedFile) -> Option<ReconstructCause> {
    let mut into = SnapshotAccumulator::new(SnapshotSource::Codex);
    load::<Codex>(staged, &mut into).err()
}

/// The content comes back from the session facts alone, never from the file;
/// the loaded state then encodes to exactly the stored rows.
fn assert_reencodes(
    reduction: &CachedJsonlReduction,
    certificate: &DurableCertificate,
    staged: &StagedFile,
) {
    let (acc, _, _) = reduction.finish_view();
    let mut restored = SnapshotAccumulator::new(SnapshotSource::Codex);
    let head = load::<Codex>(staged, &mut restored).expect("the rows load");
    assert_eq!(head.certificate, *certificate);
    assert_eq!(restored.title, acc.title);
    assert_eq!(restored.first_prompt_title, acc.first_prompt_title);
    assert_eq!(restored.first_prompt_material, acc.first_prompt_material);
    assert_eq!(restored.workspace_path, acc.workspace_path);
    assert_eq!(restored.codex_agent_label, acc.codex_agent_label);
    assert_eq!(
        restored.session_start.has_codex_prelude(),
        acc.session_start.has_codex_prelude()
    );
    let view = PreFinalization::new(&restored, &head.report, head.scalars);
    let again = stage_full::<Codex>(&view, &head.certificate, &identity());
    assert!(again.head == staged.head, "the head re-encodes exactly");
    assert!(again.pages == staged.pages, "the pages re-encode exactly");
    assert!(again.collections == staged.collections);
}

/// [format] Every Codex field home round-trips, including every slot collection
/// across a page boundary and parse-time totals, with no finish field at the seam.
#[test]
fn every_codex_field_home_round_trips_through_head_and_pages() {
    let (mut reduction, certificate) = parse(&lines(300));
    let acc = reduction.accumulator_for_test();
    acc.codex_observed_priority_turns = Some(
        (0..300)
            .map(|n| (format!("turn-{n:04}"), n % 7 == 0))
            .collect(),
    );
    for n in 0..300 {
        acc.codex_dictionary_slots
            .priority_turns
            .note(&format!("turn-{n:04}"));
    }
    acc.codex_physical_signatures.clear();
    for n in 0..300 {
        // Multiplicity and order are data: every tenth repeats its predecessor.
        let n = n - usize::from(n % 10 == 9);
        acc.codex_physical_signatures
            .push(sha256_hex(&["tail-codex-signature", &n.to_string()]));
    }
    let staged = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    let (acc, _, _) = reduction.finish_view();
    assert_eq!(Codex::finish_field_nonempty(acc), None);
    assert_eq!(Codex::elements(acc, Collection::CodexActiveTurns), 300);
    assert!(acc.cache_active_turns.is_empty());
    for spec in Codex::collections().iter().filter(|spec| spec.g > 0) {
        let pages = staged
            .pages
            .keys()
            .filter(|(collection, _)| *collection == spec.collection)
            .count() as u64;
        assert_eq!(
            pages,
            Codex::elements(acc, spec.collection).div_ceil(u64::from(spec.g)),
            "{:?}",
            spec.collection
        );
    }
    for collection in [
        Collection::CodexActiveTurns,
        Collection::CodexOpenCalls,
        Collection::PriorityTurns,
        Collection::Signatures,
    ] {
        assert!(
            staged.pages.contains_key(&(collection, 1)),
            "{collection:?}"
        );
    }

    let back = loaded(&staged);
    assert_eq!(back.accepted_usage_totals, acc.accepted_usage_totals);
    assert_eq!(back.session_cumulative_usage, acc.session_cumulative_usage);
    assert_eq!(
        back.usage_buckets.keys().collect::<Vec<_>>(),
        acc.usage_buckets.keys().collect::<Vec<_>>()
    );
    assert!(back.session_cumulative_usage.is_some());
    assert_eq!(back.activity_tool_counts, acc.activity_tool_counts);
    assert_eq!(back.activity_mcp_call_ids, acc.activity_mcp_call_ids);
    assert_eq!(
        back.activity_call_tools
            .keys()
            .map(|call| &call.id)
            .collect::<Vec<_>>(),
        acc.activity_call_tools
            .keys()
            .map(|call| &call.id)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        back.codex_observed_priority_turns,
        acc.codex_observed_priority_turns
    );
    assert_eq!(
        *back.codex_physical_signatures,
        *acc.codex_physical_signatures
    );
    assert_eq!(*back.compaction_timestamps, *acc.compaction_timestamps);
    assert_eq!(
        back.activity_changed_file_hashes,
        acc.activity_changed_file_hashes
    );
    assert_eq!(
        back.activity_capability_buckets,
        acc.activity_capability_buckets
    );
    assert_eq!(
        back.codex_dictionary_slots.open_calls.ordered(),
        acc.codex_dictionary_slots.open_calls.ordered()
    );
    // Live inputs never come back from storage.
    assert!(back.codex_turn_traces.is_none() && back.codex_tier_replay.is_none());
    assert!(back.codex_parent_signatures.is_none());
    assert!(back.codex_parent_prefix_proof.is_none());
    assert_reencodes(&reduction, &certificate, &staged);
}

/// [format] A turn removed and started again keeps its first slot, whatever its
/// sort position; an earlier page does not move when a later slot tombstones.
#[test]
fn a_reinserted_turn_keeps_its_slot_and_earlier_pages_stay() {
    let mut rollout = vec![header()];
    for (minute, kind, turn) in [
        (1, "task_started", "z-first"),
        (2, "task_started", "a-second"),
        (3, "task_complete", "z-first"),
        (4, "task_started", "m-third"),
        (5, "task_started", "z-first"),
    ] {
        rollout.push(event(minute, json!({"type":kind,"turn_id":turn})));
    }
    let (reduction, certificate) = parse(&rollout);
    let (acc, _, _) = reduction.finish_view();
    let slots = &acc.codex_dictionary_slots.active_turns;
    assert_eq!(slots.ordered(), ["z-first", "a-second", "m-third"]);
    let staged = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    let back = loaded(&staged);
    assert_eq!(
        back.codex_dictionary_slots.active_turns.ordered(),
        ["z-first", "a-second", "m-third"]
    );
    assert_eq!(back.cache_active_turns, acc.cache_active_turns);

    let (mut reduction, _) = parse(&lines(70));
    let acc = reduction.accumulator_for_test();
    let before = Codex::encode_pages(acc, Collection::CodexActiveTurns).unwrap();
    let last = "turn-0069".to_owned();
    acc.cache_active_turns.insert(last.clone());
    let during = Codex::encode_pages(acc, Collection::CodexActiveTurns).unwrap();
    assert_eq!(before[0], during[0], "an earlier page keeps its bytes");
    assert_ne!(before[1], during[1]);
    acc.cache_active_turns.remove(&last);
    assert_eq!(
        before,
        Codex::encode_pages(acc, Collection::CodexActiveTurns).unwrap(),
        "the tombstone restores the same bytes"
    );
}

/// [format] A pending MCP call is not a deletion, completion is its own value,
/// and a removed call is a counted tombstone that takes its slot back.
#[test]
fn mcp_call_states_survive_and_a_gone_call_is_a_tombstone() {
    let (mut reduction, certificate) = parse(&lines(1));
    let acc = reduction.accumulator_for_test();
    let slots_before = acc.codex_dictionary_slots.open_calls.len();
    for (call, completed) in [("mcp-pending", false), ("mcp-done", true)] {
        acc.codex_dictionary_slots.open_calls.note(&call.to_owned());
        acc.activity_mcp_call_ids.insert(call.to_owned(), completed);
    }
    acc.codex_dictionary_slots
        .open_calls
        .note(&"mcp-gone".to_owned());
    let staged = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    let back = loaded(&staged);
    assert_eq!(back.activity_mcp_call_ids.get("mcp-pending"), Some(&false));
    assert_eq!(back.activity_mcp_call_ids.get("mcp-done"), Some(&true));
    assert_eq!(back.activity_mcp_call_ids.get("mcp-gone"), None);
    let open_calls = &back.codex_dictionary_slots.open_calls;
    assert_eq!(open_calls.len(), slots_before + 3);
    assert!(open_calls.contains(&"mcp-gone".to_owned()));
    assert_reencodes(&reduction, &certificate, &staged);
}

/// [format] A removed native tool count remains a tombstone in its slot.
#[test]
fn a_removed_tool_count_is_a_tombstone() {
    let (mut reduction, certificate) = parse(&lines(1));
    let acc = reduction.accumulator_for_test();
    acc.note_activity_tool("gone");
    acc.activity_tool_counts.remove("gone");
    let staged = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    let back = loaded(&staged);
    assert_eq!(back.activity_tool_counts.get("gone"), None);
    assert!(back
        .codex_dictionary_slots
        .name_counts
        .contains(&(CodexCountMap::Tool, "gone".to_owned())));
    assert_reencodes(&reduction, &certificate, &staged);
}

/// [money] A native insert that missed its slot would vanish at load: it refuses
/// this file's stage instead of storing a short dictionary.
#[test]
fn a_live_key_without_a_slot_refuses_the_stage() {
    let (mut reduction, certificate) = parse(&lines(1));
    reduction
        .accumulator_for_test()
        .cache_active_turns
        .insert("no-slot".into());
    let (acc, report, scalars) = reduction.finish_view();
    let view = PreFinalization::new(acc, report, scalars);
    assert!(matches!(
        super::super::seam::TailBase::default().stage::<Codex>(
            &view,
            &certificate,
            &identity(),
            crate::snapshots::state_v2::Change::Reset
        ),
        Err(Refuse::NonEmpty(_))
    ));
}

/// [format] No decisions and an empty decision map stay apart.
#[test]
fn priority_none_and_empty_stay_apart() {
    let (mut reduction, certificate) = parse(&lines(1));
    reduction
        .accumulator_for_test()
        .codex_observed_priority_turns = None;
    let none = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    assert!(loaded(&none).codex_observed_priority_turns.is_none());
    let acc = reduction.accumulator_for_test();
    acc.codex_observed_priority_turns = Some(BTreeMap::new());
    acc.codex_dictionary_slots.priority_turns = Default::default();
    let empty = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    assert_eq!(
        loaded(&empty).codex_observed_priority_turns,
        Some(BTreeMap::new())
    );
    assert_ne!(none.head, empty.head);
}

/// [format] Repeated compaction timestamps each keep a slot; sizes sort and
/// deduplicate on their own in the head and are never zipped to them.
#[test]
fn duplicate_compaction_timestamps_stay_apart_from_sizes() {
    let (mut reduction, certificate) = parse(&lines(8));
    let acc = reduction.accumulator_for_test();
    let repeated = acc.compaction_timestamps[0].clone();
    acc.compaction_timestamps.push(repeated.clone());
    acc.compaction_timestamps.push(repeated);
    let staged = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    let (acc, _, _) = reduction.finish_view();
    assert_eq!(acc.compaction_timestamps.len(), 4);
    assert_eq!(
        *loaded(&staged).compaction_timestamps,
        *acc.compaction_timestamps
    );
    assert_reencodes(&reduction, &certificate, &staged);
}

/// [format] Damaged stored state is a classified reconstruction, never a
/// default-empty success.
#[test]
fn damaged_state_is_classified() {
    let (reduction, certificate) = parse(&lines(70));
    let staged = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    assert_eq!(cause(&staged), None);

    let mut short = copy(&staged);
    short.head.pop();
    assert_eq!(cause(&short), Some(ReconstructCause::Corrupt));

    let mut trailing = copy(&staged);
    trailing
        .pages
        .get_mut(&(Collection::CodexActiveTurns, 0))
        .unwrap()
        .push(0);
    assert_eq!(cause(&trailing), Some(ReconstructCause::Corrupt));

    // A page that starts past the slots held leaves a gap.
    let mut gap = copy(&staged);
    gap.pages.remove(&(Collection::CodexActiveTurns, 0));
    assert_eq!(cause(&gap), Some(ReconstructCause::Corrupt));

    let mut count = copy(&staged);
    count
        .collections
        .get_mut(&Collection::CodexActiveTurns)
        .unwrap()
        .elements += 1;
    assert_eq!(cause(&count), Some(ReconstructCause::Incomplete));

    let mut foreign = copy(&staged);
    let meta = foreign.collections[&Collection::Signatures];
    foreign.collections.insert(Collection::Responses, meta);
    assert_eq!(cause(&foreign), Some(ReconstructCause::Corrupt));

    // One slot twice.
    let mut into = SnapshotAccumulator::new(SnapshotSource::Codex);
    Codex::decode_head(staged.revision, &staged.head, &mut into).unwrap();
    let repeat = page_bytes(
        [
            CodexActiveTurn {
                turn_id: "t".into(),
                active: true,
            },
            CodexActiveTurn {
                turn_id: "t".into(),
                active: false,
            },
        ]
        .iter(),
        |turn, e| turn.put(e),
    )
    .unwrap();
    assert_eq!(
        Codex::decode_page(Collection::CodexActiveTurns, 0, &repeat, &mut into).err(),
        Some(ReconstructCause::Corrupt)
    );

    // Decisions under a head that recorded none contradict it.
    let mut into = SnapshotAccumulator::new(SnapshotSource::Codex);
    into.codex_observed_priority_turns = None;
    let decisions = page_bytes(
        [CodexPriorityTurn {
            turn_id: "t".into(),
            priority: true,
        }]
        .iter(),
        |turn, e| turn.put(e),
    )
    .unwrap();
    assert_eq!(
        Codex::decode_page(Collection::PriorityTurns, 0, &decisions, &mut into).err(),
        Some(ReconstructCause::Corrupt)
    );

    // Another source's head.
    let (mut reduction, certificate) = parse(&lines(1));
    reduction.accumulator_for_test().source = SnapshotSource::ClaudeCode;
    let other_source = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    assert_eq!(cause(&other_source), Some(ReconstructCause::Corrupt));
}

/// [behaviour] Codex's finish list names the walk's `I` fields it never
/// stores; its parse-time totals, buckets and requests are ordinary head and
/// page state, and Claude's stored fields are the walk's.
#[test]
fn the_finish_list_is_codex_own() {
    let new = || SnapshotAccumulator::new(SnapshotSource::Codex);
    let mut acc = new();
    acc.accepted_usage_totals.input_tokens = 1;
    acc.session_cumulative_usage = Some(UsageTotals::default());
    acc.usage_buckets.insert("hour".into(), Default::default());
    acc.claude_last_user_ts = Some(at(0));
    assert_eq!(Codex::finish_field_nonempty(&acc), None);

    let mut acc = new();
    acc.claude_usage_request_ids.insert("r".into());
    assert_eq!(
        Codex::finish_field_nonempty(&acc),
        Some("claude_usage_request_ids")
    );
    let mut acc = new();
    acc.account_identifier_hash = Some("a".repeat(64));
    assert_eq!(
        Codex::finish_field_nonempty(&acc),
        Some("account_identifier_hash")
    );
}

/// [format] Priority decisions keep their first-seen slot by turn, not their
/// sort order, and a decision restated later does not move.
#[test]
fn priority_decisions_are_slots_by_first_seen_turn() {
    let (mut reduction, certificate) = parse(&lines(1));
    let acc = reduction.accumulator_for_test();
    let mut observed = BTreeMap::new();
    let mut slots = crate::snapshots::codex_dictionary_slots::CodexDictionarySlots::default();
    for turn in ["z-first", "a-second", "z-first", "m-third"] {
        slots.priority_turns.note(&turn.to_owned());
        observed.insert(turn.to_owned(), turn == "a-second");
    }
    acc.codex_dictionary_slots.priority_turns = slots.priority_turns;
    acc.codex_observed_priority_turns = Some(observed);
    let staged = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    let back = loaded(&staged);
    assert_eq!(
        back.codex_dictionary_slots.priority_turns.ordered(),
        ["z-first", "a-second", "m-third"]
    );
    let (acc, _, _) = reduction.finish_view();
    assert_eq!(
        back.codex_observed_priority_turns,
        acc.codex_observed_priority_turns
    );
    assert_reencodes(&reduction, &certificate, &staged);

    // A decision without its slot refuses the stage.
    reduction
        .accumulator_for_test()
        .codex_observed_priority_turns
        .as_mut()
        .unwrap()
        .insert("no-slot".into(), false);
    let (acc, report, scalars) = reduction.finish_view();
    let view = PreFinalization::new(acc, report, scalars);
    assert!(matches!(
        super::super::seam::TailBase::default().stage::<Codex>(
            &view,
            &certificate,
            &identity(),
            crate::snapshots::state_v2::Change::Reset
        ),
        Err(Refuse::NonEmpty(_))
    ));
}

/// A candidate for `path` as discovery would list it.
pub(in crate::snapshots) fn candidate(path: &Path) -> CandidateFile {
    CandidateFile {
        physical_identity: None,
        scan_root: path.parent().unwrap().to_owned(),
        path: path.to_owned(),
        size_bytes: std::fs::metadata(path).map_or(0, |metadata| metadata.len()),
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: "a".repeat(64),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    }
}

/// A rollout whose owning header names `SESSION`, written once.
fn owned_rollout() -> &'static Path {
    static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let dir =
            std::env::temp_dir().join(format!("ottto-tail-codex-lineage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("rollout-2026-10-18T10-00-00-{SESSION}.jsonl"));
        std::fs::write(&path, lines(1).join("\n") + "\n").unwrap();
        path
    })
}

fn install(
    stored: &mut SnapshotAccumulator,
    live: &SnapshotAccumulator,
) -> Result<(), LiveLoadError> {
    Codex::install_live(stored, &candidate(owned_rollout()), live)
}

/// A stored head of `SESSION`'s lineage that every other check lets continue.
fn continuable() -> SnapshotAccumulator {
    let mut stored = SnapshotAccumulator::new(SnapshotSource::Codex);
    stored.codex_observed_priority_turns = Some(BTreeMap::new());
    stored.codex_creator_header_id = Some(SESSION.into());
    stored
}

/// [money] The lineage (D131): a head continues only the session its owning
/// header named. Another id, or none stored, is a counted `Identity`
/// reconstruction; a header this read cannot read waits.
#[test]
fn install_live_continues_only_the_stored_lineage() {
    let live = SnapshotAccumulator::new(SnapshotSource::Codex);
    assert_eq!(install(&mut continuable(), &live), Ok(()));
    let identity = Err(LiveLoadError::Reconstruct(ReconstructCause::Identity));
    let mut other = continuable();
    other.codex_creator_header_id = Some("019a0c2a-8e11-7222-8333-944445555000".into());
    assert_eq!(install(&mut other, &live), identity);
    let mut none = continuable();
    none.codex_creator_header_id = None;
    assert_eq!(install(&mut none, &live), identity);
    let missing = candidate(&owned_rollout().with_file_name("rollout-missing.jsonl"));
    assert_eq!(
        Codex::install_live(&mut continuable(), &missing, &live),
        Err(LiveLoadError::Unavailable)
    );
}

const INCOMPATIBLE: Result<(), LiveLoadError> =
    Err(LiveLoadError::Reconstruct(ReconstructCause::Incompatible));

/// [behaviour] Every prior decision holding installs this cycle's inputs, and
/// the fresh parser keeps its own for the read's preparation.
#[test]
fn install_live_installs_when_evidence_holds() {
    let mut stored = continuable();
    stored
        .codex_observed_priority_turns
        .as_mut()
        .unwrap()
        .extend([("priority".to_owned(), true), ("plain".to_owned(), false)]);
    let mut traces = CodexTurnTraceMap::default();
    traces.priority_turns.insert("priority".into());
    let mut live = SnapshotAccumulator::new(SnapshotSource::Codex);
    live.codex_turn_traces = Some(Arc::new(traces));
    live.codex_sidecar_projected_next_ordinal = Some(7);
    assert_eq!(install(&mut stored, &live), Ok(()));
    assert_eq!(stored.codex_sidecar_projected_next_ordinal, Some(7));
    assert!(stored.codex_turn_traces.is_some());
    assert!(live.codex_turn_traces.is_some());
}

/// [money] The stored projected ordinal against this read's: a missing one
/// waits, a lower one is another sidecar, a higher one is an append.
#[test]
fn install_live_compares_the_projected_ordinal() {
    let stored = || {
        let mut stored = continuable();
        stored.codex_sidecar_projected_next_ordinal = Some(5);
        stored
    };
    let live = |ordinal| {
        let mut live = SnapshotAccumulator::new(SnapshotSource::Codex);
        live.codex_sidecar_projected_next_ordinal = ordinal;
        live
    };
    assert_eq!(
        install(&mut stored(), &live(None)),
        Err(LiveLoadError::Unavailable)
    );
    assert_eq!(install(&mut stored(), &live(Some(4))), INCOMPATIBLE);
    let mut grown = stored();
    assert_eq!(install(&mut grown, &live(Some(6))), Ok(()));
    assert_eq!(grown.codex_sidecar_projected_next_ordinal, Some(6));
}

/// [money] The counting rule and the priority decisions decide reuse: absent or
/// incomplete evidence waits, evidence that disagrees rebuilds.
#[test]
fn install_live_waits_on_missing_evidence_and_rebuilds_on_changed() {
    let live = SnapshotAccumulator::new(SnapshotSource::Codex);

    let mut stored = continuable();
    stored.codex_counting = Some(Box::new(codex_usage_occurrence::CodexCounting::new(
        codex_counting_version::AckEvidence::None,
        Some(1),
    )));
    assert_eq!(install(&mut stored, &live), INCOMPATIBLE);

    let mut stored = SnapshotAccumulator::new(SnapshotSource::Codex);
    assert_eq!(install(&mut stored, &live), INCOMPATIBLE);

    let decided = |priority: bool| {
        let mut stored = continuable();
        stored
            .codex_observed_priority_turns
            .as_mut()
            .unwrap()
            .insert("t".into(), priority);
        stored
    };
    assert_eq!(
        install(&mut decided(true), &live),
        Err(LiveLoadError::Unavailable),
        "no traces cannot prove a change"
    );
    assert_eq!(install(&mut decided(false), &live), Ok(()));

    let with_traces = |incomplete: bool| {
        let traces = CodexTurnTraceMap {
            incomplete,
            ..Default::default()
        };
        let mut live = SnapshotAccumulator::new(SnapshotSource::Codex);
        live.codex_turn_traces = Some(Arc::new(traces));
        live
    };
    assert_eq!(
        install(&mut decided(true), &with_traces(false)),
        INCOMPATIBLE,
        "complete traces prove the change"
    );
    assert_eq!(
        install(&mut decided(true), &with_traces(true)),
        Err(LiveLoadError::Unavailable),
        "incomplete traces do not"
    );
}

fn child(boundary: CodexOwnershipBoundary) -> SnapshotAccumulator {
    let mut stored = continuable();
    stored.codex_parent_ledger_consulted = true;
    stored.codex_parent_session_ref = Some("parent".into());
    stored.codex_ownership_boundary = boundary;
    stored
}

fn with_ledger(ledger: CodexParentOwnershipLedger) -> SnapshotAccumulator {
    let mut live = SnapshotAccumulator::new(SnapshotSource::Codex);
    live.codex_parent_ownership_ledgers = Some(Arc::new(Mutex::new(BTreeMap::from([(
        "parent".to_owned(),
        ledger,
    )]))));
    live
}

fn ledger(identity: &str, scan_complete: bool) -> CodexParentOwnershipLedger {
    CodexParentOwnershipLedger {
        signatures: vec!["s0".into(), "s1".into()],
        scan_complete,
        opened_object_identity: identity.into(),
        ..Default::default()
    }
}

/// [money] A child comparing against the parent ledger it used gets that
/// ledger back, waits while it is missing or partial, and rebuilds when the
/// parent changed. Never a continuation without its parent prefix.
#[test]
fn install_live_restores_the_parent_ledger_the_child_used() {
    let used = || {
        let mut stored = child(CodexOwnershipBoundary::AwaitingParentPrefix);
        stored.codex_parent_ledger_identity_used = Some("parent-open-1".into());
        stored
    };
    let mut stored = used();
    assert_eq!(
        install(&mut stored, &with_ledger(ledger("parent-open-1", true))),
        Ok(())
    );
    assert!(matches!(
        stored.codex_parent_signatures,
        Some(CodexParentPrefix::Ledger(ref signatures)) if signatures.len() == 2
    ));
    assert!(!stored.codex_parent_resolution_pending());
    assert_eq!(
        install(
            &mut used(),
            &SnapshotAccumulator::new(SnapshotSource::Codex)
        ),
        Err(LiveLoadError::Unavailable)
    );
    assert_eq!(
        install(&mut used(), &with_ledger(ledger("parent-open-1", false))),
        Err(LiveLoadError::Unavailable)
    );
    assert_eq!(
        install(&mut used(), &with_ledger(ledger("parent-open-2", true))),
        INCOMPATIBLE
    );
    // Comparing with neither a ledger nor a proof contradicts the stored state.
    assert_eq!(
        install(
            &mut child(CodexOwnershipBoundary::AwaitingParentPrefix),
            &with_ledger(ledger("parent-open-1", true))
        ),
        Err(LiveLoadError::Reconstruct(ReconstructCause::Corrupt))
    );
    // A proof job's ring is that job's alone.
    let mut paged = used();
    paged.codex_proof_decision_only = true;
    assert_eq!(
        install(&mut paged, &with_ledger(ledger("parent-open-1", true))),
        INCOMPATIBLE
    );
}

/// [money] A child pending its parent holds until parent evidence exists,
/// then rebuilds; a witnessed-unusable parent stays absorbing, as stored.
#[test]
fn install_live_holds_a_child_pending_its_parent() {
    let pending = || child(CodexOwnershipBoundary::AmbiguousFork);
    assert_eq!(
        install(
            &mut pending(),
            &SnapshotAccumulator::new(SnapshotSource::Codex)
        ),
        Err(LiveLoadError::Unavailable)
    );
    assert_eq!(
        install(&mut pending(), &with_ledger(ledger("parent-open-1", true))),
        INCOMPATIBLE
    );
    let mut witnessed = pending();
    witnessed.codex_parent_unresolvable = Some(CodexParentUnresolvable::NoLedger);
    assert_eq!(
        install(
            &mut witnessed,
            &SnapshotAccumulator::new(SnapshotSource::Codex)
        ),
        Ok(())
    );
    assert!(matches!(
        witnessed.codex_parent_signatures,
        Some(CodexParentPrefix::Ledger(ref signatures)) if signatures.is_empty()
    ));
    assert!(!witnessed.codex_parent_resolution_pending());
}

/// [format] Codex's content is session facts in the shared slot collection:
/// title, first prompt, workspace, the agent label (kind 4) and the prelude
/// parser (kind 5) each load back from its own page, and the head stores none
/// of them. A kind this build does not know is incompatible.
#[test]
fn codex_content_loads_back_from_its_session_facts() {
    let (mut reduction, certificate) = parse(&lines(3));
    let acc = reduction.accumulator_for_test();
    acc.title = Some("Ünïcödé title".into());
    acc.first_prompt_material = Some("the first prompt".into());
    acc.workspace_path = Some(PathBuf::from("/tmp/tail-codex"));
    acc.codex_agent_label = Some("explorer".into());
    assert!(
        acc.session_start.has_codex_prelude(),
        "the parse holds its prelude parser"
    );
    let staged = stage_reduction::<Codex>(&reduction, &certificate, &identity());
    let facts: Vec<u64> = staged
        .pages
        .keys()
        .filter(|(collection, _)| *collection == Collection::SessionFacts)
        .map(|(_, page)| *page)
        .collect();
    for kind in [0, 1, 2, 4, 5] {
        assert!(facts.contains(&kind), "fact kind {kind} is stored");
    }
    let head = String::from_utf8_lossy(&staged.head);
    for content in ["Ünïcödé title", "the first prompt", "explorer"] {
        assert!(!head.contains(content), "{content} stays out of the head");
    }
    let back = loaded(&staged);
    assert_eq!(back.title.as_deref(), Some("Ünïcödé title"));
    assert_eq!(
        back.first_prompt_material.as_deref(),
        Some("the first prompt")
    );
    assert_eq!(back.workspace_path, Some(PathBuf::from("/tmp/tail-codex")));
    assert_eq!(back.codex_agent_label.as_deref(), Some("explorer"));
    assert!(back.session_start.has_codex_prelude());
    assert_reencodes(&reduction, &certificate, &staged);

    let mut into = SnapshotAccumulator::new(SnapshotSource::Codex);
    Codex::decode_head(staged.revision, &staged.head, &mut into).unwrap();
    let unknown = encode(|e| {
        e.varint(6)?;
        e.varint(1)
    })
    .unwrap();
    assert_eq!(
        Codex::decode_page(Collection::SessionFacts, 6, &unknown, &mut into).err(),
        Some(ReconstructCause::Incompatible)
    );
}

const PROOF_PARENT: &str = "019fd6a0-0000-7000-8000-0000000000a1";

fn proof_turn(at: &str, turn: &str) -> serde_json::Value {
    json!({"timestamp":at,"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5"}})
}

fn proof_tokens(at: &str, total: u64, last: u64) -> serde_json::Value {
    json!({"timestamp":at,"type":"event_msg","payload":{"type":"token_count","info":{
        "total_token_usage":{"input_tokens":total,"output_tokens":total / 10},
        "last_token_usage":{"input_tokens":last,"output_tokens":last / 10},
        "model":"gpt-5"}}})
}

/// A real parent prefix proof: P written and sealed as `Checkpoint::seal_as`
/// mints it, the child's shared leading signatures matched against P's, and
/// the chain digest over the child's signatures up to the deciding one.
fn real_proof() -> (CodexParentPrefixProof, PrefixDigest) {
    let parent = [
        json!({"timestamp":"2026-10-18T10:00:00Z","type":"session_meta",
            "payload":{"id":PROOF_PARENT,"thread_source":"user"}}),
        proof_turn("2026-10-18T10:00:01Z", "parent-turn"),
        proof_tokens("2026-10-18T10:00:02Z", 100, 100),
        proof_turn("2026-10-18T10:30:01Z", "parent-later"),
        proof_tokens("2026-10-18T10:30:02Z", 150, 50),
    ];
    let child = [
        parent[1].clone(),
        parent[2].clone(),
        proof_turn("2026-10-18T10:20:01Z", "child-local"),
        proof_tokens("2026-10-18T10:20:02Z", 115, 15),
    ];
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ottto-tail-codex-proof-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("rollout-2026-10-18T10-00-00-{PROOF_PARENT}.jsonl"));
    let body: String = parent.iter().map(|line| line.to_string() + "\n").collect();
    std::fs::write(&path, body).unwrap();
    let seal = crate::snapshots::codex_parent_proof_use_tests::seal_of(
        &File::open(&path).unwrap(),
        NOW,
        "tail-codex-proof",
    );
    std::fs::remove_dir_all(&dir).unwrap();
    let signatures = |values: &[serde_json::Value]| -> Vec<String> {
        values
            .iter()
            .filter_map(codex_ownership_signature)
            .collect()
    };
    let (parent, child) = (signatures(&parent), signatures(&child));
    let matched = parent
        .iter()
        .zip(&child)
        .take_while(|(parent, child)| parent == child)
        .count();
    assert!(
        matched > 0 && matched < child.len(),
        "the child diverges after a shared prefix"
    );
    let mut digest = codex_parent_prefix_seed();
    for signature in &child[..=matched] {
        digest = codex_parent_prefix_chain(&digest, signature);
    }
    let proof = CodexParentPrefixProof {
        parent: PROOF_PARENT.into(),
        parent_seal: seal,
        matched: matched as u64,
        child_digest: codex_digest_hex(&digest),
        owned: true,
        published: false,
    };
    assert_eq!(codex_digest_from_hex(&proof.child_digest), Some(digest));
    (proof, digest)
}

/// [money] A child whose stored boundary used a parent prefix proof continues
/// only on that same proof from this read's evidence: it gets the proof's
/// prefix back (matched count and digest), waits while no proof is installed,
/// and rebuilds on a different proof. The used proof round-trips the head.
#[test]
fn install_live_restores_the_parent_proof_the_child_used() {
    let (proof, digest) = real_proof();
    let used = || {
        let mut stored = continuable();
        stored.codex_parent_ledger_consulted = true;
        stored.codex_parent_session_ref = Some(PROOF_PARENT.into());
        stored.codex_ownership_boundary = CodexOwnershipBoundary::AwaitingParentPrefix;
        stored.codex_parent_proof_used = Some((proof.clone(), None));
        stored
    };
    let live = |proof: Option<CodexParentPrefixProof>| {
        let mut live = SnapshotAccumulator::new(SnapshotSource::Codex);
        live.codex_parent_prefix_proof = proof.map(|proof| (proof, digest));
        live
    };

    let mut stored = used();
    assert_eq!(install(&mut stored, &live(Some(proof.clone()))), Ok(()));
    assert!(matches!(
        stored.codex_parent_signatures,
        Some(CodexParentPrefix::Proof { matched, digest: installed })
            if matched == proof.matched && installed == digest
    ));
    assert_eq!(
        install(&mut used(), &live(None)),
        Err(LiveLoadError::Unavailable),
        "no installed proof cannot show the prefix holds"
    );
    let mut other = proof.clone();
    other.matched += 1;
    assert_eq!(install(&mut used(), &live(Some(other))), INCOMPATIBLE);
    let mut elsewhere = proof.clone();
    elsewhere.parent = "019fd6a0-0000-7000-8000-0000000000a2".into();
    assert_eq!(
        install(&mut used(), &live(Some(elsewhere))),
        Err(LiveLoadError::Unavailable),
        "another parent's proof is no evidence for this one"
    );

    // The used proof is head state: it survives a stage and load.
    let (mut reduction, certificate) = parse(&lines(1));
    reduction.accumulator_for_test().codex_parent_proof_used = Some((proof.clone(), None));
    let back = loaded(&stage_reduction::<Codex>(
        &reduction,
        &certificate,
        &identity(),
    ));
    assert_eq!(back.codex_parent_proof_used, Some((proof, None)));
}
