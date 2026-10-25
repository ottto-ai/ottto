// Extends the verifier's e18242c2 real-pipeline fixture with a seven-day,
// trigger-agnostic observe-only parity test. Compare the same selection and
// delivery events with instrumentation disabled/enabled; no read is withheld.
use super::*;
use crate::snapshots::reread_guard::{
    clear_cache_for_test, observe_plan_for_test, TestClock, TestObservations,
};
const HEALTHY: [&str; 5] = [
    "e1000000-0000-4000-8000-000000000001",
    "e2000000-0000-4000-8000-000000000002",
    "e3000000-0000-4000-8000-000000000003",
    "e4000000-0000-4000-8000-000000000004",
    "e5000000-0000-4000-8000-000000000005",
];

#[test]
#[serial(source_manifests)]
fn structural_reread_observe_counts_all_triggers_for_seven_days_without_changing_reads() {
    if !c1a_layout_supported("structural-reread-seven-days-observe") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let (control, _, _) = run_observe_events(false);
    let (observed, would_refuse, reads) = run_observe_events(true);
    assert_eq!(
        observed, control,
        "observe-only leaves every page's reads and delivery decisions unchanged"
    );
    assert!(
        would_refuse > 0,
        "repeated unchanged reads are counted, never delayed"
    );
    assert!(
        HEALTHY
            .iter()
            .any(|session| reads.get(*session).copied().unwrap_or(0) > 2),
        "observe mode continues reading beyond the hypothetical per-file budget"
    );
    eprintln!("REREAD_OBSERVE_ACCEPTANCE would_refuse={would_refuse} reads={reads:?} unchanged_selection=true tripwire_would_fire=true");
}

fn run_observe_events(observe: bool) -> (Vec<serde_json::Value>, u64, BTreeMap<String, usize>) {
    let _observations = TestObservations::enabled(observe);
    let start = time::OffsetDateTime::parse(
        "2026-08-02T08:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp() as u64;
    let clock = TestClock::at(start);
    let mut fixture = c1a_fixture("structural-reread-seven-days");
    // Keep the real cached frame within the existing per-page layout budget.
    fixture.native_file_limit = 2;
    fixture.owned_base_preparation = true;
    fixture.reread_guard_cache = Some(std::sync::Arc::new(Default::default()));
    for session in HEALTHY {
        std::fs::write(
            fixture.root.join(format!("{session}.jsonl")),
            rearm_transcript_line(session, None, &format!("req_{session}"), 0),
        )
        .unwrap();
    }
    let mut closed = false;
    for minute in 0..8 {
        let closing = fixture.page(
            &format!("2026-08-02T08:{minute:02}:00Z"),
            RearmUpload::Accept,
        );
        if closing.scan.census_complete {
            closed = true;
            break;
        }
    }
    assert!(closed, "initial import completes before measurement");
    let baseline = ScanIndex::load(&fixture.index_path).unwrap();
    let heads = baseline
        .files
        .iter()
        .filter(|(key, _)| HEALTHY.iter().any(|id| key.contains(id)))
        .map(|(key, entry)| (key.clone(), entry.last_snapshot_fingerprint.clone()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(heads.len(), HEALTHY.len());
    let held_head = c1b_terminal_head(&baseline);
    assert!(held_head.is_some());
    let mut index = baseline;
    index.insert_retry_pending_claude_authority_for_test(REARM_TERMINAL);
    index.save(&fixture.index_path).unwrap();
    RearmFixture::append(&c1b_sibling_path(&fixture), "not-json\n");
    // One actual change explains the held family's first read. Its subsequent
    // retries have the same bytes; observe mode must retain BASE liveness.
    RearmFixture::append(
        &c1b_terminal_path(&fixture),
        &rearm_transcript_line(REARM_TERMINAL, None, "req_guard_held", 1),
    );
    let mut reads = BTreeMap::<String, usize>::new();
    let mut facts = Vec::new();
    let mut final_index = None;
    let mut event_counts = [0usize; 9];
    for tick in 0..=28usize {
        let elapsed_hours = tick * 6 + 1;
        clock.set(start + elapsed_hours as u64 * 3600);
        let day = 2 + (8 + elapsed_hours) / 24;
        let hour = (8 + elapsed_hours) % 24;
        let event = tick % event_counts.len();
        event_counts[event] += 1;
        match event {
            0 => {} // terminal-unhealthy retry: clock passes every backoff.
            1 => {
                // A process restart loses RAM, retains the sparse budget.
                fixture.reread_guard_cache = Some(std::sync::Arc::new(Default::default()));
                let reopened = ScanIndex::load(&fixture.index_path).unwrap();
                assert_eq!(c1b_terminal_head(&reopened), held_head);
            }
            2 => c1a_edit_index(&fixture, |saved| {
                if saved["traversal"].is_object() {
                    saved["traversal"]["context_fingerprint"] = "synthetic-new-context".into();
                }
            }),
            3 => c1a_edit_index(&fixture, |saved| {
                saved.insert(
                    "upload_context_fingerprint".into(),
                    "synthetic-old-policy".into(),
                );
            }),
            4 | 5 => c1a_edit_index(&fixture, |saved| {
                saved.insert(
                    "claude_duplicate_request_witness_overflowed".into(),
                    (event == 4).into(),
                );
            }),
            6 => {
                fixture.request_identity = !fixture.request_identity;
            }
            7 => c1a_edit_index(&fixture, |saved| {
                // A source revision without an approved ReplayGrant, also
                // exercising LegacyIdentity independently of fingerprint clears.
                saved["reread_guard"]["source_revision"] = "unapproved-previous-version".into();
                for entry in saved["files"].as_object_mut().unwrap().values_mut() {
                    entry["scan_identity_version"] = serde_json::Value::Null;
                }
            }),
            8 => clear_cache_for_test(fixture.reread_guard_cache.as_ref().unwrap()),
            _ => unreachable!(),
        }
        let mut last = None;
        for page_number in 0..8 {
            let at = format!("2026-08-{day:02}T{hour:02}:{page_number:02}:00Z");
            let page = fixture.page(&at, RearmUpload::Accept);
            for session in &page.parsed {
                if HEALTHY.contains(&session.as_str()) {
                    *reads.entry(session.clone()).or_default() += 1;
                }
            }
            facts.push(serde_json::json!({
                "parsed": page.parsed, "scanned": page.scan.scanned_file_count,
                "census_complete": page.scan.census_complete,
                "offered": page.offered.len(), "uploaded": page.uploaded.len(),
                "held": page.held.len(), "fully_settled": page.fully_settled,
            }));
            let ended = c1b_traversal_ended(&page.index).0;
            last = Some(page);
            if ended {
                break;
            }
        }
        let page = last.unwrap();
        assert!(
            c1b_traversal_ended(&page.index).0,
            "bounded traversal ends at event {event}"
        );
        let held = page
            .index
            .claude_authority_record_for_test(REARM_TERMINAL)
            .expect("held family remains disclosed");
        assert!(
            !held.terminal,
            "observation never settles a pending authority hold"
        );
        assert_eq!(
            c1b_terminal_head(&page.index),
            held_head,
            "held ACK does not advance"
        );
        assert!(
            page.index
                .files
                .keys()
                .filter(|key| HEALTHY.iter().any(|id| key.contains(id)))
                .count()
                >= HEALTHY.len()
        );
        final_index = Some(page.index);
    }
    assert!(
        event_counts.iter().all(|count| *count > 0),
        "every trigger was exercised"
    );
    let mut index = final_index.unwrap();
    let value = serde_json::to_value(&index).unwrap();
    let would_refuse = if observe {
        let guard = &value["reread_guard"];
        let count = guard["over_budget"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap())
            .sum::<u64>();
        let stamps = guard["attempts"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|slots| slots.as_array().unwrap())
            .filter(|n| n.as_u64().unwrap() != 0)
            .count() as u64;
        assert_eq!(guard["observed_reads"].as_u64().unwrap(), stamps + count,
            "within this first window every observation is a first/second stamp or one would-refuse count");
        // Whole-history metadata plan exceeds the threshold but cannot hold reads.
        let entry = index.files.values().next().unwrap().clone();
        for i in 0..301 {
            index
                .files
                .insert(format!("whole-history-{i}"), entry.clone());
        }
        index.activate_upload_context("whole-history-observe-policy".into());
        let (held, planned, alarm) = observe_plan_for_test(&mut index, "2026-08-09T10:00:00Z");
        assert!(!held);
        assert!(planned > 300);
        assert!(alarm > 0);
        count
    } else {
        0
    };
    (facts, would_refuse, reads)
}
