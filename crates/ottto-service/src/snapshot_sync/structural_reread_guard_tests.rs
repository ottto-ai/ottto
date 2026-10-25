// Extends the verifier's e18242c2 real-pipeline fixture with a seven-day,
// trigger-agnostic read bound. Initial import occurs BEFORE the measured
// window (NewFile is exempt). No existing acceptance assertion is changed.
use super::*;
use crate::snapshots::reread_guard::{clear_cache_for_test, TestClock};
const HEALTHY: [&str; 5] = [
    "e1000000-0000-4000-8000-000000000001",
    "e2000000-0000-4000-8000-000000000002",
    "e3000000-0000-4000-8000-000000000003",
    "e4000000-0000-4000-8000-000000000004",
    "e5000000-0000-4000-8000-000000000005",
];

#[test]
#[serial(source_manifests)]
fn structural_reread_budget_bounds_healthy_files_across_all_triggers_for_seven_days() {
    if !c1a_layout_supported("structural-reread-seven-days") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let start = time::OffsetDateTime::parse(
        "2026-08-02T08:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp() as u64;
    let clock = TestClock::at(start);
    let mut fixture = c1a_fixture("structural-reread-seven-days");
    fixture.native_file_limit = 64;
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
    // retries have the same bytes; holding never bypasses the shared budget.
    RearmFixture::append(
        &c1b_terminal_path(&fixture),
        &rearm_transcript_line(REARM_TERMINAL, None, "req_guard_held", 1),
    );
    let mut reads = BTreeMap::<String, usize>::new();
    let mut refusals = 0u64;
    let mut event_counts = [0usize; 9];
    for tick in 0..28usize {
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
            "budget refusal never settles a pending authority hold"
        );
        assert_eq!(
            c1b_terminal_head(&page.index),
            held_head,
            "held ACK does not advance"
        );
        for (key, head) in &heads {
            assert_eq!(&page.index.files[key].last_snapshot_fingerprint, head);
        }
        let value = serde_json::to_value(&page.index).unwrap();
        refusals += value["reread_guard"]["refused"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap())
            .sum::<u64>();
        if refusals > 0 {
            assert!(
                !page.scan.census_complete,
                "withheld debt never becomes a clean census"
            );
        }
    }
    assert!(
        event_counts.iter().all(|count| *count > 0),
        "every trigger was exercised"
    );
    assert!(
        refusals > 0,
        "the shared guard refused recurring unchanged work"
    );
    for session in HEALTHY {
        assert!(
            reads.get(session).copied().unwrap_or(0) <= 2,
            "{session}: healthy full rereads over 7d: {reads:?}"
        );
    }
}
