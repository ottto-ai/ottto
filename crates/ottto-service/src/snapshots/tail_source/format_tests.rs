//! S2 c7 on real committed Tail state: a shorter file reads main's counted
//! Full (D158), a key rotation is a counted explicit-action reconstruction
//! while an attribution toggle scrubs and reuses, the legacy record directory
//! is erased and counted before the first load, the first format round-trips
//! the lineage clocks and the rule epoch, the shared hour pages carry usage
//! buckets, and only Claude has a codec.
use super::super::claude::tests::lines;
use super::super::claude::Claude;
use super::super::seam::tests::{route, scope};
use super::tests::{append, cold, committed, committed_lines, counted, len, loaded, read};
use super::*;
use crate::local_resource_diagnostics::capture;
use crate::snapshots::sampled_jsonl::durable::test_finish_items;
use crate::snapshots::tail_source::{
    counters, has_codec, hour_pages, keeps_ram, read_hour_page, tail_route,
};
use crate::transcript_acquisition::ReadMode;
use serde_json::Value;

/// [behaviour] D158: a file shorter than its committed head reads main's
/// counted Full, `Shrunk`, with no hold.
#[test]
fn a_shorter_file_reads_full_and_is_counted() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(len(&path) - 1)
        .unwrap();
    let (load, records) = loaded(&route, &path, &key);
    assert!(matches!(load, Load::Cold(Some(FullReason::Shrunk))));
    assert_eq!(counted(&records), ("miss".into(), vec![]));
    assert_eq!(counters::total("tail_shorter_file_full", "files"), 1);
}

/// [behaviour] #1255: a head made under another attribution key is never
/// reused; the Full is a counted explicit-action reconstruction, apart from
/// the release gate.
#[test]
fn a_key_epoch_change_is_a_counted_reconstruction() {
    let mut route = route();
    claude_request_identity::bind_test_session_context_key(Some([1; 32]));
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    claude_request_identity::bind_test_session_context_key(Some([7; 32]));
    let (load, records) = loaded(&route, &path, &key);
    assert!(matches!(load, Load::Cold(None)));
    assert_eq!(counted(&records), ("miss".into(), vec!["key_epoch".into()]));
    assert_eq!(counters::total("tail_reconstruct", "key_epoch"), 1);
    assert_eq!(
        counters::total("tail_reconstruct_after_head", "key_epoch"),
        0
    );
}

/// `lines(responses)` with the user's email ahead of the first response, so
/// a head made under a key stores a keyed context digest.
fn keyed_lines(responses: usize) -> Vec<String> {
    let mut lines = lines(responses);
    let sentence = serde_json::json!({"type": "attachment", "attachment": {
        "type": "session_context", "context": {"userEmail": "one@example.invalid"}}});
    lines.insert(1, sentence.to_string());
    lines
}

/// [behaviour] D168-2: session attribution toggled off, then on, is a
/// settings change applied forward only, never a reconstruction: each load
/// reuses the head with its context digest scrubbed, as main scrubs a
/// retained parse's, and the continued body equals a cold read's under the
/// new setting.
#[test]
fn an_attribution_toggle_scrubs_the_digest_and_reuses_the_head() {
    const KEY: [u8; 32] = [1; 32];
    let mut route = route();
    for (name, stored, current) in [
        ("off.jsonl", Some(KEY), None),
        ("on.jsonl", None, Some(KEY)),
    ] {
        claude_request_identity::bind_test_session_context_key(stored);
        let (path, key) = committed_lines(&mut route, name, &keyed_lines(3));
        let (Load::Reused(mut unscrubbed, _), _) = loaded(&route, &path, &key) else {
            panic!("{name}: the same key reuses the head");
        };
        claude_request_identity::bind_test_session_context_key(current);
        append(&path, 3);
        claude_request_identity::take_context_digest_scrubs_for_test();
        let (load, records) = loaded(&route, &path, &key);
        let Load::Reused(mut taken, Some(_)) = load else {
            panic!("{name}: a toggle reuses the head");
        };
        assert_eq!(counted(&records), ("hit".into(), vec![]), "{name}");
        assert_eq!(
            claude_request_identity::take_context_digest_scrubs_for_test(),
            1,
            "{name}"
        );
        if current.is_none() {
            // The stored digest is gone: the markers are a no-key cold read's.
            let (fresh, _, _) = read(&route, &path, None);
            let markers = &taken
                .retained
                .state
                .accumulator_for_test()
                .claude_org_markers;
            assert!(fresh.accumulator.claude_org_markers.is_some());
            assert_eq!(markers, &fresh.accumulator.claude_org_markers);
            assert_ne!(
                markers,
                &unscrubbed
                    .retained
                    .state
                    .accumulator_for_test()
                    .claude_org_markers
            );
        }
        let (parser, mode, _) = read(&route, &path, Some(taken));
        assert!(matches!(mode, ReadMode::Tail), "{name}");
        let warm = test_finish_items(parser, &path, SnapshotSource::ClaudeCode);
        assert_eq!(warm, cold(&route, &path), "{name}");
    }
    assert_eq!(counters::total("tail_reconstruct", "key_epoch"), 0);
}

/// [behaviour] #1255: the pass's start removes the retired record directory,
/// counted, before the pass's first Tail load.
#[test]
fn legacy_erasure_is_counted_before_the_first_load() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    crate::locked_state_dir::test_locks::hold(&route.dir);
    let legacy = state_v2::retired_record_dir(&route.path);
    std::fs::create_dir_all(legacy.join("ab")).unwrap();
    std::fs::write(legacy.join("ab/synthetic.rec"), b"retired").unwrap();
    let cache = sampled_scan::SharedCache::default();
    let id = HeadIdentity::new(
        &route.path,
        SnapshotSource::ClaudeCode,
        &route.dir,
        &path,
        false,
    );
    let fresh = super::settlement_tests::candidate(&path);
    let (load, records) = capture(|| {
        begin_source_pass(
            &cache,
            &route.dir,
            SnapshotSource::ClaudeCode,
            &route.path,
            &scope(),
            false,
        );
        let mut held = File::open(&path).unwrap();
        load::<Claude>(
            &route.index,
            &route.path,
            &key,
            &id,
            &mut held,
            &scope(),
            &fresh,
            &SnapshotAccumulator::new(SnapshotSource::ClaudeCode),
        )
    });
    assert!(matches!(load, Load::Reused(_, Some(_))));
    assert!(!legacy.exists());
    // The pass removed the directory before this load hit.
    let removed = records
        .iter()
        .find(|record| record["stage"] == "tail_legacy_dir")
        .expect("the pass reports the removal");
    assert_eq!(removed["counts"]["removed"], 1);
    assert_eq!(counters::total("tail_db_loads", "hit"), 1);
}

/// [format] L04 + L12: the lineage clocks (copied history included) and each
/// request's rule epoch round-trip through the first head and page format.
#[test]
fn lineage_clocks_and_rule_epoch_round_trip() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let stamps: Vec<i128> = lines(3)
        .iter()
        .filter_map(|line| {
            let value: Value = serde_json::from_str(line).ok()?;
            rfc3339_unix_nanos(value.get("timestamp")?.as_str()?)
        })
        .collect();
    let expected = (*stamps.iter().min().unwrap(), *stamps.iter().max().unwrap());
    let (Load::Reused(mut taken, _), _) = loaded(&route, &path, &key) else {
        panic!("the committed head is reused");
    };
    let acc = taken.retained.state.accumulator_for_test();
    assert_eq!(acc.claude_line_clocks, Some(expected));
    assert!(expected.0 < expected.1);
    let epochs: Vec<u8> = acc
        .claude_responses
        .values()
        .map(|response| response.rule_epoch)
        .collect();
    assert_eq!(epochs.len(), 3);
    assert!(epochs
        .iter()
        .all(|epoch| *epoch == claude_request_money::e2::RULE_EPOCH));
}

/// [behaviour] L01: the codec list alone gives a source its codec and Tail
/// route, whatever the registry's `state_v2` flag says (Claude and Pi; Codex
/// not yet), and each source's counters stay on its own line.
#[test]
fn codec_list_gives_routes_and_counters_stay_per_source() {
    const CODECS: [SnapshotSource; 2] = [SnapshotSource::ClaudeCode, SnapshotSource::Pi];
    let route = route();
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let codec = CODECS.contains(&source);
        assert_eq!(has_codec(source), codec, "{}", source.api_slug());
        assert_eq!(
            tail_route(source, &route.index).is_some(),
            codec,
            "{}",
            source.api_slug()
        );
    }
    counters::bump(SnapshotSource::ClaudeCode, "tail_db_loads", "hit");
    for other in [SnapshotSource::Codex, SnapshotSource::Pi] {
        let ((), lines) = capture(|| counters::emit(other));
        assert!(lines.is_empty());
    }
    let ((), claude) = capture(|| counters::emit(SnapshotSource::ClaudeCode));
    assert_eq!(claude.len(), 1);
}

/// [regress] Retention and the RAM take share one rule, keyed on the Tail
/// route: a source off a route keeps and takes its RAM copy, one on a route
/// neither. The take keyed on the codec, so a codec source off a route kept a
/// copy it never took and read Full every time (CX1 S2b run 41569018173).
#[test]
fn the_ram_copy_is_kept_and_taken_only_off_a_tail_route() {
    let route = route();
    assert!(!keeps_ram(SnapshotSource::ClaudeCode, &route.index));
    assert!(keeps_ram(SnapshotSource::ClaudeCode, &ScanIndex::default()));
    assert!(keeps_ram(SnapshotSource::Codex, &route.index));
}

/// [format] The one hourly page codec carries usage buckets (`UsageHours`,
/// for Pi and Codex): each bucket on its hour's page, and the pages decode
/// back to the same pages.
#[test]
fn usage_buckets_round_trip_through_the_shared_hour_pages() {
    let start = String::as_str;
    let mut buckets = BTreeMap::new();
    for (bucket, at) in [
        ("2026-10-20T10:00:00Z", "2026-10-20T10:07:00Z"),
        ("2026-10-20T10:30:00Z", "2026-10-20T10:31:00Z"),
        ("2026-10-20T12:00:00Z", "2026-10-20T12:59:00Z"),
    ] {
        let mut state = UsageBucketState::default();
        state.note_activity_at(at);
        buckets.insert(bucket.to_owned(), state);
    }
    let pages = hour_pages(&buckets, start).unwrap();
    assert_eq!(pages.len(), 2);
    let mut decoded = BTreeMap::<String, UsageBucketState>::new();
    for (page, bytes) in &pages {
        read_hour_page(*page, bytes, &mut decoded, start).unwrap();
    }
    assert_eq!(hour_pages(&decoded, start).unwrap(), pages);
    let (page, bytes) = &pages[0];
    assert_eq!(
        read_hour_page(
            page + 1,
            bytes,
            &mut BTreeMap::<String, UsageBucketState>::new(),
            start
        ),
        Err(ReconstructCause::Corrupt)
    );
}
