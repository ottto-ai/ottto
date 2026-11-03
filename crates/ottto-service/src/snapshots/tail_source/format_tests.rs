//! S2 c7 on real committed Tail state: a shorter file reads main's counted
//! Full (D158), a key epoch change is a counted explicit-action
//! reconstruction, the legacy record directory is erased and counted before
//! the first load, the first format round-trips the lineage clocks and the
//! rule epoch, and only Claude has a codec.
use super::super::claude::tests::lines;
use super::super::claude::Claude;
use super::super::seam::tests::{route, scope};
use super::tests::{committed, counted, len, loaded};
use super::*;
use crate::local_resource_diagnostics::capture;
use crate::snapshots::tail_source::{counters, has_codec, tail_route};
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
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    claude_request_identity::bind_test_session_context_key(Some([7; 32]));
    let (load, records) = loaded(&route, &path, &key);
    assert!(matches!(load, Load::Cold(None)));
    assert_eq!(counted(&records), ("miss".into(), vec!["key_epoch".into()]));
    let reconstruct = records
        .iter()
        .find(|record| record["stage"] == "tail_reconstruct")
        .unwrap();
    assert_eq!(reconstruct["counts"]["explicit_action"], true);
    assert_eq!(reconstruct["counts"]["after_head"], false);
    assert_eq!(counters::total("tail_reconstruct", "key_epoch"), 1);
    assert_eq!(
        counters::total("tail_reconstruct_after_head", "key_epoch"),
        0
    );

    // No key at all is its own epoch, too.
    claude_request_identity::bind_test_session_context_key(None);
    let (load, _) = loaded(&route, &path, &key);
    assert!(matches!(load, Load::Cold(None)));
    assert_eq!(counters::total("tail_reconstruct", "key_epoch"), 2);
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
        )
    });
    assert!(matches!(load, Load::Reused(_, Some(_))));
    assert!(!legacy.exists());
    let at = |stage: &str| {
        records
            .iter()
            .position(|record| record["stage"] == stage)
            .unwrap()
    };
    assert!(at("tail_legacy_dir") < at("tail_db_loads"));
    assert_eq!(records[at("tail_legacy_dir")]["counts"]["removed"], 1);
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

/// [behaviour] L01: only Claude has a codec, whatever the registry's
/// `state_v2` flag says, and each source's counters stay on its own line.
#[test]
fn only_claude_has_a_codec_and_counters_stay_per_source() {
    let route = route();
    assert!(has_codec(SnapshotSource::ClaudeCode));
    assert!(tail_route(SnapshotSource::ClaudeCode, &route.index).is_some());
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        assert!(!has_codec(source));
        assert!(tail_route(source, &route.index).is_none());
    }
    counters::bump(SnapshotSource::ClaudeCode, "tail_db_loads", "hit");
    let ((), codex) = capture(|| counters::emit(SnapshotSource::Codex));
    assert!(codex.is_empty());
    let ((), claude) = capture(|| counters::emit(SnapshotSource::ClaudeCode));
    assert_eq!(claude.len(), 1);
}
