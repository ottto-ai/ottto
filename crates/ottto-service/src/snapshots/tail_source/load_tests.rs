//! The Claude load on real committed Tail state: a restart continues past the
//! sealed offset with the cold Full's body (its session facts from the
//! database), a quiet restart reads nothing,
//! damaged or missing state is a counted reconstruction, a Tail-only failure
//! resumes from the committed head, absence retires, an identity mismatch
//! retires before reuse, and a newer build's head holds.
use super::super::claude::tests::lines;
use super::super::claude::Claude;
use super::super::seam::tests::{route, scope, Route, NOW};
use super::*;
use crate::local_resource_diagnostics::capture;
use crate::snapshots::sampled_jsonl::durable::test_finish_items;
use crate::snapshots::state_v2::{Collection, StagedFile};
use crate::transcript_acquisition::ReadMode;
use serde_json::Value;

/// A first completion of `responses` committed as `name`.
pub(in crate::snapshots::tail_source) fn committed(
    route: &mut Route,
    name: &str,
    responses: usize,
) -> (PathBuf, String) {
    committed_lines(route, name, &lines(responses))
}

/// A first completion of `lines` committed as `name`.
pub(super) fn committed_lines(
    route: &mut Route,
    name: &str,
    lines: &[String],
) -> (PathBuf, String) {
    let (tail, native) = route.complete(name, lines, None, |_| {});
    let key = tail.key_for_test().to_owned();
    assert!(tail.publish(&native));
    route.save(false);
    assert!(state_v2::tail_head_keys(&route.index)
        .unwrap()
        .contains(&key));
    (route.dir.join(name), key)
}

/// Appends the next response of a `responses` file (and its compaction).
pub(super) fn append(path: &Path, responses: usize) {
    let (before, after) = (lines(responses), lines(responses + 1));
    let grown = &after[before.len() - 1..after.len() - 1];
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all((grown.join("\n") + "\n").as_bytes())
        .unwrap();
}

pub(super) fn len(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

/// One load's diagnostics: its points, and what it counted.
pub(super) struct Loaded {
    pub(super) records: Vec<Value>,
    outcome: String,
    causes: Vec<String>,
}

fn load_as(route: &Route, path: &Path, key: &str, index_path: &Path) -> (Load, Loaded) {
    let id = HeadIdentity::new(
        index_path,
        SnapshotSource::ClaudeCode,
        &route.dir,
        path,
        false,
    );
    let mut held = File::open(path).unwrap();
    let fresh = super::settlement_tests::candidate(path);
    let before = counters::totals();
    let (load, records) = capture(|| {
        load::<Claude>(
            &route.index,
            &route.path,
            key,
            &id,
            &mut held,
            &scope(),
            &fresh,
            &SnapshotAccumulator::new(SnapshotSource::ClaudeCode),
        )
    });
    let after = counters::totals();
    // Each label once per count the load added to `name`.
    let added = |name: &str| -> Vec<String> {
        after
            .iter()
            .filter(|((counted, _), _)| *counted == name)
            .flat_map(|(at, total)| {
                let grown = total - before.get(at).copied().unwrap_or(0);
                std::iter::repeat(at.1.to_owned()).take(grown as usize)
            })
            .collect()
    };
    let [outcome] = &added("tail_db_loads")[..] else {
        panic!("one counted load: {:?}", added("tail_db_loads"));
    };
    let loaded = Loaded {
        records,
        outcome: outcome.clone(),
        causes: added("tail_reconstruct"),
    };
    (load, loaded)
}

pub(super) fn loaded(route: &Route, path: &Path, key: &str) -> (Load, Loaded) {
    load_as(route, path, key, &route.path)
}

fn points<'a>(records: &'a [Value], stage: &str) -> Vec<&'a Value> {
    records
        .iter()
        .filter(|record| record["stage"] == stage)
        .map(|record| &record["counts"])
        .collect()
}

/// The load's counted outcome and reconstruction causes.
pub(super) fn counted(loaded: &Loaded) -> (String, Vec<String>) {
    (loaded.outcome.clone(), loaded.causes.clone())
}

/// A prepared read of `path` over `taken`, its start, and its consumed bytes.
pub(super) fn read(
    route: &Route,
    path: &Path,
    taken: Option<Box<Taken<CachedJsonlReduction>>>,
) -> (OwnedJsonlParser, ReadMode, u64) {
    let mut parser = route.open(path);
    let Ok(mode) = parser.prepare_acquisition_owned(taken, &scope(), None, NOW) else {
        panic!("the read prepares");
    };
    let start = parser
        .reader
        .acquisition
        .as_ref()
        .map_or(0, |plan| plan.start_offset());
    if !matches!(mode, ReadMode::Unchanged) {
        while !parser.step().unwrap() {}
    }
    (parser, mode, start)
}

/// The unsampled native oracle: an independently admitted cold Full.
pub(super) fn cold(route: &Route, path: &Path) -> Value {
    let (parser, mode, start) = read(route, path, None);
    assert!(matches!(mode, ReadMode::Full(_)) && start == 0);
    test_finish_items(parser, path, SnapshotSource::ClaudeCode)
}

/// The cold Full's PRE-finalization state.
pub(super) fn cold_accumulator(route: &Route, path: &Path) -> SnapshotAccumulator {
    let (parser, mode, _) = read(route, path, None);
    assert!(matches!(mode, ReadMode::Full(_)));
    let acc: &SnapshotAccumulator = &parser.accumulator;
    acc.clone()
}

/// [money] A restart loads the committed head, reads only past the sealed
/// offset, and finishes with the cold Full's body.
#[test]
fn a_restart_continues_past_the_sealed_offset_with_the_cold_body() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 300);
    let sealed = len(&path);
    append(&path, 300);
    let (load, records) = loaded(&route, &path, &key);
    let Load::Reused(taken, Some(_)) = load else {
        panic!("the committed head is reused with its base");
    };
    assert_eq!(counted(&records), ("hit".into(), vec![]));
    let (parser, mode, start) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Tail));
    assert_eq!(start, sealed, "no native byte before the sealed offset");
    assert_eq!(parser.reader.consumed_bytes(), len(&path) - sealed);
    let warm = test_finish_items(parser, &path, SnapshotSource::ClaudeCode);
    assert_eq!(warm, cold(&route, &path));
}

/// [behaviour] A quiet restart is Unchanged and reads no native byte.
#[test]
fn a_quiet_restart_is_unchanged() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let (load, records) = loaded(&route, &path, &key);
    let Load::Reused(taken, Some(_)) = load else {
        panic!("the committed head is reused");
    };
    assert_eq!(counted(&records).0, "hit");
    let (parser, mode, _) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Unchanged));
    assert_eq!(parser.reader.consumed_bytes(), 0);
}

/// [behaviour] A corrupt page, an incomplete collection, a missing page or
/// no head at all is one counted reconstruction, then a Full.
#[test]
fn damaged_or_missing_state_is_a_counted_reconstruction() {
    let mut route = route();
    type Damage = fn(&mut StagedFile);
    let cases: [(&str, Damage, &str); 3] = [
        (
            "corrupt.jsonl",
            |staged| {
                staged.pages.insert((Collection::Responses, 0), vec![0]);
            },
            "corrupt",
        ),
        (
            "incomplete.jsonl",
            |staged| {
                staged.collections.remove(&Collection::Compactions);
                staged
                    .pages
                    .retain(|(collection, _), _| *collection != Collection::Compactions);
            },
            "incomplete",
        ),
        (
            "missing.jsonl",
            |staged| {
                assert!(staged.pages.remove(&(Collection::Responses, 1)).is_some());
            },
            "incomplete",
        ),
    ];
    for (name, damage, cause) in cases {
        let (mut tail, _native) = route.complete(name, &lines(300), None, |_| {});
        let key = tail.key_for_test().to_owned();
        let mut staged = tail.take_staged_for_test();
        damage(&mut staged);
        state_v2::stage_tail(&route.path, &key, staged).unwrap();
        route.save(false);
        let path = route.dir.join(name);
        let (load, records) = loaded(&route, &path, &key);
        assert!(matches!(load, Load::Cold(_)), "{name}");
        assert_eq!(
            counted(&records),
            ("error".into(), vec![cause.into()]),
            "{name}"
        );
        let (_, mode, _) = read(&route, &path, None);
        assert!(matches!(mode, ReadMode::Full(_)), "{name}");
    }
    let path = route.dir.join("new.jsonl");
    std::fs::write(&path, lines(3).join("\n") + "\n").unwrap();
    let (load, records) = loaded(&route, &path, &local_index_key(&path));
    assert!(matches!(load, Load::Cold(_)));
    assert_eq!(counted(&records), ("miss".into(), vec!["no_head".into()]));
}

/// [money] A Tail-only failure keeps the committed head; the next pass is
/// selected by its marker, resumes from that head, counts the appended
/// response once and clears the marker.
#[test]
fn a_tail_only_failure_resumes_from_the_committed_head() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let committed_head = route.head(&key).unwrap().body;
    let sealed = len(&path);
    append(&path, 3);
    let (Load::Reused(taken, Some(base)), _) = loaded(&route, &path, &key) else {
        panic!("the committed head is reused");
    };
    let (parser, _, _) = read(&route, &path, Some(taken));
    let (tail, native) = route.finish(&path, parser, Some(base), |acc| {
        acc.account_identifier_hash = Some("a".repeat(64));
    });
    assert!(!tail.publish(&native));
    route.save(false);
    assert!(set_aside(&route.index, &key));
    assert_eq!(route.head(&key).unwrap().body, committed_head);

    let (Load::Reused(taken, None), records) = loaded(&route, &path, &key) else {
        panic!("a set-aside file reuses its head without a base");
    };
    assert_eq!(counted(&records).0, "hit");
    let (parser, mode, start) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Tail) && start == sealed);
    let (tail, native) = route.finish(&path, parser, None, |_| {});
    let warm = serde_json::to_value(&native.as_ref().unwrap().snapshots).unwrap();
    assert!(tail.publish(&native));
    route.save(false);
    assert!(!set_aside(&route.index, &key));

    let (parser, _, _) = read(&route, &path, None);
    let (_, cold) = route.finish(&path, parser, None, |_| {});
    assert_eq!(
        warm,
        serde_json::to_value(&cold.unwrap().snapshots).unwrap()
    );
    let head = route.head(&key).unwrap();
    let mut acc = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    Claude::decode_head(head.revision, &head.body, &mut acc).unwrap();
    state_v2::load_tail(&route.index, &key, &head, |collection, page, bytes| {
        Claude::decode_page(collection, page, &bytes, &mut acc).unwrap();
        Ok(())
    })
    .unwrap();
    assert_eq!(acc.claude_responses.values().len(), 4);
}

/// [behaviour] A4d: a head neither observed, residue nor indexed retires;
/// the other three stay.
#[test]
fn absent_heads_retire() {
    let mut route = route();
    let [(_, observed), (_, residue), (_, indexed), _absent] =
        ["a", "b", "c", "d"].map(|name| committed(&mut route, &format!("{name}.jsonl"), 3));
    route.index.files.insert(
        indexed.clone(),
        serde_json::from_value::<ScanIndexEntry>(serde_json::json!({
            "size_bytes": 4, "modified_unix_seconds": 1,
            "source_file_fingerprint": "a".repeat(64),
            "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION
        }))
        .unwrap(),
    );
    retire_absent(
        SnapshotSource::ClaudeCode,
        &route.index,
        &BTreeSet::from([observed.clone()]),
        &BTreeSet::from([residue.clone()]),
    );
    route.save(false);
    assert_eq!(
        state_v2::tail_head_keys(&route.index).unwrap(),
        BTreeSet::from([observed, residue, indexed])
    );
}

/// [behaviour] A4d classifies absent heads by custody, never by set
/// difference alone: a reduction retires and its revisions stay under a
/// metadata-only head, which the next complete census keeps (absence never
/// clears debt); a head that fails to load is set aside, not retired (F4).
/// The metadata-only head is no checkpoint: its file reads as a first read,
/// with no reconstruction.
#[test]
fn absent_heads_are_classified_by_custody() {
    let mut route = route();
    let (path, owed) = committed(&mut route, "owed.jsonl", 3);
    // F1: an observation restates the head's current summary.
    let common = route.head(&owed).unwrap().common;
    state_v2::observe_tail(
        &route.path,
        &owed,
        state_v2::Observation {
            representation: common.representation,
            summary: common.debt,
            added: vec![b"debt".to_vec()],
            ..Default::default()
        },
    )
    .unwrap();
    let (mut future, _native) = route.complete("future.jsonl", &lines(3), None, |_| {});
    let future_key = future.key_for_test().to_owned();
    let mut staged = future.take_staged_for_test();
    staged.revision = Claude::REDUCTION_REVISION + 1;
    state_v2::stage_tail(&route.path, &future_key, staged).unwrap();
    route.save(false);

    let none = BTreeSet::new();
    for census in 0..2 {
        let ((), records) =
            capture(|| retire_absent(SnapshotSource::ClaudeCode, &route.index, &none, &none));
        route.save(false);
        let keys = state_v2::tail_head_keys(&route.index).unwrap();
        assert!(
            keys.contains(&owed) && keys.contains(&future_key),
            "{census}"
        );
        assert!(route.head(&owed).unwrap().metadata_only, "{census}");
        assert!(route.marker(&future_key).is_some(), "{census}");
        let [counts] = points(&records, "tail_absent")[..] else {
            panic!("one classification point: {records:?}");
        };
        let retired = u64::from(census == 0);
        let count = |name: &str| counts[name].as_u64();
        assert_eq!(
            [count("retired"), count("kept_debt"), count("set_aside")],
            [Some(retired), Some(1 - retired), Some(1)],
            "{census}"
        );
    }

    let (load, records) = loaded(&route, &path, &owed);
    assert!(matches!(load, Load::Cold(None)));
    assert_eq!(counted(&records), ("miss".into(), vec![]));
}

/// [behaviour] C′: a head bound to another destination's route is retired
/// before anything in it is reused.
#[test]
fn an_identity_mismatch_retires_before_reuse() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let other = route.dir.join("other-destination").join("state.db");
    let (load, records) = load_as(&route, &path, &key, &other);
    assert!(matches!(load, Load::Cold(_)));
    assert_eq!(counted(&records), ("error".into(), vec!["identity".into()]));
    route.save(false);
    assert!(route.head(&key).is_none() && route.marker(&key).is_none());
}

/// [behaviour] A newer build's head holds the file: no reconstruction, no
/// Full, the head untouched.
#[test]
fn a_future_revision_holds() {
    let mut route = route();
    let (mut tail, _native) = route.complete("a.jsonl", &lines(3), None, |_| {});
    let key = tail.key_for_test().to_owned();
    let mut staged = tail.take_staged_for_test();
    staged.revision = Claude::REDUCTION_REVISION + 1;
    state_v2::stage_tail(&route.path, &key, staged).unwrap();
    route.save(false);
    let (load, records) = loaded(&route, &route.dir.join("a.jsonl"), &key);
    assert!(matches!(load, Load::Held));
    assert_eq!(counted(&records), ("held".into(), vec![]));
    assert!(state_v2::tail_head_keys(&route.index)
        .unwrap()
        .contains(&key));
}
