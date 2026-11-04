//! A committed head rewritten under an ACK still in flight, parameterized by
//! source, on the real database route, native finishes and upload ledger: ACK(a)
//! settles only a's exact body, B stays owed with its pages intact, and a crash
//! between the two recovers head A, suppresses the identical a POST and leaves b
//! owed. Then Codex's own continuation and page-shrink rows on the same route.
use super::super::claude::{tests::lines as claude_lines, Claude};
use super::super::codex::{tests::candidate, tests::lines as codex_lines, tests::SESSION, Codex};
use super::super::load::{load, Load};
use super::tests::{route_for, scope, Route, NOW};
use super::*;
use crate::snapshot_sync::tail_ack_ledger::AckLedger;
use crate::snapshots::sampled_jsonl::durable::test_finish_items;
use crate::snapshots::sampled_scan::transition_fixture::native_cold as fixture;
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::state_v2::{BaselineRelease, TailHead};
use crate::transcript_acquisition::{ReadMode, Scope};
use serde_json::Value;

/// What the shared rows need from a source.
trait FixtureSource: TailSource {
    const INDEX: Source;
    const APPLY: fn(&Value, &mut SnapshotAccumulator);
    fn name() -> String;
    fn lines(size: usize) -> Vec<String>;
}
impl FixtureSource for Claude {
    const INDEX: Source = Source::Claude;
    const APPLY: fn(&Value, &mut SnapshotAccumulator) = apply_claude_code_line;
    fn name() -> String {
        "a.jsonl".to_owned()
    }
    fn lines(size: usize) -> Vec<String> {
        claude_lines(size)
    }
}
impl FixtureSource for Codex {
    const INDEX: Source = Source::Codex;
    const APPLY: fn(&Value, &mut SnapshotAccumulator) = apply_codex_line;
    fn name() -> String {
        format!("rollout-2026-10-18T10-00-00-{SESSION}.jsonl")
    }
    fn lines(size: usize) -> Vec<String> {
        codex_lines(size)
    }
}

/// A new object at `path`, as an atomic rewrite leaves it.
fn rewrite(path: &Path, lines: &[String]) {
    let next = path.with_extension("next");
    std::fs::write(&next, lines.join("\n") + "\n").unwrap();
    std::fs::rename(&next, path).unwrap();
}

fn open<S: FixtureSource>(path: &Path) -> OwnedJsonlParser {
    fixture::parser(S::SOURCE, path, File::open(path).unwrap(), S::APPLY)
}

fn id<S: FixtureSource>(route: &Route, path: &Path) -> HeadIdentity {
    HeadIdentity::new(&route.path, S::SOURCE, &route.dir, path, false)
}

/// `S`'s load of `path`'s committed head, with a fresh parser's accumulator as
/// this read's live inputs, as the scan prepares them before the load.
fn load_at<S: FixtureSource>(route: &Route, path: &Path, key: &str) -> Load {
    load_under::<S>(route, path, key, &scope())
}

/// `load_at` under this read's acquisition `scope`.
fn load_under<S: FixtureSource>(route: &Route, path: &Path, key: &str, scope: &Scope) -> Load {
    let mut held = File::open(path).unwrap();
    let live = open::<S>(path);
    load::<S>(
        &route.index,
        &route.path,
        key,
        &id::<S>(route, path),
        &mut held,
        scope,
        &candidate(path),
        &live.accumulator,
    )
}

/// A read of `path` stepped to its end, to its certified completion and native
/// finish, encoded at the real PRE seam over `base` (none: every row).
fn finish<S: FixtureSource>(
    route: &Route,
    path: &Path,
    parser: OwnedJsonlParser,
    base: Option<TailBase>,
    at_pre: impl FnOnce(&mut SnapshotAccumulator),
) -> (PendingTail, Result<ParsedJsonlFile>) {
    finish_under::<S>(route, path, parser, base, at_pre, &scope())
}

/// `finish` under this read's acquisition `scope`.
fn finish_under<S: FixtureSource>(
    route: &Route,
    path: &Path,
    parser: OwnedJsonlParser,
    base: Option<TailBase>,
    at_pre: impl FnOnce(&mut SnapshotAccumulator),
    scope: &Scope,
) -> (PendingTail, Result<ParsedJsonlFile>) {
    route.finish_under::<S>(path, parser, base, at_pre, scope)
}

/// One certified Full read of `path` as it stands now.
fn complete<S: FixtureSource>(
    route: &Route,
    path: &Path,
    base: Option<TailBase>,
    at_pre: impl FnOnce(&mut SnapshotAccumulator),
) -> (PendingTail, Result<ParsedJsonlFile>) {
    let mut parser = open::<S>(path);
    parser
        .prepare_acquisition(None, &scope(), None, NOW)
        .unwrap();
    while !parser.step().unwrap() {}
    finish::<S>(route, path, parser, base, at_pre)
}

fn head<S: FixtureSource>(route: &Route, key: &str) -> TailHead {
    state_v2::load_head(&route.index, key, S::REDUCTION_REVISION)
        .unwrap()
        .expect("a committed head")
}

fn pages<S: FixtureSource>(route: &Route, key: &str) -> BTreeMap<(Collection, u64), Vec<u8>> {
    let head = head::<S>(route, key);
    let mut pages = BTreeMap::new();
    state_v2::load_tail(&route.index, key, &head, |collection, page, bytes| {
        pages.insert((collection, page), bytes);
        Ok(())
    })
    .unwrap();
    pages
}

/// The native bodies frozen for upload, under `logical`'s fingerprints when the
/// rewrite is to the same logical entity.
fn frozen<S: FixtureSource>(
    native: &Result<ParsedJsonlFile>,
    logical: Option<&[SnapshotItem]>,
) -> Vec<SnapshotItem> {
    let mut items = native.as_ref().unwrap().snapshots.clone();
    assert!(!items.is_empty(), "the fixture has a body to deliver");
    for (n, item) in items.iter_mut().enumerate() {
        item.snapshot_fingerprint = match logical {
            Some(logical) => logical[n].snapshot_fingerprint.clone(),
            None => snapshot_fingerprint(S::SOURCE, item),
        };
    }
    items
}

fn differs(a: &[SnapshotItem], b: &[SnapshotItem]) -> bool {
    a.iter()
        .map(snapshot_upload_body_witness)
        .ne(b.iter().map(snapshot_upload_body_witness))
}

fn ack_a_after_rewrite_settles_only_a<S: FixtureSource>() {
    let mut route = route_for(S::INDEX);
    let path = route.dir.join(S::name());
    rewrite(&path, &S::lines(3));
    let (tail, native) = complete::<S>(&route, &path, None, |_| {});
    let key = tail.key.clone();
    let a = frozen::<S>(&native, None);
    assert!(tail.publish(&native));
    route.save(false);
    let head_a = head::<S>(&route, &key).body;

    rewrite(&path, &S::lines(4));
    let (tail, native) = complete::<S>(&route, &path, None, |_| {});
    let b = frozen::<S>(&native, Some(&a));
    assert_eq!(a.len(), b.len());
    assert!(differs(&a, &b), "the rewrite changes the body");
    assert!(tail.publish(&native));
    route.save(false);
    let head_b = head::<S>(&route, &key).body;
    assert_ne!(head_a, head_b);
    let pages_b = pages::<S>(&route, &key);

    let mut ledger = AckLedger::new(S::SOURCE);
    ledger.deliver(&a);
    assert_eq!(ledger.posts(), a.len());
    assert!(a.iter().all(|item| ledger.settled(item)));
    assert!(!b.iter().any(|item| ledger.settled(item)), "B stays owed");
    assert_eq!(head::<S>(&route, &key).body, head_b);
    assert!(pages::<S>(&route, &key) == pages_b, "B's pages stay intact");

    ledger.deliver(&a);
    assert_eq!(ledger.posts(), a.len(), "a replayed ACK is no new credit");
    ledger.deliver(&b);
    assert_eq!(ledger.posts(), a.len() + b.len());
    assert!(b.iter().all(|item| ledger.settled(item)));
    ledger.deliver(&b);
    assert_eq!(ledger.posts(), a.len() + b.len(), "nor is b's");
}

/// [money] ACK(a) after A→B settles a's exact body once and leaves b owed.
#[test]
fn claude_ack_a_after_rewrite_settles_only_a() {
    ack_a_after_rewrite_settles_only_a::<Claude>();
}
/// [money] ACK(a) after A→B settles a's exact body once and leaves b owed.
#[test]
fn codex_ack_a_after_rewrite_settles_only_a() {
    ack_a_after_rewrite_settles_only_a::<Codex>();
}

#[derive(Clone, Copy)]
enum Crash {
    /// B was staged and never saved.
    BeforeSave,
    /// B was staged and never saved, and the file's Tail is set aside.
    SetAside,
}

fn ack_a_before_b_save_then_crash<S: FixtureSource>(crash: Crash) {
    let mut route = route_for(S::INDEX);
    let path = route.dir.join(S::name());
    rewrite(&path, &S::lines(3));
    let (tail, native) = complete::<S>(&route, &path, None, |_| {});
    let key = tail.key.clone();
    let a = frozen::<S>(&native, None);
    assert!(tail.publish(&native));
    route.save(false);
    let head_a = head::<S>(&route, &key).body;
    let pages_a = pages::<S>(&route, &key);

    rewrite(&path, &S::lines(4));
    let (tail, native) = complete::<S>(&route, &path, None, |_| {});
    let b = frozen::<S>(&native, Some(&a));
    assert!(differs(&a, &b));
    assert!(tail.publish(&native));
    let mut ledger = AckLedger::new(S::SOURCE);
    ledger.deliver(&a);

    // The crash loses the stage; the durable ACK and head A remain.
    drop(BaselineRelease::new(&route.path, &route.index));
    if matches!(crash, Crash::SetAside) {
        state_v2::set_aside_tail(&route.path, &key, SetAsideCause::Encode).unwrap();
        route.save(false);
    }
    assert_eq!(head::<S>(&route, &key).body, head_a);
    assert!(pages::<S>(&route, &key) == pages_a);

    // The file is no longer the certified one: an ordinary Full, not a reuse.
    let recovered = load_at::<S>(&route, &path, &key);
    assert!(matches!(recovered, Load::Cold(Some(_))));

    let (tail, native) = complete::<S>(&route, &path, None, |_| {});
    let replayed = frozen::<S>(&native, Some(&a));
    assert!(!differs(&b, &replayed), "the replay reaches the same body");
    ledger.deliver(&a);
    assert_eq!(
        ledger.posts(),
        a.len(),
        "the identical a POST is suppressed"
    );
    assert!(!b.iter().any(|item| ledger.settled(item)), "b stays owed");
    assert!(tail.publish(&native));
    route.save(false);
    assert_ne!(head::<S>(&route, &key).body, head_a);
    ledger.deliver(&b);
    assert_eq!(ledger.posts(), a.len() + b.len());
    assert!(b.iter().all(|item| ledger.settled(item)));
}

/// [money] Durable ACK(a), B never saved: recover A, suppress a, b owed.
#[test]
fn claude_ack_a_before_b_save_recovers_after_a_crash() {
    ack_a_before_b_save_then_crash::<Claude>(Crash::BeforeSave);
    ack_a_before_b_save_then_crash::<Claude>(Crash::SetAside);
}
/// [money] Durable ACK(a), B never saved: recover A, suppress a, b owed.
#[test]
fn codex_ack_a_before_b_save_recovers_after_a_crash() {
    ack_a_before_b_save_then_crash::<Codex>(Crash::BeforeSave);
    ack_a_before_b_save_then_crash::<Codex>(Crash::SetAside);
}

/// One stored read past the committed head of `path`.
fn stored_read(route: &Route, path: &Path, key: &str) -> (OwnedJsonlParser, TailBase, ReadMode) {
    stored_read_under(route, path, key, &scope())
}

/// `stored_read` under this read's acquisition `scope`.
fn stored_read_under(
    route: &Route,
    path: &Path,
    key: &str,
    scope: &Scope,
) -> (OwnedJsonlParser, TailBase, ReadMode) {
    let Load::Reused(taken, Some(base)) = load_under::<Codex>(route, path, key, scope) else {
        panic!("the committed head is reused with its base");
    };
    let mut parser = open::<Codex>(path);
    let Ok(mode) = parser.prepare_acquisition_owned(Some(taken), scope, None, NOW) else {
        panic!("the read prepares");
    };
    if !matches!(mode, ReadMode::Unchanged) {
        while !parser.step().unwrap() {}
    }
    (parser, base, mode)
}

fn cold_items(path: &Path) -> Value {
    let mut parser = open::<Codex>(path);
    parser
        .prepare_acquisition(None, &scope(), None, NOW)
        .unwrap();
    while !parser.step().unwrap() {}
    test_finish_items(parser, path, SnapshotSource::Codex)
}

fn append(path: &Path, from: usize, to: usize) {
    let (before, after) = (codex_lines(from), codex_lines(to));
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all((after[before.len()..].join("\n") + "\n").as_bytes())
        .unwrap();
}

/// [money] Native cold Full == Tail == database restart, twice, over appends,
/// and a quiet restart reads no native byte.
#[test]
fn a_codex_restart_continues_with_the_cold_body_across_two_restarts() {
    let mut route = route_for(Source::Codex);
    let path = route.dir.join(Codex::name());
    rewrite(&path, &codex_lines(6));
    let (tail, native) = complete::<Codex>(&route, &path, None, |_| {});
    let key = tail.key.clone();
    assert!(tail.publish(&native));
    route.save(false);

    let (parser, _, mode) = stored_read(&route, &path, &key);
    assert!(matches!(mode, ReadMode::Unchanged));
    assert_eq!(parser.reader.consumed_bytes(), 0);

    let sealed = std::fs::metadata(&path).unwrap().len();
    append(&path, 6, 7);
    let (parser, _, mode) = stored_read(&route, &path, &key);
    assert!(matches!(mode, ReadMode::Tail));
    assert_eq!(
        parser.reader.consumed_bytes(),
        std::fs::metadata(&path).unwrap().len() - sealed
    );
    assert_eq!(
        test_finish_items(parser, &path, SnapshotSource::Codex),
        cold_items(&path)
    );

    let (parser, base, _) = stored_read(&route, &path, &key);
    let (tail, native) = finish::<Codex>(&route, &path, parser, Some(base), |_| {});
    assert!(tail.publish(&native));
    route.save(false);

    append(&path, 7, 8);
    let (parser, _, mode) = stored_read(&route, &path, &key);
    assert!(matches!(mode, ReadMode::Tail));
    assert_eq!(
        test_finish_items(parser, &path, SnapshotSource::Codex),
        cold_items(&path)
    );
}

/// [behaviour] A slot collection that shrinks deletes its vanished pages and the
/// head still loads after a collection's contents are retired.
#[test]
fn a_shrunk_collection_retires_its_vanished_pages() {
    let mut route = route_for(Source::Codex);
    let path = route.dir.join(Codex::name());
    rewrite(&path, &codex_lines(3));
    let (tail, native) = complete::<Codex>(&route, &path, None, |acc| {
        acc.compaction_timestamps.clear();
        for n in 0..300 {
            acc.compaction_timestamps
                .push(sha256_hex(&["tail-transition-compaction", &n.to_string()]));
        }
    });
    let key = tail.key.clone();
    assert!(tail.publish(&native));
    route.save(false);
    assert!(pages::<Codex>(&route, &key).contains_key(&(Collection::Compactions, 1)));

    let committed = head::<Codex>(&route, &key);
    let mut base = TailBase::new(&committed.body);
    state_v2::load_tail(&route.index, &key, &committed, |collection, page, bytes| {
        base.observe::<Codex>(collection, page, &bytes)
            .map_err(|_| anyhow::anyhow!("page"))
    })
    .unwrap();
    let (tail, native) = complete::<Codex>(&route, &path, Some(base), |acc| {
        acc.compaction_timestamps.clear();
    });
    let staged = tail.staged_for_test().expect("the shrink restates");
    assert!(staged.obsolete.contains(&(Collection::Compactions, 0)));
    assert!(staged.obsolete.contains(&(Collection::Compactions, 1)));
    assert!(tail.publish(&native));
    route.save(false);
    assert!(!pages::<Codex>(&route, &key)
        .keys()
        .any(|(collection, _)| *collection == Collection::Compactions));
    assert!(matches!(
        load_at::<Codex>(&route, &path, &key),
        Load::Reused(..)
    ));
}

/// [behaviour] A field Codex never stores, set at PRE, sets aside only its own
/// file; a sibling commits, and neither is lost.
#[test]
fn a_codex_finish_field_sets_aside_only_its_own_file() {
    let mut route = route_for(Source::Codex);
    let (dirty, clean) = (route.dir.join("dirty.jsonl"), route.dir.join(Codex::name()));
    rewrite(&dirty, &codex_lines(2));
    rewrite(&clean, &codex_lines(2));
    let (held, native) = complete::<Codex>(&route, &dirty, None, |acc| {
        acc.claude_usage_request_ids.insert("r".into());
    });
    let dirty_key = held.key.clone();
    assert!(!held.publish(&native));
    let (tail, native) = complete::<Codex>(&route, &clean, None, |_| {});
    let clean_key = tail.key.clone();
    assert!(tail.publish(&native));
    route.save(false);
    assert!(route.marker(&dirty_key).is_some());
    assert!(
        state_v2::load_head(&route.index, &dirty_key, Codex::REDUCTION_REVISION)
            .unwrap()
            .is_none()
    );
    assert!(route.marker(&clean_key).is_none());
    assert_eq!(
        head::<Codex>(&route, &clean_key).revision,
        Codex::REDUCTION_REVISION
    );
}

/// `path`'s committed head and pages as a read's base.
fn base_of(route: &Route, key: &str) -> TailBase {
    let committed = head::<Codex>(route, key);
    let mut base = TailBase::new(&committed.body);
    state_v2::load_tail(&route.index, key, &committed, |collection, page, bytes| {
        base.observe::<Codex>(collection, page, &bytes)
            .map_err(|_| anyhow::anyhow!("page"))
    })
    .unwrap();
    base
}

/// [behaviour] F3 on Codex: a title, first-prompt or workspace rewrite
/// restages only its own session-fact slot and stages `DropsPrivate`, so the
/// old value is purged; an unchanged restage restates no fact. The new value
/// then loads from the database.
#[test]
fn a_codex_content_rewrite_restages_its_fact_and_drops_the_old_value() {
    let mut route = route_for(Source::Codex);
    let path = route.dir.join(Codex::name());
    rewrite(&path, &codex_lines(3));
    let (tail, native) = complete::<Codex>(&route, &path, None, |acc| {
        acc.title = Some("Before".into());
        acc.first_prompt_material = Some("first prompt before".into());
    });
    let key = tail.key.clone();
    assert!(tail.publish(&native));
    route.save(false);

    let (same, _) = complete::<Codex>(&route, &path, Some(base_of(&route, &key)), |acc| {
        acc.title = Some("Before".into());
        acc.first_prompt_material = Some("first prompt before".into());
    });
    if let Some(staged) = same.staged_for_test() {
        assert_eq!(staged.change, Change::Ordinary);
        assert!(!staged
            .pages
            .keys()
            .any(|(collection, _)| *collection == Collection::SessionFacts));
    }

    type Rewrite = fn(&mut SnapshotAccumulator);
    let rewrites: [(u64, Rewrite); 3] = [
        (0, |acc| acc.title = Some("After".into())),
        (1, |acc| {
            acc.first_prompt_material = Some("first prompt after".into())
        }),
        (2, |acc| {
            acc.workspace_path = Some(PathBuf::from("/tmp/elsewhere"))
        }),
    ];
    let before = |acc: &mut SnapshotAccumulator| {
        acc.title = Some("Before".into());
        acc.first_prompt_material = Some("first prompt before".into());
    };
    for (slot, rewrite_fact) in rewrites {
        let (renamed, _) = complete::<Codex>(&route, &path, Some(base_of(&route, &key)), |acc| {
            before(acc);
            rewrite_fact(acc);
        });
        let staged = renamed.staged_for_test().expect("the rewrite restates");
        assert_eq!(staged.change, Change::DropsPrivate, "fact {slot}");
        assert_eq!(
            staged
                .pages
                .keys()
                .filter(|(collection, _)| *collection == Collection::SessionFacts)
                .copied()
                .collect::<Vec<_>>(),
            [(Collection::SessionFacts, slot)],
            "only fact {slot} restates"
        );
    }
    let (renamed, native) = complete::<Codex>(&route, &path, Some(base_of(&route, &key)), |acc| {
        before(acc);
        acc.title = Some("After".into());
    });
    assert!(renamed.publish(&native));
    route.save(false);
    let Load::Reused(taken, _) = load_at::<Codex>(&route, &path, &key) else {
        panic!("the committed head is reused");
    };
    let (acc, _, _) = taken.retained.state.finish_view();
    assert_eq!(acc.title.as_deref(), Some("After"));
}

// Codex money rows: native cold Full against the Tail's restart and upgrade
// arms on the real database route, in totals and placement (the transition
// fixture's money oracle). Codex places a session by its creator pair
// (`session_account_evidence`); it has no per-request identity tags or side
// calls, so the plan §5 controls map to: two accounts, a mid-session creator
// switch (a contradicting header clears the witness), an evidence gap (no
// creator pair) and tagged sessions (those that keep their pair).
use crate::snapshots::sampled_scan::transition_fixture::{
    self as oracle_fixture, money_oracle, Accepted, Mode, RouteResult,
};

const ACCOUNT_B: &str = "019a0c2a-8e11-7222-8333-944445555778";
const GAP: &str = "019a0c2a-8e11-7222-8333-944445555779";

fn codex_header(id: &str, account: Option<&str>, at: &str) -> String {
    let mut payload = serde_json::json!({"id": id, "timestamp": "2026-10-18T10:00:00Z",
        "source": "cli", "cwd": "/tmp/tail-codex"});
    if let Some(account) = account {
        payload["creator_user_id"] = format!("synthetic-user-{account}").into();
        payload["creator_account_id"] = format!("synthetic-workspace-{account}").into();
    }
    serde_json::json!({"timestamp": at, "type": "session_meta", "payload": payload}).to_string()
}

/// The plain `rollout-<id>` name: its id is the path's one candidate. A
/// timestamped name needs the sidecar's identity (production binds it), and
/// this finish passes no sidecar, so its creator witness would be withheld.
fn rollout_name(id: &str) -> String {
    format!("rollout-{id}.jsonl")
}

/// `turns` closed turns under `id`'s own header with `account`'s creator pair.
fn account_rollout(route: &Route, id: &str, account: Option<&str>, turns: usize) -> PathBuf {
    let path = route.dir.join(rollout_name(id));
    let mut lines = codex_lines(turns);
    lines[0] = codex_header(id, account, "2026-10-18T10:00:00Z");
    rewrite(&path, &lines);
    path
}

fn append_line(path: &Path, line: &str) {
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all((line.to_owned() + "\n").as_bytes()).unwrap();
}

/// The emitted bodies of `items` as one canonical upload, with the Codex
/// evidence the oracle requires (the route's index entries, the items' tokens).
fn codex_emitted(mode: Mode, index: &ScanIndex, items: &[SnapshotItem]) -> RouteResult {
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::Codex.api_slug().into(),
        machine_id: "a".repeat(64),
        collector_version: Some("0.1.synthetic".into()),
        snapshots: items.to_vec(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let batches = if items.is_empty() {
        Vec::new()
    } else {
        vec![serde_json::to_vec(&request).unwrap()]
    };
    let mut route = RouteResult::emitted(mode, SnapshotSource::Codex, batches, items);
    route.codex_evidence = oracle_fixture::codex_evidence_of_items(index, items);
    route
}

/// An independent cold Full of every path: a fresh parser, no stored state.
fn codex_cold(route: &Route, paths: &[PathBuf]) -> RouteResult {
    let mut items = Vec::new();
    for path in paths {
        let mut parser = open::<Codex>(path);
        let mode = parser
            .prepare_acquisition(None, &scope(), None, NOW)
            .unwrap();
        assert!(matches!(mode, ReadMode::Full(_)));
        while !parser.step().unwrap() {}
        let (_, native) = finish::<Codex>(route, path, parser, None, |_| {});
        items.extend(native.unwrap().snapshots);
    }
    codex_emitted(Mode::ColdFull, &route.index, &items)
}

/// A new process's read of every path from its committed head: each must load
/// and continue as `expect`, consuming only the bytes past its seal. Returns
/// the emitted bodies and each completion, unpublished.
fn codex_stored(
    route: &Route,
    paths: &[PathBuf],
    mode: Mode,
    expect: fn(&ReadMode) -> bool,
) -> (RouteResult, Vec<(PendingTail, Result<ParsedJsonlFile>)>) {
    codex_stored_under(route, paths, mode, expect, &scope())
}

/// `codex_stored` under this read's acquisition `scope`.
fn codex_stored_under(
    route: &Route,
    paths: &[PathBuf],
    mode: Mode,
    expect: fn(&ReadMode) -> bool,
    scope: &Scope,
) -> (RouteResult, Vec<(PendingTail, Result<ParsedJsonlFile>)>) {
    let mut items = Vec::new();
    let mut completions = Vec::new();
    for path in paths {
        let key = local_index_key(path);
        let (parser, base, read) = stored_read_under(route, path, &key, scope);
        assert!(expect(&read), "{}: {read:?}", path.display());
        let (tail, native) = finish_under::<Codex>(route, path, parser, Some(base), |_| {}, scope);
        items.extend(native.as_ref().unwrap().snapshots.clone());
        completions.push((tail, native));
    }
    (codex_emitted(mode, &route.index, &items), completions)
}

fn evidence(route: &RouteResult, session: &str) -> Value {
    route.snapshots[session]["session_account_evidence"].clone()
}

/// [money] Codex cold Full == Tail restart == upgrade, totals AND placement,
/// over two accounts, a mid-session creator switch, an evidence gap and tagged
/// sessions; a swapped placement fails the oracle (positive control).
#[test]
fn codex_cold_full_equals_tail_restart_and_upgrade_in_totals_and_placement() {
    let mut route = route_for(Source::Codex);
    let paths = [
        account_rollout(&route, SESSION, Some("a"), 3),
        account_rollout(&route, ACCOUNT_B, Some("b"), 2),
        account_rollout(&route, GAP, None, 2),
    ];
    for path in &paths {
        let (tail, native) = complete::<Codex>(&route, path, None, |_| {});
        assert!(tail.publish(&native));
    }
    route.save(false);
    let first = codex_cold(&route, &paths);
    let (a, b) = (evidence(&first, SESSION), evidence(&first, ACCOUNT_B));
    assert!(a.is_object() && b.is_object(), "two tagged sessions");
    assert_ne!(a, b, "positive control: two accounts");
    assert!(
        evidence(&first, GAP).is_null(),
        "positive control: an evidence gap"
    );

    // Growth everywhere; session A's creator switches mid-session.
    append(&paths[0], 3, 4);
    append_line(
        &paths[0],
        &codex_header(SESSION, Some("a-switched"), "2026-10-18T13:00:00Z"),
    );
    append(&paths[1], 2, 3);
    append(&paths[2], 2, 3);
    let cold = codex_cold(&route, &paths);
    assert!(
        evidence(&cold, SESSION).is_null(),
        "positive control: the switch clears A's creator witness"
    );
    assert_eq!(evidence(&cold, ACCOUNT_B), b, "B stays tagged");

    let is_tail = |read: &ReadMode| matches!(read, ReadMode::Tail);
    let (restart, completions) = codex_stored(&route, &paths, Mode::Restart, is_tail);
    money_oracle::assert_equivalent(&cold, &restart);
    let mut swapped = restart.clone();
    swapped.snapshots.get_mut(ACCOUNT_B).unwrap()["session_account_evidence"] =
        evidence(&first, SESSION);
    assert!(
        std::panic::catch_unwind(|| money_oracle::assert_equivalent(&cold, &swapped)).is_err(),
        "the oracle sees a moved placement"
    );
    for (tail, native) in completions {
        assert!(tail.publish(&native));
    }
    route.save(false);

    // Upgrade: the older owner's next pass finds every file unchanged and
    // rewrites no head; a new process then Tails the growth from those heads.
    let is_unchanged = |read: &ReadMode| matches!(read, ReadMode::Unchanged);
    let (quiet, completions) = codex_stored(&route, &paths, Mode::Restart, is_unchanged);
    money_oracle::assert_equivalent(&codex_cold(&route, &paths), &quiet);
    for (tail, _) in &completions {
        assert!(tail
            .staged_for_test()
            .map_or(true, |staged| staged.pages.is_empty()));
    }
    drop(completions);
    append(&paths[1], 3, 4);
    let (upgraded, _) = codex_stored(&route, &paths[1..2], Mode::DiskRestore, is_tail);
    money_oracle::assert_equivalent(&codex_cold(&route, &paths[1..2]), &upgraded);
}

/// [money] D168-3: an account-witness change, then a destination change, after
/// a restart (each a new acquisition scope) continue every Codex head from
/// Tail, and each restart equals a cold Full in totals AND creator placement:
/// account evidence is applied from the stored creator facts and this read's
/// live evidence, never by a re-read. A swapped placement fails the oracle.
#[test]
fn a_codex_restart_under_a_changed_account_scope_places_like_a_cold_full() {
    let mut route = route_for(Source::Codex);
    let paths = [
        account_rollout(&route, SESSION, Some("a"), 3),
        account_rollout(&route, ACCOUNT_B, Some("b"), 2),
        account_rollout(&route, GAP, None, 2),
    ];
    for path in &paths {
        let (tail, native) = complete::<Codex>(&route, path, None, |_| {});
        assert!(tail.publish(&native));
    }
    route.save(false);
    let first = codex_cold(&route, &paths);
    let (a, b) = (evidence(&first, SESSION), evidence(&first, ACCOUNT_B));
    assert!(a.is_object() && b.is_object(), "two tagged sessions");
    assert_ne!(a, b, "positive control: two accounts");

    let is_tail = |read: &ReadMode| matches!(read, ReadMode::Tail);
    for (n, namespace) in ["tail-seam-witness-changed", "tail-seam-destination-changed"]
        .into_iter()
        .enumerate()
    {
        assert_ne!(Scope(namespace.into()), scope());
        append(&paths[0], 3 + n, 4 + n);
        append(&paths[1], 2 + n, 3 + n);
        append(&paths[2], 2 + n, 3 + n);
        let (restart, completions) = codex_stored_under(
            &route,
            &paths,
            Mode::Restart,
            is_tail,
            &Scope(namespace.into()),
        );
        let cold = codex_cold(&route, &paths);
        money_oracle::assert_equivalent(&cold, &restart);
        assert_eq!(evidence(&restart, SESSION), a, "{namespace}");
        assert_eq!(evidence(&restart, ACCOUNT_B), b, "{namespace}");
        assert!(evidence(&restart, GAP).is_null(), "{namespace}");
        let mut swapped = restart.clone();
        swapped.snapshots.get_mut(ACCOUNT_B).unwrap()["session_account_evidence"] = a.clone();
        assert!(
            std::panic::catch_unwind(|| money_oracle::assert_equivalent(&cold, &swapped)).is_err(),
            "the oracle sees a moved placement ({namespace})"
        );
        for (tail, native) in completions {
            assert!(tail.publish(&native));
        }
        route.save(false);
    }
}

/// [money] A future revision's head holds its file: no body is re-emitted,
/// the accepted body and witness stay, and nothing smaller replaces them.
#[test]
fn a_future_codex_head_holds_without_a_smaller_reemit() {
    let mut route = route_for(Source::Codex);
    let path = account_rollout(&route, SESSION, Some("a"), 3);
    let (mut tail, native) = complete::<Codex>(&route, &path, None, |_| {});
    let key = tail.key.clone();
    let items = native.unwrap().snapshots;
    let mut prior = codex_emitted(Mode::ColdFull, &route.index, &items);
    for item in &items {
        prior.accepted.insert(
            item.source_session_id.clone(),
            Accepted {
                body: prior.snapshots[&item.source_session_id].clone(),
                witness: snapshot_upload_body_witness(item),
            },
        );
    }
    let mut staged = tail.take_staged_for_test();
    staged.revision = Codex::REDUCTION_REVISION + 1;
    state_v2::stage_tail(&route.path, &key, staged).unwrap();
    route.save(false);
    assert!(matches!(load_at::<Codex>(&route, &path, &key), Load::Held));
    let mut held = codex_emitted(Mode::Restart, &route.index, &[]);
    held.accepted = prior.accepted.clone();
    money_oracle::assert_no_smaller_reemit(
        SESSION,
        &prior,
        &held,
        &codex_cold(&route, std::slice::from_ref(&path)),
        true,
    );
}

/// [money] An ownership-affecting sidecar change after a committed head
/// reconstructs through the existing counted path; totals and placement equal
/// a cold Full under the new evidence, including the newly withheld session.
#[test]
fn codex_sidecar_change_after_commit_equals_cold_full_in_totals_and_placement() {
    let mut route = route_for(Source::Codex);
    let paths = [
        account_rollout(&route, SESSION, Some("a"), 3),
        account_rollout(&route, ACCOUNT_B, Some("b"), 2),
        account_rollout(&route, GAP, None, 2),
    ];
    let open_with = |path: &Path, metadata: &CodexTitleMetadata| {
        OwnedJsonlParser::new(
            File::open(path).unwrap(),
            path,
            SnapshotSource::Codex,
            apply_codex_line,
            Some(metadata),
            None,
            None,
        )
        .unwrap()
    };
    let before = CodexTitleMetadata::default();
    for path in &paths {
        let mut parser = open_with(path, &before);
        parser
            .prepare_acquisition(None, &scope(), None, NOW)
            .unwrap();
        while !parser.step().unwrap() {}
        let (tail, native) = route.finish_under::<Codex>(path, parser, None, |_| {}, &scope());
        assert!(!native.as_ref().unwrap().snapshots.is_empty());
        assert!(tail.publish(&native));
    }
    route.save(false);
    let mut after = before.clone();
    after.state_created_threads.insert(SESSION.to_owned());
    assert_ne!(
        before.path_reduction_fingerprint(&paths[0]),
        after.path_reduction_fingerprint(&paths[0])
    );
    for (n, path) in paths.iter().enumerate() {
        append(path, if n == 0 { 3 } else { 2 }, if n == 0 { 4 } else { 3 });
    }
    let mut resumed = Vec::new();
    let mut cold = Vec::new();
    let reconstructions = super::super::counters::total("tail_reconstruct", "incompatible");
    for (n, path) in paths.iter().enumerate() {
        let key = local_index_key(path);
        let mut parser = open_with(path, &after);
        let mut held = File::open(path).unwrap();
        let loaded = load::<Codex>(
            &route.index,
            &route.path,
            &key,
            &id::<Codex>(&route, path),
            &mut held,
            &scope(),
            &candidate(path),
            &parser.accumulator,
        );
        let base = match loaded {
            Load::Cold(None) if n == 0 => {
                assert!(matches!(
                    parser
                        .prepare_acquisition(None, &scope(), None, NOW)
                        .unwrap(),
                    ReadMode::Full(_)
                ));
                None
            }
            Load::Reused(taken, Some(base)) if n != 0 => {
                assert!(matches!(
                    parser
                        .prepare_acquisition_owned(Some(taken), &scope(), None, NOW)
                        .unwrap_or_else(|_| panic!("unchanged session prepares Tail")),
                    ReadMode::Tail
                ));
                Some(base)
            }
            _ => panic!("changed ownership reconstructs, other sessions Tail"),
        };
        while !parser.step().unwrap() {}
        let (_, native) = route.finish_under::<Codex>(path, parser, base, |_| {}, &scope());
        resumed.extend(native.unwrap().snapshots);
        let mut parser = open_with(path, &after);
        parser
            .prepare_acquisition(None, &scope(), None, NOW)
            .unwrap();
        while !parser.step().unwrap() {}
        let (_, native) = route.finish_under::<Codex>(path, parser, None, |_| {}, &scope());
        cold.extend(native.unwrap().snapshots);
    }
    assert_eq!(
        super::super::counters::total("tail_reconstruct", "incompatible"),
        reconstructions + 1
    );
    assert!(
        !cold.iter().any(|item| item.source_session_id == SESSION),
        "state-created without a rollout declaration is withheld"
    );
    let cold = codex_emitted(Mode::ColdFull, &route.index, &cold);
    let resumed = codex_emitted(Mode::Restart, &route.index, &resumed);
    assert!(evidence(&cold, ACCOUNT_B).is_object());
    assert!(evidence(&cold, GAP).is_null());
    money_oracle::assert_equivalent(&cold, &resumed);
}
