//! A committed head rewritten under an ACK still in flight, parameterized by
//! source, on the real database route, native finishes and upload ledger: ACK(a)
//! settles only a's exact body, B stays owed with its pages intact, and a crash
//! between the two recovers head A, suppresses the identical a POST and leaves b
//! owed. Then Codex's own continuation and page-shrink rows on the same route.
use super::super::claude::{tests::lines as claude_lines, Claude};
use super::super::codex::{tests::lines as codex_lines, tests::SESSION, Codex};
use super::super::load::{load, Load};
use super::tests::{route_for, scope, Route, NOW};
use super::*;
use crate::snapshot_sync::tail_ack_ledger::AckLedger;
use crate::snapshots::sampled_jsonl::durable::test_finish_items;
use crate::snapshots::sampled_jsonl::SideCertificate;
use crate::snapshots::sampled_scan::transition_fixture::native_cold as fixture;
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::state_v2::{BaselineRelease, TailHead};
use crate::transcript_acquisition::ReadMode;
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

/// A read of `path` stepped to its end, to its certified completion and native
/// finish, encoded at the real PRE seam over `base` (none: every row).
fn finish<S: FixtureSource>(
    route: &Route,
    path: &Path,
    mut parser: OwnedJsonlParser,
    base: Option<TailBase>,
    at_pre: impl FnOnce(&mut SnapshotAccumulator),
) -> (PendingTail, Result<ParsedJsonlFile>) {
    let SideCertificate::Certified { completed, .. } =
        parser.certify_without_retention(&scope(), NOW).unwrap()
    else {
        panic!("a clean fixture is certified");
    };
    at_pre(&mut parser.accumulator);
    let mut tail = PendingTail {
        route: route.path.clone(),
        key: local_index_key(path),
        id: id::<S>(route, path),
        certificate: completed.checkpoint.durable_certificate(0).unwrap(),
        unsealed: completed.unsealed,
        full: base.is_none(),
        base,
        encode: tail_encode::<S>,
        encoded: None,
    };
    let identity = opened_object_identity(S::SOURCE, &mut File::open(path).unwrap()).unwrap();
    let request = FinishRequest {
        expected_opened_object_identity: &identity,
        path,
        collected_at: "2026-10-20T16:00:00Z",
        source_file_fingerprint: "a".repeat(64),
        codex_title_metadata: None,
        claude_title_metadata: None,
        attribution_context: None,
        repository_identity: None,
        money_context: None,
    };
    let native = parser.finish_native(
        request,
        Some(&mut |live: PreFinalization<'_>| tail.encode(&live)),
    );
    assert!(tail.encoded.is_some(), "PRE encoded");
    (tail, native)
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
    let mut held = File::open(&path).unwrap();
    let recovered = load::<S>(
        &route.index,
        &route.path,
        &key,
        &id::<S>(&route, &path),
        &mut held,
        &scope(),
    );
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
    let mut held = File::open(path).unwrap();
    let id = id::<Codex>(route, path);
    let Load::Reused(taken, Some(base)) =
        load::<Codex>(&route.index, &route.path, key, &id, &mut held, &scope())
    else {
        panic!("the committed head is reused with its base");
    };
    let mut parser = open::<Codex>(path);
    let Ok(mode) = parser.prepare_acquisition_owned(Some(taken), &scope(), None, NOW) else {
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
/// head still loads: Codex's signature list clears at its cap.
#[test]
fn a_shrunk_collection_retires_its_vanished_pages() {
    let mut route = route_for(Source::Codex);
    let path = route.dir.join(Codex::name());
    rewrite(&path, &codex_lines(3));
    let (tail, native) = complete::<Codex>(&route, &path, None, |acc| {
        acc.codex_physical_signatures.clear();
        for n in 0..300 {
            acc.codex_physical_signatures
                .push(sha256_hex(&["tail-transition-signature", &n.to_string()]));
        }
    });
    let key = tail.key.clone();
    assert!(tail.publish(&native));
    route.save(false);
    assert!(pages::<Codex>(&route, &key).contains_key(&(Collection::Signatures, 1)));

    let committed = head::<Codex>(&route, &key);
    let mut base = TailBase::new(&committed.body, false);
    state_v2::load_tail(&route.index, &key, &committed, |collection, page, bytes| {
        base.observe::<Codex>(collection, page, &bytes)
            .map_err(|_| anyhow::anyhow!("page"))
    })
    .unwrap();
    let (tail, native) = complete::<Codex>(&route, &path, Some(base), |acc| {
        acc.codex_physical_signatures.clear();
    });
    let staged = tail.staged_for_test().expect("the shrink restates");
    assert!(staged.obsolete.contains(&(Collection::Signatures, 0)));
    assert!(staged.obsolete.contains(&(Collection::Signatures, 1)));
    assert!(tail.publish(&native));
    route.save(false);
    assert!(!pages::<Codex>(&route, &key)
        .keys()
        .any(|(collection, _)| *collection == Collection::Signatures));
    let mut held = File::open(&path).unwrap();
    let id = id::<Codex>(&route, &path);
    assert!(matches!(
        load::<Codex>(&route.index, &route.path, &key, &id, &mut held, &scope()),
        Load::Reused(..)
    ));
}

/// [behaviour] A foreign field at PRE sets aside only its own file; a sibling
/// commits, and neither is lost.
#[test]
fn a_codex_finish_field_sets_aside_only_its_own_file() {
    let mut route = route_for(Source::Codex);
    let (dirty, clean) = (route.dir.join("dirty.jsonl"), route.dir.join(Codex::name()));
    rewrite(&dirty, &codex_lines(2));
    rewrite(&clean, &codex_lines(2));
    let (held, native) = complete::<Codex>(&route, &dirty, None, |acc| {
        acc.claude_fork_parent = Some("parent".into());
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
