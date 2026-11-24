//! Tests and test counters for the Codex rollout header cache (unix only).

use super::*;
thread_local! {
    pub(in crate::snapshots) static READ_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static READ_PATHS: std::cell::RefCell<Option<Vec<PathBuf>>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn note_read(path: &Path) {
    READ_CALLS.with(|calls| calls.set(calls.get() + 1));
    READ_PATHS.with(|paths| {
        if let Some(paths) = paths.borrow_mut().as_mut() {
            paths.push(path.to_path_buf());
        }
    });
}

pub(in crate::snapshots) fn observe_read_paths<T>(
    run: impl FnOnce() -> T,
) -> (T, Vec<PathBuf>) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            let _ = READ_PATHS.with(|paths| paths.replace(None));
        }
    }
    READ_PATHS.with(|paths| assert!(paths.replace(Some(Vec::new())).is_none()));
    let _reset = Reset;
    let value = run();
    let paths = READ_PATHS.with(|paths| paths.take().unwrap());
    (value, paths)
}

pub(in crate::snapshots) fn page(
    root: &Path,
    paths: &BTreeSet<String>,
    cache: &Arc<sampled_scan::SharedCache>,
) -> HeaderInventory {
    let sessions = root.join("sessions");
    let mut census = DirectoryCensus::new();
    census.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let mut inventory = HeaderInventory::new(&[sessions], paths, Some(&census));
    while !inventory.step_encoded(&CodexTitleMetadata::default(), Some(cache)) {}
    inventory
}

fn paths(inventory: &HeaderInventory) -> BTreeSet<String> {
    inventory
        .headers
        .iter()
        .map(|header| local_index_key(&header.candidate.path))
        .collect()
}
fn facts(inventory: &HeaderInventory) -> Vec<(String, String, Option<i64>)> {
    inventory
        .headers
        .iter()
        .map(|header| {
            (
                local_index_key(&header.candidate.path),
                header.owner.clone(),
                header.created_unix_ms,
            )
        })
        .collect()
}
#[test]
fn unchanged_pages_reuse_without_reading_and_restart_is_cold() {
    let (root, fixture) = tests::fixture();
    let paths = paths(&fixture);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let first = page(&root, &paths, &cache);
    assert!(first.complete);
    assert_eq!(first.reuse_misses, paths.len());
    assert!(first.read_bytes > 0);
    READ_CALLS.with(|calls| calls.set(0));
    let second = page(&root, &paths, &cache);
    assert!(second.complete);
    assert_eq!(second.reuse_hits, paths.len());
    assert_eq!(second.reuse_misses, 0);
    assert_eq!(second.reuse_evictions, 0);
    assert_eq!(second.read_bytes, 0);
    assert_eq!(second.bytes_avoided, first.read_bytes);
    READ_CALLS.with(|calls| assert_eq!(calls.get(), 0));
    assert_eq!(facts(&first), facts(&second));
    let cold = page(
        &root,
        &paths,
        &Arc::new(sampled_scan::SharedCache::default()),
    );
    assert_eq!(facts(&cold), facts(&second));
    assert_eq!(cold.read_bytes, first.read_bytes);
    READ_CALLS.with(|calls| assert_eq!(calls.get(), paths.len()));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn growth_and_replacement_refresh_once_failures_never_become_hits() {
    let (root, fixture) = tests::fixture();
    let paths = paths(&fixture);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    page(&root, &paths, &cache);
    let path = Path::new(paths.first().unwrap());
    let original = fs::read(path).unwrap();
    let mut grown = original.clone();
    grown.extend_from_slice(b"{}\n");
    fs::write(path, &grown).unwrap();
    READ_CALLS.with(|calls| calls.set(0));
    let growth = page(&root, &paths, &cache);
    assert_eq!(growth.reuse_misses, 1);
    assert_eq!(growth.reuse_hits, 1);
    assert_eq!(growth.reuse_evictions, 1);
    READ_CALLS.with(|calls| assert_eq!(calls.get(), 1));
    assert_eq!(page(&root, &paths, &cache).read_bytes, 0);
    let modified = fs::metadata(path).unwrap().modified().unwrap();
    let replacement = root.join("replacement");
    fs::write(&replacement, &grown).unwrap();
    fs::File::options()
        .write(true)
        .open(&replacement)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    fs::rename(replacement, path).unwrap();
    let replaced = page(&root, &paths, &cache);
    assert_eq!(replaced.reuse_misses, 1, "inode alone invalidates");
    assert_eq!(replaced.reuse_evictions, 1);
    assert_eq!(page(&root, &paths, &cache).read_bytes, 0);
    fs::write(path, b"{incomplete").unwrap();
    for attempt in 0..2 {
        let refused = page(&root, &paths, &cache);
        assert!(!refused.complete);
        assert_eq!(refused.refused.len(), 1);
        assert_eq!(refused.reuse_misses, 1);
        assert_eq!(refused.reuse_hits, 1);
        assert_eq!(refused.reuse_evictions, usize::from(attempt == 0));
        assert!(cache
            .with_cursor(|cursor| cursor.headers.get(paths.first().unwrap()))
            .unwrap()
            .is_none());
    }
    fs::write(path, original).unwrap();
    assert_eq!(page(&root, &paths, &cache).reuse_misses, 1);
    assert_eq!(page(&root, &paths, &cache).read_bytes, 0);
    fs::remove_file(path).unwrap();
    let missing = page(&root, &paths, &cache);
    assert!(!missing.complete, "unreadable is not a hit");
    assert_eq!(missing.reuse_evictions, 1);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn byte_admission_refuses_optional_facts_and_clear_releases_them() {
    let (root, fixture) = tests::fixture();
    let paths = paths(&fixture);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let refused =
        sampled_scan::codex_cursor::with_test_state_budget(0, || page(&root, &paths, &cache));
    assert!(
        refused.complete,
        "cache refusal never refuses the inventory"
    );
    assert_eq!(facts(&refused), facts(&fixture));
    assert!(cache
        .with_cursor(|cursor| cursor.headers.is_empty())
        .unwrap());
    let populated = page(&root, &paths, &cache);
    assert_eq!(populated.reuse_misses, paths.len());
    assert_eq!(page(&root, &paths, &cache).read_bytes, 0);
    cache.with_cursor(|cursor| cursor.headers.clear());
    assert!(cache
        .with_cursor(|cursor| cursor.headers.is_empty())
        .unwrap());
    READ_CALLS.with(|calls| calls.set(0));
    let cleared = page(&root, &paths, &cache);
    assert_eq!(cleared.reuse_misses, paths.len());
    assert_eq!(cleared.reuse_evictions, paths.len());
    READ_CALLS.with(|calls| assert_eq!(calls.get(), paths.len()));
    fs::remove_dir_all(root).unwrap();
}
/// [regress] A mandatory decoder claim that cannot fit beside the header
/// facts in the shared state budget no longer clears them: the next
/// unchanged archive walk reads 0 header bytes and opens no decoder, with
/// the facts of a cold read. A replaced archive is read again, alone.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs validated heap layout"
)]
fn unchanged_archives_reuse_header_facts_after_decoder_pressure() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    let (root, fixture) = tests::fixture();
    let archives = paths(&fixture)
        .into_iter()
        .map(|plain| {
            let plain = PathBuf::from(plain);
            let archive = plain.with_extension("jsonl.zst");
            let bytes = zstd::stream::encode_all(&fs::read(&plain).unwrap()[..], 1).unwrap();
            fs::write(&archive, bytes).unwrap();
            fs::remove_file(&plain).unwrap();
            local_index_key(&archive)
        })
        .collect::<BTreeSet<_>>();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let first = page(&root, &archives, &cache);
    assert!(first.complete);
    assert_eq!(first.reuse_misses, archives.len());
    assert!(first.read_bytes > 0);
    // Pressure: facts heavy enough that no decoder fits beside them.
    cache
        .with_cursor(|cursor| {
            let facts = cursor.headers.get(archives.first().unwrap()).unwrap();
            for number in 0..2 {
                let mut key = format!("pressure-{number}");
                key.reserve_exact(crate::transcript_cache::CACHE_BYTES / 8);
                cursor.headers.refresh(key, Some(facts.clone()));
            }
        })
        .unwrap();
    let other = root.join("other.jsonl.zst");
    fs::write(&other, zstd::stream::encode_all(&b"{}\n"[..], 1).unwrap()).unwrap();
    crate::snapshots::codex_compressed_input::OpenedInput::funded(
        fs::File::open(&other).unwrap(),
        &cache,
    )
    .unwrap()
    .expect("the mandatory decoder is admitted")
    .close();
    READ_CALLS.with(|calls| calls.set(0));
    let second = page(&root, &archives, &cache);
    assert!(second.complete);
    assert_eq!(second.reuse_hits, archives.len());
    assert_eq!(second.reuse_misses, 0);
    assert_eq!(
        second.read_bytes, 0,
        "no header bytes after admission pressure"
    );
    READ_CALLS.with(|calls| assert_eq!(calls.get(), 0, "no decoder opened"));
    let cold = page(
        &root,
        &archives,
        &Arc::new(sampled_scan::SharedCache::default()),
    );
    assert_eq!(facts(&second), facts(&cold));
    assert_eq!(facts(&first), facts(&cold));
    let replaced = PathBuf::from(archives.first().unwrap());
    let replacement = root.join("replacement");
    fs::write(&replacement, fs::read(&replaced).unwrap()).unwrap();
    fs::rename(&replacement, &replaced).unwrap();
    READ_CALLS.with(|calls| calls.set(0));
    let reread = page(&root, &archives, &cache);
    assert_eq!(reread.reuse_misses, 1, "a replaced object reads again");
    assert_eq!(reread.reuse_hits, archives.len() - 1);
    READ_CALLS.with(|calls| assert_eq!(calls.get(), 1));
    assert_eq!(facts(&reread), facts(&cold));
    fs::remove_dir_all(root).unwrap();
}
/// Owners of the lookup-order members: a joined archive with staged
/// durable facts, a plain file whose reduction head holds physical facts,
/// and a joined archive with no head.
const ORDER_OWNERS: [&str; 3] = [
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeee1",
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeee2",
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeee3",
];
const ORDER_NAMES: [&str; 3] = ["a.jsonl.zst", "b.jsonl", "c.jsonl.zst"];
/// The header times; durable facts carry `None` (joined) and 42 (physical).
const ORDER_CREATED: [i64; 3] = [1_790_848_800_000, 1_790_848_860_000, 1_790_848_920_000];
const PHYSICAL_READ_BYTES: u64 = 777;
fn order_paths(root: &Path) -> BTreeSet<String> {
    ORDER_NAMES
        .iter()
        .map(|name| local_index_key(&root.join("sessions").join(name)))
        .collect()
}
/// The three members on a live session: `a` accepted-joined with staged
/// facts and no created time, `b` with a reduction head and physical facts
/// (created 42), `c` accepted-joined with no head.
fn lookup_order_fixture() -> (
    crate::test_scratch::ScratchDir,
    crate::snapshots::StateV2ColdSession,
    ScanIndex,
) {
    lookup_order_fixture_at(None)
}
/// [`lookup_order_fixture`]; with `joined_head`, `a` first commits a
/// reduction head at that revision, as a rollout carry leaves it.
fn lookup_order_fixture_at(
    joined_head: Option<u32>,
) -> (
    crate::test_scratch::ScratchDir,
    crate::snapshots::StateV2ColdSession,
    ScanIndex,
) {
    // State v2 refuses a store under a symlinked or shared ancestor.
    let root = crate::test_scratch::ScratchDir::canonical("codex-header-order");
    let sessions = root.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    for (number, name) in ORDER_NAMES.iter().enumerate() {
        let at = format!("2026-10-01T10:0{number}:00Z");
        let header = json!({"type":"session_meta","timestamp":at,
            "payload":{"id":ORDER_OWNERS[number],"timestamp":at}});
        let line = format!("{header}\n");
        let bytes = if codex_archive_path(Path::new(name)) {
            zstd::stream::encode_all(line.as_bytes(), 1).unwrap()
        } else {
            line.into_bytes()
        };
        fs::write(sessions.join(name), bytes).unwrap();
    }
    let paths = order_paths(&root);
    let keys = paths.iter().cloned().collect::<Vec<_>>();
    let native = page(
        &root,
        &paths,
        &Arc::new(sampled_scan::SharedCache::default()),
    );
    let native_facts = (0..3)
        .map(|n| {
            (
                keys[n].clone(),
                ORDER_OWNERS[n].to_owned(),
                Some(ORDER_CREATED[n]),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(facts(&native), native_facts);
    let state = root.join("state");
    crate::test_scratch::create_private_dir(&state).unwrap();
    let (session, mut index) = crate::snapshots::StateV2ColdSession::publish(
        crate::snapshots::scan_index_persistence::Source::Codex,
        &ScanIndex::default(),
        &state,
    );
    accept_order(&mut index, &keys);
    if let Some(revision) = joined_head {
        let route = state_v2::runtime_path(&index).unwrap().unwrap();
        let staged = state_v2::StagedFile {
            revision,
            head: b"head".to_vec(),
            ..Default::default()
        };
        state_v2::stage_tail(&route, &keys[0], staged).unwrap();
        index = session.save_reload(&mut index);
        accept_order(&mut index, &keys);
    }
    stage_independent_inventory(
        &index,
        &[native.headers[0].candidate.clone()],
        ORDER_OWNERS[0],
    )
    .unwrap();
    stage_physical(&root, &index, 42, true);
    let mut index = session.save_reload(&mut index);
    accept_order(&mut index, &keys);
    let head = |n: usize| state_v2::load_head(&index, &keys[n], u32::MAX).unwrap();
    let joined = head(0).unwrap();
    assert_eq!(joined.metadata_only, joined_head.is_none());
    assert_eq!(joined.revision, joined_head.unwrap_or(joined.revision));
    assert_eq!(joined.common.inventory.unwrap().created_unix_ms, None);
    let physical = head(1).unwrap();
    assert!(!physical.metadata_only);
    assert_eq!(physical.common.inventory.unwrap().created_unix_ms, Some(42));
    assert!(head(2).is_none());
    (root, session, index)
}
/// The scan graph's accepted joined members `a` and `c`, and plain `b`.
fn accept_order(index: &mut ScanIndex, keys: &[String]) {
    for n in [0, 2] {
        let fingerprint = format!("{n}").repeat(64);
        index.files.insert(
            keys[n].clone(),
            ScanIndexEntry {
                last_snapshot_fingerprint: Some(fingerprint.clone()),
                codex_joined_member_set: Some("joined".into()),
                codex_counting_owner: Some(codex_protected_owner(ORDER_OWNERS[n]).into()),
                ..Default::default()
            },
        );
        index
            .file_snapshot_fingerprints
            .insert(keys[n].clone(), BTreeSet::from([fingerprint.clone()]));
        index.accepted_snapshot_fingerprints.insert(fingerprint);
    }
    index.files.entry(keys[1].clone()).or_default();
}
/// Stages `b`'s physical header facts (created `created`) for the next
/// commit, with a reduction head when `head`; its file is unchanged.
fn stage_physical(root: &Path, index: &ScanIndex, created: i64, head: bool) {
    let route = state_v2::runtime_path(index).unwrap().unwrap();
    let key = local_index_key(&root.join("sessions").join(ORDER_NAMES[1]));
    let plain = fs::File::open(root.join("sessions").join(ORDER_NAMES[1])).unwrap();
    if head {
        let staged = state_v2::StagedFile {
            revision: 1,
            head: b"head".to_vec(),
            ..Default::default()
        };
        state_v2::stage_tail(&route, &key, staged).unwrap();
    }
    let inventory = state_v2::InventoryFacts {
        owner: ORDER_OWNERS[1].to_owned(),
        created_unix_ms: Some(created),
        stamp: sampled_scan::codex_cursor::OpenStamp::capture(&plain)
            .unwrap()
            .content_stamp(),
        read_bytes: PHYSICAL_READ_BYTES,
    };
    let observation = state_v2::Observation {
        inventory: Some(inventory),
        ..Default::default()
    };
    state_v2::observe_tails(&route, vec![(key, observation)]).unwrap();
}
/// One inventory over the lookup-order members on `index`; the durable
/// head lookups it ran. `fail` fails that 1-based lookup.
fn ordered(
    root: &Path,
    index: &mut ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
    fail: Option<usize>,
) -> (HeaderInventory, usize) {
    let sessions = root.join("sessions");
    let mut census = DirectoryCensus::new();
    census.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let mut inventory = HeaderInventory::new(&[sessions], &order_paths(root), Some(&census));
    state_v2::LOAD_HEAD_CALLS.set((0, fail));
    while !inventory.step_selected(
        &CodexTitleMetadata::default(),
        index,
        &BTreeMap::new(),
        Some(cache),
    ) {}
    let calls = state_v2::LOAD_HEAD_CALLS.get().0;
    state_v2::LOAD_HEAD_CALLS.set((0, None));
    (inventory, calls)
}
/// [regress] Durable header facts keep precedence over the RAM cache and
/// are looked up lazily. A joined-archive hit ran the physical-match head
/// lookup as well (base: 2 lookups for `a`); now 1, so that lookup can no
/// longer fail the member. Each member's facts are the base order's: `a`
/// joined durable (created None even with the header time in RAM), `b`
/// physical durable, `c` RAM after both lookups miss. Any lookup that
/// runs and errors still fails its member. A later inventory on the same
/// cache carries `a`'s and `b`'s durable facts without a lookup.
#[test]
fn joined_archive_hit_runs_one_durable_lookup_and_keeps_durable_facts() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    // `a` also with a head a rollout carry left at the current Codex
    // reduction revision: both common-only reads still load it.
    let current = <tail_source::codex::Codex as tail_source::TailSource>::REDUCTION_REVISION;
    for joined_head in [None, Some(current)] {
        let (root, session, mut index) = lookup_order_fixture_at(joined_head);
        let keys = order_paths(&root).into_iter().collect::<Vec<_>>();
        let expected = vec![
            (keys[0].clone(), ORDER_OWNERS[0].to_owned(), None),
            (keys[1].clone(), ORDER_OWNERS[1].to_owned(), Some(42)),
            (
                keys[2].clone(),
                ORDER_OWNERS[2].to_owned(),
                Some(ORDER_CREATED[2]),
            ),
        ];
        // `a` alone: one joined lookup, no physical lookup.
        let sessions = root.join("sessions");
        let mut census = DirectoryCensus::new();
        census.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut alone = HeaderInventory::new(
            &[sessions],
            &BTreeSet::from([keys[0].clone()]),
            Some(&census),
        );
        state_v2::LOAD_HEAD_CALLS.set((0, None));
        let cold = Arc::new(sampled_scan::SharedCache::default());
        while !alone.step_selected(
            &CodexTitleMetadata::default(),
            &mut index,
            &BTreeMap::new(),
            Some(&cold),
        ) {}
        assert_eq!(state_v2::LOAD_HEAD_CALLS.get().0, 1, "joined hit: 1 lookup");
        assert_eq!(facts(&alone), expected[..1]);
        // All three: `a` carries its durable facts (base: 1 lookup), b 1 + c 2.
        let (first, calls) = ordered(&root, &mut index, &cold, None);
        assert_eq!(calls, 3);
        assert!(first.complete);
        assert_eq!(facts(&first), expected);
        assert_eq!((first.reuse_hits, first.reuse_misses), (2, 1));
        assert!(first.read_bytes > 0, "c is read natively");
        let staged_bytes = MAX_HEADER_BYTES + PHYSICAL_READ_BYTES as usize;
        assert_eq!(first.bytes_avoided, staged_bytes);
        // Warm: only `c` looks up (base: 4); `a` keeps its durable None.
        let (warm, calls) = ordered(&root, &mut index, &cold, None);
        assert_eq!(calls, 2);
        assert_eq!(facts(&warm), expected);
        assert_eq!((warm.reuse_hits, warm.read_bytes), (3, 0));
        assert_eq!(warm.bytes_avoided, staged_bytes + first.read_bytes);
        let counted = cold.counters_for_test();
        assert_eq!(counted.header_durable_lookups, 1 + 3 + 2);
        assert_eq!(counted.header_reuse_hits, 1 + 2 + 3);
        assert_eq!(
            counted.header_bytes_avoided as usize,
            MAX_HEADER_BYTES + staged_bytes + staged_bytes + first.read_bytes
        );
        // A carried member runs no lookup that could fail it: the warm
        // cache's 1st lookup is `c`'s joined lookup.
        let (failed, _) = ordered(&root, &mut index, &cold, Some(1));
        assert_eq!(
            failed.refused.keys().cloned().collect::<Vec<_>>(),
            vec![keys[2].clone()]
        );
        assert_eq!(facts(&failed), expected[..2]);
        // An evaluated lookup's error fails its member as before: `a`'s
        // joined lookup (1st), and `c`'s physical lookup after its joined miss
        // (4th), even with `c`'s facts in RAM.
        for (fail, member) in [(1, 0), (4, 2)] {
            let fresh = Arc::new(sampled_scan::SharedCache::default());
            let (failed, _) = ordered(&root, &mut index, &fresh, Some(fail));
            assert!(!failed.complete, "lookup {fail}");
            assert_eq!(
                failed.refused.keys().cloned().collect::<Vec<_>>(),
                vec![keys[member].clone()],
                "lookup {fail}"
            );
            let survivors = expected
                .iter()
                .filter(|(key, _, _)| *key != keys[member])
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(facts(&failed), survivors, "lookup {fail}");
        }
        drop(session);
        drop(root);
    }
}
/// [regress] Carried durable facts end, per key, with every commit that
/// may change the key's committed head, even on an unchanged file: a
/// finish commit, a debt-only observation, the exit commit, erasure,
/// retirement and a removed progress row. Another cache taking the store's
/// head writes ends them all. Every inventory's facts are a fresh
/// lookup's (the base path's), so `a`'s durable None wins over its header
/// time while carried.
#[test]
fn carried_header_facts_end_with_each_head_write() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    let (root, session, mut index) = lookup_order_fixture();
    let keys = order_paths(&root).into_iter().collect::<Vec<_>>();
    let route = state_v2::runtime_path(&index).unwrap().unwrap();
    let warm = Arc::new(sampled_scan::SharedCache::default());
    // One inventory on the warm cache: (its facts, its lookups).
    let pass = |index: &mut ScanIndex| {
        let (inventory, calls) = ordered(&root, index, &warm, None);
        assert!(inventory.complete);
        (facts(&inventory), calls)
    };
    let mut expected = vec![
        (keys[0].clone(), ORDER_OWNERS[0].to_owned(), None),
        (keys[1].clone(), ORDER_OWNERS[1].to_owned(), Some(42)),
        (
            keys[2].clone(),
            ORDER_OWNERS[2].to_owned(),
            Some(ORDER_CREATED[2]),
        ),
    ];
    // Cold: a 1 + b 1 + c 2. Warm: `c` alone; then again after another
    // cache took the head writes, since any head may have changed.
    assert_eq!(pass(&mut index), (expected.clone(), 4));
    assert_eq!(pass(&mut index), (expected.clone(), 2));
    ordered(&root, &mut index, &Arc::default(), None);
    assert_eq!(pass(&mut index), (expected.clone(), 4));
    assert_eq!(pass(&mut index), (expected.clone(), 2));
    assert_eq!(
        warm.counters_for_test().header_durable_lookups,
        4 + 2 + 4 + 2
    );
    let reload = |index: &mut ScanIndex| {
        let mut next = session.save_reload(index);
        accept_order(&mut next, &keys);
        *index = next;
    };
    // `b`'s new facts on its unchanged file: its finish commit, a
    // debt-only observation, then the exit commit.
    for (created, head) in [(43, true), (44, false)] {
        stage_physical(&root, &index, created, head);
        reload(&mut index);
        expected[1].2 = Some(created);
        assert_eq!(pass(&mut index), (expected.clone(), 1 + 2), "{created}");
        assert_eq!(pass(&mut index), (expected.clone(), 2), "{created}");
    }
    stage_physical(&root, &index, 45, false);
    state_v2::BaselineRelease::new(&route, &index)
        .commit_tail()
        .unwrap();
    let mut index = ScanIndex::load(session.path()).unwrap();
    accept_order(&mut index, &keys);
    expected[1].2 = Some(45);
    assert_eq!(pass(&mut index), (expected.clone(), 1 + 2));
    assert_eq!(pass(&mut index), (expected.clone(), 2));
    // Erased, then (after a new head) retired: `b` reads its header.
    state_v2::erase_tail(&route, &mut index, [keys[1].clone()]).unwrap();
    reload(&mut index);
    expected[1].2 = Some(ORDER_CREATED[1]);
    assert_eq!(pass(&mut index), (expected.clone(), 1 + 2));
    stage_physical(&root, &index, 46, true);
    reload(&mut index);
    expected[1].2 = Some(46);
    assert_eq!(pass(&mut index), (expected.clone(), 1 + 2));
    assert_eq!(pass(&mut index), (expected.clone(), 2));
    state_v2::retire_tail(&route, [keys[1].clone()]).unwrap();
    reload(&mut index);
    expected[1].2 = Some(ORDER_CREATED[1]);
    assert_eq!(pass(&mut index), (expected.clone(), 1 + 2));
    // `a`'s progress row goes: its head retires with it. Re-accepted, it
    // runs both lookups and reads its header time.
    index.files.remove(&keys[0]);
    index.file_snapshot_fingerprints.remove(&keys[0]);
    reload(&mut index);
    assert!(state_v2::load_head(&index, &keys[0], u32::MAX).unwrap().is_none());
    expected[0].2 = Some(ORDER_CREATED[0]);
    assert_eq!(pass(&mut index), (expected.clone(), 2 + 1 + 2));
    drop(session);
    drop(root);
}
#[cfg(unix)]
#[test]
fn ctime_only_reuses_but_nanosecond_mtime_and_symlink_do_not() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (root, fixture) = tests::fixture();
    let paths = paths(&fixture);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    page(&root, &paths, &cache);
    let path = Path::new(paths.first().unwrap());
    let stat = fs::metadata(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    let unchanged = page(&root, &paths, &cache);
    assert_eq!(unchanged.read_bytes, 0);
    // A refreshed ctime witness also avoids validation's fallback read.
    READ_CALLS.with(|calls| calls.set(0));
    tests::validator(unchanged).validate_all().unwrap();
    READ_CALLS.with(|calls| assert_eq!(calls.get(), 0));
    let modified = stat.modified().unwrap() + std::time::Duration::from_nanos(1);
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(page(&root, &paths, &cache).reuse_misses, 1);
    let moved = root.join("moved");
    fs::rename(path, &moved).unwrap();
    symlink(&moved, path).unwrap();
    let refused = page(&root, &paths, &cache);
    assert!(!refused.complete);
    assert_eq!(refused.refused.len(), 1);
    assert_eq!(refused.reuse_hits, 1);
    fs::remove_dir_all(root).unwrap();
}
