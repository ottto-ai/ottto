//! Store-layer tests: envelope, crash matrix against real scan-index saves,
//! interrupted replacement, schema both ways, GC, dirty-only bounded batches,
//! the single-writer seam and the content-free certificate. The record body
//! is a placeholder; no accumulator field is encoded here.
use super::*;
use crate::snapshots::ScanIndex;
use crate::transcript_acquisition::{DurableAdmission, FullReason, ReadPlan, Scope};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

/// Real compiled v1 body/allowlist; arbitrary test-only representations are U.
fn placeholder_allowlist() -> Digest32 {
    parse_hex_digest("8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c").unwrap()
}
fn placeholder_body(count: u64, sum: u64) -> Vec<u8> {
    crate::snapshots::durable_store_fixture_body(
        crate::snapshots::SnapshotSource::ClaudeCode,
        count,
        sum,
    )
}

/// #801's real lock: `StateDirLock` on the scratch state directory.
use crate::locked_state_dir::LockedStateDir;
use crate::state_dir_lock::StateDirLockError;

/// Takes the lock after its previous holder was dropped. Dropping #801's
/// lock unlocks it (#812), so the first try normally succeeds; the bounded
/// wait only tolerates a release that is not yet visible.
fn acquire_released(dir: &Path) -> LockedStateDir {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match LockedStateDir::acquire(dir) {
            Ok(lock) => return lock,
            Err(StateDirLockError::Held { .. }) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("released lock still unavailable: {error:?}"),
        }
    }
}

struct Scratch {
    root: PathBuf,
}
impl Scratch {
    fn new() -> Self {
        Self {
            root: crate::test_scratch::private_dir("ottto-durable-tail"),
        }
    }
    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }
    fn store(&self) -> DurableTailStore {
        DurableTailStore::new(
            store_dir_for_index(&self.index_path()),
            DurableSource::ClaudeCode,
        )
    }
    fn transcript(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const NOW: u64 = 1_800_000_000;

fn scope() -> Scope {
    Scope("durable-tail-test-scope".into())
}

/// A real committed checkpoint for `path` (a full read of its sealed rows).
fn checkpoint(path: &Path) -> crate::transcript_acquisition::Checkpoint {
    let mut file = File::open(path).unwrap();
    let mut plan = ReadPlan::prepare(&mut file, None, &scope(), None, NOW).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    if let Some(last) = bytes.iter().rposition(|byte| *byte == b'\n') {
        plan.observe_complete_records(&bytes[..=last]).unwrap();
    }
    plan.commit_after_native_completion(&file, &scope(), NOW)
        .unwrap()
}

fn certificate(path: &Path) -> DurableCertificate {
    let birth = crate::transcript_acquisition::birth_unix_nanos(&fs::metadata(path).unwrap());
    checkpoint(path).durable_certificate(birth).unwrap()
}

const INDEX_KEY: &str = "/Users/canary-user/.claude/projects/canary-workspace/session.jsonl";

fn binding(context: &str, file_scope: &str, entry: (&str, Option<&str>)) -> Binding {
    Binding {
        source: DurableSource::ClaudeCode,
        key: key_digest(DurableSource::ClaudeCode, INDEX_KEY),
        context: context_digest("namespace", Some(context)),
        scope: scope_digest(
            file_scope,
            &placeholder_allowlist(),
            "identity:v1",
            "legacy",
        ),
        entry: entry_digest(entry.0, entry.1),
    }
}

fn pending(binding: Binding, certificate: DurableCertificate, count: u64) -> PendingRecord {
    PendingRecord {
        binding,
        certificate,
        body: placeholder_body(count, count * 7),
        allowlist: placeholder_allowlist(),
    }
}

fn found(outcome: ReadOutcome) -> DurableRecord {
    match outcome {
        ReadOutcome::Found(record) => *record,
        other => panic!("expected a record, got {other:?}"),
    }
}

/// Save the scan index through its real CAS path; the committed generation.
fn save_index(index: &mut ScanIndex, path: &Path) -> u64 {
    index.save(path).expect("save scan index");
    index.generation
}

fn record_file(store: &DurableTailStore, key: &Digest32) -> PathBuf {
    store.dir().join(format!("{}{RECORD_SUFFIX}", hex(key)))
}

/// Put record bytes back as an owner-only file, as the store writes them; a
/// recreated file would otherwise take the umask's 0644 and be refused.
fn put_record(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    std::io::Write::write_all(&mut file, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn envelope_round_trips_and_carries_no_path_or_raw_bytes() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{\"canary\":\"CANARY-HEAD-TEXT\"}\n");
    let mut store = scratch.store();
    let record = pending(
        binding(
            "account-canary@example.com",
            "scope-a",
            ("fp-1", Some("w-1")),
        ),
        certificate(&transcript),
        3,
    );
    let receipt = store
        .write_after_save(&lock, 1, vec![record.clone()])
        .unwrap();
    assert_eq!(receipt.written, 1);
    let key = record.binding.key;
    let bytes = fs::read(record_file(&store, &key)).unwrap();
    for canary in [
        INDEX_KEY.as_bytes(),
        b"canary-user".as_slice(),
        b"canary-workspace".as_slice(),
        b"CANARY-HEAD-TEXT".as_slice(),
        b"account-canary@example.com".as_slice(),
        b"fp-1".as_slice(),
        b"scope-a".as_slice(),
    ] {
        assert!(
            !bytes.windows(canary.len()).any(|window| window == canary),
            "store bytes contain {:?}",
            String::from_utf8_lossy(canary)
        );
    }
    let read = found(store.read(&key, &placeholder_allowlist()));
    assert_eq!(read.record, record);
    assert_eq!(read.index_generation, 1);
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&record_file(&store, &key)), 0o600);
    assert_eq!(mode(store.dir()), 0o700);
}

/// index {old, new} x checkpoint {old, new, torn, missing}, against real
/// scan-index saves. The checkpoint is always written after its save.
#[test]
fn crash_matrix_index_old_new_by_checkpoint_old_new_torn_missing() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let index_path = scratch.index_path();
    let transcript = scratch.transcript("t.jsonl", b"{\"n\":1}\n");
    let mut index = ScanIndex::default();
    let mut store = scratch.store();
    let allowlist = placeholder_allowlist();

    // Save 1 commits entry E1, then its checkpoint is written.
    let g1 = save_index(&mut index, &index_path);
    let old_index_bytes = fs::read(&index_path).unwrap();
    let e1 = binding("acct", "scope", ("fp-1", Some("w-1")));
    store
        .write_after_save(
            &lock,
            g1,
            vec![pending(e1.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let key = e1.key;
    let old_record = fs::read(record_file(&store, &key)).unwrap();

    // The file grows; save 2 commits entry E2, then its checkpoint.
    fs::write(&transcript, b"{\"n\":1}\n{\"n\":2}\n").unwrap();
    let g2 = save_index(&mut index, &index_path);
    assert!(g2 > g1);
    let new_index_bytes = fs::read(&index_path).unwrap();
    let e2 = binding("acct", "scope", ("fp-2", Some("w-2")));
    store
        .write_after_save(
            &lock,
            g2,
            vec![pending(e2.clone(), certificate(&transcript), 2)],
        )
        .unwrap();
    let new_record = fs::read(record_file(&store, &key)).unwrap();

    let torn = |bytes: &[u8]| {
        let mut variants = vec![
            bytes[..bytes.len() / 2].to_vec(),
            bytes[..bytes.len() - 1].to_vec(),
            bytes[..20].to_vec(),
            Vec::new(),
        ];
        let mut flipped = bytes.to_vec();
        let middle = flipped.len() / 2;
        flipped[middle] ^= 0x40;
        variants.push(flipped);
        variants
    };

    for (index_label, index_bytes, entry) in [
        ("old", &old_index_bytes, &e1),
        ("new", &new_index_bytes, &e2),
    ] {
        fs::write(&index_path, index_bytes).unwrap();
        let loaded = ScanIndex::load(&index_path).unwrap();
        let expected = Expected {
            binding: entry.clone(),
            committed_generation: loaded.generation,
        };
        for (checkpoint_label, record_bytes, want) in [
            (
                "old",
                &old_record,
                if index_label == "old" {
                    Ok(())
                } else {
                    Err(Ineligible::EntryChanged)
                },
            ),
            (
                "new",
                &new_record,
                if index_label == "old" {
                    Err(Ineligible::GenerationAhead)
                } else {
                    Ok(())
                },
            ),
        ] {
            put_record(&record_file(&store, &key), record_bytes);
            let record = found(store.read(&key, &allowlist));
            assert_eq!(
                record.eligible(&expected),
                want,
                "index {index_label} x checkpoint {checkpoint_label}"
            );
        }
        for bytes in torn(&new_record) {
            put_record(&record_file(&store, &key), &bytes);
            let expected = if bytes.len() < 171 {
                Refusal::Undecodable
            } else {
                Refusal::Corrupt
            };
            assert_eq!(
                store.read(&key, &allowlist),
                ReadOutcome::Refused(expected),
                "index {index_label} x torn checkpoint ({} bytes)",
                bytes.len()
            );
        }
        fs::remove_file(record_file(&store, &key)).unwrap();
        assert_eq!(
            store.read(&key, &allowlist),
            ReadOutcome::Missing,
            "index {index_label} x missing checkpoint"
        );
    }

    // A later save that did not change the entry leaves the older record
    // valid: generation at or below the committed one, same entry.
    fs::write(&index_path, new_index_bytes).unwrap();
    let mut index = ScanIndex::load(&index_path).unwrap();
    put_record(&record_file(&store, &key), &new_record);
    let g3 = save_index(&mut index, &index_path);
    let record = found(store.read(&key, &allowlist));
    assert_eq!(record.index_generation, g2);
    assert_eq!(
        record.eligible(&Expected {
            binding: e2,
            committed_generation: g3,
        }),
        Ok(())
    );
}

#[test]
fn every_binding_mismatch_refuses() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let base = binding("acct", "scope", ("fp", None));
    store
        .write_after_save(
            &lock,
            4,
            vec![pending(base.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let record = found(store.read(&base.key, &placeholder_allowlist()));
    let check = |mutate: &dyn Fn(&mut Binding)| {
        let mut want = base.clone();
        mutate(&mut want);
        record.eligible(&Expected {
            binding: want,
            committed_generation: 4,
        })
    };
    assert_eq!(check(&|_| {}), Ok(()));
    assert_eq!(
        check(&|b| b.source = DurableSource::Codex),
        Err(Ineligible::Source)
    );
    assert_eq!(
        check(&|b| b.key = key_digest(DurableSource::ClaudeCode, "other")),
        Err(Ineligible::Key)
    );
    assert_eq!(
        check(&|b| b.context = context_digest("namespace", Some("other-account"))),
        Err(Ineligible::Context)
    );
    for scope in [
        scope_digest("scope-2", &placeholder_allowlist(), "identity:v1", "legacy"),
        scope_digest(
            "scope",
            &allowlist_digest(&["other"]),
            "identity:v1",
            "legacy",
        ),
        // Identity contract or counting view alone refuses, even when the
        // file scope does not move.
        scope_digest("scope", &placeholder_allowlist(), "identity:v2", "legacy"),
        scope_digest("scope", &placeholder_allowlist(), "identity:v1", "v2"),
    ] {
        assert_eq!(check(&|b| b.scope = scope), Err(Ineligible::Scope));
    }
    assert_eq!(
        check(&|b| b.entry = entry_digest("fp", Some("w"))),
        Err(Ineligible::EntryChanged)
    );
    assert_eq!(
        record.eligible(&Expected {
            binding: base.clone(),
            committed_generation: 3,
        }),
        Err(Ineligible::GenerationAhead)
    );
}

/// A crash after the temp file is written and synced but before the rename
/// leaves the old record readable and a temp that GC removes.
#[test]
fn interrupted_replacement_temp_present_keeps_the_old_record() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let allowlist = placeholder_allowlist();
    let old = binding("acct", "scope", ("fp-1", None));
    store
        .write_after_save(
            &lock,
            1,
            vec![pending(old.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    test_hooks::set_before_rename(Some(Box::new(|_: &Path, _: &Path| -> io::Result<()> {
        panic!("crash before rename")
    })));
    let new = binding("acct", "scope", ("fp-2", None));
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.write_after_save(
            &lock,
            2,
            vec![pending(new.clone(), certificate(&transcript), 2)],
        )
    }));
    test_hooks::set_before_rename(None);
    assert!(crashed.is_err());
    let temps = fs::read_dir(store.dir())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(TEMP_SUFFIX))
        .count();
    assert_eq!(temps, 1, "the synced temp is left behind");
    let record = found(store.read(&old.key, &allowlist));
    assert_eq!(record.record.binding, old);
    assert_eq!(record.index_generation, 1);
    let mut keep = BTreeMap::new();
    keep.insert(old.key, Some(old.scope));
    store.gc(&lock, &old.context, &allowlist, &keep).unwrap();
    assert_eq!(store.counters().gc_temps_deleted, 1);
    assert_eq!(found(store.read(&old.key, &allowlist)).record.binding, old);
}

/// A crash after the rename but before the directory fsync may surface
/// either the new record or, after power loss, the old one. Both are whole
/// records that bind or refuse on their own; neither mixes.
#[test]
fn interrupted_replacement_renamed_but_directory_not_synced() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let allowlist = placeholder_allowlist();
    let old = binding("acct", "scope", ("fp-1", None));
    store
        .write_after_save(
            &lock,
            1,
            vec![pending(old.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let old_bytes = fs::read(record_file(&store, &old.key)).unwrap();
    test_hooks::set_before_dir_sync(Some(Box::new(|_: &Path| -> io::Result<()> {
        panic!("crash before dir fsync")
    })));
    let new = binding("acct", "scope", ("fp-2", None));
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.write_after_save(
            &lock,
            2,
            vec![pending(new.clone(), certificate(&transcript), 2)],
        )
    }));
    test_hooks::set_before_dir_sync(None);
    assert!(crashed.is_err());
    let committed = Expected {
        binding: new.clone(),
        committed_generation: 2,
    };
    // The rename survived.
    let survived = found(store.read(&new.key, &allowlist));
    assert_eq!(survived.record.binding, new);
    assert_eq!(survived.eligible(&committed), Ok(()));
    // The rename was lost with the directory entry: the old record is back.
    put_record(&record_file(&store, &new.key), &old_bytes);
    let reverted = found(store.read(&new.key, &allowlist));
    assert_eq!(reverted.index_generation, 1);
    assert_eq!(reverted.eligible(&committed), Err(Ineligible::EntryChanged));
}

fn set_version(bytes: &mut [u8], version: u16) {
    bytes[8..10].copy_from_slice(&version.to_le_bytes());
    let end = bytes.len() - TRAILER_BYTES;
    let trailer: Digest32 = Sha256::digest(&bytes[..end]).into();
    bytes[end..].copy_from_slice(&trailer);
}

/// Schema both ways: a newer store is refused and kept (downgrade ignores);
/// an older store or another field allowlist is refused and dropped.
#[test]
fn schema_both_ways_and_downgrade() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let allowlist = placeholder_allowlist();
    let newer = binding("acct", "scope", ("fp-newer", None));
    let mut other = newer.clone();
    other.key = key_digest(DurableSource::ClaudeCode, "older");
    let mut third = newer.clone();
    third.key = key_digest(DurableSource::ClaudeCode, "allowlist");
    store
        .write_after_save(
            &lock,
            1,
            vec![
                pending(newer.clone(), certificate(&transcript), 1),
                pending(other.clone(), certificate(&transcript), 2),
                pending(third.clone(), certificate(&transcript), 3),
            ],
        )
        .unwrap();
    for (binding, version) in [(&newer, FORMAT_VERSION + 1), (&other, FORMAT_VERSION - 1)] {
        let path = record_file(&store, &binding.key);
        let mut bytes = fs::read(&path).unwrap();
        set_version(&mut bytes, version);
        put_record(&path, &bytes);
    }
    assert_eq!(
        store.read(&newer.key, &allowlist),
        ReadOutcome::Refused(Refusal::NewerFormat)
    );
    assert_eq!(
        store.read(&other.key, &allowlist),
        ReadOutcome::Refused(Refusal::Unknown)
    );
    let changed = allowlist_digest(&["placeholder.count", "placeholder.sum", "placeholder.new"]);
    let path = record_file(&store, &third.key);
    let mut unknown = fs::read(&path).unwrap();
    unknown[10..42].copy_from_slice(&changed);
    put_record(&path, &unknown);
    assert_eq!(
        store.read(&third.key, &changed),
        ReadOutcome::Refused(Refusal::Unknown)
    );
    let keep = [&newer, &other, &third]
        .into_iter()
        .map(|binding| (binding.key, Some(binding.scope)))
        .collect::<BTreeMap<_, _>>();
    store.gc(&lock, &newer.context, &changed, &keep).unwrap();
    assert!(
        record_file(&store, &newer.key).exists(),
        "a newer store is kept"
    );
    assert!(
        record_file(&store, &other.key).exists(),
        "an unknown older representation is preserved"
    );
    assert!(
        record_file(&store, &third.key).exists(),
        "an unknown allowlist is preserved"
    );
    let counters = store.counters();
    assert!(counters.format_hold[Refusal::NewerFormat as usize] >= 1);
    assert!(counters.format_hold[Refusal::Unknown as usize] >= 2);
    assert_eq!(counters.gc_records_deleted, 0);
}

/// Concurrent writer: a second holder cannot take #801's state-directory
/// lock, so it never holds a writer; a writer for another directory is
/// refused before any file is created.
#[test]
fn concurrent_writer_is_refused_through_the_single_writer_seam() {
    let scratch = Scratch::new();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let first = LockedStateDir::acquire(&scratch.root).unwrap();
    assert!(matches!(
        LockedStateDir::acquire(&scratch.root),
        Err(StateDirLockError::Held { .. })
    ));
    let elsewhere = Scratch::new();
    let foreign = LockedStateDir::acquire(&elsewhere.root).unwrap();
    let mut store = scratch.store();
    let record = pending(
        binding("acct", "scope", ("fp", None)),
        certificate(&transcript),
        1,
    );
    let refused = store
        .write_after_save(&foreign, 1, vec![record.clone()])
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
    assert!(!store.dir().exists(), "a refused writer creates nothing");
    assert!(store
        .gc(
            &foreign,
            &record.binding.context,
            &placeholder_allowlist(),
            &BTreeMap::new()
        )
        .is_err());
    drop(first);
    let second = acquire_released(&scratch.root);
    assert_eq!(
        store
            .write_after_save(&second, 1, vec![record])
            .unwrap()
            .written,
        1
    );
}

/// Write amplification: only dirty records are written, at most MAX_BATCH
/// per save, and an unchanged entry is never rewritten on a later save.
#[test]
fn only_dirty_records_are_written_in_bounded_batches() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{\"n\":1}\n");
    let certificate = certificate(&transcript);
    let mut store = scratch.store();
    let records = |changed: Option<usize>| {
        (0..40usize)
            .map(|n| {
                let mut b = binding("acct", "scope", ("fp", None));
                b.key = key_digest(DurableSource::ClaudeCode, &format!("key-{n}"));
                let count = if changed == Some(n) { 99 } else { n as u64 };
                pending(b, certificate.clone(), count)
            })
            .collect::<Vec<_>>()
    };
    let first = store.write_after_save(&lock, 1, records(None)).unwrap();
    assert_eq!(
        (first.written, first.clean, first.deferred),
        (MAX_BATCH, 0, 8)
    );
    let second = store.write_after_save(&lock, 2, records(None)).unwrap();
    assert_eq!((second.written, second.clean, second.deferred), (8, 32, 0));
    let third = store.write_after_save(&lock, 3, records(None)).unwrap();
    assert_eq!(
        (third.written, third.clean, third.bytes_written),
        (0, 40, 0)
    );
    let fourth = store.write_after_save(&lock, 4, records(Some(7))).unwrap();
    assert_eq!((fourth.written, fourth.clean), (1, 39));
    let per_record = fourth.bytes_written;
    assert_eq!(
        per_record as usize,
        HEADER_BYTES + placeholder_body(99, 99 * 7).len() + TRAILER_BYTES
    );
    let counters = store.counters();
    assert_eq!(counters.disk_records, 40);
    // Real varint bodies: each record's size follows its own counts.
    let disk_bytes = (0..40u64)
        .map(|n| if n == 7 { 99 } else { n })
        .map(|count| HEADER_BYTES + placeholder_body(count, count * 7).len() + TRAILER_BYTES)
        .sum::<usize>();
    assert_eq!(counters.disk_bytes, disk_bytes as u64);
    // Restart: a fresh store adopts what it reads, so the next save of the
    // same entries rewrites nothing.
    let mut restarted = scratch.store();
    for record in records(Some(7)) {
        found(restarted.read(&record.binding.key, &placeholder_allowlist()));
    }
    let after = restarted
        .write_after_save(&lock, 5, records(Some(7)))
        .unwrap();
    assert_eq!((after.written, after.bytes_written), (0, 0));
}

#[test]
fn budget_refusal_writes_nothing_and_drops_the_stale_record() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let b = binding("acct", "scope", ("fp", None));
    store
        .write_after_save(
            &lock,
            1,
            vec![pending(b.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let mut big = pending(b.clone(), certificate(&transcript), 2);
    big.body = vec![0; RECORD_BYTES];
    let receipt = store.write_after_save(&lock, 2, vec![big]).unwrap();
    assert_eq!((receipt.written, receipt.budget_refused), (0, 1));
    assert_eq!(
        store.read(&b.key, &placeholder_allowlist()),
        ReadOutcome::Missing
    );
    assert_eq!(store.counters().budget_refused, 1);
    assert_eq!(store.counters().disk_bytes, 0);
}

/// GC on an account or scope change, and on keys the save no longer keeps.
#[test]
fn gc_drops_other_accounts_scopes_and_unkept_keys() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let allowlist = placeholder_allowlist();
    let make = |name: &str| {
        let mut b = binding("acct-a", "scope", ("fp", None));
        b.key = key_digest(DurableSource::ClaudeCode, name);
        b
    };
    let (kept, rescoped, dropped) = (make("kept"), make("rescoped"), make("dropped"));
    let undecided = make("undecided");
    store
        .write_after_save(
            &lock,
            1,
            [&kept, &rescoped, &dropped, &undecided]
                .into_iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let mut keep = BTreeMap::new();
    keep.insert(kept.key, Some(kept.scope));
    keep.insert(
        rescoped.key,
        Some(scope_digest(
            "scope-after-upgrade",
            &allowlist,
            "identity:v1",
            "legacy",
        )),
    );
    // Kept by the index, file not decided this pass: its scope is unknown.
    keep.insert(undecided.key, None);
    store.gc(&lock, &kept.context, &allowlist, &keep).unwrap();
    assert!(record_file(&store, &kept.key).exists());
    assert!(record_file(&store, &undecided.key).exists());
    assert!(!record_file(&store, &rescoped.key).exists());
    assert!(!record_file(&store, &dropped.key).exists());
    // An account switch makes every record unreachable; GC deletes them.
    store
        .gc(
            &lock,
            &context_digest("namespace", Some("acct-b")),
            &allowlist,
            &keep,
        )
        .unwrap();
    assert!(!record_file(&store, &kept.key).exists());
    assert!(!record_file(&store, &undecided.key).exists());
    assert_eq!(store.counters().disk_records, 0);
    store
        .gc(&lock, &[0; 32], &allowlist, &BTreeMap::new())
        .unwrap();
    assert_eq!(fs::read_dir(store.dir()).unwrap().count(), 0);
}

/// F5: GC reads one header per record, never a body. A record whose body
/// alone is damaged still binds by its header, so GC keeps it until a full
/// read refuses (and condemns) it; the next GC deletes it without reading
/// it again.
#[test]
fn gc_verifies_cold_records_and_preserves_corrupt_bodies() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let allowlist = placeholder_allowlist();
    let bindings = (0..4)
        .map(|n| {
            let mut b = binding("acct-a", "scope", ("fp", None));
            b.key = key_digest(DurableSource::ClaudeCode, &format!("key-{n}"));
            b
        })
        .collect::<Vec<_>>();
    store
        .write_after_save(
            &lock,
            1,
            bindings
                .iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let keep = bindings
        .iter()
        .map(|b| (b.key, Some(b.scope)))
        .collect::<BTreeMap<_, _>>();
    let damaged = record_file(&store, &bindings[0].key);
    let mut bytes = fs::read(&damaged).unwrap();
    bytes[HEADER_BYTES] ^= 0xff;
    put_record(&damaged, &bytes);
    let context = bindings[0].context;

    let before = store.counters();
    store.gc(&lock, &context, &allowlist, &keep).unwrap();
    let after = store.counters();
    assert_eq!(after.gc_records_read - before.gc_records_read, 4);
    assert_eq!(
        after.gc_bytes_read - before.gc_bytes_read,
        4 * HEADER_BYTES as u64
    );
    assert_eq!(after.bytes_read, before.bytes_read, "no body read");
    assert!(damaged.exists(), "the header still binds");

    assert!(matches!(
        store.read(&bindings[0].key, &allowlist),
        ReadOutcome::Refused(Refusal::Corrupt)
    ));
    store.gc(&lock, &context, &allowlist, &keep).unwrap();
    let last = store.counters();
    assert!(damaged.exists(), "T14 is kept until a rebuild replaces it");
    assert_eq!(last.gc_records_read - after.gc_records_read, 4);
    assert_eq!(last.disk_records, 4);
    for b in &bindings[1..] {
        found(store.read(&b.key, &allowlist));
    }
    println!(
        "dt_gc_header_receipt: records=4 gc_records_read={} gc_bytes_read={} \
         header_bytes={HEADER_BYTES} record_bytes={} peak_codec_bytes={}",
        after.gc_records_read - before.gc_records_read,
        after.gc_bytes_read - before.gc_bytes_read,
        bytes.len(),
        last.peak_codec_bytes,
    );
}

/// F2: invalidating held or reverted selections deletes exactly their
/// records; a later read of them is Missing.
#[test]
fn remove_keys_deletes_only_the_invalidated_records() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let allowlist = placeholder_allowlist();
    let bindings = (0..3)
        .map(|n| {
            let mut b = binding("acct-a", "scope", ("fp", None));
            b.key = key_digest(DurableSource::ClaudeCode, &format!("key-{n}"));
            b
        })
        .collect::<Vec<_>>();
    store
        .write_after_save(
            &lock,
            1,
            bindings
                .iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let held = std::collections::BTreeSet::from([
        bindings[1].key,
        key_digest(DurableSource::ClaudeCode, "never-written"),
    ]);
    assert_eq!(store.remove_keys(&lock, &held).unwrap(), 1);
    assert_eq!(store.counters().records_invalidated, 1);
    assert_eq!(store.counters().disk_records, 2);
    assert!(matches!(
        store.read(&bindings[1].key, &allowlist),
        ReadOutcome::Missing
    ));
    found(store.read(&bindings[0].key, &allowlist));
    found(store.read(&bindings[2].key, &allowlist));
    assert_eq!(store.remove_keys(&lock, &held).unwrap(), 0);
}

/// C1: owner-only mode faults on our own store are store-level and repaired
/// in place (directory 0700, records 0600); nothing is rebuilt or held.
#[test]
fn store_mode_faults_are_repaired_without_rebuilds() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let bindings = ["open", "closed"].map(|name| {
        let mut b = binding("acct", "scope", ("fp", None));
        b.key = key_digest(DurableSource::ClaudeCode, name);
        b
    });
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            bindings
                .iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let paths = bindings.each_ref().map(|b| record_file(&store, &b.key));
    let bytes = paths.each_ref().map(|path| fs::read(path).unwrap());
    fs::set_permissions(&paths[0], fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&paths[1], fs::Permissions::from_mode(0o000)).unwrap();
    fs::set_permissions(store.dir(), fs::Permissions::from_mode(0o755)).unwrap();
    let mut cold = scratch.store();
    for b in &bindings {
        assert_eq!(cold.hold(&b.key), None);
        found(cold.read(&b.key, &placeholder_allowlist()));
    }
    assert_eq!(mode(cold.dir()), 0o700);
    for (path, bytes) in paths.iter().zip(&bytes) {
        assert_eq!(mode(path), 0o600);
        assert_eq!(&fs::read(path).unwrap(), bytes);
    }
    let counters = cold.counters();
    assert_eq!(counters.mode_repaired, 3);
    assert_eq!(counters.t14_rebuild, 0);
    assert_eq!(counters.format_hold, [0; 5]);
    assert_eq!(cold.disabled(), None);
}

/// Restores the store's own uid on drop.
struct ForeignUid;
impl ForeignUid {
    fn set() -> Self {
        // SAFETY: geteuid has no preconditions.
        test_hooks::set_uid(Some(unsafe { libc::geteuid() }.wrapping_add(1)));
        Self
    }
}
impl Drop for ForeignUid {
    fn drop(&mut self) {
        test_hooks::set_uid(None);
    }
}

/// C1: a store this process does not own (here a record, after the directory
/// passed) is disabled for the process (memory-only, pre-#806): no hold, no
/// rebuild, no restore, no mutation.
#[test]
fn foreign_owner_disables_the_store_without_rebuilds() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let bindings = ["valid", "corrupt", "newer"].map(|name| {
        let mut b = binding("acct", "scope", ("fp", None));
        b.key = key_digest(DurableSource::ClaudeCode, name);
        b
    });
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            bindings
                .iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let paths = bindings.each_ref().map(|b| record_file(&store, &b.key));
    let mut corrupt = fs::read(&paths[1]).unwrap();
    let end = corrupt.len() - 1;
    corrupt[end] ^= 1;
    put_record(&paths[1], &corrupt);
    let mut newer = fs::read(&paths[2]).unwrap();
    set_version(&mut newer, 2);
    put_record(&paths[2], &newer);
    let before = paths.each_ref().map(|path| fs::read(path).unwrap());
    // The directory passes its check; then a foreign-owned record with a
    // newer header is store-level, not a hold.
    let mut cold = scratch.store();
    assert_eq!(cold.hold(&bindings[0].key), None);
    let _foreign = ForeignUid::set();
    assert_eq!(cold.hold(&bindings[2].key), None);
    assert_eq!(cold.disabled(), Some("foreign_owner"));
    for b in &bindings {
        assert_eq!(cold.hold(&b.key), None);
        assert_eq!(
            cold.read(&b.key, &placeholder_allowlist()),
            ReadOutcome::Missing
        );
    }
    let receipt = cold
        .write_after_save(
            &lock,
            2,
            bindings
                .iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 2))
                .collect(),
        )
        .unwrap();
    assert_eq!(receipt, BatchReceipt::default());
    cold.gc(&lock, &[0; 32], &placeholder_allowlist(), &BTreeMap::new())
        .unwrap();
    assert_eq!(
        cold.remove_keys(&lock, &bindings.iter().map(|b| b.key).collect())
            .unwrap(),
        0
    );
    assert!(cold.inventory().unwrap().is_empty());
    cold.begin_pass();
    assert_eq!(
        cold.hold(&bindings[2].key),
        None,
        "disabled for the process"
    );
    assert_eq!(cold.disabled(), Some("foreign_owner"));
    let counters = cold.counters();
    assert_eq!((counters.t14_rebuild, counters.mode_repaired), (0, 0));
    assert_eq!(counters.records_written, 0);
    for (path, bytes) in paths.iter().zip(&before) {
        assert_eq!(&fs::read(path).unwrap(), bytes);
    }
}

/// C1: per-record T14 is one counted rebuild (Full, then the post-save
/// overwrite; nothing deleted first). More than max(20, 2%) T14 records in
/// one pass trip the breaker: no more rebuilds, the store is disabled.
#[test]
fn t14_rebuilds_are_counted_and_the_breaker_trips_past_twenty() {
    for corrupt_count in [20_usize, 25] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let transcript = scratch.transcript("t.jsonl", b"{}\n");
        let bindings = (0..100)
            .map(|n| {
                let mut b = binding("acct", "scope", ("fp", None));
                b.key = key_digest(DurableSource::ClaudeCode, &format!("key-{n}"));
                b
            })
            .collect::<Vec<_>>();
        let mut store = scratch.store();
        for chunk in bindings.chunks(MAX_BATCH) {
            store
                .write_after_save(
                    &lock,
                    1,
                    chunk
                        .iter()
                        .map(|b| pending(b.clone(), certificate(&transcript), 1))
                        .collect(),
                )
                .unwrap();
        }
        // Every fourth record is corrupt, interleaved with valid ones.
        let corrupt = (0..corrupt_count).map(|n| n * 4).collect::<BTreeSet<_>>();
        let mut kept = Vec::new();
        for n in &corrupt {
            let path = record_file(&store, &bindings[*n].key);
            let mut bytes = fs::read(&path).unwrap();
            let end = bytes.len() - 1;
            bytes[end] ^= 1;
            put_record(&path, &bytes);
            kept.push((path, bytes));
        }
        let mut cold = scratch.store();
        cold.begin_pass();
        for b in &bindings {
            assert_eq!(cold.hold(&b.key), None, "T14 and valid records never hold");
        }
        // A repeat in the same pass (the restore seam's re-check) counts once.
        assert_eq!(cold.hold(&bindings[0].key), None);
        let tripped = corrupt_count > 20;
        assert_eq!(cold.counters().t14_rebuild, 20);
        assert_eq!(cold.disabled(), tripped.then_some("t14_breaker"));
        for (path, bytes) in &kept {
            assert_eq!(&fs::read(path).unwrap(), bytes, "nothing deleted first");
        }
        // The rebuild post-save write repairs T14 unless the breaker disabled the store.
        for n in &corrupt {
            assert_eq!(cold.full_hold(&bindings[*n].key, true), None);
        }
        let rebuild = corrupt
            .iter()
            .map(|n| pending(bindings[*n].clone(), certificate(&transcript), 2))
            .collect::<Vec<_>>();
        let receipt = cold.write_after_save(&lock, 2, rebuild).unwrap();
        assert_eq!(receipt.written, if tripped { 0 } else { corrupt_count });
        for n in &corrupt {
            let outcome = scratch
                .store()
                .read(&bindings[*n].key, &placeholder_allowlist());
            assert_eq!(matches!(outcome, ReadOutcome::Found(_)), !tripped);
        }
    }
}

fn admits(path: &Path, certificate: &DurableCertificate) -> Result<DurableAdmission, FullReason> {
    let mut file = File::open(path).unwrap();
    let admission = certificate.admits(&mut file);
    file.seek(SeekFrom::Start(0)).unwrap();
    admission
}

/// ctime is not a refusal input; mtime, object, length and samples are.
#[test]
fn certificate_ignores_ctime_and_refuses_content_changes() {
    use std::os::unix::fs::MetadataExt;
    let scratch = Scratch::new();
    let head = vec![b'a'; 5000];
    let mut bytes = head.clone();
    bytes.push(b'\n');
    let path = scratch.transcript("t.jsonl", &bytes);
    let cert = certificate(&path);
    assert_eq!(cert.sealed_offset, bytes.len() as u64);
    assert_eq!(
        admits(&path, &cert),
        Ok(DurableAdmission {
            unchanged: true,
            sample_bytes_read: 2 * crate::transcript_acquisition::SAMPLE_BYTES,
        })
    );

    // Metadata-only touch: mode change moves ctime only. Still restores.
    let ctime = |path: &Path| {
        let metadata = fs::metadata(path).unwrap();
        (metadata.ctime(), metadata.ctime_nsec())
    };
    let before = ctime(&path);
    for _ in 0..200 {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        if ctime(&path) != before {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_ne!(ctime(&path), before, "the mode change moved ctime");
    assert!(admits(&path, &cert).unwrap().unchanged);

    // Append: same object, longer; admitted for a Tail.
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    std::io::Write::write_all(&mut file, b"{\"more\":1}\n").unwrap();
    drop(file);
    assert!(!admits(&path, &cert).unwrap().unchanged);

    // Truncate after the checkpoint.
    let truncated = scratch.transcript("trunc.jsonl", &bytes);
    let cert_t = certificate(&truncated);
    OpenOptions::new()
        .write(true)
        .open(&truncated)
        .unwrap()
        .set_len(10)
        .unwrap();
    assert_eq!(admits(&truncated, &cert_t), Err(FullReason::Shrunk));

    // A touch at the same length moves mtime: a same-size edit.
    let touched = scratch.transcript("touch.jsonl", &bytes);
    let cert_m = certificate(&touched);
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
    File::options()
        .write(true)
        .open(&touched)
        .unwrap()
        .set_modified(later)
        .unwrap();
    assert_eq!(admits(&touched, &cert_m), Err(FullReason::SameSizeEdit));

    // An edit that keeps length and mtime is caught by the head sample.
    let edited = scratch.transcript("edit.jsonl", &bytes);
    let cert_e = certificate(&edited);
    let mtime = fs::metadata(&edited).unwrap().modified().unwrap();
    let mut changed = bytes.clone();
    changed[0] = b'b';
    fs::write(&edited, changed).unwrap();
    File::options()
        .write(true)
        .open(&edited)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert_eq!(admits(&edited, &cert_e), Err(FullReason::HeadChanged));

    // The same at the boundary window.
    let tail_edit = scratch.transcript("boundary.jsonl", &bytes);
    let cert_b = certificate(&tail_edit);
    let mtime = fs::metadata(&tail_edit).unwrap().modified().unwrap();
    let mut changed = bytes.clone();
    let at = changed.len() - 2;
    changed[at] = b'z';
    fs::write(&tail_edit, changed).unwrap();
    File::options()
        .write(true)
        .open(&tail_edit)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert_eq!(
        admits(&tail_edit, &cert_b),
        Err(FullReason::BoundaryChanged)
    );

    // Replace: the same bytes under a new inode.
    let replaced = scratch.transcript("replace.jsonl", &bytes);
    let cert_r = certificate(&replaced);
    let staged = scratch.transcript("staged.jsonl", &bytes);
    fs::rename(staged, &replaced).unwrap();
    assert_eq!(admits(&replaced, &cert_r), Err(FullReason::Replaced));
}

/// SOURCE P2-5: both certificate samples are stored as the
/// `ottto-dt-sample:v1` domain-separated SHA-256 of their window. For a file
/// shorter than one window, the head sample is the whole file, yet neither
/// digest is the file's plain SHA-256, and the envelope holds neither raw
/// bytes nor the plain digest. The envelope's 32-byte digests are exactly the
/// audited `ENVELOPE_H` list.
#[test]
fn certificate_samples_are_domain_separated_digests() {
    use sha2::Digest as _;
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let content = b"{\"canary\":\"CANARY-SMALL-FILE\"}\n";
    let path = scratch.transcript("t.jsonl", content);
    let cert = certificate(&path);
    assert_eq!(u64::from(cert.sample_len), content.len() as u64);
    let plain: Digest32 = sha2::Sha256::digest(content).into();
    let separated: Digest32 = sha2::Sha256::new()
        .chain_update(b"ottto-dt-sample:v1\0")
        .chain_update(content)
        .finalize()
        .into();
    assert_eq!(
        crate::transcript_acquisition::DURABLE_SAMPLE_DOMAIN,
        b"ottto-dt-sample:v1\0"
    );
    assert_eq!(cert.head_sha256, separated);
    assert_eq!(cert.boundary_sha256, separated);
    assert_ne!(cert.head_sha256, plain);
    let mut store = scratch.store();
    let b = binding("acct", "scope", ("fp", None));
    store
        .write_after_save(&lock, 1, vec![pending(b.clone(), cert.clone(), 1)])
        .unwrap();
    let bytes = fs::read(record_file(&store, &b.key)).unwrap();
    assert!(!bytes.windows(plain.len()).any(|window| window == plain));
    assert!(!bytes
        .windows(content.len())
        .any(|window| window == content.as_slice()));
    assert_eq!(
        bytes
            .windows(separated.len())
            .filter(|window| *window == separated)
            .count(),
        2,
        "head and boundary"
    );
    assert!(admits(&path, &cert).unwrap().unchanged);
    // The envelope layout holds exactly the listed digests: allowlist, four
    // binding digests and two samples.
    assert_eq!(ENVELOPE_H.len(), 1 + 4 + 2);
    assert_eq!(
        HEADER_BYTES - CERTIFICATE_BYTES,
        8 + 2 + 32 + 1 + 32 * 4 + 8 + 4
    );
    assert_eq!(
        CERTIFICATE_BYTES,
        8 * 3 + 8 * 2 + 8 + 8 + 4 + 32 * 2 + 8 + 1 + 8
    );
}

/// A certificate survives the envelope byte for byte.
#[test]
fn certificate_survives_the_envelope() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("t.jsonl", b"{\"n\":1}\n");
    let mut cert = certificate(&path);
    cert.audit_debt_unix_seconds = Some(NOW + 60);
    let mut store = scratch.store();
    let b = binding("acct", "scope", ("fp", None));
    store
        .write_after_save(&lock, 1, vec![pending(b.clone(), cert.clone(), 1)])
        .unwrap();
    let read = found(store.read(&b.key, &placeholder_allowlist()));
    assert_eq!(read.record.certificate, cert);
    assert!(admits(&path, &read.record.certificate).unwrap().unchanged);
}

/// Budget receipt for the store layer alone (placeholder body): bytes per
/// record, a full store at the RAM entry count, write amplification of a
/// save with one dirty entry, and per-pass read I/O. Printed for the report.
#[test]
fn store_budget_receipt() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("t.jsonl", b"{\"n\":1}\n");
    let cert = certificate(&path);
    let mut store = scratch.store();
    let records = |dirty: Option<usize>| {
        (0..MAX_RECORDS)
            .map(|n| {
                let mut b = binding("acct", "scope", ("fp", None));
                b.key = key_digest(DurableSource::ClaudeCode, &format!("key-{n}"));
                pending(b, cert.clone(), if dirty == Some(n) { 1 } else { 0 })
            })
            .collect::<Vec<_>>()
    };
    let mut generation = 0;
    let mut saves = 0;
    while store.counters().disk_records < MAX_RECORDS as u64 {
        generation += 1;
        saves += 1;
        store
            .write_after_save(&lock, generation, records(None))
            .unwrap();
    }
    let fill = store.take_pass();
    generation += 1;
    let one_dirty = store
        .write_after_save(&lock, generation, records(Some(3)))
        .unwrap();
    let write_pass = store.take_pass();
    let mut restarted = scratch.store();
    for record in records(Some(3)) {
        found(restarted.read(&record.binding.key, &placeholder_allowlist()));
    }
    let read_pass = restarted.take_pass();
    // A full store's GC: headers only, and one reused header buffer.
    let keep = records(None)
        .into_iter()
        .map(|record| (record.binding.key, Some(record.binding.scope)))
        .collect::<BTreeMap<_, _>>();
    restarted
        .gc(
            &lock,
            &binding("acct", "scope", ("fp", None)).context,
            &placeholder_allowlist(),
            &keep,
        )
        .unwrap();
    let gc_pass = restarted.take_pass();
    let envelope = (HEADER_BYTES + TRAILER_BYTES) as u64;
    println!(
        "dt_store_budget: envelope_bytes_per_record={envelope} placeholder_body_bytes={} \
         records={} disk_bytes_total={} fill_saves={saves} fill_bytes_written={} \
         one_dirty_save_bytes_written={} one_dirty_save_records_written={} \
         one_dirty_save_clean={} restore_pass_bytes_read={} restore_pass_records_read={} \
         gc_records_read={} gc_bytes_read={} gc_body_bytes_read={} gc_peak_codec_bytes={} \
         peak_codec_bytes={}",
        placeholder_body(0, 0).len(),
        write_pass.disk_records,
        write_pass.disk_bytes,
        fill.bytes_written,
        one_dirty.bytes_written,
        one_dirty.written,
        one_dirty.clean,
        read_pass.bytes_read,
        read_pass.records_read,
        gc_pass.gc_records_read,
        gc_pass.gc_bytes_read,
        gc_pass.bytes_read,
        gc_pass.peak_codec_bytes,
        fill.peak_codec_bytes.max(read_pass.peak_codec_bytes),
    );
    assert_eq!(gc_pass.gc_records_read, MAX_RECORDS as u64);
    assert_eq!(gc_pass.gc_bytes_read, (MAX_RECORDS * HEADER_BYTES) as u64);
    assert_eq!(gc_pass.bytes_read, 0);
    assert_eq!(gc_pass.disk_records, MAX_RECORDS as u64);
    assert_eq!(saves, MAX_RECORDS.div_ceil(MAX_BATCH));
    assert_eq!(one_dirty.written, 1);
    assert_eq!(
        one_dirty.bytes_written,
        write_pass.disk_bytes / MAX_RECORDS as u64
    );
    assert_eq!(read_pass.bytes_read, write_pass.disk_bytes);
    assert!(write_pass.disk_bytes <= STORE_BYTES);
}

/// K21/L20/L24: every seam starts with an empty memo, without a preceding read.
/// U is preserved and held. T14 (C1) is preserved by every seam except the
/// rebuild's own overwrite, and is never held: one counted rebuild instead.
#[test]
fn every_mutation_preserves_unknown_and_known_corrupt_predecessors_unprimed() {
    for kind in [
        "unknown",
        "newer",
        "reserved_v2",
        "spent_v2",
        "bad_trailer",
        "bad_body",
        "foreign_source",
        "bad_length",
        "debt_tag",
        "unbindable",
        "undecodable",
        "oversized_newer",
    ] {
        for seam in [
            "read",
            "gc_kept",
            "gc_absent",
            "budget",
            "overwrite",
            "invalidate",
            "fresh",
        ] {
            let scratch = Scratch::new();
            let lock = LockedStateDir::acquire(&scratch.root).unwrap();
            let transcript = scratch.transcript("t.jsonl", b"{}\n");
            let mut store = scratch.store();
            let b = binding("acct", "scope", ("fp", None));
            let old = pending(b.clone(), certificate(&transcript), 1);
            store.write_after_save(&lock, 1, vec![old.clone()]).unwrap();
            let path = record_file(&store, &b.key);
            let mut bytes = fs::read(&path).unwrap();
            let reason = match kind {
                "unknown" => {
                    bytes[10] ^= 1;
                    Refusal::Unknown
                }
                "newer" | "reserved_v2" | "spent_v2" | "oversized_newer" => {
                    set_version(&mut bytes, 2);
                    // Future fields are opaque here; 5a1 must not interpret a mark.
                    if kind == "oversized_newer" {
                        bytes.resize(RECORD_BYTES + HEADER_BYTES + TRAILER_BYTES + 1, 0);
                    }
                    Refusal::NewerFormat
                }
                "unbindable" => {
                    bytes[43] ^= 1;
                    Refusal::Unbindable
                }
                "undecodable" => {
                    bytes.truncate(5);
                    Refusal::Undecodable
                }
                "bad_body" => {
                    bytes[HEADER_BYTES] = 255; // invalid nested source enum, but valid trailer
                    set_version(&mut bytes, 1);
                    Refusal::Corrupt
                }
                "foreign_source" => {
                    // Structurally valid Codex body under a Claude envelope: `decode` refuses it.
                    assert_eq!(bytes[HEADER_BYTES], 1);
                    bytes[HEADER_BYTES] = 0;
                    set_version(&mut bytes, 1);
                    Refusal::Corrupt
                }
                "bad_length" => {
                    bytes[HEADER_BYTES - 4] ^= 1;
                    set_version(&mut bytes, 1);
                    Refusal::Corrupt
                }
                "debt_tag" => {
                    bytes[HEADER_BYTES - 13] = 2;
                    set_version(&mut bytes, 1);
                    Refusal::Corrupt
                }
                _ => {
                    let end = bytes.len() - 1;
                    bytes[end] ^= 1;
                    Refusal::Corrupt
                }
            };
            put_record(&path, &bytes);
            let t14 = reason == Refusal::Corrupt;
            let rebuilt = t14 && seam == "overwrite";
            let mut cold = scratch.store();
            match seam {
                "read" => assert_eq!(
                    cold.read(&b.key, &placeholder_allowlist()),
                    ReadOutcome::Refused(reason)
                ),
                "gc_kept" | "gc_absent" | "fresh" => {
                    let keep = if seam == "gc_kept" {
                        BTreeMap::from([(b.key, Some(b.scope))])
                    } else {
                        BTreeMap::new()
                    };
                    cold.gc(&lock, &b.context, &placeholder_allowlist(), &keep)
                        .unwrap();
                }
                "budget" | "overwrite" => {
                    let mut replacement = pending(b.clone(), certificate(&transcript), 2);
                    if seam == "budget" {
                        replacement.body.resize(RECORD_BYTES, 0);
                    }
                    let receipt = cold.write_after_save(&lock, 2, vec![replacement]).unwrap();
                    assert_eq!(receipt.written, usize::from(rebuilt), "{kind} x {seam}");
                }
                _ => {
                    assert_eq!(
                        cold.remove_keys(&lock, &BTreeSet::from([b.key])).unwrap(),
                        0
                    );
                }
            }
            assert!(cold.counters().format_hold[reason as usize] > 0);
            if rebuilt {
                let record = found(scratch.store().read(&b.key, &placeholder_allowlist()));
                assert_eq!(record.index_generation, 2, "{kind} rebuilt");
                continue;
            }
            assert_eq!(fs::read(&path).unwrap(), bytes, "{kind} x {seam}");
            let held = (!t14).then_some(reason);
            assert_eq!(cold.hold(&b.key), held, "{kind} x {seam}");
            assert_eq!(
                cold.counters().t14_rebuild,
                u64::from(t14),
                "{kind} x {seam}"
            );
            assert_eq!(
                scratch.store().hold(&b.key),
                held,
                "restart {kind} x {seam}"
            );
        }
    }
}

#[test]
fn exact_predecessor_memo_reuses_verification_and_invalidates_on_change() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    scratch
        .store()
        .write_after_save(
            &lock,
            1,
            vec![pending(b.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let mut cold = scratch.store();
    assert_eq!(cold.hold(&b.key), None);
    let verified = cold.counters().guard_verify_bytes;
    assert!(verified > 0);
    assert_eq!(cold.hold(&b.key), None);
    assert_eq!(cold.counters().guard_verify_bytes, verified);
    let path = record_file(&cold, &b.key);
    let mut bytes = fs::read(&path).unwrap();
    let end = bytes.len() - 1;
    bytes[end] ^= 1;
    put_record(&path, &bytes);
    // T14 is not held: one counted rebuild.
    assert_eq!(cold.hold(&b.key), None);
    assert_eq!(cold.counters().t14_rebuild, 1);
    assert!(cold.counters().guard_verify_bytes > verified);
}

#[test]
fn fresh_cleanup_is_bounded_preserves_unsafe_entries_and_only_reaps_dead_writer_temps() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    ensure_private_dir(store.dir()).unwrap();
    let b = binding("acct", "scope", ("fp", None));
    let base = pending(b.clone(), certificate(&transcript), 1);
    // All are U, so directory enumeration order cannot affect the preservation assertion.
    for n in 0..INVENTORY_BOUND + 3 {
        let mut record = base.clone();
        record.binding.key = key_digest(DurableSource::ClaudeCode, &format!("unknown-{n}"));
        let mut bytes = encode(&DurableRecord {
            record: record.clone(),
            index_generation: 1,
        });
        set_version(&mut bytes, 2);
        put_record(&record_file(&store, &record.binding.key), &bytes);
    }
    let link = store.dir().join(format!("{}.rec", hex(&[1; 32])));

    let directory = store.dir().join(format!("{}.rec", hex(&[2; 32])));

    // A group-readable U record: header dispatch precedes the mode repair.
    let unsafe_path = store.dir().join(format!("{}.rec", hex(&[3; 32])));
    let mut unsafe_bytes = encode(&DurableRecord {
        record: base,
        index_generation: 1,
    });
    set_version(&mut unsafe_bytes, 2);
    put_record(&unsafe_path, &unsafe_bytes);
    fs::set_permissions(&unsafe_path, fs::Permissions::from_mode(0o644)).unwrap();
    // pid 1 is always alive and never this writer.
    let live = store.dir().join(format!(".{}.rec.1.tmp", hex(&b.key)));
    let dead = store
        .dir()
        .join(format!(".{}.rec.2147483647.tmp", hex(&b.key)));
    put_record(&live, b"live");
    put_record(&dead, b"dead");
    let unrelated = store.dir().join("unrelated.tmp");
    put_record(&unrelated, b"keep");
    store
        .gc(
            &lock,
            &b.context,
            &placeholder_allowlist(),
            &BTreeMap::new(),
        )
        .unwrap();

    assert!(unsafe_path.exists());
    assert!(live.exists());
    assert!(unrelated.exists());
    assert!(!dead.exists());
    // Records past the bound are untouched but still counted in the level.
    assert_eq!(store.counters().disk_records, INVENTORY_BOUND as u64 + 4);
    assert_eq!(store.counters().uninventoried_records, 4);
    assert_eq!(store.counters().gc_temps_deleted, 1);
    // Non-regular entries are still preserved. ELOOP is an access failure,
    // not bytes claiming an unknown format; it disables without mutation.
    symlink(&transcript, &link).unwrap();
    fs::create_dir(&directory).unwrap();
    assert_eq!(store.hold(&[2; 32]), Some(Refusal::Undecodable));
    assert_eq!(store.hold(&[1; 32]), None);
    assert_eq!(store.disabled(), Some("record_access"));
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert!(directory.is_dir());
}

/// Review F1: kept U records past `INVENTORY_BOUND` never block an existing
/// key's replacement; a new key is a counted deferral, and nothing kept is
/// deleted.
#[test]
fn inventory_overflow_replaces_existing_records_and_defers_new_keys() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let receipt = scratch
        .store()
        .write_after_save(
            &lock,
            1,
            vec![pending(b.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    assert_eq!(receipt.written, 1);
    let store = scratch.store();
    let mut kept = Vec::new();
    // One record past the bound: whether the known record or a kept one is
    // unlisted, promoting the known key must not admit the new key.
    for n in 0..INVENTORY_BOUND {
        let mut record = pending(b.clone(), certificate(&transcript), 1);
        record.binding.key = key_digest(DurableSource::ClaudeCode, &format!("kept-{n}"));
        let mut bytes = encode(&DurableRecord {
            record: record.clone(),
            index_generation: 1,
        });
        set_version(&mut bytes, 2);
        let path = record_file(&store, &record.binding.key);
        put_record(&path, &bytes);
        kept.push((path, bytes));
    }
    // Fresh process: no RAM memo of the known record.
    let mut store = scratch.store();
    let mut new = b.clone();
    new.key = key_digest(DurableSource::ClaudeCode, "new-session");
    new.entry = entry_digest("fp-new", None);
    let mut replaced = b.clone();
    replaced.entry = entry_digest("fp-2", None);
    let receipt = store
        .write_after_save(
            &lock,
            2,
            vec![
                pending(replaced.clone(), certificate(&transcript), 2),
                pending(new.clone(), certificate(&transcript), 3),
            ],
        )
        .unwrap();
    assert_eq!(receipt.written, 1);
    assert_eq!(receipt.budget_refused, 0);
    assert_eq!(receipt.deferred_keys, vec![new.key]);
    let counters = store.counters();
    assert_eq!(counters.store_write_skipped, [0, 1]);
    assert_eq!(counters.disk_records, INVENTORY_BOUND as u64 + 1);
    assert!(!record_file(&store, &new.key).exists());
    let record = found(scratch.store().read(&b.key, &placeholder_allowlist()));
    assert_eq!(record.index_generation, 2);
    assert_eq!(record.record.binding, replaced);
    for (path, bytes) in kept {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

/// Reset thread-local fault seams even if an assertion panics.
struct ResetFaults;
impl Drop for ResetFaults {
    fn drop(&mut self) {
        test_hooks::set_before_access(None);
        test_hooks::set_before_rename(None);
        test_hooks::set_gc_records_first(false);
    }
}

#[test]
fn access_failures_disable_instead_of_holding_and_not_found_stays_absent() {
    for arm in [
        "retry",
        "directory",
        "metadata",
        "fstat",
        "missing",
        "retry_missing",
        "metadata_missing",
    ] {
        let _reset = ResetFaults;
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let transcript = scratch.transcript("t.jsonl", b"{}\n");
        let b = binding("acct", "scope", ("fp", None));
        let mut store = scratch.store();
        store
            .write_after_save(
                &lock,
                1,
                vec![pending(b.clone(), certificate(&transcript), 1)],
            )
            .unwrap();
        let path = record_file(&store, &b.key);
        let before = fs::read(&path).unwrap();
        let record_path = path.clone();
        let store_path = store.dir().to_path_buf();
        let opens = std::rc::Rc::new(std::cell::Cell::new(0));
        let calls = opens.clone();
        if arm == "retry" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        test_hooks::set_before_access(Some(Box::new(move |path, op| {
            let deny = (path == record_path && op == "open")
                || (arm == "directory" && path == store_path && op == "metadata")
                || (arm == "fstat" && op == "fstat");
            if path == record_path && op == "metadata" && arm.starts_with("metadata") {
                return Err(io::Error::from(if arm == "metadata_missing" {
                    io::ErrorKind::NotFound
                } else {
                    io::ErrorKind::PermissionDenied
                }));
            }
            if deny {
                if op == "open" {
                    calls.set(calls.get() + 1);
                }
                let missing = arm == "missing" || (arm == "retry_missing" && calls.get() == 2);
                return Err(io::Error::from(if missing {
                    io::ErrorKind::NotFound
                } else {
                    io::ErrorKind::PermissionDenied
                }));
            }
            Ok(())
        })));
        // fstat must be reached through a successful open.
        if arm == "fstat" {
            test_hooks::set_before_access(Some(Box::new(|_, op| {
                if op == "fstat" {
                    Err(io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(())
                }
            })));
        }
        let mut cold = scratch.store();
        assert_eq!(cold.hold(&b.key), None, "{arm}");
        let missing = arm.ends_with("missing");
        assert_eq!(cold.disabled().is_some(), !missing, "{arm}");
        assert_eq!(cold.counters().format_hold, [0; 5], "{arm}");
        assert_eq!(cold.counters().t14_rebuild, 0, "{arm}");
        if arm == "retry" {
            assert_eq!(opens.get(), 2, "exactly one retry");
            assert_eq!(cold.counters().mode_repaired, 1);
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        if !missing {
            assert_eq!(
                cold.read(&b.key, &placeholder_allowlist()),
                ReadOutcome::Missing
            );
            assert_eq!(
                cold.write_after_save(
                    &lock,
                    2,
                    vec![pending(b.clone(), certificate(&transcript), 2)]
                )
                .unwrap(),
                BatchReceipt::default()
            );
            cold.gc(&lock, &[0; 32], &placeholder_allowlist(), &BTreeMap::new())
                .unwrap();
            cold.begin_pass();
            assert_eq!(cold.hold(&b.key), None);
        }
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "{arm}: no record mutation"
        );
    }
}

#[test]
fn gc_stops_before_orphan_cleanup_when_classification_disables_mid_loop() {
    let _reset = ResetFaults;
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            vec![pending(b.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let record = record_file(&store, &b.key);
    let before = fs::read(&record).unwrap();
    let temp = store.dir().join(format!(
        ".{}.{}.tmp",
        record.file_name().unwrap().to_str().unwrap(),
        std::process::id()
    ));
    fs::write(&temp, b"orphan").unwrap();
    test_hooks::set_gc_records_first(true);
    test_hooks::set_before_access(Some(Box::new(|_, op| {
        if op == "open" {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(())
        }
    })));
    let mut cold = scratch.store();
    assert!(cold.disabled().is_none(), "GC starts enabled");
    cold.gc(&lock, &[0; 32], &placeholder_allowlist(), &BTreeMap::new())
        .unwrap();
    assert_eq!(cold.disabled(), Some("record_access"));
    assert_eq!(
        cold.counters().gc_records_read,
        1,
        "classification ran inside GC"
    );
    assert_eq!(cold.counters().gc_records_deleted, 0);
    assert_eq!(cold.counters().gc_temps_deleted, 0);
    assert_eq!(fs::read(&record).unwrap(), before);
    assert_eq!(fs::read(&temp).unwrap(), b"orphan");
    // Control: this is a recognized orphan, deleted when the store works.
    test_hooks::set_before_access(None);
    scratch
        .store()
        .gc(
            &lock,
            &b.context,
            &placeholder_allowlist(),
            &BTreeMap::from([(b.key, None)]),
        )
        .unwrap();
    assert!(!temp.exists());
}

#[test]
fn rebuilt_t14_replaces_once_or_stays_memory_only_until_restart() {
    for arm in ["success", "write_failure", "budget"] {
        let _reset = ResetFaults;
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let transcript = scratch.transcript("t.jsonl", b"{}\n");
        let b = binding("acct", "scope", ("fp", None));
        let mut store = scratch.store();
        store
            .write_after_save(
                &lock,
                1,
                vec![pending(b.clone(), certificate(&transcript), 1)],
            )
            .unwrap();
        let path = record_file(&store, &b.key);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        put_record(&path, &bytes);
        let mut cold = scratch.store();
        assert_eq!(cold.hold(&b.key), None);
        assert_eq!(
            cold.hold(&b.key),
            None,
            "same acquisition's restore recheck"
        );
        assert_eq!(
            cold.hold(&b.key),
            None,
            "unstarted allowance survives scheduling deferral"
        );
        test_hooks::set_before_rename(Some(Box::new(|_, _| panic!("unstarted replacement"))));
        assert_eq!(
            cold.write_after_save(
                &lock,
                2,
                vec![pending(b.clone(), certificate(&transcript), 2)]
            )
            .unwrap(),
            BatchReceipt::default()
        );
        test_hooks::set_before_rename(None);
        assert_eq!(cold.full_hold(&b.key, true), None);
        assert_eq!(cold.counters().t14_rebuild_full_started, 1);
        assert_eq!(cold.full_hold(&b.key, true), Some(Refusal::Corrupt));
        let mut replacement = pending(b.clone(), certificate(&transcript), 2);
        if arm == "budget" {
            replacement.body.resize(RECORD_BYTES, 0);
        }
        if arm == "write_failure" {
            test_hooks::set_before_rename(Some(Box::new(|_, _| {
                Err(io::Error::other("replacement refused"))
            })));
        }
        let result = cold.write_after_save(&lock, 2, vec![replacement]);
        test_hooks::set_before_rename(None);
        if arm == "success" {
            assert_eq!(result.unwrap().written, 1);
            assert!(!cold.rebuilt.contains_key(&b.key));
            cold.begin_pass();
            assert_eq!(cold.hold(&b.key), None, "healthy after RAM eviction");
            assert_eq!(cold.full_hold(&b.key, true), None);
            assert_eq!(cold.counters().t14_rebuild_full_started, 1);
            let mut restarted = scratch.store();
            assert!(
                matches!(restarted.read(&b.key, &placeholder_allowlist()), ReadOutcome::Found(record) if record.index_generation == 2)
            );
            assert_eq!(restarted.full_hold(&b.key, true), None);
            assert_eq!(restarted.counters().t14_rebuild_full_started, 0);
            assert!(restarted.rebuilt.is_empty(), "restart needs no rebuild");
            continue;
        }
        assert_eq!(result.is_err(), arm == "write_failure");
        assert_eq!(cold.rebuilt.get(&b.key), Some(&Rebuild::NotReplaced));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(cold.counters().t14_rebuild, 1);
        cold.take_pass();
        for _ in 0..3 {
            cold.begin_pass();
            assert_eq!(cold.hold(&b.key), Some(Refusal::Corrupt), "{arm}");
        }
        assert_eq!(cold.counters().t14_rebuild, 0);
        assert_eq!(cold.counters().format_hold[Refusal::Corrupt as usize], 3);
        // A failed replacement cannot reach the writer again.
        test_hooks::set_before_rename(Some(Box::new(|_, _| panic!("second replacement"))));
        cold.write_after_save(
            &lock,
            3,
            vec![pending(b.clone(), certificate(&transcript), 3)],
        )
        .unwrap();
        cold.begin_pass();
        assert_eq!(cold.hold(&b.key), Some(Refusal::Corrupt));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(cold.counters().t14_rebuild, 0);
        assert_eq!(
            scratch.store().hold(&b.key),
            None,
            "restart has its own allowance"
        );
        let mut restarted = scratch.store();
        assert_eq!(restarted.full_hold(&b.key, true), None);
        assert_eq!(restarted.counters().t14_rebuild_full_started, 1);
        assert_eq!(restarted.full_hold(&b.key, true), Some(Refusal::Corrupt));
    }
}

#[test]
fn process_rebuild_history_overflow_disables_without_forgetting_an_attempt() {
    let scratch = Scratch::new();
    let mut store = scratch.store();
    ensure_private_dir(store.dir()).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut records = Vec::new();
    for n in 0..=REBUILT_BOUND {
        let mut b = binding("acct", "scope", ("fp", None));
        b.key = key_digest(DurableSource::ClaudeCode, &format!("corrupt-{n}"));
        let mut bytes = encode(&DurableRecord {
            record: pending(b.clone(), certificate(&transcript), 1),
            index_generation: 1,
        });
        *bytes.last_mut().unwrap() ^= 1;
        let path = record_file(&store, &b.key);
        put_record(&path, &bytes);
        records.push((path, bytes));
        store.begin_pass();
        assert_eq!(store.hold(&b.key), None);
        assert_eq!(store.rebuilt.len(), (n + 1).min(REBUILT_BOUND));
        assert_eq!(
            store.disabled(),
            (n == REBUILT_BOUND).then_some("t14_rebuilt_overflow")
        );
    }
    assert_eq!(store.counters().t14_rebuild, REBUILT_BOUND as u64);
    assert!(store.inventory().unwrap().is_empty());
    for (path, bytes) in records {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn restore_read_access_failure_disables_but_disappearance_is_absence() {
    for arm in ["permission", "metadata", "missing"] {
        let _reset = ResetFaults;
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let transcript = scratch.transcript("t.jsonl", b"{}\n");
        let b = binding("acct", "scope", ("fp", None));
        let mut store = scratch.store();
        store
            .write_after_save(
                &lock,
                1,
                vec![pending(b.clone(), certificate(&transcript), 1)],
            )
            .unwrap();
        let path = record_file(&store, &b.key);
        let before = fs::read(&path).unwrap();
        test_hooks::set_before_access(Some(Box::new(move |_, op| match (arm, op) {
            ("permission", "restore_open") => Err(io::ErrorKind::PermissionDenied.into()),
            ("metadata", "restore_metadata") => Err(io::ErrorKind::Other.into()),
            ("missing", "restore_open") => Err(io::ErrorKind::NotFound.into()),
            _ => Ok(()),
        })));
        let mut cold = scratch.store();
        assert_eq!(
            cold.read(&b.key, &placeholder_allowlist()),
            ReadOutcome::Missing
        );
        assert_eq!(cold.disabled().is_some(), arm != "missing");
        assert_eq!(cold.counters().format_hold, [0; 5]);
        assert_eq!(cold.counters().t14_rebuild, 0);
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn non_format_io_errors_disable_at_every_read_boundary_without_spending_t14() {
    for stage in ["open", "header", "body", "restore_open", "restore_metadata"] {
        for errno in [libc::EIO, libc::EMFILE, libc::ENFILE, libc::EPERM] {
            let _reset = ResetFaults;
            let scratch = Scratch::new();
            let lock = LockedStateDir::acquire(&scratch.root).unwrap();
            let transcript = scratch.transcript("t.jsonl", b"{}\n");
            let b = binding("acct", "scope", ("fp", None));
            let mut store = scratch.store();
            store
                .write_after_save(
                    &lock,
                    1,
                    vec![pending(b.clone(), certificate(&transcript), 1)],
                )
                .unwrap();
            let record = record_file(&store, &b.key);
            let before = fs::read(&record).unwrap();
            test_hooks::set_before_access(Some(Box::new(move |_, op| {
                if op == stage {
                    Err(io::Error::from_raw_os_error(errno))
                } else {
                    Ok(())
                }
            })));
            let mut cold = scratch.store();
            if stage.starts_with("restore") {
                assert_eq!(
                    cold.read(&b.key, &placeholder_allowlist()),
                    ReadOutcome::Missing
                );
            } else {
                assert_eq!(cold.hold(&b.key), None);
            }
            assert!(cold.disabled().is_some(), "{stage}/{errno}");
            assert_eq!(cold.hold(&b.key), None);
            assert_eq!(cold.counters().format_hold, [0; 5]);
            assert_eq!(cold.counters().t14_rebuild, 0);
            assert!(cold.rebuilt.is_empty());
            assert_eq!(fs::read(&record).unwrap(), before);
        }
    }
}

#[test]
fn scheduling_deferral_preserves_t14_allowance_until_full_actually_starts() {
    let scratch = Scratch::new();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    ensure_private_dir(store.dir()).unwrap();
    let mut bytes = encode(&DurableRecord {
        record: pending(b.clone(), certificate(&transcript), 1),
        index_generation: 1,
    });
    *bytes.last_mut().unwrap() ^= 1;
    put_record(&record_file(&store, &b.key), &bytes);
    for _ in 0..3 {
        store.begin_pass();
        assert_eq!(store.hold(&b.key), None);
        assert_eq!(
            store.full_hold(&b.key, false),
            None,
            "plan/defer does not spend"
        );
        assert_eq!(store.counters().t14_rebuild_full_started, 0);
    }
    assert_eq!(store.full_hold(&b.key, true), None);
    assert_eq!(store.counters().t14_rebuild_full_started, 1);
    store.begin_pass();
    assert_eq!(store.hold(&b.key), Some(Refusal::Corrupt));
    assert_eq!(store.full_hold(&b.key, true), Some(Refusal::Corrupt));
    assert_eq!(store.counters().t14_rebuild, 1);
    assert_eq!(fs::read(record_file(&store, &b.key)).unwrap(), bytes);
}

#[test]
fn unoffered_started_rebuild_survives_save_until_its_replacement_is_offered() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            vec![pending(b.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let path = record_file(&store, &b.key);
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    put_record(&path, &bytes);
    assert_eq!(store.full_hold(&b.key, true), None);
    store.write_after_save(&lock, 2, vec![]).unwrap();
    assert_eq!(store.rebuilt.get(&b.key), Some(&Rebuild::Started));
    assert_eq!(
        fs::read(&path).unwrap(),
        bytes,
        "save N never offered this key"
    );
    store.begin_pass();
    assert_eq!(store.full_hold(&b.key, true), Some(Refusal::Corrupt));
    let receipt = store
        .write_after_save(
            &lock,
            3,
            vec![pending(b.clone(), certificate(&transcript), 2)],
        )
        .unwrap();
    assert_eq!(receipt.written, 1);
    assert_eq!(store.hold(&b.key), None);
    assert!(store.rebuilt.is_empty());
    assert_eq!(store.counters().t14_rebuild_full_started, 1);
}
