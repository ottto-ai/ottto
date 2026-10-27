//! Store-layer tests: envelope, crash matrix against real scan-index saves,
//! interrupted replacement, schema both ways, GC, dirty-only bounded batches,
//! the single-writer seam and the content-free certificate. The record body
//! is a placeholder; no accumulator field is encoded here.
use super::*;
use crate::snapshots::ScanIndex;
use crate::transcript_acquisition::{DurableAdmission, FullReason, ReadPlan, Scope};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;

/// The placeholder codec: two numbers, with a compiled field list.
const PLACEHOLDER_FIELDS: &[&str] = &["placeholder.count", "placeholder.sum"];

fn placeholder_allowlist() -> Digest32 {
    allowlist_digest(PLACEHOLDER_FIELDS)
}

fn placeholder_body(count: u64, sum: u64) -> Vec<u8> {
    let mut body = count.to_le_bytes().to_vec();
    body.extend_from_slice(&sum.to_le_bytes());
    body
}

/// Test stand-in for #801's `StateDirLock` (`ottto_core::state_dir_lock`),
/// with the same acquire shape and the same file: an exclusive, non-blocking
/// `flock` on `<support>/ottto-service.lock`. Production implements
/// `SingleWriter` for #801's type once it lands; no lock is added here.
struct StubStateDirLock {
    dir: PathBuf,
    _file: File,
}

#[derive(Debug, PartialEq, Eq)]
enum StubLockError {
    Held,
}

impl StubStateDirLock {
    fn acquire(dir: &Path) -> Result<Self, StubLockError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join("ottto-service.lock"))
            .expect("open lock file");
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(StubLockError::Held);
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            _file: file,
        })
    }
}

impl SingleWriter for StubStateDirLock {
    fn state_dir(&self) -> &Path {
        &self.dir
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
        DurableTailStore::new(store_dir_for_index(&self.index_path()))
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

#[test]
fn envelope_round_trips_and_carries_no_path_or_raw_bytes() {
    let scratch = Scratch::new();
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
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
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
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
            fs::write(record_file(&store, &key), record_bytes).unwrap();
            let record = found(store.read(&key, &allowlist));
            assert_eq!(
                record.eligible(&expected),
                want,
                "index {index_label} x checkpoint {checkpoint_label}"
            );
        }
        for bytes in torn(&new_record) {
            fs::write(record_file(&store, &key), &bytes).unwrap();
            assert_eq!(
                store.read(&key, &allowlist),
                ReadOutcome::Refused(Refusal::Corrupt),
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
    fs::write(&index_path, &new_index_bytes).unwrap();
    let mut index = ScanIndex::load(&index_path).unwrap();
    fs::write(record_file(&store, &key), &new_record).unwrap();
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
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
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
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
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
    keep.insert(old.key, old.scope);
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
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
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
    fs::write(record_file(&store, &new.key), &old_bytes).unwrap();
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
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
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
        fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(
        store.read(&newer.key, &allowlist),
        ReadOutcome::Refused(Refusal::NewerFormat)
    );
    assert_eq!(
        store.read(&other.key, &allowlist),
        ReadOutcome::Refused(Refusal::OlderFormat)
    );
    let changed = allowlist_digest(&["placeholder.count", "placeholder.sum", "placeholder.new"]);
    assert_eq!(
        store.read(&third.key, &changed),
        ReadOutcome::Refused(Refusal::AllowlistChanged)
    );
    let keep = [&newer, &other, &third]
        .into_iter()
        .map(|binding| (binding.key, binding.scope))
        .collect::<BTreeMap<_, _>>();
    store.gc(&lock, &newer.context, &changed, &keep).unwrap();
    assert!(
        record_file(&store, &newer.key).exists(),
        "a newer store is kept"
    );
    assert!(
        !record_file(&store, &other.key).exists(),
        "an older store is dropped"
    );
    assert!(
        !record_file(&store, &third.key).exists(),
        "another allowlist is dropped"
    );
    let counters = store.counters();
    assert_eq!(counters.refused_newer, 1);
    assert_eq!(counters.refused_older, 1);
    assert_eq!(counters.refused_allowlist, 1);
    assert_eq!(counters.gc_records_deleted, 2);
}

/// Concurrent writer: a second holder cannot take #801's state-directory
/// lock, so it never holds a writer; a writer for another directory is
/// refused before any file is created.
#[test]
fn concurrent_writer_is_refused_through_the_single_writer_seam() {
    let scratch = Scratch::new();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let first = StubStateDirLock::acquire(&scratch.root).unwrap();
    assert_eq!(
        StubStateDirLock::acquire(&scratch.root).err(),
        Some(StubLockError::Held)
    );
    let elsewhere = Scratch::new();
    let foreign = StubStateDirLock::acquire(&elsewhere.root).unwrap();
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
    let second = StubStateDirLock::acquire(&scratch.root).unwrap();
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
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{\"n\":1}\n");
    let certificate = certificate(&transcript);
    let mut store = scratch.store();
    let records = |changed: Option<usize>| {
        (0..40usize)
            .map(|n| {
                let mut b = binding("acct", "scope", ("fp", None));
                b.key = key_digest(DurableSource::Codex, &format!("key-{n}"));
                b.source = DurableSource::Codex;
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
        HEADER_BYTES + placeholder_body(0, 0).len() + TRAILER_BYTES
    );
    let counters = store.counters();
    assert_eq!(counters.disk_records, 40);
    assert_eq!(counters.disk_bytes, 40 * per_record);
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
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
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
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let allowlist = placeholder_allowlist();
    let make = |name: &str| {
        let mut b = binding("acct-a", "scope", ("fp", None));
        b.key = key_digest(DurableSource::ClaudeCode, name);
        b
    };
    let (kept, rescoped, dropped) = (make("kept"), make("rescoped"), make("dropped"));
    store
        .write_after_save(
            &lock,
            1,
            [&kept, &rescoped, &dropped]
                .into_iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let mut keep = BTreeMap::new();
    keep.insert(kept.key, kept.scope);
    keep.insert(
        rescoped.key,
        scope_digest("scope-after-upgrade", &allowlist, "identity:v1", "legacy"),
    );
    store.gc(&lock, &kept.context, &allowlist, &keep).unwrap();
    assert!(record_file(&store, &kept.key).exists());
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
    assert_eq!(store.counters().disk_records, 0);
    store.remove_all(&lock).unwrap();
    assert!(!store.dir().exists());
}

#[test]
fn a_record_readable_by_others_is_refused() {
    let scratch = Scratch::new();
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
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
    let path = record_file(&store, &b.key);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        store.read(&b.key, &placeholder_allowlist()),
        ReadOutcome::Refused(Refusal::Unusable)
    );
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
    fs::write(&edited, &changed).unwrap();
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
    fs::write(&tail_edit, &changed).unwrap();
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
    fs::rename(&staged, &replaced).unwrap();
    assert_eq!(admits(&replaced, &cert_r), Err(FullReason::Replaced));
}

/// A certificate survives the envelope byte for byte.
#[test]
fn certificate_survives_the_envelope() {
    let scratch = Scratch::new();
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
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
    let lock = StubStateDirLock::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("t.jsonl", b"{\"n\":1}\n");
    let cert = certificate(&path);
    let mut store = scratch.store();
    let records = |dirty: Option<usize>| {
        (0..MAX_RECORDS)
            .map(|n| {
                let mut b = binding("acct", "scope", ("fp", None));
                b.key = key_digest(DurableSource::Codex, &format!("key-{n}"));
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
    let envelope = (HEADER_BYTES + TRAILER_BYTES) as u64;
    println!(
        "dt_store_budget: envelope_bytes_per_record={envelope} placeholder_body_bytes={} \
         records={} disk_bytes_total={} fill_saves={saves} fill_bytes_written={} \
         one_dirty_save_bytes_written={} one_dirty_save_records_written={} \
         one_dirty_save_clean={} restore_pass_bytes_read={} restore_pass_records_read={} \
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
        fill.peak_codec_bytes.max(read_pass.peak_codec_bytes),
    );
    assert_eq!(saves, MAX_RECORDS.div_ceil(MAX_BATCH));
    assert_eq!(one_dirty.written, 1);
    assert_eq!(
        one_dirty.bytes_written,
        write_pass.disk_bytes / MAX_RECORDS as u64
    );
    assert_eq!(read_pass.bytes_read, write_pass.disk_bytes);
    assert!(write_pass.disk_bytes <= STORE_BYTES);
}
