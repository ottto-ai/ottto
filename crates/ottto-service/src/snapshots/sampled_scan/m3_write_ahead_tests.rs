//! Substrate regression controls, registered by the integration owner's patch.
use crate::durable_tail_codec::{Enc, Refuse};
use crate::durable_tail_store::{self as store, tests as fixture};
use crate::locked_state_dir::{test_locks, LockedStateDir};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

struct Case {
    root: PathBuf,
    writer: &'static LockedStateDir,
    record: store::PendingRecord,
}
impl Case {
    fn new() -> Self {
        let root = crate::test_scratch::private_dir("m3-write-ahead");
        let writer = test_locks::hold(&root);
        let transcript = root.join("fixture.jsonl");
        fs::write(&transcript, b"{}\n").unwrap();
        let record = fixture::pending(
            fixture::binding("account", "scope", ("fingerprint", None)),
            fixture::certificate(&transcript),
            3,
        );
        assert!(!record.body.is_empty());
        Self {
            root,
            writer,
            record,
        }
    }
    fn store(&self, leaf: &str) -> store::DurableTailStore {
        store::DurableTailStore::new(self.root.join(leaf), store::DurableSource::ClaudeCode)
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// [money] writer sink refuses underflow overflow and propagates io failure.
#[test]
fn writer_sink_refuses_underflow_overflow_and_propagates_io_failure() {
    let mut out = Vec::new();
    let mut writer = Enc::writer(&mut out, 3);
    writer.raw(b"ab").unwrap();
    assert_eq!(writer.finish_written(), Err(Refuse::WriteFailed));
    let mut out = Vec::new();
    let mut writer = Enc::writer(&mut out, 2);
    assert_eq!(writer.raw(b"abc"), Err(Refuse::TooLarge));
    assert!(out.is_empty());
    struct Failed;
    impl Write for Failed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("EIO"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        Enc::writer(&mut Failed, 1).raw(b"x"),
        Err(Refuse::WriteFailed)
    );
}

/// [money] fresh duplicate dirty offers produce one exact completion.
#[test]
fn fresh_duplicate_dirty_offers_produce_one_exact_completion() {
    let case = Case::new();
    let mut store = case.store("duplicate");
    let receipt = store
        .write_after_save(
            case.writer,
            7,
            0,
            vec![case.record.clone(), case.record.clone()],
        )
        .unwrap();
    assert_eq!(receipt.written, 1);
    assert_eq!(receipt.completed.len(), 1);
    assert_eq!(store.counters().records_written, 1);
    let clean = store
        .write_after_save(case.writer, 8, 0, vec![case.record.clone()])
        .unwrap();
    assert!(clean.completed.is_empty());
    assert_eq!(clean.clean, 1);
}

/// [format] failed immediate cleanup is retried by same process gc.
#[test]
fn failed_immediate_cleanup_is_retried_by_same_process_gc() {
    let case = Case::new();
    let mut store = case.store("orphan");
    store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
        Err(io::Error::other("rename EIO"))
    })));
    store::test_hooks::set_before_unlink(Some(Box::new(|_| Err(io::Error::other("unlink EIO")))));
    let result = store.write_after_save(case.writer, 7, 0, vec![case.record.clone()]);
    store::test_hooks::set_before_rename(None);
    store::test_hooks::set_before_unlink(None);
    result.unwrap();
    let temps = || {
        fs::read_dir(case.root.join("orphan"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "tmp"))
            .count()
    };
    assert_eq!(temps(), 1, "both cleanup attempts were refused");
    assert!(store.counters().temp_discard_failed >= 2);
    assert_eq!(store.counters().store_write_cleanup_failed, 1);
    store
        .gc(
            case.writer,
            &case.record.binding.context,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(temps(), 0);
    assert_eq!(store.counters().gc_temps_deleted, 1);
}
