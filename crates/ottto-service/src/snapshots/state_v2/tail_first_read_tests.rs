//! The first read's import list rows: one commit at a time against a real
//! state-v2 database, as `tail::apply` drives them.
use super::*;

const ANCHOR_MS: u64 = 1_794_484_800_000;

struct Db {
    _scratch: crate::test_scratch::ScratchDir,
    db: sqlite::Sqlite,
}

fn db(name: &str) -> Db {
    let scratch = crate::test_scratch::ScratchDir::canonical(name);
    let db = sqlite::Sqlite::create_import(&scratch.join("index.v2.sqlite.import")).unwrap();
    Db {
        _scratch: scratch,
        db,
    }
}

fn observed(class: Class, bucket: u8, bytes: u64) -> Observed {
    Observed {
        member: Member {
            class,
            bucket,
            bytes,
        },
        debt_gone: false,
    }
}

fn anchor(certify: bool) -> SummaryEdit {
    SummaryEdit {
        anchor_at_ms: Some(ANCHOR_MS),
        certify_at_ms: certify.then_some(ANCHOR_MS),
        ..Default::default()
    }
}

/// One `tail::apply`: every staged member in its own isolated block, then
/// the erasures, then the summary.
fn commit(
    tx: &mut dyn Transaction,
    edit: Option<SummaryEdit>,
    members: &[(&[u8], Observed)],
    erased: &[&[u8]],
) {
    let mut generation = Commit::begin(tx, edit.as_ref());
    if generation.open() {
        for (file, observed) in members {
            let counts = generation.write(tx, file, *observed).unwrap();
            generation.committed(counts);
        }
    }
    for file in erased {
        generation.erased(tx, file).unwrap();
    }
    generation.finish(tx, edit.as_ref()).unwrap();
}

fn summary(tx: &mut dyn Transaction) -> Summary {
    read_summary(tx).unwrap().expect("summary")
}

#[test]
fn member_and_summary_codecs_round_trip() {
    for class in [
        Class::Owed,
        Class::Held,
        Class::Failed,
        Class::ExcludedPolicy,
        Class::ExcludedDeleted,
        Class::Done,
    ] {
        let member = Member {
            class,
            bucket: 3,
            bytes: u64::MAX - 1,
        };
        assert_eq!(Member::decode(&member.encode()), Some(member));
    }
    assert_eq!(Member::decode(&[2, 1, 0]), None);
    let mut counts = Counts::default();
    counts.replace(None, observed(Class::Held, 4, 9).member);
    let summary = Summary {
        anchor_at_ms: ANCHOR_MS,
        certified_at_ms: Some(ANCHOR_MS + 1),
        counts,
        sources_enabled: 0b101,
        done_at_ms: Some(ANCHOR_MS + 2),
    };
    assert_eq!(Summary::decode(&summary.encode()), Some(summary));
}

/// The commit that creates the generation never freezes it, even when
/// its own page saw every member done and the walk certified; the next
/// commit can. An empty inventory is the one exception.
#[test]
fn creating_commit_never_freezes_except_an_empty_inventory() {
    let mut store = db("first-read-creating");
    let mut tx = store.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(anchor(true)),
        &[(b"/h/a.jsonl", observed(Class::Done, 2, 10))],
        &[],
    );
    let created = summary(&mut tx);
    assert!(created.open(), "the creating commit froze");
    assert_eq!(created.counts.members, 1);
    assert!(read_member(&mut tx, b"/h/a.jsonl").unwrap().is_some());

    commit(&mut tx, None, &[], &[]);
    let frozen = summary(&mut tx);
    assert!(frozen.done_at_ms.is_some());
    assert_eq!(frozen.counts.done, 1);
    assert!(read_member(&mut tx, b"/h/a.jsonl").unwrap().is_none());

    let mut empty = db("first-read-empty");
    let mut tx = empty.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(SummaryEdit {
            empty_inventory: true,
            ..anchor(true)
        }),
        &[],
        &[],
    );
    let frozen = summary(&mut tx);
    assert!(frozen.done_at_ms.is_some());
    assert_eq!(frozen.counts, Counts::default());
}

/// A new member whose isolated block rolled back is written failed
/// outside it, and that commit cannot freeze.
#[test]
fn rolled_back_new_member_is_failed_and_blocks_the_freeze() {
    let mut store = db("first-read-rolled-back");
    let mut tx = store.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(anchor(true)),
        &[(b"/h/a.jsonl", observed(Class::Done, 0, 10))],
        &[],
    );
    let mut generation = Commit::begin(&mut tx, None);
    generation
        .rolled_back(&mut tx, b"/h/b.jsonl", Some(observed(Class::Done, 1, 20)))
        .unwrap();
    generation.finish(&mut tx, None).unwrap();
    let after = summary(&mut tx);
    assert!(after.open(), "a rollback commit froze");
    assert_eq!(after.counts.members, 2);
    assert_eq!(after.counts.failed, 1);
    assert_eq!(
        read_member(&mut tx, b"/h/b.jsonl").unwrap().unwrap().class,
        Class::Failed
    );
    // The next listing reclassifies it; only then can it freeze.
    commit(
        &mut tx,
        None,
        &[(b"/h/b.jsonl", observed(Class::Done, 1, 20))],
        &[],
    );
    let frozen = summary(&mut tx);
    assert!(frozen.done_at_ms.is_some());
    assert_eq!((frozen.counts.members, frozen.counts.done), (2, 2));
}

/// Fixture `delete-done-before-last-ack` and `delete-unaccepted`.
#[test]
fn deletes_keep_done_members_and_exclude_undelivered_ones() {
    let mut store = db("first-read-deletes");
    let mut tx = store.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(anchor(true)),
        &[
            (b"/h/a.jsonl", observed(Class::Done, 0, 100)),
            (b"/h/b.jsonl", observed(Class::Owed, 1, 100)),
        ],
        &[],
    );
    commit(&mut tx, None, &[], &[b"/h/a.jsonl"]);
    let deleted_done = summary(&mut tx);
    assert!(deleted_done.open());
    assert_eq!(
        (
            deleted_done.counts.members,
            deleted_done.counts.done,
            deleted_done.counts.owed()
        ),
        (2, 1, 1)
    );
    // The last ACK: B's import debt left.
    let acked = Observed {
        member: observed(Class::Owed, 1, 100).member,
        debt_gone: true,
    };
    commit(&mut tx, None, &[(b"/h/b.jsonl", acked)], &[]);
    let frozen = summary(&mut tx);
    assert!(frozen.done_at_ms.is_some());
    assert_eq!((frozen.counts.members, frozen.counts.done), (2, 2));

    let mut store = db("first-read-delete-unaccepted");
    let mut tx = store.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(anchor(true)),
        &[
            (b"/h/a.jsonl", observed(Class::Done, 0, 100)),
            (b"/h/b.jsonl", observed(Class::Owed, 1, 100)),
        ],
        &[],
    );
    commit(&mut tx, None, &[], &[b"/h/b.jsonl"]);
    let excluded = summary(&mut tx);
    assert_eq!(
        (
            excluded.counts.members,
            excluded.counts.done,
            excluded.counts.excluded
        ),
        (2, 1, 1)
    );
    // B still obstructs its bucket: done with an exception.
    assert_eq!(excluded.counts.obstruct, [0, 1, 0, 0, 0]);
    assert!(excluded.done_at_ms.is_some());
}

/// Fixture `delete-then-discover`: the deleted member keeps counting.
#[test]
fn delete_then_discover_counts_all_three() {
    let mut store = db("first-read-delete-discover");
    let mut tx = store.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(anchor(false)),
        &[
            (b"/h/a.jsonl", observed(Class::Done, 0, 100)),
            (b"/h/b.jsonl", observed(Class::Owed, 1, 100)),
        ],
        &[],
    );
    commit(&mut tx, None, &[], &[b"/h/b.jsonl"]);
    commit(
        &mut tx,
        None,
        &[(b"/h/c.jsonl", observed(Class::Owed, 2, 50))],
        &[],
    );
    let counts = summary(&mut tx).counts;
    assert_eq!(
        (counts.members, counts.done, counts.excluded, counts.owed()),
        (3, 1, 1, 1)
    );
    assert_eq!(counts.bytes_total, 250);
}

/// A summary whose totals disagree with the rows never freezes: the recount
/// replaces the totals, and a later commit freezes on the true ones.
#[test]
fn recount_mismatch_refuses_the_freeze_and_repairs_the_totals() {
    let mut store = db("first-read-recount");
    let mut tx = store.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(anchor(true)),
        &[
            (b"/h/a.jsonl", observed(Class::Done, 0, 10)),
            (b"/h/b.jsonl", observed(Class::Owed, 0, 10)),
        ],
        &[],
    );
    // Damage: the summary claims everything done.
    let mut damaged = summary(&mut tx);
    damaged.counts = Counts::default();
    damaged
        .counts
        .replace(None, observed(Class::Done, 0, 10).member);
    damaged
        .counts
        .replace(None, observed(Class::Done, 0, 10).member);
    put_inline(&mut tx, &summary_row().unwrap(), &damaged.encode()).unwrap();
    commit(&mut tx, None, &[], &[]);
    let repaired = summary(&mut tx);
    assert!(repaired.open());
    assert_eq!((repaired.counts.done, repaired.counts.owed()), (1, 1));
}

/// An unreadable member row is left alone: the file's own commit is not
/// failed by it, it is not counted twice, and the recount refuses the freeze.
#[test]
fn unreadable_member_row_never_fails_the_save_and_blocks_the_freeze() {
    let mut store = db("first-read-unreadable");
    let mut tx = store.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(anchor(true)),
        &[(b"/h/a.jsonl", observed(Class::Done, 0, 10))],
        &[],
    );
    // Everything is done, so only the damaged row stands between this
    // generation and its freeze.
    put_inline(&mut tx, &member_row(b"/h/a.jsonl").unwrap(), b"garbage").unwrap();
    let mut generation = Commit::begin(&mut tx, None);
    let counts = generation
        .write(&mut tx, b"/h/a.jsonl", observed(Class::Done, 0, 10))
        .expect("an unreadable row does not fail the block");
    assert_eq!((counts.members, counts.done), (1, 1));
    generation.committed(counts);
    generation.erased(&mut tx, b"/h/a.jsonl").unwrap();
    generation.finish(&mut tx, None).unwrap();
    assert!(summary(&mut tx).open());
}

/// The freeze stamps `done_at` after the last block sent.
#[test]
fn freeze_stamps_done_after_the_floor() {
    let mut store = db("first-read-floor");
    let mut tx = store.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(anchor(true)),
        &[(b"/h/a.jsonl", observed(Class::Done, 0, 10))],
        &[],
    );
    let floor = u64::MAX / 4;
    commit(
        &mut tx,
        Some(SummaryEdit {
            floor_ms: Some(floor),
            sources_enabled: Some(0b11),
            ..Default::default()
        }),
        &[],
        &[],
    );
    let frozen = summary(&mut tx);
    assert_eq!(frozen.done_at_ms, Some(floor + 1));
    assert_eq!(frozen.sources_enabled, 0b11);
    // Frozen is terminal: nothing reopens or rewrites it.
    commit(
        &mut tx,
        Some(anchor(true)),
        &[(b"/h/z.jsonl", observed(Class::Owed, 4, 1))],
        &[],
    );
    assert_eq!(summary(&mut tx), frozen);
    assert!(read_member(&mut tx, b"/h/z.jsonl").unwrap().is_none());
}

/// A rename carries the member; an existing target row is kept.
#[test]
fn carried_moves_the_member_row() {
    let mut store = db("first-read-carry");
    let mut tx = store.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(anchor(false)),
        &[
            (b"/h/a.jsonl", observed(Class::Owed, 1, 10)),
            (b"/h/c.jsonl", observed(Class::Held, 2, 30)),
        ],
        &[],
    );
    carried(&mut tx, b"/h/a.jsonl", b"/h/b.jsonl").unwrap();
    assert!(read_member(&mut tx, b"/h/a.jsonl").unwrap().is_none());
    assert_eq!(
        read_member(&mut tx, b"/h/b.jsonl").unwrap().unwrap().bytes,
        10
    );
    carried(&mut tx, b"/h/b.jsonl", b"/h/c.jsonl").unwrap();
    assert_eq!(
        read_member(&mut tx, b"/h/c.jsonl").unwrap().unwrap().class,
        Class::Held
    );
    assert_eq!(recount(&mut tx).unwrap(), summary(&mut tx).counts);
}

/// Done and deleted are terminal for a member; a later debt-gone observation
/// of a member is done; bytes never shrink.
#[test]
fn resolve_keeps_terminal_classes() {
    let done = observed(Class::Done, 0, 10).member;
    assert_eq!(resolve(Some(done), observed(Class::Owed, 0, 5)), done);
    let deleted = Member {
        class: Class::ExcludedDeleted,
        ..done
    };
    assert_eq!(resolve(Some(deleted), observed(Class::Held, 0, 5)), deleted);
    let owed = observed(Class::Owed, 1, 10).member;
    let gone = Observed {
        member: observed(Class::Owed, 1, 4).member,
        debt_gone: true,
    };
    assert_eq!(resolve(Some(owed), gone).class, Class::Done);
    assert_eq!(resolve(Some(owed), gone).bytes, 10);
    assert_eq!(resolve(None, gone).class, Class::Owed);
}

/// Commits that only change counts (no certificate, no source mask, no
/// freeze) save their totals: the summary always equals a recount.
#[test]
fn count_only_commits_save_their_totals() {
    let mut store = db("first-read-count-only");
    let mut tx = store.db.begin(TxnMode::Write).unwrap();
    commit(
        &mut tx,
        Some(anchor(false)),
        &[(b"/h/a.jsonl", observed(Class::Owed, 0, 10))],
        &[],
    );
    commit(
        &mut tx,
        None,
        &[(b"/h/b.jsonl", observed(Class::Held, 1, 20))],
        &[],
    );
    assert_eq!(summary(&mut tx).counts, recount(&mut tx).unwrap());
    commit(&mut tx, None, &[], &[b"/h/a.jsonl"]);
    assert_eq!(summary(&mut tx).counts, recount(&mut tx).unwrap());
    let mut generation = Commit::begin(&mut tx, None);
    generation
        .rolled_back(&mut tx, b"/h/c.jsonl", Some(observed(Class::Owed, 2, 5)))
        .unwrap();
    generation.finish(&mut tx, None).unwrap();
    let counts = summary(&mut tx).counts;
    assert_eq!(counts, recount(&mut tx).unwrap());
    assert_eq!(
        (counts.members, counts.held, counts.excluded, counts.failed),
        (3, 1, 1, 1)
    );
}
