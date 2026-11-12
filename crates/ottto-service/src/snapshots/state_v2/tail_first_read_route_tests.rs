//! The first read's import list over the real route: staged with the pass,
//! committed by the real graph save (`tail::apply`) and the exit commit,
//! dropped with a discarded stage.
use super::super::tail::first_read::{Class, Member, Observed, SummaryEdit, FAIL_MEMBER_WRITE};
use super::tail_route::{
    first_read_member, first_read_summary, observe_first_read, staged_first_read_anchor,
    tail_set_aside, tail_stage_discards,
};
use super::tests::{load_with, save_with, Fixture};
use super::*;

const ANCHOR_MS: u64 = 1_794_484_800_000;

fn member(class: Class) -> Observed {
    Observed {
        member: Member {
            class,
            bucket: 2,
            bytes: 10,
        },
        debt_gone: false,
    }
}

fn members(keys: &[&str], class: Class) -> Vec<(String, Observed)> {
    keys.iter()
        .map(|key| (key.to_string(), member(class)))
        .collect()
}

/// A stage with nothing but the source promise: the save runs `tail::apply`.
fn touch(path: &Path) {
    let edit = SummaryEdit {
        sources_enabled: Some(1),
        ..Default::default()
    };
    observe_first_read(path, Vec::new(), Some(edit)).unwrap();
}

fn anchor() -> SummaryEdit {
    SummaryEdit {
        anchor_at_ms: Some(ANCHOR_MS),
        certify_at_ms: Some(ANCHOR_MS),
        ..Default::default()
    }
}

/// [behaviour] The anchor staged with a page's members opens the generation
/// for that same save: every member of a one-page first walk commits with it
/// (files_total = N), and that save does not freeze even though every member
/// is done and the listing is certified. The next save freezes.
#[test]
fn staged_anchor_admits_the_first_page_and_never_freezes_with_it() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(staged_first_read_anchor(&f.path).unwrap(), None);
    observe_first_read(&f.path, Vec::new(), Some(anchor())).unwrap();
    assert_eq!(staged_first_read_anchor(&f.path).unwrap(), Some(ANCHOR_MS));
    let keys = ["/h/a.jsonl", "/h/b.jsonl", "/h/c.jsonl"];
    observe_first_read(&f.path, members(&keys, Class::Done), None).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let created = first_read_summary(&index).unwrap().expect("summary");
    assert_eq!(created.counts.members, 3);
    assert_eq!(created.counts.done, 3);
    assert!(created.open(), "the creating save froze");
    for key in keys {
        assert!(first_read_member(&index, key).unwrap().is_some());
    }

    touch(&f.path);
    save_with(&f.path, &mut index).unwrap();
    let frozen = first_read_summary(&index).unwrap().unwrap();
    assert!(frozen.done_at_ms.is_some());
    assert_eq!(frozen.counts, created.counts);
    assert!(first_read_member(&index, keys[0]).unwrap().is_none());
}

/// [behaviour] A real isolated-block failure in `tail::apply` for a new
/// member: the member is written failed outside the block, it is not set
/// aside (it has no Tail rows to re-read), and that save cannot freeze. Only
/// a later observation clears it.
#[test]
fn failed_member_write_is_failed_and_blocks_that_freeze() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    observe_first_read(
        &f.path,
        members(&["/h/a.jsonl"], Class::Done),
        Some(anchor()),
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();

    FAIL_MEMBER_WRITE.with(|fail| fail.set(true));
    observe_first_read(&f.path, members(&["/h/b.jsonl"], Class::Done), None).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert!(
        !FAIL_MEMBER_WRITE.with(std::cell::Cell::get),
        "the write ran"
    );
    let after = first_read_summary(&index).unwrap().unwrap();
    assert!(after.open(), "a rolled-back save froze");
    assert_eq!((after.counts.members, after.counts.failed), (2, 1));
    assert_eq!(
        first_read_member(&index, "/h/b.jsonl")
            .unwrap()
            .unwrap()
            .class,
        Class::Failed
    );
    assert!(tail_set_aside(&index, "/h/b.jsonl").unwrap().is_none());

    // A save with nothing new keeps it failed: no freeze.
    touch(&f.path);
    save_with(&f.path, &mut index).unwrap();
    assert!(first_read_summary(&index).unwrap().unwrap().open());
    observe_first_read(&f.path, members(&["/h/b.jsonl"], Class::Done), None).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let frozen = first_read_summary(&index).unwrap().unwrap();
    assert!(frozen.done_at_ms.is_some());
    assert_eq!((frozen.counts.members, frozen.counts.done), (2, 2));
}

/// [money] A pass that fails after staging (authority, checkpoint or upload
/// error): the dropped stage takes its members with it, nothing commits, the
/// discard is counted (so that walk cannot certify), and the exit commit of
/// a healthy pass commits the members it staged.
#[test]
fn discarded_stage_drops_members_and_counts_the_discard() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    observe_first_read(
        &f.path,
        members(&["/h/a.jsonl"], Class::Owed),
        Some(anchor()),
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();
    let before = first_read_summary(&index).unwrap().unwrap();
    let discards = tail_stage_discards(&f.path).unwrap();

    observe_first_read(&f.path, members(&["/h/a.jsonl"], Class::Done), None).unwrap();
    drop(BaselineRelease::new(&f.path, &index));
    assert_eq!(tail_stage_discards(&f.path).unwrap(), discards + 1);
    assert_eq!(first_read_summary(&index).unwrap().unwrap(), before);
    assert_eq!(
        first_read_member(&index, "/h/a.jsonl")
            .unwrap()
            .unwrap()
            .class,
        Class::Owed
    );

    let mut debt_gone = member(Class::Owed);
    debt_gone.debt_gone = true;
    observe_first_read(&f.path, vec![("/h/a.jsonl".to_owned(), debt_gone)], None).unwrap();
    BaselineRelease::new(&f.path, &index).commit_tail().unwrap();
    let index = load_with(&f.path, false).unwrap().unwrap();
    let committed = first_read_summary(&index).unwrap().unwrap();
    assert_eq!(committed.counts.done, 1);
    // The exit commit was not the creating one: it may freeze.
    assert!(committed.done_at_ms.is_some());
}
