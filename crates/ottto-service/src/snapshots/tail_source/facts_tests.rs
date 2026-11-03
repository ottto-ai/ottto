//! Session facts (D168-1) on real committed Tail state: a restart restores
//! them from the database with no transcript byte, a changed fact rewrites
//! only its slot and purges the old value, and a long first prompt goes
//! through the store's fragments and loads back whole.
use super::super::claude::tests::lines;
use super::super::seam::tests::{route, Route};
use super::tests::{cold_accumulator, committed, counted, loaded, read};
use super::*;
use crate::snapshots::state_v2::{Change, Collection};
use crate::transcript_acquisition::ReadMode;

/// The committed head of `key` as a read's base.
fn base(route: &Route, key: &str) -> TailBase {
    let head = route.head(key).unwrap();
    let mut base = TailBase::new(&head.body, false);
    state_v2::load_tail(&route.index, key, &head, |collection, page, bytes| {
        base.observe::<Claude>(collection, page, &bytes).unwrap();
        Ok(())
    })
    .unwrap();
    base
}

/// The facts a load restored.
fn facts(taken: &Taken<CachedJsonlReduction>) -> [Option<String>; 4] {
    let (acc, _, _) = taken.retained.state.finish_view();
    [
        acc.title.clone(),
        acc.first_prompt_material.clone(),
        acc.first_prompt_title.clone(),
        acc.workspace_path
            .as_ref()
            .map(|path| path.display().to_string()),
    ]
}

/// [money] A restart restores the session facts from the database, never
/// from the file: the stored value comes back where the file holds another,
/// an unchanged file's facts equal its cold Full's, and the quiet read is
/// Unchanged with 0 transcript bytes.
#[test]
fn a_restart_restores_session_facts_from_the_database() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let (Load::Reused(taken, Some(_)), records) = loaded(&route, &path, &key) else {
        panic!("the committed head is reused");
    };
    assert_eq!(counted(&records), ("hit".into(), vec![]));
    let cold = cold_accumulator(&route, &path);
    assert_eq!(
        facts(&taken),
        [
            cold.title.clone(),
            cold.first_prompt_material.clone(),
            cold.first_prompt_title.clone(),
            cold.workspace_path
                .as_ref()
                .map(|path| path.display().to_string()),
        ]
    );
    let [title, prompt, _, workspace] = facts(&taken);
    assert!(title.is_some() && prompt.is_some() && workspace.is_some());
    let (parser, mode, _) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Unchanged));
    assert_eq!(parser.reader.consumed_bytes(), 0);

    let (tail, native) = route.complete("b.jsonl", &lines(3), None, |acc| {
        acc.title = Some("Only in the database".into());
    });
    let key = tail.key_for_test().to_owned();
    assert!(tail.publish(&native));
    route.save(false);
    let (Load::Reused(taken, _), _) = loaded(&route, &route.dir.join("b.jsonl"), &key) else {
        panic!("the committed head is reused");
    };
    assert_eq!(facts(&taken)[0].as_deref(), Some("Only in the database"));
}

/// [behaviour] A changed title rewrites its slot alone and stages
/// `DropsPrivate`, so the old value is purged (F3); a restage with the same
/// facts restates no fact and stays `Ordinary`. The new title then loads.
#[test]
fn a_title_change_rewrites_its_slot_and_drops_the_old_value() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let (same, _) = route.complete("a.jsonl", &lines(3), Some(base(&route, &key)), |_| {});
    // Only a new mtime restates anything, and then the head alone.
    if let Some(staged) = same.staged_for_test() {
        assert_eq!(staged.change, Change::Ordinary);
        assert!(staged.pages.is_empty() && staged.obsolete.is_empty());
    }

    let (renamed, native) = route.complete("a.jsonl", &lines(3), Some(base(&route, &key)), |acc| {
        acc.title = Some("Renamed".into());
    });
    let staged = renamed.staged_for_test().unwrap();
    assert_eq!(staged.change, Change::DropsPrivate);
    assert_eq!(
        staged.pages.keys().copied().collect::<Vec<_>>(),
        [(Collection::SessionFacts, 0)]
    );
    assert!(renamed.publish(&native));
    route.save(false);
    let (Load::Reused(taken, _), _) = loaded(&route, &path, &key) else {
        panic!("the committed head is reused");
    };
    assert_eq!(facts(&taken)[0].as_deref(), Some("Renamed"));
}

/// [format] A first prompt above the store's 16 MiB row value is one fact
/// page the store splits into `tail.frag`; it loads back whole.
#[test]
fn a_long_first_prompt_goes_through_fragments() {
    const ROW: usize = 16 * 1024 * 1024;
    let mut route = route();
    let long = "p".repeat(ROW + 4096);
    let (mut tail, _native) = route.complete("a.jsonl", &lines(3), None, |acc| {
        acc.first_prompt_material = Some(long.clone());
    });
    let key = tail.key_for_test().to_owned();
    state_v2::stage_tail(&route.path, &key, tail.take_staged_for_test()).unwrap();
    route.save(false);
    let head = route.head(&key).unwrap();
    let mut fact = 0;
    state_v2::load_tail(&route.index, &key, &head, |collection, page, bytes| {
        if (collection, page) == (Collection::SessionFacts, 1) {
            fact = bytes.len();
        }
        Ok(())
    })
    .unwrap();
    assert!(fact > ROW, "the fact page is over one row value: {fact}");
    let (Load::Reused(taken, _), records) = loaded(&route, &route.dir.join("a.jsonl"), &key) else {
        panic!("the committed head is reused");
    };
    assert_eq!(counted(&records), ("hit".into(), vec![]));
    assert_eq!(facts(&taken)[1].as_deref(), Some(long.as_str()));
}
