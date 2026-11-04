//! The first-read bound: a file never read whose mtime is more than 60 days
//! before the census time is not admitted for a first read. Read evidence,
//! committed debt and queued work keep the walk window. Synthetic fixtures.
use super::g7_debt::tests::{accept, entry, Fixture};
use super::line_delivery_tests::{candidates, unselected_page};
use super::scan_index_persistence::Source;
use super::*;
use std::time::Duration;

const STORES: [Source; 3] = [Source::Claude, Source::Codex, Source::Pi];
const CENSUS: &str = "2026-10-30T00:00:00Z";
/// Two days after `CENSUS`: a file 59 days old then is 61 days old now.
const LATER: &str = "2026-11-01T00:00:00Z";
const DAY: u64 = 24 * 60 * 60;

fn census() -> u64 {
    rfc3339_unix_seconds(CENSUS).unwrap()
}

fn set_mtime(path: &Path, unix_seconds: u64) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(unix_seconds))
        .unwrap();
}

/// One single-page walk at `census`: its G7 debt counts.
fn walk_at(f: &mut Fixture, census: &str) -> Value {
    f.index.traversal = None;
    ensure_bounded_traversal(
        f.source,
        std::slice::from_ref(&f.root),
        &mut f.index,
        census,
        BACKFILL_WINDOW_DAYS,
    );
    let source = f.source;
    let index = &mut f.index;
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        advance_bounded_directory_traversal_with_budget(
            source,
            index,
            BACKFILL_WINDOW_DAYS,
            64,
            None,
        )
    });
    rows.into_iter()
        .find(|row| row["stage"] == "freshness_alarm")
        .expect("one row per walk")["counts"]["debt"]
        .clone()
}

/// A committed Tail head: the file's G7 debt record.
fn has_head(index: &ScanIndex, path: &Path) -> bool {
    state_v2::load_head(index, &local_index_key(path), u32::MAX)
        .unwrap()
        .is_some()
}

/// [behaviour] Every admission site applies the bound to a never-read file
/// only, to the second, for both encodings: the walk (where G7 starts no
/// debt), a watcher hint and the Codex roster. Read
/// evidence keeps the walk window: an indexed file stays observed (never
/// pruned) and an archive with a body witness is listed; a Held archive
/// without one is not. A file already queued still opens, and a skipped file
/// that grows is listed for its first read.
#[test]
fn first_read_bound_admits_only_files_with_read_evidence() {
    for store in STORES {
        let mut f = Fixture::new(store, "first-read-bound");
        let codex = f.source == SnapshotSource::Codex;
        let (now, cutoff) = (census(), census() - 60 * DAY);
        let mut cases = vec![
            ("never-61.jsonl", now - 61 * DAY, false),
            ("never-59.jsonl", now - 59 * DAY, true),
            ("cut-out.jsonl", cutoff - 1, false),
            ("cut-in.jsonl", cutoff + 1, true),
            ("indexed-61.jsonl", now - 61 * DAY, true),
        ];
        if codex {
            cases.extend([
                ("held-61.jsonl.zst", now - 61 * DAY, false),
                ("witnessed-61.jsonl.zst", now - 61 * DAY, true),
                ("cut-out.jsonl.zst", cutoff - 1, false),
                ("cut-in.jsonl.zst", cutoff + 1, true),
            ]);
        }
        for (name, modified, _) in &cases {
            set_mtime(&f.file(name, 10), *modified);
        }
        let root = f.root.clone();
        let path = |name: &str| root.join(name);
        let indexed = path("indexed-61.jsonl");
        f.index
            .files
            .insert(local_index_key(&indexed), entry(&indexed));
        if codex {
            let held = codex_compressed_input::ArchiveEvidence::unknown();
            let mut witnessed = codex_compressed_input::ArchiveEvidence::unknown();
            witnessed.work.as_mut().unwrap().body_witness = Some("body".into());
            for (name, archive) in [
                ("held-61.jsonl.zst", held),
                ("witnessed-61.jsonl.zst", witnessed),
            ] {
                f.index
                    .archives
                    .insert(local_index_key(&path(name)), archive);
            }
        }
        unselected_page(f.source.api_slug());
        walk_at(&mut f, CENSUS);
        let mut admitted = cases
            .iter()
            .filter(|case| case.2)
            .map(|case| path(case.0))
            .collect::<Vec<_>>();
        admitted.sort();
        assert_eq!(candidates(&f.index), admitted, "{store:?}");
        let gated = cases.iter().filter(|case| !case.2).count();
        assert_eq!(
            unselected_page(f.source.api_slug()),
            json!({ "first_read_age": gated }),
            "{store:?}"
        );
        let observed = &f.index.traversal.as_ref().unwrap().observed_index_keys;
        assert!(observed.contains(&local_index_key(&indexed)), "{store:?}");
        assert!(!observed.contains(&local_index_key(&path("never-61.jsonl"))));

        let (old, young) = (path("never-61.jsonl"), path("never-59.jsonl"));
        assert_eq!(
            changed_watcher_hints(&f.index, &[old.clone(), young.clone()]),
            vec![young.clone()],
            "{store:?}: hint"
        );
        if codex {
            // A rollout that appears after the walk meets the same bound.
            std::thread::sleep(Duration::from_millis(50));
            let (late_old, late_young) = (f.file("late-61.jsonl", 10), f.file("late-59.jsonl", 10));
            set_mtime(&late_old, now - 61 * DAY);
            set_mtime(&late_young, now - 59 * DAY);
            refresh_retained_codex_roster(f.source, &mut f.index, BACKFILL_WINDOW_DAYS, None);
            let queued = candidates(&f.index);
            assert!(queued.contains(&late_young) && !queued.contains(&late_old));
            assert_eq!(unselected_page("codex"), json!({ "first_read_age": 1 }));
        }
        // Queued work keeps the walk window: the open recheck admits it.
        let mut counts = ScanCensus::default();
        let queued = candidate_from_traversal_path(
            f.source,
            ScanTraversalPath {
                scan_root: root.clone(),
                path: old.clone(),
                census_member: true,
                watcher_hint: false,
            },
            &mut counts,
            Some(now),
            BACKFILL_WINDOW_DAYS,
            &mut CandidateDiscovery::new(&mut f.index, None),
        );
        assert!(queued.is_some(), "{store:?}: queued");

        f.save();
        for name in ["never-61.jsonl", "cut-out.jsonl"] {
            assert!(!has_head(&f.index, &path(name)), "{store:?}: G7 quiet");
        }
        assert!(has_head(&f.index, &young));
        fs::OpenOptions::new()
            .append(true)
            .open(&old)
            .unwrap()
            .write_all(b"y")
            .unwrap();
        walk_at(&mut f, CENSUS);
        assert!(candidates(&f.index).contains(&old), "{store:?}: grown");
        f.close();
    }
}

/// [behaviour] First-seen: a never-read file listed inside the bound owes G7
/// debt. Unread when it crosses the bound, that debt keeps it admitted, and
/// its exact acknowledgement settles the debt.
#[test]
fn listed_then_aged_file_is_still_read_and_settles() {
    for store in STORES {
        let mut f = Fixture::new(store, "first-read-edge");
        let file = f.file("edge.jsonl", 10);
        set_mtime(&file, census() - 59 * DAY);
        assert_eq!(walk_at(&mut f, CENSUS)["outstanding_files"], 1, "{store:?}");
        f.save();
        assert!(has_head(&f.index, &file), "{store:?}");
        assert_eq!(walk_at(&mut f, LATER)["outstanding_files"], 1, "{store:?}");
        assert!(candidates(&f.index).contains(&file), "{store:?}");
        f.index.files.insert(local_index_key(&file), entry(&file));
        accept(f.source, &mut f.index, &file);
        assert_eq!(walk_at(&mut f, LATER)["outstanding_files"], 0, "{store:?}");
        f.close();
    }
}

/// [behaviour] End to end on Pi: a never-read session past the bound is not
/// read; once it grows it takes one ordinary first read.
#[test]
fn skipped_session_that_grows_takes_one_first_read() {
    let root = crate::test_scratch::unique_path("first-read-pi");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("session.jsonl");
    let message = |at: &str| {
        format!(
            "{{\"type\":\"message\",\"timestamp\":\"{at}\",\"message\":{{\"role\":\"assistant\",\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"usage\":{{\"input\":12,\"output\":4}}}}}}\n"
        )
    };
    let session =
        "{\"type\":\"session\",\"id\":\"first-read\",\"timestamp\":\"2026-08-01T00:00:00Z\"}\n";
    fs::write(
        &path,
        format!("{session}{}", message("2026-08-01T00:01:00Z")),
    )
    .unwrap();
    set_mtime(&path, rfc3339_unix_seconds("2026-08-01T00:02:00Z").unwrap());
    let mut index = ScanIndex::default();
    let mut scan = |at: &str| {
        index.traversal = None;
        scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            at,
            BACKFILL_WINDOW_DAYS,
        )
        .unwrap()
    };
    let skipped = scan("2026-10-05T00:00:00Z");
    assert_eq!(
        (skipped.scanned_file_count, skipped.snapshots.len()),
        (0, 0)
    );
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(message("2026-10-05T00:00:30Z").as_bytes())
        .unwrap();
    let read = scan("2026-10-05T00:01:00Z");
    assert_eq!((read.scanned_file_count, read.snapshots.len()), (1, 1));
    let _ = fs::remove_dir_all(root);
}
