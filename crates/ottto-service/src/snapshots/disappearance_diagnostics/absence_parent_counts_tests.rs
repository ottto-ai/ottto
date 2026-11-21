//! Tests for the absence parent-probe counts in the resource report (unix only).

use super::super::*;
use super::{observe_sites, Site, OUTCOMES, SITES};
use crate::local_resource_diagnostics::{self as lr, claude_reread::Scope};

fn counts(scope: Scope) -> serde_json::Value {
    serde_json::to_value(scope.finish()).unwrap()
}

#[test]
fn parent_probe_boolean_and_each_refusal_class_are_unchanged() {
    let dir = crate::test_scratch::ScratchDir::new("absence-classes");
    let real = dir.join("real");
    fs::create_dir(&real).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let file = dir.join("file");
    fs::write(&file, b"fixture").unwrap();
    let cycle = dir.join("cycle");
    std::os::unix::fs::symlink(&cycle, &cycle).unwrap();
    // ELOOP supplies an actual metadata error without permission/root assumptions.
    for (parent, suffix, expected) in [
        (dir.join("missing"), "missing", false),
        (link, "symlink", false),
        (file, "not_directory", false),
        (cycle.join("nested"), "metadata_error", false),
        (real, "", true),
    ] {
        let path = parent.join("member.jsonl");
        let original = path
            .parent()
            .and_then(|p| fs::symlink_metadata(p).ok())
            .is_some_and(|p| p.is_dir() && !p.file_type().is_symlink());
        let scope = Scope::begin(true);
        let result =
            claude_absence_is_removal(SnapshotSource::ClaudeCode, &path).is_removal(&path);
        assert_eq!(result, original);
        assert_eq!(result, expected);
        let actual = counts(scope);
        if expected {
            assert_eq!(actual, serde_json::json!({}));
        } else {
            let mut wanted = serde_json::Map::new();
            wanted.insert(format!("claude_absence_parent_{suffix}"), 1.into());
            assert_eq!(actual, serde_json::Value::Object(wanted));
        }
    }
}

#[test]
fn candidate_sites_count_once_and_live_parent_still_removes() {
    let dir = crate::test_scratch::ScratchDir::new("absence-sites-counts");
    let real = dir.join("real");
    fs::create_dir(&real).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    for site in [Site::CandidateWalk, Site::CandidateForcedIndex] {
        for (parent, suffix) in [
            (dir.join("missing"), "missing"),
            (link.clone(), "symlink"),
            (real.clone(), ""),
        ] {
            let path = parent.join("member.jsonl");
            let scope = Scope::begin(true);
            let mut census = ScanCensus::default();
            let (_, events) = observe_sites(|| {
                candidate_from_traversal_path_at(
                    SnapshotSource::ClaudeCode,
                    site,
                    ScanTraversalPath {
                        scan_root: dir.to_path_buf(),
                        path: path.clone(),
                        census_member: true,
                        watcher_hint: false,
                    },
                    &mut census,
                    None,
                    BACKFILL_WINDOW_DAYS,
                    &mut crate::snapshots::CandidateDiscovery::new(
                        &mut ScanIndex::default(),
                        None,
                    ),
                )
            });
            let removal = suffix != "symlink";
            assert_eq!(
                events[1][site.index()],
                if removal { [0, 1] } else { [1, 0] }
            );
            assert_eq!(census.disappeared_file_count, usize::from(!removal));
            assert_eq!(
                census.removed_index_keys.contains(&local_index_key(&path)),
                removal
            );
            let actual = counts(scope);
            let mut wanted = serde_json::Map::new();
            if !suffix.is_empty() {
                wanted.insert(format!("claude_absence_parent_{suffix}"), 1.into());
            }
            assert_eq!(actual, serde_json::Value::Object(wanted));
        }
    }
}

#[test]
fn parent_races_count_file_and_metadata_error_once_per_not_found() {
    for site in [Site::CandidateWalk, Site::CandidateForcedIndex] {
        for metadata_error in [false, true] {
            let dir = crate::test_scratch::ScratchDir::new("absence-parent-race");
            let base = dir.join("parent");
            let parent = if metadata_error {
                base.join("nested")
            } else {
                base.clone()
            };
            fs::create_dir_all(&parent).unwrap();
            let path = parent.join("missing.jsonl");
            // The child lstat returns NotFound first; change only the existing
            // parent probe's result, at the production call boundary.
            super::ABSENCE_PARENT_PROBE_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    fs::remove_dir(&parent).unwrap();
                    if metadata_error {
                        fs::remove_dir(&base).unwrap();
                        std::os::unix::fs::symlink(&base, &base).unwrap();
                    } else {
                        fs::write(&base, b"fixture").unwrap();
                    }
                }));
            });
            let scope = Scope::begin(true);
            let mut census = ScanCensus::default();
            let (candidate, events) = observe_sites(|| {
                candidate_from_traversal_path_at(
                    SnapshotSource::ClaudeCode,
                    site,
                    ScanTraversalPath {
                        scan_root: dir.to_path_buf(),
                        path,
                        census_member: true,
                        watcher_hint: false,
                    },
                    &mut census,
                    None,
                    BACKFILL_WINDOW_DAYS,
                    &mut crate::snapshots::CandidateDiscovery::new(
                        &mut ScanIndex::default(),
                        None,
                    ),
                )
            });
            assert!(candidate.is_none());
            assert!(super::ABSENCE_PARENT_PROBE_HOOK.with(|hook| hook.borrow().is_none()));
            let mut wanted_events = [[[0; OUTCOMES]; SITES]; 3];
            wanted_events[1][site.index()] = [1, 0];
            assert_eq!(events, wanted_events);
            assert_eq!(census.disappeared_file_count, 1);
            assert!(census.removed_index_keys.is_empty());
            let key = if metadata_error {
                "claude_absence_parent_metadata_error"
            } else {
                "claude_absence_parent_not_directory"
            };
            let mut wanted = serde_json::Map::new();
            wanted.insert(key.to_owned(), 1.into());
            assert_eq!(counts(scope), serde_json::Value::Object(wanted));
        }
    }
}

#[test]
fn open_subagent_counts_survive_steps_and_emit_on_existing_page() {
    let dir = crate::test_scratch::ScratchDir::new("absence-open-subagent");
    let parent = dir.join("subagents");
    fs::create_dir(&parent).unwrap();
    let path = parent.join("member.jsonl");
    fs::write(&path, b"{}\n").unwrap();
    let mut census = ScanCensus::default();
    let candidate = candidate_from_traversal_path(
        SnapshotSource::ClaudeCode,
        ScanTraversalPath {
            scan_root: dir.to_path_buf(),
            path: path.clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut census,
        None,
        BACKFILL_WINDOW_DAYS,
        &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
    )
    .unwrap();
    fs::remove_file(&path).unwrap();
    fs::remove_dir(&parent).unwrap();
    let scope = Scope::begin(true);
    let (_, events) = observe_sites(|| {
        open_and_identify_scan_candidate(
            SnapshotSource::ClaudeCode,
            candidate,
            &mut census,
            None,
            BACKFILL_WINDOW_DAYS,
            crate::snapshots::DiscoveryRetention::unverified(
                &crate::snapshots::SharedMap::default(),
            ),
        )
    });
    assert_eq!(events[1][Site::Open.index()], [1, 0]);
    assert_eq!(census.disappeared_file_count, 1);
    assert!(census.removed_index_keys.is_empty());
    let mut probe = lr::Probe::start();
    probe.page_events.merge(scope.finish());
    let empty_step = Scope::begin(true);
    probe.page_events.merge(empty_step.finish());
    let (_, records) = lr::capture(|| {
        probe.collection(
            "claude_code",
            lr::CollectionCounts {
                scanned_files: 0,
                semantic_noops: 0,
                sampled_acquisition: None,
                full_causes: Default::default(),
            },
        )
    });
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["stage"], "native_collection_page");
    assert_eq!(records[0]["schema_version"], 2);
    let c = &records[0]["counts"];
    assert_eq!(c["claude_absence_parent_missing"], 1);
    assert_eq!(c["claude_absence_parent_subagent_missing"], 1);
    assert_eq!(
        c.as_object()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("claude_absence_parent"))
            .count(),
        2
    );
    assert_eq!(counts(Scope::begin(true)), serde_json::json!({}));
}

#[test]
fn other_sources_hints_and_nonmembers_add_no_parent_counts() {
    let dir = crate::test_scratch::ScratchDir::new("absence-excluded");
    for (source, census_member, watcher_hint) in [
        (SnapshotSource::Codex, true, false),
        (SnapshotSource::Pi, true, false),
        (SnapshotSource::ClaudeCode, false, false),
        (SnapshotSource::ClaudeCode, true, true),
    ] {
        let scope = Scope::begin(true);
        let mut census = ScanCensus::default();
        candidate_from_traversal_path(
            source,
            ScanTraversalPath {
                scan_root: dir.to_path_buf(),
                path: dir.join("missing/member.jsonl"),
                census_member,
                watcher_hint,
            },
            &mut census,
            None,
            BACKFILL_WINDOW_DAYS,
            &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
        );
        assert_eq!(counts(scope), serde_json::json!({}));
    }
}
