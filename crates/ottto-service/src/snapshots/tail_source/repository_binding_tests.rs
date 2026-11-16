//! Session-owned repository observations: compatible facts, shared native
//! capture, restart without a cwd, and display-only folder labels.
use super::seam::tests::{route_for, scope, Route, NOW};
use super::*;
use crate::context_footprint::{resolve_repository_identity, workspace_label};
use crate::snapshots::sampled_scan::transition_fixture::native_cold;
use crate::snapshots::scan_index_persistence::Source;
use serde_json::json;

/// [format] Workspace bytes written by v0.1.221 hydrate without reconstruction;
/// only Workspace accepts v2, an unbound Workspace still writes v1, and a
/// non-Git v2 binding round-trips byte for byte.
#[test]
fn previous_release_workspace_fact_and_per_kind_versions() {
    // v0.1.221 Fact::Workspace: kind, version, Some, byte length, UTF-8 cwd.
    const PREVIOUS: &[u8] = b"\x02\x01\x01\x12/tmp/prior-release";
    // Bound v2 bytes from the original field-by-field writer: same UTF-8
    // options and field order after replacing it with durable_struct!.
    const BOUND: &[u8] = b"\x02\x02\x01\x12/tmp/prior-release\x01\x04hash\x01\x0egit_common_dir\x01\x0frepository_root\x01\x09workspace\x01\x08git_root";
    // Non-Git v2: no hash, source or labels; only the workspace kind.
    const NON_GIT: &[u8] = b"\x02\x02\x01\x12/tmp/prior-release\x00\x00\x01\x07non_git\x00\x00";
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let mut acc = SnapshotAccumulator::new(source);
        read_fact_page(2, PREVIOUS, &mut acc).unwrap();
        assert_eq!(
            acc.workspace_path.as_deref(),
            Some(Path::new("/tmp/prior-release"))
        );
        assert!(acc.repository_binding.is_none());
        assert_eq!(fact_pages(&acc).unwrap(), [(2, PREVIOUS.to_vec())]);
        read_fact_page(2, BOUND, &mut acc).unwrap();
        assert_eq!(
            acc.repository_binding,
            Some(crate::context_footprint::RepositoryIdentity {
                repository_hash: Some("hash".into()),
                repository_identity_source: Some("git_common_dir".into()),
                workspace_kind: Some("repository_root".into()),
                repository_label: Some("workspace".into()),
                repository_label_source: Some("git_root".into()),
            })
        );
        assert_eq!(fact_pages(&acc).unwrap(), [(2, BOUND.to_vec())]);
        read_fact_page(2, NON_GIT, &mut acc).unwrap();
        assert_eq!(
            acc.repository_binding,
            Some(crate::context_footprint::RepositoryIdentity {
                repository_hash: None,
                repository_identity_source: None,
                workspace_kind: Some("non_git".into()),
                repository_label: None,
                repository_label_source: None,
            })
        );
        assert_eq!(fact_pages(&acc).unwrap(), [(2, NON_GIT.to_vec())]);
        assert_eq!(
            read_fact_page(0, &[0, 2, 1, 1, b'x'], &mut acc),
            Err(ReconstructCause::INCOMPATIBLE)
        );
        assert_eq!(
            read_fact_page(2, &[2, 3], &mut acc),
            Err(ReconstructCause::INCOMPATIBLE)
        );
    }
}

fn git_init(cwd: &Path) {
    fs::create_dir(cwd).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "-q"])
        .arg(cwd)
        .status()
        .unwrap()
        .success());
}

/// Restore `path` from the committed database pages and run the production
/// Unchanged finish, which reads no transcript bytes.
fn unchanged_finish<S: TailSource>(
    route: &Route,
    path: &Path,
    apply: fn(&Value, &mut SnapshotAccumulator),
) -> (seam::PendingTail, Result<ParsedJsonlFile>) {
    let mut parser = native_cold::parser(S::SOURCE, path, File::open(path).unwrap(), apply);
    let load::Load::Reused(taken, base) = load::load::<S>(
        &route.index,
        &route.path,
        &local_index_key(path),
        &HeadIdentity::new(&route.path, S::SOURCE, &route.dir, path, false),
        &mut File::open(path).unwrap(),
        &scope(),
        &codex::tests::candidate(path),
        &parser.accumulator,
    ) else {
        panic!("the committed reduction restores");
    };
    assert!(matches!(
        parser
            .prepare_acquisition(Some(taken), &scope(), None, NOW)
            .unwrap(),
        crate::transcript_acquisition::ReadMode::Unchanged
    ));
    assert_eq!(parser.reader.consumed_bytes(), 0);
    route.finish_under::<S>(path, parser, base, |_| {}, &scope())
}

/// The staged Workspace fact version, `None` when the finish left it as committed.
fn staged_workspace_version(tail: &seam::PendingTail) -> Option<u8> {
    tail.staged_for_test()?
        .pages
        .get(&(Collection::SessionFacts, 2))
        .map(|bytes| bytes[1])
}

/// With `git`, the cwd is a repository at the first read. Without it, the cwd
/// is absent at the first read, so the session keeps a path-only v1 fact (what
/// earlier releases saved for every non-Git folder); the folder then appears,
/// not under Git, before an Unchanged finish.
fn capture_restore<S: TailSource>(
    source: Source,
    lines: Vec<String>,
    apply: fn(&Value, &mut SnapshotAccumulator),
    git: bool,
) {
    let mut route = route_for(source);
    let cwd = route.dir.join("workspace");
    if git {
        git_init(&cwd);
    }
    let path = route.dir.join("session.jsonl");
    let lines: Vec<_> = lines
        .into_iter()
        .map(|line| {
            let mut value: Value = serde_json::from_str(&line).unwrap();
            if let Some(payload) = value.get_mut("payload").filter(|p| p.get("cwd").is_some()) {
                payload["cwd"] = json!(cwd);
            }
            if value.get("cwd").is_some() {
                value["cwd"] = json!(cwd);
            }
            value.to_string()
        })
        .collect();
    fs::write(&path, lines.join("\n") + "\n").unwrap();
    let mut parser = native_cold::parser(S::SOURCE, &path, File::open(&path).unwrap(), apply);
    parser
        .prepare_acquisition(None, &scope(), None, NOW)
        .unwrap();
    while !parser.step().unwrap() {}
    assert_eq!(
        parser.accumulator.workspace_path.as_deref(),
        Some(cwd.as_path())
    );
    let (tail, native) = route.finish_under::<S>(&path, parser, None, |_| {}, &scope());
    let mut first = native.as_ref().unwrap().snapshots[0].clone();
    if git {
        assert_eq!(staged_workspace_version(&tail), Some(2));
    } else {
        assert_eq!(first.workspace_kind.as_deref(), Some("unknown"));
        assert_eq!(staged_workspace_version(&tail), Some(1));
    }
    assert!(tail.publish(&native));
    route.save(false);
    route.index = ScanIndex::load(&route.path).unwrap();
    if !git {
        fs::create_dir(&cwd).unwrap();
        let (tail, native) = unchanged_finish::<S>(&route, &path, apply);
        assert_eq!(staged_workspace_version(&tail), Some(2));
        first = native.as_ref().unwrap().snapshots[0].clone();
        assert_eq!(first.workspace_kind.as_deref(), Some("non_git"));
        assert_eq!(first.workspace_display_label.as_deref(), Some("workspace"));
        assert!(tail.publish(&native));
        route.save(false);
        route.index = ScanIndex::load(&route.path).unwrap();
    }
    let expected = resolve_repository_identity(&cwd, true);
    assert_eq!(first.repository_hash, expected.repository_hash);
    fs::remove_dir_all(&cwd).unwrap();
    let head = route.head(&local_index_key(&path)).unwrap();
    let mut restored = SnapshotAccumulator::new(S::SOURCE);
    S::decode_head(head.revision, &head.body, &mut restored).unwrap();
    let mut workspace_version = None;
    state_v2::load_tail(
        &route.index,
        &local_index_key(&path),
        &head,
        |collection, page, bytes| {
            if (collection, page) == (Collection::SessionFacts, 2) {
                workspace_version = Some(bytes[1]);
            }
            S::decode_page(collection, page, &bytes, &mut restored).unwrap();
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(workspace_version, Some(2));
    assert_eq!(restored.repository_binding, Some(expected.clone()));
    let bound = restored.repository_binding.as_ref().unwrap();
    let heap = [
        &bound.repository_hash,
        &bound.repository_identity_source,
        &bound.workspace_kind,
        &bound.repository_label,
        &bound.repository_label_source,
    ]
    .into_iter()
    .flatten()
    .map(String::capacity)
    .sum::<usize>();
    eprintln!(
        "repository_binding_metrics inline_bytes={} heap_bytes={} fact_bytes={}",
        std::mem::size_of_val(&restored.repository_binding),
        heap,
        fact_pages(&restored)
            .unwrap()
            .into_iter()
            .find(|(page, _)| *page == 2)
            .unwrap()
            .1
            .len()
    );
    let missing = resolve_repository_identity(&cwd, true);
    assert_eq!(missing.workspace_kind.as_deref(), Some("unknown"));
    // Exercise the production load and native finish, including forwarding
    // the restored binding to into_items, without reading transcript bytes.
    let (tail, native) = unchanged_finish::<S>(&route, &path, apply);
    let items = &native.as_ref().unwrap().snapshots;
    assert_eq!(items[0].repository_hash, expected.repository_hash);
    assert_eq!(items[0].repository_label, expected.repository_label);
    assert_eq!(items[0].workspace_kind, expected.workspace_kind);
    assert_eq!(items[0].workspace_hash, first.workspace_hash);
    assert_eq!(
        items[0].workspace_display_label,
        first.workspace_display_label
    );
    if git {
        return;
    }
    // Live Git evidence replaces a saved non-Git binding.
    assert!(tail.publish(&native));
    route.save(false);
    route.index = ScanIndex::load(&route.path).unwrap();
    git_init(&cwd);
    let (tail, native) = unchanged_finish::<S>(&route, &path, apply);
    assert_eq!(staged_workspace_version(&tail), Some(2));
    let item = &native.as_ref().unwrap().snapshots[0];
    assert_eq!(item.workspace_kind.as_deref(), Some("repository_root"));
    assert_eq!(
        item.repository_hash,
        resolve_repository_identity(&cwd, true).repository_hash
    );
    assert!(item.repository_hash.is_some());
}

/// [behaviour] Each source's native PRE captures the same binding; a committed
/// restart restores it from database pages after cwd deletion, with no transcript
/// reads or dependency on the process cache.
#[test]
fn every_source_pins_the_native_observation_before_staging() {
    every_source(true);
}

/// [regress] A non-Git folder's v1 fact (all saved before this fix) gains its
/// non-Git binding on an Unchanged finish; after a restart and the folder's
/// deletion, every source keeps `non_git`, its workspace hash and its folder
/// label instead of falling back to `unknown`. [behaviour] Live Git evidence
/// later replaces the saved non-Git binding in the same flow.
#[test]
fn every_source_keeps_a_non_git_folder_after_deletion() {
    every_source(false);
}

fn every_source(git: bool) {
    capture_restore::<claude::Claude>(
        Source::Claude,
        claude::tests::lines(2),
        apply_claude_code_line,
        git,
    );
    capture_restore::<codex::Codex>(Source::Codex, codex::tests::lines(2), apply_codex_line, git);
    capture_restore::<pi::Pi>(Source::Pi, vec![
        json!({"type":"session","version":3,"id":"synthetic-folder-session","timestamp":"2026-10-20T16:00:00Z","cwd":"/tmp/pi-folder"}).to_string(),
        json!({"type":"message","id":"a1","timestamp":"2026-10-20T16:01:00Z","message":{"role":"assistant","provider":"openai","model":"gpt-5","responseId":"r1","usage":{"input":10,"output":2,"cacheRead":3,"cacheWrite":4,"totalTokens":19,"cost":{"total":0.001}}}}).to_string(),
    ], apply_pi_line, git);
}

/// [behaviour] Folder labels use the shared sanitizer and current upload policy.
/// Missing cwd evidence stays retryable, so ordinary selected work can bind later;
/// a non-Git folder is pinned like a repository.
#[test]
fn folder_labels_and_failed_lookup_recovery() {
    let route = route_for(Source::Claude);
    let cwd = route.dir.join("new-folder");
    for (exists, init, kind, version) in [
        (false, false, "unknown", 1),
        (true, false, "non_git", 2),
        (true, true, "repository_root", 2),
        (false, false, "unknown", 1),
    ] {
        if !exists && cwd.exists() {
            fs::remove_dir_all(&cwd).unwrap();
        }
        if exists && !cwd.exists() {
            fs::create_dir(&cwd).unwrap();
        }
        if init {
            assert!(std::process::Command::new("git")
                .args(["init", "-q"])
                .arg(&cwd)
                .status()
                .unwrap()
                .success());
        }
        let (tail, native) =
            route.complete("session.jsonl", &claude::tests::lines(2), None, |acc| {
                acc.workspace_path = Some(cwd.clone());
            });
        let staged = tail.staged_for_test().unwrap();
        assert_eq!(staged.pages[&(Collection::SessionFacts, 2)][1], version);
        let mut items = native.unwrap().snapshots;
        assert_eq!(items[0].workspace_kind.as_deref(), Some(kind));
        assert_eq!(
            items[0].workspace_display_label.as_deref(),
            (!init).then_some("new-folder")
        );
        assert_eq!(
            items[0].workspace_label_source.as_deref(),
            (!init).then_some("directory_name")
        );
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut items,
            SnapshotUploadPolicy {
                workspace_labels_enabled: false,
                ..SnapshotUploadPolicy::default()
            },
        );
        assert!(
            items[0].workspace_display_label.is_none() && items[0].workspace_label_source.is_none()
        );
    }
    for (name, label) in [
        ("  work  folder  ", Some("work folder")),
        ("workspace-é", Some("workspace-é")),
        (".claude", None),
        ("x.codex", None),
        ("workspace_path", None),
        ("transcript_path", None),
        ("authorization: secret", None),
        ("x\\y", None),
    ] {
        assert_eq!(
            workspace_label(&Path::new("/tmp").join(name)).as_deref(),
            label
        );
    }
}

/// [format] Null display values retain the previous component bytes; newly
/// populated folder labels have an exact receiver-parity digest, while money's
/// policy-neutral content hash remains unchanged.
#[test]
fn folder_label_wire_component_matches_receiver_fixture() {
    let mut item = crate::snapshots::tests::sample_session_artifact_item();
    let old = snapshot_semantic_component_hashes(SnapshotSource::Pi, &item);
    assert_eq!(
        old["display_identity"],
        "e429ca317695770aab75860ce9f24f0c000cd6ea56ad8ef193e5b1150988459e"
    );
    item.workspace_display_label = Some("workspace-é".into());
    item.workspace_label_source = Some("directory_name".into());
    let labelled = snapshot_semantic_component_hashes(SnapshotSource::Pi, &item);
    assert_eq!(
        labelled["display_identity"],
        "46c434ea2ff002ab27b237f315da1d744fd08651fb8c2635702234a4d7cbef20"
    );
    assert_eq!(
        snapshot_content_hash(SnapshotSource::Pi, &item.source_session_id, &old),
        snapshot_content_hash(SnapshotSource::Pi, &item.source_session_id, &labelled)
    );
}
