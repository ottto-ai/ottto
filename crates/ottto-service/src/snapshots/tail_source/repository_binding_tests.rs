//! Session-owned repository observations: compatible facts, shared native
//! capture, restart without a cwd, and display-only folder labels.
use super::seam::tests::{route_for, scope, NOW};
use super::*;
use crate::context_footprint::{resolve_repository_identity, workspace_label};
use crate::snapshots::sampled_scan::transition_fixture::native_cold;
use crate::snapshots::scan_index_persistence::Source;
use serde_json::json;

/// [format] Workspace bytes written by v0.1.221 hydrate without reconstruction;
/// only Workspace accepts v2, and an unbound Workspace still writes v1.
#[test]
fn previous_release_workspace_fact_and_per_kind_versions() {
    // v0.1.221 Fact::Workspace: kind, version, Some, byte length, UTF-8 cwd.
    const PREVIOUS: &[u8] = b"\x02\x01\x01\x12/tmp/prior-release";
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

fn capture_restore<S: TailSource>(
    source: Source,
    lines: Vec<String>,
    apply: fn(&Value, &mut SnapshotAccumulator),
) {
    let mut route = route_for(source);
    let cwd = route.dir.join("workspace");
    fs::create_dir(&cwd).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "-q"])
        .arg(&cwd)
        .status()
        .unwrap()
        .success());
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
    let initial = native.as_ref().unwrap().snapshots.first().unwrap();
    let expected = resolve_repository_identity(&cwd, true);
    assert_eq!(initial.repository_hash, expected.repository_hash);
    assert!(tail.publish(&native));
    route.save(false);
    route.index = ScanIndex::load(&route.path).unwrap();
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
    let missing = resolve_repository_identity(&cwd, true);
    assert_eq!(missing.workspace_kind.as_deref(), Some("unknown"));
    // Neither stale path-cache state nor a later failed measurement wins.
    let items = restored.into_items_with_repository_identity(
        &path,
        "2026-10-20T16:00:00Z",
        "a".repeat(64),
        None,
        Some(missing),
        false,
    );
    assert_eq!(items[0].repository_hash, expected.repository_hash);
    assert_eq!(items[0].repository_label, expected.repository_label);
    assert_eq!(items[0].workspace_kind, expected.workspace_kind);
}

/// [behaviour] Each source's native PRE captures the same binding; a committed
/// restart restores it from database pages after cwd deletion, with no transcript
/// reads or dependency on the process cache.
#[test]
fn every_source_pins_the_native_observation_before_staging() {
    capture_restore::<claude::Claude>(
        Source::Claude,
        claude::tests::lines(2),
        apply_claude_code_line,
    );
    capture_restore::<codex::Codex>(Source::Codex, codex::tests::lines(2), apply_codex_line);
    capture_restore::<pi::Pi>(Source::Pi, vec![
        json!({"type":"session","version":3,"id":"synthetic-folder-session","timestamp":"2026-10-20T16:00:00Z","cwd":"/tmp/pi-folder"}).to_string(),
        json!({"type":"message","id":"a1","timestamp":"2026-10-20T16:01:00Z","message":{"role":"assistant","provider":"openai","model":"gpt-5","responseId":"r1","usage":{"input":10,"output":2,"cacheRead":3,"cacheWrite":4,"totalTokens":19,"cost":{"total":0.001}}}}).to_string(),
    ], apply_pi_line);
}

/// [behaviour] Folder labels use the shared sanitizer and current upload policy.
/// Missing cwd evidence stays retryable, so ordinary selected work can bind later.
#[test]
fn folder_labels_and_failed_lookup_recovery() {
    let route = route_for(Source::Claude);
    let cwd = route.dir.join("new-folder");
    for exists in [false, true] {
        if exists {
            fs::create_dir(&cwd).unwrap();
        }
        let (tail, native) =
            route.complete("session.jsonl", &claude::tests::lines(2), None, |acc| {
                acc.workspace_path = Some(cwd.clone());
            });
        let staged = tail.staged_for_test().unwrap();
        assert_eq!(
            staged.pages[&(Collection::SessionFacts, 2)][1],
            if exists { 2 } else { 1 }
        );
        let mut items = native.unwrap().snapshots;
        assert_eq!(
            items[0].workspace_kind.as_deref(),
            Some(if exists { "non_git" } else { "unknown" })
        );
        assert_eq!(
            items[0].workspace_display_label.as_deref(),
            Some("new-folder")
        );
        assert_eq!(
            items[0].workspace_label_source.as_deref(),
            Some("directory_name")
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
