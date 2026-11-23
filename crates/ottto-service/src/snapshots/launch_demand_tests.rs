//! Synthetic proof that Claude subagent transcripts never demand launch lookup.
//!
//! A subagent is re-keyed from its path before launch facts are read, so neither
//! its parsed parent `sessionId` nor a UUID-looking file stem can own a launch
//! event. Demanding either key discarded the prepared batch for nothing. These
//! tests drive the native scan, parser finish and synchronous reader.
use super::*;
use base64::Engine;

const CONTROLLER: &str = "a9789dcf-1e4a-4a6e-8abd-f30094efb269";
const NOW: &str = "2026-10-07T12:00:00Z";
/// Top-level worker with a valid launch event, scanned in the same page.
const TOP: &str = "019fa111-2222-7333-8444-555555555555";
/// Subagent parents whose top-level transcripts are not in the batch. The first
/// also has a retained launch event, so the old parsed demand could match it.
const PARENTS: [&str; 3] = [
    "11111111-aaaa-4bbb-8ccc-000000000001",
    "11111111-aaaa-4bbb-8ccc-000000000002",
    "11111111-aaaa-4bbb-8ccc-000000000003",
];
/// A UUID-looking subagent stem that also names a retained launch worker.
const UUID_STEM: &str = "22222222-aaaa-4bbb-8ccc-000000000004";

pub(super) struct Home(PathBuf);
impl Home {
    pub(super) fn new() -> Self {
        let path = crate::test_scratch::unique_path("ottto-launch-demand");
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn event(&self, worker: &str) {
        let raw = json!({"schema":"agent_launch.v1", "controller_session_ref":CONTROLLER,
            "worker_session_ref":worker, "relationship_kind":"launched", "workflow_ref":null,
            "pr_ref":null, "launch_ts":"2026-09-20T10:00:00Z",
            "capture_source":"launcher_event:opus_cli_agent", "evidence":"direct"})
        .to_string();
        let reduced = crate::launch_events::validate_event(&raw).unwrap();
        let dir = self.0.join(".ottto/launch-events/processed");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!(
                "{}.json",
                crate::launch_events::event_digest(&reduced)
            )),
            raw,
        )
        .unwrap();
    }
    pub(super) fn fill_retained_events(&self, count: usize) {
        for n in 1..=count {
            self.event(&format!("{n:08x}-2222-3333-4444-555555555555"));
        }
    }
    pub(super) fn block_pending_directory(&self) {
        let root = self.0.join(".ottto/launch-events");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("pending"), b"not a directory").unwrap();
    }
    pub(super) fn context(&self) -> crate::session_attribution::SessionAttributionContext {
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([13_u8; 32]);
        crate::session_attribution::SessionAttributionContext::from_activity_hint(
            SnapshotSource::ClaudeCode,
            &self.0,
            true,
            Some(&key),
            Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn transcript(session: &str, request: &str, sidechain: bool) -> String {
    format!(
        "{}\n{}\n",
        json!({"type":"user","sessionId":session,"isSidechain":sidechain,
            "timestamp":"2026-10-07T10:00:00Z","message":{"role":"user","content":"Synthetic fixture"}}),
        json!({"type":"assistant","sessionId":session,"isSidechain":sidechain,
            "timestamp":"2026-10-07T10:01:00Z","requestId":format!("req-{request}"),
            "message":{"id":format!("msg-{request}"),"model":"fixture-model",
                "usage":{"input_tokens":100,"output_tokens":20}}}),
    )
}

/// One top-level worker plus a Task subagent of it, a Task subagent and a
/// Workflow agent of unbatched parents, and a UUID-stem subagent.
struct Transcripts {
    root: PathBuf,
    /// (path, re-keyed session id, direct parent)
    subagents: Vec<(PathBuf, String, &'static str)>,
}

fn transcripts(home: &Home) -> Transcripts {
    let root = home.0.join(".claude/projects");
    let project = root.join("fixture-project");
    let top = project.join(format!("{TOP}.jsonl"));
    fs::create_dir_all(&project).unwrap();
    fs::write(&top, transcript(TOP, "top", false)).unwrap();
    let mut subagents = Vec::new();
    for (parent, relative, stem) in [
        (TOP, "subagents", "agent-0000000000000000a"),
        (PARENTS[0], "subagents", "agent-0000000000000000b"),
        (
            PARENTS[1],
            "subagents/workflows/wf_fixture-01",
            "agent-0000000000000000c",
        ),
        (PARENTS[2], "subagents", UUID_STEM),
    ] {
        let dir = project.join(parent).join(relative);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{stem}.jsonl"));
        fs::write(&path, transcript(parent, stem, true)).unwrap();
        subagents.push((path, format!("{parent}_{stem}"), parent));
    }
    Transcripts { root, subagents }
}

fn has_launcher_fact(item: &SnapshotItem) -> bool {
    item.attribution_facts
        .iter()
        .any(|fact| fact.evidence.kind == "launcher_event")
}

fn has_parent(item: &SnapshotItem, parent: &str) -> bool {
    item.attribution_facts
        .iter()
        .any(|fact| fact.field == "parent_session_ref" && fact.value == parent)
}

fn assert_subagent_without_launch_lineage(item: &SnapshotItem, parent: &str) {
    assert!(has_parent(item, parent), "{}", item.source_session_id);
    assert!(!has_parent(item, CONTROLLER), "{}", item.source_session_id);
    assert!(!has_launcher_fact(item), "{}", item.source_session_id);
}

fn scan(
    home: &Home,
    root: &Path,
) -> (
    ScanIndex,
    SourceScanResult,
    usize,
    crate::session_attribution::SessionAttributionContext,
) {
    let context = home.context();
    let mut state = new_scan(root);
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 10000, "lookup/scan must make finite progress");
        match state.step(Some(&context)) {
            OwnedSourceScanStep::Pending(next) => state = next,
            OwnedSourceScanStep::Complete {
                mut index,
                mut scan,
                ..
            } => {
                apply_upload_policy(
                    SnapshotSource::ClaudeCode,
                    &mut scan.snapshots,
                    SnapshotUploadPolicy {
                        session_attribution_enabled: true,
                        ..SnapshotUploadPolicy::default()
                    },
                );
                finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
                return (index, scan, steps, context);
            }
        }
    }
}

fn new_scan(root: &Path) -> OwnedSourceScan {
    OwnedSourceScan::new(
        SnapshotSource::ClaudeCode,
        &[root.to_path_buf()],
        ScanIndex::default(),
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        None,
        &[],
        false,
    )
    .with_sampled_acquisition(
        Arc::new(sampled_scan::SharedCache::default()),
        crate::transcript_acquisition::Scope("launch-demand-fixture".into()),
    )
}

fn item<'a>(scan: &'a SourceScanResult, session: &str) -> &'a SnapshotItem {
    scan.snapshots
        .iter()
        .find(|item| item.source_session_id == session)
        .unwrap_or_else(|| panic!("missing snapshot for {session}"))
}

#[test]
fn subagents_with_unbatched_parents_keep_one_prepared_native_batch() {
    let home = Home::new();
    let control_home = Home::new();
    let fixture = transcripts(&home);
    for worker in [TOP, PARENTS[0], UUID_STEM] {
        home.event(worker);
    }
    // Enough retained claims that every full sweep spans several native steps.
    home.fill_retained_events(1100);
    let probe = home.context();
    let mut sweep_steps = 0;
    while !probe
        .launch_events()
        .prepare_step(&[TOP.to_owned()])
        .unwrap()
    {
        sweep_steps += 1;
    }
    assert!(sweep_steps > 4, "one retained-store sweep crosses steps");

    let (control_index, control, control_steps, _) = scan(&control_home, &fixture.root);
    let (index, launched, launched_steps, context) = scan(&home, &fixture.root);
    assert_eq!(control.snapshots.len(), 5);
    assert_eq!(launched.snapshots.len(), 5);
    assert_eq!(launched.unreadable_path_count, 0);
    // Each subagent of an unbatched parent used to reset the batch to that
    // parsed parent at finish, and a later UUID-stem front rebuilt the batch:
    // at least four full sweeps here, none of them for a usable fact key.
    assert!(
        launched_steps <= control_steps + 2 * sweep_steps,
        "subagents must not resweep the retained store: {launched_steps} vs {control_steps} + 2x{sweep_steps}"
    );

    let top = item(&launched, TOP);
    assert!(
        has_parent(top, CONTROLLER),
        "top-level launch edge survives"
    );
    assert!(top
        .attribution_facts
        .iter()
        .any(|fact| fact.field == "agent_kind" && fact.value == "opus-cli-agent"));
    assert!(context.launch_events().prepared(&[TOP.to_owned()]));
    for (_, session, parent) in &fixture.subagents {
        let launched_item = item(&launched, session);
        assert_subagent_without_launch_lineage(launched_item, parent);
        assert_eq!(
            launched_item.snapshot_fingerprint,
            item(&control, session).snapshot_fingerprint,
            "subagent canonical body does not depend on launch evidence"
        );
    }
    let subagent_entries = control_index
        .files
        .iter()
        .filter(|(key, _)| key.contains("/subagents/"))
        .collect::<Vec<_>>();
    assert_eq!(subagent_entries.len(), fixture.subagents.len());
    for (key, entry) in subagent_entries {
        assert_eq!(
            index.files[key].source_file_fingerprint, entry.source_file_fingerprint,
            "no launch witness for a subagent, even a UUID stem that names a worker"
        );
    }
}

#[test]
fn incomplete_lookup_holds_top_level_workers_but_not_subagents() {
    let home = Home::new();
    let fixture = transcripts(&home);
    home.event(TOP);
    // A regular file where the inbox directory belongs fails every sweep.
    home.block_pending_directory();
    let (_, result, _, context) = scan(&home, &fixture.root);
    assert!(!context.launch_events().prepared(&[TOP.to_owned()]));
    assert!(
        result.unreadable_path_count > 0,
        "top-level worker stays owed"
    );
    assert!(result
        .snapshots
        .iter()
        .all(|item| item.source_session_id != TOP));
    for (_, session, parent) in &fixture.subagents {
        // The owed top-level worker's own family is not this change's decision;
        // every unbatched-parent subagent must finish without launch proof.
        if *parent == TOP {
            if let Some(child) = result
                .snapshots
                .iter()
                .find(|item| &item.source_session_id == session)
            {
                assert_subagent_without_launch_lineage(child, parent);
            }
            continue;
        }
        assert_subagent_without_launch_lineage(item(&result, session), parent);
    }
}

#[test]
fn unfinished_launch_batch_leaves_the_selection_untouched() {
    let home = Home::new();
    let fixture = transcripts(&home);
    let second = PARENTS[0];
    fs::write(
        fixture
            .root
            .join("fixture-project")
            .join(format!("{second}.jsonl")),
        transcript(second, "second", false),
    )
    .unwrap();
    home.fill_retained_events(300);
    let context = home.context();
    let events = context.launch_events();
    let workers = [TOP.to_owned(), second.to_owned()];
    let mut scan = new_scan(&fixture.root);
    scan.identified_candidates.retain(|candidate| {
        candidate
            .path
            .file_stem()
            .is_some_and(|stem| stem == TOP || stem == second)
    });
    let before = scan.trace_projection();
    let candidates = |scan: &OwnedSourceScan| {
        scan.identified_candidates
            .iter()
            .map(|candidate| candidate.path.clone())
            .collect::<Vec<_>>()
    };
    let selected = candidates(&scan);
    assert_eq!(selected.len(), workers.len());
    for step in 0..32 {
        let OwnedSourceScanStep::Pending(next) = scan.step(Some(&context)) else {
            panic!("the first batch must prepare before page close");
        };
        if events.prepared(&workers) {
            assert!(step > 0, "the retained store requires more than one step");
            assert!(
                next.active_file.is_some(),
                "prepared batch starts the first file"
            );
            return;
        }
        assert_eq!(next.trace_projection(), before);
        assert_eq!(candidates(&next), selected);
        scan = next;
    }
    panic!("the whole selection's launch batch never prepared");
}
