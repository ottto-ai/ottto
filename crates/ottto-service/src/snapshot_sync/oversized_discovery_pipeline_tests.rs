// Real bounded scan -> local evidence/family fold -> binding -> upload/ACK ->
// durable save/reload. Sparse oversized fixtures do not parse 512 MiB.
use super::*;

const OVERSIZED_BYTES: u64 = 512 * 1024 * 1024 + 1;
const OVERSIZED_SESSION: &str = "e9000000-0000-4000-8000-000000000009";

fn oversized_path(fixture: &RearmFixture) -> PathBuf {
    fixture.root.join(format!("{OVERSIZED_SESSION}.jsonl"))
}

fn oversized_create(fixture: &RearmFixture) -> PathBuf {
    let path = oversized_path(fixture);
    std::fs::File::create(&path)
        .unwrap()
        .set_len(OVERSIZED_BYTES)
        .unwrap();
    path
}

fn oversized_seed(case: &'static str) -> (RearmFixture, PathBuf) {
    let fixture = c1a_fixture(case);
    let closed = c1b_generation(&fixture, "oversized", (8, 0));
    assert!(closed.census_complete && closed.proven);
    let path = oversized_create(&fixture);
    let seed = c1b_generation(&fixture, "oversized", (8, 10));
    assert!(seed.red && !seed.census_complete);
    let saved = c1a_saved(&fixture);
    assert_eq!(saved["traversal"]["counts"]["oversized_file_count"], 1);
    assert_eq!(
        saved["traversal"]["oversized_discovery"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    (fixture, path)
}

fn oversized_deadline(saved: &serde_json::Value) -> u64 {
    saved["traversal"]["unhealthy_retry_not_before_unix_seconds"]
        .as_u64()
        .unwrap()
}

fn oversized_clock(now: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(now as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn oversized_tick(fixture: &RearmFixture, now: u64) -> RearmPage {
    let (page, rows) = crate::local_resource_diagnostics::capture(|| {
        fixture.page(&oversized_clock(now), RearmUpload::Accept)
    });
    assert!(
        rows.iter().all(|row| {
            row["stage"] != "bounded_traversal_transition" || row["counts"]["event"] != "starting"
        }),
        "scoped discovery never restarts the traversal or stale family debt"
    );
    page
}

#[test]
#[serial(source_manifests)]
fn oversized_unchanged_has_no_clock_restarts_and_keeps_incomplete_disclosure() {
    if !c1a_layout_supported("oversized-unchanged") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let (fixture, _) = oversized_seed("oversized-unchanged");
    let saved = c1a_saved(&fixture);
    let latch = c1a_latch(&fixture);
    for offset in [0, 3600, 7200, 5 * 3600] {
        let page = oversized_tick(&fixture, oversized_deadline(&saved) + offset);
        assert!(!page.scan.census_complete);
        assert_eq!(
            page.scan.oversized_file_count, 1,
            "existing disclosure stays visible"
        );
        assert_eq!(page.scan.scanned_file_count, 0);
        let current = c1a_saved(&fixture);
        assert_eq!(current["traversal"], saved["traversal"]);
        assert_eq!(c1a_latch(&fixture), latch);
    }
    // The only new durable content consists of hashes plus a sighting count.
    for (key, debt) in saved["traversal"]["oversized_discovery"]
        .as_object()
        .unwrap()
    {
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let hash = debt["content_hash"].as_str().unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(debt.as_object().unwrap().len(), 2);
    }
}

#[test]
#[serial(source_manifests)]
fn oversized_growth_retries_only_its_discovery_then_shrink_admits_it() {
    if !c1a_layout_supported("oversized-growth") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let (fixture, path) = oversized_seed("oversized-growth");
    let before = c1a_saved(&fixture);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(OVERSIZED_BYTES + 100)
        .unwrap();
    let now = oversized_deadline(&before);
    let page = oversized_tick(&fixture, now);
    assert!(!page.scan.census_complete);
    assert_eq!(page.scan.oversized_file_count, 1);
    assert_eq!(page.scan.scanned_file_count, 0);
    let retried = c1a_saved(&fixture);
    assert_ne!(
        retried["traversal"]["oversized_discovery"],
        before["traversal"]["oversized_discovery"]
    );
    assert_eq!(
        retried["traversal"]["census_window_end"],
        before["traversal"]["census_window_end"]
    );
    assert_eq!(oversized_deadline(&retried), now + 120);
    oversized_tick(&fixture, oversized_deadline(&retried) + 1);
    assert_eq!(
        c1a_saved(&fixture)["traversal"],
        retried["traversal"],
        "one content change gives one retry"
    );
    std::fs::write(
        &path,
        rearm_transcript_line(OVERSIZED_SESSION, None, "req_shrunk", 0),
    )
    .unwrap();
    let page = oversized_tick(&fixture, oversized_deadline(&retried) + 2);
    assert_eq!(page.scan.oversized_file_count, 0);
    assert!(
        page.parsed.contains(OVERSIZED_SESSION),
        "a content change retries actual discovery and parsing"
    );
}

#[test]
#[serial(source_manifests)]
fn oversized_same_size_sample_edit_wakes_discovery() {
    if !c1a_layout_supported("oversized-sample-edit") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let (fixture, path) = oversized_seed("oversized-sample-edit");
    let before = c1a_saved(&fixture);
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.write_all(b"changed sampled bytes").unwrap();
    let page = oversized_tick(&fixture, oversized_deadline(&before));
    assert!(!page.scan.census_complete);
    let after = c1a_saved(&fixture);
    assert_ne!(
        after["traversal"]["oversized_discovery"],
        before["traversal"]["oversized_discovery"]
    );
    assert_eq!(
        oversized_deadline(&after),
        oversized_deadline(&before) + 120
    );
}

#[test]
#[serial(source_manifests)]
#[cfg_attr(not(target_os = "macos"), ignore = "runs macOS /usr/bin/xattr")]
fn oversized_metadata_only_touches_give_zero_wakes() {
    if !c1a_layout_supported("oversized-metadata") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let (mut fixture, path) = oversized_seed("oversized-metadata");
    fixture.hinted_paths.push(path.clone());
    let before = c1a_saved(&fixture);
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let original_modified = file.metadata().unwrap().modified().unwrap();
    file.set_modified(original_modified + std::time::Duration::from_secs(3600))
        .unwrap();
    let original_permissions = file.metadata().unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    // xattr writes also move ctime. Spotlight/backup attributes must not wake
    // discovery; only the content marker is compared by the production seam.
    assert!(std::process::Command::new("/usr/bin/xattr")
        .args(["-w", "com.ottto.synthetic-metadata-touch", "test"])
        .arg(&path)
        .status()
        .unwrap()
        .success());
    assert_ne!(
        file.metadata().unwrap().modified().unwrap(),
        original_modified
    );
    for offset in [0, 60, 3600] {
        let page = oversized_tick(&fixture, oversized_deadline(&before) + offset);
        assert!(!page.scan.census_complete);
        assert_eq!(c1a_saved(&fixture)["traversal"], before["traversal"]);
        assert_eq!(page.scan.scanned_file_count, 0);
    }
    std::fs::set_permissions(&path, original_permissions).unwrap();
}

#[test]
#[serial(source_manifests)]
fn oversized_does_not_suppress_another_retryable_problem() {
    if !c1a_layout_supported("oversized-other-problem") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let fixture = c1a_fixture("oversized-other-problem");
    assert!(c1b_generation(&fixture, "oversized", (8, 0)).census_complete);
    oversized_create(&fixture);
    RearmFixture::append(&c1b_sibling_path(&fixture), "not-json\n");
    let seed = c1b_generation(&fixture, "oversized", (8, 10));
    assert!(seed.red && !seed.census_complete);
    let before = c1a_saved(&fixture);
    assert_eq!(
        before["traversal"]["counts"]["malformed_json_line_count"],
        1
    );
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        fixture.page(
            &oversized_clock(oversized_deadline(&before)),
            RearmUpload::Accept,
        )
    });
    let start = rows
        .iter()
        .find(|row| {
            row["stage"] == "bounded_traversal_transition" && row["counts"]["event"] == "starting"
        })
        .unwrap();
    assert_eq!(start["counts"]["reason"], "terminal_unhealthy_retry");
    assert_eq!(
        start["counts"]["previous"]["counts"]["oversized_file_count"],
        1
    );
}

#[test]
#[serial(source_manifests)]
fn oversized_keeps_complete_families_empty_and_refuses_absence_retirement_sweep_wide() {
    if !c1a_layout_supported("oversized-complete-families") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    // Even a fully readable family cannot be newly proven while unread
    // content anywhere could contain another member or copy of that family.
    let fixture = c1a_fixture("oversized-complete-families");
    oversized_create(&fixture);
    let partial = c1b_generation(&fixture, "oversized", (8, 0));
    assert!(partial.red && !partial.census_complete && !partial.proven);
    let index = ScanIndex::load(&fixture.index_path).unwrap();
    assert!(index
        .claude_usage_family_witness_digest_for_test(REARM_ROOT)
        .is_none());
    // Remove every readable member of a previously proven family while an
    // unrelated oversized file could still hide another member or copy.
    let fixture = c1a_fixture("oversized-absence-fence");
    let closed = c1b_generation(&fixture, "oversized", (8, 0));
    assert!(closed.census_complete && closed.proven);
    // The first proof re-arms its members. Replay that real debt before
    // binding quarantine to current, nonempty source revisions.
    let replayed = c1b_generation(&fixture, "oversized", (8, 5));
    assert!(replayed.census_complete && replayed.proven);
    let mut index = ScanIndex::load(&fixture.index_path).unwrap();
    assert_eq!(RearmFixture::family_rearm_debt(&index), 0);
    let witness = index
        .claude_usage_family_witness_digest_for_test(REARM_ROOT)
        .unwrap();
    let members = RearmFixture::family_keys(&index)
        .into_iter()
        .map(|(session, key)| (session, index.files[&key].source_file_fingerprint.clone()))
        .collect();
    index.bind_retry_pending_claude_authority_for_test(REARM_ROOT, members);
    index.save(&fixture.index_path).unwrap();
    let before = c1a_saved(&fixture);
    std::fs::remove_file(fixture.root.join(format!("{REARM_ROOT}.jsonl"))).unwrap();
    std::fs::remove_dir_all(fixture.root.join(REARM_ROOT)).unwrap();
    oversized_create(&fixture);
    let red = c1b_generation(&fixture, "oversized", (8, 10));
    assert!(red.red && !red.census_complete);
    let saved = c1a_saved(&fixture);
    let page = oversized_tick(&fixture, oversized_deadline(&saved) + 3600);
    assert!(!page.scan.census_complete);
    assert_eq!(page.scan.oversized_file_count, 1);
    assert_eq!(
        page.index
            .claude_usage_family_witness_digest_for_test(REARM_ROOT),
        Some(witness)
    );
    assert!(page
        .index
        .claude_authority_record_for_test(REARM_ROOT)
        .is_some_and(|record| !record.terminal));
    assert_eq!(
        RearmFixture::family_heads(&page.index),
        RearmFixture::family_heads(&index),
        "no family retraction or absent-member reconciliation"
    );
    assert_eq!(
        c1a_saved(&fixture)["claude_retired_family_tombstones"],
        before["claude_retired_family_tombstones"]
    );
}

fn oversized_floor(saved: &serde_json::Value) -> u64 {
    time::OffsetDateTime::parse(
        saved["traversal"]["census_window_end"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp() as u64
        + 6 * 3600
}

/// Real pages, including durable reload at each boundary, until exhaustion.
fn oversized_walk(
    fixture: &RearmFixture,
    now: u64,
    first_upload: RearmUpload,
) -> (Vec<RearmPage>, Vec<serde_json::Value>) {
    let mut pages = Vec::new();
    let mut transitions = Vec::new();
    for number in 0..C1B_MAX_PAGES {
        let upload = if number == 0 {
            first_upload
        } else {
            RearmUpload::Accept
        };
        let (page, rows) = crate::local_resource_diagnostics::capture(|| {
            fixture.page(&oversized_clock(now + number as u64), upload)
        });
        transitions.extend(rows.into_iter().filter(|row| {
            row["stage"] == "bounded_traversal_transition" && row["counts"]["event"] == "starting"
        }));
        let (ended, _) = c1b_traversal_ended(&page.index);
        pages.push(page);
        if ended {
            return (pages, transitions);
        }
    }
    panic!("oversized traversal must exhaust within the existing page bound");
}

#[test]
#[serial(source_manifests)]
fn oversized_shed_upload_is_reoffered_at_the_original_retry_deadline() {
    if !c1a_layout_supported("oversized-shed-recovery") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let fixture = c1a_fixture("oversized-shed-recovery");
    oversized_create(&fixture);
    let start = time::OffsetDateTime::parse(
        "2026-08-02T08:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp() as u64;
    let (pages, _) = oversized_walk(&fixture, start, RearmUpload::Shed);
    let first = &pages[0];
    assert!(!first.fully_settled);
    let owed = first
        .scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == REARM_ROOT)
        .expect("the shed page offered the root session");
    assert!(first.offered.contains(&owed.snapshot_fingerprint));
    assert!(first.uploaded.is_empty());
    let saved = c1a_saved(&fixture);
    assert_eq!(saved["traversal"]["counts"]["oversized_file_count"], 1);
    assert!(pages
        .last()
        .unwrap()
        .index
        .bounded_sweep_unsettled_cause_names()
        .contains(&"shed"));
    let deadline = oversized_deadline(&saved);
    assert!(deadline < oversized_floor(&saved));
    oversized_tick(&fixture, deadline - 1);
    let (retry, starts) = oversized_walk(&fixture, deadline, RearmUpload::Accept);
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0]["counts"]["reason"], "terminal_unhealthy_retry");
    assert!(
        retry
            .iter()
            .any(|page| page.scan.snapshots.iter().any(|item| {
                item.source_session_id == REARM_ROOT
                    && page.offered.contains(&item.snapshot_fingerprint)
                    && page.uploaded.contains(&item.snapshot_fingerprint)
            })),
        "the shed session reaches the real uploader and ACK on the old cadence"
    );
    assert!(!retry.last().unwrap().scan.census_complete);
}

#[test]
#[serial(source_manifests)]
fn oversized_blocking_hold_is_reoffered_once_per_six_hour_floor() {
    // Legacy demotion hold; E2 literals bypass it, so only the listed held
    // family reaches it (real list, loaded by every page after an unlisted
    // baseline). Gate-on local holds and the same six-hour floor:
    // oversized_request_owned_hold_is_reoffered_once_per_six_hour_floor.

    let _manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new("oversized-blocking-hold-floor");
    fixture.baseline();
    fixture.list_held(&[PIPELINE_HELD_SESSION]);
    let revision = fixture.seed_terminal_authority(PIPELINE_HELD_SESSION);
    let oversized = fixture.root.join(format!("{OVERSIZED_SESSION}.jsonl"));
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(OVERSIZED_BYTES)
        .unwrap();
    // The production replay reset leaves this real demotion hold no committed
    // entry to restore. Completed settlement must keep it progress-blocking.
    let cycle = PipelineCycle {
        replay_generation: "replay-generation-reset",
        proven_owner_session: Some(PIPELINE_HELD_SESSION),
        historical_replay: true,
        ..PIPELINE_HOLD_CYCLE
    };
    let walk = |now: u64| {
        let mut pages = Vec::new();
        let mut starts = Vec::new();
        for number in 0..C1B_MAX_PAGES {
            let (page, rows) = crate::local_resource_diagnostics::capture(|| {
                fixture.page(
                    &oversized_clock(now + number as u64),
                    &cycle,
                    PipelineUpload::Accept,
                )
            });
            if let Some(start) = transition_row(&rows, "starting") {
                starts.push(start);
            }
            let ended = c1b_traversal_ended(&page.index).0;
            pages.push(page);
            if ended {
                return (pages, starts);
            }
        }
        panic!("hold floor traversal must exhaust");
    };
    let at = time::OffsetDateTime::parse(
        "2026-08-02T09:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp() as u64;
    let (seed, starts) = walk(at);
    assert_eq!(starts.len(), 1);
    assert_eq!(seed.iter().map(|page| page.held.len()).sum::<usize>(), 1);
    assert_listed_fold_absent(&seed, PIPELINE_HELD_SESSION);
    let held = seed
        .iter()
        .flat_map(|page| page.held.iter())
        .next()
        .unwrap()
        .clone();
    let saved = serde_json::to_value(&seed.last().unwrap().index).unwrap();
    assert_eq!(saved["traversal"]["counts"]["oversized_file_count"], 1);
    assert_eq!(
        seed.last()
            .unwrap()
            .index
            .bounded_sweep_unsettled_cause_names(),
        ["completed_blocking_holds"]
    );
    let mut floor = oversized_floor(&saved);
    for _ in 0..2 {
        for now in [floor - 5 * 3600, floor - 3600, floor - 1] {
            if now == floor - 1 {
                // A content wake immediately before the floor installs a
                // future ordinary deadline. It must not postpone the re-walk.
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&oversized)
                    .unwrap()
                    .set_len(OVERSIZED_BYTES + floor)
                    .unwrap();
            }
            let (quiet, starts) = walk(now);
            assert!(starts.is_empty(), "no hourly re-walk for a blocking hold");
            assert!(quiet.iter().all(|page| page.held.is_empty()));
            assert!(!quiet.last().unwrap().scan.census_complete);
            if now == floor - 1 {
                assert!(
                    oversized_deadline(
                        &serde_json::to_value(&quiet.last().unwrap().index).unwrap()
                    ) > floor
                );
            }
        }
        let (retry, starts) = walk(floor);
        assert_eq!(starts.len(), 1, "exactly one re-walk at the floor");
        assert_eq!(starts[0]["counts"]["reason"], "terminal_unhealthy_retry");
        assert_eq!(retry.iter().map(|page| page.held.len()).sum::<usize>(), 1);
        assert_listed_fold_absent(&retry, PIPELINE_HELD_SESSION);
        assert!(
            retry.iter().any(|page| page.held.contains(&held)),
            "the same demoted body is offered to real hold classification again"
        );
        assert!(retry.iter().all(|page| !page.uploaded.contains(&held)));
        let last = retry.last().unwrap();
        assert!(!last.scan.census_complete);
        assert_eq!(last.scan.oversized_file_count, 1);
        assert_eq!(
            last.index
                .bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION),
            Some(revision.clone())
        );
        let next_floor = oversized_floor(&serde_json::to_value(&last.index).unwrap());
        assert_eq!(next_floor, floor + 6 * 3600);
        floor = next_floor;
    }
}

#[test]
#[serial(source_manifests)]
fn oversized_restart_discovers_and_uploads_a_new_file_without_hints_within_floor() {
    if !c1a_layout_supported("oversized-restart-no-hints") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let (fixture, _) = oversized_seed("oversized-restart-no-hints");
    let saved = c1a_saved(&fixture);
    let floor = oversized_floor(&saved);
    let restarted = ScanIndex::load(&fixture.index_path).unwrap();
    assert_eq!(c1b_traversal_ended(&restarted), (true, true));
    assert_eq!(
        serde_json::to_value(&restarted).unwrap()["traversal"],
        saved["traversal"]
    );
    assert!(fixture.hinted_paths.is_empty());
    const NEW_SESSION: &str = "e8000000-0000-4000-8000-000000000008";
    std::fs::write(
        fixture.root.join(format!("{NEW_SESSION}.jsonl")),
        rearm_transcript_line(NEW_SESSION, None, "req_no_hint", 0),
    )
    .unwrap();
    // Every fixture page independently reloads the exhausted checkpoint: no
    // process-local state or watcher input can discover this file for it.
    let quiet = oversized_tick(&fixture, floor - 1);
    assert!(!quiet.parsed.contains(NEW_SESSION));
    let (retry, starts) = oversized_walk(&fixture, floor, RearmUpload::Accept);
    assert_eq!(starts.len(), 1);
    assert!(retry.iter().any(|page| page.parsed.contains(NEW_SESSION)));
    assert!(
        retry
            .iter()
            .any(|page| page.scan.snapshots.iter().any(|item| {
                item.source_session_id == NEW_SESSION
                    && page.offered.contains(&item.snapshot_fingerprint)
                    && page.uploaded.contains(&item.snapshot_fingerprint)
            })),
        "no-hint discovery reaches the real uploader and durable ACK"
    );
    assert!(!retry.last().unwrap().scan.census_complete);
    assert_eq!(retry.last().unwrap().scan.oversized_file_count, 1);
    assert!(fixture.hinted_paths.is_empty());
}

#[test]
#[serial(source_manifests)]
fn oversized_two_files_retry_only_changed_content_and_keep_exact_count() {
    if !c1a_layout_supported("oversized-two-files") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let fixture = c1a_fixture("oversized-two-files");
    let closed = c1b_generation(&fixture, "oversized-two", (8, 0));
    assert!(closed.census_complete && closed.proven);
    let changed = oversized_create(&fixture);
    let unchanged = fixture
        .root
        .join("e8000000-0000-4000-8000-000000000008.jsonl");
    std::fs::File::create(&unchanged)
        .unwrap()
        .set_len(OVERSIZED_BYTES)
        .unwrap();
    let seed = c1b_generation(&fixture, "oversized-two", (8, 10));
    assert!(seed.red && !seed.census_complete);
    let before = c1a_saved(&fixture);
    let debts = before["traversal"]["oversized_discovery"]
        .as_object()
        .unwrap();
    assert_eq!(debts.len(), 2);
    assert_eq!(before["traversal"]["counts"]["oversized_file_count"], 2);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&changed)
        .unwrap()
        .set_len(OVERSIZED_BYTES + 100)
        .unwrap();
    let page = oversized_tick(&fixture, oversized_deadline(&before));
    let grown = c1a_saved(&fixture);
    let grown_debts = grown["traversal"]["oversized_discovery"]
        .as_object()
        .unwrap();
    assert_eq!(grown_debts.len(), 2);
    assert_eq!(
        debts
            .iter()
            .filter(|(key, debt)| grown_debts[*key] != **debt)
            .count(),
        1
    );
    assert_eq!(page.scan.oversized_file_count, 2);
    assert_eq!(page.scan.scanned_file_count, 0);
    assert_eq!(
        grown["traversal"]["census_window_end"],
        before["traversal"]["census_window_end"]
    );
    // Shrink only that same file, leaving the other cap refusal intact.
    std::fs::write(
        &changed,
        rearm_transcript_line(OVERSIZED_SESSION, None, "req_one_shrunk", 0),
    )
    .unwrap();
    let page = oversized_tick(&fixture, oversized_deadline(&grown));
    let after = c1a_saved(&fixture);
    let remaining = after["traversal"]["oversized_discovery"]
        .as_object()
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert!(
        remaining.iter().all(|(key, debt)| debts[key] == *debt),
        "the unchanged file's marker and count never change"
    );
    assert_eq!(page.scan.oversized_file_count, 1);
    assert!(page.parsed.contains(OVERSIZED_SESSION));
    assert_eq!(page.scan.scanned_file_count, 1);
    assert!(!page.scan.census_complete);
}

/// E2 holds stay progress-blocking beside an oversized file and are offered
/// again at the same recovery floor, never cancelled or uploaded while held.
#[test]
#[serial(source_manifests)]
fn oversized_request_owned_hold_is_reoffered_once_per_six_hour_floor() {
    if !c1a_layout_supported("oversized-e2-hold-floor") {
        return;
    }

    let _manifests = SourceManifestTestGuard::new();
    let mut fixture = c1a_fixture("oversized-e2-hold-floor");
    crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(&fixture.support, &[]);
    fixture.owned_base_preparation = true;
    fixture.local_holds.insert(REARM_ROOT.to_owned());
    let oversized = oversized_create(&fixture);
    let at = time::OffsetDateTime::parse(
        "2026-08-02T09:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp() as u64;
    let (seed, starts) = oversized_walk(&fixture, at, RearmUpload::Accept);
    assert_eq!(starts.len(), 1);
    let assert_held = |pages: &[RearmPage]| {
        // classify removes held bodies from scan.snapshots before upload. The
        // existing finalizer trace captures their exact body before that cut.
        let trace = fixture.body_trace.borrow();
        let body = trace
            .finalizer_bodies
            .get(REARM_ROOT)
            .expect("the held root is re-offered");
        assert_eq!(
            body["usage_accounting_contract"],
            crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT
        );
        let fingerprint = body["snapshot_fingerprint"].as_str().unwrap();
        assert!(pages.iter().any(|page| page.parsed.contains(REARM_ROOT)));
        assert!(pages.iter().any(|page| page.held.contains(fingerprint)));
        assert!(pages.iter().all(
            |page| !page.offered.contains(fingerprint) && !page.uploaded.contains(fingerprint)
        ));
        let last = pages.last().unwrap();
        assert!(!last.scan.census_complete);
        assert_eq!(last.scan.oversized_file_count, 1);
        assert_eq!(
            last.index.bounded_sweep_unsettled_cause_names(),
            ["completed_blocking_holds"]
        );
        assert!(last
            .index
            .bound_terminal_claude_authority_revision_for_test(REARM_ROOT)
            .is_none());
    };
    assert_held(&seed);
    let mut floor = oversized_floor(&c1a_saved(&fixture));
    for _ in 0..2 {
        for now in [floor - 5 * 3600, floor - 3600, floor - 1] {
            if now == floor - 1 {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&oversized)
                    .unwrap()
                    .set_len(OVERSIZED_BYTES + floor)
                    .unwrap();
            }
            let quiet = oversized_tick(&fixture, now);
            assert!(quiet.held.is_empty());
            assert!(!quiet.scan.census_complete);
            if now == floor - 1 {
                assert!(oversized_deadline(&c1a_saved(&fixture)) > floor);
            }
        }
        *fixture.body_trace.borrow_mut() = RearmBodyTrace::default();
        let (retry, starts) = oversized_walk(&fixture, floor, RearmUpload::Accept);
        assert_eq!(starts.len(), 1, "one recovery walk at the floor");
        assert_eq!(starts[0]["counts"]["reason"], "terminal_unhealthy_retry");
        assert_held(&retry);
        let next_floor = oversized_floor(&c1a_saved(&fixture));
        assert_eq!(next_floor, floor + 6 * 3600);
        floor = next_floor;
    }
}
