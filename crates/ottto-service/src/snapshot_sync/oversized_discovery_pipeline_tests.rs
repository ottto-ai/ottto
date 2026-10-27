// Real bounded scan -> local evidence/family fold -> binding -> upload/ACK ->
// durable save/reload. Sparse oversized fixtures do not parse 256 MiB.
use super::*;

const OVERSIZED_BYTES: u64 = 256 * 1024 * 1024 + 1;
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
    for offset in [0, 3600, 7200, 86400] {
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
fn oversized_minutely_growth_is_bounded_by_existing_exponential_cadence() {
    if !c1a_layout_supported("oversized-cadence") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let (mut fixture, path) = oversized_seed("oversized-cadence");
    fixture.hinted_paths.push(path.clone());
    let mut saved = c1a_saved(&fixture);
    let start = oversized_deadline(&saved);
    let mut wakes = 0;
    // Reach the hourly ceiling and cover two full hourly windows at it.
    for minute in 0..190 {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(OVERSIZED_BYTES + minute + 1)
            .unwrap();
        let now = start + minute * 60;
        let previous_deadline = oversized_deadline(&saved);
        let previous_attempt = saved["traversal"]["unhealthy_retry_attempt"]
            .as_u64()
            .unwrap();
        let page = oversized_tick(&fixture, now);
        assert!(!page.scan.census_complete);
        assert_eq!(page.scan.oversized_file_count, 1);
        let next = c1a_saved(&fixture);
        if now < previous_deadline {
            assert_eq!(
                next["traversal"], saved["traversal"],
                "growth within a cadence window is coalesced"
            );
        } else {
            wakes += 1;
            assert_ne!(
                next["traversal"]["oversized_discovery"],
                saved["traversal"]["oversized_discovery"]
            );
            let attempt = (previous_attempt + 1).min(7);
            assert_eq!(next["traversal"]["unhealthy_retry_attempt"], attempt);
            assert_eq!(
                oversized_deadline(&next),
                now + (60 * (1_u64 << (attempt - 1))).min(3600)
            );
        }
        saved = next;
    }
    assert_eq!(wakes, 8, "six exponential retries and two hourly retries");
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
