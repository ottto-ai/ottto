// Paged Claude S0: red and characterization baselines for Claude transcripts
// over the per-file cap (`max_jsonl_file_bytes`). Tests named `*_red_*` assert
// the behavior a later slice must produce and fail on main for the reason in
// their doc comment. Tests named `*_characterization_*` assert today's
// behavior and pass on main; the assertions a fix inverts are marked `FLIPS`.
// Every other assertion is a precondition that must keep holding after the
// fix, so a setup failure fails the test instead of passing as the defect.
//
// Fixtures are synthetic and KiB-sized: `with_test_claude_file_cap` scales the
// Claude cap to `PCS0_CAP` on the test thread only. No test here writes
// cap-sized bytes; the real 256 MiB cap stays pinned by the sparse-file test
// `scan_policy_skips_oversized_non_codex_transcript_files`. Each test writes
// one count-only `PAGED_CLAUDE_S0` line to stderr.

const PCS0_CAP: u64 = 4 * 1024;
const PCS0_WINDOW_DAYS: u64 = 183;
const PCS0_FILE_LIMIT: usize = 64;
const PCS0_T0: &str = "2026-08-02T07:10:00Z";
const PCS0_T1: &str = "2026-08-02T08:10:00Z";
/// The transcript that crosses the cap.
const PCS0_BIG: &str = "e5555555-5555-4555-8555-555555555555";
/// An unrelated single-file family that never crosses it.
const PCS0_SIBLING: &str = "d4444444-4444-4444-8444-444444444444";

fn pcs0_line(session: &str, request: &str, second: usize) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n",
        second % 60
    )
}

struct Pcs0Fixture {
    base: PathBuf,
    root: PathBuf,
    support: PathBuf,
}

impl Pcs0Fixture {
    fn new(name: &str) -> Self {
        // The scan canonicalizes its roots (`/var` is `/private/var` on
        // macOS), so index keys and active paths name the canonical path.
        let base = fs::canonicalize(temp_dir(name)).expect("canonical fixture directory");
        let root = base.join("projects");
        let support = base.join("support");
        fs::create_dir_all(&root).expect("create synthetic Claude root");
        fs::create_dir_all(&support).expect("create support directory");
        Self {
            base,
            root,
            support,
        }
    }

    fn path(&self, session: &str) -> PathBuf {
        self.root.join(format!("{session}.jsonl"))
    }

    fn key(&self, session: &str) -> String {
        local_index_key(&self.path(session))
    }

    fn len(&self, session: &str) -> u64 {
        fs::metadata(self.path(session)).map_or(0, |metadata| metadata.len())
    }

    /// Appends one usage-bearing response per request id.
    fn append<S: AsRef<str>>(&self, session: &str, requests: impl IntoIterator<Item = S>) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path(session))
            .expect("open synthetic Claude transcript");
        for (second, request) in requests.into_iter().enumerate() {
            file.write_all(pcs0_line(session, request.as_ref(), second).as_bytes())
                .expect("append synthetic Claude response");
        }
    }

    /// Appends responses `{prefix}_{n}` from `first` until the transcript is
    /// longer than `PCS0_CAP`. Returns how many it appended.
    fn grow_past_cap(&self, session: &str, prefix: &str, first: usize) -> usize {
        let mut next = first;
        while self.len(session) <= PCS0_CAP {
            self.append(session, [format!("{prefix}_{next}")]);
            next += 1;
        }
        next - first
    }

    /// Paired local OTEL API and trace rows for one root-session request, in
    /// the shape the receiver writes (the stable-proof re-arm fixture's rows).
    fn append_evidence(&self, session: &str, request: &str, sequence: u64) {
        let mut api = crate::claude_local_otel::ClaudeLocalOtelEvidence {
            capture_revision: "claude_api_request:v2".to_string(),
            session_id: session.to_string(),
            request_id: request.to_string(),
            client_request_id: format!("client-{request}"),
            observed_at: format!("2026-08-02T07:00:{sequence:02}Z"),
            model: "claude-haiku-4-5".to_string(),
            effort: "high".to_string(),
            query_source: "user".to_string(),
            speed: "fast".to_string(),
            cost_usd_micros: Some(100),
            event_sequence: Some(sequence),
            app_version: "2.1.226".to_string(),
            input_tokens: 10,
            output_tokens: 10,
            request_count: 1,
            ..Default::default()
        };
        api.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&api).expect("serialize API evidence"))
        );
        let mut trace = crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
            capture_revision: "claude_llm_request_ownership:v1".to_string(),
            session_id: session.to_string(),
            request_id: request.to_string(),
            client_request_id: format!("client-{request}"),
            observed_at: "2026-08-02T07:00:30Z".to_string(),
            ..Default::default()
        };
        trace.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&trace).expect("serialize trace evidence"))
        );
        let name = format!("{:x}.jsonl", Sha256::digest(session.as_bytes()));
        for (kind, line) in [
            (
                "claude-code-effort",
                serde_json::to_string(&api).expect("encode API evidence"),
            ),
            (
                "claude-code-trace-ownership",
                serde_json::to_string(&trace).expect("encode trace evidence"),
            ),
        ] {
            let directory = self.support.join("local-otel").join(kind);
            fs::create_dir_all(&directory).expect("create sidecar directory");
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(directory.join(&name))
                .expect("open synthetic sidecar");
            file.write_all(format!("{line}\n").as_bytes())
                .expect("append synthetic sidecar row");
        }
    }
}

impl Drop for Pcs0Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

struct Pcs0Page {
    scan: SourceScanResult,
    duplicate: ClaudeDuplicateCensusCounts,
}

/// One bounded (unsampled) Claude scan under the scaled cap, then the
/// post-scan stages in `finish_sync_source` order: local evidence and the
/// family fold, upload policy, finalization, and acceptance of every offered
/// body in place of the network.
fn pcs0_page(fixture: &Pcs0Fixture, index: &mut ScanIndex, collected_at: &str) -> Pcs0Page {
    with_test_claude_file_cap(PCS0_CAP, || {
        let mut scan = scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&fixture.root),
            index,
            collected_at,
            PCS0_WINDOW_DAYS,
            PCS0_FILE_LIMIT,
            true,
        )
        .expect("scan bounded Claude page");
        let (disposition, _, _) = crate::snapshot_sync::apply_claude_local_evidence_to_scan(
            &fixture.support,
            &mut scan,
            index,
        );
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, index);
        let accepted = scan
            .snapshots
            .iter()
            .map(|snapshot| snapshot.snapshot_fingerprint.clone())
            .collect();
        index.record_accepted_snapshot_fingerprints(&accepted);
        Pcs0Page {
            scan,
            duplicate: disposition.duplicate_census,
        }
    })
}

/// One sampled Claude scan under the scaled cap, stepped to completion.
fn pcs0_sampled_scan(
    fixture: &Pcs0Fixture,
    index: ScanIndex,
    collected_at: &str,
) -> (ScanIndex, SourceScanResult) {
    with_test_claude_file_cap(PCS0_CAP, || {
        let mut state = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&fixture.root),
            index,
            collected_at,
            PCS0_WINDOW_DAYS,
            PCS0_FILE_LIMIT,
            true,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(
            Arc::new(sampled_scan::SharedCache::default()),
            crate::transcript_acquisition::Scope("paged-claude-s0".into()),
        );
        loop {
            match state.step(None) {
                OwnedSourceScanStep::Pending(next) => state = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
            }
        }
    })
}

fn pcs0_item<'a>(scan: &'a SourceScanResult, session: &str) -> Option<&'a SnapshotItem> {
    scan.snapshots
        .iter()
        .find(|item| item.source_session_id == session)
}

/// The next traversal start: the red traversal's retry deadline, or one hour
/// later when no red traversal is left (a completed census).
fn pcs0_next_restart(index: &ScanIndex, after: &str) -> String {
    let now = rfc3339_unix_seconds(after).expect("fixture clock");
    let at = index
        .traversal
        .as_ref()
        .and_then(|traversal| traversal.unhealthy_retry_not_before_unix_seconds)
        .filter(|deadline| *deadline > now)
        .unwrap_or(now + UNHEALTHY_SCAN_RETRY_MAX_SECONDS);
    OffsetDateTime::from_unix_timestamp(at as i64)
        .expect("restart clock")
        .format(&Rfc3339)
        .expect("format restart clock")
}

/// F17 hook guard (green): the scaled cap applies to Claude only, on this
/// thread, inside the closure; it nests and restores, and the production cap
/// is unchanged outside it.
#[test]
fn paged_claude_s0_cap_hook_is_test_scoped() {
    assert_eq!(
        max_jsonl_file_bytes(SnapshotSource::ClaudeCode),
        MAX_JSONL_FILE_BYTES
    );
    with_test_claude_file_cap(PCS0_CAP, || {
        assert_eq!(max_jsonl_file_bytes(SnapshotSource::ClaudeCode), PCS0_CAP);
        assert_eq!(
            max_jsonl_file_bytes(SnapshotSource::Pi),
            MAX_JSONL_FILE_BYTES
        );
        with_test_claude_file_cap(1, || {
            assert_eq!(max_jsonl_file_bytes(SnapshotSource::ClaudeCode), 1);
        });
        assert_eq!(max_jsonl_file_bytes(SnapshotSource::ClaudeCode), PCS0_CAP);
        let other_thread = std::thread::spawn(|| max_jsonl_file_bytes(SnapshotSource::ClaudeCode))
            .join()
            .expect("join cap probe");
        assert_eq!(other_thread, MAX_JSONL_FILE_BYTES);
    });
    assert_eq!(
        max_jsonl_file_bytes(SnapshotSource::ClaudeCode),
        MAX_JSONL_FILE_BYTES
    );
}

/// RB-1 (design §8.1), RED until paged Claude reads ship (review §6, S3). A
/// Claude transcript over the cap is read on a sampled scan: one snapshot
/// carrying every response before and after the crossing, no oversized
/// count, and a complete census.
///
/// Expected red reason on main: `oversized_file_count == 1` and no snapshot.
/// Discovery counts the file oversized and never queues it
/// (`advance_bounded_directory_traversal_with_budget`, the
/// `max_jsonl_file_bytes` check). The hook scales only the discovery, open and
/// finish caps; S3 must route this read through the paged cursor under its own
/// scaled page limits.
#[test]
fn paged_claude_s0_rb1_red_oversized_transcript_is_read_on_a_sampled_scan() {
    let fixture = Pcs0Fixture::new("paged-claude-s0-rb1");
    let before = 8;
    fixture.append(PCS0_BIG, (0..before).map(|n| format!("req_before_{n}")));
    assert!(
        fixture.len(PCS0_BIG) <= PCS0_CAP,
        "precondition: the first responses fit under the cap"
    );
    let after = fixture.grow_past_cap(PCS0_BIG, "req_after", 0);
    assert!(
        after >= before,
        "precondition: at least as many responses after the crossing"
    );
    let responses = before + after;

    let (_index, scan) = pcs0_sampled_scan(&fixture, ScanIndex::default(), PCS0_T0);
    let request_ids = pcs0_item(&scan, PCS0_BIG).map(|item| item.claude_usage_request_ids.len());
    eprintln!(
        "PAGED_CLAUDE_S0 test=RB-1 len={} cap={PCS0_CAP} responses={responses} discovered={} oversized={} scanned={} request_ids={request_ids:?} census_complete={}",
        fixture.len(PCS0_BIG),
        scan.discovered_file_count,
        scan.oversized_file_count,
        scan.scanned_file_count,
        scan.census_complete
    );
    assert_eq!(
        scan.oversized_file_count, 0,
        "RB-1 red on main: the over-cap transcript is counted oversized at discovery and never read"
    );
    assert_eq!(
        request_ids,
        Some(responses),
        "one snapshot carries every response"
    );
    assert!(scan.census_complete);
}

/// RB-2 (design §8.1, corrected per review F12), CHARACTERIZATION: green on
/// main. A published transcript that grows past the cap is never read again:
/// no new snapshot, its index entry kept unchanged, and the census red. The
/// census discloses only generic owed work. On main `pending_work_count == 1`
/// (only its terminal-unhealthy term; the scan keeps the count local, so it is
/// derived below from the same traversal fields), hence `scan_cap_hit ==
/// true`, while `skipped_file_count_due_to_limit == 0` and no field names the
/// file's owed bytes. The design's `scan_cap_hit == false` was wrong (F12).
///
/// FLIPS at S1 (review §5): `census_complete`, the derived pending work,
/// `scan_cap_hit` and, if S1 discloses owed bytes on the scan result or the
/// traversal counts, the owed-bytes check.
#[test]
fn paged_claude_s0_rb2_characterization_oversized_census_discloses_generic_owed_work_only() {
    let fixture = Pcs0Fixture::new("paged-claude-s0-rb2");
    let published = 4;
    fixture.append(PCS0_BIG, (0..published).map(|n| format!("req_big_{n}")));
    let mut index = ScanIndex::default();
    let first = pcs0_page(&fixture, &mut index, PCS0_T0);
    assert!(
        first.scan.census_complete,
        "precondition: a clean first census"
    );
    assert_eq!(
        pcs0_item(&first.scan, PCS0_BIG).map(|item| item.claude_usage_request_ids.len()),
        Some(published),
        "precondition: the transcript is published under the cap"
    );
    let key = fixture.key(PCS0_BIG);
    let entry = |index: &ScanIndex| {
        (
            index.files[&key].source_file_fingerprint.clone(),
            index.file_snapshot_fingerprints.get(&key).cloned(),
        )
    };
    let entry_before = entry(&index);
    assert!(!entry_before.0.is_empty());

    let grown = fixture.grow_past_cap(PCS0_BIG, "req_grown", 0);
    let second = pcs0_page(&fixture, &mut index, PCS0_T1);
    let traversal = index
        .traversal
        .as_ref()
        .expect("an unhealthy census keeps its traversal");
    // Every term of the scan's `pending_work_count` that can be nonzero for a
    // Claude census: queued candidates and directories, plus one for a
    // finished discovery with errors (`terminal_unhealthy`). The other terms
    // are pinned to zero below.
    let derived_pending_work_count = traversal.pending_candidates.len()
        + traversal.pending_directories.len()
        + usize::from(traversal.counts.has_errors());
    let disclosure = format!("{:?} {:?}", second.scan, traversal.counts);
    let names_owed_bytes = disclosure.contains("bytes_owed") || disclosure.contains("owed_bytes");
    eprintln!(
        "PAGED_CLAUDE_S0 test=RB-2 grown_responses={grown} discovered={} oversized={} scanned={} census_complete={} scan_cap_hit={} skipped_due_to_limit={} derived_pending_work_count={derived_pending_work_count} names_owed_bytes={names_owed_bytes}",
        second.scan.discovered_file_count,
        second.scan.oversized_file_count,
        second.scan.scanned_file_count,
        second.scan.census_complete,
        second.scan.scan_cap_hit,
        second.scan.skipped_file_count_due_to_limit
    );
    assert_eq!(second.scan.oversized_file_count, 1);
    assert_eq!(second.scan.scanned_file_count, 0);
    assert!(
        pcs0_item(&second.scan, PCS0_BIG).is_none(),
        "no new snapshot"
    );
    assert_eq!(
        entry(&index),
        entry_before,
        "the index entry is kept unchanged"
    );
    assert_eq!(second.scan.skipped_file_count_due_to_limit, 0);
    assert!(traversal.pending_candidates.is_empty());
    assert!(traversal.pending_directories.is_empty());
    assert!(!traversal.watcher_hint_seen);
    assert!(!traversal.codex_parent_resolution_retry_required);
    assert!(!index.bounded_sweep_had_unsettled_upload);
    // FLIPS at S1.
    assert!(!second.scan.census_complete);
    assert_eq!(derived_pending_work_count, 1);
    assert!(
        second.scan.scan_cap_hit,
        "F12: generic owed work is surfaced"
    );
    assert!(
        !names_owed_bytes,
        "no per-file disclosure of owed bytes on main"
    );
}

/// RB-3 (design §8.1), CHARACTERIZATION: green on main. A transcript under
/// the cap when it is opened, which grows past the cap while its in-page
/// (unsampled) read is active, is not published. The finish revalidation
/// (`OwnedJsonlParser::finish`, `opened_object_identity`) refuses the held
/// object, and the read counts as unreadable (`Reduction`), not oversized. The
/// next due retry counts the file oversized at discovery.
///
/// Control arm: growth that stays under the cap fails the same way, so the
/// refusal is the in-page "changed while parsed" rule, not the cap itself.
/// Paging (S3) changes this shape: a frozen extent commits the read prefix
/// (design §4.6), so S3 needs a sampled variant of this test.
#[test]
fn paged_claude_s0_rb3_characterization_growth_during_in_page_read_fails_publication() {
    let mut receipt = Vec::new();
    for past_cap in [true, false] {
        let arm = if past_cap { "past-cap" } else { "under-cap" };
        let fixture = Pcs0Fixture::new(&format!("paged-claude-s0-rb3-{arm}"));
        fixture.append(PCS0_BIG, (0..4).map(|n| format!("req_big_{n}")));
        let path = fixture.path(PCS0_BIG);
        let mut grown = false;
        let (mut index, scan) = with_test_claude_file_cap(PCS0_CAP, || {
            let mut state = OwnedSourceScan::new(
                SnapshotSource::ClaudeCode,
                std::slice::from_ref(&fixture.root),
                ScanIndex::default(),
                PCS0_T0,
                PCS0_WINDOW_DAYS,
                PCS0_FILE_LIMIT,
                true,
                None,
                &[],
                false,
                true,
            );
            for _ in 0..10_000 {
                if !grown
                    && state
                        .active_file
                        .as_deref()
                        .is_some_and(|active| active.candidate.path == path)
                {
                    if past_cap {
                        fixture.grow_past_cap(PCS0_BIG, "req_grown", 0);
                    } else {
                        fixture.append(PCS0_BIG, ["req_grown_0"]);
                    }
                    grown = true;
                }
                match state.step(None) {
                    OwnedSourceScanStep::Pending(next) => state = next,
                    OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
                }
            }
            panic!("the scan did not complete");
        });
        assert!(grown, "{arm}: precondition: the transcript grew mid-read");
        assert_eq!(
            fixture.len(PCS0_BIG) > PCS0_CAP,
            past_cap,
            "{arm}: precondition"
        );
        let traversal = index
            .traversal
            .as_ref()
            .expect("a failed read keeps the traversal red");
        let causes =
            serde_json::to_value(traversal.counts.unreadable_causes).expect("serialize causes");
        let reduction = causes["counts"][UnreadableCause::Reduction as usize].as_u64();
        let at = pcs0_next_restart(&index, PCS0_T0);
        let retry = pcs0_page(&fixture, &mut index, &at);
        receipt.push(format!(
            "{arm}:scanned={},unreadable={},reduction={reduction:?},oversized={},census_complete={},retry_oversized={},retry_published={}",
            scan.scanned_file_count,
            scan.unreadable_path_count,
            scan.oversized_file_count,
            scan.census_complete,
            retry.scan.oversized_file_count,
            pcs0_item(&retry.scan, PCS0_BIG).is_some()
        ));
        assert_eq!(scan.scanned_file_count, 1, "{arm}: the read started");
        assert!(pcs0_item(&scan, PCS0_BIG).is_none(), "{arm}: not published");
        assert_eq!(scan.unreadable_path_count, 1, "{arm}");
        assert_eq!(reduction, Some(1), "{arm}: refused at finish");
        assert_eq!(scan.oversized_file_count, 0, "{arm}");
        assert!(!scan.census_complete, "{arm}");
        assert_eq!(
            retry.scan.oversized_file_count,
            usize::from(past_cap),
            "{arm}: the next due retry"
        );
        assert_eq!(
            pcs0_item(&retry.scan, PCS0_BIG).is_some(),
            !past_cap,
            "{arm}: the next due retry"
        );
    }
    eprintln!("PAGED_CLAUDE_S0 test=RB-3 {}", receipt.join(" "));
}

/// RB-5 (review F1), RED until S1. While the Claude census is red, every due
/// retry starts a traversal, finds each published family's pending entry from
/// an older window, and clears its members' source fingerprints (the
/// stale-pending re-arm at traversal start). The unchanged family is then
/// re-parsed at every retry, hourly once the latch saturates. Desired: once
/// the census completes beside the oversized member (S1), no restart
/// re-parses the unchanged family.
///
/// Expected red reason on main: `scanned_file_count` is 1, not 0, at each of
/// the two due restarts (the sibling family re-parsed).
///
/// Note for S1: the F11 pin as proposed (`census_invalid` while an oversized
/// member is in the window) closes the duplicate fence, and a fence that
/// closes schedules a full re-arm of every indexed Claude member
/// (`claude_duplicate_fence_full_rearm_due`, 1 h doubling to 24 h). That would
/// keep this test red. The pin must not trigger that re-arm.
#[test]
fn paged_claude_s0_rb5_red_census_retry_does_not_reparse_pending_family() {
    let fixture = Pcs0Fixture::new("paged-claude-s0-rb5");
    fixture.append(PCS0_SIBLING, ["req_sibling_0"]);
    fixture.grow_past_cap(PCS0_BIG, "req_big", 0);
    let sibling = fixture.key(PCS0_SIBLING);
    let bytes = fs::read(fixture.path(PCS0_SIBLING)).expect("read sibling transcript");
    let mut index = ScanIndex::default();
    let first = pcs0_page(&fixture, &mut index, PCS0_T0);
    assert_eq!(first.scan.oversized_file_count, 1, "precondition");
    assert!(
        pcs0_item(&first.scan, PCS0_SIBLING).is_some(),
        "precondition"
    );
    assert!(pcs0_item(&first.scan, PCS0_BIG).is_none(), "precondition");
    assert!(!index.files[&sibling].source_file_fingerprint.is_empty());
    let pending_after_first = index.claude_usage_family_pending.contains_key(PCS0_SIBLING);

    let mut at = PCS0_T0.to_string();
    let mut restarts = Vec::new();
    for _ in 0..2 {
        at = pcs0_next_restart(&index, &at);
        let page = pcs0_page(&fixture, &mut index, &at);
        assert_eq!(
            fs::read(fixture.path(PCS0_SIBLING)).expect("read sibling transcript"),
            bytes,
            "precondition: the sibling never changes"
        );
        assert_eq!(
            page.scan.oversized_file_count, 1,
            "precondition: the member stays oversized"
        );
        restarts.push((
            at.clone(),
            page.scan.scanned_file_count,
            page.scan.semantic_noop_count,
            page.scan.census_complete,
        ));
    }
    eprintln!(
        "PAGED_CLAUDE_S0 test=RB-5 first_census_complete={} pending_after_first={pending_after_first} restarts(at,scanned,semantic_noops,census_complete)={restarts:?}",
        first.scan.census_complete
    );
    let reparsed = restarts
        .iter()
        .map(|(_, scanned, _, _)| *scanned)
        .collect::<Vec<_>>();
    assert_eq!(
        reparsed,
        [0, 0],
        "RB-5 (F1) red on main: each due restart re-parsed the unchanged sibling family; restarts={restarts:?}"
    );
}

/// RB-6 (review F2), CHARACTERIZATION: green on main. An audit-pending
/// (`sampled_unverified`) entry is exempt from the window skip
/// (`sampled_audit::path_requires_verification`), so once it is over the cap
/// it is counted oversized even with an mtime years outside the window. It is
/// never parsed again, so the marker is never cleared and the count never ages
/// out. Control arm: the same file without the marker ages out of the census,
/// and the census completes.
///
/// The marker is seeded by hand (controlled); in production a sampled Tail
/// acceptance stages it (`stage_sampled_audit`).
///
/// FLIPS at S1: `census_complete == false` in the marker arm. The oversized
/// count must keep holding; S1 adds the audit-owed disclosure beside it.
#[test]
fn paged_claude_s0_rb6_characterization_audit_pending_oversized_entry_counts_past_the_window() {
    let mut receipt = Vec::new();
    for marked in [false, true] {
        let arm = if marked { "marked" } else { "control" };
        let fixture = Pcs0Fixture::new(&format!("paged-claude-s0-rb6-{arm}"));
        fixture.append(PCS0_BIG, ["req_big_0"]);
        let mut index = ScanIndex::default();
        let first = pcs0_page(&fixture, &mut index, PCS0_T0);
        assert!(first.scan.census_complete, "{arm}: precondition");
        assert!(
            pcs0_item(&first.scan, PCS0_BIG).is_some(),
            "{arm}: precondition"
        );
        if marked {
            let due = rfc3339_unix_seconds(PCS0_T0).expect("fixture clock");
            index
                .files
                .get_mut(&fixture.key(PCS0_BIG))
                .expect("indexed transcript")
                .set_unverified_deadline(due);
        }
        assert_eq!(
            sampled_audit::path_requires_verification(&index.files, &fixture.path(PCS0_BIG)),
            marked,
            "{arm}: precondition"
        );
        fixture.grow_past_cap(PCS0_BIG, "req_big_tail", 1);
        // 2020-01-01T00:00:00Z: years outside the 183-day window (and the
        // 730-day ceiling) of every census below.
        File::options()
            .write(true)
            .open(fixture.path(PCS0_BIG))
            .expect("open transcript")
            .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1_577_836_800))
            .expect("age transcript");
        for at in [PCS0_T1, "2029-01-01T00:00:00Z"] {
            let page = pcs0_page(&fixture, &mut index, at);
            receipt.push(format!(
                "{arm}@{at}:discovered={},oversized={},census_complete={}",
                page.scan.discovered_file_count,
                page.scan.oversized_file_count,
                page.scan.census_complete
            ));
            assert_eq!(
                page.scan.discovered_file_count,
                usize::from(marked),
                "{arm}@{at}"
            );
            assert_eq!(
                page.scan.oversized_file_count,
                usize::from(marked),
                "{arm}@{at}: still counts only with the marker"
            );
            // FLIPS at S1 (marker arm).
            assert_eq!(page.scan.census_complete, !marked, "{arm}@{at}");
            assert_eq!(
                sampled_audit::path_requires_verification(&index.files, &fixture.path(PCS0_BIG)),
                marked,
                "{arm}@{at}: the marker is never cleared"
            );
        }
    }
    eprintln!("PAGED_CLAUDE_S0 test=RB-6 {}", receipt.join(" "));
}

/// RB-7 (review F11), RED until S1 with its F11 pin. The oversized member's
/// unread tail holds a request that a sibling family also reports. Across two
/// complete generations after the crossing, the duplicate fence must stay
/// closed: the census cannot prove that request unique.
///
/// Expected red reason on main: generation 1 has `census_complete == false`
/// (the oversized member keeps the traversal unhealthy), so no complete
/// generation exists. After an S1 without the pin, generation 1 completes
/// with the fence open, because the fence was open before the crossing, no
/// stale pending survives the earlier complete census, and the
/// coverage-reopen rule only keeps an already-closed fence closed. The fence
/// assertion then fails instead.
#[test]
fn paged_claude_s0_rb7_red_unread_member_keeps_duplicate_fence_closed() {
    let fixture = Pcs0Fixture::new("paged-claude-s0-rb7");
    fixture.append(PCS0_BIG, ["req_big_0"]);
    fixture.append(PCS0_SIBLING, ["req_sibling_0"]);
    let mut index = ScanIndex::default();
    let before = pcs0_page(&fixture, &mut index, PCS0_T0);
    assert!(before.scan.census_complete, "precondition");
    assert!(before.duplicate.census_complete, "precondition");
    assert!(
        !before.duplicate.fence_after,
        "precondition: the fence is open before the crossing"
    );

    fixture.append(PCS0_BIG, ["req_shared"]);
    fixture.grow_past_cap(PCS0_BIG, "req_big_tail", 1);
    fixture.append(PCS0_SIBLING, ["req_shared"]);
    let mut at = PCS0_T1.to_string();
    let mut generations = Vec::new();
    for generation in 1..=2 {
        let page = pcs0_page(&fixture, &mut index, &at);
        generations.push((
            generation,
            page.scan.oversized_file_count,
            page.scan.census_complete,
            page.duplicate.census_invalid,
            page.duplicate.fence_after,
            page.duplicate.coverage_missing_member_count,
        ));
        at = pcs0_next_restart(&index, &at);
    }
    eprintln!(
        "PAGED_CLAUDE_S0 test=RB-7 generations(n,oversized,census_complete,census_invalid,fence_after,coverage_missing)={generations:?}"
    );
    for (generation, oversized, census_complete, _, fence_after, _) in &generations {
        assert_eq!(*oversized, 1, "precondition: generation {generation}");
        assert!(
            *census_complete,
            "RB-7 red on main: generation {generation} is not a complete census; {generations:?}"
        );
        assert!(
            *fence_after,
            "RB-7 (F11): generation {generation} opened the fence over an unread request; {generations:?}"
        );
    }
}

/// RB-8 (review §5), RED until S1. A healthy sibling family with complete
/// local API and trace evidence folds (its family proof is retained) on the
/// first complete census. An oversized member elsewhere in the window must not
/// stop that. Control arm (green on main, runs first): the same family with
/// no oversized member folds, which proves the evidence fixture suffices.
///
/// Expected red reason on main: the oversized arm has `census_complete ==
/// false`, so the census-gated fold never runs and no proof is retained.
#[test]
fn paged_claude_s0_rb8_red_healthy_sibling_family_folds_beside_oversized_member() {
    let mut receipt = Vec::new();
    for oversized in [false, true] {
        let arm = if oversized { "oversized" } else { "control" };
        let fixture = Pcs0Fixture::new(&format!("paged-claude-s0-rb8-{arm}"));
        for (sequence, request) in ["req_sibling_0", "req_sibling_1"].into_iter().enumerate() {
            fixture.append(PCS0_SIBLING, [request]);
            fixture.append_evidence(PCS0_SIBLING, request, sequence as u64 + 1);
        }
        if oversized {
            fixture.grow_past_cap(PCS0_BIG, "req_big", 0);
        }
        let mut index = ScanIndex::default();
        let page = pcs0_page(&fixture, &mut index, PCS0_T0);
        let folded = index
            .claude_usage_family_witnesses
            .contains_key(PCS0_SIBLING);
        let contract = pcs0_item(&page.scan, PCS0_SIBLING)
            .and_then(|item| item.usage_accounting_contract.clone());
        receipt.push(format!(
            "{arm}:oversized={},census_complete={},folded={folded},contract={contract:?}",
            page.scan.oversized_file_count, page.scan.census_complete
        ));
        assert!(
            pcs0_item(&page.scan, PCS0_SIBLING).is_some(),
            "{arm}: precondition: the sibling is published"
        );
        assert_eq!(
            page.scan.oversized_file_count,
            usize::from(oversized),
            "{arm}: precondition"
        );
        assert!(
            page.scan.census_complete,
            "RB-8 red on main ({arm}): the oversized member keeps the census incomplete; {receipt:?}"
        );
        assert!(
            folded,
            "RB-8 ({arm}): the healthy sibling family is not folded; {receipt:?}"
        );
    }
    eprintln!("PAGED_CLAUDE_S0 test=RB-8 {}", receipt.join(" "));
}
