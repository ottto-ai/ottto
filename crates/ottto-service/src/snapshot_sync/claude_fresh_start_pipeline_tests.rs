// Slice 2c (P4) through the local-evidence step production runs,
// `try_apply_claude_local_evidence_to_scan_with_comparison`: H5 settles a
// root's telemetry only through the existing sidecar-absence check (B-F5
// option (a)), every 2c set is funded from the native reservation before it
// is allocated (T18), a stranded candidate spends one settlement re-arm
// (A-F2), and the switch off changes nothing. The SI twin (BASE-equivalence)
// runs a telemetry-proven peer beside the fresh root. The fake-client
// `finish_sync_source` cases (SOURCE P3-3) run the real finish. Synthetic
// fixtures only.
use super::*;

const FRESH_START_ROOT: &str = "f1000000-0000-4000-8000-00000000001f";
/// A root with paired local API and trace rows for every request.
const FRESH_START_PEER: &str = "f2000000-0000-4000-8000-00000000002f";
const FRESH_START_ORG: &str = "22222222-2222-4222-8222-222222222222";

fn fresh_start_ms(timestamp: &str) -> i64 {
    let at = OffsetDateTime::parse(timestamp, &Rfc3339).expect("RFC 3339 fixture");
    i64::try_from(at.unix_timestamp_nanos() / 1_000_000).expect("fixture time")
}

/// One fresh root transcript: three responses with unique request ids.
fn fresh_start_transcript(dir: &Path) {
    fresh_start_transcript_with_marker(dir, false);
}

/// The fresh root transcript, optionally led by an owned org marker.
fn fresh_start_transcript_with_marker(dir: &Path, org_marker: bool) {
    let root = FRESH_START_ROOT;
    let marker = if org_marker {
        format!(
            "{{\"timestamp\":\"2026-08-20T10:00:00Z\",\"type\":\"attachment\",\"sessionId\":\"{root}\",\"attachment\":{{\"type\":\"credential_org\",\"organizationUuid\":\"{FRESH_START_ORG}\"}}}}\n"
        )
    } else {
        String::new()
    };
    let user = format!(
        "{{\"timestamp\":\"2026-08-20T10:00:00Z\",\"type\":\"user\",\"uuid\":\"u_0\",\"sessionId\":\"{root}\",\"message\":{{\"role\":\"user\",\"content\":\"x\"}}}}\n"
    );
    let assistant = |request: &str, second: u32, input_tokens: u64| {
        format!(
            "{{\"timestamp\":\"2026-08-20T10:00:{second:02}Z\",\"type\":\"assistant\",\"uuid\":\"u_{request}\",\"sessionId\":\"{root}\",\"requestId\":\"{request}\",\"message\":{{\"id\":\"msg_{request}\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":1}}}}}}\n"
        )
    };
    let body = [
        marker,
        user,
        assistant("req_1", 2, 100),
        assistant("req_2", 4, 300),
        assistant("req_3", 5, 200),
    ]
    .concat();
    std::fs::write(dir.join(format!("{root}.jsonl")), body).expect("write transcript");
}

struct FreshStartPipeline {
    base: PathBuf,
    transcripts: PathBuf,
    /// Local OTEL support directory with no sidecars: both are absent.
    support: PathBuf,
    index: ScanIndex,
    /// The reservation's allocation between the fold and the upload
    /// settlement, and the credit's upload part, on the last pass that
    /// admitted a body.
    upload_charge: Option<(usize, usize)>,
}

impl FreshStartPipeline {
    fn new(name: &str) -> Self {
        let base = test_dir(name);
        let transcripts = base.join("projects").join("-synthetic-repo");
        std::fs::create_dir_all(&transcripts).expect("create transcripts");
        fresh_start_transcript(&transcripts);
        Self {
            support: base.join("support"),
            base,
            transcripts,
            index: ScanIndex::default(),
            upload_charge: None,
        }
    }

    /// The fresh root (led by an org marker) beside a peer root whose every
    /// request has paired local API and trace rows.
    fn with_telemetry_peer(name: &str) -> Self {
        let pipeline = Self::new(name);
        fresh_start_transcript_with_marker(&pipeline.transcripts, true);
        let peer = FRESH_START_PEER;
        let mut lines = format!(
            "{{\"timestamp\":\"2026-08-20T10:00:00Z\",\"type\":\"user\",\"uuid\":\"p_0\",\"sessionId\":\"{peer}\",\"message\":{{\"role\":\"user\",\"content\":\"x\"}}}}\n"
        );
        for (sequence, request) in ["req_p1", "req_p2"].into_iter().enumerate() {
            let second = sequence + 2;
            lines.push_str(&format!(
                "{{\"timestamp\":\"2026-08-20T10:00:{second:02}Z\",\"type\":\"assistant\",\"uuid\":\"p_{request}\",\"sessionId\":\"{peer}\",\"requestId\":\"{request}\",\"message\":{{\"id\":\"msg_{request}\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
            ));
            let (api, trace) = fresh_start_peer_evidence(request, sequence as u64 + 1);
            let sidecar = |kind: &str| {
                pipeline
                    .support
                    .join("local-otel")
                    .join(kind)
                    .join(format!("{:x}.jsonl", Sha256::digest(peer.as_bytes())))
            };
            for (path, line) in [
                (sidecar("claude-code-effort"), api),
                (sidecar("claude-code-trace-ownership"), trace),
            ] {
                std::fs::create_dir_all(path.parent().expect("sidecar parent"))
                    .expect("create sidecar directory");
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .expect("open sidecar")
                    .write_all(line.as_bytes())
                    .expect("append sidecar row");
            }
        }
        std::fs::write(pipeline.transcripts.join(format!("{peer}.jsonl")), lines)
            .expect("write peer transcript");
        pipeline
    }

    /// An ordinary forced re-arm of the fresh root's file (the OFF control).
    fn force_rearm(&mut self) {
        let stem = format!("{FRESH_START_ROOT}.jsonl");
        let mut rearmed = 0;
        for (key, entry) in &mut self.index.files {
            if key.ends_with(&stem) {
                entry.source_file_fingerprint.clear();
                rearmed += 1;
            }
        }
        assert_eq!(rearmed, 1, "one indexed fresh root file");
    }

    /// Whether the fresh root's indexed key is re-armed (its fingerprint
    /// cleared, so the next pass parses it).
    fn rearmed(&self) -> bool {
        let stem = format!("{FRESH_START_ROOT}.jsonl");
        self.index
            .files
            .iter()
            .any(|(key, entry)| key.ends_with(&stem) && entry.source_file_fingerprint.is_empty())
    }

    /// Append one more response to the fresh root: a new revision.
    fn grow(&self) {
        let root = FRESH_START_ROOT;
        let line = format!(
            "{{\"timestamp\":\"2026-08-20T10:00:06Z\",\"type\":\"assistant\",\"uuid\":\"u_req_4\",\"sessionId\":\"{root}\",\"requestId\":\"req_4\",\"message\":{{\"id\":\"msg_req_4\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":250,\"output_tokens\":1}}}}}}\n"
        );
        std::fs::OpenOptions::new()
            .append(true)
            .open(self.transcripts.join(format!("{root}.jsonl")))
            .expect("open transcript")
            .write_all(line.as_bytes())
            .expect("append response");
    }

    /// One scan page, the production evidence step, finalization, and an
    /// upload whose server applies every admitted body.
    fn pass(
        &mut self,
        collected_at: &str,
        permit: bool,
        comparison: Option<&mut crate::snapshots::claude_native_comparison::Completion>,
    ) -> Vec<SnapshotItem> {
        self.pass_with_disposition(collected_at, permit, comparison)
            .0
    }

    /// `pass` with a native reservation that funds every 2c set here.
    fn pass_funded(&mut self, collected_at: &str, permit: bool) -> Vec<SnapshotItem> {
        let mut completion = funded_completion();
        self.pass(collected_at, permit, Some(&mut completion))
    }

    fn pass_with_disposition(
        &mut self,
        collected_at: &str,
        permit: bool,
        mut comparison: Option<&mut crate::snapshots::claude_native_comparison::Completion>,
    ) -> (
        Vec<SnapshotItem>,
        crate::snapshots::ClaudeUsageAuthorityDisposition,
    ) {
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.transcripts),
            &mut self.index,
            collected_at,
            183,
            1_000,
            true,
        )
        .expect("scan page");
        assert!(scan.census_complete, "one page covers the fixture");
        let (disposition, _, _, credit) = try_apply_claude_local_evidence_to_scan_with_comparison(
            &self.support,
            &mut scan,
            &mut self.index,
            permit.then(crate::snapshots::claude_emission_permit_for_test),
            None,
            comparison.as_deref_mut(),
            None,
        )
        .expect("a 2c funding refusal never fails the page");
        let items = scan.snapshots.clone();
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut self.index);
        // The upload settlement as `finish_sync_source` runs it: borrowed
        // views, funded by the credit, and a server that applies every
        // offered body. The credit returns once the views are dropped.
        let applied = items
            .iter()
            .filter(|item| {
                disposition
                    .fresh_start_admitted
                    .contains(&item.source_session_id)
            })
            .map(|item| item.snapshot_fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        if !applied.is_empty() {
            let credit = credit.as_ref().expect("an admitted body was funded");
            assert!(applied.len() <= credit.upload_items(), "every view is funded");
            let allocated = comparison
                .as_deref()
                .and_then(crate::snapshots::claude_native_comparison::Completion::reservation_allocated_for_test)
                .expect("a funded fold has a reservation");
            self.upload_charge = Some((allocated, credit.upload_bytes_for_test()));
        }
        crate::snapshots::settle_claude_fresh_start_emissions(
            &mut self.index,
            &items,
            &disposition.fresh_start_admitted,
            &applied,
        );
        drop(applied);
        if let Some(comparison) = comparison {
            if let Some(credit) = credit {
                comparison.release_fresh_start_roots(credit);
            }
            assert_eq!(
                comparison.reservation_allocated_for_test().unwrap_or(0),
                0,
                "the whole 2c credit is returned"
            );
        }
        (items, disposition)
    }

    fn state(&self) -> Option<&'static str> {
        crate::snapshots::claude_fresh_start_state_for_test(&self.index, FRESH_START_ROOT)
    }
}

impl Drop for FreshStartPipeline {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Paired API and trace rows for one peer request, as the local OTEL
/// receiver writes them.
fn fresh_start_peer_evidence(request: &str, sequence: u64) -> (String, String) {
    let mut api = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".to_string(),
        session_id: FRESH_START_PEER.to_string(),
        request_id: request.to_string(),
        client_request_id: format!("client-{request}"),
        observed_at: format!("2026-08-20T10:00:{:02}Z", sequence + 1),
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
        session_id: FRESH_START_PEER.to_string(),
        request_id: request.to_string(),
        client_request_id: format!("client-{request}"),
        observed_at: "2026-08-20T10:00:30Z".to_string(),
        ..Default::default()
    };
    trace.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&trace).expect("serialize trace evidence"))
    );
    (
        serde_json::to_string(&api).expect("encode API evidence") + "\n",
        serde_json::to_string(&trace).expect("encode trace evidence") + "\n",
    )
}

type FreshStartScalars = Option<(Option<u64>, Option<u64>, Option<u64>)>;

fn fresh_start_scalars(items: &[SnapshotItem]) -> FreshStartScalars {
    items
        .iter()
        .find(|item| item.source_session_id == FRESH_START_ROOT)
        .map(|item| {
            (
                item.first_turn_context_tokens,
                item.peak_context_fill_tokens,
                item.last_turn_context_tokens,
            )
        })
}

fn fresh_start_overrides(enabled: bool) -> crate::snapshots::ClaudeFreshStartTestOverrides {
    fresh_start_overrides_with(enabled, Some(true))
}

/// `census_complete: None` keeps the production H3 stub.
fn fresh_start_overrides_with(
    enabled: bool,
    census_complete: Option<bool>,
) -> crate::snapshots::ClaudeFreshStartTestOverrides {
    crate::snapshots::ClaudeFreshStartTestOverrides::new(
        enabled,
        &[(FRESH_START_ROOT, fresh_start_ms("2026-08-20T09:59:30Z"))],
        census_complete,
    )
}

/// A completion whose moving reservation funds every 2c set here.
fn funded_completion() -> crate::snapshots::claude_native_comparison::Completion {
    crate::snapshots::claude_native_comparison::Completion::reservation_only_for_test(
        crate::source_rotation::PaidReservation::from_remainder(Some(1 << 20), 0, 0),
    )
}

/// Every body as uploaded bytes would carry it.
fn fresh_start_bodies(items: &[SnapshotItem]) -> Vec<serde_json::Value> {
    items
        .iter()
        .map(|item| serde_json::to_value(item).expect("body"))
        .collect()
}

/// The identity and settlement state a pass leaves, without the 2c map.
fn fresh_start_identity_state(index: &ScanIndex) -> Vec<Option<serde_json::Value>> {
    let saved = serde_json::to_value(index).expect("index");
    [
        "files",
        "session_account_bindings",
        "claude_usage_family_witnesses",
        "claude_usage_family_pending",
        "claude_usage_authority_quarantine",
        "claude_duplicate_request_owners",
        "claude_duplicate_request_witness_overflowed",
        "claude_owned_start_census",
        "accepted_snapshot_fingerprints",
    ]
    .into_iter()
    .map(|key| saved.get(key).cloned())
    .collect()
}

#[test]
fn h5_settles_an_absent_sidecar_root_through_the_production_evidence_step() {
    let _overrides = fresh_start_overrides(true);
    let mut pipeline = FreshStartPipeline::new("claude-2c-h5-e2e");
    // Census pass: both sidecars confirmed absent by the existing check (the
    // contract-5 permit path), so the candidate verifies and is re-armed.
    let first = pipeline.pass_funded("2026-08-20T10:30:00Z", true);
    assert_eq!(fresh_start_scalars(&first), Some((None, None, None)));
    assert_eq!(pipeline.state(), Some("verified"));
    // The corrective parse carries the numbers; the server applies them.
    let second = pipeline.pass_funded("2026-08-20T10:40:00Z", true);
    assert_eq!(
        fresh_start_scalars(&second),
        Some((Some(100), Some(300), Some(200)))
    );
    assert_eq!(pipeline.state(), Some("emitted"));
    let third = pipeline.pass_funded("2026-08-20T10:50:00Z", true);
    assert!(third.is_empty(), "no replay loop");
}

#[test]
fn b_f5_a_permit_less_pass_leaves_the_candidate_unsettled_and_one_permitted_pass_settles_it() {
    // B-F5 option (a), closed: H5 settles only on the permit path. A
    // permit-less pass keeps the candidate unsettled and leaves every body
    // and identity field as 2c off would. A later eligible permitted pass
    // settles it once, through the one settlement re-arm (A-F2) of the
    // unchanged file; repeating that pass settles nothing again and replays
    // nothing.
    let mut pipeline = FreshStartPipeline::new("claude-2c-bf5");
    let twin = {
        let _overrides = fresh_start_overrides(false);
        let items = pipeline.pass_funded("2026-08-20T10:30:00Z", false);
        (
            fresh_start_bodies(&items),
            fresh_start_identity_state(&pipeline.index),
        )
    };
    pipeline.index = ScanIndex::default();
    let _overrides = fresh_start_overrides(true);
    let first = pipeline.pass_funded("2026-08-20T10:30:00Z", false);
    assert_eq!(pipeline.state(), Some("candidate"), "unsettled");
    assert_eq!(fresh_start_scalars(&first), Some((None, None, None)));
    assert_eq!(
        (
            fresh_start_bodies(&first),
            fresh_start_identity_state(&pipeline.index)
        ),
        twin,
        "a permit-less pass changes no body, identity or settlement state"
    );
    // Repeating the permit-less pass spends nothing.
    assert!(pipeline
        .pass_funded("2026-08-20T10:35:00Z", false)
        .is_empty());
    assert_eq!(pipeline.state(), Some("candidate"));
    assert!(!pipeline.rearmed());
    // The eligible permitted pass: the unchanged file spends its one
    // settlement re-arm.
    assert!(pipeline
        .pass_funded("2026-08-20T10:40:00Z", true)
        .is_empty());
    assert_eq!(pipeline.state(), Some("settlement_rearmed"));
    assert!(pipeline.rearmed());
    // Its re-parse settles the telemetry and verifies; the corrective parse
    // carries the numbers and the server applies them.
    let verifying = pipeline.pass_funded("2026-08-20T10:45:00Z", true);
    assert_eq!(fresh_start_scalars(&verifying), Some((None, None, None)));
    assert_eq!(pipeline.state(), Some("verified"));
    let corrective = pipeline.pass_funded("2026-08-20T10:50:00Z", true);
    assert_eq!(
        fresh_start_scalars(&corrective),
        Some((Some(100), Some(300), Some(200)))
    );
    assert_eq!(pipeline.state(), Some("emitted"));
    // Repeating the eligible pass: no second settlement, no replay loop.
    for collected_at in ["2026-08-20T11:00:00Z", "2026-08-20T11:10:00Z"] {
        assert!(
            pipeline.pass_funded(collected_at, true).is_empty(),
            "no replay at {collected_at}"
        );
        assert_eq!(pipeline.state(), Some("emitted"));
        assert!(!pipeline.rearmed());
    }
}

#[test]
fn a_f2_one_settlement_rearm_per_revision_across_stub_funds_failed_save_restart_and_permit() {
    // Parent A-F2 conditions on the real pipeline: the attempt is spent only
    // by an accepted, permitted and funded census; a failed save leaks
    // nothing; a restart neither resets nor clears it; a permit flip after
    // the spend earns no second attempt; a new revision is a new binding.
    let mut pipeline = FreshStartPipeline::new("claude-2c-af2");
    {
        let _stub = fresh_start_overrides_with(true, None);
        pipeline.pass_funded("2026-08-20T10:30:00Z", false);
        assert_eq!(pipeline.state(), Some("candidate"));
        // Never while H3 is the false stub, even permitted and funded.
        for collected_at in ["2026-08-20T10:31:00Z", "2026-08-20T10:32:00Z"] {
            assert!(pipeline.pass_funded(collected_at, true).is_empty());
            assert_eq!(pipeline.state(), Some("candidate"));
            assert!(!pipeline.rearmed());
        }
    }
    let _overrides = fresh_start_overrides(true);
    // Never without funds (P4): no comparison, so no native reservation.
    assert!(pipeline.pass("2026-08-20T10:33:00Z", true, None).is_empty());
    assert_eq!(pipeline.state(), Some("candidate"));
    assert!(!pipeline.rearmed());
    // A failed selected save: the daemon reloads the committed index, so the
    // in-memory spend and re-arm are discarded together and the candidate is
    // still owed its one attempt.
    let committed = pipeline.index.clone();
    assert!(pipeline
        .pass_funded("2026-08-20T10:34:00Z", true)
        .is_empty());
    assert_eq!(pipeline.state(), Some("settlement_rearmed"));
    assert!(pipeline.rearmed());
    // A partial (shed) checkpoint commits the spend with its re-arm or
    // neither, never one without the other.
    let shed = pipeline
        .index
        .committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
    let shed_state =
        crate::snapshots::claude_fresh_start_state_for_test(&shed, FRESH_START_ROOT);
    let shed_rearmed = shed.files.iter().any(|(key, entry)| {
        key.ends_with(&format!("{FRESH_START_ROOT}.jsonl"))
            && entry.source_file_fingerprint.is_empty()
    });
    assert!(
        matches!(
            (shed_state, shed_rearmed),
            (Some("settlement_rearmed"), true) | (Some("candidate"), false)
        ),
        "{shed_state:?} rearmed={shed_rearmed}"
    );
    pipeline.index = committed;
    assert_eq!(pipeline.state(), Some("candidate"));
    assert!(!pipeline.rearmed());
    // Spent for real, then a restart: the persisted spend and its owed parse
    // both survive the reload.
    assert!(pipeline
        .pass_funded("2026-08-20T10:35:00Z", true)
        .is_empty());
    pipeline.index = serde_json::from_value(
        serde_json::to_value(&pipeline.index).expect("save index"),
    )
    .expect("reload index");
    assert_eq!(pipeline.state(), Some("settlement_rearmed"));
    assert!(pipeline.rearmed());
    // The owed parse runs without the permit, so nothing settles; no later
    // permitted window spends a second attempt for this revision.
    let reparsed = pipeline.pass_funded("2026-08-20T10:36:00Z", false);
    assert_eq!(fresh_start_scalars(&reparsed), Some((None, None, None)));
    assert_eq!(pipeline.state(), Some("settlement_rearmed"));
    assert!(!pipeline.rearmed());
    for collected_at in ["2026-08-20T10:40:00Z", "2026-08-20T10:50:00Z"] {
        assert!(pipeline.pass_funded(collected_at, true).is_empty());
        assert_eq!(pipeline.state(), Some("settlement_rearmed"));
        assert!(!pipeline.rearmed());
    }
    // A new revision is a new binding, reached only by an ordinary
    // changed-input parse; parsed with the permit, it verifies directly.
    pipeline.grow();
    let grown = pipeline.pass_funded("2026-08-20T11:00:00Z", true);
    assert_eq!(fresh_start_scalars(&grown), Some((None, None, None)));
    assert_eq!(pipeline.state(), Some("verified"));
}

#[test]
fn t18_an_unfunded_fold_refuses_new_2c_work_and_recovers_once_funded() {
    // T18 (P4): one aggregate charge on the fold's native reservation funds
    // every 2c set of the cycle (settled roots, admitted roots, both upload
    // views) before any is built. No comparison, a completion without a
    // reservation, or a reservation without funds refuses new 2c work for the
    // fold: no verification, the strict body, and the page still folds.
    let unfunded_reservation =
        || crate::source_rotation::PaidReservation::from_remainder(Some(0), 0, 0);
    let strict_body = {
        let _overrides = fresh_start_overrides(false);
        let mut pipeline = FreshStartPipeline::new("claude-2c-t18-off");
        let mut completion =
            crate::snapshots::claude_native_comparison::Completion::reservation_only_for_test(
                unfunded_reservation(),
            );
        let items = pipeline.pass("2026-08-20T10:30:00Z", true, Some(&mut completion));
        assert_eq!(pipeline.state(), None, "off writes no witness");
        assert_eq!(completion.reservation_allocated_for_test(), Some(0));
        fresh_start_scalars(&items)
    };
    assert_eq!(strict_body, Some((None, None, None)));

    let _overrides = fresh_start_overrides(true);
    let refusals = [
        ("no-comparison", None),
        (
            "no-reservation",
            Some(
                crate::snapshots::claude_native_comparison::Completion::reservation_only_for_test(
                    None,
                ),
            ),
        ),
        (
            "no-funds",
            Some(
                crate::snapshots::claude_native_comparison::Completion::reservation_only_for_test(
                    unfunded_reservation(),
                ),
            ),
        ),
    ];
    for (name, mut completion) in refusals {
        let mut refused = FreshStartPipeline::new(&format!("claude-2c-t18-{name}"));
        let unfunded = refused.pass("2026-08-20T10:30:00Z", true, completion.as_mut());
        assert_eq!(
            fresh_start_scalars(&unfunded),
            strict_body,
            "{name}: refused 2c keeps the strict body"
        );
        assert_eq!(refused.state(), Some("candidate"), "{name}: no verification");
        assert!(!refused.rearmed(), "{name}: no re-arm");
        // Still unfunded, a later permitted window spends nothing either.
        assert!(refused.pass("2026-08-20T10:40:00Z", true, None).is_empty());
        assert_eq!(refused.state(), Some("candidate"), "{name}");
        assert!(!refused.rearmed(), "{name}");
        assert!(refused.upload_charge.is_none(), "{name}: nothing admitted");
        if name != "no-funds" {
            continue;
        }
        // Recovery: the first funded pass re-arms the stranded candidate once
        // (A-F2), its re-parse verifies, and the corrective parse carries the
        // numbers with the admitted set and both upload views still charged
        // to the same reservation until the settlement drops them (the
        // helper then checks the whole credit came back).
        assert!(refused
            .pass_funded("2026-08-20T10:50:00Z", true)
            .is_empty());
        assert_eq!(refused.state(), Some("settlement_rearmed"));
        let verifying = refused.pass_funded("2026-08-20T11:00:00Z", true);
        assert_eq!(fresh_start_scalars(&verifying), strict_body);
        assert_eq!(refused.state(), Some("verified"));
        let corrective = refused.pass_funded("2026-08-20T11:10:00Z", true);
        assert_eq!(
            fresh_start_scalars(&corrective),
            Some((Some(100), Some(300), Some(200)))
        );
        assert_eq!(refused.state(), Some("emitted"));
        let (allocated, upload_bytes) = refused.upload_charge.expect("the admission was charged");
        assert!(upload_bytes > 0);
        assert!(
            allocated >= upload_bytes,
            "the upload part stays charged through the settlement"
        );
        assert!(refused
            .pass_funded("2026-08-20T11:20:00Z", true)
            .is_empty());
    }

    // Funded from the start: the same census pass verifies.
    let mut funded = FreshStartPipeline::new("claude-2c-t18-funded");
    funded.pass_funded("2026-08-20T10:30:00Z", true);
    assert_eq!(funded.state(), Some("verified"));
}

#[test]
fn si_twin_a_rearm_observes_what_an_ordinary_forced_rearm_observes() {
    // SI ruling (BASE-equivalence, I1 and I2) with a contract-5 permit, real
    // identity evidence (the peer's API and trace rows, RequestSink grouping)
    // and a complete census. ON: pass N verifies and re-arms the fresh root,
    // pass N+1 re-parses it with numbers. OFF control: the same files, pass N,
    // then an ordinary forced re-arm of the root before pass N+1. Every pass
    // observes the same ownership and identity; the admitted body differs
    // from its twin only in context scalars and the derived fingerprint.
    // `TranscriptOwnership.settled` is derived from exactly these values.
    type Ownership = (bool, crate::snapshots::ClaudeDuplicateCensusCounts);
    let ownership = |disposition: &crate::snapshots::ClaudeUsageAuthorityDisposition| -> Ownership {
        (
            disposition.transcript_ownership_complete,
            disposition.duplicate_census,
        )
    };
    let mut pipeline = FreshStartPipeline::with_telemetry_peer("claude-2c-si-twin");
    let passes = ["2026-08-20T10:30:00Z", "2026-08-20T10:40:00Z"];
    let mut on = Vec::new();
    {
        let _overrides = fresh_start_overrides(true);
        for collected_at in passes {
            let mut completion = funded_completion();
            let (items, disposition) =
                pipeline.pass_with_disposition(collected_at, true, Some(&mut completion));
            if on.is_empty() {
                assert_eq!(pipeline.state(), Some("verified"), "pass N verifies");
            }
            on.push((items, ownership(&disposition)));
        }
        assert_eq!(pipeline.state(), Some("emitted"));
    }
    pipeline.index = ScanIndex::default();
    let mut off = Vec::new();
    {
        let _overrides = fresh_start_overrides(false);
        for (pass, collected_at) in passes.into_iter().enumerate() {
            if pass == 1 {
                pipeline.force_rearm();
            }
            let mut completion = funded_completion();
            let (items, disposition) =
                pipeline.pass_with_disposition(collected_at, true, Some(&mut completion));
            off.push((items, ownership(&disposition)));
        }
        assert_eq!(pipeline.state(), None, "off writes no witness");
    }
    let body = |items: &[SnapshotItem], session: &str| {
        let item = items
            .iter()
            .find(|item| item.source_session_id == session)
            .unwrap_or_else(|| panic!("{session} parsed"))
            .clone();
        let value = serde_json::to_value(&item).expect("body");
        (item, value)
    };
    // Pass N: the root is not admitted yet, so every body is byte-identical,
    // and the ownership the census settled is the same.
    assert_eq!(on[0].1, off[0].1, "pass N ownership");
    for session in [FRESH_START_ROOT, FRESH_START_PEER] {
        assert_eq!(
            body(&on[0].0, session).1,
            body(&off[0].0, session).1,
            "{session}"
        );
    }
    // Pass N+1: the 2c re-arm and the forced re-arm re-parse the same root.
    assert_eq!(on[1].1, off[1].1, "pass N+1 ownership");
    let parsed = |items: &[SnapshotItem]| {
        items
            .iter()
            .map(|item| item.source_session_id.clone())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(parsed(&on[1].0), parsed(&off[1].0));
    let (admitted, admitted_body) = body(&on[1].0, FRESH_START_ROOT);
    let (twin, twin_body) = body(&off[1].0, FRESH_START_ROOT);
    assert_eq!(
        fresh_start_scalars(std::slice::from_ref(&admitted)),
        Some((Some(100), Some(300), Some(200)))
    );
    assert_eq!(
        fresh_start_scalars(std::slice::from_ref(&twin)),
        Some((None, None, None))
    );
    // The identity path really ran for the root (contract 5 took it).
    assert_eq!(
        twin.provenance.collector,
        crate::snapshots::claude_request_identity::COLLECTOR
    );
    let (admitted_body, twin_body) = (
        admitted_body.as_object().expect("body object"),
        twin_body.as_object().expect("body object"),
    );
    let differing = admitted_body
        .keys()
        .chain(twin_body.keys())
        .filter(|key| admitted_body.get(*key) != twin_body.get(*key))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let context_only = BTreeSet::from([
        "compaction_count",
        "compaction_timestamps",
        "compaction_total_cumulative_dropped_tokens",
        "compaction_total_duration_ms",
        "compaction_total_post_tokens",
        "compaction_total_pre_tokens",
        "first_turn_context_tokens",
        "last_turn_context_tokens",
        "peak_context_fill_tokens",
        "snapshot_fingerprint",
    ]);
    assert!(
        differing.is_subset(&context_only),
        "only context scalars differ: {differing:?}"
    );
    for identity_field in [
        "request_evidence",
        "request_identity_refusals",
        "attribution_facts",
        "session_account_evidence",
        "usage_accounting_contract",
        "provenance",
    ] {
        assert_eq!(
            admitted_body.get(identity_field),
            twin_body.get(identity_field),
            "{identity_field}"
        );
    }
    assert_eq!(admitted.request_evidence, twin.request_evidence);
    assert_eq!(
        admitted.request_identity_refusals,
        twin.request_identity_refusals
    );
    assert_eq!(
        admitted.claude_account_withheld_reason,
        twin.claude_account_withheld_reason
    );
}

// ---------------------------------------------------------------------------
// SOURCE P3-3: the real `finish_sync_source` settlement against a fake
// backend. A verified fresh root is admitted in finish's own fold and its
// body is uploaded with numbers; only the backend's answer differs.

/// How the fake backend answers every offered body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FreshStartFinishAck {
    /// An `accepted` entity: the server holds the body.
    Accepted,
    /// A plain `unchanged` entity: the identical body is already stored.
    PlainUnchanged,
    /// An h573 `unchanged` entity with `unchanged_basis`: not stored.
    DominatedBasis,
    /// `accepted`, but the local upload checkpoint cannot be saved after it.
    LocalSaveFailure,
}

struct FreshStartFinishServer {
    url: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    offered: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl FreshStartFinishServer {
    fn new(ack: FreshStartFinishAck) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let offered = Arc::new(Mutex::new(Vec::new()));
        let bodies = offered.clone();
        let worker = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic 2c finish accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let request = read_complete_http_request(&mut stream);
                assert!(http_request_complete(request.as_bytes()));
                let raw = request.split_once("\r\n\r\n").unwrap().1;
                let value: serde_json::Value = if raw.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_str(raw).unwrap()
                };
                let response = if request.contains("/relay-token") {
                    serde_json::json!({"token":"synthetic-2c-token","expires_at":"2099-01-01T00:00:00Z"})
                } else if request.contains("/activity-hints") {
                    // The contract-5 cohort token: this cycle holds the permit.
                    serde_json::json!({"source":"claude_code","server_time":current_rfc3339(),
                        "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
                        "local_usage_reconciliation_enabled":true,"backfill_window_days":183,
                        "session_request_identity_contract":"own_request_identity_rows:v1",
                        "recommended_scan_after":"2099-01-01T00:00:00Z"})
                } else if request.contains("/agent-status/snapshots") {
                    serde_json::json!({"accepted":1,"machine_id":"otm_test","sources":["claude_code"]})
                } else if let Some(items) = value.get("snapshots").and_then(|v| v.as_array()) {
                    assert!(!items.is_empty());
                    bodies.lock().unwrap().extend(items.iter().cloned());
                    let entities = items
                        .iter()
                        .map(|item| {
                            assert!(item.get("cache_observations").is_none());
                            assert!(item.get("context_curve").is_none());
                            let mut payload = serde_json::Map::new();
                            for key in ["session_account_evidence", "tool_usage", "tool_usage_truncated"] {
                                if let Some(value) = item.get(key) {
                                    payload.insert(key.into(), value.clone());
                                }
                            }
                            let exclusive = item.get("usage_accounting_contract").and_then(|v| v.as_str())
                                == Some("session_exclusive_reported_usage:v1");
                            let version = item.get("session_account_evidence").is_some()
                                .then_some(if exclusive { 8u64 } else { 7u64 });
                            let digest = format!("{:x}", Sha256::digest(
                                crate::canonical_json::canonicalize(&serde_json::Value::Object(payload)).unwrap()));
                            let mut entity = serde_json::json!({"source_session_id":item["source_session_id"],
                                "snapshot_fingerprint":item["snapshot_fingerprint"],"occurrence_count":1,
                                "body_witness_version":version,"body_witness_digest":version.map(|_| digest)});
                            if ack == FreshStartFinishAck::DominatedBasis {
                                entity["unchanged_basis"] = serde_json::json!("dominated_by_head");
                            }
                            entity
                        })
                        .collect::<Vec<_>>();
                    let unchanged = matches!(
                        ack,
                        FreshStartFinishAck::PlainUnchanged | FreshStartFinishAck::DominatedBasis
                    );
                    let (accepted_entities, unchanged_entities) = if unchanged {
                        (Vec::new(), entities)
                    } else {
                        (entities, Vec::new())
                    };
                    serde_json::json!({"accepted":items.len(),"sessions_reconciled":items.len(),
                        "session_ids":[],"disabled":false,"disabled_reason":null,
                        "entity_ack_contract":"snapshot_entity_ack:v1",
                        "accepted_entities":accepted_entities,"unchanged_entities":unchanged_entities,
                        "rejected_entities":[],"conflict_entities":[]})
                } else {
                    serde_json::json!({"accepted":true,"source":"claude_code","machine_id":"otm_test","disabled":false})
                };
                bounded_native_response(&mut stream, "200 OK", &response.to_string());
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            offered,
        }
    }
}

impl Drop for FreshStartFinishServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let result = self.worker.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

/// One real prepare, scan and `finish_sync_source` cycle for a verified fresh
/// root, answered by `ack`. Returns the finish result, the offered body of the
/// root, and the witness state in the saved index.
fn fresh_start_finish(
    ack: FreshStartFinishAck,
) -> Option<(Result<()>, serde_json::Value, Option<&'static str>)> {
    if !crate::heap_layout_bound::layout_supported() {
        writeln!(std::io::stderr().lock(), "fresh_start_finish: ack={ack:?} supported_positive=UNEXECUTED layout_supported=false").unwrap();
        return None;
    }
    let base = test_dir(&format!("claude-2c-finish-{ack:?}"));
    let home = base.join("home");
    let project = home.join(".claude").join("projects").join("-synthetic-repo");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(
        home.join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions"),
    )
    .unwrap();
    // A fresh root an hour old, led by an owned org marker; its file was born
    // just before its first record.
    let at = |seconds_ago: i64| {
        (OffsetDateTime::now_utc() - TimeDuration::seconds(seconds_ago))
            .replace_nanosecond(0)
            .unwrap()
            .format(&Rfc3339)
            .unwrap()
    };
    let root = FRESH_START_ROOT;
    let mut lines = vec![
        serde_json::json!({"timestamp": at(3600), "type": "attachment", "sessionId": root,
            "attachment": {"type": "credential_org", "organizationUuid": FRESH_START_ORG}}),
        serde_json::json!({"timestamp": at(3600), "type": "user", "uuid": "u_0", "sessionId": root,
            "message": {"role": "user", "content": "x"}}),
    ];
    for (request, seconds_ago, input_tokens) in
        [("req_1", 3598, 100), ("req_2", 3596, 300), ("req_3", 3595, 200)]
    {
        lines.push(serde_json::json!({"timestamp": at(seconds_ago), "type": "assistant",
            "uuid": format!("u_{request}"), "sessionId": root, "requestId": request,
            "message": {"id": format!("msg_{request}"), "model": "claude-haiku-4-5",
                "usage": {"input_tokens": input_tokens, "output_tokens": 1}}}));
    }
    std::fs::write(
        project.join(format!("{root}.jsonl")),
        lines
            .iter()
            .map(|line| line.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let _overrides = crate::snapshots::ClaudeFreshStartTestOverrides::new(
        true,
        &[(root, fresh_start_ms(&at(3630)))],
        None,
    );
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let cadence = IdentityPipelineCadence::new();
    let support = base.join("support");
    let secrets = base.join("secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = FreshStartFinishServer::new(ack);
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device = LocalDeviceBinding {
        device_id: "fresh-start-finish-device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["claude_code".into()],
    };
    FileDeviceStore::default().save(&device).unwrap();
    std::fs::write(
        secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .unwrap();
    let client = SnapshotApiClient::new(server.url.clone());
    let daemon = test_daemon("otm_test");
    let mut transport = crate::net_resilience::TransportCycleOutcome::default();
    let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
    let collection = || AgentStatusCollection {
        snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
        source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    };
    cadence.next_due_cycle();
    let frame = crate::agent_status_refresh::with_test_collection(collection(), || {
        prepare_sync_source(
            &client,
            &device,
            "device-secret",
            SnapshotSource::ClaudeCode,
            "otm_test",
            &home,
            &support,
            &daemon,
            &mut transport,
            daemon.snapshot_scan_account_witness().unwrap(),
            false,
        )
    })
    .unwrap()
    .expect("a due Claude cycle prepares a scan");
    let (preparation, mut index, scan) = collect_native_preparation_with_rotation(frame, false);
    assert!(scan.census_complete);
    assert!(
        cycle_request_identity_permit(SnapshotSource::ClaudeCode, &preparation.activity_hint)
            .is_some(),
        "the cycle holds the contract-5 permit"
    );
    // An earlier accepted census verified this exact revision.
    assert!(
        crate::snapshots::claude_fresh_start_verify_for_test(&mut index, root),
        "the parse recorded the candidate"
    );
    let index_path = preparation.index_path.clone();
    if ack == FreshStartFinishAck::LocalSaveFailure {
        // Every save of the upload checkpoint fails; the first one runs only
        // after the server's ACK.
        let progress_path = preparation.upload_progress_path.clone();
        let _ = std::fs::remove_file(&progress_path);
        std::fs::create_dir_all(progress_path.join("blocked")).unwrap();
    }
    let result = crate::agent_status_refresh::with_test_collection(collection(), || {
        finish_sync_source(
            preparation,
            index,
            scan,
            &client,
            &device,
            "device-secret",
            SnapshotSource::ClaudeCode,
            "otm_test",
            &home,
            &support,
            &daemon,
            &mut transport,
            &mut retry,
        )
    });
    let body = server
        .offered
        .lock()
        .unwrap()
        .iter()
        .find(|body| body["source_session_id"] == root)
        .cloned()
        .expect("the root's body was offered");
    let saved = ScanIndex::load(&index_path).unwrap();
    let state = crate::snapshots::claude_fresh_start_state_for_test(&saved, root);
    drop(server);
    let _ = std::fs::remove_dir_all(&base);
    Some((result, body, state))
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn finish_sync_source_marks_emitted_only_when_the_server_stores_the_admitted_body() {
    for ack in [
        FreshStartFinishAck::Accepted,
        FreshStartFinishAck::PlainUnchanged,
        FreshStartFinishAck::DominatedBasis,
        FreshStartFinishAck::LocalSaveFailure,
    ] {
        let Some((result, body, state)) = fresh_start_finish(ack) else {
            return;
        };
        // Finish's own fold admitted the verified root: the body carries the
        // census-verified numbers.
        for (field, expected) in [
            ("first_turn_context_tokens", 100),
            ("peak_context_fill_tokens", 300),
            ("last_turn_context_tokens", 200),
        ] {
            assert_eq!(
                body.get(field).and_then(serde_json::Value::as_u64),
                Some(expected),
                "{ack:?}: {field}"
            );
        }
        match ack {
            FreshStartFinishAck::Accepted | FreshStartFinishAck::PlainUnchanged => {
                assert!(result.is_ok(), "{ack:?}: {result:?}");
                assert_eq!(state, Some("emitted"), "{ack:?}: the server holds the body");
            }
            FreshStartFinishAck::DominatedBasis => {
                assert!(result.is_ok(), "{ack:?}: {result:?}");
                assert_eq!(
                    state,
                    Some("verified"),
                    "{ack:?}: not stored, so not emitted and not retried"
                );
            }
            FreshStartFinishAck::LocalSaveFailure => {
                assert!(result.is_err(), "{ack:?}: the checkpoint save failed");
                assert_ne!(
                    state,
                    Some("emitted"),
                    "{ack:?}: a local-state error never certifies the ACK"
                );
            }
        }
        writeln!(
            std::io::stderr().lock(),
            "claude_2c_finish: ack={ack:?} state={state:?}"
        )
        .unwrap();
    }
}
