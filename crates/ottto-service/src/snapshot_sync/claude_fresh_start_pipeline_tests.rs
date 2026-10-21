// Slice 2c (P4) through the local-evidence step production runs,
// `try_apply_claude_local_evidence_to_scan_with_comparison`: H5 settles a
// root's telemetry only through the existing sidecar-absence check, the root
// set is funded from the native reservation before it is allocated (T18), and
// the switch off changes nothing. The SI twin (BASE-equivalence) runs a
// telemetry-proven peer beside the fresh root. Synthetic fixtures only.
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

    fn pass_with_disposition(
        &mut self,
        collected_at: &str,
        permit: bool,
        comparison: Option<&mut crate::snapshots::claude_native_comparison::Completion>,
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
        let (disposition, _, _) = try_apply_claude_local_evidence_to_scan_with_comparison(
            &self.support,
            &mut scan,
            &mut self.index,
            permit.then(crate::snapshots::claude_emission_permit_for_test),
            None,
            comparison,
            None,
        )
        .expect("a 2c funding refusal never fails the page");
        let items = scan.snapshots.clone();
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut self.index);
        let applied = items
            .iter()
            .filter(|item| {
                disposition
                    .fresh_start_admitted
                    .contains(&item.source_session_id)
            })
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        crate::snapshots::settle_claude_fresh_start_emissions(
            &mut self.index,
            &items,
            &disposition.fresh_start_admitted,
            &applied,
        );
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
    crate::snapshots::ClaudeFreshStartTestOverrides::new(
        enabled,
        &[(FRESH_START_ROOT, fresh_start_ms("2026-08-20T09:59:30Z"))],
        Some(true),
    )
}

#[test]
fn h5_settles_an_absent_sidecar_root_through_the_production_evidence_step() {
    let _overrides = fresh_start_overrides(true);
    let mut pipeline = FreshStartPipeline::new("claude-2c-h5-e2e");
    // Census pass: both sidecars confirmed absent by the existing check (the
    // contract-5 permit path), so the candidate verifies and is re-armed.
    let first = pipeline.pass("2026-08-20T10:30:00Z", true, None);
    assert_eq!(fresh_start_scalars(&first), Some((None, None, None)));
    assert_eq!(pipeline.state(), Some("verified"));
    // The corrective parse carries the numbers; the server applies them.
    let second = pipeline.pass("2026-08-20T10:40:00Z", true, None);
    assert_eq!(
        fresh_start_scalars(&second),
        Some((Some(100), Some(300), Some(200)))
    );
    assert_eq!(pipeline.state(), Some("emitted"));
    let third = pipeline.pass("2026-08-20T10:50:00Z", true, None);
    assert!(third.is_empty(), "no replay loop");

    // Review B-F5 (routed, unchanged here): without the permit no absence
    // check runs, nothing settles, and the candidate waits without a re-arm.
    let mut unpermitted = FreshStartPipeline::new("claude-2c-h5-no-permit");
    let first = unpermitted.pass("2026-08-20T10:30:00Z", false, None);
    assert_eq!(fresh_start_scalars(&first), Some((None, None, None)));
    assert_eq!(unpermitted.state(), Some("candidate"));
    assert!(unpermitted
        .pass("2026-08-20T10:40:00Z", false, None)
        .is_empty());
}

#[test]
fn t18_an_unfunded_root_set_refuses_2c_and_keeps_the_strict_body() {
    // T18 (P4): the settled-root set is charged to the moving native
    // reservation before it is allocated. With no remainder, 2c is refused
    // for the fold (no verification, strict body) and the page still folds;
    // a funded fold verifies and returns its credit afterwards.
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
    // The census pass that parses the new candidate needs funds for its
    // settled-root set.
    let mut refused = FreshStartPipeline::new("claude-2c-t18-refused");
    let mut completion =
        crate::snapshots::claude_native_comparison::Completion::reservation_only_for_test(
            unfunded_reservation(),
        );
    let unfunded = refused.pass("2026-08-20T10:30:00Z", true, Some(&mut completion));
    assert_eq!(
        fresh_start_scalars(&unfunded),
        strict_body,
        "refused 2c keeps the strict body"
    );
    assert_eq!(refused.state(), Some("candidate"), "no verification");
    assert_eq!(completion.reservation_allocated_for_test(), Some(0));
    assert!(refused.pass("2026-08-20T10:40:00Z", true, None).is_empty());

    // Funded: the same census pass verifies, and the credit is returned.
    let mut funded = FreshStartPipeline::new("claude-2c-t18-funded");
    let mut completion =
        crate::snapshots::claude_native_comparison::Completion::reservation_only_for_test(
            crate::source_rotation::PaidReservation::from_remainder(Some(1 << 20), 0, 0),
        );
    funded.pass("2026-08-20T10:30:00Z", true, Some(&mut completion));
    assert_eq!(funded.state(), Some("verified"));
    assert_eq!(completion.reservation_allocated_for_test(), Some(0));
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
            let (items, disposition) = pipeline.pass_with_disposition(collected_at, true, None);
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
            let (items, disposition) = pipeline.pass_with_disposition(collected_at, true, None);
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
