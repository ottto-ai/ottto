// Slice 2c (P4) through the local-evidence step production runs,
// `try_apply_claude_local_evidence_to_scan_with_comparison`: H5 settles a
// root's telemetry only through the existing sidecar-absence check, the root
// set is funded from the native reservation before it is allocated (T18), and
// the switch off changes nothing. Synthetic transcripts only; no sidecars.
use super::*;

const FRESH_START_ROOT: &str = "f1000000-0000-4000-8000-00000000001f";

fn fresh_start_ms(timestamp: &str) -> i64 {
    let at = OffsetDateTime::parse(timestamp, &Rfc3339).expect("RFC 3339 fixture");
    i64::try_from(at.unix_timestamp_nanos() / 1_000_000).expect("fixture time")
}

/// One fresh root transcript: three responses with unique request ids.
fn fresh_start_transcript(dir: &Path) {
    let root = FRESH_START_ROOT;
    let user = format!(
        "{{\"timestamp\":\"2026-08-20T10:00:00Z\",\"type\":\"user\",\"uuid\":\"u_0\",\"sessionId\":\"{root}\",\"message\":{{\"role\":\"user\",\"content\":\"x\"}}}}\n"
    );
    let assistant = |request: &str, second: u32, input_tokens: u64| {
        format!(
            "{{\"timestamp\":\"2026-08-20T10:00:{second:02}Z\",\"type\":\"assistant\",\"uuid\":\"u_{request}\",\"sessionId\":\"{root}\",\"requestId\":\"{request}\",\"message\":{{\"id\":\"msg_{request}\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":1}}}}}}\n"
        )
    };
    let body = [
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

    /// One scan page, the production evidence step, finalization, and an
    /// upload whose server applies every admitted body.
    fn pass(
        &mut self,
        collected_at: &str,
        permit: bool,
        comparison: Option<&mut crate::snapshots::claude_native_comparison::Completion>,
    ) -> Vec<SnapshotItem> {
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            &[self.transcripts.clone()],
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
        items
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
