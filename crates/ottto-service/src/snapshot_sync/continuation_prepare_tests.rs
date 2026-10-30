// Stage 1 (K1 a″, K2/P-1, K5): the continuation-local prepare and the cached
// same-cycle inputs, on synthetic fixtures. Nothing here opens a socket: the
// receipt client names an offline address and is never called, and the
// attribution key is a synthetic sentinel, never printed.

/// A destination namespace hash: a snapshot fingerprint (64 lowercase hex),
/// or the upload-progress load quarantines the file as invalid.
const CONTINUATION_NAMESPACE: &str =
    "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
/// The synthetic attribution key (a sentinel, not a real key).
const CONTINUATION_SENTINEL_KEY: [u8; 32] = [0x5a; 32];

fn continuation_sentinel_key() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(CONTINUATION_SENTINEL_KEY)
}

/// An attribution-enabled hint; `with_key` leaves the raw key in it, as the
/// hint is before the ordinary prepare takes the key out.
fn continuation_hint(with_key: bool) -> crate::snapshot_client::ActivityHintResponse {
    let mut hint = serde_json::json!({
        "source": SnapshotSource::Codex.api_slug(),
        "server_time": "2026-10-24T00:00:00Z",
        "last_data_at": null,
        "record_count_15m": 0,
        "record_count_24h": 0,
        "local_usage_reconciliation_enabled": true,
        "backfill_window_days": 30,
        "recommended_scan_after": "2026-10-24T00:05:00Z",
        "session_attribution_enabled": true,
        "session_attribution_hmac_key_version":
            crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION,
    });
    if with_key {
        hint["session_attribution_hmac_key"] =
            serde_json::Value::String(continuation_sentinel_key());
    }
    serde_json::from_value(hint).unwrap()
}

/// A destination on disk whose ordinary prepare already ran and saved
/// (backfilled, ledger migrated, upload progress claimed), with the curve
/// off: quiescent, so a continuation page may prepare on it.
struct ContinuationFixture {
    home: PathBuf,
    support_dir: PathBuf,
    index_path: PathBuf,
    upload_progress_path: PathBuf,
}

impl ContinuationFixture {
    fn quiescent(name: &str) -> Self {
        let root = test_dir(name);
        let fixture = Self {
            home: root.join("home"),
            support_dir: root.join("support"),
            index_path: root.join("codex-index.json"),
            upload_progress_path: root.join("codex-upload-progress.json"),
        };
        std::fs::create_dir_all(&fixture.home).unwrap();
        std::fs::create_dir_all(&fixture.support_dir).unwrap();
        let mut backfill = crate::backfill::BackfillState::default();
        crate::backfill::mark_backfill_complete_for_destination(
            &mut backfill,
            SnapshotSource::Codex,
            CONTINUATION_NAMESPACE,
        );
        crate::backfill::save_backfill_state(&fixture.support_dir, &backfill).unwrap();
        fixture.ordinary_prepare_saves();
        fixture
    }

    fn load(&self) -> (SnapshotUploadProgress, ScanIndex) {
        let source = SnapshotSource::Codex;
        let progress = SnapshotUploadProgress::load(
            &self.upload_progress_path,
            CONTINUATION_NAMESPACE,
            snapshot_quarantine_witness(source),
        )
        .unwrap();
        let (index, _) = ScanIndex::load_for_snapshot_source_with_origin(
            &self.index_path,
            source,
            &self.support_dir,
        )
        .unwrap();
        (progress, index)
    }

    /// The ordinary prepare's mutating steps (admission re-offer, legacy
    /// migration, upload-progress claim) and their saves, as the minting
    /// cycle ran them.
    fn ordinary_prepare_saves(&self) {
        let source = SnapshotSource::Codex;
        let (mut progress, mut index) = self.load();
        let _ = index.prepare_snapshot_admission_reoffer(SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE);
        if index.legacy_settlement_ledger_needs_migration() {
            let _ = index.prepare_legacy_settlement_reconciliation(
                source,
                LEGACY_SETTLEMENT_RECONCILE_LIMIT_PER_CYCLE,
            );
        }
        assert!(!index.legacy_settlement_ledger_needs_migration());
        let generation = cycle_replay_generation(source, false, &index, CONTINUATION_NAMESPACE);
        let now = reason_reoffer::now_unix_seconds();
        let _ = prepare_upload_progress_for_cycle_with_reoffer(
            &mut progress,
            &index,
            &generation,
            false,
            Some(&reason_reoffer::Scope {
                index: &index,
                now,
                window_start_unix_seconds: now.saturating_sub(30 * 86_400),
            }),
        );
        index.save(&self.index_path).unwrap();
        progress.save(&self.upload_progress_path).unwrap();
    }

    /// Every file a prepare could save, byte for byte.
    fn disk(&self) -> Vec<Option<Vec<u8>>> {
        [
            self.index_path.clone(),
            self.upload_progress_path.clone(),
            crate::backfill::backfill_state_path(&self.support_dir),
        ]
        .iter()
        .map(|path| std::fs::read(path).ok())
        .collect()
    }

    /// An ordinary Codex preparation of this destination (its scan already
    /// consumed), as the minting finish holds it.
    fn preparation(&self, attribution: bool) -> SourcePreparation {
        let status = test_agent_status(SourceKind::Codex);
        SourcePreparation {
            native_comparison_reservation: None,
            native_comparison_lease: None,
            prepared_claude_evidence: None,
            terminal_native_traversal: None,
            native_comparison_controller: None,
            retry_authority: None,
            source: SnapshotSource::Codex,
            claude_scan_roots: None,
            account_witness: [3; 32],
            scan_started_at: "2026-10-24T00:00:00Z".into(),
            activity_hint: continuation_hint(true),
            receipt_window_days: 30,
            context_curve_enabled: false,
            cache_observations_enabled: false,
            scan_agent_status_collection: std::sync::Arc::new(AgentStatusCollection {
                snapshots: vec![status.clone()],
                source_health_snapshot: status,
                codex_scan_homes: vec![],
                codex_home_bindings: vec![],
            }),
            attribution_context: attribution.then(|| {
                SessionAttributionContext::from_activity_hint(
                    SnapshotSource::Codex,
                    &self.home,
                    true,
                    Some(&continuation_sentinel_key()),
                    Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
                )
                .expect("a synthetic 32-byte key")
            }),
            upload_policy: SnapshotUploadPolicy {
                session_attribution_enabled: attribution,
                ..SnapshotUploadPolicy::default()
            },
            upload_destination_namespace: CONTINUATION_NAMESPACE.into(),
            receipt_client: SnapshotApiClient::new("http://offline.invalid"),
            index_path: self.index_path.clone(),
            upload_progress_path: self.upload_progress_path.clone(),
            upload_progress: test_upload_progress(),
            committed_index: ScanIndex::default(),
            backfill_state: Default::default(),
            backfill_pending: false,
            replay_generation: "ordinary".into(),
            legacy_reconciliation_pending: BTreeSet::new(),
            active_legacy_reconciliation: BTreeSet::new(),
            scan: None,
        }
    }

    fn prepare(
        &self,
        inputs: &mut ContinuationInputs,
    ) -> std::result::Result<SourcePreparation, ContinuationRefusal> {
        let cache = std::sync::Arc::new(crate::snapshots::sampled_scan::SharedCache::default());
        self.prepare_on(&cache, inputs)
    }

    fn prepare_on(
        &self,
        cache: &std::sync::Arc<crate::snapshots::sampled_scan::SharedCache>,
        inputs: &mut ContinuationInputs,
    ) -> std::result::Result<SourcePreparation, ContinuationRefusal> {
        prepare_continuation_source(
            &self.home,
            &self.support_dir,
            cache,
            inputs,
            Some(Duration::from_secs(300)),
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap()
    }

    /// An ordinary Codex pass's C14 on this destination, and its C15 when
    /// its save succeeded. Returns that pass's gate.
    fn ordinary_side_pass(
        &self,
        cache: &crate::snapshots::sampled_scan::SharedCache,
        saved: bool,
    ) -> bool {
        let (_, mut index) = self.load();
        let pass = crate::snapshots::begin_codex_side_pass(cache, &self.index_path, &mut index);
        if saved {
            let mark = crate::snapshots::codex_side_save_mark(cache, &self.index_path);
            crate::snapshots::note_codex_side_pass_saved(cache, &self.index_path, false, mark);
        }
        pass.side_allowed_for_test()
    }

    /// A refused continuation prepare after a saved ordinary pass: the
    /// refusal, no save, the context still cached, and the next ordinary
    /// pass not gated.
    fn assert_refused(&self, refusal: ContinuationRefusal) {
        let cache = std::sync::Arc::new(crate::snapshots::sampled_scan::SharedCache::default());
        self.ordinary_side_pass(&cache, true);
        let mut minted = self.preparation(true);
        let mut inputs = take_continuation_inputs(
            &mut minted,
            &std::sync::Arc::default(),
            std::sync::Arc::new(crate::snapshots::codex_version::CodexVersionFeed::new(None)),
        );
        let before = self.disk();
        assert_eq!(self.prepare_on(&cache, &mut inputs).err(), Some(refusal));
        assert_eq!(self.disk(), before, "no save, no claim, no reset");
        assert!(inputs.holds_attribution(), "a refusal keeps it cached");
        assert!(self.ordinary_side_pass(&cache, true), "no gate reset");
    }
}

#[cfg(target_os = "macos")]
pub(super) fn continuation_preparation_for_test() -> SourcePreparation {
    ContinuationFixture::quiescent("continuation-mint-finish").preparation(true)
}

/// K2: cached inputs for the continuation tests, with a drop sentinel (the
/// status collection's `Arc`, whose count falls back to one when the inputs,
/// and the context with them, are dropped).
pub(super) fn continuation_inputs_for_test(
    attribution: bool,
) -> (ContinuationInputs, std::sync::Arc<AgentStatusCollection>) {
    let fixture = ContinuationFixture::quiescent("continuation-inputs-for-test");
    let mut preparation = fixture.preparation(attribution);
    let inputs = take_continuation_inputs(
        &mut preparation,
        &std::sync::Arc::default(),
        std::sync::Arc::new(crate::snapshots::codex_version::CodexVersionFeed::new(None)),
    );
    let sentinel = std::sync::Arc::clone(&preparation.scan_agent_status_collection);
    drop(preparation);
    (inputs, sentinel)
}

#[test]
fn continuation_inputs_move_the_context_and_cache_no_raw_key() {
    let fixture = ContinuationFixture::quiescent("continuation-inputs-move");
    let mut preparation = fixture.preparation(true);
    assert!(preparation.attribution_context.is_some());
    assert!(preparation
        .activity_hint
        .session_attribution_hmac_key
        .is_some());
    let inputs = take_continuation_inputs(
        &mut preparation,
        &std::sync::Arc::default(),
        std::sync::Arc::new(crate::snapshots::codex_version::CodexVersionFeed::new(None)),
    );
    assert!(
        preparation.attribution_context.is_none(),
        "moved out, not copied"
    );
    assert!(inputs.holds_attribution());
    assert!(
        inputs.activity_hint.session_attribution_hmac_key.is_none(),
        "the cached hint holds no raw key"
    );
    let sentinel = &preparation.scan_agent_status_collection;
    assert_eq!(std::sync::Arc::strong_count(sentinel), 2);
    drop(inputs);
    assert_eq!(
        std::sync::Arc::strong_count(sentinel),
        1,
        "dropped, with its context"
    );
}

/// K1.3: on a quiescent destination the continuation prepare yields the
/// preparation the ordinary prepare's tail yields, on every field
/// `finish_sync_source` reads, except the documented SKIPs; and it saves
/// nothing.
#[test]
fn the_continuation_prepare_matches_the_ordinary_tail_on_a_quiescent_fixture() {
    let fixture = ContinuationFixture::quiescent("continuation-prepare-parity");
    let mut minted = fixture.preparation(true);
    let mut inputs = take_continuation_inputs(
        &mut minted,
        &std::sync::Arc::default(),
        std::sync::Arc::new(crate::snapshots::codex_version::CodexVersionFeed::new(None)),
    );
    let before = fixture.disk();
    let prepared = fixture
        .prepare(&mut inputs)
        .unwrap_or_else(|refusal| panic!("refused: {}", refusal.label()));
    assert_eq!(fixture.disk(), before, "no save, no claim, no reset");
    assert!(!inputs.holds_attribution(), "moved into the preparation");
    assert!(prepared.attribution_context.is_some());

    // The cached same-cycle inputs.
    assert_eq!(prepared.source, SnapshotSource::Codex);
    assert_eq!(prepared.account_witness, minted.account_witness);
    assert_eq!(prepared.receipt_window_days, minted.receipt_window_days);
    assert_eq!(prepared.context_curve_enabled, minted.context_curve_enabled);
    assert_eq!(
        prepared.cache_observations_enabled,
        minted.cache_observations_enabled
    );
    assert!(std::sync::Arc::ptr_eq(
        &prepared.scan_agent_status_collection,
        &minted.scan_agent_status_collection
    ));
    assert_eq!(prepared.upload_policy, minted.upload_policy);
    assert_eq!(
        prepared.upload_destination_namespace,
        minted.upload_destination_namespace
    );
    assert_eq!(
        format!("{:?}", prepared.receipt_client),
        format!("{:?}", minted.receipt_client)
    );
    assert_eq!(prepared.index_path, minted.index_path);
    assert_eq!(prepared.upload_progress_path, minted.upload_progress_path);
    assert!(prepared
        .activity_hint
        .session_attribution_hmac_key
        .is_none());
    assert_eq!(
        prepared.activity_hint.backfill_window_days,
        minted.activity_hint.backfill_window_days
    );

    // The documented SKIPs.
    assert!(
        prepared.retry_authority.is_none(),
        "no LiveAuthority capture"
    );
    assert!(!prepared.backfill_pending);
    assert!(prepared.legacy_reconciliation_pending.is_empty());
    assert!(prepared.active_legacy_reconciliation.is_empty());
    assert!(prepared.claude_scan_roots.is_none());
    assert!(prepared.native_comparison_lease.is_none());
    assert!(prepared.scan.is_some());

    // The ordinary tail on the same loaded state (C14 as the continuation
    // runs it; no hint, budget, save or reset).
    let source = SnapshotSource::Codex;
    let (mut progress, mut index) = fixture.load();
    let side_cache = std::sync::Arc::new(crate::snapshots::sampled_scan::SharedCache::default());
    let _pass = crate::snapshots::begin_codex_continuation_side_pass(
        &side_cache,
        &fixture.index_path,
        &mut index,
    );
    let checkpoint = prepared
        .attribution_context
        .as_ref()
        .map(SessionAttributionContext::checkpoint_namespace);
    activate_source_upload_context(
        source,
        cycle_upload_context(minted.upload_policy, checkpoint.as_deref(), false),
        &mut index,
        &mut progress,
    );
    let generation = cycle_replay_generation(source, false, &index, CONTINUATION_NAMESPACE);
    assert_eq!(prepared.replay_generation, generation);
    let now = reason_reoffer::now_unix_seconds();
    let claimed = prepare_upload_progress_for_cycle_with_reoffer(
        &mut progress,
        &index,
        &generation,
        false,
        Some(&reason_reoffer::Scope {
            index: &index,
            now,
            window_start_unix_seconds: now.saturating_sub(30 * 86_400),
        }),
    );
    assert!(!claimed, "quiescent: the minting cycle claimed already");
    index.activate_effective_upload_body_witness_revision(effective_upload_body_witness_revision(
        source,
    ));
    assert_eq!(
        serde_json::to_value(&prepared.committed_index).unwrap(),
        serde_json::to_value(&index).unwrap(),
        "K3: the committed state before the scan"
    );
    let mut scan_index = index.clone();
    scan_index.activate_reason_reoffer_retries(progress.active_reason_reoffers.clone());
    scan_index.activate_reason_reoffer_cooldowns(progress.reason_reoffer_cooldowns(now));
    progress.reselect_pending_cache_heads(&mut scan_index, false);
    assert_eq!(prepared.upload_progress, progress);
    assert_eq!(
        serde_json::to_value(&prepared.backfill_state).unwrap(),
        serde_json::to_value(load_backfill_state(&fixture.support_dir)).unwrap()
    );
}

/// K1.1: a destination with a historical replay pending refuses before any
/// read, saves nothing and keeps the context in the cached inputs.
#[test]
fn a_pending_historical_replay_refuses_the_continuation_prepare() {
    let fixture = ContinuationFixture::quiescent("continuation-prepare-replay");
    crate::backfill::save_backfill_state(
        &fixture.support_dir,
        &crate::backfill::BackfillState::default(),
    )
    .unwrap();
    let mut minted = fixture.preparation(true);
    let mut inputs = take_continuation_inputs(
        &mut minted,
        &std::sync::Arc::default(),
        std::sync::Arc::new(crate::snapshots::codex_version::CodexVersionFeed::new(None)),
    );
    let before = fixture.disk();
    assert_eq!(
        fixture.prepare(&mut inputs).err(),
        Some(ContinuationRefusal::HistoricalReplay)
    );
    assert_eq!(fixture.disk(), before);
    assert!(inputs.holds_attribution(), "a refusal keeps it cached");
}

/// K1 (a″): the upload-claim predicate is the ordinary selection's answer
/// on a copy: it never changes the loaded progress.
#[test]
fn the_upload_claim_predicate_is_pure_and_matches_the_ordinary_selection() {
    let fixture = ContinuationFixture::quiescent("continuation-claim-predicate");
    let (progress, index) = fixture.load();
    let now = reason_reoffer::now_unix_seconds();
    let scope = reason_reoffer::Scope {
        index: &index,
        now,
        window_start_unix_seconds: now.saturating_sub(30 * 86_400),
    };
    for generation in [
        cycle_replay_generation(SnapshotSource::Codex, false, &index, CONTINUATION_NAMESPACE),
        "another-generation".to_string(),
    ] {
        let unchanged = progress.clone();
        let needed = continuation_upload_claim_needed(&progress, &index, &generation, &scope);
        assert_eq!(progress, unchanged, "pure");
        let mut ordinary = progress.clone();
        assert_eq!(
            needed,
            prepare_upload_progress_for_cycle_with_reoffer(
                &mut ordinary,
                &index,
                &generation,
                false,
                Some(&scope)
            )
        );
    }
}

/// Contract-5 cutover, byte-stable keys (Lead B): a Claude cycle's sampled
/// scope keeps the permit-era permitted `:request_identity` suffix for good,
/// and a Codex cycle keeps its suffix-free bytes, so durable records and
/// retained parsers written before the cutover still bind after it. Golden
/// digests of the pre-cutover scope strings.
#[test]
fn the_always_on_sampled_scope_keeps_the_permit_era_bytes() {
    use crate::snapshots::claude_request_identity::captures;
    let witness = [3u8; 32];
    let index_path = Path::new("/tmp/ottto-continuation-scope-index.json");
    for (source, curve, golden) in [
        (
            SnapshotSource::ClaudeCode,
            false,
            "c58cf74dc52ebcdb56cce301dde881fac71e0045ddf127d0137ed7d16b80ae55",
        ),
        (
            SnapshotSource::ClaudeCode,
            true,
            "2d63534231ce46641c37958033fe49bdfb683d2592f1648ddd715ac412022292",
        ),
        (
            SnapshotSource::Codex,
            false,
            "26648c9996bbbd2102f21bab2bd0a6c2fc6a522bb3b159ba6869d5c645d9df04",
        ),
        (
            SnapshotSource::Codex,
            true,
            "a9cd90d380262e8c616ed6ff63cb6bbc1b568a8b375526a90b32a94f6537103d",
        ),
    ] {
        let scope = cycle_sampled_scope(
            &witness,
            CONTINUATION_NAMESPACE,
            index_path,
            curve,
            captures(source),
        );
        assert_eq!(scope.0, golden, "{source:?} curve={curve}");
    }
}

/// K2: no serialized output of a continuation preparation carries the
/// context's key.
#[test]
fn no_continuation_output_serializes_the_attribution_key() {
    let fixture = ContinuationFixture::quiescent("continuation-no-key-output");
    let mut minted = fixture.preparation(true);
    let mut inputs = take_continuation_inputs(
        &mut minted,
        &std::sync::Arc::default(),
        std::sync::Arc::new(crate::snapshots::codex_version::CodexVersionFeed::new(None)),
    );
    let prepared = fixture
        .prepare(&mut inputs)
        .unwrap_or_else(|refusal| panic!("refused: {}", refusal.label()));
    let encoded = continuation_sentinel_key();
    let hex = CONTINUATION_SENTINEL_KEY
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    for (name, output) in [
        (
            "committed index",
            serde_json::to_string(&prepared.committed_index).unwrap(),
        ),
        (
            "upload progress",
            serde_json::to_string(&prepared.upload_progress).unwrap(),
        ),
        (
            "backfill state",
            serde_json::to_string(&prepared.backfill_state).unwrap(),
        ),
        (
            "upload policy",
            serde_json::to_string(&prepared.upload_policy).unwrap(),
        ),
    ] {
        assert!(!output.contains(&encoded), "{name}");
        assert!(!output.contains(&hex), "{name}");
    }
}

/// K1.1 (C-1 lease): a destination whose ordinary prepare armed an
/// admission re-offer refuses before any read.
#[test]
fn a_pending_admission_reoffer_refuses_the_continuation_prepare() {
    let fixture = ContinuationFixture::quiescent("continuation-prepare-admission");
    let (_, mut index) = fixture.load();
    let fingerprint = "e".repeat(64);
    index.file_snapshot_fingerprints.insert(
        "/synthetic/admission.jsonl".into(),
        BTreeSet::from([fingerprint.clone()]),
    );
    // A refusal under a smaller item limit, as before a reviewed admission
    // increase.
    index.quarantined_snapshot_fingerprints.insert(
        fingerprint,
        SnapshotQuarantineRecord {
            contract_retry_claims: None,
            reconstruction_contract: crate::snapshots::terminal_contract_retry::current_contract(),
            witness: SnapshotQuarantineWitness {
                item_wire_byte_limit: 128 * 1024,
                ..snapshot_quarantine_witness(SnapshotSource::Codex)
            },
            retry_after_unix_seconds: 0,
            upload_body_witness: None,
            failed_reconstruction_count: MAX_SNAPSHOT_RECONSTRUCTION_FAILURES,
            disposition: SnapshotQuarantineDisposition::UnprovenTerminal,
        },
    );
    // The ordinary prepare's arming and save.
    assert!(index.prepare_snapshot_admission_reoffer(SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE));
    index.save(&fixture.index_path).unwrap();
    assert!(fixture.load().1.snapshot_admission_reoffer_pending());
    fixture.assert_refused(ContinuationRefusal::AdmissionReoffer);
}

/// K1.1 (C-1 lease): an accepted ledger the legacy settlement has not yet
/// migrated (the unproven version the first migration wrote) refuses
/// before any read.
#[test]
fn a_pending_legacy_settlement_refuses_the_continuation_prepare() {
    let fixture = ContinuationFixture::quiescent("continuation-prepare-legacy");
    let (_, index) = fixture.load();
    let mut value = serde_json::to_value(&index).unwrap();
    value["accepted_snapshot_fingerprint_ledger_version"] = serde_json::json!(1);
    let mut index: ScanIndex = serde_json::from_value(value).unwrap();
    assert!(index.legacy_settlement_ledger_needs_migration());
    assert!(!index.snapshot_admission_reoffer_pending());
    index.save(&fixture.index_path).unwrap();
    assert!(fixture.load().1.legacy_settlement_ledger_needs_migration());
    fixture.assert_refused(ContinuationRefusal::LegacySettlement);
}

/// K1 (a″, C-1 lease): a due quarantine retry the ordinary selection would
/// lease (and save) refuses at the pure probe, before C14.
#[test]
fn a_due_quarantine_retry_refuses_the_continuation_prepare() {
    let fixture = ContinuationFixture::quiescent("continuation-prepare-claim");
    let (mut progress, _) = fixture.load();
    progress.quarantined_fingerprints.insert(
        "f".repeat(64),
        SnapshotQuarantineRecord {
            contract_retry_claims: None,
            reconstruction_contract: crate::snapshots::terminal_contract_retry::current_contract(),
            witness: snapshot_quarantine_witness(SnapshotSource::Codex),
            retry_after_unix_seconds: 0,
            upload_body_witness: None,
            failed_reconstruction_count: 1,
            disposition: SnapshotQuarantineDisposition::RetryPending,
        },
    );
    progress.save(&fixture.upload_progress_path).unwrap();
    fixture.assert_refused(ContinuationRefusal::UploadClaim);
}

/// K1 (a″, C-1 lease): a due, exactly bound reason re-offer. The ordinary
/// selection that activates a re-offer always reports a claim, so the page
/// refuses at the pure probe, before C14 (UploadClaim); the post-claim
/// ReasonReoffer arm stays the backstop and is not reachable from disk.
#[test]
fn a_due_reason_reoffer_refuses_the_continuation_prepare() {
    let fixture = ContinuationFixture::quiescent("continuation-prepare-reoffer");
    let fingerprint = "d".repeat(64);
    let body = "b".repeat(64);
    let (mut progress, mut index) = fixture.load();
    index.file_snapshot_fingerprints.insert(
        "/synthetic/reoffer.jsonl".into(),
        BTreeSet::from([fingerprint.clone()]),
    );
    index.quarantined_snapshot_fingerprints.insert(
        fingerprint.clone(),
        SnapshotQuarantineRecord {
            contract_retry_claims: None,
            reconstruction_contract: crate::snapshots::terminal_contract_retry::current_contract(),
            witness: snapshot_quarantine_witness(SnapshotSource::Codex),
            retry_after_unix_seconds: 0,
            upload_body_witness: Some(body.clone()),
            failed_reconstruction_count: MAX_SNAPSHOT_RECONSTRUCTION_FAILURES,
            disposition: SnapshotQuarantineDisposition::UnprovenTerminal,
        },
    );
    progress.permanent_rejections.insert(
        fingerprint,
        PermanentSnapshotRejection {
            body_witness: body,
            reason: crate::upload_receipts::RejectedUsageReason::Other,
            reoffer: Some(reason_reoffer::RefusalReoffer::OriginalPair {
                retry_after_unix_seconds: 0,
            }),
        },
    );
    index.save(&fixture.index_path).unwrap();
    progress.save(&fixture.upload_progress_path).unwrap();
    let (progress, index) = fixture.load();
    assert!(!index.snapshot_admission_reoffer_pending());
    let now = reason_reoffer::now_unix_seconds();
    let mut selected = progress.clone();
    assert!(prepare_upload_progress_for_cycle_with_reoffer(
        &mut selected,
        &index,
        &cycle_replay_generation(SnapshotSource::Codex, false, &index, CONTINUATION_NAMESPACE),
        false,
        Some(&reason_reoffer::Scope {
            index: &index,
            now,
            window_start_unix_seconds: now.saturating_sub(30 * 86_400),
        }),
    ));
    assert_eq!(
        selected.active_reason_reoffers.len(),
        1,
        "a claimed re-offer"
    );
    fixture.assert_refused(ContinuationRefusal::UploadClaim);
}

/// C-1 (a), (b), (d) on the production continuation prepare: its C14 runs
/// (the page prepares; it is non-EOF, never saved, or dropped as a refusal
/// after C14 drops it) and the next ordinary pass keeps the last ordinary
/// save's outcome.
#[test]
fn a_prepared_continuation_page_keeps_the_ordinary_side_gate() {
    for ordinary_saved in [true, false] {
        let fixture = ContinuationFixture::quiescent(if ordinary_saved {
            "continuation-prepare-gate-saved"
        } else {
            "continuation-prepare-gate-failed"
        });
        let cache = std::sync::Arc::new(crate::snapshots::sampled_scan::SharedCache::default());
        assert!(fixture.ordinary_side_pass(&cache, ordinary_saved));
        let mut minted = fixture.preparation(true);
        let mut inputs = take_continuation_inputs(
            &mut minted,
            &std::sync::Arc::default(),
            std::sync::Arc::new(crate::snapshots::codex_version::CodexVersionFeed::new(None)),
        );
        let before = fixture.disk();
        let prepared = fixture
            .prepare_on(&cache, &mut inputs)
            .unwrap_or_else(|refusal| panic!("refused: {}", refusal.label()));
        drop(prepared);
        assert_eq!(fixture.disk(), before);
        assert_eq!(
            fixture.ordinary_side_pass(&cache, true),
            ordinary_saved,
            "the next ordinary pass"
        );
    }
}
