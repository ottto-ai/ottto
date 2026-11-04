// Ordinary scan, selected-save, recovery and acknowledgement controls retained
// after retiring the optional comparison experiment. Synthetic fixtures only.
use super::*;
use crate::snapshots::disappearance_diagnostics::tests::finish;

type Api = crate::claude_local_otel::ClaudeLocalOtelLoadReport;
type Trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport;

fn reports(root: &str, extra: bool) -> (Api, Trace) {
    let mut api = (1..=5)
        .map(|i| {
            complete_api_row(
                root,
                &format!("req_{i}"),
                i,
                10,
                if i == 5 { 1 } else { 10 },
                0,
            )
        })
        .collect::<Vec<_>>();
    let mut trace = (1..=5)
        .map(|i| {
            complete_trace_row(
                root,
                &format!("req_{i}"),
                if i == 5 { "a4d1585d310070d0f" } else { "" },
            )
        })
        .collect::<Vec<_>>();
    if extra {
        api.push(complete_api_row(root, "req_extra", 6, 10, 10, 0));
        trace.push(complete_trace_row(root, "req_extra", ""));
    }
    (
        Api {
            evidence: BTreeMap::from([(root.to_string(), api)]),
            health: Default::default(),
        },
        Trace {
            evidence: BTreeMap::from([(root.to_string(), trace)]),
            ..Default::default()
        },
    )
}

struct SelectionFixture {
    _scratch: crate::test_scratch::ScratchDir,
    roots: [PathBuf; 1],
    paths: [PathBuf; 4], // A, audit B, uncommitted C, A's subagent
    index_path: PathBuf,
    previous: ScanIndex,
}
impl SelectionFixture {
    fn new() -> Self {
        let scratch = crate::test_scratch::ScratchDir::new("envelope-selection-matrix");
        let root = scratch.join("native");
        fs::create_dir_all(&root).unwrap();
        let a = "a1111111-1111-4111-8111-111111111111";
        let sessions = [
            a,
            "b2222222-2222-4222-8222-222222222222",
            "c3333333-3333-4333-8333-333333333333",
            a,
        ];
        let paths = [
            root.join(format!("{a}.jsonl")),
            root.join(format!("{}.jsonl", sessions[1])),
            root.join(format!("{}.jsonl", sessions[2])),
            root.join(a).join("subagents/agent-comparison.jsonl"),
        ];
        let mut previous = ScanIndex {
            accepted_snapshot_fingerprint_ledger_version: SNAPSHOT_ACCEPTED_LEDGER_VERSION,
            ..Default::default()
        };
        for (slot, path) in paths.iter().enumerate() {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let agent = if slot == 3 {
                "\"agentId\":\"comparison\",\"isSidechain\":true,"
            } else {
                ""
            };
            fs::write(path, format!("{{\"timestamp\":\"2026-08-02T07:00:00Z\",\"type\":\"assistant\",\"sessionId\":\"{}\",{agent}\"requestId\":\"req_matrix_{slot}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n", sessions[slot])).unwrap();
            if slot != 2 {
                let body = format!("{slot:064x}");
                index_file(
                    &mut previous,
                    &local_index_key(path),
                    &hex64('a'),
                    &body,
                    WINDOW,
                );
                previous.accepted_snapshot_fingerprints.insert(body);
            }
        }
        previous
            .files
            .get_mut(&local_index_key(&paths[1]))
            .unwrap()
            .set_unverified_deadline(1);
        let index_path = scratch.join("index.json");
        previous.save(&index_path).unwrap();
        Self {
            _scratch: scratch,
            roots: [root],
            paths,
            index_path,
            previous,
        }
    }
    fn prepare(&self, index: ScanIndex, limit: usize) -> OwnedSourceScan {
        OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            &self.roots,
            index,
            WINDOW,
            30,
            limit,
            None,
            &[],
            false,
            false,
        )
    }
}

struct BodyFixture {
    dir: PathBuf,
    parent: String,
    /// The parent's own scanned item: the evidence loaders open the pairs of
    /// the roots the page's items name.
    index: ScanIndex,
    api: Api,
    trace: Trace,
}
impl BodyFixture {
    fn new() -> Self {
        let (dir, parent, _) = claude_account_family_fixture(false);
        let native = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&dir),
            ScanIndex::default(),
            WINDOW,
            30,
            8,
            None,
            &[],
            false,
            false,
        );
        let (mut index, mut scan) = finish(native);
        assert!(scan.census_complete);
        let (api, trace) = reports(&parent, false);
        // An upgraded store: the family's witness was stored by an older
        // build, and the fold rebuilds it.
        assert!(index.install_stored_claude_family_witness_for_test(
            &parent,
            &scan.snapshots,
            &api,
            &trace
        ));
        apply_claude_reported_usage_with_index(&mut scan.snapshots, &api, &trace, &mut index);
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
        index.active_upload_context_fingerprint = Some("native-preparation-test".into());
        // Model delivered history: each file holds its receipt in this context.
        let context = index.active_upload_context_fingerprint.clone().unwrap();
        for entry in index.files.values_mut() {
            entry.upload_context_receipt = Some(upload_context_receipt::Receipt {
                context_fingerprint: context.clone(),
                replay_generation: upload_context_receipt::RECEIPT_REPLAY_EPOCH,
                source_witness: entry.source_file_fingerprint.clone(),
                body_witness: entry.last_upload_body_witness.clone().unwrap_or_default(),
            });
        }
        assert!(index.claude_usage_family_witnesses.contains_key(&parent));
        Self {
            dir,
            parent,
            index,
            api,
            trace,
        }
    }
}
impl Drop for BodyFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn recovery_priority_scan(
    fixture: &SelectionFixture,
    index: ScanIndex,
    limit: usize,
    paths: &[PathBuf],
) -> OwnedSourceScan {
    OwnedSourceScan::new_selecting(
        SnapshotSource::ClaudeCode,
        &fixture.roots,
        index,
        WINDOW,
        30,
        limit,
        None,
        &[],
        false,
        &mut Default::default(),
        false,
        paths,
    )
}

#[test]
fn recovery_selection_preserves_ordinary_audit_order_and_page_limit() {
    let fixture = SelectionFixture::new();
    let mut rearmed = fixture.previous.clone();
    let key = local_index_key(&fixture.paths[0]);
    rearmed
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    rearmed.save(&fixture.index_path).unwrap();
    let rearmed = ScanIndex::load(&fixture.index_path).unwrap();
    assert!(rearmed.files[&key].source_file_fingerprint.is_empty());
    let base = fixture.prepare(rearmed, 1);
    assert_eq!(base.identified_candidates.len(), 1);
    assert_eq!(base.identified_candidates[0].path, fixture.paths[1]);
    let (index, scan) = finish(base);
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(scan.snapshots.len(), 1);
    assert!(index.files[&key].source_file_fingerprint.is_empty());
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .any(|entry| entry.path == fixture.paths[0]));
}

#[test]
fn recovery_priority_requires_scope_queued_debt_and_remaining_budget() {
    let fixture = SelectionFixture::new();
    let mut rearmed = fixture.previous.clone();
    rearmed
        .files
        .get_mut(&local_index_key(&fixture.paths[0]))
        .unwrap()
        .source_file_fingerprint
        .clear();
    let inactive = recovery_priority_scan(&fixture, rearmed.clone(), 1, &fixture.paths[..1]);
    assert_eq!(inactive.identified_candidates[0].path, fixture.paths[1]);
    let no_debt =
        recovery_priority_scan(&fixture, fixture.previous.clone(), 1, &fixture.paths[..1]);
    assert_eq!(no_debt.identified_candidates[0].path, fixture.paths[1]);
    let unknown = fixture.roots[0].join("unknown-recovery.jsonl");
    let missing = recovery_priority_scan(&fixture, rearmed.clone(), 1, &[unknown]);
    assert_eq!(
        missing.identified_candidates[0].path, fixture.paths[1],
        "missing path cannot become a synthetic queued candidate"
    );
    let zero = recovery_priority_scan(&fixture, rearmed, 0, &fixture.paths[..1]);
    assert!(zero.identified_candidates.is_empty());
}

#[test]
fn incomplete_census_keeps_its_existing_traversal_owner() {
    let fixture = SelectionFixture::new();
    let (index, scan) = finish(fixture.prepare(fixture.previous.clone(), 1));
    assert!(!scan.census_complete);
    assert!(index.traversal.is_some());
}

fn replace_candidate(state: &OwnedSourceScan) -> PathBuf {
    let path = state.identified_candidates[0].path.clone();
    let replacement = path.with_extension("replacement");
    fs::write(&replacement, fs::read(&path).unwrap()).unwrap();
    fs::rename(replacement, &path).unwrap();
    path
}

#[test]
fn replaced_selected_file_keeps_safe_open_failure_visible() {
    let fixture = SelectionFixture::new();
    let state = fixture.prepare(fixture.previous.clone(), 1);
    let path = replace_candidate(&state);
    let key = local_index_key(&path);
    let old = serde_json::to_vec(&state.index.files[&key]).unwrap();
    let (index, scan) = finish(state);
    assert_eq!(
        serde_json::to_vec(&index.files[&key]).unwrap(),
        old,
        "a replaced frozen object cannot refresh the index entry"
    );
    assert!(scan.disappeared_file_count + scan.unreadable_path_count > 0);
    assert_eq!(
        scan.scanned_file_count, 0,
        "failed read is not successful work"
    );
    assert!(scan.snapshots.is_empty());
    assert!(!scan.census_complete);
}

#[test]
fn failed_selected_file_keeps_dependent_source_unresolved() {
    let fixture = SelectionFixture::new();
    let state = fixture.prepare(fixture.previous.clone(), 2);
    let path = replace_candidate(&state);
    let key = local_index_key(&path);
    let old = serde_json::to_vec(&state.index.files[&key]).unwrap();
    let (index, scan) = finish(state);
    assert_eq!(
        scan.scanned_file_count, 1,
        "only the unchanged sibling completed"
    );
    assert_eq!(serde_json::to_vec(&index.files[&key]).unwrap(), old);
    assert!(scan
        .snapshots
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    assert!(!scan.census_complete);
}

#[test]
fn authority_quarantine_preserves_body_and_correction_debt() {
    for corrected in [false, true] {
        let fixture = BodyFixture::new();
        let mut index = fixture.index.clone();
        let witness = &index.claude_usage_family_witnesses[&fixture.parent];
        let digest = claude_usage_family_witness_fingerprint(witness);
        let members = witness
            .member_request_id_fingerprints
            .keys()
            .map(|member| {
                let key = index
                    .files
                    .keys()
                    .find(|key| {
                        claude_index_path_family_member(Path::new(key))
                            .is_some_and(|(_, current)| current == *member)
                    })
                    .unwrap();
                (
                    member.clone(),
                    index.files[key].source_file_fingerprint.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        index.claude_usage_authority_quarantine.insert(
            fixture.parent.clone(),
            ClaudeUsageAuthorityQuarantineRecord {
                contract: if corrected {
                    CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION
                } else {
                    CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION
                }
                .into(),
                proven_witness_fingerprint: digest.clone(),
                member_source_file_fingerprints: members.clone(),
                failed_reconstruction_count: MAX_CLAUDE_USAGE_AUTHORITY_FAILURES,
                disposition: ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
                retry_after_unix_seconds: claude_usage_authority_retry_deadline(
                    &fixture.parent,
                    &digest,
                ),
                proof_correction: corrected.then(|| ClaudeAuthorityProofCorrection {
                    proof_witness_fingerprint: digest,
                    owed_member_ids: members.into_keys().collect(),
                }),
            },
        );
        let held = index.current_snapshot_fingerprints();
        let selected =
            index.with_locally_held_keys_reverted(&fixture.index, &held, &BTreeSet::new());
        assert_eq!(
            serde_json::to_value(&selected.files).unwrap(),
            serde_json::to_value(&fixture.index.files).unwrap()
        );
        assert_eq!(
            selected.accepted_snapshot_fingerprints,
            fixture.index.accepted_snapshot_fingerprints
        );
        assert_eq!(
            serde_json::to_value(&selected.claude_usage_authority_quarantine).unwrap(),
            serde_json::to_value(&index.claude_usage_authority_quarantine).unwrap()
        );
    }
}

fn selected_fixture() -> (SelectionFixture, ScanIndex, SourceScanResult, ScanIndex) {
    let fixture = SelectionFixture::new();
    let previous = fixture.previous.clone();
    let (mut index, mut scan) = finish(OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        &fixture.roots,
        previous.clone(),
        WINDOW,
        30,
        2,
        None,
        &fixture.paths[2..3],
        false,
        false,
    ));
    assert!(!scan.census_complete);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    (fixture, index, scan, previous)
}

#[test]
fn selected_restore_preserves_prior_body_and_queued_debt() {
    let (fixture, index, _scan, previous) = selected_fixture();
    let key = local_index_key(&fixture.paths[1]);
    let old = serde_json::to_vec(&previous.files[&key]).unwrap();
    let mut selected = index.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(serde_json::to_vec(&selected.files[&key]).unwrap(), old);
    assert_eq!(
        selected.file_snapshot_fingerprints[&key],
        previous.file_snapshot_fingerprints[&key]
    );
    assert!(selected.accepted_snapshot_fingerprints.contains(
        previous.files[&key]
            .last_snapshot_fingerprint
            .as_ref()
            .unwrap()
    ));
    let queued = &selected.traversal.as_ref().unwrap().pending_candidates;
    assert!(queued.iter().any(|entry| entry.path == fixture.paths[0]));
    selected.mark_bounded_sweep_unsettled();
    selected.save(&fixture.index_path).unwrap();
    let restored = ScanIndex::load(&fixture.index_path).unwrap();
    assert_eq!(serde_json::to_vec(&restored.files[&key]).unwrap(), old);
    assert!(restored.bounded_sweep_had_unsettled_upload());
}

#[test]
fn selected_restore_keeps_invalidated_census_record_absent() {
    let (fixture, mut index, _scan, mut previous) = selected_fixture();
    let key = local_index_key(&fixture.paths[1]);
    let record = claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
        &"a".repeat(64),
        1,
        claude_request_census::ClaudeRequestCensusShape::Exact,
        vec![1],
    );
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, record);
    previous
        .claude_request_census_mut_for_test()
        .insert_for_test(
            &key,
            claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
                &"b".repeat(64),
                1,
                claude_request_census::ClaudeRequestCensusShape::Exact,
                vec![1],
            ),
        );
    index
        .files
        .get_mut(&key)
        .unwrap()
        .set_unverified_deadline(1);
    assert!(index.retire_vanished_claude_audit_debt_entry(&key));
    let selected = index.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(
        serde_json::to_vec(&selected.files[&key]).unwrap(),
        serde_json::to_vec(&previous.files[&key]).unwrap()
    );
    assert!(selected
        .claude_request_census_for_test()
        .get(&key)
        .is_none());
}

#[test]
fn partial_locked_save_and_restart_keep_exact_debt() {
    let (fixture, index, scan, previous) = selected_fixture();
    let progress = fixture._scratch.join("partial-progress.json");
    let selected = crate::snapshot_sync::checkpoint_unselected_for_test(
        &index,
        &previous,
        &scan,
        &fixture.index_path,
        &progress,
    )
    .unwrap();
    let key = local_index_key(&fixture.paths[1]);
    assert_eq!(
        serde_json::to_vec(&selected.files[&key]).unwrap(),
        serde_json::to_vec(&previous.files[&key]).unwrap()
    );
    let new_key = local_index_key(&fixture.paths[2]);
    assert!(!selected.files.contains_key(&new_key));
    assert!(!selected.confirmed_empty_files.contains(&new_key));
    assert!(selected.bounded_sweep_had_unsettled_upload());
    let restarted = ScanIndex::load(&fixture.index_path).unwrap();
    assert_eq!(
        serde_json::to_vec(&restarted.files[&key]).unwrap(),
        serde_json::to_vec(&previous.files[&key]).unwrap()
    );
    assert_eq!(
        restarted
            .traversal
            .as_ref()
            .unwrap()
            .pending_candidates
            .len(),
        index.traversal.as_ref().unwrap().pending_candidates.len()
    );
}

#[test]
fn selected_save_cas_loser_never_commits() {
    let (fixture, index, scan, previous) = selected_fixture();
    let mut winner = previous.clone();
    winner.save(&fixture.index_path).unwrap();
    let durable = fs::read(&fixture.index_path).unwrap();
    let progress = fixture._scratch.join("cas-progress.json");
    assert!(crate::snapshot_sync::checkpoint_unselected_for_test(
        &index,
        &previous,
        &scan,
        &fixture.index_path,
        &progress
    )
    .is_err());
    assert_eq!(fs::read(&fixture.index_path).unwrap(), durable);
}

fn finish_component_cursor(fixture: &mut BodyFixture) {
    for _ in 0..8 {
        if fixture.index.traversal.is_none() {
            return;
        }
        let native = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&fixture.dir),
            fixture.index.clone(),
            WINDOW,
            30,
            8,
            None,
            &[],
            false,
            false,
        );
        let (index, scan) = finish(native);
        assert_eq!(
            scan.scanned_file_count, 0,
            "only the existing unchanged cursor tail is consumed"
        );
        assert!(scan.snapshots.is_empty() && scan.pending_finalization.is_empty());
        assert_eq!(
            index.claude_usage_family_witnesses,
            fixture.index.claude_usage_family_witnesses
        );
        assert_eq!(
            index.accepted_snapshot_fingerprints,
            fixture.index.accepted_snapshot_fingerprints
        );
        fixture.index = index;
    }
    panic!("component cursor did not terminate");
}

fn corrected_body_fixture(mode: &str) -> (BodyFixture, ScanIndex) {
    let fixture = if mode == "noop" {
        let (mut fixture, accepted) = corrected_body_fixture("exact_ack");
        fixture.index = accepted;
        finish_component_cursor(&mut fixture);
        fixture
    } else {
        BodyFixture::new()
    };
    let mut previous =
        crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(fixture.index.clone());
    let key = local_index_key(&fixture.dir.join(format!("{}.jsonl", fixture.parent)));
    previous
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let (mut index, mut scan) = finish(OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&fixture.dir),
        previous.clone(),
        WINDOW,
        30,
        1,
        None,
        &[],
        false,
        false,
    ));
    assert_eq!(scan.scanned_file_count, 1);
    apply_claude_reported_usage_to_scan_with_identity(
        &mut scan,
        &fixture.api,
        &fixture.trace,
        &mut index,
        None,
    );
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(
        scan.snapshots[0].usage_accounting_contract.as_deref(),
        Some("session_exclusive_reported_usage:v1")
    );
    for item in &mut scan.snapshots {
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
    }
    let offered = scan.snapshots.clone();
    let mut baseline_scan = scan.clone();
    let mut baseline_index = index.clone();
    let mut baseline_projections = 0;
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::ClaudeCode,
        &mut baseline_scan,
        &mut baseline_index,
        |item| {
            baseline_projections += 1;
            snapshot_upload_body_witness(item)
        },
    );
    let mut projections = 0;
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::ClaudeCode,
        &mut scan,
        &mut index,
        |item| {
            projections += 1;
            snapshot_upload_body_witness(item)
        },
    );
    assert_eq!(projections, baseline_projections);
    assert_eq!(
        serde_json::to_vec(&scan.snapshots).unwrap(),
        serde_json::to_vec(&baseline_scan.snapshots).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&index).unwrap(),
        serde_json::to_vec(&baseline_index).unwrap()
    );
    if matches!(mode, "exact_ack" | "wrong_witness") {
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "claude_code".into(),
            machine_id: "otm_receipt".into(),
            collector_version: None,
            snapshots: offered,
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let refs = request.snapshots.iter().map(|item| {
            let version = crate::snapshot_client::snapshot_ack_body_witness_version(item).expect("public ACK mapping");
            json!({"source_session_id":item.source_session_id, "snapshot_fingerprint":item.snapshot_fingerprint,
                "occurrence_count":1,"body_witness_version":version,
                "body_witness_digest":version.map(|_| if mode == "wrong_witness" { "f".repeat(64) } else { snapshot_upload_body_witness(item) })})
        }).collect::<Vec<_>>();
        let response: crate::snapshot_client::SnapshotBatchResponse = serde_json::from_value(json!({
            "accepted": request.snapshots.len(), "sessions_reconciled":request.snapshots.len(),
            "session_ids":[],"disabled":false,"disabled_reason":null,"entity_ack_contract":"snapshot_entity_ack:v1",
            "accepted_entities":refs,"unchanged_entities":[],"rejected_entities":[],"conflict_entities":[]
        })).unwrap();
        let validation = response.validate_entity_ack(&request);
        if mode == "wrong_witness" {
            assert!(
                validation.is_err(),
                "same fingerprint with another body witness is not an ACK"
            );
        } else {
            validation.unwrap();
            index.record_accepted_snapshot_fingerprints(
                &request
                    .snapshots
                    .iter()
                    .map(|item| item.snapshot_fingerprint.clone())
                    .collect(),
            );
        }
    }
    if mode == "noop" {
        assert_eq!(
            previous.files[&key].last_upload_body_witness,
            index.files[&key].last_upload_body_witness,
            "no-op must be the exact previously acknowledged body"
        );
    }
    let path = fixture.dir.join("correction-selected.json");
    index.save(&path).unwrap();
    (fixture, index)
}

#[test]
fn receipt_requires_exact_ack_or_accepted_noop_after_selected_save() {
    for mode in ["pending", "wrong_witness", "refused", "exact_ack", "noop"] {
        corrected_body_fixture(mode);
    }
}

#[test]
fn proof_revision_reparse_and_restart_preserve_body_custody() {
    for change in ["proof", "revision"] {
        let (fixture, mut index) = corrected_body_fixture("exact_ack");
        let accepted = index.accepted_snapshot_fingerprints.clone();
        if change == "proof" {
            index
                .claude_usage_family_witnesses
                .get_mut(&fixture.parent)
                .unwrap()
                .evidence_fingerprint = "changed-proof".into();
        } else {
            let key = local_index_key(&fixture.dir.join(format!("{}.jsonl", fixture.parent)));
            index.files.get_mut(&key).unwrap().source_file_fingerprint = "f".repeat(64);
        }
        let path = fixture.dir.join("restart-index.json");
        index.save(&path).unwrap();
        let restarted = ScanIndex::load(&path).unwrap();
        assert_eq!(restarted.accepted_snapshot_fingerprints, accepted);
    }
}

#[test]
fn default_constructor_keeps_durable_recovery_debt_under_ordinary_census_order() {
    let fixture = SelectionFixture::new();
    let mut index = fixture.previous.clone();
    let key = local_index_key(&fixture.paths[0]);
    index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    index.save(&fixture.index_path).unwrap();
    let index = ScanIndex::load(&fixture.index_path).unwrap();
    let base = fixture.prepare(index, 1);
    assert_eq!(base.identified_candidates[0].path, fixture.paths[1]);
    let (mut index, scan) = finish(base);
    assert_eq!(scan.scanned_file_count, 1);
    assert!(index.files[&key].source_file_fingerprint.is_empty());
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .any(|p| p.path == fixture.paths[0]));
    index.save(&fixture.index_path).unwrap();
    let restarted = ScanIndex::load(&fixture.index_path).unwrap();
    assert!(restarted.files[&key].source_file_fingerprint.is_empty());
    assert!(restarted
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .any(|p| p.path == fixture.paths[0]));
}

#[test]
fn unknown_input_creates_no_false_credit_or_new_debt() {
    let fixture = BodyFixture::new();
    let path = fixture.dir.join(format!("{}.jsonl", fixture.parent));
    let mut generic = parse_claude_code_jsonl_file(&path, WINDOW, hex64('e'))
        .unwrap()
        .remove(0);
    generic.source_session_id = "generic-unproven-input".into();
    generic.claude_usage_request_ids.clear();
    assert!(generic.request_count > 0);
    let before_body = serde_json::to_vec(&generic).unwrap();
    let before_index = serde_json::to_value(&fixture.index).unwrap();
    let family = reconstruct_claude_usage_family(
        &fixture.parent,
        &fixture.index.claude_usage_family_witnesses[&fixture.parent],
        &fixture.api,
        &fixture.trace,
        None,
    )
    .unwrap();
    assert!(
        claude_reported_usage_inputs(&generic, &family).is_none(),
        "positive request counts without witnessed IDs cannot acquire reported rows"
    );
    assert_eq!(serde_json::to_vec(&generic).unwrap(), before_body);
    assert_eq!(serde_json::to_value(&fixture.index).unwrap(), before_index);
}

#[test]
fn account_audit_release_waits_for_cache_heads_and_selected_settlement() {
    for partial in [false, true] {
        let (fixture, mut index, mut scan, mut previous) = selected_fixture();
        let key = local_index_key(&fixture.paths[2]);
        let entry = index.files[&key].clone();
        previous.files.insert(key.clone(), entry.clone());
        previous
            .file_snapshot_fingerprints
            .insert(key.clone(), index.file_snapshot_fingerprints[&key].clone());
        previous
            .claude_account_deferred_holds
            .insert(key.clone(), entry.source_file_fingerprint.clone());
        index
            .claude_account_deferred_holds
            .insert(key.clone(), entry.source_file_fingerprint.clone());
        for n in 0..crate::transcript_cache::CACHE_ENTRIES {
            let audit_key = format!("/synthetic-unavailable-release/{n}.jsonl");
            let mut audit_entry = entry.clone();
            audit_entry.set_unverified_deadline(1);
            index.files.insert(audit_key.clone(), audit_entry.clone());
            previous.files.insert(audit_key, audit_entry);
        }
        let cache = sampled_scan::SharedCache::default();
        let selected = if partial {
            let progress = fixture._scratch.join("released-progress.json");
            crate::snapshot_sync::checkpoint_account_release_for_test(
                index,
                &previous,
                &mut scan,
                &cache,
                &fixture.roots,
                (&fixture.index_path, &progress),
            )
            .unwrap()
        } else {
            let mut selected = crate::snapshot_sync::accept_account_release_for_test(
                index,
                &previous,
                &mut scan,
                &cache,
                &fixture.roots,
            );
            selected.save(&fixture.index_path).unwrap();
            selected
        };
        assert!(!selected.claude_account_deferred_holds.contains_key(&key));
        assert!(selected.files[&key].source_file_fingerprint.is_empty());
        assert_eq!(
            selected
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .count(),
            crate::transcript_cache::CACHE_ENTRIES
        );
        let copy = local_index_key(&fixture.paths[0]);
        assert_eq!(
            serde_json::to_value(&selected.files[&copy]).unwrap(),
            serde_json::to_value(&previous.files[&copy]).unwrap()
        );
        assert_eq!(
            selected.file_snapshot_fingerprints[&copy],
            previous.file_snapshot_fingerprints[&copy]
        );
        let restarted = ScanIndex::load(&fixture.index_path).unwrap();
        assert!(restarted.files[&key].source_file_fingerprint.is_empty());
        assert!(restarted
            .traversal
            .as_ref()
            .unwrap()
            .pending_candidates
            .iter()
            .any(|candidate| local_index_key(&candidate.path) == key));
        if partial {
            assert!(restarted.bounded_sweep_had_unsettled_upload());
        }
    }
}

#[test]
fn completed_census_drops_finished_traversal_with_empty_diagnostic_causes() {
    let fixture = BodyFixture::new();
    let state = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&fixture.dir),
        fixture.index.clone(),
        WINDOW,
        30,
        8,
        None,
        &[],
        false,
        false,
    );
    let (index, scan) = finish(state);
    assert!(scan.census_complete);
    assert!(scan.causes.is_empty(), "exercise the empty diagnostic case");
    assert!(index.traversal.is_none());
}
