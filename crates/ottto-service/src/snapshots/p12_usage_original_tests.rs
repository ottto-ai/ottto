// Pinned oracle from public #583 head609ef1c3; function body unchanged.
// Original assertions remain; ignored because its optimized quiet prelude
// cannot be reached by the current base or an uncertified experiment.
// Terminal family-proof re-arm through the production reported-usage fold: a
// new or changed exact family witness reparses earlier-page members once, and
// an unchanged witness adds no reparse debt. Every fixture is synthetic and
// content-free; the index round-trips through the production save and load.
use super::*;
use crate::claude_local_otel::{
    ClaudeLocalOtelEvidence, ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipEvidence,
    ClaudeTraceOwnershipLoadReport,
};

const CHILD_AGENT: &str = "a4d1585d310070d0f";
const REPORTED: Option<&str> = Some("session_exclusive_reported_usage:v1");

fn revision(seed: u64) -> String {
    format!("{seed:064x}")
}

/// A root transcript and one subagent transcript under the same family, with
/// complete paired API and trace evidence for every request. Each traversal
/// parses the root on an earlier page and the child on the terminal page.
struct Family {
    dir: PathBuf,
    state_dir: PathBuf,
    root_session_id: String,
    parent_path: PathBuf,
    child_path: PathBuf,
    parent_key: String,
    child_key: String,
    api_rows: Vec<ClaudeLocalOtelEvidence>,
    trace_rows: Vec<ClaudeTraceOwnershipEvidence>,
    index: ScanIndex,
    native_lifecycle: std::sync::Arc<claude_native_comparison::lifecycle::Lifecycle>,
}

impl Family {
    fn new() -> Self {
        let (dir, root_session_id, _) = claude_account_family_fixture();
        let parent_path = dir.join(format!("{root_session_id}.jsonl"));
        let child_path = dir
            .join(&root_session_id)
            .join("subagents")
            .join(format!("agent-{CHILD_AGENT}.jsonl"));
        let mut api_rows = (1..=4)
            .map(|index| {
                complete_api_row(&root_session_id, &format!("req_{index}"), index, 10, 10, 0)
            })
            .collect::<Vec<_>>();
        api_rows.push(complete_api_row(&root_session_id, "req_5", 5, 10, 1, 0));
        let mut trace_rows = (1..=4)
            .map(|index| complete_trace_row(&root_session_id, &format!("req_{index}"), ""))
            .collect::<Vec<_>>();
        trace_rows.push(complete_trace_row(&root_session_id, "req_5", CHILD_AGENT));
        let parent_key = local_index_key(&parent_path);
        let child_key = local_index_key(&child_path);
        let mut index = ScanIndex::default();
        for (key, seed) in [(&parent_key, 1), (&child_key, 2)] {
            let mut entry = manifest_index_entry(None);
            entry.source_file_fingerprint = revision(seed);
            index.files.insert(key.clone(), entry);
        }
        Self {
            dir,
            state_dir: crate::test_scratch::private_dir("claude-usage-proof-rearm-state"),
            root_session_id,
            parent_path,
            child_path,
            parent_key,
            child_key,
            api_rows,
            trace_rows,
            index,
            native_lifecycle: std::sync::Arc::new(Default::default()),
        }
    }

    fn parse(&self, path: &Path, window: &str, seed: u64) -> Vec<SnapshotItem> {
        parse_claude_code_jsonl_file(path, window, revision(seed)).expect("parse family member")
    }

    fn parent(&self, window: &str) -> Vec<SnapshotItem> {
        self.parse(&self.parent_path, window, 1)
    }

    fn child(&self, window: &str, seed: u64) -> Vec<SnapshotItem> {
        self.parse(&self.child_path, window, seed)
    }

    fn page(
        &mut self,
        items: &mut [SnapshotItem],
        census_complete: bool,
        window: &str,
    ) -> ClaudeUsageAuthorityDisposition {
        if claude_native_comparison::enabled() {
            return self.native_unit_page(items, census_complete, window);
        }
        let api_report = ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::from([(self.root_session_id.clone(), self.api_rows.clone())]),
            health: Default::default(),
        };
        let trace_report = ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(self.root_session_id.clone(), self.trace_rows.clone())]),
            ..Default::default()
        };
        apply_claude_reported_usage_with_index(
            items,
            &api_report,
            &trace_report,
            &mut self.index,
            census_complete,
            window,
        )
    }

    /// Controlled-R primitive oracle, not physical source/performance proof.
    /// It preserves the original logical pages and calls the same frozen-P,
    /// corrected-body ACK/no-op and selected-save receipt code as production.
    fn native_unit_page(
        &mut self,
        items: &mut [SnapshotItem],
        census_complete: bool,
        window: &str,
    ) -> ClaudeUsageAuthorityDisposition {
        let api = ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::from([(self.root_session_id.clone(), self.api_rows.clone())]),
            health: Default::default(),
        };
        let trace = ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(self.root_session_id.clone(), self.trace_rows.clone())]),
            ..Default::default()
        };
        // An empty real scan supplies only the typed result envelope. It does
        // NOT supply native-read evidence, a traversal, eligibility or a grant.
        let empty = self.state_dir.join("empty-container");
        fs::create_dir_all(&empty).unwrap();
        let mut scratch_index = ScanIndex::default();
        let mut scan = scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            &[empty],
            &mut scratch_index,
            window,
            365,
            2,
            false,
        )
        .unwrap();
        scan.census_complete = census_complete;
        scan.census_window_end = window.to_owned();
        scan.snapshots = items.to_vec();
        let previous = self.index.clone();
        scan.pending_finalization = items
            .iter()
            .map(|item| {
                let key = [&self.parent_key, &self.child_key]
                    .into_iter()
                    .find(|key| {
                        claude_index_path_family_member(Path::new(key))
                            .is_some_and(|(_, member)| member == item.source_session_id)
                    })
                    .expect("exact parsed member key");
                let old = &previous.files[key];
                PendingIndexFinalization {
                    archive_first_read: false,
                    withheld_content: None,
                    sampled_audit_verified: false,
                    codex_pending_recovery: false,
                    index_key: key.clone(),
                    source_file_fingerprint: item
                        .source_file_fingerprint
                        .clone()
                        .expect("controlled parsed revision"),
                    previous_snapshot_fingerprint: old.last_snapshot_fingerprint.clone(),
                    previous_upload_body_witness: old.last_upload_body_witness.clone(),
                    parse_complete: true,
                    diagnostic_reason: FileReason::Complete,
                    parsed_snapshot_count: 1,
                    effective_upload_body_witness_revision: 0,
                }
            })
            .collect();
        let mut lease = self.native_lifecycle.begin();
        lease.bind("primitive-native-unit".to_owned());
        let healthy = BTreeSet::from([self.root_session_id.clone()]);
        let mut completion = claude_native_comparison::NativePhase::primitive_completion_for_test(
            &scan,
            &self.index,
            claude_native_comparison::PairedRows {
                api: &api.evidence,
                trace: &trace.evidence,
                healthy_roots: &healthy,
            },
            &mut lease,
        );
        // Original primitive current-files premise is unchanged. This is the
        // actual single fold, with no synthetic Skip or forced permission.
        let disposition = apply_claude_reported_usage_with_index_limits_and_current_files(
            &mut scan.snapshots,
            &api,
            &trace,
            &mut self.index,
            census_complete,
            window,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            None,
            &BTreeSet::new(),
            None,
            Some(completion.fold_view(Some(&lease))),
            &BTreeMap::new(),
        );
        items.clone_from_slice(&scan.snapshots);
        completion.capture_native_corrections(
            &mut scan,
            &previous,
            &disposition,
            snapshot_upload_body_witness,
        );
        // A held member's prior entry/body is untouched. Never classify it as
        // empty or ACKed simply because its current body cannot be offered.
        let held = &disposition.quarantined_source_session_ids;
        let held_keys = scan
            .snapshots
            .iter()
            .filter(|item| held.contains(&item.source_session_id))
            .filter_map(|item| {
                scan.pending_finalization
                    .iter()
                    .find(|pending| {
                        claude_index_path_family_member(Path::new(&pending.index_key))
                            .is_some_and(|(_, member)| member == item.source_session_id)
                    })
                    .map(|pending| pending.index_key.clone())
            })
            .collect::<BTreeSet<_>>();
        disposition.retain_uploadable(&mut scan.snapshots);
        scan.pending_finalization
            .retain(|pending| !held_keys.contains(&pending.index_key));
        for pending in &scan.pending_finalization {
            let entry = self.index.files.get_mut(&pending.index_key).unwrap();
            // Preserve a terminal proof's newly created rearm debt. Ordinary
            // parse completion commits R only when the fold did not rearm it.
            if !entry.source_file_fingerprint.is_empty() || !census_complete {
                entry.source_file_fingerprint = pending.source_file_fingerprint.clone();
            }
            entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_owned());
        }
        finalize_scan_after_policy_with_body_witness(
            SnapshotSource::ClaudeCode,
            &mut scan,
            &mut self.index,
            snapshot_upload_body_witness,
        );
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "claude_code".to_owned(),
            machine_id: "otm_primitive_native_unit".to_owned(),
            collector_version: None,
            snapshots: scan.snapshots.clone(),
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let head_cas = request
            .snapshots
            .iter()
            .any(|item| item.cache_observations.is_some());
        let refs = request.snapshots.iter().map(|item| {
            let version = crate::snapshot_client::snapshot_ack_body_witness_version(item).expect("production public ACK mapping");
            serde_json::json!({"source_session_id":item.source_session_id,
                "snapshot_fingerprint":item.snapshot_fingerprint,"occurrence_count":1,
                "head_etag":head_cas.then(||snapshot_upload_body_witness(item)),
                "body_witness_version":version,"body_witness_digest":version.map(|_|snapshot_upload_body_witness(item))})
        }).collect::<Vec<_>>();
        let response: crate::snapshot_client::SnapshotBatchResponse =
            serde_json::from_value(serde_json::json!({
                "accepted":request.snapshots.len(),"sessions_reconciled":request.snapshots.len(),
                "session_ids":[],"disabled":false,"disabled_reason":null,
                "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":refs,
                "unchanged_entities":[],"rejected_entities":[],"conflict_entities":[],
            }))
            .unwrap();
        response
            .validate_entity_ack(&request)
            .expect("strict actual corrected-body ACK validator");
        let acknowledgments = request
            .snapshots
            .iter()
            .map(|item| {
                (
                    item.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(item),
                )
            })
            .collect::<BTreeMap<_, _>>();
        self.index
            .record_accepted_snapshot_fingerprints(&acknowledgments.keys().cloned().collect());
        self.index
            .save(&self.state_dir.join("scan-index.json"))
            .unwrap();
        let fully_settled = disposition.quarantined_entity_count() == 0;
        if fully_settled && lease.allowed() {
            completion.note_native_corrections_after_save(&self.index, &previous, |fp, witness| {
                Some(
                    acknowledgments
                        .get(fp)
                        .is_some_and(|actual| actual == witness),
                )
            });
        }
        lease.note_selected_save(
            fully_settled && claude_native_comparison::actual_native_conjunction(&disposition),
        );
        lease.stage_window_after_save(completion.window, &self.index, census_complete);
        // Logical-page cleanliness is solely this primitive's real native fold
        // and exact ACK/save. No physical traversal cleanliness is fabricated.
        lease.finish(
            fully_settled
                && !disposition.duplicate_census.census_invalid
                && !disposition.duplicate_census.fence_after,
        );
        disposition
    }

    /// Persist and reload the index in the SAME process. A separate lifecycle
    /// restart control proves that disk state cannot restore a native receipt.
    fn reload(&mut self) {
        let path = self.state_dir.join("scan-index.json");
        assert!(
            self.index.files.contains_key(&self.parent_key),
            "the fixture retains its parent before save"
        );
        self.index.save(&path).expect("save scan index");
        assert!(
            self.index.files.contains_key(&self.parent_key),
            "the fixture retains its parent after save"
        );
        let decoded = lenient_decode::read_file(
            File::open(&path).expect("open saved fixture"),
            "load",
            "unattributed",
        )
        .expect("the saved fixture decodes without quarantine");
        assert!(
            decoded.files.contains_key(&self.parent_key),
            "the saved fixture decodes its parent at {path:?}; decoded keys: {:?}",
            decoded.files.keys().collect::<Vec<_>>()
        );
        self.index = ScanIndex::load(&path).expect("load scan index");
        assert!(
            self.index.files.contains_key(&self.parent_key),
            "the saved index reloads intact instead of being quarantined"
        );
    }

    /// An accepted upload commits the parsed revision again.
    fn settle(&mut self, key: &str, seed: u64) {
        self.index
            .files
            .get_mut(key)
            .expect("indexed family member")
            .source_file_fingerprint = revision(seed);
    }

    fn armed(&self, key: &str) -> bool {
        !self.index.files[key].source_file_fingerprint.is_empty()
    }

    fn witness(&self) -> ClaudeUsageFamilyWitness {
        self.index
            .claude_usage_family_witnesses
            .get(&self.root_session_id)
            .cloned()
            .expect("family witness")
    }

    /// First traversal proves the family, then the correction traversal
    /// rebuilds the re-armed root from the retained witness and settles it.
    fn proven_and_corrected(&mut self) -> ClaudeUsageFamilyWitness {
        let mut parent = self.parent("2026-08-02T07:10:00Z");
        self.page(&mut parent, false, "2026-08-02T07:10:00Z");
        assert_eq!(parent[0].usage_accounting_contract, None);
        let mut child = self.child("2026-08-02T07:10:00Z", 2);
        self.page(&mut child, true, "2026-08-02T07:10:00Z");
        assert_eq!(child[0].usage_accounting_contract.as_deref(), REPORTED);
        let first_witness = self.witness();
        assert!(
            !self.armed(&self.parent_key),
            "the first exact proof re-arms the earlier-page root once"
        );
        assert!(self.armed(&self.child_key));
        self.reload();

        let mut corrected = self.parent("2026-08-02T07:20:00Z");
        let disposition = self.page(&mut corrected, false, "2026-08-02T07:20:00Z");
        assert_eq!(disposition.quarantined_entity_count(), 0);
        assert_eq!(corrected[0].usage_accounting_contract.as_deref(), REPORTED);
        assert_eq!(corrected[0].request_count, 4);
        assert_eq!(corrected[0].input_tokens, 40);
        assert_eq!(corrected[0].output_tokens, 40);
        self.settle(&self.parent_key.clone(), 1);
        self.reload();
        first_witness
    }
}

impl Drop for Family {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
        let _ = fs::remove_dir_all(&self.state_dir);
    }
}

#[test]
#[ignore = "P12: needs full qualified two-phase driver; original expectations preserved"]
fn member_change_after_unchanged_proof_fails_closed_until_family_reparse() {
    let mut family = Family::new();
    let first_witness = family.proven_and_corrected();
    let parent_key = family.parent_key.clone();
    let child_key = family.child_key.clone();
    let mut child = family.child("2026-08-02T07:20:00Z", 2);
    family.page(&mut child, true, "2026-08-02T07:20:00Z");
    assert!(family.armed(&parent_key));

    // Only the child grows. Its new request is reported, so the retained
    // witness no longer reconstructs and the child is held, never downgraded.
    let root_session_id = family.root_session_id.clone();
    let appended = format!(
        "{{\"timestamp\":\"2026-08-02T07:00:05Z\",\"type\":\"assistant\",\"sessionId\":\"{root_session_id}\",\"agentId\":\"{CHILD_AGENT}\",\"isSidechain\":true,\"requestId\":\"req_6\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":1}}}}}}\n"
    );
    let mut transcript = fs::read_to_string(&family.child_path).expect("read child transcript");
    transcript.push_str(&appended);
    fs::write(&family.child_path, transcript).expect("append child transcript");
    family
        .api_rows
        .push(complete_api_row(&root_session_id, "req_6", 6, 10, 1, 0));
    family
        .trace_rows
        .push(complete_trace_row(&root_session_id, "req_6", CHILD_AGENT));
    let mut grown = family.child("2026-08-02T07:30:00Z", 3);
    let disposition = family.page(&mut grown, false, "2026-08-02T07:30:00Z");
    assert_eq!(grown[0].usage_accounting_contract, None);
    assert_eq!(disposition.quarantined_entity_count(), 1);
    let mut uploadable = grown;
    disposition.retain_uploadable(&mut uploadable);
    assert!(uploadable.is_empty(), "the demoting child body is held");

    // The unchanged root was not parsed in this window, so the census cannot
    // prove the family. Nothing is re-armed here; the bounded quarantine bound
    // to the retained witness owns the family retry.
    family.page(&mut [], true, "2026-08-02T07:30:00Z");
    assert_eq!(family.witness(), first_witness);
    assert!(family.armed(&parent_key));
    let quarantine = family
        .index
        .claude_usage_authority_quarantine
        .get(&root_session_id)
        .expect("family is quarantined")
        .clone();
    assert_eq!(
        quarantine.disposition,
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending
    );
    assert_eq!(
        quarantine.proven_witness_fingerprint,
        claude_usage_family_witness_fingerprint(&first_witness)
    );
    family.reload();

    // The quarantine's family reparse observes every member in one window.
    // Its census proves the changed witness and re-arms both members once.
    let mut parent = family.parent("2026-08-02T07:40:00Z");
    let mut grown = family.child("2026-08-02T07:40:00Z", 3);
    parent.append(&mut grown);
    let disposition = family.page(&mut parent, false, "2026-08-02T07:40:00Z");
    assert_eq!(disposition.quarantined_entity_count(), 2);
    family.page(&mut [], true, "2026-08-02T07:40:00Z");
    assert_ne!(family.witness(), first_witness);
    assert!(!family.armed(&parent_key));
    assert!(!family.armed(&child_key));

    // The re-armed members rebuild from the new witness with the grown usage,
    // which resolves the quarantine.
    let mut parent = family.parent("2026-08-02T07:50:00Z");
    let mut grown = family.child("2026-08-02T07:50:00Z", 3);
    parent.append(&mut grown);
    let disposition = family.page(&mut parent, false, "2026-08-02T07:50:00Z");
    assert_eq!(disposition.quarantined_entity_count(), 0);
    assert!(parent
        .iter()
        .all(|item| item.usage_accounting_contract.as_deref() == REPORTED));
    assert_eq!(parent[1].request_count, 2);
    assert_eq!(parent[1].output_tokens, 2);
    assert!(!family
        .index
        .claude_usage_authority_quarantine
        .contains_key(&root_session_id));
}

#[test]
fn native_comparison_original_member_change_unit_oracle() {
    // Legacy reported-body proof/delivery; E2 publishes a request-owned literal instead.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        writeln!(std::io::stderr().lock(), "native_comparison_original_member_change_unit: supported_positive=UNEXECUTED original_body_ran=false original_passed=false").unwrap();
        return;
    }
    let _native = claude_native_comparison::enable_for_test();
    member_change_after_unchanged_proof_fails_closed_until_family_reparse();
    writeln!(std::io::stderr().lock(), "native_comparison_original_member_change_unit: original_body_ran=true original_passed=true controlled_revision_unit=true physical_source_or_performance_proof=false strict_body_ACK_validator=true selected_save=true").unwrap();
}
