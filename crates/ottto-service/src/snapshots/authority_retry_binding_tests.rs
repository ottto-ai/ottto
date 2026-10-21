// Controlled fold tests. The separate native-page regression exercises the
// earned completion, actual ACK ledger, selected checkpoint, disk CAS/reload.
use super::*;

const WINDOW: &str = "2026-08-02T08:00:00Z";

type Api = crate::claude_local_otel::ClaudeLocalOtelLoadReport;
type Trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport;

struct BindingFixture {
    root: PathBuf,
    family: String,
    raw: Vec<SnapshotItem>,
    api: Api,
    trace: Trace,
    index: ScanIndex,
}

impl BindingFixture {
    fn new() -> Self {
        let (root, family, mut raw) = claude_account_family_fixture();
        let api = Api {
            evidence: BTreeMap::from([(
                family.clone(),
                (1..=5)
                    .map(|n| {
                        complete_api_row(
                            &family,
                            &format!("req_{n}"),
                            n,
                            10,
                            if n == 5 { 1 } else { 10 },
                            0,
                        )
                    })
                    .collect(),
            )]),
            health: Default::default(),
        };
        let trace = Trace {
            evidence: BTreeMap::from([(
                family.clone(),
                (1..=5)
                    .map(|n| {
                        complete_trace_row(
                            &family,
                            &format!("req_{n}"),
                            if n == 5 { "a4d1585d310070d0f" } else { "" },
                        )
                    })
                    .collect(),
            )]),
            ..Default::default()
        };
        let mut index = ScanIndex::default();
        let keys = [
            root.join(format!("{family}.jsonl")),
            root.join(&family)
                .join("subagents/agent-a4d1585d310070d0f.jsonl"),
        ];
        for (n, (item, key)) in raw.iter_mut().zip(keys).enumerate() {
            let revision = if n == 0 { "a" } else { "b" }.repeat(64);
            item.source_file_fingerprint = Some(revision.clone());
            let mut entry = manifest_index_entry(None);
            entry.source_file_fingerprint = revision;
            index.files.insert(local_index_key(&key), entry);
        }
        let mut initial = raw.clone();
        apply_claude_reported_usage_with_index(
            &mut initial,
            &api,
            &trace,
            &mut index,
            true,
            WINDOW,
        );
        assert!(initial
            .iter()
            .all(|i| i.usage_accounting_contract.as_deref()
                == Some("session_exclusive_reported_usage:v1")));
        assert!(index.claude_usage_family_witnesses.contains_key(&family));
        Self {
            root,
            family,
            raw,
            api,
            trace,
            index,
        }
    }

    // A deliberately controlled previous proof. Current transcripts/reports
    // really prove P1; this retained older evidence digest is distinct P0.
    fn old_index(&self, restriction: bool, terminal: bool) -> ScanIndex {
        let mut old = self.index.clone();
        let witness = old
            .claude_usage_family_witnesses
            .get_mut(&self.family)
            .unwrap();
        witness.evidence_fingerprint = "e".repeat(64);
        assert_ne!(
            claude_usage_family_witness_fingerprint(witness),
            claude_usage_family_witness_fingerprint(
                &self.index.claude_usage_family_witnesses[&self.family]
            )
        );
        if restriction {
            let digest = claude_usage_family_witness_fingerprint(witness);
            old.claude_usage_authority_quarantine.insert(
                self.family.clone(),
                ClaudeUsageAuthorityQuarantineRecord {
                    contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
                    proven_witness_fingerprint: digest.clone(),
                    member_source_file_fingerprints: self
                        .raw
                        .iter()
                        .map(|item| {
                            (
                                item.source_session_id.clone(),
                                item.source_file_fingerprint.clone().unwrap(),
                            )
                        })
                        .collect(),
                    failed_reconstruction_count: if terminal {
                        MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
                    } else {
                        1
                    },
                    disposition: if terminal {
                        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal
                    } else {
                        ClaudeUsageAuthorityQuarantineDisposition::RetryPending
                    },
                    retry_after_unix_seconds: claude_usage_authority_retry_deadline(
                        &self.family,
                        &digest,
                    ),
                    proof_correction: None,
                },
            );
        }
        old
    }

    // Preserve raw observations before selecting the current emission items,
    // exactly the distinction the native fold owns. Census=true here is a
    // controlled fold input, not a fabricated native completion or lease.
    fn fold(
        &self,
        index: &mut ScanIndex,
        items: &mut [SnapshotItem],
        identity: bool,
    ) -> ClaudeUsageAuthorityDisposition {
        let counts = accumulate_claude_usage_family_pending_with_limit(
            &self.raw,
            &mut index.claude_usage_family_pending,
            WINDOW,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        );
        let observed = ClaudeNativeObservations {
            counts,
            census_window_end: WINDOW.to_string(),
            index_generation: index.generation,
        };
        let evidence = identity.then(|| {
            // Use the production emission gate, with the fixture's own hint.
            claude_request_identity::emission_permit(
                SnapshotSource::ClaudeCode,
                Some(claude_request_identity::COHORT_HINT_TOKEN),
            )
            .expect("real C5 gate");
            claude_request_identity::ScanEvidence::new(
                &self.api,
                &self.trace,
                BTreeSet::new(),
                None,
            )
        });
        let mut disposition = apply_claude_reported_usage_with_index_limits_and_current_files(
            items,
            &self.api,
            &self.trace,
            index,
            true,
            WINDOW,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            evidence.as_ref(),
            &BTreeSet::new(),
            Some(observed),
            None,
        );
        if let Some(evidence) = evidence {
            let ownership =
                claude_request_identity::TranscriptOwnership::after_census(index, &disposition);
            claude_request_identity::apply_scan_with_ownership(
                items,
                &evidence,
                std::mem::take(&mut disposition.request_groupings),
                &ownership,
            );
        }
        disposition
    }
}

impl Drop for BindingFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn authority_retry_binding_same_pass_demotion_keeps_p0_and_resolution_installs_p1() {
    let f = BindingFixture::new();
    let mut index = f.old_index(false, false);
    let prior =
        claude_usage_family_witness_fingerprint(&index.claude_usage_family_witnesses[&f.family]);
    let mut broken = vec![f.raw[0].clone()];
    broken[0].claude_usage_occurrences.clear(); // selected rebuild cannot be exact
    let disposition = f.fold(&mut index, &mut broken, false);
    assert!(disposition
        .quarantined_source_session_ids
        .contains(&f.raw[0].source_session_id));
    let record = &index.claude_usage_authority_quarantine[&f.family];
    assert_eq!(
        record.disposition,
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending
    );
    assert_eq!(record.failed_reconstruction_count, 1);
    assert!(record.proof_correction.is_none());
    assert_eq!(record.proven_witness_fingerprint, prior);
    assert_eq!(
        claude_usage_family_witness_fingerprint(&index.claude_usage_family_witnesses[&f.family]),
        prior
    );

    let mut resolved = f.old_index(true, false);
    let mut all_current = f.raw.clone();
    f.fold(&mut resolved, &mut all_current, false);
    assert!(!resolved
        .claude_usage_authority_quarantine
        .contains_key(&f.family));
    assert!(!resolved.claude_usage_family_pending.contains_key(&f.family));
    assert_eq!(
        serde_json::to_vec(&resolved.claude_usage_family_witnesses[&f.family]).unwrap(),
        serde_json::to_vec(&f.index.claude_usage_family_witnesses[&f.family]).unwrap()
    );
    writeln!(
        std::io::stderr().lock(),
        "h559_binding_fold: same_pass_RetryPending_P0_pair=true existing_resolution_P1_pair=true"
    )
    .unwrap();
}

#[test]
fn authority_retry_binding_failed_t1_rebuild_stays_paired_without_late_regrant() {
    let f = BindingFixture::new();
    let mut index = f.old_index(true, true);
    let before = index.claude_usage_authority_quarantine[&f.family].clone();
    for _ in 0..2 {
        // Keep every member current in this controlled fold, so an unrelated
        // earlier-page rearm cannot change the member revision map between
        // the two failed rebuilds being compared.
        let mut broken = f.raw.clone();
        broken[0].claude_usage_occurrences.clear();
        f.fold(&mut index, &mut broken, false);
        let record = &index.claude_usage_authority_quarantine[&f.family];
        assert!(record.proof_correction.is_none());
        assert_eq!(
            record.failed_reconstruction_count,
            before.failed_reconstruction_count
        );
        assert_eq!(
            record.retry_after_unix_seconds,
            before.retry_after_unix_seconds
        );
        assert_eq!(
            record.proven_witness_fingerprint,
            claude_usage_family_witness_fingerprint(
                &index.claude_usage_family_witnesses[&f.family]
            )
        );
    }
    writeln!(std::io::stderr().lock(), "h559_binding_T1: same_pass_failed_rebuild_bound_P1=true terminal_deadline_attempts_kept=true no_late_regrant=true").unwrap();
}

#[test]
fn authority_retry_binding_unsettled_p1_preserves_per_member_own_c5_serialized_rows() {
    let f = BindingFixture::new();
    for member in &f.raw {
        let mut control = f.index.clone();
        let mut restricted = f.old_index(true, false);
        let p0 =
            serde_json::to_vec(&restricted.claude_usage_authority_quarantine[&f.family]).unwrap();
        let mut control_body = vec![member.clone()];
        let mut candidate_body = control_body.clone();
        f.fold(&mut control, &mut control_body, true);
        f.fold(&mut restricted, &mut candidate_body, true);
        assert_eq!(
            serde_json::to_vec(&restricted.claude_usage_authority_quarantine[&f.family]).unwrap(),
            p0
        );
        let item = &candidate_body[0];
        assert_eq!(
            item.provenance.collector,
            claude_request_identity::COLLECTOR
        );
        assert!(
            !item.request_evidence.is_empty(),
            "own native requests emitted C5 evidence"
        );
        assert_eq!(
            serde_json::to_vec(&candidate_body).unwrap(),
            serde_json::to_vec(&control_body).unwrap(),
            "same own-request C5 rows, evidence, account fields, names and tags"
        );
        // All fixture requests have the same exact telemetry login. Both
        // top-level and bucket rows therefore use Single, not mixed Parts.
        assert!(!item.model_usage.is_empty());
        let bucket_rows = item
            .usage_buckets
            .iter()
            .flat_map(|bucket| bucket.model_usage.iter())
            .collect::<Vec<_>>();
        assert!(!bucket_rows.is_empty());
        let expected_login = "a".repeat(64);
        for row in item.model_usage.iter().chain(bucket_rows) {
            assert!(row.identity_parts.is_none());
            assert_eq!(row.account_identifier_hash.as_ref(), Some(&expected_login));
            let evidence = item
                .request_evidence
                .get(usize::from(row.evidence_ref.expect("own Single evidence")))
                .expect("evidence reference is in range");
            assert_eq!(
                evidence.identity_basis,
                claude_request_identity::TELEMETRY_LOGIN
            );
            assert!(evidence.provider_workspace_hash.is_none());
        }
        // The real public ACK validator consumes the exact serialized body
        // identities, as an in-process backend would; no ACK state is seeded.
        let response: crate::snapshot_client::SnapshotBatchResponse =
            serde_json::from_value(json!({
                "accepted": 1, "sessions_reconciled": 1, "session_ids": [item.source_session_id],
                "disabled": false, "entity_ack_contract": SNAPSHOT_ENTITY_ACK_CONTRACT,
                "accepted_entities": [{"source_session_id": item.source_session_id,
                    "snapshot_fingerprint": item.snapshot_fingerprint, "occurrence_count": 1}],
                "unchanged_entities": [], "rejected_entities": [], "conflict_entities": []
            }))
            .unwrap();
        response
            .validate_entity_ack_identities(std::iter::once((
                item.source_session_id.as_str(),
                item.snapshot_fingerprint.as_str(),
            )))
            .unwrap();
    }
    writeln!(std::io::stderr().lock(), "h559_binding_C5: real_emission_gate=true per_member_serialized_body_equal=true own_evidence_nonempty=true exact_public_ACK_validator=true unresolved_record_byte_equal=true").unwrap();
}
