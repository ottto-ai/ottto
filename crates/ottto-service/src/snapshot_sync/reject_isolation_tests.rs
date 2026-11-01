// Validation-isolation regression fixtures stay outside the harness copied
// onto the comparison base by the cross-build money check.
use super::money_equivalence_tests::corpus;
use super::*;
use crate::snapshot_sync::tests::permanent_finish_pipeline_tests::prior_index_lifetime_tests::Guard as RetryClockGuard;

fn tagged_api(
    request: &str,
    tokens: u64,
    account: Option<&str>,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    use crate::claude_local_otel::{
        ClaudeIdentityAttributeEvidence as Attribute, ClaudeIdentityAttributeOrigin as Origin,
        ClaudeIdentityDisposition as Disposition, ClaudeRequestIdentityEvidence,
    };
    let mut row = api(request, tokens, tokens * 10);
    row.account_identity_checked = true;
    row.account_identifier_hash = account.map(str::to_owned);
    row.request_identity = Some(ClaudeRequestIdentityEvidence {
        identity_hash_scheme: "provider-sha256:v1".into(),
        account: Attribute {
            // None models a present but invalid login attribute.
            origin: Origin::LogRecord,
            disposition: if account.is_some() {
                Disposition::Complete
            } else {
                Disposition::Invalid
            },
            resource_hash: None,
            log_record_hash: account.map(str::to_owned),
        },
        organization: Attribute {
            origin: Origin::Missing,
            disposition: Disposition::Missing,
            resource_hash: None,
            log_record_hash: None,
        },
        disposition: if account.is_some() {
            Disposition::Missing
        } else {
            Disposition::Invalid
        },
    });
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}

fn with_retry_clock<T>(now: u64, run: impl FnOnce() -> T) -> T {
    let _guard = RetryClockGuard::new(false, None, Some(now));
    run()
}

/// [regress] An indexed validation hold preserves money and lets exact-ACK siblings settle.
#[test]
#[serial(client_report)]
fn indexed_422_quarantines_entity_settles_siblings_and_retries_with_fresh_work() {
    use crate::snapshots::sampled_scan::transition_fixture::{
        self as oracle,
        money_oracle::{assert_equivalent, assert_held},
        Accepted, Mode, RouteResult,
    };

    crate::client_report::reset_for_test();
    with_e2(|| {
        // Reuse the emitted-money corpus: A, a switch to B, a side call, and
        // an evidence gap. The uploader exercises the same typed bodies for
        // each source, independently of source-specific acquisition rules.
        let mut c = corpus("indexed-validation-hold");
        let marker = |org: &str| {
            json!({"type":"attachment","sessionId":ROOT,
            "attachment":{"type":"credential_org","organizationUuid":org}})
            .to_string()
                + "\n"
        };
        let switch = json!({"type":"attachment","sessionId":ROOT,
            "attachment":{"type":"session_context","context":{}}})
        .to_string()
            + "\n";
        c.root(
            ROOT,
            &(marker("11111111-1111-4111-8111-111111111111")
                + &line(ROOT, "r1", AT, 10)
                + &switch
                + &marker("22222222-2222-4222-8222-222222222222")
                + &line(ROOT, "r2", "2026-08-02T08:00:20Z", 20)),
        );
        // The sibling has priced usage but no account or organization evidence.
        c.root(COPY, &line(COPY, "sibling", AT, 30));
        let attributed = |request: &str, tokens, account: &str, org: &str| {
            use crate::claude_local_otel::{
                ClaudeIdentityAttributeOrigin, ClaudeIdentityDisposition,
            };
            let mut row = tagged_api(request, tokens, Some(&account.repeat(64)));
            let identity = row.request_identity.as_mut().unwrap();
            identity.organization.origin = ClaudeIdentityAttributeOrigin::LogRecord;
            identity.organization.disposition = ClaudeIdentityDisposition::Complete;
            identity.organization.log_record_hash =
                Some(ottto_core::billing_identity_hash("anthropic", "organization", org).unwrap());
            identity.disposition = ClaudeIdentityDisposition::Complete;
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            row
        };
        c.evidence(
            &[
                attributed("r1", 10, "a", "11111111-1111-4111-8111-111111111111"),
                attributed("r2", 20, "b", "22222222-2222-4222-8222-222222222222"),
                attributed("side", 5, "b", "22222222-2222-4222-8222-222222222222"),
            ],
            &[trace("r1", ""), trace("r2", ""), trace("side", "")],
        );
        c.evidence_for(COPY, &[api_for(COPY, "sibling", 30, 300)], &[]);
        let mut page = c.raw(
            &E2ScanFixture::capturing_identity(),
            ScanIndex::default(),
            100,
            true,
            &[],
        );
        page.enrich(&c);
        page.finish();
        assert!(page.scan.snapshots.len() >= 2);
        let root = page
            .scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == ROOT)
            .unwrap();
        assert_eq!(
            root.request_count, 3,
            "two transcript requests and the side call"
        );
        assert!(
            root.cost
                .as_ref()
                .unwrap()
                .total_cost_usd
                .as_deref()
                .unwrap()
                != "0"
        );
        let accounts = root
            .usage_buckets
            .iter()
            .flat_map(|bucket| &bucket.model_usage)
            .flat_map(|row| {
                row.account_identifier_hash.iter().chain(
                    row.identity_parts
                        .iter()
                        .flatten()
                        .filter_map(|part| part.account_identifier_hash.as_ref()),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            accounts,
            BTreeSet::from([&"a".repeat(64), &"b".repeat(64)]),
            "two-account placement control"
        );
        assert!(
            root.request_evidence.len() >= 2,
            "organization switch control"
        );
        assert!(
            page.scan
                .snapshots
                .iter()
                .flat_map(|item| &item.usage_buckets)
                .flat_map(|bucket| &bucket.model_usage)
                .any(|row| row.account_identifier_hash.is_none()
                    && row.evidence_ref.is_none()
                    && row.identity_parts.is_none()),
            "the untagged sibling keeps the account-evidence gap explicit"
        );
        assert!(
            root.usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage)
                .any(|row| row.evidence_ref.is_some() || row.identity_parts.is_some()),
            "tagged placement control"
        );

        for source in [
            SnapshotSource::ClaudeCode,
            SnapshotSource::Codex,
            SnapshotSource::Pi,
        ] {
            let scratch = crate::test_scratch::ScratchDir::new("indexed-validation-progress");
            let progress_path = scratch.join("progress.json");
            let mut items = page.scan.snapshots.clone();
            for item in &mut items {
                item.snapshot_fingerprint = crate::snapshots::snapshot_fingerprint(source, item);
            }
            // Packing is fingerprint sorted; reverse scan order so mapping a
            // request index directly into the scan cannot pass this fixture.
            items.sort_by(|a, b| b.snapshot_fingerprint.cmp(&a.snapshot_fingerprint));
            let poison = items[0].clone();
            assert!(
                poison
                    .cost
                    .as_ref()
                    .and_then(|cost| cost.total_cost_usd.as_deref())
                    .is_some_and(|cost| cost != "0"),
                "rejected entity carries nonzero money"
            );
            let fp = poison.snapshot_fingerprint.clone();
            let entity = poison.source_session_id.clone();
            let mut progress =
                SnapshotUploadProgress::new("a".repeat(64), snapshot_quarantine_witness(source));
            progress
                .accepted_identity_buckets
                .bind_test_key(Some([0x42; 32]));
            let mut backend = BTreeMap::<String, SnapshotItem>::new();
            let mut fresh = poison.clone();
            fresh.source_session_id = "synthetic-fresh".into();
            fresh.snapshot_fingerprint = crate::snapshots::snapshot_fingerprint(source, &fresh);
            let wire = |items: &[SnapshotItem]| {
                let mut request = request(items);
                request.source = source.api_slug().into();
                request
            };
            let route = |mode,
                         emitted: Vec<SnapshotItem>,
                         backend: &BTreeMap<String, SnapshotItem>,
                         progress: &SnapshotUploadProgress| {
                let mut emitted = emitted;
                emitted.sort_by(|a, b| a.source_session_id.cmp(&b.source_session_id));
                let batches = if emitted.is_empty() {
                    vec![]
                } else {
                    vec![canonical(&wire(&emitted))]
                };
                let mut result = RouteResult::emitted(mode, source, batches, &emitted);
                result.codex_evidence = oracle::codex_evidence(&page.index, &page.scan);
                result.accepted = backend
                    .iter()
                    .map(|(id, item)| {
                        (
                            id.clone(),
                            Accepted {
                                body: serde_json::to_value(item).unwrap(),
                                witness: snapshot_upload_body_witness(item),
                            },
                        )
                    })
                    .collect();
                result.accepted_identity_buckets = Some(json!(backend
                    .keys()
                    .filter_map(
                        |id| progress.accepted_identity_buckets.get(id).map(|buckets| {
                            let mut buckets = serde_json::to_value(buckets).unwrap();
                            // last_ack is a global LRU sequence: the prior ACK
                            // and retry history differ from a cold Full. As in
                            // advertised_cap_retags_previously_stripped_accepted_body,
                            // re-ACKs may change it without changing money or shares.
                            let last_ack = buckets.as_object_mut().unwrap().remove("last_ack");
                            assert!(last_ack
                                .and_then(|value| value.as_u64())
                                .is_some_and(|ack| ack > 0));
                            (id.clone(), buckets)
                        })
                    )
                    .collect::<BTreeMap<_, _>>()));
                result
            };
            let send = |offered: &[SnapshotItem],
                        progress: &mut SnapshotUploadProgress,
                        backend: &mut BTreeMap<String, SnapshotItem>,
                        reject: bool| {
                let retrying = progress.active_quarantine_retries.contains(&fp);
                let mut accepted = 0;
                let mut emitted = Vec::new();
                let result = upload_resumable_batches_with_literal_families(
                    offered,
                    source.api_slug(),
                    progress,
                    &mut accepted,
                    |s| s.snapshot_fingerprint.as_str(),
                    snapshot_upload_body_witness,
                    |s| Some(s.source_session_id.as_str()),
                    |_| false,
                    |_| None,
                    &mut InplaceRetryBudget::default(),
                    |batch| {
                        if let Some(index) = batch
                            .iter()
                            .position(|item| item.snapshot_fingerprint == fp)
                        {
                            if reject {
                                if retrying {
                                    assert!(
                                        batch.iter().any(|item| item.source_session_id == "synthetic-fresh"),
                                        "the repeat indexed rejection shares an ordinary batch with fresh work"
                                    );
                                }
                                if !retrying && batch.len() > 1 {
                                    assert!(index > 0, "post-packing nonzero request index");
                                }
                                let text = json!({"errors":[
                                    {"ctx":{"validator": "x".repeat(700)},"loc":["body","snapshots",index,"session_artifacts",0,"value"]},
                                    {"loc":["body","snapshots",index,"session_artifacts",1,"value"]}
                                ]}).to_string();
                                assert!(text.len() > 500);
                                return Err(anyhow::Error::new(BatchRejected::from_response(
                                    422,
                                    text.as_bytes(),
                                    batch.len(),
                                )));
                            }
                        }
                        let response = ack(&batch)?;
                        response.validate_entity_ack(&wire(&batch))?;
                        for item in &batch {
                            backend.insert(item.source_session_id.clone(), item.clone());
                        }
                        emitted.extend(batch);
                        Ok(response)
                    },
                    |state| state.save(&progress_path),
                );
                (result.unwrap(), accepted, emitted)
            };
            // Earn the old accepted money through an actual stored-body ACK.
            let mut old = poison.clone();
            old.status = if old.status == "completed" {
                "active"
            } else {
                "completed"
            }
            .into();
            old.snapshot_fingerprint = crate::snapshots::snapshot_fingerprint(source, &old);
            assert_ne!(old.snapshot_fingerprint, fp);
            let (_, accepted, _) = send(&[old], &mut progress, &mut backend, false);
            assert_eq!(accepted, 1, "one ACK for the distinct prior revision");
            let prior = route(Mode::Ram, vec![], &backend, &progress);
            let (result, accepted, emitted) = send(&items, &mut progress, &mut backend, true);
            assert_eq!(result, ResumableUploadResult::Deferred { count: 1 });
            assert_eq!(accepted as usize, items.len() - 1);
            assert_eq!(progress.quarantined_fingerprints.len(), 1);
            assert!(!progress.accepted_fingerprints.contains(&fp));
            assert!(!progress.accepted_body_witnesses.contains_key(&fp));
            assert!(progress
                .context_receipt_candidates
                .iter()
                .flat_map(|candidate| candidate.entities())
                .all(|(entity_fp, _)| entity_fp != &fp));
            assert!(items
                .iter()
                .filter(|item| item.snapshot_fingerprint != fp)
                .all(|item| progress
                    .accepted_body_witnesses
                    .get(&item.snapshot_fingerprint)
                    == Some(&snapshot_upload_body_witness(item))));
            let mut cold_progress =
                SnapshotUploadProgress::new("b".repeat(64), snapshot_quarantine_witness(source));
            cold_progress
                .accepted_identity_buckets
                .bind_test_key(Some([0x42; 32]));
            let mut cold_backend = BTreeMap::new();
            // The comparison independently accepts every cold Full body.
            let mut count = 0;
            upload_resumable_batches_with_body_witness(
                &items,
                source.api_slug(),
                &mut cold_progress,
                &mut count,
                |s| s.snapshot_fingerprint.as_str(),
                snapshot_upload_body_witness,
                |batch| {
                    for item in &batch {
                        cold_backend.insert(item.source_session_id.clone(), item.clone());
                    }
                    ack(&batch)
                },
                |_| Ok(()),
            )
            .unwrap();
            let cold = route(Mode::ColdFull, items.clone(), &cold_backend, &cold_progress);
            let held = route(Mode::Ram, emitted, &backend, &progress);
            assert_held(&entity, &prior, &held, &cold);
            let namespace = progress.destination_namespace_hash.clone();
            progress = SnapshotUploadProgress::load(
                &progress_path,
                &namespace,
                snapshot_quarantine_witness(source),
            )
            .unwrap();
            progress
                .accepted_identity_buckets
                .bind_test_key(Some([0x42; 32]));
            let deadline = progress.quarantined_fingerprints[&fp].retry_after_unix_seconds;
            with_retry_clock(deadline - 1, || {
                assert!(!progress.prepare_quarantine_retries(&BTreeMap::new()));
                let (_, accepted, emitted) = send(&items, &mut progress, &mut backend, true);
                assert_eq!(accepted, 0);
                assert!(emitted.is_empty());
            });
            items.push(fresh);
            with_retry_clock(deadline, || {
                assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));
                let (result, accepted, emitted) = send(&items, &mut progress, &mut backend, true);
                assert_eq!(result, ResumableUploadResult::Deferred { count: 1 });
                assert_eq!(accepted, 1);
                assert_eq!(emitted.len(), 1);
                assert_eq!(emitted[0].source_session_id, "synthetic-fresh");
                assert_eq!(
                    progress
                        .accepted_body_witnesses
                        .get(&emitted[0].snapshot_fingerprint),
                    Some(&snapshot_upload_body_witness(&emitted[0])),
                    "the fresh sibling has its exact ACK"
                );
                assert_eq!(progress.quarantined_fingerprints.len(), 1);
                assert!(!progress.accepted_fingerprints.contains(&fp));
                assert!(!progress.accepted_body_witnesses.contains_key(&fp));
                let record = &progress.quarantined_fingerprints[&fp];
                assert_eq!(
                    record.disposition,
                    SnapshotQuarantineDisposition::RetryPending
                );
                assert_eq!(record.failed_reconstruction_count, 1);
            });
            let next = progress.quarantined_fingerprints[&fp].retry_after_unix_seconds;
            assert!(next > deadline);
            with_retry_clock(next, || {
                assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));
                let (result, accepted, _) = send(&items, &mut progress, &mut backend, false);
                assert_eq!(result, ResumableUploadResult::Completed);
                assert_eq!(accepted, 1);
            });
            assert!(progress.quarantined_fingerprints.is_empty());
            assert_eq!(
                progress.accepted_body_witnesses.get(&fp),
                Some(&snapshot_upload_body_witness(&poison)),
                "eventual acceptance clears the hold with an exact ACK"
            );
            let mut count = 0;
            upload_resumable_batches_with_body_witness(
                &items,
                source.api_slug(),
                &mut cold_progress,
                &mut count,
                |s| s.snapshot_fingerprint.as_str(),
                snapshot_upload_body_witness,
                |batch| {
                    for item in &batch {
                        cold_backend.insert(item.source_session_id.clone(), item.clone());
                    }
                    ack(&batch)
                },
                |_| Ok(()),
            )
            .unwrap();
            let cold = route(Mode::ColdFull, items.clone(), &cold_backend, &cold_progress);
            let caught_up = route(
                Mode::Restart,
                backend.values().cloned().collect(),
                &backend,
                &progress,
            );
            assert_equivalent(&cold, &caught_up);
        }
    });
    assert_eq!(
        crate::client_report::observe()
            .quantity(crate::client_report::ClientReportReason::Poisoned),
        0
    );
    crate::client_report::reset_for_test();
}

/// A scanned semantic-no-op sibling, an ACKed sibling, and one indexed
/// refusal with durable quarantine custody, for sibling-settlement regressions.
pub(in crate::snapshot_sync) struct IndexedRefusalFixture {
    pub committed: ScanIndex,
    pub scanned: ScanIndex,
    pub progress: SnapshotUploadProgress,
    pub sibling: String,
    pub refused: String,
}

pub(in crate::snapshot_sync) fn indexed_refusal_fixture() -> IndexedRefusalFixture {
    let entry = |fingerprint: &str, source: &str| -> crate::snapshots::ScanIndexEntry {
        serde_json::from_value(json!({"size_bytes": 1, "modified_unix_seconds": 2,
            "source_file_fingerprint": source, "last_snapshot_fingerprint": fingerprint}))
        .unwrap()
    };
    let [unchanged, sibling, refused, old] = [1, 2, 3, 4].map(|n| format!("{n:064x}"));
    let mut committed: ScanIndex = serde_json::from_value(json!({
        "files": {},
        "upload_context_fingerprint": "prior-context"
    }))
    .unwrap();
    for (key, fingerprint, source) in [("reread", &unchanged, ""), ("refused", &old, "source")] {
        committed
            .files
            .insert(key.into(), entry(fingerprint, source));
        committed
            .file_snapshot_fingerprints
            .insert(key.into(), BTreeSet::from([fingerprint.clone()]));
        committed.record_accepted_snapshot_fingerprints(&BTreeSet::from([fingerprint.clone()]));
    }
    let mut scanned_state = serde_json::to_value(&committed).unwrap();
    scanned_state["upload_context_fingerprint"] = json!("scanned-context");
    let mut scanned: ScanIndex = serde_json::from_value(scanned_state).unwrap();
    scanned.activate_upload_context("scanned-context".into());
    for (key, fingerprint) in [
        ("reread", &unchanged),
        ("sibling", &sibling),
        ("refused", &refused),
    ] {
        scanned
            .files
            .insert(key.into(), entry(fingerprint, "source"));
        scanned
            .file_snapshot_fingerprints
            .insert(key.into(), BTreeSet::from([fingerprint.clone()]));
    }

    // The unchanged entity is a semantic no-op: only the sibling and the
    // refused revision are offered, and the backend locates the refusal.
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let result = upload_resumable_batches(
        &[sibling.clone(), refused.clone()],
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| match batch.iter().position(|item| item == &refused) {
            Some(index) => Err(anyhow::Error::new(BatchRejected::from_response(
                422,
                json!({"errors":[{"loc":["body","snapshots",index,"field"]}]})
                    .to_string()
                    .as_bytes(),
                batch.len(),
            ))),
            None => Ok(accepted_batch(batch.len())),
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(result, ResumableUploadResult::Deferred { count: 1 });
    assert_eq!(accepted, 1);
    assert!(progress.quarantined_fingerprints.contains_key(&refused));

    IndexedRefusalFixture {
        committed,
        scanned,
        progress,
        sibling,
        refused,
    }
}

/// [regress] A page ending in one indexed refusal must settle its other
/// files, including a re-read file whose unchanged entity was not resent
/// (its committed witness was cleared). An ACK-only checkpoint returned that
/// file to the cleared witness, so it was read again next pass.
#[test]
fn indexed_refusal_settles_unsent_siblings_without_a_reread() {
    let IndexedRefusalFixture {
        committed,
        scanned,
        progress,
        sibling,
        refused,
    } = indexed_refusal_fixture();

    let ack_only = scanned.committable_subset_with_local_holds(
        &committed,
        &progress.accepted_fingerprints,
        &BTreeMap::new(),
        &BTreeSet::new(),
    );
    assert!(
        ack_only.files["reread"].source_file_fingerprint.is_empty(),
        "control: an ACK-only subset keeps the cleared witness"
    );

    let no_holds = LocalHoldSettlement {
        held_entity_count: 0,
        retry_pending_family_count: 0,
        held_fingerprints: BTreeSet::new(),
        account_deferred_fingerprints: BTreeSet::new(),
        progress_blocking: false,
        held_family_roots: None,
    };
    let settlement =
        settle_checkpointed_upload(scanned.clone(), &committed, &progress, &no_holds, false);
    assert!(
        !settlement.fully_settled,
        "the refused item keeps a follow-up owed"
    );
    let mut settled = settlement.index;
    settle_index_after_upload(&mut settled, &committed, &progress);
    assert_eq!(
        serde_json::to_value(&settled).unwrap()["upload_context_fingerprint"],
        "scanned-context",
        "the settled census context must not force healthy siblings to reparse"
    );
    for key in ["reread", "sibling"] {
        assert_eq!(
            serde_json::to_value(&settled.files[key]).unwrap(),
            serde_json::to_value(&scanned.files[key]).unwrap(),
            "{key} settles as scanned, so the next pass does not read it again"
        );
    }
    assert!(settled
        .accepted_snapshot_fingerprints_for_test()
        .contains(&sibling));
    assert!(
        !settled
            .accepted_snapshot_fingerprints_for_test()
            .contains(&refused),
        "the refused revision gets no credit"
    );
    assert!(
        settled
            .quarantined_snapshot_fingerprints
            .contains_key(&refused),
        "its quarantine owes the retry"
    );
}
