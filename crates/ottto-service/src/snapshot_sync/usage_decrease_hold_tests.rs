//! `usage_decrease_hold_ack:v1` fixtures: a backend money-decrease hold keeps
//! the exact body retryable. Offline; no installed state or providers.
use super::*;
use crate::snapshot_client::{SnapshotBatchResponse, SnapshotEntityRef, SnapshotEntityRejection};

const HELD: &str = "usage_decrease_held_for_review";
const REFUSED: &str = "usage_decrease_refused_after_review";

fn item(i: usize, literal: bool) -> SnapshotItem {
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    item.source_session_id = format!("synthetic-hold-{i}");
    item.cache_observations = None;
    item.cache_observations_state = None;
    item.usage_accounting_contract =
        literal.then(|| crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT.into());
    item.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
    item
}

fn request(source: SnapshotSource, items: Vec<SnapshotItem>) -> SnapshotBatchRequest {
    SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: source.api_slug().into(),
        machine_id: "synthetic".into(),
        collector_version: None,
        snapshots: items,
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    }
}

/// Accept every item except `rejected`'s, which get `(reason, permanent)`.
fn ack(items: &[SnapshotItem], rejected: &[(usize, &str, bool)]) -> SnapshotBatchResponse {
    let refused = |i: usize| rejected.iter().find(|(at, _, _)| *at == i);
    let accepted = (0..items.len())
        .filter(|i| refused(*i).is_none())
        .map(|i| {
            let version =
                crate::snapshot_client::snapshot_ack_body_witness_version(&items[i]).unwrap();
            SnapshotEntityRef {
                source_session_id: items[i].source_session_id.clone(),
                snapshot_fingerprint: items[i].snapshot_fingerprint.clone(),
                occurrence_count: 1,
                body_witness_version: version,
                body_witness_digest: version.map(|_| snapshot_upload_body_witness(&items[i])),
                head_etag: None,
                head_challenge: None,
                unchanged_basis: None,
                retained_proof_missing: Vec::new(),
            }
        })
        .collect::<Vec<_>>();
    SnapshotBatchResponse {
        accepted: accepted.len() as u64,
        sessions_reconciled: 0,
        session_ids: Vec::new(),
        disabled: false,
        disabled_reason: None,
        entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
        accepted_entities: accepted,
        unchanged_entities: Vec::new(),
        conflict_entities: Vec::new(),
        rejected_entities: rejected
            .iter()
            .map(|(i, reason, permanent)| SnapshotEntityRejection {
                source_session_id: items[*i].source_session_id.clone(),
                snapshot_fingerprint: items[*i].snapshot_fingerprint.clone(),
                reason: (*reason).into(),
                detail: "not logged".into(),
                permanent: *permanent,
                occurrence_count: 1,
            })
            .collect(),
    }
}

/// The batch position of `fingerprint`: the uploader packs by fingerprint,
/// not by input order.
fn at(batch: &[SnapshotItem], fingerprint: &str) -> usize {
    batch
        .iter()
        .position(|item| item.snapshot_fingerprint == fingerprint)
        .unwrap()
}

fn progress() -> SnapshotUploadProgress {
    SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
}

fn upload(
    items: &[SnapshotItem],
    scope: &str,
    ledger: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    mut respond: impl FnMut(&[SnapshotItem]) -> SnapshotBatchResponse,
) -> Result<ResumableUploadResult> {
    upload_resumable_batches_with_body_witness(
        items,
        scope,
        ledger,
        accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let response = respond(&batch);
            response.validate_entity_ack(&request(SnapshotSource::ClaudeCode, batch))?;
            Ok(response)
        },
        |_| Ok(()),
    )
}

#[test]
fn hold_ack_contract_is_declared_only_on_claude_literal_batches() {
    for (source, items, declared) in [
        (SnapshotSource::ClaudeCode, vec![item(0, true)], true),
        (
            SnapshotSource::ClaudeCode,
            vec![item(0, false), item(1, true)],
            true,
        ),
        (SnapshotSource::ClaudeCode, vec![item(0, false)], false),
        (SnapshotSource::Codex, vec![item(0, true)], false),
        (SnapshotSource::Pi, vec![item(0, true)], false),
    ] {
        let request = request(source, items);
        assert_eq!(
            crate::snapshots::declares_usage_decrease_hold_ack(&request),
            declared
        );
        for (kind, encoded) in [
            ("ordinary", serde_json::to_vec(&request).unwrap()),
            (
                "cas",
                serde_json::to_vec(&request.wire_with_head_cas()).unwrap(),
            ),
            (
                "retry",
                crate::snapshot_retry::encode_json(&request, crate::snapshot_retry::REQUEST_BYTES)
                    .unwrap(),
            ),
            (
                "cas_retry",
                crate::snapshot_retry::encode_json(
                    &request.wire_with_head_cas(),
                    crate::snapshot_retry::REQUEST_BYTES,
                )
                .unwrap(),
            ),
        ] {
            let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            let token = value.get("usage_decrease_hold_ack_contract");
            if declared {
                assert_eq!(
                    token.and_then(serde_json::Value::as_str),
                    Some(crate::snapshots::USAGE_DECREASE_HOLD_ACK_CONTRACT),
                    "{source:?}/{kind}"
                );
            } else {
                assert!(token.is_none(), "{source:?}/{kind} envelope changed");
            }
            assert_eq!(
                value["entity_ack_contract"],
                crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT
            );
        }
    }
}

#[test]
fn ack_accepts_non_permanent_only_for_declared_literal_holds() {
    let literal = vec![item(0, true), item(1, true)];
    let mixed = vec![item(0, true), item(1, false)];
    for (source, items, rejected, valid) in [
        (SnapshotSource::ClaudeCode, &literal, (0, HELD, false), true),
        (
            SnapshotSource::ClaudeCode,
            &literal,
            (0, REFUSED, false),
            true,
        ),
        (
            SnapshotSource::ClaudeCode,
            &literal,
            (0, REFUSED, true),
            true,
        ),
        (SnapshotSource::ClaudeCode, &literal, (0, HELD, true), true),
        // Every other reason stays permanent-only.
        (
            SnapshotSource::ClaudeCode,
            &literal,
            (0, "other", false),
            false,
        ),
        (
            SnapshotSource::ClaudeCode,
            &literal,
            (0, "accepted_log_stale_older_upload", false),
            false,
        ),
        (
            SnapshotSource::ClaudeCode,
            &literal,
            (0, "usage_decrease_future", false),
            false,
        ),
        // A hold must name a literal body of a declaring batch.
        (SnapshotSource::ClaudeCode, &mixed, (1, HELD, false), false),
        (SnapshotSource::ClaudeCode, &mixed, (0, HELD, false), true),
        (SnapshotSource::Codex, &literal, (0, HELD, false), false),
        (SnapshotSource::Pi, &literal, (0, REFUSED, false), false),
    ] {
        let response = ack(items, &[rejected]);
        let result = response.validate_entity_ack(&request(source, items.clone()));
        assert_eq!(result.is_ok(), valid, "{source:?} {rejected:?}: {result:?}");
    }
    let rejection = &ack(&literal, &[(0, HELD, false)]).rejected_entities[0];
    assert_eq!(rejection.safe_reason(), HELD);
    assert!(rejection.usage_decrease_hold());
    let rejection = &ack(&literal, &[(0, REFUSED, true)]).rejected_entities[0];
    assert_eq!(rejection.safe_reason(), REFUSED);
    assert_eq!(
        crate::upload_receipts::RejectedUsageReason::from_wire(rejection.safe_reason()),
        crate::upload_receipts::RejectedUsageReason::Other,
        "persisted vocabulary is unchanged"
    );
}

#[test]
#[serial_test::serial(client_report)]
fn held_literal_body_is_retryable_reoffered_and_never_poison() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let scope = "claude_code-usage-decrease-held";
    let items = (0..3).map(|i| item(i, true)).collect::<Vec<_>>();
    let held = items[0].snapshot_fingerprint.clone();
    assert!(items[1..].iter().all(|i| i.snapshot_fingerprint != held));
    let mut ledger = progress();
    let mut accepted = 0;
    let outcome = upload(&items, scope, &mut ledger, &mut accepted, |batch| {
        ack(batch, &[(at(batch, &held), HELD, false)])
    })
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Deferred { count: 1 });
    // Siblings are checkpointed; the held body is not.
    assert_eq!(accepted, 2);
    for sibling in &items[1..] {
        assert!(ledger
            .accepted_fingerprints
            .contains(&sibling.snapshot_fingerprint));
    }
    assert!(!ledger.accepted_fingerprints.contains(&held));
    assert!(!ledger.permanent_rejections.contains_key(&held));
    let record = &ledger.quarantined_fingerprints[&held];
    assert_eq!(
        record.disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    assert_eq!(record.failed_reconstruction_count, 1);
    assert!(record.retry_after_unix_seconds >= current_unix_seconds());
    assert!(snapshot_quarantine_deadline_is_bounded(record));
    assert!(!counted_poison_fingerprints_for_test(scope).contains(&held));

    // Restart before the deadline: nothing is resent.
    let mut restarted: SnapshotUploadProgress =
        serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
    restarted.active_quarantine_witness = ledger.active_quarantine_witness.clone();
    let mut ledger = restarted;
    assert!(!ledger.prepare_quarantine_retries(&BTreeMap::new()));
    let outcome = upload(&items, scope, &mut ledger, &mut accepted, |_| {
        panic!("a not-yet-due hold and accepted siblings are never resent")
    })
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Completed);

    // A newer body (new usage, so a new fingerprint) is offered at once;
    // the backend judges it afresh.
    let mut newer = items.clone();
    newer[0].request_count += 1;
    newer[0].snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::ClaudeCode, &newer[0]);
    let newer_fingerprint = newer[0].snapshot_fingerprint.clone();
    assert_ne!(newer_fingerprint, held);
    let mut sent = Vec::new();
    upload(&newer, scope, &mut ledger, &mut accepted, |batch| {
        sent.extend(batch.iter().map(|i| i.snapshot_fingerprint.clone()));
        ack(batch, &[(at(batch, &newer_fingerprint), HELD, false)])
    })
    .unwrap();
    assert_eq!(sent, vec![newer_fingerprint.clone()]);

    // Once due, the same body is re-offered and settles on acceptance.
    let mut ledger = progress();
    let mut accepted = 0;
    upload(&items, scope, &mut ledger, &mut accepted, |batch| {
        ack(batch, &[(at(batch, &held), HELD, false)])
    })
    .unwrap();
    ledger
        .quarantined_fingerprints
        .get_mut(&held)
        .unwrap()
        .retry_after_unix_seconds = 1;
    assert!(ledger.prepare_quarantine_retries(&BTreeMap::new()));
    assert!(ledger.active_quarantine_retries.contains(&held));
    let mut sent = Vec::new();
    let outcome = upload(&items, scope, &mut ledger, &mut accepted, |batch| {
        sent.extend(batch.iter().map(|i| i.snapshot_fingerprint.clone()));
        ack(batch, &[])
    })
    .unwrap();
    assert_eq!(sent, vec![held.clone()]);
    assert_eq!(outcome, ResumableUploadResult::Completed);
    assert!(ledger.accepted_fingerprints.contains(&held));
    assert!(!counted_poison_fingerprints_for_test(scope).contains(&held));
}

#[test]
#[serial_test::serial(client_report)]
fn refused_after_review_permanent_takes_the_permanent_path() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let scope = "claude_code-usage-decrease-refused";
    let items = (0..2).map(|i| item(i, true)).collect::<Vec<_>>();
    let refused = items[0].snapshot_fingerprint.clone();
    let mut ledger = progress();
    let mut accepted = 0;
    let outcome = upload(&items, scope, &mut ledger, &mut accepted, |batch| {
        ack(batch, &[(at(batch, &refused), REFUSED, true)])
    })
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Rejected { count: 1 });
    assert_eq!(accepted, 1);
    assert!(ledger
        .accepted_fingerprints
        .contains(&items[1].snapshot_fingerprint));
    assert_eq!(
        ledger.permanent_rejections[&refused].reason,
        crate::upload_receipts::RejectedUsageReason::Other
    );
    assert_eq!(
        ledger.quarantined_fingerprints[&refused].disposition,
        SnapshotQuarantineDisposition::UnprovenTerminal
    );
    assert!(counted_poison_fingerprints_for_test(scope).contains(&refused));
    // Never re-offered, across a restart.
    let mut restarted: SnapshotUploadProgress =
        serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
    restarted.active_quarantine_witness = ledger.active_quarantine_witness.clone();
    let mut ledger = restarted;
    ledger.prepare_quarantine_retries(&BTreeMap::new());
    assert!(!ledger.active_quarantine_retries.contains(&refused));
    let outcome = upload(&items, scope, &mut ledger, &mut accepted, |_| {
        panic!("a reviewed final refusal is never re-offered")
    })
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Rejected { count: 1 });
}

#[test]
#[serial_test::serial(client_report)]
fn non_literal_hold_is_an_invalid_ack_and_checkpoints_nothing() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let items = (0..2).map(|i| item(i, false)).collect::<Vec<_>>();
    let mut ledger = progress();
    let mut accepted = 0;
    let error = upload_resumable_batches_with_body_witness(
        &items,
        "claude_code-usage-decrease-legacy",
        &mut ledger,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let response = ack(&batch, &[(0, HELD, false)]);
            response.validate_entity_ack(&request(SnapshotSource::ClaudeCode, batch))?;
            Ok(response)
        },
        |_| panic!("an invalid ACK must not checkpoint"),
    )
    .unwrap_err();
    assert_eq!(
        snapshot_upload_error_class(&error),
        Some(SnapshotUploadErrorClass::BackendResponse)
    );
    assert_eq!(accepted, 0);
    assert!(ledger.accepted_fingerprints.is_empty());
    assert!(ledger.quarantined_fingerprints.is_empty());
}
