//! Offline head-CAS conflict-recovery fixtures. Synthetic items and a fake
//! server only; no installed state, transcripts or providers.
use super::*;
use crate::snapshot_client::{SnapshotBatchResponse, SnapshotEntityRef};
use serde_json::Value;

const SCOPE: &str = "codex-head-conflict-answer-test";

fn stale_head() -> String {
    "1".repeat(64)
}

fn challenge(n: u8) -> String {
    format!("{n:x}").repeat(64)
}

fn item() -> SnapshotItem {
    let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    assert!(
        item.cache_observations.is_some(),
        "fixture carries a cache patch"
    );
    item
}

fn progress_with_stale_head(item: &SnapshotItem) -> SnapshotUploadProgress {
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    progress
        .accepted_cache_heads
        .insert(cache_session_key(&item.source_session_id), stale_head());
    progress
}

fn request(items: Vec<SnapshotItem>) -> SnapshotBatchRequest {
    SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: if items
            .iter()
            .all(crate::snapshots::claude_request_money::is_request_owned_literal)
        {
            SnapshotSource::ClaudeCode.api_slug()
        } else {
            SnapshotSource::Codex.api_slug()
        }
        .into(),
        machine_id: "a".repeat(64),
        collector_version: None,
        snapshots: items,
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    }
}

fn reference(item: &SnapshotItem) -> SnapshotEntityRef {
    SnapshotEntityRef {
        source_session_id: item.source_session_id.clone(),
        snapshot_fingerprint: item.snapshot_fingerprint.clone(),
        occurrence_count: 1,
        body_witness_version: None,
        body_witness_digest: None,
        head_etag: None,
        head_challenge: None,
        unchanged_basis: None,
        retained_proof_missing: Vec::new(),
    }
}

fn empty_ack() -> SnapshotBatchResponse {
    SnapshotBatchResponse {
        conflict_rescans: Default::default(),
        accepted: 0,
        sessions_reconciled: 0,
        session_ids: Vec::new(),
        disabled: false,
        disabled_reason: None,
        entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
        accepted_entities: Vec::new(),
        unchanged_entities: Vec::new(),
        rejected_entities: Vec::new(),
        conflict_entities: Vec::new(),
    }
}

/// The server stored the body and returns its new head with the exact echo.
fn accepted(item: &SnapshotItem, head: &str) -> SnapshotBatchResponse {
    let version = crate::snapshot_client::snapshot_ack_body_witness_version(item).unwrap();
    let mut ack = empty_ack();
    ack.accepted = 1;
    ack.accepted_entities.push(SnapshotEntityRef {
        body_witness_version: version,
        body_witness_digest: version.map(|_| snapshot_upload_body_witness(item)),
        head_etag: Some(head.to_string()),
        ..reference(item)
    });
    ack
}

/// The server's CAS check refused the base and minted a rescan challenge.
fn conflict(item: &SnapshotItem, challenge: &str) -> SnapshotBatchResponse {
    let mut ack = empty_ack();
    ack.conflict_entities.push(SnapshotEntityRef {
        head_challenge: Some(challenge.to_string()),
        ..reference(item)
    });
    ack
}

/// One production-shaped source page: base from the saved head, answer
/// attached at `now`, the normal ACK validator and conflict binding, and the
/// normal page settlement. A held conflict body is offered under its bounded
/// retry lease, as the quarantine retry selection does.
fn cycle(
    progress: &mut SnapshotUploadProgress,
    item: &SnapshotItem,
    now: u64,
    server: impl Fn(&SnapshotItem) -> SnapshotBatchResponse,
) -> (Result<ResumableUploadResult>, Value) {
    cycle_with_transport(progress, item, now, |item| Ok(server(item)))
}

fn cycle_with_transport(
    progress: &mut SnapshotUploadProgress,
    item: &SnapshotItem,
    now: u64,
    server: impl Fn(&SnapshotItem) -> Result<SnapshotBatchResponse>,
) -> (Result<ResumableUploadResult>, Value) {
    let root = crate::test_scratch::ScratchDir::new("head-conflict-cycle");
    let path = root.join("progress.json");
    // Each call starts from this view, then saves at the real page boundary.
    let mut durable = progress.clone();
    durable.generation = 0;
    durable.save(&path).unwrap();
    progress.generation = durable.generation;
    let mut items = vec![item.clone()];
    items[0].cache_base_head_etag = progress
        .accepted_cache_heads
        .get(&cache_session_key(&item.source_session_id))
        .cloned();
    attach_head_conflict_answers(&mut items, progress, now);
    progress
        .active_quarantine_retries
        .insert(item.snapshot_fingerprint.clone());
    let mut wire = Value::Null;
    let mut accepted_count = 0;
    let result = upload_resumable_batches_with_body_witness(
        &items,
        SCOPE,
        progress,
        &mut accepted_count,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let request = request(batch);
            wire = serde_json::to_value(request.wire_with_head_cas())?;
            let mut response = server(&request.snapshots[0])?;
            response.validate_entity_ack_with_head_cas(&request, true)?;
            response.bind_conflict_rescans(&request);
            Ok(response)
        },
        |state| state.save(&path),
    );
    if result.is_ok() {
        let restored = SnapshotUploadProgress::load(
            &path,
            &progress.destination_namespace_hash,
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
        .unwrap();
        assert_eq!(
            restored.head_conflict_challenges,
            progress.head_conflict_challenges
        );
        assert_eq!(
            restored.accepted_body_witnesses,
            progress.accepted_body_witnesses
        );
    }
    progress.active_quarantine_retries.clear();
    (result, wire)
}

fn envelope(wire: &Value) -> &Value {
    &wire["snapshots"][0]["semantic_envelope"]
}

fn revision_v2(item: &SnapshotItem) -> String {
    crate::snapshots::snapshot_semantic_envelope(
        SnapshotSource::Codex,
        item,
        SnapshotUploadPolicy::default(),
    )
    .revision_v2_hash
}

#[test]
fn conflict_challenge_is_answered_once_and_replaces_the_server_head() {
    super::tests::claude_money_e2_pipeline_tests::money_equivalence_tests::assert_head_conflict_account_placement();
    let item = item();
    let key = cache_session_key(&item.source_session_id);
    let mut progress = progress_with_stale_head(&item);

    // Stale base: the server refuses it and returns a challenge.
    let (result, refused_wire) = cycle(&mut progress, &item, 1_000, |item| {
        conflict(item, &challenge(0xc))
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert_eq!(envelope(&refused_wire)["base_head_etag"], stale_head());
    assert_eq!(
        progress.accepted_cache_heads[&key],
        stale_head(),
        "no head invented"
    );
    let record = &progress.head_conflict_challenges[&key];
    assert_eq!(record.challenge, challenge(0xc));
    assert_eq!(record.stale_revision_v2_hash, revision_v2(&item));
    assert_eq!(record.answer_attempts, 0);
    assert!(progress
        .quarantined_fingerprints
        .contains_key(&item.snapshot_fingerprint));

    // The owed challenge survives a restart through the persisted ledger.
    let root = crate::test_scratch::ScratchDir::new("head-conflict-restart");
    let path = root.join("upload-progress.json");
    // This is a copy into a new ledger, not a CAS update of cycle's file.
    progress.generation = 0;
    progress.save(&path).unwrap();
    let mut progress = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert_eq!(
        progress.head_conflict_challenges[&key].challenge,
        challenge(0xc)
    );
    drop(root);

    // Next offer answers through the existing rescan handshake.
    let (result, answer_wire) = cycle(&mut progress, &item, 1_001, |item| {
        accepted(item, &"2".repeat(64))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    let answer = envelope(&answer_wire);
    assert!(
        answer.get("base_head_etag").is_none(),
        "never combined with a base"
    );
    assert_eq!(answer["conflict_head_challenge"], challenge(0xc));
    assert_eq!(answer["rescan_from_revision_hash"], revision_v2(&item));
    assert_eq!(answer["forced_full_rescan"], true);

    // Same session key and the same full-state body as a clean upload: the
    // server replaces its head, never adds a copy.
    let mut clean = item.clone();
    clean.cache_base_head_etag = Some("2".repeat(64));
    let clean_wire = serde_json::to_value(request(vec![clean]).wire_with_head_cas()).unwrap();
    let body = |wire: &Value| {
        let mut body = wire["snapshots"][0].clone();
        body.as_object_mut().unwrap().remove("semantic_envelope");
        body
    };
    assert_eq!(body(&answer_wire), body(&clean_wire));
    let mut answer = answer.clone();
    let mut clean_envelope = envelope(&clean_wire).clone();
    for field in [
        "base_head_etag",
        "conflict_head_challenge",
        "rescan_from_revision_hash",
        "forced_full_rescan",
    ] {
        answer.as_object_mut().unwrap().remove(field);
        clean_envelope.as_object_mut().unwrap().remove(field);
    }
    assert_eq!(answer, clean_envelope, "same identity, revision and totals");
    let mut normalized_answer = answer_wire.clone();
    let mut normalized_clean = clean_wire.clone();
    normalized_answer["snapshots"][0]["semantic_envelope"] = answer;
    normalized_clean["snapshots"][0]["semantic_envelope"] = clean_envelope;
    assert_eq!(
        serde_json::to_vec(&normalized_answer).unwrap(),
        serde_json::to_vec(&normalized_clean).unwrap(),
        "exact wire bytes outside handshake"
    );

    assert_eq!(progress.accepted_cache_heads[&key], "2".repeat(64));
    assert!(progress.head_conflict_challenges.is_empty());
    assert_eq!(
        progress.accepted_body_witnesses[&item.snapshot_fingerprint],
        snapshot_upload_body_witness(&item)
    );
    assert!(progress.quarantined_fingerprints.is_empty());

    // Recovered: the following upload uses the new base and no answer.
    let mut next = vec![item.clone()];
    next[0].cache_base_head_etag = progress.accepted_cache_heads.get(&key).cloned();
    assert_eq!(attach_head_conflict_answers(&mut next, &progress, 1_002), 0);
    let next_wire = serde_json::to_value(request(next).wire_with_head_cas()).unwrap();
    assert_eq!(envelope(&next_wire)["base_head_etag"], "2".repeat(64));
    assert!(envelope(&next_wire)
        .get("conflict_head_challenge")
        .is_none());

    let mut not_stored = progress_with_stale_head(&item);
    let _ = cycle(&mut not_stored, &item, 1_004, |item| {
        conflict(item, &challenge(0xc))
    });
    let (result, _) = cycle(&mut not_stored, &item, 1_005, |item| {
        let mut response = accepted(item, &"3".repeat(64));
        // Accepted count covers stored AND unchanged occurrence refs.
        let mut entity = response.accepted_entities.pop().unwrap();
        entity.unchanged_basis = Some("usage_identical".into());
        response.unchanged_entities.push(entity);
        response
    });
    assert!(result.is_ok());
    assert!(not_stored.head_conflict_challenges.is_empty());
    assert!(not_stored.accepted_body_witnesses.is_empty());
    assert!(not_stored.fresh_context_body_acks.is_empty());
    assert!(not_stored
        .quarantined_fingerprints
        .contains_key(&item.snapshot_fingerprint));

    let root = crate::test_scratch::ScratchDir::new("head-conflict-destination");
    let path = root.join("progress.json");
    let mut other = progress_with_stale_head(&item);
    let _ = cycle(&mut other, &item, 1_006, |item| {
        conflict(item, &challenge(0xc))
    });
    other.generation = 0;
    other.save(&path).unwrap();
    let foreign = SnapshotUploadProgress::load(
        &path,
        &"b".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert!(foreign.head_conflict_challenges.is_empty());
    assert!(foreign.accepted_body_witnesses.is_empty());
}

#[test]
fn witness_only_ack_rejection_recovers_through_the_next_conflict() {
    let item = item();
    let key = cache_session_key(&item.source_session_id);
    let mut progress = progress_with_stale_head(&item);

    // The server stored the body but echoed a different witness digest. The
    // whole response is rejected, so the daemon keeps the predecessor head.
    let (result, _) = cycle(&mut progress, &item, 1_000, |item| {
        let mut ack = accepted(item, &"2".repeat(64));
        ack.accepted_entities[0].body_witness_digest = Some("0".repeat(64));
        ack
    });
    assert!(
        result.is_err(),
        "mismatched witness echo is not a settlement"
    );
    assert_eq!(progress.accepted_cache_heads[&key], stale_head());
    assert!(progress.head_conflict_challenges.is_empty());
    assert!(
        crate::snapshot_client::ANSWERED_WITNESS_WARNINGS.with(|lines| lines.borrow().is_empty())
    );

    // That predecessor is now stale on the server: conflict with challenge.
    let (result, _) = cycle(&mut progress, &item, 1_001, |item| {
        conflict(item, &challenge(0xd))
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert_eq!(
        progress.head_conflict_challenges[&key].challenge,
        challenge(0xd)
    );

    // Residual risk: the answered upload's ACK echoes another witness. The
    // cycle does not settle, and one content-free warning names the session
    // hash and versions. An unanswered rejection (above) warns nothing.
    let warnings = || {
        crate::snapshot_client::ANSWERED_WITNESS_WARNINGS
            .with(|lines| std::mem::take(&mut *lines.borrow_mut()))
    };
    let version = crate::snapshot_client::snapshot_ack_body_witness_version(&item)
        .unwrap()
        .unwrap();
    let (result, _) = cycle(&mut progress, &item, 1_002, |item| {
        let mut ack = accepted(item, &"2".repeat(64));
        ack.accepted_entities[0].body_witness_digest = Some("0".repeat(64));
        ack
    });
    assert!(result.is_err());
    assert_eq!(
        warnings(),
        [format!(
            "warning: local snapshot head-CAS answer ACK rejected: session_hash={} \
             witness_version={version} echoed_witness_version={version} \
             reason=ack_body_witness_mismatch; the next conflict re-records the challenge",
            &key[..8]
        )]
    );
    assert_eq!(progress.accepted_cache_heads[&key], stale_head());
    assert_eq!(
        progress.head_conflict_challenges[&key].challenge,
        challenge(0xd)
    );

    assert_eq!(progress.head_conflict_challenges[&key].answer_attempts, 0);
    assert_eq!(progress.head_conflict_challenges[&key].last_answer_unix, 0);
    let before = progress.clone();
    let (lost, wire) = cycle_with_transport(&mut progress, &item, 1_003, |_| {
        Err(anyhow!("synthetic lost reply"))
    });
    assert!(lost.is_err());
    assert_eq!(envelope(&wire)["conflict_head_challenge"], challenge(0xd));
    assert_eq!(
        progress.head_conflict_challenges,
        before.head_conflict_challenges
    );
    assert_eq!(
        progress.accepted_body_witnesses,
        before.accepted_body_witnesses
    );

    // The challenge answer settles and the saved head is current again.
    let (result, wire) = cycle(&mut progress, &item, 1_003, |item| {
        accepted(item, &"3".repeat(64))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(envelope(&wire)["conflict_head_challenge"], challenge(0xd));
    assert_eq!(progress.accepted_cache_heads[&key], "3".repeat(64));
    assert!(progress.head_conflict_challenges.is_empty());
}

#[test]
#[serial_test::serial(client_report)]
fn refused_answers_are_counted_and_paced_by_the_quarantine_window() {
    let item = item();
    let key = cache_session_key(&item.source_session_id);
    let window = crate::snapshots::SNAPSHOT_QUARANTINE_RETRY_SECONDS;
    let mut progress = progress_with_stale_head(&item);

    let _ = cycle(&mut progress, &item, 1_000, |item| {
        conflict(item, &challenge(0xa))
    });
    // The answer itself is refused (the head moved again).
    let answered_at = current_unix_seconds();
    let (result, wire) = cycle(&mut progress, &item, 1_001, |item| {
        conflict(item, &challenge(0xb))
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert_eq!(envelope(&wire)["conflict_head_challenge"], challenge(0xa));
    let record = progress.head_conflict_challenges[&key].clone();
    assert_eq!(record.challenge, challenge(0xb));
    assert_eq!(record.answer_attempts, 1);
    assert!(record.last_answer_unix >= answered_at);

    // Inside the window every offer keeps today's stale-base behaviour, and
    // an unanswered conflict neither counts an attempt nor resets the window.
    for offset in [0, 1, window - 1] {
        let (result, wire) = cycle(
            &mut progress,
            &item,
            record.last_answer_unix + offset,
            |item| conflict(item, &challenge(0xe)),
        );
        assert_eq!(
            result.unwrap(),
            ResumableUploadResult::Deferred { count: 1 }
        );
        assert_eq!(envelope(&wire)["base_head_etag"], stale_head());
        assert!(envelope(&wire).get("conflict_head_challenge").is_none());
        let current = &progress.head_conflict_challenges[&key];
        assert_eq!(current.answer_attempts, 1);
        assert_eq!(current.last_answer_unix, record.last_answer_unix);
    }
    assert_eq!(progress.accepted_cache_heads[&key], stale_head());

    // One answer per window, never terminal: the session stays retryable.
    let (result, wire) = cycle(
        &mut progress,
        &item,
        record.last_answer_unix + window,
        |item| conflict(item, &challenge(0xf)),
    );
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert_eq!(envelope(&wire)["conflict_head_challenge"], challenge(0xe));
    assert_eq!(progress.head_conflict_challenges[&key].answer_attempts, 2);
    assert!(progress.permanent_rejections.is_empty());
    assert_eq!(
        progress.quarantined_fingerprints[&item.snapshot_fingerprint].disposition,
        SnapshotQuarantineDisposition::RetryPending
    );

    let cap = ack_retention::default_ack_capacity();
    let held = progress.quarantined_fingerprints.clone();
    let template = progress.head_conflict_challenges[&key].clone();
    for n in 0..cap - 1 {
        progress
            .head_conflict_challenges
            .insert(format!("{n:064x}"), template.clone());
    }
    assert_eq!(progress.head_conflict_challenges.len(), cap);
    head_conflict::REFUSALS.with(|counts| counts.borrow_mut().clear());
    let mut overflow = item.clone();
    overflow.source_session_id = "synthetic-new-over-cap".into();
    overflow.snapshot_fingerprint = "9".repeat(64);
    progress
        .accepted_cache_heads
        .insert(cache_session_key(&overflow.source_session_id), stale_head());
    let (result, _) = cycle(&mut progress, &overflow, 2_000, |item| {
        conflict(item, &challenge(0xa))
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert_eq!(progress.head_conflict_challenges.len(), cap);
    assert!(!progress
        .head_conflict_challenges
        .contains_key(&cache_session_key(&overflow.source_session_id)));
    assert!(progress
        .quarantined_fingerprints
        .contains_key(&overflow.snapshot_fingerprint));
    assert_eq!(
        progress.quarantined_fingerprints[&item.snapshot_fingerprint],
        held[&item.snapshot_fingerprint]
    );
    head_conflict::REFUSALS.with(|counts| assert_eq!(&*counts.borrow(), &["capacity_hold"]));
    // Existing keys still update at the cap, including their pacing count.
    let (result, _) = cycle(
        &mut progress,
        &item,
        current_unix_seconds() + window,
        |item| conflict(item, &challenge(0xb)),
    );
    assert!(result.is_ok());
    assert_eq!(
        progress.head_conflict_challenges[&key].challenge,
        challenge(0xb)
    );
    assert_eq!(progress.head_conflict_challenges[&key].answer_attempts, 3);

    for permanent in [false, true] {
        let mut rejected_item = item.clone();
        rejected_item.usage_accounting_contract =
            Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT.into());
        rejected_item.snapshot_fingerprint =
            crate::snapshots::snapshot_fingerprint(SnapshotSource::ClaudeCode, &rejected_item);
        let mut rejected = progress_with_stale_head(&rejected_item);
        let _ = cycle(&mut rejected, &rejected_item, 1_000, |item| {
            conflict(item, &challenge(0xc))
        });
        let (result, _) = cycle(&mut rejected, &rejected_item, 1_001, |item| {
            let mut response = empty_ack();
            response
                .rejected_entities
                .push(crate::snapshot_client::SnapshotEntityRejection {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    permanent,
                    reason: if permanent {
                        "body_exceeds_max_bytes"
                    } else {
                        "usage_decrease_held_for_review"
                    }
                    .into(),
                    detail: String::new(),
                });
            response
        });
        assert!(result.is_ok());
        assert_eq!(rejected.head_conflict_challenges.is_empty(), permanent);
        assert!(rejected.accepted_body_witnesses.is_empty());
        assert!(rejected
            .quarantined_fingerprints
            .contains_key(&rejected_item.snapshot_fingerprint));
        if !permanent {
            assert_eq!(rejected.head_conflict_challenges[&key].answer_attempts, 0);
        }
    }
}

#[test]
fn healthy_sessions_send_the_unchanged_wire_and_keep_no_challenge() {
    let item = item();
    let key = cache_session_key(&item.source_session_id);
    let mut progress = progress_with_stale_head(&item);
    let mut baseline = item.clone();
    baseline.cache_base_head_etag = Some(stale_head());
    let baseline_wire = serde_json::to_value(request(vec![baseline]).wire_with_head_cas()).unwrap();

    let (result, wire) = cycle(&mut progress, &item, 1_000, |item| {
        accepted(item, &"2".repeat(64))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(wire, baseline_wire, "no answer fields on a healthy upload");
    for field in [
        "conflict_head_challenge",
        "rescan_from_revision_hash",
        "forced_full_rescan",
    ] {
        assert!(envelope(&wire).get(field).is_none(), "{field}");
    }
    assert_eq!(progress.accepted_cache_heads[&key], "2".repeat(64));
    assert!(progress.head_conflict_challenges.is_empty());

    // A body whose cache patch was withheld sends no CAS contract, so it
    // keeps today's wire even while a challenge is owed.
    progress.head_conflict_challenges.insert(
        key.clone(),
        HeadConflictChallenge {
            challenge: challenge(0xc),
            stale_revision_v2_hash: revision_v2(&item),
            answer_attempts: 0,
            last_answer_unix: 0,
        },
    );
    let reserved = identity_cache_wire_reserve(&item, &progress);
    let mut projected = item.clone();
    prepare_snapshot_cache_for_upload(&mut projected, &progress, true, false, &BTreeSet::new());
    attach_head_conflict_answers(std::slice::from_mut(&mut projected), &progress, u64::MAX);
    assert!(projected.cache_conflict_answer.is_some());
    assert_eq!(
        crate::snapshots::claude_request_identity::item_bytes(&item) + reserved,
        crate::snapshots::claude_request_identity::item_bytes(&projected),
        "preflight reserves the complete challenge framing"
    );
    let mut no_answer = projected.clone();
    no_answer.cache_conflict_answer = None;
    assert!(
        crate::snapshots::claude_request_identity::item_bytes(&projected)
            > crate::snapshots::claude_request_identity::item_bytes(&no_answer)
    );
    let record = progress.head_conflict_challenges.get_mut(&key).unwrap();
    record.answer_attempts = 1;
    record.last_answer_unix = current_unix_seconds();
    assert_eq!(
        identity_cache_wire_reserve(&item, &progress),
        reserved,
        "pacing-boundary crossing cannot evade admission reserve"
    );
    let mut withheld = vec![item.clone()];
    withheld[0].cache_base_head_etag = Some("2".repeat(64));
    withheld[0].cache_observations = None;
    withheld[0].cache_observations_state = None;
    assert_eq!(
        attach_head_conflict_answers(&mut withheld, &progress, 1_000),
        0
    );
    assert!(withheld[0].cache_conflict_answer.is_none());
    let mut no_base = vec![item.clone()];
    no_base[0].cache_base_head_etag = None;
    assert_eq!(
        attach_head_conflict_answers(&mut no_base, &progress, 1_000),
        0
    );
    assert!(no_base[0].cache_conflict_answer.is_none());
    progress
        .head_conflict_challenges
        .get_mut(&key)
        .unwrap()
        .answer_attempts = 0;
    let saved = progress.head_conflict_challenges.clone();
    let (foreign, _) = cycle(&mut progress, &item, 1_000, |item| {
        let mut response = conflict(item, &challenge(0xe));
        response.conflict_entities[0].source_session_id = "synthetic-foreign".into();
        response
    });
    assert!(foreign.is_err());
    assert_eq!(progress.head_conflict_challenges, saved);
    progress.head_conflict_challenges.clear();

    // A conflict without a challenge or a bound request body records nothing.
    let mut unbound = item.clone();
    unbound.cache_base_head_etag = Some("2".repeat(64));
    let mut response = conflict(&unbound, &challenge(0xc));
    response.conflict_rescans.clear();
    let mut accepted_count = 0;
    progress
        .active_quarantine_retries
        .insert(item.snapshot_fingerprint.clone());
    upload_resumable_batches_with_body_witness(
        &[unbound],
        SCOPE,
        &mut progress,
        &mut accepted_count,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| Ok(response.clone()),
        |_| Ok(()),
    )
    .unwrap();
    assert!(progress.head_conflict_challenges.is_empty());
}

#[test]
fn released_0205_rewrite_preserves_money_ledgers_and_drops_only_recovery_metadata() {
    let item = item();
    let key = cache_session_key(&item.source_session_id);
    let mut progress = progress_with_stale_head(&item);
    let _ = cycle(&mut progress, &item, 1_000, |item| {
        conflict(item, &challenge(0xc))
    });
    progress.record_body(&"b".repeat(64), &"c".repeat(64));
    progress.quarantine_permanent_body(&"d".repeat(64), &"e".repeat(64), "body_exceeds_max_bytes");
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    let identity = serde_json::json!({"source_session_id":"synthetic-compat",
        "provenance":{"collector":crate::snapshots::claude_request_identity::COLLECTOR},
        "request_evidence":[{"identity_basis":"telemetry_login"}],
        "usage_buckets":[{"bucket_start":"2026-09-01T10:00:00Z","model_usage":[{
            "model":"claude-synthetic","evidence_ref":0,"account_identifier_hash":"a".repeat(64),
            "input_tokens":10,"cost_usd":"1.00"}]}]});
    progress.accepted_identity_buckets.record(&identity);
    progress
        .accepted_identity_buckets
        .record_proved(&identity, true, &[]);
    assert!(!progress.accepted_identity_buckets.is_empty());
    let bytes = serde_json::to_vec(&progress).unwrap();
    let old: head_conflict_released_progress_fixture::SnapshotUploadProgress =
        serde_json::from_slice(&bytes).unwrap();
    let rewritten = serde_json::to_vec(&old).unwrap();
    let rewritten_value: Value = serde_json::from_slice(&rewritten).unwrap();
    assert!(rewritten_value.get("head_conflict_challenges").is_none());
    let mut known: Value = serde_json::from_slice(&bytes).unwrap();
    known
        .as_object_mut()
        .unwrap()
        .remove("head_conflict_challenges");
    assert_eq!(
        rewritten_value, known,
        "released codec preserves every known durable field"
    );
    // Enter the real load boundary before executing another cycle: runtime
    // quarantine witnesses are intentionally absent from every serde codec.
    let root = crate::test_scratch::ScratchDir::new("head-conflict-downgrade");
    let path = root.join("progress.json");
    std::fs::write(&path, &rewritten).unwrap();
    let mut upgraded = SnapshotUploadProgress::load(
        &path,
        &progress.destination_namespace_hash,
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    upgraded
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    assert!(
        upgraded.head_conflict_challenges.is_empty(),
        "pacing continuity is deliberately lost"
    );
    assert_eq!(
        upgraded.accepted_identity_buckets,
        progress.accepted_identity_buckets
    );
    assert_eq!(
        upgraded.accepted_body_witnesses,
        progress.accepted_body_witnesses
    );
    assert_eq!(upgraded.permanent_rejections, progress.permanent_rejections);
    assert_eq!(
        upgraded.quarantined_fingerprints,
        progress.quarantined_fingerprints
    );
    assert_eq!(upgraded.accepted_cache_heads, progress.accepted_cache_heads);
    let _ = cycle(&mut upgraded, &item, 1_001, |item| {
        conflict(item, &challenge(0xd))
    });
    assert_eq!(upgraded.head_conflict_challenges[&key].answer_attempts, 0);
    assert_eq!(
        upgraded.head_conflict_challenges[&key].challenge,
        challenge(0xd)
    );

    // A record persisted with the retired refused-entity field still decodes.
    let mut retired: Value = serde_json::from_slice(&bytes).unwrap();
    retired["head_conflict_challenges"][&key]["snapshot_fingerprint"] = Value::from("8".repeat(64));
    let decoded: SnapshotUploadProgress = serde_json::from_value(retired).unwrap();
    assert_eq!(
        decoded.head_conflict_challenges,
        progress.head_conflict_challenges
    );
}
