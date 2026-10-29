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
        source: "codex".into(),
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
            let mut response = server(&request.snapshots[0]);
            response.validate_entity_ack_with_head_cas(&request, true)?;
            response.bind_conflict_rescans(&request);
            Ok(response)
        },
        |_| Ok(()),
    );
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
    let root = std::env::temp_dir().join(format!(
        "ottto-head-conflict-answer-{}-{}",
        std::process::id(),
        current_unix_seconds()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("upload-progress.json");
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
    let _ = std::fs::remove_dir_all(root);

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
    let mut withheld = vec![item.clone()];
    withheld[0].cache_base_head_etag = Some("2".repeat(64));
    withheld[0].cache_observations = None;
    withheld[0].cache_observations_state = None;
    assert_eq!(
        attach_head_conflict_answers(&mut withheld, &progress, 1_000),
        0
    );
    assert!(withheld[0].cache_conflict_answer.is_none());
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
