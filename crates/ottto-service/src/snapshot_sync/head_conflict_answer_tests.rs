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
    {
        super::tests::claude_money_e2_pipeline_tests::money_equivalence_tests::assert_head_conflict_account_placement();
    }
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
    // [money] The owed answer does not wait behind the 6-12 h quarantine
    // timer: the real selection leases the held body for the next page.
    assert!(
        progress.quarantined_fingerprints[&item.snapshot_fingerprint].retry_after_unix_seconds
            <= current_unix_seconds()
    );
    let mut selecting = progress.clone();
    selecting.prepare_quarantine_retries(&BTreeMap::new());
    assert_eq!(
        selecting.active_quarantine_retries,
        BTreeSet::from([item.snapshot_fingerprint.clone()])
    );

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
    let refusals = || {
        crate::snapshot_client::BODY_WITNESS_REFUSALS
            .with(|lines| std::mem::take(&mut *lines.borrow_mut()))
    };
    let unanswered = refusals();
    assert_eq!(unanswered.len(), 1);
    assert!(unanswered[0].contains("reason=digest_mismatch class=accepted "));
    assert!(unanswered[0].ends_with(" bad_refs=1 answered=false"));

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
    // cycle does not settle, and one content-free line names the failed
    // check, session hash, fingerprint prefix and versions.
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
        refusals(),
        [format!(
            "warning: local snapshot ACK body witness refused: reason=digest_mismatch \
             class=accepted session_hash={} fingerprint={} witness_version={version} \
             echoed_witness_version={version} bad_refs=1 answered=true",
            &key[..8],
            &item.snapshot_fingerprint[..8]
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

/// [regress] A refused answer holds only its identical re-send, and for at
/// most one hour. A new challenge, or a new revision of the session, gets the
/// next answer attempt instead of inheriting the old refusal's hold.
#[test]
#[serial_test::serial(client_report)]
fn refused_answers_hold_only_the_identical_answer_for_at_most_an_hour() {
    let item = item();
    let key = cache_session_key(&item.source_session_id);
    let fingerprint = item.snapshot_fingerprint.clone();
    let hour = 3_600;
    let mut progress = progress_with_stale_head(&item);

    let _ = cycle(&mut progress, &item, 1_000, |item| {
        conflict(item, &challenge(0xa))
    });
    // The answer is refused because the head moved again: a NEW challenge.
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
    assert_eq!(
        record.last_answer_unix, 0,
        "a new challenge inherits no hold"
    );
    assert!(
        progress.quarantined_fingerprints[&fingerprint].retry_after_unix_seconds
            <= current_unix_seconds()
    );

    // So the next page answers it, and the server refuses the IDENTICAL answer.
    let answered_at = current_unix_seconds();
    let (result, wire) = cycle(&mut progress, &item, 1_002, |item| {
        conflict(item, &challenge(0xb))
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert_eq!(envelope(&wire)["conflict_head_challenge"], challenge(0xb));
    let record = progress.head_conflict_challenges[&key].clone();
    assert_eq!(record.answer_attempts, 2);
    assert!(record.last_answer_unix >= answered_at);
    let due = conflict_probe_after(&fingerprint, record.last_answer_unix);
    assert!((record.last_answer_unix + hour / 2..record.last_answer_unix + hour).contains(&due));
    assert_eq!(
        progress.quarantined_fingerprints[&fingerprint].retry_after_unix_seconds, due,
        "the held body is retried exactly when its answer is due"
    );

    // A new revision of the session carries the owed answer at once.
    let mut changed = item.clone();
    changed.avg_duration_ms = Some(changed.avg_duration_ms.unwrap_or_default() + 1);
    changed.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &changed);
    assert_ne!(changed.snapshot_fingerprint, fingerprint);
    let mut revised = progress.clone();
    let (result, wire) = cycle(&mut revised, &changed, record.last_answer_unix, |item| {
        accepted(item, &"3".repeat(64))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(envelope(&wire)["conflict_head_challenge"], challenge(0xb));
    assert!(revised.head_conflict_challenges.is_empty());

    // Inside the hold the identical body keeps today's stale-base behaviour,
    // and an unanswered repeat neither counts an attempt nor moves the hold.
    for at in [record.last_answer_unix, due - 1] {
        let (result, wire) = cycle(&mut progress, &item, at, |item| {
            conflict(item, &challenge(0xb))
        });
        assert_eq!(
            result.unwrap(),
            ResumableUploadResult::Deferred { count: 1 }
        );
        assert_eq!(envelope(&wire)["base_head_etag"], stale_head());
        assert!(envelope(&wire).get("conflict_head_challenge").is_none());
        let current = &progress.head_conflict_challenges[&key];
        assert_eq!(current.answer_attempts, 2);
        assert_eq!(current.last_answer_unix, record.last_answer_unix);
    }
    assert_eq!(progress.accepted_cache_heads[&key], stale_head());

    // The identical answer repeats within the hour, never terminal.
    let (result, wire) = cycle(&mut progress, &item, due, |item| {
        conflict(item, &challenge(0xb))
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert_eq!(envelope(&wire)["conflict_head_challenge"], challenge(0xb));
    assert_eq!(progress.head_conflict_challenges[&key].answer_attempts, 3);
    assert!(progress.permanent_rejections.is_empty());
    assert_eq!(
        progress.quarantined_fingerprints[&fingerprint].disposition,
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
        current_unix_seconds() + hour,
        |item| conflict(item, &challenge(0xb)),
    );
    assert!(result.is_ok());
    assert_eq!(
        progress.head_conflict_challenges[&key].challenge,
        challenge(0xb)
    );
    assert_eq!(progress.head_conflict_challenges[&key].answer_attempts, 4);

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

/// [regress] Observed: identical refused bodies were re-sent byte-identical
/// and refused again for days, each waiting the 6-12 h quarantine retry. A
/// plain conflict (no challenge) is never input-change-only either, because
/// backend state can change without a local change: it is probed within one
/// hour. Held-body suppression and changed-body admission are main's own
/// quarantine tests.
#[test]
fn plain_conflict_is_probed_within_an_hour() {
    // A body without a cache patch sends no head-CAS contract, so its
    // conflict carries no challenge and the ordinary ACK validator applies.
    let mut item = item();
    item.cache_observations = None;
    item.cache_observations_state = None;
    item.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &item);
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    let before = current_unix_seconds();
    let result = upload_resumable_batches_with_body_witness(
        std::slice::from_ref(&item),
        SCOPE,
        &mut progress,
        &mut 0,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let request = request(batch);
            let mut response = empty_ack();
            response
                .conflict_entities
                .push(reference(&request.snapshots[0]));
            response.validate_entity_ack(&request)?;
            Ok(response)
        },
        |_| Ok(()),
    );
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert!(progress.head_conflict_challenges.is_empty());
    let probe =
        progress.quarantined_fingerprints[&item.snapshot_fingerprint].retry_after_unix_seconds;
    assert!(probe >= before + 30 * 60, "not re-sent every page");
    assert!(
        probe < current_unix_seconds() + 60 * 60,
        "mandatory probe within one hour, not 6-12 h"
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
    // The estimate is the upload's own wire at its largest policy framing.
    let largest = SnapshotUploadPolicy {
        session_titles_enabled: false,
        workspace_labels_enabled: false,
        ..SnapshotUploadPolicy::default()
    };
    assert_eq!(
        crate::snapshots::claude_request_identity::item_bytes(&projected),
        crate::snapshots::snapshot_item_wire_size(SnapshotSource::ClaudeCode, &projected, largest)
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

/// The cycle's upload-context activation, on a copy of the ledger: whether
/// the scan index then holds the session as owing an answer (its files read
/// a native Full, never a Tail re-fold).
fn mirrored(progress: &SnapshotUploadProgress, key: &str) -> bool {
    let mut index = ScanIndex::default();
    activate_source_upload_context(
        SnapshotSource::Codex,
        "a".repeat(64),
        &mut index,
        &mut progress.clone(),
    );
    index.head_conflict_owed(key)
}

/// The server's conditions on a POSTed envelope: `forced_full_rescan` is set
/// exactly when `conflict_head_challenge` is, and then with the refused and
/// current revision hashes, under the head-CAS contract and with no base.
fn assert_rescan_claim(wire: &Value, answered: bool) {
    let envelope = envelope(wire);
    assert_eq!(envelope.get("forced_full_rescan").is_some(), answered);
    assert_eq!(envelope.get("conflict_head_challenge").is_some(), answered);
    if answered {
        assert_eq!(envelope["forced_full_rescan"], true);
        assert!(envelope["rescan_from_revision_hash"].is_string());
        assert!(envelope["revision_hash"].is_string());
        assert!(wire["head_cas_contract"].is_string(), "enforced head CAS");
        assert!(envelope.get("base_head_etag").is_none(), "no expected head");
    }
}

/// [money] D142(a) on the POSTed envelope: only the upload of a session that
/// owes an answer carries the rescan claim, and that session is mirrored
/// into the scan index, so the body was read by a native Full. Before the
/// conflict and after the answer the session is not mirrored, so its files
/// may re-fold, and none of those uploads carries `forced_full_rescan`.
#[test]
fn only_a_conflict_owed_native_full_carries_the_rescan_claim() {
    let item = item();
    let key = cache_session_key(&item.source_session_id);
    let mut progress = progress_with_stale_head(&item);
    assert!(!mirrored(&progress, &key), "healthy: may re-fold");

    let (_, refused) = cycle(&mut progress, &item, 1_000, |item| {
        conflict(item, &challenge(0xc))
    });
    assert_rescan_claim(&refused, false);
    assert!(mirrored(&progress, &key), "owed: native Full");

    let (result, answer) = cycle(&mut progress, &item, 1_001, |item| {
        accepted(item, &"2".repeat(64))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_rescan_claim(&answer, true);
    assert_eq!(envelope(&answer)["conflict_head_challenge"], challenge(0xc));
    assert_eq!(
        envelope(&answer)["rescan_from_revision_hash"],
        revision_v2(&item)
    );

    assert!(!mirrored(&progress, &key), "answered: may re-fold again");
    let (result, later) = cycle(&mut progress, &item, 1_002, |item| {
        accepted(item, &"3".repeat(64))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_rescan_claim(&later, false);
}

/// A stale answer refused with a FRESH challenge: the daemon records the
/// fresh challenge from that refusal, the session stays mirrored (its next
/// read is a native Full), and exactly one later upload carries the fresh
/// answer: not two, and never a re-fold's.
#[test]
#[serial_test::serial(client_report)]
fn a_stale_refusal_is_answered_by_exactly_one_native_full() {
    let item = item();
    let key = cache_session_key(&item.source_session_id);
    let mut progress = progress_with_stale_head(&item);
    let _ = cycle(&mut progress, &item, 1_000, |item| {
        conflict(item, &challenge(0xa))
    });
    let (result, stale) = cycle(&mut progress, &item, 1_001, |item| {
        conflict(item, &challenge(0xb))
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert_eq!(envelope(&stale)["conflict_head_challenge"], challenge(0xa));
    assert_eq!(
        progress.head_conflict_challenges[&key].challenge,
        challenge(0xb)
    );
    assert!(mirrored(&progress, &key));
    assert!(
        progress.quarantined_fingerprints[&item.snapshot_fingerprint].retry_after_unix_seconds
            <= current_unix_seconds(),
        "the fresh answer is due at once"
    );

    let mut fresh_answers = 0;
    for (at, head) in [(1_002, "2"), (1_003, "3"), (1_004, "4")] {
        let owed = mirrored(&progress, &key);
        let (result, wire) = cycle(&mut progress, &item, at, |item| {
            accepted(item, &head.repeat(64))
        });
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        let answered = envelope(&wire)["conflict_head_challenge"] == challenge(0xb);
        assert_rescan_claim(&wire, answered);
        assert!(!answered || owed, "an answer rides only a mirrored Full");
        fresh_answers += usize::from(answered);
    }
    assert_eq!(fresh_answers, 1);
    assert!(!mirrored(&progress, &key));
}

/// The mirror is runtime-only: a restart reloads the open challenge from
/// the persisted ledger, and the first activation after it mirrors the
/// session again; the scan index itself never stores it.
#[test]
fn a_restart_mirrors_the_persisted_challenge_again() {
    let item = item();
    let key = cache_session_key(&item.source_session_id);
    let mut progress = progress_with_stale_head(&item);
    let _ = cycle(&mut progress, &item, 1_000, |item| {
        conflict(item, &challenge(0xc))
    });
    let root = crate::test_scratch::ScratchDir::new("head-conflict-mirror-restart");
    let progress_path = root.join("upload-progress.json");
    let index_path = root.join("scan-index.json");
    progress.generation = 0;
    progress.save(&progress_path).unwrap();
    let mut index = ScanIndex::default();
    activate_source_upload_context(
        SnapshotSource::Codex,
        "a".repeat(64),
        &mut index,
        &mut progress,
    );
    assert!(index.head_conflict_owed(&key));
    index.save(&index_path).unwrap();

    let mut restarted = SnapshotUploadProgress::load(
        &progress_path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    let mut index = ScanIndex::load(&index_path).unwrap();
    assert!(!index.head_conflict_owed(&key), "never persisted");
    activate_source_upload_context(
        SnapshotSource::Codex,
        "a".repeat(64),
        &mut index,
        &mut restarted,
    );
    assert!(index.head_conflict_owed(&key));
}

// Upload request split by cache-patch class. The client declares head CAS for
// a whole request when one body carries a cache patch, so an unpatched body
// sent beside a patched one used to travel under CAS with no base, conflict
// with its server head, and owe a challenge it could never answer.

use crate::snapshots::cache_observations::CacheObservations;

fn fresh_progress() -> SnapshotUploadProgress {
    SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
}

fn complete_empty() -> CacheObservations {
    CacheObservations {
        schema_version: 1,
        operations: Vec::new(),
        coverage: "complete".into(),
        omitted_observation_count: None,
    }
}

/// The fixture body as session `name`, carrying `patch` (None: unpatched,
/// as a birth- or cap-withheld body or an unproven Codex body is).
fn body(name: &str, patch: Option<CacheObservations>) -> SnapshotItem {
    let mut item = item();
    item.source_session_id = name.into();
    if patch.is_none() {
        item.cache_observations_state = None;
    }
    item.cache_observations = patch;
    item.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &item);
    item
}

/// A changed revision of `item` (new usage), same session and patch class.
fn revised(item: &SnapshotItem, step: u64) -> SnapshotItem {
    let mut item = item.clone();
    item.avg_duration_ms = Some(item.avg_duration_ms.unwrap_or_default() + step);
    item.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &item);
    item
}

/// The observed seed: an owed challenge, no saved base or cache state, and
/// no answer attempt.
fn owe(progress: &mut SnapshotUploadProgress, item: &SnapshotItem, challenge: String) {
    progress.head_conflict_challenges.insert(
        cache_session_key(&item.source_session_id),
        HeadConflictChallenge {
            challenge,
            stale_revision_v2_hash: revision_v2(item),
            answer_attempts: 0,
            last_answer_unix: 0,
        },
    );
}

fn sessions(wire: &Value) -> Vec<String> {
    wire["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|body| body["source_session_id"].as_str().unwrap().to_owned())
        .collect()
}

/// A backend-shaped head store for the daemon rows; real HTTP and Postgres
/// admission is the backend's own receiver test. An ordinary request skips
/// CAS. Under the head-CAS contract a changed body whose base is not the
/// current head conflicts with a fresh challenge unless it answers the
/// current one. An exact repeat is unchanged; a conflict stores nothing.
#[derive(Clone, Default)]
struct HeadStore {
    /// session -> (head etag, stored body witness)
    heads: BTreeMap<String, (String, String)>,
    challenges: BTreeMap<String, String>,
    minted: u64,
    stored: Vec<String>,
}

impl HeadStore {
    fn mint(&mut self) -> String {
        self.minted += 1;
        format!("{:064x}", 0x1000 + self.minted)
    }

    /// The server already holds an older body of `session`.
    fn seed(&mut self, session: &str) -> String {
        let head = self.mint();
        self.heads
            .insert(session.into(), (head.clone(), "older".into()));
        head
    }

    fn post(&mut self, request: &SnapshotBatchRequest, wire: &Value) -> SnapshotBatchResponse {
        let cas = wire["head_cas_contract"].is_string();
        let mut ack = empty_ack();
        for (item, sent) in request
            .snapshots
            .iter()
            .zip(wire["snapshots"].as_array().unwrap())
        {
            let envelope = &sent["semantic_envelope"];
            let witness = snapshot_upload_body_witness(item);
            let version = crate::snapshot_client::snapshot_ack_body_witness_version(item).unwrap();
            let echo = SnapshotEntityRef {
                body_witness_version: version,
                body_witness_digest: version.map(|_| witness.clone()),
                ..reference(item)
            };
            let session = item.source_session_id.clone();
            if let Some((head, held)) = self.heads.get(&session).cloned() {
                if held == witness {
                    ack.accepted += 1;
                    ack.unchanged_entities.push(SnapshotEntityRef {
                        head_etag: cas.then_some(head),
                        ..echo
                    });
                    continue;
                }
                let answer = envelope["conflict_head_challenge"].as_str();
                let answered =
                    answer.is_some() && answer == self.challenges.get(&session).map(String::as_str);
                if cas && envelope["base_head_etag"].as_str() != Some(head.as_str()) && !answered {
                    let challenge = self.mint();
                    self.challenges.insert(session, challenge.clone());
                    ack.conflict_entities.push(SnapshotEntityRef {
                        head_challenge: Some(challenge),
                        ..reference(item)
                    });
                    continue;
                }
            }
            let head = self.mint();
            self.heads.insert(session.clone(), (head.clone(), witness));
            self.challenges.remove(&session);
            self.stored.push(session);
            ack.accepted += 1;
            ack.accepted_entities.push(SnapshotEntityRef {
                head_etag: cas.then_some(head),
                ..echo
            });
        }
        ack
    }
}

/// One production-shaped main-upload page over several sessions: each saved
/// base, owed answers, the batch `class`, the client's wire (head CAS when a
/// body carries a patch, or for a legacy page), the normal ACK validator and
/// conflict binding, and page settlement saved at each page boundary.
fn page_with_class(
    progress: &mut SnapshotUploadProgress,
    items: &[SnapshotItem],
    legacy: &BTreeSet<String>,
    class: impl Fn(&SnapshotItem) -> u8,
    mut server: impl FnMut(&SnapshotBatchRequest, &Value) -> Result<SnapshotBatchResponse>,
) -> (Result<ResumableUploadResult>, Vec<Value>) {
    let root = crate::test_scratch::ScratchDir::new("class-split-page");
    let path = root.join("progress.json");
    let mut durable = progress.clone();
    durable.generation = 0;
    durable.save(&path).unwrap();
    progress.generation = durable.generation;
    let mut items = items.to_vec();
    for item in &mut items {
        item.cache_base_head_etag = progress
            .accepted_cache_heads
            .get(&cache_session_key(&item.source_session_id))
            .cloned();
        progress
            .active_quarantine_retries
            .insert(item.snapshot_fingerprint.clone());
    }
    attach_head_conflict_answers(&mut items, progress, current_unix_seconds());
    let mut wires = Vec::new();
    let mut accepted = 0;
    let result = upload_resumable_batches_with_literal_families(
        &items,
        SCOPE,
        progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |item| Some(item.source_session_id.as_str()),
        class,
        |_| None,
        &mut InplaceRetryBudget::default(),
        |batch| {
            let request = request(batch);
            let reconcile = request
                .snapshots
                .iter()
                .all(|item| legacy.contains(&item.snapshot_fingerprint));
            let wire = if reconcile {
                serde_json::to_value(request.wire_with_head_cas())?
            } else {
                serde_json::to_value(&request)?
            };
            wires.push(wire.clone());
            let mut response = server(&request, &wire)?;
            response.validate_entity_ack_with_head_cas(&request, reconcile)?;
            response.bind_conflict_rescans(&request);
            Ok(response)
        },
        |state| state.save(&path),
    );
    progress.active_quarantine_retries.clear();
    (result, wires)
}

/// `page_with_class` under the production main-upload class.
fn page(
    progress: &mut SnapshotUploadProgress,
    items: &[SnapshotItem],
    legacy: &BTreeSet<String>,
    server: impl FnMut(&SnapshotBatchRequest, &Value) -> Result<SnapshotBatchResponse>,
) -> (Result<ResumableUploadResult>, Vec<Value>) {
    page_with_class(
        progress,
        items,
        legacy,
        |item| snapshot_upload_batch_class(item, legacy.contains(&item.snapshot_fingerprint)),
        server,
    )
}

/// [money] M1 + R5 + E2: a mixed page (patched, admitted-empty and
/// partial-empty patches; birth- and cap-withheld unpatched bodies; saved and
/// missing bases; existing, missing and exact-repeat server heads). Only the
/// patched request declares head CAS; the ordinary one carries no contract
/// and no borrowed token, and each entity settles by its own ACK.
#[test]
fn mixed_page_sends_each_patch_class_in_its_own_request() {
    let none = BTreeSet::new();
    let mut store = HeadStore::default();
    let mut progress = fresh_progress();
    let patched = body("m1-patched", Some(item().cache_observations.unwrap()));
    let empty = body("m1-admitted-empty", Some(complete_empty()));
    let partial = body(
        "m1-partial-empty",
        Some(CacheObservations::partial(Some(2))),
    );
    let birth = body("m1-birth-withheld", None);
    let cap = body("m1-cap-withheld", None);
    let repeat = body("m1-exact-repeat", None);
    // Saved bases equal the server heads. The birth-withheld session has a
    // server head and no base (the observed population); the partial-empty
    // session is new to the server; the repeat is already stored exactly.
    for item in [&patched, &empty, &cap] {
        let head = store.seed(&item.source_session_id);
        progress
            .accepted_cache_heads
            .insert(cache_session_key(&item.source_session_id), head);
    }
    store.seed(&birth.source_session_id);
    let head = store.mint();
    store.heads.insert(
        repeat.source_session_id.clone(),
        (head, snapshot_upload_body_witness(&repeat)),
    );
    let items = [
        patched.clone(),
        birth.clone(),
        empty.clone(),
        cap.clone(),
        partial.clone(),
        repeat.clone(),
    ];
    let bases = items
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                progress
                    .accepted_cache_heads
                    .get(&cache_session_key(&item.source_session_id))
                    .cloned(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    // Before the split: one patched sibling made the whole request CAS and
    // the base-less unpatched body conflicted with a challenge.
    let mut before = progress.clone();
    let mut old_store = store.clone();
    let (result, wires) = page_with_class(
        &mut before,
        &items,
        &none,
        |_| 0,
        |request, wire| Ok(old_store.post(request, wire)),
    );
    assert_eq!(wires.len(), 1);
    assert!(wires[0]["head_cas_contract"].is_string());
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert!(before
        .head_conflict_challenges
        .contains_key(&cache_session_key("m1-birth-withheld")));

    let (result, wires) = page(&mut progress, &items, &none, |request, wire| {
        Ok(store.post(request, wire))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(wires.len(), 2, "one request per class");
    assert!(wires[0].get("head_cas_contract").is_none());
    assert!(wires[1]["head_cas_contract"].is_string());
    let mut ordinary = sessions(&wires[0]);
    ordinary.sort();
    assert_eq!(
        ordinary,
        ["m1-birth-withheld", "m1-cap-withheld", "m1-exact-repeat"]
    );
    let mut cas = sessions(&wires[1]);
    cas.sort();
    assert_eq!(cas, ["m1-admitted-empty", "m1-partial-empty", "m1-patched"]);
    for (index, wire) in wires.iter().enumerate() {
        for sent in wire["snapshots"].as_array().unwrap() {
            let session = sent["source_session_id"].as_str().unwrap();
            let item = items
                .iter()
                .find(|item| item.source_session_id == session)
                .unwrap();
            let envelope = &sent["semantic_envelope"];
            assert!(envelope.get("conflict_head_challenge").is_none());
            // Only the entity's own saved base, never a borrowed token.
            assert_eq!(
                envelope.get("base_head_etag").and_then(Value::as_str),
                bases[session].as_deref(),
                "{session}"
            );
            // [money] Exact cache event sets: the patch whole, or none.
            assert_eq!(
                sent.get("cache_observations")
                    .filter(|value| !value.is_null()),
                item.cache_observations
                    .as_ref()
                    .map(|patch| serde_json::to_value(patch).unwrap())
                    .as_ref(),
                "{session}"
            );
            assert_eq!(item.cache_observations.is_some(), index == 1, "{session}");
        }
    }
    assert!(progress.head_conflict_challenges.is_empty(), "no conflict");
    for item in &items {
        assert_eq!(
            progress
                .accepted_body_witnesses
                .get(&item.snapshot_fingerprint),
            Some(&snapshot_upload_body_witness(item)),
            "{}",
            item.source_session_id
        );
    }
    let mut stored = store.stored.clone();
    stored.sort();
    assert_eq!(
        stored,
        [
            "m1-admitted-empty",
            "m1-birth-withheld",
            "m1-cap-withheld",
            "m1-partial-empty",
            "m1-patched"
        ],
        "the exact repeat is not stored again"
    );
    for item in [&patched, &empty, &partial] {
        assert_eq!(
            progress.accepted_cache_heads[&cache_session_key(&item.source_session_id)],
            store.heads[&item.source_session_id].0
        );
    }
    // R5: the ordinary ACK has no etag, so the cap-withheld session's saved
    // token is dropped; a later patch for it re-bootstraps through a probe.
    for item in [&birth, &cap, &repeat] {
        assert!(!progress
            .accepted_cache_heads
            .contains_key(&cache_session_key(&item.source_session_id)));
    }

    // E2: a single-class page sends the same bytes as before the split.
    let single = [
        body("e2-patched", Some(item().cache_observations.unwrap())),
        body("e2-admitted-empty", Some(complete_empty())),
    ];
    let (result, now) = page(&mut fresh_progress(), &single, &none, |request, wire| {
        Ok(HeadStore::default().post(request, wire))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    let (result, previous) = page_with_class(
        &mut fresh_progress(),
        &single,
        &none,
        |_| 0,
        |request, wire| Ok(HeadStore::default().post(request, wire)),
    );
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(now, previous);
}

/// [money] R1: the observed seed (challenge, no base or state, no attempt)
/// with a no-patch offer beside a patched sibling. The owed session reads a
/// native Full, goes out in an ordinary request, is accepted, and its exact
/// ACK clears the challenge without an answer. A restart keeps it clear.
#[test]
fn observed_unanswered_challenge_clears_through_an_ordinary_accept() {
    let none = BTreeSet::new();
    let mut store = HeadStore::default();
    let mut progress = fresh_progress();
    let owed = body("r1-owed", None);
    let sibling = body(
        "r1-patched-sibling",
        Some(item().cache_observations.unwrap()),
    );
    store.seed("r1-owed");
    let head = store.seed("r1-patched-sibling");
    progress
        .accepted_cache_heads
        .insert(cache_session_key("r1-patched-sibling"), head);
    let key = cache_session_key("r1-owed");
    owe(&mut progress, &owed, challenge(0xc));
    assert!(
        mirrored(&progress, &key),
        "the owed session reads a native Full"
    );

    let (result, wires) = page(
        &mut progress,
        &[owed.clone(), sibling.clone()],
        &none,
        |request, wire| Ok(store.post(request, wire)),
    );
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(wires.len(), 2);
    assert!(wires[0].get("head_cas_contract").is_none());
    assert_eq!(sessions(&wires[0]), ["r1-owed"]);
    let envelope = envelope(&wires[0]);
    for field in [
        "base_head_etag",
        "conflict_head_challenge",
        "rescan_from_revision_hash",
        "forced_full_rescan",
    ] {
        assert!(envelope.get(field).is_none(), "{field}");
    }
    assert!(
        progress.head_conflict_challenges.is_empty(),
        "cleared by the accept, never answered"
    );
    assert_eq!(
        progress.accepted_body_witnesses[&owed.snapshot_fingerprint],
        snapshot_upload_body_witness(&owed),
        "exact receipt"
    );
    assert!(!progress.accepted_cache_heads.contains_key(&key));
    assert_eq!(store.stored, ["r1-owed", "r1-patched-sibling"]);
    assert!(!mirrored(&progress, &key));

    let root = crate::test_scratch::ScratchDir::new("class-split-restart");
    let path = root.join("upload-progress.json");
    progress.generation = 0;
    progress.save(&path).unwrap();
    let restarted = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert!(restarted.head_conflict_challenges.is_empty());
    assert_eq!(
        restarted.accepted_body_witnesses,
        progress.accepted_body_witnesses
    );
    assert!(!mirrored(&restarted, &key));
}

/// [money] R2: the same seed when the session regains a patch, including a
/// partial-empty one. The existing ordinary bootstrap probe's ACK clears the
/// challenge, its exact CAS repeat saves the head, and the patched main offer
/// declares CAS with that base and carries its whole patch.
#[test]
fn a_session_that_regains_a_patch_clears_through_the_ordinary_bootstrap() {
    let none = BTreeSet::new();
    for regained in [
        item().cache_observations.unwrap(),
        CacheObservations::partial(Some(2)),
    ] {
        let mut store = HeadStore::default();
        let mut progress = fresh_progress();
        let item = body("r2-owed", Some(regained.clone()));
        let key = cache_session_key("r2-owed");
        store.seed("r2-owed");
        owe(&mut progress, &item, challenge(0xc));

        let probes = vec![cache_head_probe(&item)];
        let mut probe_wires = Vec::new();
        let deferred = bootstrap_cache_heads(
            &probes,
            SCOPE,
            &mut progress,
            true,
            |batch, enforce_head_cas| {
                let request = request(batch);
                let wire = if enforce_head_cas {
                    serde_json::to_value(request.wire_with_head_cas())?
                } else {
                    serde_json::to_value(&request)?
                };
                probe_wires.push(wire.clone());
                let mut response = store.post(&request, &wire);
                response.validate_entity_ack_with_head_cas(&request, enforce_head_cas)?;
                response.bind_conflict_rescans(&request);
                Ok(response)
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(deferred, 0);
        assert_eq!(probe_wires.len(), 2, "ordinary probe, then its CAS repeat");
        assert!(probe_wires[0].get("head_cas_contract").is_none());
        assert!(probe_wires[1]["head_cas_contract"].is_string());
        assert!(progress.head_conflict_challenges.is_empty());
        let head = progress.accepted_cache_heads[&key].clone();
        assert_eq!(head, store.heads["r2-owed"].0);

        let mut items = vec![item.clone()];
        assert_eq!(
            apply_bootstrapped_cache_heads(&mut items, &progress).unwrap(),
            0
        );
        assert_eq!(
            items[0].cache_base_head_etag.as_deref(),
            Some(head.as_str())
        );
        let (result, wires) = page(&mut progress, &items, &none, |request, wire| {
            Ok(store.post(request, wire))
        });
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(wires.len(), 1);
        assert!(wires[0]["head_cas_contract"].is_string());
        let sent = &wires[0]["snapshots"][0];
        assert_eq!(sent["semantic_envelope"]["base_head_etag"], head);
        assert!(sent["semantic_envelope"]
            .get("conflict_head_challenge")
            .is_none());
        assert_eq!(
            sent["cache_observations"],
            serde_json::to_value(&regained).unwrap(),
            "no accepted cache rows lost"
        );
        assert_eq!(
            progress.accepted_cache_heads[&key],
            store.heads["r2-owed"].0
        );
        assert!(progress.head_conflict_challenges.is_empty());
    }
}

/// [money] R3: a lost ACK keeps the debt; the replay is an exact repeat
/// (unchanged, no second store); a repeat pass sends no POST; a fresh
/// challenge from a later CAS conflict is recorded and cleared again by the
/// next ordinary accept.
#[test]
fn lost_ack_replays_unchanged_and_a_fresh_challenge_clears_again() {
    let none = BTreeSet::new();
    let mut store = HeadStore::default();
    let mut progress = fresh_progress();
    let owed = body("r3-owed", None);
    let key = cache_session_key("r3-owed");
    store.seed("r3-owed");
    owe(&mut progress, &owed, challenge(0xc));

    let (lost, _) = page(
        &mut progress,
        std::slice::from_ref(&owed),
        &none,
        |request, wire| {
            store.post(request, wire);
            Err(anyhow!("synthetic lost reply"))
        },
    );
    assert!(lost.is_err());
    assert!(progress.head_conflict_challenges.contains_key(&key));
    assert!(!progress
        .accepted_body_witnesses
        .contains_key(&owed.snapshot_fingerprint));

    let (result, _) = page(
        &mut progress,
        std::slice::from_ref(&owed),
        &none,
        |request, wire| Ok(store.post(request, wire)),
    );
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert!(progress.head_conflict_challenges.is_empty());
    assert_eq!(store.stored, ["r3-owed"], "no double credit");

    // A repeat pass sends no POST: the packer skips an exact settled body.
    // (`page` forces a retry of every item, so ask the packer's predicate.)
    assert!(progress.contains_body(
        &owed.snapshot_fingerprint,
        &snapshot_upload_body_witness(&owed)
    ));

    // A later patched revision under a stale saved base conflicts under CAS.
    let mut patched = revised(&owed, 1);
    patched.cache_observations = item().cache_observations;
    patched.cache_observations_state = item().cache_observations_state;
    patched.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &patched);
    progress
        .accepted_cache_heads
        .insert(key.clone(), stale_head());
    let (result, wires) = page(&mut progress, &[patched], &none, |request, wire| {
        Ok(store.post(request, wire))
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert!(wires[0]["head_cas_contract"].is_string());
    assert_eq!(
        progress.head_conflict_challenges[&key].challenge,
        store.challenges["r3-owed"]
    );
    // The next unpatched revision goes ordinary, is accepted, and clears it.
    let next = revised(&owed, 2);
    let (result, wires) = page(&mut progress, &[next], &none, |request, wire| {
        Ok(store.post(request, wire))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert!(wires[0].get("head_cas_contract").is_none());
    assert!(progress.head_conflict_challenges.is_empty());
    assert!(!progress.accepted_cache_heads.contains_key(&key));
    assert_eq!(store.stored, ["r3-owed", "r3-owed"]);
}

/// [money] R4: fence outcomes for the owed session's ordinary body. A covered
/// older or other authority downgrade is a permanent rejection: the
/// challenge clears and the body is held with no receipt. Mixed usage is
/// retryable: the challenge stays and the page is Deferred. A dominated
/// re-offer is unchanged with a basis: the challenge clears, the body is
/// held, no receipt. No saved head is created or lowered.
#[test]
fn ordinary_fence_outcomes_settle_the_owed_challenge_by_their_own_rules() {
    let none = BTreeSet::new();
    for (outcome, permanent) in [
        ("accepted_log_stale_older_upload", Some(true)),
        ("usage_accounting_authority_downgrade", Some(true)),
        ("accepted_log_stale_older_mixed", Some(false)),
        ("dominated_by_head", None),
    ] {
        let mut progress = fresh_progress();
        let owed = body("r4-owed", None);
        let key = cache_session_key("r4-owed");
        owe(&mut progress, &owed, challenge(0xc));
        let (result, wires) = page(
            &mut progress,
            std::slice::from_ref(&owed),
            &none,
            |request, _| {
                let item = &request.snapshots[0];
                let mut ack = empty_ack();
                match permanent {
                    Some(permanent) => {
                        ack.rejected_entities.push(
                            crate::snapshot_client::SnapshotEntityRejection {
                                source_session_id: item.source_session_id.clone(),
                                snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                                occurrence_count: 1,
                                permanent,
                                reason: outcome.into(),
                                detail: String::new(),
                            },
                        );
                    }
                    None => {
                        let version =
                            crate::snapshot_client::snapshot_ack_body_witness_version(item)
                                .unwrap();
                        ack.accepted = 1;
                        ack.unchanged_entities.push(SnapshotEntityRef {
                            body_witness_version: version,
                            body_witness_digest: version
                                .map(|_| snapshot_upload_body_witness(item)),
                            unchanged_basis: Some(outcome.into()),
                            ..reference(item)
                        });
                    }
                }
                Ok(ack)
            },
        );
        assert!(wires[0].get("head_cas_contract").is_none(), "{outcome}");
        let result = result.unwrap();
        let retryable = permanent == Some(false);
        assert_eq!(
            progress.head_conflict_challenges.contains_key(&key),
            retryable,
            "{outcome}"
        );
        if retryable {
            assert!(
                matches!(result, ResumableUploadResult::Deferred { .. }),
                "{outcome}: {result:?}"
            );
            assert_eq!(progress.head_conflict_challenges[&key].answer_attempts, 0);
        }
        assert!(
            progress.accepted_body_witnesses.is_empty(),
            "{outcome}: no receipt"
        );
        assert!(
            progress
                .quarantined_fingerprints
                .contains_key(&owed.snapshot_fingerprint),
            "{outcome}: held"
        );
        assert!(progress.accepted_cache_heads.is_empty(), "{outcome}");
    }
}

/// [money] N1: negative controls. A legacy reconciliation stays CAS and alone
/// in its request. A route that enforces CAS on every request refuses the
/// base-less changed body with a plain conflict: the debt stays and no
/// answer is sent (the trigger for an answer-gate change, not this one).
#[test]
fn legacy_stays_isolated_and_a_mandatory_route_keeps_the_debt() {
    let mut store = HeadStore::default();
    let mut progress = fresh_progress();
    let legacy_item = body("n1-legacy", None);
    let ordinary = body("n1-ordinary", None);
    let patched = body("n1-patched", Some(item().cache_observations.unwrap()));
    for item in [&legacy_item, &patched] {
        let head = store.seed(&item.source_session_id);
        progress
            .accepted_cache_heads
            .insert(cache_session_key(&item.source_session_id), head);
    }
    let legacy = BTreeSet::from([legacy_item.snapshot_fingerprint.clone()]);
    let (result, wires) = page(
        &mut progress,
        &[legacy_item, ordinary, patched],
        &legacy,
        |request, wire| Ok(store.post(request, wire)),
    );
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    let shape = wires
        .iter()
        .map(|wire| (wire["head_cas_contract"].is_string(), sessions(wire)))
        .collect::<Vec<_>>();
    assert_eq!(
        shape,
        [
            (false, vec!["n1-ordinary".to_owned()]),
            (true, vec!["n1-patched".to_owned()]),
            (true, vec!["n1-legacy".to_owned()]),
        ]
    );

    let mut progress = fresh_progress();
    let owed = body("n1-mandatory", None);
    let key = cache_session_key("n1-mandatory");
    owe(&mut progress, &owed, challenge(0xc));
    let (result, wires) = page(&mut progress, &[owed], &BTreeSet::new(), |request, _| {
        let mut ack = empty_ack();
        ack.conflict_entities.push(reference(&request.snapshots[0]));
        Ok(ack)
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert!(wires[0].get("head_cas_contract").is_none());
    assert!(envelope(&wires[0]).get("conflict_head_challenge").is_none());
    let record = &progress.head_conflict_challenges[&key];
    assert_eq!(record.challenge, challenge(0xc), "the debt stays");
    assert_eq!(record.answer_attempts, 0);
}
