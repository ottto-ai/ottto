// Ledger-level controls for the reason-scoped refusal re-offer: the bounded
// isolating decoder, the old-reader disk form, shared-budget selection, exact
// witness binding and crash ordering. Synthetic hashes only.
use super::*;

const DAY: u64 = 86_400;
const NOW: u64 = 2_000_000_000;

fn fp(value: usize) -> String {
    format!("{value:064x}")
}

fn body(value: usize) -> String {
    format!("{:064x}", value + 0xb0d1)
}

fn ledger() -> SnapshotUploadProgress {
    SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
}

fn terminal_record(body: &str) -> SnapshotQuarantineRecord {
    SnapshotQuarantineRecord {
        witness: snapshot_quarantine_witness(SnapshotSource::Codex),
        retry_after_unix_seconds: 0,
        upload_body_witness: Some(body.to_string()),
        failed_reconstruction_count: MAX_SNAPSHOT_RECONSTRUCTION_FAILURES,
        disposition: SnapshotQuarantineDisposition::UnprovenTerminal,
    }
}

/// A committed index in which every refusal is current and bound to its
/// exact terminal record, and the matching ledger.
fn refused(
    entities: &[(usize, Option<reason_reoffer::RefusalReoffer>)],
) -> (SnapshotUploadProgress, ScanIndex) {
    let mut index = ScanIndex::default();
    index.generation = 7;
    let mut progress = ledger();
    for (value, reoffer) in entities {
        let key = format!("/opaque/{value}.jsonl");
        index
            .file_snapshot_fingerprints
            .insert(key, BTreeSet::from([fp(*value)]));
        index
            .quarantined_snapshot_fingerprints
            .insert(fp(*value), terminal_record(&body(*value)));
        progress.permanent_rejections.insert(
            fp(*value),
            PermanentSnapshotRejection {
                body_witness: body(*value),
                reason: crate::upload_receipts::RejectedUsageReason::Other,
                reoffer: *reoffer,
            },
        );
    }
    (progress, index)
}

fn original_pair(retry_after_unix_seconds: u64) -> Option<reason_reoffer::RefusalReoffer> {
    Some(reason_reoffer::RefusalReoffer::OriginalPair {
        retry_after_unix_seconds,
    })
}

fn select(progress: &mut SnapshotUploadProgress, index: &ScanIndex, now: u64) -> bool {
    let scope = reason_reoffer::Scope {
        index,
        now,
        window_start_unix_seconds: now - 183 * DAY,
    };
    progress.prepare_quarantine_and_reason_retries(
        &index.quarantined_snapshot_fingerprints,
        Some(&scope),
    )
}

fn decode(reoffer: &str) -> Option<reason_reoffer::RefusalReoffer> {
    let json = format!(
        r#"{{"body_witness":"{}","reason":"other","reoffer":{reoffer}}}"#,
        "b".repeat(64)
    );
    let record: PermanentSnapshotRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(record.body_witness, "b".repeat(64), "{reoffer}");
    assert_eq!(
        record.reason,
        crate::upload_receipts::RejectedUsageReason::Other
    );
    record.reoffer
}

/// R10: only an exact version-1 extension qualifies; everything else
/// disables this record's retry while the refusal itself survives.
#[test]
fn reoffer_decoder_is_bounded_and_isolating() {
    use reason_reoffer::RefusalReoffer;
    let json = format!(
        r#"{{"body_witness":"{}","reason":"other"}}"#,
        "b".repeat(64)
    );
    let record: PermanentSnapshotRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(record.reoffer, None, "legacy record");
    assert_eq!(decode("null"), None);
    assert_eq!(
        decode(
            r#"{"version":1,"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5}"#
        ),
        original_pair(5)
    );
    assert_eq!(
        decode(
            r#"{"version":1,"reason":"legacy_other_reclassification","retry_after_unix_seconds":9}"#
        ),
        Some(RefusalReoffer::LegacyOther {
            retry_after_unix_seconds: 9
        })
    );
    assert_eq!(
        decode(r#"{"version":1,"reason":"classified"}"#),
        Some(RefusalReoffer::Classified)
    );
    // Unknown bounded members are skipped.
    assert_eq!(
        decode(
            r#"{"version":1,"note":[1,{"a":null}],"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5}"#
        ),
        original_pair(5)
    );
    let long = "x".repeat(65);
    let huge = "y".repeat(1 << 20);
    let deep = format!("{}1{}", "[".repeat(12), "]".repeat(12));
    let wide = (0..1_000)
        .map(|index| format!(r#""k{index}":{index}"#))
        .collect::<Vec<_>>()
        .join(",");
    for hostile in [
        "true".to_string(),
        "5".to_string(),
        "-1".to_string(),
        "1.5".to_string(),
        r#""original_pair_candidate_unproved""#.to_string(),
        "[1,2]".to_string(),
        "{}".to_string(),
        r#"{"version":2,"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5}"#.to_string(),
        r#"{"version":"1","reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5}"#.to_string(),
        r#"{"version":1,"reason":"accepted","retry_after_unix_seconds":5}"#.to_string(),
        r#"{"version":1,"reason":"original_pair_candidate_unproved"}"#.to_string(),
        r#"{"version":1,"reason":"classified","retry_after_unix_seconds":5}"#.to_string(),
        r#"{"version":1,"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":-5}"#.to_string(),
        r#"{"version":1,"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5.5}"#.to_string(),
        r#"{"version":1,"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":"5"}"#.to_string(),
        r#"{"version":1,"version":1,"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5}"#.to_string(),
        format!(r#"{{"version":1,"reason":"{long}","retry_after_unix_seconds":5}}"#),
        format!(r#"{{"version":1,"{long}":1,"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5}}"#),
        format!(r#"{{"version":1,"note":"{huge}","reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5}}"#),
        format!(r#"{{"version":1,"note":{deep},"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5}}"#),
        format!(r#"{{"version":1,{wide},"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5}}"#),
        format!(r#"{{"version":1,"reason":"original_pair_candidate_unproved","retry_after_unix_seconds":5,"note":{{"a":[{huge:?}]}}}}"#),
    ] {
        assert_eq!(
            decode(&hostile),
            Some(RefusalReoffer::Classified),
            "{}",
            &hostile[..hostile.len().min(120)]
        );
    }
}

/// R10: a malformed extension never resets the ledger. Load keeps the
/// accepted sibling, the refusal and its terminal disclosure.
#[test]
fn malformed_reoffer_extension_keeps_every_sibling_on_load() {
    let root = test_dir("reoffer-malformed-load");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("progress.json");
    let mut progress = ledger();
    progress.record_body(&fp(1), &body(1));
    progress.quarantine_permanent_body(&fp(2), &body(2), "original_pair_candidate_unproved");
    progress.save(&path).unwrap();
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json["permanent_rejections"][fp(2)]["reoffer"] =
        serde_json::json!({"version": 1, "reason": vec!["x"; 40], "retry_after_unix_seconds": 1});
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    let loaded = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert!(loaded.accepted_fingerprints.contains(&fp(1)));
    assert_eq!(loaded.accepted_body_witnesses[&fp(1)], body(1));
    assert_eq!(loaded.permanent_rejections[&fp(2)].body_witness, body(2));
    assert_eq!(
        loaded.permanent_rejections[&fp(2)].reoffer,
        Some(reason_reoffer::RefusalReoffer::Classified)
    );
    assert!(loaded.contains_body(&fp(2), &body(2)), "suppression kept");
    let _ = std::fs::remove_dir_all(root);
}

/// R9: a frozen pre-change reader reads newly written records: the new
/// reason keeps the old enum value, the extension is ignored, siblings and
/// the receipt reason survive. An old rewrite drops the extension, which
/// leaves a legacy record (one idempotent re-classification offer).
#[test]
fn old_daemon_reads_new_refusal_records_and_receipt_reason() {
    #[derive(Debug, Serialize, Deserialize)]
    struct OldPermanentSnapshotRejection {
        body_witness: String,
        reason: crate::upload_receipts::RejectedUsageReason,
    }
    #[derive(Debug, Serialize, Deserialize)]
    struct OldProgress {
        schema_version: u16,
        generation: u64,
        destination_namespace_hash: String,
        accepted_fingerprints: BTreeSet<String>,
        accepted_body_witnesses: BTreeMap<String, String>,
        #[serde(default)]
        permanent_rejections: BTreeMap<String, OldPermanentSnapshotRejection>,
    }
    let mut progress = ledger();
    progress.record_body(&fp(1), &body(1));
    progress.quarantine_permanent_body(&fp(2), &body(2), "original_pair_candidate_unproved");
    progress.quarantine_permanent_body(&fp(3), &body(3), "future_private_reason");
    progress.quarantine_permanent_body(&fp(4), &body(4), "body_exceeds_max_bytes");
    let written = serde_json::to_value(&progress).unwrap();
    assert_eq!(written["permanent_rejections"][fp(2)]["reason"], "other");
    assert_eq!(
        written["permanent_rejections"][fp(2)]["reoffer"]["reason"],
        "original_pair_candidate_unproved"
    );
    assert_eq!(
        written["permanent_rejections"][fp(3)]["reoffer"]["reason"],
        "classified",
        "a fresh server `other` is already classified: no legacy pass"
    );
    assert!(
        written["permanent_rejections"][fp(4)]
            .get("reoffer")
            .is_none(),
        "known reasons keep their old record byte-for-byte"
    );
    let old: OldProgress = serde_json::from_value(written).unwrap();
    assert_eq!(old.schema_version, SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION);
    assert_eq!(old.generation, 0);
    assert_eq!(old.destination_namespace_hash, "a".repeat(64));
    assert!(old.accepted_fingerprints.contains(&fp(1)));
    assert_eq!(old.accepted_body_witnesses[&fp(1)], body(1));
    for value in [2, 3] {
        assert_eq!(
            old.permanent_rejections[&fp(value)].reason,
            crate::upload_receipts::RejectedUsageReason::Other
        );
        assert_eq!(
            old.permanent_rejections[&fp(value)].body_witness,
            body(value)
        );
    }
    // Old rewrite, then upgrade again: the identity cannot be recovered.
    let rewritten: PermanentSnapshotRejection =
        serde_json::from_value(serde_json::to_value(&old.permanent_rejections[&fp(2)]).unwrap())
            .unwrap();
    assert_eq!(rewritten.reoffer, None);

    // The private receipt ring keeps the old vocabulary too.
    let rejection = crate::snapshot_client::SnapshotEntityRejection {
        source_session_id: "synthetic".into(),
        snapshot_fingerprint: fp(2),
        reason: "original_pair_candidate_unproved".into(),
        detail: "private detail".into(),
        permanent: true,
        occurrence_count: 1,
    };
    assert_eq!(rejection.safe_reason(), "original_pair_candidate_unproved");
    let receipt_reason =
        crate::upload_receipts::RejectedUsageReason::from_wire(rejection.safe_reason());
    assert_eq!(
        receipt_reason,
        crate::upload_receipts::RejectedUsageReason::Other
    );
    assert_eq!(serde_json::to_value(receipt_reason).unwrap(), "other");
    assert!(!receipt_reason.is_dominated());
}

/// R3: due re-offers and ordinary retries share one 50-slot budget, oldest
/// deadline first; the remainder is deferred and counted, its deadline
/// untouched. A selected re-offer reserves now + 24 h.
#[test]
fn reoffers_share_the_ordinary_retry_budget_oldest_first() {
    let mut entities = (0..60)
        .map(|value| (value, original_pair(NOW - 1_000 + value as u64)))
        .collect::<Vec<_>>();
    // Legacy records are due since forever.
    entities.push((100, None));
    let (mut progress, mut index) = refused(&entities);
    // Ten ordinary retries due before every re-offer.
    for value in 200..210 {
        let mut record = terminal_record(&body(value));
        record.disposition = SnapshotQuarantineDisposition::RetryPending;
        record.failed_reconstruction_count = 1;
        record.retry_after_unix_seconds = 1;
        index
            .quarantined_snapshot_fingerprints
            .insert(fp(value), record);
    }
    assert!(select(&mut progress, &index, NOW));
    assert_eq!(progress.active_quarantine_retries.len(), 10);
    assert_eq!(progress.active_reason_reoffers.len(), 40);
    assert!(progress.active_reason_reoffers.contains_key(&fp(100)));
    for value in 0..39 {
        assert_eq!(progress.active_reason_reoffers[&fp(value)], body(value));
        assert_eq!(
            progress.permanent_rejections[&fp(value)].reoffer,
            original_pair(NOW + DAY),
            "reserved before any lease is used"
        );
    }
    for value in 39..60 {
        assert!(!progress.active_reason_reoffers.contains_key(&fp(value)));
        assert_eq!(
            progress.permanent_rejections[&fp(value)].reoffer,
            original_pair(NOW - 1_000 + value as u64)
        );
    }
    assert_eq!(
        progress.permanent_rejections[&fp(100)].reoffer,
        Some(reason_reoffer::RefusalReoffer::LegacyOther {
            retry_after_unix_seconds: NOW + DAY
        })
    );
    let counts = progress.reason_reoffer_counts;
    assert_eq!(counts.due, 61);
    assert_eq!(counts.selected, 40);
    assert_eq!(counts.legacy_selected, 1);
    assert_eq!(counts.deferred_budget, 21);

    // The deferred remainder is the oldest work of the next cycle.
    assert!(select(&mut progress, &index, NOW + 300));
    assert_eq!(progress.active_reason_reoffers.len(), 21);
    assert!((39..60).all(|value| progress.active_reason_reoffers.contains_key(&fp(value))));
}

/// R4/R5/R11: only a due, current, unaccepted refusal bound to its exact
/// terminal record qualifies; other reasons, done markers, changed
/// witnesses, superseded or out-of-window records never do.
#[test]
fn only_exactly_bound_current_due_refusals_are_reoffered() {
    use reason_reoffer::RefusalReoffer;
    let (mut progress, mut index) = refused(&[
        (1, original_pair(NOW)),
        (2, original_pair(NOW + 1)),
        (3, Some(RefusalReoffer::Classified)),
        (4, original_pair(0)),
        (5, original_pair(0)),
        (6, original_pair(0)),
        (7, original_pair(0)),
        (8, original_pair(0)),
        (9, original_pair(NOW + DAY + 601)),
        (10, original_pair(NOW + DAY + 600)),
    ]);
    progress
        .permanent_rejections
        .get_mut(&fp(4))
        .unwrap()
        .reason = crate::upload_receipts::RejectedUsageReason::BodyExceedsMaxBytes;
    // Changed witness: the terminal record holds body B, not the refused A.
    index
        .quarantined_snapshot_fingerprints
        .insert(fp(5), terminal_record(&body(500)));
    index
        .quarantined_snapshot_fingerprints
        .get_mut(&fp(6))
        .unwrap()
        .disposition = SnapshotQuarantineDisposition::SupersededTerminal;
    // An exact durable ACK beats the stale refusal.
    progress.accepted_fingerprints.insert(fp(7));
    index
        .snapshot_activity_at
        .insert(fp(8), Some("2020-01-01T00:00:00Z".into()));
    assert!(select(&mut progress, &index, NOW));
    assert_eq!(
        progress
            .active_reason_reoffers
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec![fp(1)],
        "only the exactly bound due record"
    );
    assert_eq!(progress.reason_reoffer_counts.outside_policy_window, 1);
    assert_eq!(
        progress.permanent_rejections[&fp(9)].reoffer,
        original_pair(NOW + DAY),
        "a deadline past the clock bound is re-clamped, never classified"
    );
    assert_eq!(
        progress.permanent_rejections[&fp(10)].reoffer,
        original_pair(NOW + DAY + 600),
        "inside the clock tolerance: kept, not yet due"
    );
    assert!(progress.contains_body(&fp(9), &body(9)), "suppression kept");

    // Not current, or a missing index: nothing.
    let (mut progress, mut index) = refused(&[(1, original_pair(0))]);
    index.file_snapshot_fingerprints.clear();
    assert!(!select(&mut progress, &index, NOW));
    let (mut progress, mut index) = refused(&[(1, original_pair(0))]);
    index.generation = 0;
    assert!(!select(&mut progress, &index, NOW));
    assert!(progress.active_reason_reoffers.is_empty());
}

/// R5: the lease passes suppression for its exact body only, once per
/// logical offer; another body of the entity keeps normal logic.
#[test]
fn reoffer_lease_is_bound_to_the_exact_refused_body() {
    let (mut progress, index) = refused(&[(1, original_pair(0))]);
    progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    assert!(progress.contains_body(&fp(1), &body(1)));
    assert!(select(&mut progress, &index, NOW));
    assert!(
        !progress.contains_body(&fp(1), &body(1)),
        "exact lease passes"
    );
    assert!(
        !progress.contains_body(&fp(1), &body(2)),
        "a changed body is new work under the normal rules"
    );
    // A repeat refusal consumes the lease and restarts the clock.
    progress.quarantine_permanent_body(&fp(1), &body(1), "original_pair_candidate_unproved");
    assert!(progress.contains_body(&fp(1), &body(1)));
    assert!(progress.active_reason_reoffers.is_empty());
    // A changed body refused for another reason drops the schedule.
    progress.quarantine_permanent_body(&fp(1), &body(2), "body_exceeds_max_bytes");
    assert_eq!(progress.permanent_rejections[&fp(1)].reoffer, None);
    assert!(progress.contains_body(&fp(1), &body(2)));
    assert!(!progress.contains_body(&fp(1), &body(1)));
}

/// R6: the reservation is durable before any lease is used. A failed save
/// grants nothing; a crash after the claim cannot re-offer within the day.
#[test]
fn reoffer_reservation_survives_restart_and_failed_save_grants_nothing() {
    let root = test_dir("reoffer-restart");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("progress.json");
    let (mut progress, index) = refused(&[(1, original_pair(0))]);
    progress.save(&path).unwrap();

    // A concurrent writer wins the CAS: the claim save fails.
    let mut competitor = progress.clone();
    competitor.save(&path).unwrap();
    let mut stale = progress.clone();
    assert!(select(&mut stale, &index, NOW));
    assert!(stale.save(&path).is_err());
    let reloaded = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert!(reloaded.active_reason_reoffers.is_empty());
    assert_eq!(
        reloaded.permanent_rejections[&fp(1)].reoffer,
        original_pair(0)
    );

    // A successful claim, then a crash before or after POST.
    let mut claimed = reloaded;
    assert!(select(&mut claimed, &index, NOW));
    claimed.save(&path).unwrap();
    drop(claimed);
    let mut restarted = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert!(
        restarted.active_reason_reoffers.is_empty(),
        "leases are runtime"
    );
    assert!(!select(&mut restarted, &index, NOW + 300));
    assert!(restarted.active_reason_reoffers.is_empty());
    assert!(restarted.contains_body(&fp(1), &body(1)));
    assert!(select(&mut restarted, &index, NOW + DAY));
    assert_eq!(restarted.active_reason_reoffers.len(), 1);
    let _ = std::fs::remove_dir_all(root);
}

/// R8/I-R2: a lease that reaches no validated response keeps the refusal
/// and its cooldown and is reported as failed, not as a refusal.
#[test]
fn unanswered_reoffer_keeps_refusal_and_counts_failure() {
    let (mut progress, index) = refused(&[(1, original_pair(0)), (2, original_pair(0))]);
    assert!(select(&mut progress, &index, NOW));
    let attempted = progress.active_reason_reoffers.clone();
    progress
        .attempted_reason_reoffers
        .extend(attempted.keys().cloned());
    progress.record_body(&fp(2), &body(2));
    progress.finish_reason_reoffers(&attempted, false, SnapshotSource::Codex);
    let counts = progress.reason_reoffer_counts;
    assert_eq!((counts.failed, counts.accepted), (1, 1));
    assert!(progress.active_reason_reoffers.is_empty());
    assert!(progress.contains_body(&fp(1), &body(1)));
    assert_eq!(
        progress.permanent_rejections[&fp(1)].reoffer,
        original_pair(NOW + DAY)
    );
    assert!(!progress.permanent_rejections.contains_key(&fp(2)));
}

/// F2: injected wall-clock rollback keeps both kinds eligible after a full
/// cooldown; a save/reload must not turn either into the permanent done marker.
#[test]
fn clock_rollback_reclamps_and_skips_without_consuming_classification() {
    use reason_reoffer::RefusalReoffer;
    let fast_clock = NOW + 3_600;
    let (mut progress, index) = refused(&[
        (1, original_pair(fast_clock + DAY)),
        (
            2,
            Some(RefusalReoffer::LegacyOther {
                retry_after_unix_seconds: fast_clock + DAY,
            }),
        ),
    ]);
    assert!(select(&mut progress, &index, NOW));
    assert_eq!(progress.reason_reoffer_counts.clock_bound_skipped, 2);
    assert!(progress.active_reason_reoffers.is_empty());
    assert_eq!(
        progress.permanent_rejections[&fp(1)].reoffer,
        original_pair(NOW + DAY)
    );
    assert_eq!(
        progress.permanent_rejections[&fp(2)].reoffer,
        Some(RefusalReoffer::LegacyOther {
            retry_after_unix_seconds: NOW + DAY
        })
    );
    let mut reloaded: SnapshotUploadProgress =
        serde_json::from_slice(&serde_json::to_vec(&progress).unwrap()).unwrap();
    reloaded.active_quarantine_witness = progress.active_quarantine_witness.clone();
    assert!(!select(&mut reloaded, &index, NOW + DAY - 1));
    assert!(reloaded.contains_body(&fp(1), &body(1)));
    assert!(reloaded.contains_body(&fp(2), &body(2)));
    assert!(select(&mut reloaded, &index, NOW + DAY));
    assert_eq!(reloaded.active_reason_reoffers.len(), 2);
}

/// F8/F9: migration cannot starve ordinary retries or claim two slots for a
/// fingerprint whose ordinary retry and refusal disagree after a crash.
#[test]
fn legacy_pass_uses_at_most_half_the_shared_slots_and_deduplicates() {
    let entities = (0..60).map(|value| (value, None)).collect::<Vec<_>>();
    let (mut progress, mut index) = refused(&entities);
    for value in 200..230 {
        let mut record = terminal_record(&body(value));
        record.disposition = SnapshotQuarantineDisposition::RetryPending;
        record.retry_after_unix_seconds = 1;
        index
            .quarantined_snapshot_fingerprints
            .insert(fp(value), record);
    }
    // The index's A binding is authoritative for the re-offer; progress still
    // contains a newer B retry. It must not spend an additional ordinary slot.
    let mut stale = terminal_record(&body(999));
    stale.disposition = SnapshotQuarantineDisposition::RetryPending;
    stale.retry_after_unix_seconds = 0;
    progress.quarantined_fingerprints.insert(fp(0), stale);
    assert!(select(&mut progress, &index, NOW));
    assert_eq!(progress.reason_reoffer_counts.legacy_selected, 25);
    assert_eq!(progress.active_reason_reoffers.len(), 25);
    assert_eq!(progress.active_quarantine_retries.len(), 25);
    assert!(progress.active_reason_reoffers.contains_key(&fp(0)));
    assert!(!progress.active_quarantine_retries.contains(&fp(0)));
    assert_eq!(progress.reason_reoffer_counts.deferred_budget, 35);
}

#[test]
fn summaries_report_changed_backlogs_and_logical_offer_bytes() {
    use reason_reoffer::{should_log_change, ReofferCounts};
    let empty = ReofferCounts::default();
    assert!(!should_log_change(None, &empty));
    let backlog = ReofferCounts {
        outside_policy_window: 2,
        ..empty
    };
    assert!(should_log_change(Some(empty), &backlog));
    assert!(!should_log_change(Some(backlog), &backlog));
    assert!(should_log_change(Some(backlog), &empty));
    let work = ReofferCounts {
        selected: 1,
        attempted: 1,
        attempted_bytes: 123,
        ..empty
    };
    assert!(should_log_change(Some(work), &work));
    assert!(work
        .line("codex")
        .contains("attempted=1 attempted_bytes=123"));
}

#[test]
fn unsent_leases_are_held_and_conflicts_are_retryable_not_refused() {
    let (mut progress, index) = refused(&[(1, original_pair(0)), (2, original_pair(0))]);
    assert!(select(&mut progress, &index, NOW));
    let leased = progress.active_reason_reoffers.clone();
    progress.attempted_reason_reoffers.insert(fp(2));
    progress.quarantine_retryable_body(&fp(2), &body(2));
    progress.finish_reason_reoffers(&leased, false, SnapshotSource::Codex);
    let counts = progress.reason_reoffer_counts;
    assert_eq!(
        (
            counts.gate_held,
            counts.retryable,
            counts.failed,
            counts.refused_same
        ),
        (1, 1, 0, 0)
    );
}
