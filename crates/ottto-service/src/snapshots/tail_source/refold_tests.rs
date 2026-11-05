//! L02 (D168-3): a late-evidence re-fold from stored state is the body a
//! fresh native read sends now, byte for byte. It goes as an ordinary update,
//! with no rescan claim, counted by its reason (the row is
//! `oracle_tests::differing_stored_body_is_sent_as_the_cold_full_body`). A
//! body waiting on a server retry re-folds too. Stored state that is
//! incomplete for the file, or a session that owes a head-CAS answer, reads
//! natively instead. The scan-level sidecar rows
//! (`claude_tail_money_tests`: `quiet_sidecar_growth`, `side_owner`, ...)
//! compare the same re-fold's upload with a cold Full on real evidence.
use super::super::claude::tests::lines;
use super::super::seam::tests::{route, Route};
use super::settlement_tests::stored_finish;
use super::tests::{append, cold, cold_accumulator, committed, counted, loaded, read};
use super::*;
use crate::snapshots::sampled_jsonl::durable::test_finish_items;
use crate::transcript_acquisition::ReadMode;

/// The late-evidence selections: they re-fold an unchanged transcript.
const LATE: [CandidateParseReason; 5] = [
    CandidateParseReason::SourceChanged,
    CandidateParseReason::Rearmed,
    CandidateParseReason::ForcedFamily,
    CandidateParseReason::AuthorityQuarantine,
    CandidateParseReason::ActivityOrQuarantineRetry,
];

/// Each item's wire body and semantic envelope (component hashes, revision
/// v2, content hash), as serialized bytes.
fn wire(items: &[SnapshotItem]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|item| {
            let mut item = item.clone();
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
            let envelope = snapshot_semantic_envelope(
                SnapshotSource::ClaudeCode,
                &item,
                SnapshotUploadPolicy::default(),
            );
            (
                serde_json::to_string(&item).unwrap(),
                serde_json::to_string(&envelope).unwrap(),
            )
        })
        .collect()
}

/// A fresh native read of `path` now: no stored state, a Full from byte 0.
fn fresh(route: &Route, path: &Path) -> Vec<SnapshotItem> {
    let (parser, mode, start) = read(route, path, None);
    assert!(matches!(mode, ReadMode::Full(_)) && start == 0);
    let (_, native) = route.finish(path, parser, None, |_| {});
    native.unwrap().snapshots
}

/// [money] SOURCE (a), golden: every selection that continues an unchanged
/// file from stored state reads no transcript byte, and its wire bodies and
/// envelopes equal a fresh native read's, byte for byte. A grown file selected
/// by a quarantine retry reads only past the sealed offset, and its body and
/// money fold equal the cold Full's.
#[test]
fn a_refold_is_byte_equal_to_a_fresh_native_read() {
    let mut route = route();
    for (name, responses) in [("short.jsonl", 3), ("paged.jsonl", 300)] {
        let (path, key) = committed(&mut route, name, responses);
        let native = wire(&fresh(&route, &path));
        assert!(!native.is_empty());
        // The reason reaches only eligibility: one re-fold serves them all.
        let unchanged = LATE.into_iter().chain([
            CandidateParseReason::Audit,
            CandidateParseReason::UnknownOutcome,
        ]);
        for reason in unchanged {
            assert!(
                reuses_stored(&route.index, &key, Some(reason), false, false),
                "{reason:?}"
            );
        }
        let (refold, native_bytes) = stored_finish(&route, &path, &key);
        assert_eq!(native_bytes, 0, "{name}");
        assert_eq!(wire(&refold), native, "{name}");
    }

    let (path, key) = committed(&mut route, "grown.jsonl", 300);
    append(&path, 300);
    let retry = Some(CandidateParseReason::ActivityOrQuarantineRetry);
    assert!(reuses_stored(&route.index, &key, retry, true, false));
    let (Load::Reused(taken, Some(base)), _) = loaded(&route, &path, &key) else {
        panic!("the committed head is reused");
    };
    let (parser, mode, _) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Tail));
    let (_, refold) = route.finish(&path, parser, Some(base), |_| {});
    assert_eq!(
        wire(&refold.unwrap().snapshots),
        wire(&fresh(&route, &path))
    );
    let (Load::Reused(taken, _), _) = loaded(&route, &path, &key) else {
        panic!("the committed head is reused");
    };
    let (parser, _, _) = read(&route, &path, Some(taken));
    let money = test_finish_items(parser, &path, SnapshotSource::ClaudeCode);
    assert_eq!(money, cold(&route, &path));
}

/// [money] SOURCE (c): a body that waits on a server retry with no head-CAS
/// answer owed re-folds from stored state for every late-evidence selection:
/// an identity deferral (503), a non-permanent rejection and a refusal
/// re-offer lease each resend the same body, so the re-fold reads no
/// transcript byte and is byte-equal to a fresh native read.
#[test]
fn a_retry_pending_body_refolds_from_tail() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let native = wire(&fresh(&route, &path));
    let fingerprint = "c".repeat(64);
    let body = "d".repeat(64);
    route
        .index
        .file_snapshot_fingerprints
        .insert(key.clone(), [fingerprint.clone()].into());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // The index's view of each kind: the record carries no cause.
    let deferred = SnapshotQuarantineRecord {
        upload_body_witness: Some(body.clone()),
        retry_after_unix_seconds: now,
        ..snapshot_quarantine_record(SnapshotSource::ClaudeCode)
    };
    let rejected = SnapshotQuarantineRecord {
        upload_body_witness: Some(body.clone()),
        ..snapshot_quarantine_record(SnapshotSource::ClaudeCode)
    };
    type Kind = fn(&mut ScanIndex, &str, &SnapshotQuarantineRecord, &SnapshotQuarantineRecord);
    let kinds: [(&str, Kind); 3] = [
        ("identity_deferred", |index, fp, deferred, _| {
            index
                .quarantined_snapshot_fingerprints
                .insert(fp.to_owned(), deferred.clone());
        }),
        ("non_permanent_rejection", |index, fp, _, rejected| {
            index
                .quarantined_snapshot_fingerprints
                .insert(fp.to_owned(), rejected.clone());
        }),
        ("reoffer_lease", |index, fp, _, _| {
            index
                .reason_reoffer_retries
                .insert(fp.to_owned(), "d".repeat(64));
        }),
    ];
    for (kind, setup) in kinds {
        route.index.quarantined_snapshot_fingerprints.clear();
        route.index.reason_reoffer_retries.clear();
        setup(&mut route.index, &fingerprint, &deferred, &rejected);
        for reason in LATE {
            assert!(
                reuses_stored(&route.index, &key, Some(reason), false, false),
                "{kind}: {reason:?}"
            );
        }
        let (refold, native_bytes) = stored_finish(&route, &path, &key);
        assert_eq!(native_bytes, 0, "{kind}");
        assert_eq!(wire(&refold), native, "{kind}");
    }
}

/// [money] D142(a): a file whose session owes a head-CAS answer never
/// continues from stored state, whatever its selection: late evidence, a
/// change and a grown file all read a native Full from byte 0, so the answer
/// rides only a real Full. The read counts under `head_conflict`.
#[test]
fn a_conflict_owed_session_reads_native_full() {
    use crate::local_resource_diagnostics::change_reason as counts;
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let session = cold_accumulator(&route, &path)
        .wire_source_session_id(&path)
        .unwrap();
    let owed = crate::snapshot_sync::cache_session_key(&session);
    // Another session's challenge is not this file's.
    route
        .index
        .activate_head_conflict_sessions(["e".repeat(64)].into());
    assert!(matches!(loaded(&route, &path, &key).0, Load::Reused(..)));
    route
        .index
        .activate_head_conflict_sessions([owed.clone()].into());
    let changed = Some(CandidateParseReason::TranscriptChanged);
    let retry = Some(CandidateParseReason::ActivityOrQuarantineRetry);
    for (grew, reasons) in [
        (false, LATE.map(Some).to_vec()),
        (false, vec![changed, None]),
        (true, vec![changed, retry]),
    ] {
        if grew {
            append(&path, 3);
        }
        for reason in reasons {
            // The selection may continue; the load refuses on the head.
            assert!(reuses_stored(&route.index, &key, reason, grew, false));
            let (load, counted_load) = loaded(&route, &path, &key);
            assert!(matches!(load, Load::Cold(None)), "{reason:?} grew={grew}");
            assert_eq!(counted(&counted_load), ("miss".into(), vec![]));
            let (_, mode, start) = read(&route, &path, None);
            assert!(matches!(mode, ReadMode::Full(_)) && start == 0);
        }
    }
    // The conflict-owed Full counts under the existing `head_conflict` row,
    // through the selection note the scan makes after the load.
    let _ = counts::drain("claude_code");
    let _ = loaded(&route, &path, &key);
    route.index.note_change_reason_selected(
        SnapshotSource::ClaudeCode,
        &super::settlement_tests::candidate(&path),
        Some(CandidateParseReason::ForcedFamily),
        None,
    );
    counts::read(
        "claude_code",
        &key,
        ReadMode::Full(crate::transcript_acquisition::FullReason::StateMissing),
        7,
        0,
    );
    let page = serde_json::to_value(counts::drain("claude_code").unwrap()).unwrap();
    assert_eq!(page["read"]["head_conflict"]["files"], 1);
    assert_eq!(page["read"]["head_conflict"]["native_bytes"], 7);
    assert!(page["read"].get("copy_ownership").is_none());
}

/// [money] Once the session's challenge clears (an ordinary accept or an
/// unchanged ACK removes it from the ledger, and the next prepare mirrors no
/// open challenge), its file continues from the Tail again: no
/// `ConflictOwed` miss and no Full. An unchanged file re-folds reading no
/// transcript byte for every late-evidence selection, including a member the
/// family pull brings in (`ForcedFamily`); a grown file reads only past the
/// sealed offset. Only the post-clear pass is asserted here.
#[test]
fn a_cleared_challenge_continues_from_the_tail() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let session = cold_accumulator(&route, &path)
        .wire_source_session_id(&path)
        .unwrap();
    let owed = crate::snapshot_sync::cache_session_key(&session);
    route.index.activate_head_conflict_sessions([owed].into());
    assert!(
        matches!(loaded(&route, &path, &key).0, Load::Cold(None)),
        "positive control: an owed answer reads Full"
    );
    route
        .index
        .activate_head_conflict_sessions(Default::default());
    let native = wire(&fresh(&route, &path));
    assert!(LATE.contains(&CandidateParseReason::ForcedFamily));
    for reason in LATE {
        assert!(reuses_stored(
            &route.index,
            &key,
            Some(reason),
            false,
            false
        ));
        let (load, counted_load) = loaded(&route, &path, &key);
        assert!(matches!(load, Load::Reused(..)), "{reason:?}");
        assert_eq!(counted(&counted_load), ("hit".into(), vec![]));
    }
    let (refold, native_bytes) = stored_finish(&route, &path, &key);
    assert_eq!(native_bytes, 0, "no transcript byte is read");
    assert_eq!(wire(&refold), native);

    append(&path, 3);
    for reason in [
        CandidateParseReason::TranscriptChanged,
        CandidateParseReason::ActivityOrQuarantineRetry,
    ] {
        assert!(reuses_stored(&route.index, &key, Some(reason), true, false));
    }
    let (Load::Reused(taken, Some(base)), counted_load) = loaded(&route, &path, &key) else {
        panic!("the committed head is reused after the clear");
    };
    assert_eq!(counted(&counted_load), ("hit".into(), vec![]));
    let (parser, mode, start) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Tail), "a grown file reads Tail");
    assert!(start > 0, "past the sealed offset");
    let (_, grown) = route.finish(&path, parser, Some(base), |_| {});
    assert_eq!(wire(&grown.unwrap().snapshots), wire(&fresh(&route, &path)));
}

/// [money] SOURCE (b): stored state incomplete for the file never re-folds.
/// A set-aside file reads natively for late evidence (an append still resumes
/// from its head, A5); a file with no head is a counted bootstrap Full.
#[test]
fn incomplete_stored_state_never_refolds() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    for reason in LATE {
        assert!(reuses_stored(
            &route.index,
            &key,
            Some(reason),
            false,
            false
        ));
    }
    append(&path, 3);
    let (Load::Reused(taken, Some(base)), _) = loaded(&route, &path, &key) else {
        panic!("the committed head is reused");
    };
    let (parser, _, _) = read(&route, &path, Some(taken));
    let (tail, native) = route.finish(&path, parser, Some(base), |acc| {
        acc.account_identifier_hash = Some("a".repeat(64));
    });
    assert!(!tail.publish(&native));
    route.save(false);
    assert!(set_aside(&route.index, &key));
    for reason in LATE {
        assert!(
            !reuses_stored(&route.index, &key, Some(reason), false, false),
            "{reason:?}"
        );
    }
    let changed = Some(CandidateParseReason::TranscriptChanged);
    assert!(reuses_stored(&route.index, &key, changed, true, false));

    let path = route.dir.join("new.jsonl");
    std::fs::write(&path, lines(3).join("\n") + "\n").unwrap();
    let (load, _) = loaded(&route, &path, &local_index_key(&path));
    assert!(matches!(load, Load::Cold(None)));
}
