//! L02 (D168-3): a late-evidence re-fold from stored state is the body a
//! fresh native read sends now, byte for byte. It goes as an ordinary update,
//! with no rescan claim, counted by its reason (the row is
//! `oracle_tests::differing_stored_body_is_sent_as_the_cold_full_body`). Stored state that is
//! incomplete for the file, or a body waiting on a server retry (a head-CAS
//! conflict), reads natively instead. The scan-level sidecar rows
//! (`claude_tail_money_tests`: `quiet_sidecar_growth`, `side_owner`, ...)
//! compare the same re-fold's upload with a cold Full on real evidence.
use super::super::claude::tests::lines;
use super::super::seam::tests::{route, Route};
use super::settlement_tests::stored_finish;
use super::tests::{append, cold, committed, loaded, read};
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
/// envelopes equal a fresh native read's, byte for byte. A grown file reads
/// only past the sealed offset, and its body and money fold equal the cold
/// Full's.
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
                reuses_stored(&route.index, &key, Some(reason), false),
                "{reason:?}"
            );
        }
        let (refold, native_bytes) = stored_finish(&route, &path, &key);
        assert_eq!(native_bytes, 0, "{name}");
        assert_eq!(wire(&refold), native, "{name}");
    }

    let (path, key) = committed(&mut route, "grown.jsonl", 300);
    append(&path, 300);
    let changed = Some(CandidateParseReason::TranscriptChanged);
    assert!(reuses_stored(&route.index, &key, changed, false));
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

/// [money] SOURCE (c): while a body of the file waits on a server retry (a
/// head-CAS conflict), no late-evidence selection re-folds it: the read that
/// answers is a native Full. An append still continues from its head.
#[test]
fn a_retry_held_file_reads_natively() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let fingerprint = "c".repeat(64);
    route
        .index
        .file_snapshot_fingerprints
        .insert(key.clone(), [fingerprint.clone()].into());
    for reason in LATE {
        assert!(reuses_stored(&route.index, &key, Some(reason), false));
    }
    route.index.quarantined_snapshot_fingerprints.insert(
        fingerprint,
        snapshot_quarantine_record(SnapshotSource::ClaudeCode),
    );
    for reason in LATE {
        assert!(
            !reuses_stored(&route.index, &key, Some(reason), false),
            "{reason:?}"
        );
    }
    let changed = Some(CandidateParseReason::TranscriptChanged);
    assert!(reuses_stored(&route.index, &key, changed, false));
    let (_, mode, start) = read(&route, &path, None);
    assert!(matches!(mode, ReadMode::Full(_)) && start == 0);
}

/// [money] SOURCE (b): stored state incomplete for the file never re-folds.
/// A set-aside file reads natively for late evidence (an append still resumes
/// from its head, A5); a file with no head is a counted bootstrap Full.
#[test]
fn incomplete_stored_state_never_refolds() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    for reason in LATE {
        assert!(reuses_stored(&route.index, &key, Some(reason), false));
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
            !reuses_stored(&route.index, &key, Some(reason), false),
            "{reason:?}"
        );
    }
    let changed = Some(CandidateParseReason::TranscriptChanged);
    assert!(reuses_stored(&route.index, &key, changed, false));

    let path = route.dir.join("new.jsonl");
    std::fs::write(&path, lines(3).join("\n") + "\n").unwrap();
    let (load, _) = loaded(&route, &path, &local_index_key(&path));
    assert!(matches!(load, Load::Cold(None)));
}
