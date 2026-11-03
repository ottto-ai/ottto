//! [money] A held original and its dependent copy on the Tail path. A newer
//! build's head holds the original (`Load::Held`): it is never read or sent,
//! and its last accepted body stands, while the copy that gained a request is
//! read in the same pass. Ported from the two M3 production rows deleted with
//! the record store (a held original's census and the copy's proof, money and
//! witness), with their grown-original and changed-entry arms.
use super::super::claude::Claude;
use super::*;
use crate::snapshots::claude_request_census::{
    claude_census_member_status, ClaudeCensusMemberStatus,
};
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::state_v2::{Change, StagedFile};
use crate::snapshots::StateV2ColdSession;

const WINDOW: &str = "2026-08-02T09:00:00Z";
const ORIGINAL: &str = "held-original";
const COPY: &str = "dependent-copy";

fn response(session: &str, request: &str, second: u32, output_tokens: u64) -> String {
    let value = serde_json::json!({
        "timestamp": format!("2026-08-02T07:00:{second:02}Z"),
        "type": "assistant",
        "sessionId": session,
        "requestId": request,
        "message": {
            "id": format!("msg_{request}"),
            "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 10, "output_tokens": output_tokens},
        },
    });
    format!("{value}\n")
}

fn write(root: &Path, session: &str, lines: &[String]) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join(format!("{session}.jsonl")), lines.concat()).unwrap();
}

fn key(index: &ScanIndex, session: &str) -> String {
    let name = format!("{session}.jsonl");
    index
        .files
        .keys()
        .find(|key| key.ends_with(&name))
        .unwrap_or_else(|| panic!("{name} is indexed"))
        .clone()
}

/// The scan's items after policy and post-policy finalization, accepted
/// exactly.
fn accept(index: &mut ScanIndex, scan: &SourceScanResult) -> Vec<SnapshotItem> {
    let mut projected = scan.clone();
    crate::upload_policy::apply_upload_policy(
        SnapshotSource::ClaudeCode,
        &mut projected.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut projected, index);
    let accepted = projected
        .snapshots
        .iter()
        .map(|snapshot| snapshot.snapshot_fingerprint.clone())
        .collect();
    index.record_accepted_snapshot_fingerprints(&accepted);
    projected.snapshots
}

/// A session's emitted bodies.
fn bodies(snapshots: &[SnapshotItem], session: &str) -> Vec<serde_json::Value> {
    snapshots
        .iter()
        .filter(|snapshot| snapshot.source_session_id == session)
        .map(|snapshot| serde_json::to_value(snapshot).unwrap())
        .collect()
}

/// An entry's last accepted body: (entity set, body witness).
fn accepted(index: &ScanIndex, key: &str) -> (Option<String>, Option<String>) {
    let entry = &index.files[key];
    (
        entry.last_snapshot_fingerprint.clone(),
        entry.last_upload_body_witness.clone(),
    )
}

/// [money] Arms over one accepted seed, each on its own state database:
/// `cold` (no head: the original reads Full and sends nothing new), `held`
/// (a newer build's head), `held_grown` (the held original grew in place;
/// the server still has the committed version) and `entry_changed` (the
/// original's committed entry differs from its census record). Every held arm
/// sends nothing for the original and keeps its last accepted body; the copy
/// sends exactly the cold arm's body and witness while the committed entry is
/// unchanged, and the census record and the copy's proof stay.
#[test]
fn a_held_original_conserves_its_dependent_copy_money() {
    let scratch = crate::test_scratch::ScratchDir::canonical("tail-held-original");
    // The state store requires canonical ancestors (CI's TMPDIR is a symlink).
    let base = scratch.join("base");
    std::fs::create_dir_all(&base).unwrap();
    let base = base.canonicalize().unwrap();
    let root = base.join("projects");
    for session in [ORIGINAL, COPY] {
        write(
            &root,
            session,
            &[response(session, "req_held_shared", 1, 100)],
        );
    }
    let mut seeded = ScanIndex::default();
    let seed = scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&root),
        &mut seeded,
        WINDOW,
        365,
        1_000,
    )
    .unwrap();
    accept(&mut seeded, &seed);
    let (original, copy) = (key(&seeded, ORIGINAL), key(&seeded, COPY));
    let record = seeded.claude_request_census.get(&original).unwrap().clone();
    let last_accepted = accepted(&seeded, &original);
    assert!(last_accepted.0.is_some());
    write(
        &root,
        COPY,
        &[
            response(COPY, "req_held_shared", 1, 100),
            response(COPY, "req_copy_new", 2, 50),
        ],
    );
    let mut cold = None;
    for arm in ["cold", "held", "held_grown", "entry_changed"] {
        // Reparse debt: the unchanged original is selected; the copy changed.
        let mut prior = seeded.clone();
        let entry = prior.files.get_mut(&original).unwrap();
        entry.source_file_fingerprint.clear();
        if arm == "entry_changed" {
            entry.modified_unix_seconds += 5;
        }
        let (state, mut index) =
            StateV2ColdSession::publish(Source::Claude, &prior, &base.join(arm));
        if arm != "cold" {
            // A newer build's head, opaque to this build.
            state_v2::stage_tail(
                state.path(),
                &original,
                StagedFile {
                    revision: Claude::REDUCTION_REVISION + 1,
                    head: b"opaque-newer-writer-head".to_vec(),
                    change: Change::Reset,
                    ..StagedFile::default()
                },
            )
            .unwrap();
            index = state.save_reload(&mut index).0;
        }
        if arm == "held_grown" {
            write(
                &root,
                ORIGINAL,
                &[
                    response(ORIGINAL, "req_held_shared", 1, 100),
                    response(ORIGINAL, "req_original_new", 3, 70),
                ],
            );
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&original)
                .unwrap();
            let modified = file.metadata().unwrap().modified().unwrap();
            file.set_modified(modified + std::time::Duration::from_secs(5))
                .unwrap();
        }
        let held_before = counters::total("tail_db_loads", "held");
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            index,
            WINDOW,
            365,
            1_000,
            None,
            &[],
            false,
        )
        .with_sampled_acquisition(
            Arc::new(sampled_scan::SharedCache::default()),
            crate::transcript_acquisition::Scope("tail-held-original".to_owned()),
        );
        let (mut index, result) = loop {
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => break (index, scan),
            }
        };
        let held = counters::total("tail_db_loads", "held") - held_before;
        let emitted = accept(&mut index, &result);
        let copy_status =
            claude_census_member_status(&index, &copy, &result.census_window_end, true);
        let copy_sent = (bodies(&emitted, COPY), accepted(&index, &copy));
        eprintln!(
            "HELD_ORIGINAL arm={arm} held={held} copy_status={copy_status:?} record_kept={}",
            index.claude_request_census.get(&original) == Some(&record)
        );
        if arm == "cold" {
            assert_eq!(held, 0);
            assert_eq!(copy_status, ClaudeCensusMemberStatus::SharesHash);
            // Money premise: a cold read of the unchanged original sends
            // nothing new; its accepted body stands.
            assert_eq!(accepted(&index, &original), last_accepted);
            assert!(bodies(&emitted, ORIGINAL).is_empty());
            assert!(!copy_sent.0.is_empty());
            cold = Some(copy_sent);
            continue;
        }
        assert_eq!(held, 1, "{arm}: the newer head holds the original");
        assert!(bodies(&emitted, ORIGINAL).is_empty(), "{arm}: no POST");
        assert_eq!(
            accepted(&index, &original),
            last_accepted,
            "{arm}: the last accepted body is kept"
        );
        // Every held arm, a changed entry included, keeps its census record
        // as last read: the Tail path has no restore gate to invalidate it.
        assert_eq!(
            index.claude_request_census.get(&original),
            Some(&record),
            "{arm}"
        );
        assert_eq!(copy_status, ClaudeCensusMemberStatus::SharesHash, "{arm}");
        assert_eq!(Some(&copy_sent), cold.as_ref(), "{arm}: the copy's money");
    }
}
