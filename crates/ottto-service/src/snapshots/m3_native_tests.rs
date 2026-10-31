//! M3 r6 D3 source split, native side: the Codex strict retained-entry
//! rebind and the held Claude key's discovery, on the real index and
//! traversal code paths. No store, cache or upload is involved.
use super::*;
use crate::durable_tail_store as store;
use crate::transcript_acquisition::AuditDebt;
use std::time::{Duration, SystemTime};

const CODEX_KEY: &str =
    "/tmp/m3-d3/sessions/rollout-2026-10-20T10-00-00-0199f7a0-0000-7000-8000-0000000d7a11.jsonl";
const CLAUDE_KEY: &str = "/tmp/m3-d3/projects/-tmp/5f0c2a8e-1111-4222-8333-944445555666.jsonl";
const DUE: u64 = 1_790_000_000;

fn entry(fingerprint: &str, size_bytes: u64) -> ScanIndexEntry {
    serde_json::from_value(json!({
        "size_bytes": size_bytes,
        "modified_unix_seconds": 1,
        "source_file_fingerprint": fingerprint,
        "last_snapshot_fingerprint": "snap",
        "last_upload_body_witness": "witness",
    }))
    .unwrap()
}

/// A committed index holding one accepted entry with staged #865 debt and
/// its upload membership.
fn committed(key: &str) -> ScanIndex {
    let mut index = ScanIndex::default();
    index.files.insert(key.into(), entry("fp", 4096));
    assert!(index.stage_sampled_audit(
        key,
        "fp",
        AuditDebt {
            due_unix_seconds: DUE
        }
    ));
    index
        .file_snapshot_fingerprints
        .insert(key.into(), BTreeSet::from(["snap".to_string()]));
    index
}

fn without_fingerprint(entry: &ScanIndexEntry) -> Value {
    let mut value = serde_json::to_value(entry).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("source_file_fingerprint");
    value
}

/// [money] m3 d3 codex strict rebind keeps entry debt and membership.
#[test]
fn m3_d3_codex_strict_rebind_keeps_entry_debt_and_membership() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let previous = committed(CODEX_KEY);
    let mut working = previous.clone();
    assert!(codex_strict_rebind(
        &mut working,
        SnapshotSource::Codex,
        CODEX_KEY
    ));
    let (before, after) = (&previous.files[CODEX_KEY], &working.files[CODEX_KEY]);
    assert!(after.source_file_fingerprint.is_empty());
    // Not deleted, not absent, not retired: every other fact is unchanged,
    // including the #865 marker and deadline and the accepted body witness.
    assert_eq!(without_fingerprint(after), without_fingerprint(before));
    assert_eq!(after.unverified_deadline(), Some(DUE));
    assert_eq!(
        working.file_snapshot_fingerprints[CODEX_KEY],
        BTreeSet::from(["snap".to_string()])
    );
    // A's v1 binding no longer matches: the entry digest both readers
    // compare (this build's v1 Codex check, 0.1.201's for every source).
    let witness = after.last_upload_body_witness.as_deref();
    assert_ne!(
        store::entry_digest(&before.source_file_fingerprint, witness),
        store::entry_digest(&after.source_file_fingerprint, witness)
    );
    // The save that settles the publication keeps the rebind, whether the
    // upload was accepted or only partially settled.
    for accepted in [BTreeSet::from(["snap".to_string()]), BTreeSet::new()] {
        let settled = working.committable_subset_with_local_holds(
            &previous,
            &accepted,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        let saved = &settled.files[CODEX_KEY];
        assert!(saved.source_file_fingerprint.is_empty(), "{accepted:?}");
        assert_eq!(saved.unverified_deadline(), Some(DUE), "{accepted:?}");
    }
}

/// [money] m3 d3 claude is never strictly rebound.
#[test]
fn m3_d3_claude_is_never_strictly_rebound() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    // Claude holds the key instead: its original-v1 adapter and account
    // identity inputs (source fingerprint included) stay unchanged.
    let mut index = committed(CLAUDE_KEY);
    let before = serde_json::to_value(&index.files[CLAUDE_KEY]).unwrap();
    assert!(!codex_strict_rebind(
        &mut index,
        SnapshotSource::ClaudeCode,
        CLAUDE_KEY
    ));
    assert_eq!(
        serde_json::to_value(&index.files[CLAUDE_KEY]).unwrap(),
        before
    );
    // An unindexed Codex key is not invented.
    assert!(!codex_strict_rebind(
        &mut index,
        SnapshotSource::Codex,
        CODEX_KEY
    ));
    assert!(!index.files.contains_key(CODEX_KEY));
}

/// [money] m3 d3 held claude key stays discoverable past the window.
#[test]
fn m3_d3_held_claude_key_stays_discoverable_past_the_window() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = std::env::temp_dir().join(format!(
        "ottto-m3-d3-discovery-{}",
        ottto_core::generate_control_token().unwrap()
    ));
    fs::create_dir_all(&root).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    let path = root.join("5f0c2a8e-1111-4222-8333-944445555666.jsonl");
    fs::write(&path, vec![b'\n'; 64]).unwrap();
    // Quiet for far longer than the window: a held key need not grow again.
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(400 * 86_400))
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = local_index_key(&path);
    let discover = |files: &BTreeMap<String, ScanIndexEntry>| {
        candidate_from_traversal_path(
            SnapshotSource::ClaudeCode,
            ScanTraversalPath {
                scan_root: root.clone(),
                path: path.clone(),
                census_member: true,
                watcher_hint: false,
            },
            &mut ScanCensus::default(),
            Some(now),
            30,
            &mut CandidateDiscovery::new(
                &mut ScanIndex {
                    files: files.clone(),
                    ..ScanIndex::default()
                },
                None,
            ),
        )
        .is_some()
    };
    // Control: an unindexed old file and an idle accepted one age out.
    assert!(!discover(&BTreeMap::new()));
    assert!(!discover(&BTreeMap::from([(key.clone(), entry("fp", 64))])));
    // Held: the committed entry keeps its pre-hold accepted extent (the
    // held completion recorded nothing), so the read bytes past it keep
    // the key a candidate regardless of age, every pass and after restart.
    assert!(discover(&BTreeMap::from([(key.clone(), entry("fp", 16))])));
    // Its #865 marker alone also keeps it, at the accepted length.
    let mut marked = committed(&key);
    marked.files.get_mut(&key).unwrap().size_bytes = 64;
    assert!(discover(&marked.files));
}

/// Exercise the production M3 descriptor boundary with a real decoder, even
/// when the path looks plain. The remaining route preconditions cannot turn
/// the archive input into physical prefix authority or candidate-less debt.
/// [money] m3 compressed archive bypasses staging and finishes without receipt debt.
#[test]
fn m3_compressed_archive_bypasses_staging_and_finishes_without_receipt_debt() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("m3-archive-route");
    let path = root.join("rollout.jsonl");
    let archive = root.join("rollout.jsonl.zst");
    let source = SnapshotSource::Codex;
    let text = [
        json!({"type":"session_meta","timestamp":"2026-10-07T10:00:00Z",
            "payload":{"id":"0199f7a0-0000-7000-8000-0000000d7a11","cwd":"/tmp/m3-archive","source":"cli"}}),
        json!({"type":"turn_context","timestamp":"2026-10-07T10:00:00Z",
            "payload":{"turn_id":"turn-1","model":"gpt-5.2","cwd":"/tmp/m3-archive"}}),
        json!({"type":"event_msg","timestamp":"2026-10-07T10:00:00Z",
            "payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100,"output_tokens":10},
                "last_token_usage":{"input_tokens":100,"output_tokens":10}}}}),
    ].into_iter().map(|v| v.to_string()+"\n").collect::<String>();
    fs::write(&path, &text).unwrap();
    fs::write(
        &archive,
        zstd::stream::encode_all(text.as_bytes(), 1).unwrap(),
    )
    .unwrap();
    let plain = OpenedInput::plain(File::open(&path).unwrap());
    assert!(
        native_writeahead_descriptor(&path, &plain).is_some(),
        "plain control"
    );
    assert!(
        native_writeahead_descriptor(&archive, &plain).is_none(),
        "path guard"
    );
    let input = OpenedInput::compressed(
        File::open(&archive).unwrap(),
        1024 * 1024,
        codex_compressed_input::compressed_input_credit().unwrap(),
    )
    .unwrap();
    assert!(
        native_writeahead_descriptor(&path, &input).is_none(),
        "input kind, independent of suffix"
    );
    let identity = opened_object_identity(source, &mut File::open(&archive).unwrap()).unwrap();
    let mut parser = OwnedJsonlParser::new_opened(
        input,
        &archive,
        source,
        apply_codex_line,
        None,
        None,
        None,
        false,
        false,
    )
    .unwrap();
    while !parser.step().unwrap() {}
    let cache = sampled_scan::SharedCache::default();
    let key = local_index_key(&archive);
    assert!(native_writeahead_descriptor(&archive, &parser.reader.reader).is_none());
    let ordinary = parser
        .finish(
            &identity,
            &archive,
            "2026-10-20T12:00:00Z",
            "archive-fp".into(),
            None,
            None,
            None,
        )
        .unwrap();
    assert!(
        !ordinary.snapshots.is_empty(),
        "ordinary completion retains positive usage"
    );
    assert!(ordinary.snapshots.iter().any(|s| s.input_tokens > 0));
    assert!(
        !cache.owes_discovery(source, &key),
        "no M3 receipt debt or Hold"
    );
    assert!(
        cache.durable_counters(source).is_none(),
        "M3 acquired no store/lease"
    );
}
