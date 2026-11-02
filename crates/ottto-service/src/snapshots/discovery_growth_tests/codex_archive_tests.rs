use super::*;

/// [money] Re-listing uses archive stamps and custody after native-entry retirement;
/// unchanged debt is paced, settlement stays quiet, growth queues, and size debt stays isolated.
#[test]
fn archive_relisting_preserves_custody_and_owed_pacing() {
    use crate::local_resource_diagnostics::CodexZstCause;
    use codex_compressed_input::{ArchiveDisposition, ArchiveEvidence};
    for disposition in [
        ArchiveDisposition::Acquired,
        ArchiveDisposition::Empty,
        ArchiveDisposition::Pending,
        ArchiveDisposition::Held {
            cause: CodexZstCause::HeaderInvalid,
            quiet: true,
        },
        ArchiveDisposition::Held {
            cause: CodexZstCause::CorrectionUnapplied,
            quiet: true,
        },
    ] {
        let f = Fixture::new();
        let mut index = kept_generation(&f, SnapshotSource::Codex, false);
        let path = f.root.join("archive.jsonl.zst");
        fs::write(&path, b"synthetic").unwrap();
        let key = local_index_key(&path);
        let mut archive = ArchiveEvidence::from_metadata(fs::metadata(&path).unwrap()).unwrap();
        archive.owner = Some("synthetic".into());
        archive.disposition = disposition;
        archive.work.as_mut().unwrap().decoded = true;
        let owed = archive.owed_cause().is_some();
        index.archives.insert(key.clone(), archive);
        // Settled archive custody wins even over a re-armed ordinary entry.
        // Owed archives have no native entry after reconciliation retires it.
        if !owed {
            index.files.insert(key.clone(), ScanIndexEntry::default());
        }
        index
            .traversal
            .as_mut()
            .unwrap()
            .observed_index_keys
            .insert(key.clone());
        assert_eq!(discovery_retention!(index).owes(&path), owed);
        for pass in 0..3 {
            index.traversal.as_mut().unwrap().pending_candidates.clear();
            relist(SnapshotSource::Codex, &mut index);
            let traversal = index.traversal.as_ref().unwrap();
            assert_eq!(
                traversal.pending_candidates.len(),
                usize::from(owed && pass == 0)
            );
            assert_eq!(traversal.counts.listing_owed_requeued, u64::from(owed));
            assert_eq!(traversal.counts.listing_changes_without_hint, 0);
            assert!(traversal
                .pending_candidates
                .iter()
                .all(|p| p.path == path && !p.census_member));
        }
        if owed {
            *index
                .traversal
                .as_mut()
                .unwrap()
                .listing_owed_requeued_unix_seconds
                .get_mut(&key)
                .unwrap() -= LISTING_OWED_PACE_SECONDS;
            relist(SnapshotSource::Codex, &mut index);
            assert_eq!(
                index.traversal.as_ref().unwrap().pending_candidates.len(),
                1
            );
            assert_eq!(
                index
                    .traversal
                    .as_ref()
                    .unwrap()
                    .counts
                    .listing_owed_requeued,
                2
            );
        }
        index.traversal.as_mut().unwrap().pending_candidates.clear();
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"growth")
            .unwrap();
        relist(SnapshotSource::Codex, &mut index);
        let traversal = index.traversal.as_ref().unwrap();
        assert_eq!(traversal.pending_candidates.len(), 1);
        assert_eq!(traversal.pending_candidates[0].path, path);
        assert_eq!(traversal.counts.listing_changes_without_hint, 1);
    }
    let f = Fixture::new();
    let mut index = kept_generation(&f, SnapshotSource::Codex, false);
    let path = f.root.join("oversized.jsonl.zst");
    fs::File::create(&path)
        .unwrap()
        .set_len(max_jsonl_file_bytes(SnapshotSource::Codex) + 1)
        .unwrap();
    relist(SnapshotSource::Codex, &mut index);
    let traversal = index.traversal.as_ref().unwrap();
    assert!(traversal.pending_candidates.is_empty());
    assert_eq!(traversal.counts.oversized_file_count, 0);
    assert_eq!(traversal.counts.unreadable_path_count, 0);
    assert!(index
        .archive_pass
        .deferred
        .contains(&local_index_key(&path)));
    let (_, logs) = capture(|| index.disclose_archive_debt());
    assert!(index.archive_owed_count() > 0);
    assert!(logs.iter().any(|row| row["stage"] == "durable_tail_alarm"));
}
