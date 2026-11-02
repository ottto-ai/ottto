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
}

/// [regress] 0.1.212: the re-listing pass queued 8,114 archives as census
/// members but rolled back their discovery, so pending (9,702) exceeded
/// discovered (5,512) and every status report broke `skipped <= discovered`.
/// Each member it adds now counts once; a later pass does not count it again.
#[test]
fn relisted_archive_members_count_as_discovered() {
    const ARCHIVES: usize = 12;
    let f = Fixture::new();
    let mut index = kept_generation(&f, SnapshotSource::Codex, false);
    let walked = index
        .traversal
        .as_ref()
        .unwrap()
        .counts
        .discovered_file_count;
    assert!(walked > 0 && walked < ARCHIVES, "fewer plain discovered");
    for n in 0..ARCHIVES {
        fs::write(f.root.join(format!("archive-{n}.jsonl.zst")), b"synthetic").unwrap();
    }
    for pass in 0..2 {
        relist(SnapshotSource::Codex, &mut index);
        let traversal = index.traversal.as_ref().unwrap();
        let archives = traversal
            .pending_candidates
            .iter()
            .filter(|p| p.census_member && codex_archive_path(&p.path))
            .count();
        assert_eq!(archives, ARCHIVES, "pass {pass}");
        let skipped = claude_family_census_shadow::skipped_view(&index).count();
        assert_eq!(skipped, ARCHIVES, "pass {pass}");
        let discovered = traversal.counts.discovered_file_count;
        assert_eq!(discovered, walked + ARCHIVES, "pass {pass}");
        assert!(discovered >= skipped, "pass {pass}");
    }
}

/// [behaviour] Positive control: a Claude/Pi member the walk already counted
/// and the re-listing pass queues again on growth is not counted twice.
#[test]
fn relisted_known_member_keeps_discovered_count() {
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Pi] {
        let f = Fixture::new();
        let mut index = kept_generation(&f, source, false);
        let walked = index
            .traversal
            .as_ref()
            .unwrap()
            .counts
            .discovered_file_count;
        let grown = f.root.join(format!("{GROWN}.jsonl"));
        fs::OpenOptions::new()
            .append(true)
            .open(&grown)
            .unwrap()
            .write_all(b"{}\n")
            .unwrap();
        relist(source, &mut index);
        let traversal = index.traversal.as_ref().unwrap();
        assert!(
            traversal
                .pending_candidates
                .iter()
                .any(|p| p.path == grown && p.census_member),
            "{source:?}"
        );
        assert_eq!(traversal.counts.discovered_file_count, walked, "{source:?}");
        assert!(
            claude_family_census_shadow::skipped_view(&index).count() <= walked,
            "{source:?}"
        );
    }
}
