//! The retired restart-record directory beside each scan index. Nothing reads
//! it; each pass removes it whole under the writer lock and syncs the parent.
//! A failed removal is counted in that pass's point and retried every pass.
use super::*;

impl SharedCache {
    /// The caller holds the state-directory lock.
    pub(in crate::snapshots) fn remove_retired_records(
        &self,
        source: SnapshotSource,
        index_path: &Path,
    ) {
        let dir = state_v2::retired_record_dir(index_path);
        let (removed, failed) = match state_v2::remove_retired_record_dir(&dir) {
            Ok(false) => return,
            Ok(true) => (1, 0),
            Err(_) => (0, 1),
        };
        crate::local_resource_diagnostics::traversal_point(
            "tail_legacy_dir",
            source.api_slug(),
            &serde_json::json!({"removed": removed, "failed": failed}),
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn points(rows: &[serde_json::Value]) -> Vec<&serde_json::Value> {
        rows.iter()
            .filter(|row| row["stage"] == "tail_legacy_dir")
            .collect()
    }

    /// [behaviour] Removal reaches the record directory only. A failed removal
    /// is counted in each pass and retried by the next. Erasure failure never
    /// reads as healthy.
    #[test]
    fn failed_removal_stays_counted_until_the_directory_is_gone() {
        let scratch = crate::test_scratch::ScratchDir::new("retired-record-dir");
        let index_path = scratch.join("codex-scan-index.json");
        fs::write(&index_path, b"{}").unwrap();
        let cache = SharedCache::default();
        let source = SnapshotSource::Codex;
        let dir = state_v2::retired_record_dir(&index_path);
        // Absent: no row at all.
        let ((), rows) = crate::local_resource_diagnostics::capture(|| {
            cache.remove_retired_records(source, &index_path);
        });
        assert!(points(&rows).is_empty());
        fs::create_dir_all(dir.join("child")).unwrap();
        fs::write(dir.join("child/synthetic.rec"), b"retired").unwrap();
        fs::set_permissions(dir.join("child"), fs::Permissions::from_mode(0o500)).unwrap();
        // A process that ignores modes cannot observe the failing arm.
        let blocked = fs::remove_file(dir.join("child/synthetic.rec")).is_err();
        if blocked {
            for _ in 0..2 {
                let ((), rows) = crate::local_resource_diagnostics::capture(|| {
                    cache.remove_retired_records(source, &index_path);
                });
                let row = points(&rows);
                assert_eq!(row.len(), 1);
                assert_eq!(row[0]["counts"]["failed"], 1);
                assert_eq!(row[0]["counts"]["removed"], 0);
                assert!(dir.exists(), "the failed directory is kept for the retry");
            }
            assert!(index_path.exists());
        }
        fs::set_permissions(dir.join("child"), fs::Permissions::from_mode(0o700)).unwrap();
        let ((), rows) = crate::local_resource_diagnostics::capture(|| {
            if blocked {
                cache.remove_retired_records(source, &index_path);
            } else {
                fs::create_dir_all(&dir).unwrap();
                cache.remove_retired_records(source, &index_path);
            }
        });
        let row = points(&rows);
        assert_eq!(row.len(), 1);
        assert_eq!(row[0]["counts"]["removed"], 1);
        assert_eq!(row[0]["counts"]["failed"], 0);
        assert!(!dir.exists());
        assert!(index_path.exists(), "only the record directory is removed");
    }
}
