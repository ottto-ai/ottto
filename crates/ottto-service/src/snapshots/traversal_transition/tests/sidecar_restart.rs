use super::*;
use crate::snapshots::OwnedSourceScan;

/// [regress] A census restart witnesses the discarded checkpoint once, without
/// pretending it retired; an absent checkpoint has no restarting record.
#[test]
fn sidecar_restart_reports_only_an_existing_discarded_traversal() {
    for retained in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("sidecar-restart");
        let root = scratch.join(".claude/projects");
        let store = scratch.join("Library/Application Support/Claude/claude-code-sessions");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("invalid.json"), "{bad json}").unwrap();
        let mut index = ScanIndex::default();
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            T0,
            BACKFILL_WINDOW_DAYS,
        );
        index.traversal.as_mut().unwrap().completed_unix_seconds = rfc3339_unix_seconds(T0);
        let old = index.traversal.as_ref().unwrap();
        let directories = old.pending_directories.len();
        let candidates = old.pending_candidates.len();
        if !retained {
            index.traversal = None;
        }
        index.generation = 37;
        index.claude_desktop_identity_census_complete = true;
        let (_, rows) = capture(|| {
            OwnedSourceScan::new(
                SnapshotSource::ClaudeCode,
                &[root],
                index,
                T1,
                BACKFILL_WINDOW_DAYS,
                10,
                None,
                &[],
                false,
            )
        });
        let restarts = rows
            .iter()
            .filter(|row| row["counts"]["event"] == "restarting")
            .collect::<Vec<_>>();
        assert_eq!(restarts.len(), usize::from(retained));
        if retained {
            assert_eq!(
                restarts[0]["counts"],
                json!({
                    "event":"restarting", "reason":"sidecar_census_restart", "index_generation":37,
                    "window_unix_seconds":rfc3339_unix_seconds(T0),
                    "pending_directories":directories, "pending_candidates":candidates,
                })
            );
            let restart_at = rows
                .iter()
                .position(|row| row["counts"]["event"] == "restarting")
                .unwrap();
            let start_at = rows
                .iter()
                .position(|row| row["counts"]["event"] == "starting")
                .unwrap();
            assert!(
                restart_at < start_at,
                "the old checkpoint is witnessed before its replacement"
            );
        }
    }
}
