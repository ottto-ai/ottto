//! Synthetic sidecar reuse and fresh-load parity, through the scan constructor.
use super::*;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!(
            "ottto-sidecar-reuse-{}",
            ottto_core::generate_control_token().unwrap()
        ));
        fs::create_dir_all(home.join("sessions")).unwrap();
        let db = Connection::open(home.join("state_5.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE threads (id TEXT, title TEXT, tokens_used INTEGER, archived INTEGER, created_at INTEGER, updated_at INTEGER, model TEXT, rollout_path TEXT, thread_source TEXT, first_user_message TEXT); CREATE TABLE thread_spawn_edges (parent_thread_id TEXT, child_thread_id TEXT);").unwrap();
        Self(home)
    }
    fn roots(&self) -> Vec<PathBuf> {
        vec![self.0.join("sessions")]
    }
    fn selecting(&self, cache: &sampled_scan::SharedCache) -> OwnedSourceScan {
        OwnedSourceScan::new_selecting(
            SnapshotSource::Codex,
            &self.roots(),
            ScanIndex::default(),
            "2026-11-09T12:00:00Z",
            30,
            100,
            None,
            &[],
            false,
            &mut ListingRequest::default(),
            false,
            &[],
            Some((
                cache,
                &crate::transcript_acquisition::Scope("sidecar-reuse".into()),
            )),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// [regress] An unchanged second pass does not reopen the sidecar databases.
#[test]
fn reuse_skips_sidecar_read() {
    let fixture = Fixture::new();
    let cache = sampled_scan::SharedCache::default();
    let first = fixture.selecting(&cache);
    assert!(!first.codex_title_metadata.state_census_incomplete);
    let second = fixture.selecting(&cache);
    let d = second.codex_title_metadata.local_diagnostics;
    assert_eq!(
        d.state_titles.snapshot_fallbacks
            + d.state_threads.snapshot_fallbacks
            + d.spawn_edges.snapshot_fallbacks,
        0
    );
}
