use super::*;
use crate::heap_layout_bound::HeapLayoutBound;
use crate::local_resource_diagnostics::claude_reread;
use crate::snapshots::sampled_scan::SharedCache;
use std::time::Duration;

struct Store(crate::test_scratch::ScratchDir);
impl Store {
    fn new() -> Self {
        Self(crate::test_scratch::ScratchDir::new("desktop-reuse"))
    }
    fn write(&self, relative: &str, value: Value) -> PathBuf {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, value.to_string()).unwrap();
        path
    }
    fn sweep(
        &self,
        owner: &SharedCache,
        index: &mut ScanIndex,
        dir: &Path,
    ) -> (ClaudeTitleMetadata, u64) {
        index.claude_desktop_store_retry_not_before_unix_seconds = None;
        let scope = claude_reread::Scope::begin(true);
        let result = owner.with_desktop_titles(|facts| {
            ClaudeTitleMetadata::load_from_store_dirs_with_census(
                &BTreeSet::from([dir.to_owned()]),
                index,
                "2026-11-09T08:00:00Z",
                ClaudeDesktopStoreCensus::default(),
                facts,
            )
        });
        (
            result,
            scope.finish().desktop_metadata.desktop_store_body_reads,
        )
    }
}
const ACCOUNT: &str = "123e4567-e89b-12d3-a456-426614174000";
const ORG: &str = "123e4567-e89b-12d3-a456-426614174001";

/// [behaviour] Only changed/new content loads; valid non-session facts stay
/// distinct from errors, and an ordinary listing removes deleted RAM facts.
#[test]
fn desktop_titles_reuse_tracks_content_and_listing() {
    let store = Store::new();
    let native = store.write(
        &format!("{ACCOUNT}/{ORG}/native.json"),
        serde_json::json!({
            "cliSessionId":"native", "title":"first", "createdAt":1794211200000i64
        }),
    );
    let imported = store.write(
        &format!("{ACCOUNT}/{ORG}/imported.json"),
        serde_json::json!({
            "cliSessionId":"imported", "importedFrom":null, "createdAt":"2026-11-09T08:00:00Z"
        }),
    );
    let other = store.write(
        "other/bucket/session.json",
        serde_json::json!({"cliSessionId":"other"}),
    );
    let non_session = store.write("tasks.json", serde_json::json!({"tasks":[]}));
    let owner = SharedCache::default();
    let mut index = ScanIndex::default();
    assert_eq!(store.sweep(&owner, &mut index, &store.0).1, 4);
    let entry = &index.claude_desktop_title_files[&local_index_key(&native)];
    let identity = entry.original_identity.as_ref().unwrap();
    assert!(!identity.imported);
    assert!(identity.source_created_at.is_some());
    assert!(
        index.claude_desktop_title_files[&local_index_key(&imported)]
            .original_identity
            .as_ref()
            .unwrap()
            .imported
    );
    assert!(index.claude_desktop_title_files[&local_index_key(&other)]
        .original_identity
        .as_ref()
        .unwrap()
        .account_identifier_hash
        .is_none());
    let saved = serde_json::to_value(&index).unwrap();
    assert_eq!(store.sweep(&owner, &mut index, &store.0).1, 0);
    assert_eq!(saved, serde_json::to_value(&index).unwrap());
    owner.with_desktop_titles(|facts| {
        assert!(facts.kept[&local_index_key(&non_session)].1.is_none())
    });
    fs::write(
        &native,
        r#"{"cliSessionId":"native","title":"changed length"}"#,
    )
    .unwrap();
    assert_eq!(store.sweep(&owner, &mut index, &store.0).1, 1);
    assert_eq!(
        index.claude_desktop_title_files[&local_index_key(&native)]
            .title
            .as_deref(),
        Some("changed length")
    );
    // Same-sized edit with an explicitly different nanosecond mtime.
    let before = fs::metadata(&native).unwrap().modified().unwrap();
    fs::write(
        &native,
        r#"{"cliSessionId":"native","title":"another length"}"#,
    )
    .unwrap();
    fs::File::options()
        .write(true)
        .open(&native)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(before + Duration::from_nanos(1)))
        .unwrap();
    assert_eq!(store.sweep(&owner, &mut index, &store.0).1, 1);
    let replacement = store.write(
        "replacement.tmp",
        serde_json::json!({"cliSessionId":"native","title":"replacement"}),
    );
    fs::rename(replacement, &native).unwrap();
    assert_eq!(store.sweep(&owner, &mut index, &store.0).1, 1);
    store.write("new.json", serde_json::json!({"cliSessionId":"new"}));
    assert_eq!(store.sweep(&owner, &mut index, &store.0).1, 1);
    fs::remove_file(&native).unwrap();
    assert_eq!(store.sweep(&owner, &mut index, &store.0).1, 0);
    owner.with_desktop_titles(|facts| assert!(!facts.kept.contains_key(&local_index_key(&native))));
    assert!(!index
        .claude_desktop_title_files
        .contains_key(&local_index_key(&native)));
    fs::write(&non_session, "{").unwrap();
    for _ in 0..2 {
        assert_eq!(store.sweep(&owner, &mut index, &store.0).1, 1);
    }
    owner.with_desktop_titles(|facts| {
        assert!(!facts.kept.contains_key(&local_index_key(&non_session)))
    });
}

/// [behaviour] Metadata-only changes reuse content, but a new store context
/// reconstructs account/org hashes for the very same path on a hit.
#[test]
fn desktop_titles_reuse_rebinds_identity_and_ignores_ctime() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let store = Store::new();
    let path = store.write(
        &format!("{ACCOUNT}/{ORG}/{ACCOUNT}/session.json"),
        serde_json::json!({
            "cliSessionId":"native", "createdAt":"2026-11-09T08:00:00Z", "importedFrom":false
        }),
    );
    let extracted = load_desktop_session_file_facts(&path).unwrap().unwrap();
    assert!(extracted.imported && extracted.source_created_at.is_some());
    assert!(extracted.into_entry(None, None).original_identity.is_none());
    let owner = SharedCache::default();
    let mut index = ScanIndex::default();
    assert_eq!(store.sweep(&owner, &mut index, &store.0).1, 1);
    let key = local_index_key(&path);
    let old = index.claude_desktop_title_files[&key].clone();
    let before = fs::metadata(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let after = fs::metadata(&path).unwrap();
    assert_eq!(
        (before.mtime(), before.mtime_nsec()),
        (after.mtime(), after.mtime_nsec())
    );
    assert_ne!(
        (before.ctime(), before.ctime_nsec()),
        (after.ctime(), after.ctime_nsec())
    );
    assert_eq!(store.sweep(&owner, &mut index, &store.0).1, 0);
    assert_eq!(store.sweep(&owner, &mut index, &store.0.join(ACCOUNT)).1, 0);
    let rebound = &index.claude_desktop_title_files[&key];
    assert_ne!(old.account_identifier_hash, rebound.account_identifier_hash);
    assert_ne!(
        old.original_identity
            .as_ref()
            .unwrap()
            .provider_workspace_hash,
        rebound
            .original_identity
            .as_ref()
            .unwrap()
            .provider_workspace_hash
    );
    assert!(rebound.original_identity.as_ref().unwrap().imported);
    assert_eq!(
        old.original_identity.as_ref().unwrap().source_created_at,
        rebound
            .original_identity
            .as_ref()
            .unwrap()
            .source_created_at
    );
    // The new owner is cold; compare the complete durable output as well.
    let mut cold = ScanIndex::default();
    assert_eq!(
        store
            .sweep(&SharedCache::default(), &mut cold, &store.0.join(ACCOUNT))
            .1,
        1
    );
    assert_eq!(
        serde_json::to_value(&index).unwrap(),
        serde_json::to_value(cold).unwrap()
    );
}

/// [behaviour] Moving facts out permits a concurrent cold sweep, and the
/// heap walk accounts for retained strings without blocking on a busy lock.
#[test]
fn desktop_title_owner_unlocks_during_load_and_charges_facts() {
    let store = Store::new();
    store.write(
        "session.json",
        serde_json::json!({"cliSessionId":"native","title":"a retained title"}),
    );
    let owner = SharedCache::default();
    let measured = |owner: &SharedCache| {
        let mut c = crate::heap_layout_bound::Counter::new(usize::MAX);
        owner.heap_bound(&mut c).map(|_| c.bytes)
    };
    let empty = measured(&owner);
    store.sweep(&owner, &mut ScanIndex::default(), &store.0);
    if crate::heap_layout_bound::layout_supported() {
        assert!(measured(&owner).unwrap() > empty.unwrap());
    }
    std::thread::scope(|scope| {
        let (entered, wait) = std::sync::mpsc::channel();
        let (resume, paused) = std::sync::mpsc::channel();
        let borrowed = &owner;
        scope.spawn(move || {
            borrowed.with_desktop_titles(|_| {
                entered.send(()).unwrap();
                paused.recv().unwrap();
            })
        });
        wait.recv().unwrap();
        assert_eq!(
            store.sweep(&owner, &mut ScanIndex::default(), &store.0).1,
            1
        );
        resume.send(()).unwrap();
    });
    assert_eq!(
        store.sweep(&owner, &mut ScanIndex::default(), &store.0).1,
        0
    );
}
