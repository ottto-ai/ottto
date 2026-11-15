//! Linux-only synthetic append-owner tests; no process-global uninstall fence.
use super::*;
use crate::test_scratch::ScratchDir;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn handles(cap: usize) -> AppendHandles {
    AppendHandles {
        cap,
        ..AppendHandles::default()
    }
}

fn append(handles: &mut AppendHandles, dir: &Path, root: &str) -> PathBuf {
    let path = evidence_path(dir, root);
    append_rows(
        handles,
        dir,
        [(root, path.clone(), &serde_json::json!({"row": root}))],
    )
    .unwrap();
    path
}

/// [regress] A cache hit uses the same opened file, without another open.
#[test]
fn hit_reuses_open_handle() {
    let dir = ScratchDir::new("append-hit");
    let mut handles = handles(2);
    let path = append(&mut handles, &dir, "hit");
    append(&mut handles, &dir, "hit");
    assert_eq!(handles.opens, 1);
    assert_eq!(
        fs::read(path).unwrap(),
        b"{\"row\":\"hit\"}\n{\"row\":\"hit\"}\n"
    );
}

/// [regress] Replacement identity is taken from the opened file; the old inode
/// remains open throughout rename and cannot be reused for the replacement.
#[test]
fn replaced_file_reopens() {
    let dir = ScratchDir::new("append-replace");
    let mut handles = handles(2);
    let path = append(&mut handles, &dir, "replace");
    let old = path.with_extension("old");
    fs::rename(&path, &old).unwrap();
    fs::write(&path, b"replacement\n").unwrap();
    append(&mut handles, &dir, "replace");
    assert_eq!(handles.opens, 2);
    assert_eq!(fs::read(old).unwrap(), b"{\"row\":\"replace\"}\n");
    assert_eq!(
        fs::read(&path).unwrap(),
        b"replacement\n{\"row\":\"replace\"}\n"
    );
    assert_eq!(handles.open[0].ino, fs::metadata(path).unwrap().ino());
}

/// [regress] A deleted pathname is recreated instead of appending to its orphan.
#[test]
fn deleted_file_reopens() {
    let dir = ScratchDir::new("append-delete");
    let mut handles = handles(2);
    let path = append(&mut handles, &dir, "delete");
    let old = handles.open[0].file.try_clone().unwrap();
    fs::remove_file(&path).unwrap();
    append(&mut handles, &dir, "delete");
    assert_eq!(handles.opens, 2);
    assert_ne!(
        old.metadata().unwrap().ino(),
        fs::metadata(&path).unwrap().ino()
    );
    assert_eq!(
        old.metadata().unwrap().len(),
        fs::metadata(path).unwrap().len()
    );
}

/// [regress] A zero retention allowance preserves open/write/close per request.
#[test]
fn zero_cap_closes_each_append() {
    let dir = ScratchDir::new("append-zero");
    let mut handles = handles(0);
    for _ in 0..2 {
        append(&mut handles, &dir, "zero");
        assert!(handles.open.is_empty());
    }
    assert_eq!(handles.opens, 2);
}

/// [regress] Hits do not refresh insertion order; eviction happens before open.
#[test]
fn capacity_evicts_fifo() {
    let dir = ScratchDir::new("append-fifo");
    let mut handles = handles(2);
    let a = append(&mut handles, &dir, "a");
    let b = append(&mut handles, &dir, "b");
    append(&mut handles, &dir, "a");
    let c = append(&mut handles, &dir, "c");
    assert_eq!(
        handles.open.iter().map(|e| &e.path).collect::<Vec<_>>(),
        [&b, &c]
    );
    assert!(!handles.open.iter().any(|e| e.path == a));
    assert_eq!(handles.opens, 3);
}

/// [regress] Cycle release empties the owner and the next append opens afresh.
#[test]
fn clear_closes_all_handles() {
    let dir = ScratchDir::new("append-clear");
    let mut handles = handles(2);
    append(&mut handles, &dir, "a");
    append(&mut handles, &dir, "b");
    handles.clear();
    assert!(handles.open.is_empty());
    append(&mut handles, &dir, "a");
    assert_eq!(handles.opens, 3);
}

/// [regress] Retention evicts successfully unlinked, missing and failed members,
/// but preserves the complete pair on a generation mismatch.
#[test]
fn retention_unlink_evicts_under_held_guard() {
    let dir = ScratchDir::new("append-retention");
    let mut handles = handles(2);
    let root = "retained";
    let api = append(&mut handles, &dir, root);
    let trace = trace_evidence_path(&dir, root);
    fs::create_dir_all(trace.parent().unwrap()).unwrap();
    handles.append(&trace, b"{}\n").unwrap();
    let stem = telemetry_stem(root);
    let pair_at = || TelemetryPair {
        request_ids: BTreeSet::new(),
        first_observed: 0,
        last_write: 0,
        bytes: 0,
        generations: [
            telemetry_member(&api).unwrap(),
            telemetry_member(&trace).unwrap(),
        ],
    };
    let stale = pair_at();
    handles.append(&api, b"{}\n").unwrap();
    assert!(!unlink_telemetry_pair_locked(&mut handles, &dir, &stem, &stale).unwrap());
    assert_eq!(handles.open.len(), 2);
    let pair = pair_at();
    fail_telemetry_unlink_for_test(2);
    assert!(unlink_telemetry_pair_locked(&mut handles, &dir, &stem, &pair).is_err());
    assert!(!api.exists());
    assert!(trace.exists());
    assert!(handles.open.is_empty());
    handles.append(&trace, b"{}\n").unwrap();
    fs::remove_file(&trace).unwrap();
    // Leave one present member so the pair still exists; trace is absent but cached.
    fs::write(&api, b"{}\n").unwrap();
    let pair = pair_at();
    assert!(unlink_telemetry_pair_locked(&mut handles, &dir, &stem, &pair).unwrap());
    assert!(handles.open.is_empty());
    assert!(!api.exists() && !trace.exists());
}

/// [regress] A request already admitted but waiting on the owner cannot recreate
/// evidence after uninstall; an intervening cycle clear never resets the fence.
#[test]
fn uninstall_refuses_waiting_request_even_after_clear() {
    let dir = ScratchDir::new("append-disabled");
    let owner = Mutex::new(handles(2));
    let mut guard = owner.lock().unwrap();
    append(&mut guard, &dir, "before");
    std::thread::scope(|scope| {
        let (admitted, wait) = std::sync::mpsc::channel();
        let owner_ref = &owner;
        let dir_ref: &Path = &dir;
        let waiting = scope.spawn(move || {
            admitted.send(()).unwrap();
            let mut handles = owner_ref.lock().unwrap();
            append_rows(
                &mut handles,
                dir_ref,
                [("waiting", evidence_path(dir_ref, "waiting"), &1)],
            )
        });
        wait.recv().unwrap();
        guard.disable();
        guard.clear();
        assert!(guard.disabled && guard.open.is_empty());
        fs::remove_dir_all(dir.join("local-otel")).unwrap();
        drop(guard);
        assert!(waiting.join().unwrap().is_err());
    });
    assert!(!dir.join("local-otel").exists());
}

/// [regress] An opened-file write error evicts and propagates its original cause;
/// the batch is not replayed. The next request is free to open a new writer.
#[test]
fn write_error_evicts_and_preserves_error() {
    let dir = ScratchDir::new("append-write-error");
    let mut handles = handles(2);
    let path = append(&mut handles, &dir, "error");
    handles.open[0].file = File::open(&path).unwrap(); // Same identity, read-only fd.
    let error = handles.append(&path, b"must not replay\n").unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(libc::EBADF)
    );
    assert!(handles.open.is_empty());
    append(&mut handles, &dir, "error");
    assert_eq!(handles.opens, 2);
    assert_eq!(
        fs::read(path).unwrap(),
        b"{\"row\":\"error\"}\n{\"row\":\"error\"}\n"
    );
}

/// [regress] Descriptor exhaustion releases one cached file and retries once.
#[test]
fn descriptor_exhaustion_evicts_one_and_retries() {
    for code in [libc::EMFILE, libc::ENFILE] {
        let dir = ScratchDir::new("append-descriptors");
        let mut handles = handles(3);
        append(&mut handles, &dir, "a");
        let b = append(&mut handles, &dir, "b");
        handles.open_error = Some(code);
        let c = append(&mut handles, &dir, "c");
        assert_eq!(handles.opens, 4);
        assert_eq!(
            handles.open.iter().map(|e| &e.path).collect::<Vec<_>>(),
            [&b, &c]
        );
    }
}

/// [regress] First open and later cache hits preserve private file/dir modes.
#[test]
fn permissions_remain_private() {
    let dir = ScratchDir::new("append-permissions");
    let mut handles = handles(2);
    let path = append(&mut handles, &dir, "mode");
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
    append(&mut handles, &dir, "mode");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

/// [regress] Frozen JSONL bytes retain order, repeated roots and internal filtering
/// across cache hits and cycle release, matching today's encoding exactly.
#[test]
fn appended_bytes_match_golden() {
    let dir = ScratchDir::new("append-golden");
    let mut handles = handles(2);
    let internal = crate::internal_session::internal_session_id();
    let one = serde_json::json!({"count": 1, "text": "a\nb"});
    let two = serde_json::json!({"count": 2, "text": "é"});
    let path = evidence_path(&dir, "golden");
    let rows = || {
        [
            ("golden", path.clone(), &one),
            (internal.as_str(), evidence_path(&dir, &internal), &two),
            ("golden", path.clone(), &two),
        ]
    };
    assert_eq!(append_rows(&mut handles, &dir, rows()).unwrap(), 2);
    assert_eq!(append_rows(&mut handles, &dir, rows()).unwrap(), 2);
    handles.clear();
    assert_eq!(append_rows(&mut handles, &dir, rows()).unwrap(), 2);
    let golden = "{\"count\":1,\"text\":\"a\\nb\"}\n{\"count\":2,\"text\":\"é\"}\n";
    assert_eq!(fs::read(path).unwrap(), golden.repeat(3).as_bytes());
    assert!(!evidence_path(&dir, &internal).exists());
}
