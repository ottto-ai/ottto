// Shared loopback helpers and bounded checkpoint coverage.
fn bounded_native_device() -> LocalDeviceBinding {
    LocalDeviceBinding {
        device_id: "synthetic".into(),
        machine_id: Some("a".repeat(64)),
        sources: vec!["codex".into()],
    }
}
fn bounded_native_response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    use std::io::Write;
    write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
}
const ENLARGING_FILLER_FILES: usize = 1_000;

fn enlarging_filler_key(n: usize) -> String {
    format!(
        "/synthetic/filler/.codex/sessions/2026/10/21/\
         rollout-2026-10-21T05-43-00-0199f0a1-2b3c-7d4e-8f90-{n:012}.jsonl"
    )
}

fn add_enlarging_filler(index: &mut ScanIndex) {
    for n in 0..ENLARGING_FILLER_FILES {
        index.files.insert(
            enlarging_filler_key(n),
            crate::snapshots::ScanIndexEntry {
                size_bytes: 1_000_000,
                modified_unix_seconds: 1_792_540_800,
                source_file_fingerprint: format!("sha256:{}", "f".repeat(64)),
                ..Default::default()
            },
        );
    }
}

fn bounded_native_enlarged_by_filler() -> SameSourceAckFixture {
    let mut f = SameSourceAckFixture::new();
    add_enlarging_filler(&mut f.baseline);
    f.baseline.save(&f.index_path).unwrap();
    add_enlarging_filler(&mut f.working);
    f.working.generation = f.baseline.generation;
    assert!(
        std::fs::metadata(&f.index_path).unwrap().len()
            > crate::snapshot_retry::RESPONSE_BYTES as u64
    );
    f
}

// #660: the bounded checkpoint's capped read refuses the enlarged index
// with an error: the index and progress files are byte-identical (no
// truncation), and the durable ACK is still settled by the ordinary
// checkpoint afterwards (no ACK or debt loss).
#[test]
fn bounded_checkpoint_cap_refuses_an_enlarged_index_without_truncation_or_ack_loss() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut f = bounded_native_enlarged_by_filler();
    f.send(0, same_source_fixture_ack).unwrap();
    let accepted = f.progress.accepted_fingerprints.len();
    let index = std::fs::read(&f.index_path).unwrap();
    let progress = std::fs::read(&f.progress_path).unwrap();
    let result = checkpoint_partial_snapshot_index_with_audit_release(
        &f.working,
        &f.baseline,
        &f.progress,
        &f.items,
        None,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
        Some(crate::snapshot_retry::RESPONSE_BYTES),
        None,
        None,
        Default::default(),
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(&f.index_path).unwrap(), index);
    assert_eq!(std::fs::read(&f.progress_path).unwrap(), progress);

    assert_eq!(f.checkpoint_boundary(|| Ok(())).unwrap(), 1);
    f.restart_preparation();
    assert_eq!(f.progress.accepted_fingerprints.len(), accepted);
    assert!(f.baseline.files.contains_key(&f.keys[0]));
    assert!((0..ENLARGING_FILLER_FILES)
        .all(|n| f.baseline.files.contains_key(&enlarging_filler_key(n))));
}
