// The compact scan index changes which indexes pass the bounded retry's
// on-disk metadata gate (RESPONSE_BYTES, 128 KiB): one whose legacy pretty
// bytes exceed it can now fit. That gate, the independent JSON-size and heap
// gates behind it, and production activation (still off) are unchanged. The
// newly eligible band depends on the data, not a fixed byte interval.

fn compact_band_capture(
    f: &SameSourceAckFixture,
    allowance: usize,
) -> Option<super::bounded_snapshot_retry::PreparedRetry> {
    super::bounded_snapshot_retry::PreparedRetry::capture(
        SnapshotSource::Codex,
        &"a".repeat(64),
        SnapshotUploadPolicy::default(),
        [1; 32],
        std::slice::from_ref(&f.items[0]),
        &f.working,
        &f.baseline,
        &f.progress,
        &f.index_path,
        &f.progress_path,
        Instant::now(),
        Duration::from_secs(60),
        allowance,
    )
}

/// Pads `index` with `rows` synthetic set members so its compact JSON is
/// within `rows` bytes below `target`. Each member sits at depth three, so the
/// pretty encoding spends seven more bytes on it (newline and indent).
fn compact_band_pad(index: &mut ScanIndex, rows: usize, target: usize) {
    const KEY: &str = "/synthetic/compact-band/rollout.jsonl";
    let members = |filler: usize| {
        (0..rows)
            .map(|row| format!("{row:05}{}", "f".repeat(filler)))
            .collect::<BTreeSet<_>>()
    };
    index
        .file_snapshot_fingerprints
        .insert(KEY.to_string(), members(0));
    let unpadded = serde_json::to_vec(index).unwrap().len();
    assert!(unpadded < target);
    index
        .file_snapshot_fingerprints
        .insert(KEY.to_string(), members((target - unpadded) / rows));
}

#[test]
fn bounded_retry_metadata_gate_admits_compact_index_whose_pretty_bytes_exceed_it() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    const ROWS: usize = 800;
    let cap = crate::snapshot_retry::RESPONSE_BYTES;
    let mut f = SameSourceAckFixture::new();
    compact_band_pad(&mut f.baseline, ROWS, cap - 256);
    compact_band_pad(&mut f.working, ROWS, cap - 256);
    // The in-memory JSON-size gates pass for this state in either layout.
    assert!(crate::snapshot_retry::json_fits(&f.baseline, cap));
    assert!(crate::snapshot_retry::json_fits(&f.working, cap));

    // An older daemon left the same generation pretty: the metadata gate
    // refuses before any other gate runs.
    let pretty = serde_json::to_vec_pretty(&f.baseline).unwrap();
    let compact = serde_json::to_vec(&f.baseline).unwrap();
    assert!(pretty.len() > cap, "pretty {} bytes", pretty.len());
    assert!(compact.len() <= cap, "compact {} bytes", compact.len());
    std::fs::write(&f.index_path, &pretty).unwrap();
    assert!(compact_band_capture(&f, 4 * 1024 * 1024).is_none());

    // The next ordinary save writes compact bytes, which pass the gate.
    f.baseline.save(&f.index_path).unwrap();
    f.working.generation = f.baseline.generation;
    let on_disk = std::fs::metadata(&f.index_path).unwrap().len();
    assert!(on_disk <= cap as u64, "compact index {on_disk} bytes");
    let page = compact_band_capture(&f, 4 * 1024 * 1024)
        .expect("compact index within every gate is eligible");
    let bound = page.bound();
    drop(page);

    // The heap gate still runs behind the metadata gate: one byte less
    // allowance than this page's charged bound refuses it.
    assert!(compact_band_capture(&f, bound - 1).is_none());
    assert!(compact_band_capture(&f, bound).is_some());

    // The JSON-size gate still runs too: a working index over the cap is
    // refused while the compact file on disk still passes the metadata gate.
    f.working.resume_after_path = Some("x".repeat(cap));
    assert!(!crate::snapshot_retry::json_fits(&f.working, cap));
    assert_eq!(std::fs::metadata(&f.index_path).unwrap().len(), on_disk);
    assert!(compact_band_capture(&f, 4 * 1024 * 1024).is_none());

    // Eligibility moved; activation did not.
    assert!(!super::bounded_snapshot_retry::production_activation_reviewed());
    eprintln!(
        "compact_band pretty_bytes={} compact_bytes={} on_disk={on_disk} cap={cap} heap_bound={bound}",
        pretty.len(),
        compact.len()
    );
}
