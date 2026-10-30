// Dedicated qualification command for linux-tests.yml's `Rust tests (Linux)` job
// (the dedicated step is not wired by this test-only slice):
// cargo test -p ottto-service --lib ci_import_peak_does_not_exceed_same_corpus_v1_load -- --ignored --nocapture --test-threads=1
// Kept ignored because it measures whole-process RSS in fresh child processes;
// the normal concurrent test lane cannot qualify performance. This is NOT a
// mapper-only surrogate: publication still paused is an explicit test failure.
#[test]
#[ignore = "dedicated Linux import-peak qualification step; production publication required"]
fn ci_import_peak_does_not_exceed_same_corpus_v1_load() {
    const NAME: &str = "snapshots::state_v2::import::application_cases::ci_import_peak_does_not_exceed_same_corpus_v1_load";
    const MODE: &str = "OTTTO_TEST_IMPORT_PEAK_MODE";
    const CORPUS: &str = "OTTTO_TEST_IMPORT_PEAK_PATH";
    if let Ok(mode) = std::env::var(MODE) {
        assert!(matches!(mode.as_str(), "v1" | "v2"));
        let path = PathBuf::from(std::env::var_os(CORPUS).unwrap());
        let support = path.parent().unwrap().parent().unwrap();
        let before = fs::read(&path).unwrap();
        use sha2::Digest;
        println!(
            "S1_IMPORT_CORPUS_SHA256={:x}",
            sha2::Sha256::digest(&before)
        );
        drop(before); // Neither route retains a second source-byte buffer.
        if mode == "v2" {
            sqlite::import_peak_probe::begin();
        }
        let watch = ImportWalWatch::start(&path);
        let (mut index, _) = ScanIndex::load_inner_with_support(
            &path,
            Some(super::super::super::SnapshotSource::ClaudeCode),
            Some(support),
            std::time::SystemTime::now(),
        )
        .unwrap();
        if mode == "v2" {
            assert!(
                index.persistence_v2.is_some(),
                "publication is still paused; cannot qualify import peak"
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap()
                    ["storage_format"],
                2
            );
        } else {
            assert!(index.persistence_v2.is_none());
            // Acceptance baseline is v1 LOAD + SAVE of this exact corpus.
            index.save(&path).unwrap();
        }
        let sampled = watch.finish();
        let committed = if mode == "v2" {
            sqlite::import_peak_probe::finish()
        } else {
            0
        };
        let wal_peak = sampled.max(committed);
        assert!(
            wal_peak <= WAL_ALARM_BYTES,
            "import WAL {wal_peak} > 64 MiB"
        );
        println!("S1_IMPORT_WAL_PEAK_BYTES={wal_peak}");
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        assert_eq!(
            unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
            0
        );
        let peak = u64::try_from(unsafe { usage.assume_init() }.ru_maxrss).unwrap();
        #[cfg(not(target_os = "macos"))]
        let peak = peak.checked_mul(1024).unwrap();
        assert!(peak > 0);
        println!("S1_IMPORT_PEAK_BYTES={peak}");
        std::hint::black_box(index);
        return;
    }
    let source = Corpus::new();
    // Stream the generator so its allocations cannot contaminate either child.
    let mut writer = std::io::BufWriter::new(fs::File::create(&source.path).unwrap());
    writer
        .write_all(br#"{"schema_version":2,"generation":0,"files":{"#)
        .unwrap();
    let entry = super::super::super::tests::manifest_index_entry(Some(&"f".repeat(64)));
    for n in 0..15_000 {
        if n > 0 {
            writer.write_all(b",").unwrap();
        }
        serde_json::to_writer(&mut writer, &format!("synthetic-file-{n}")).unwrap();
        writer.write_all(b":").unwrap();
        serde_json::to_writer(&mut writer, &entry).unwrap();
    }
    // Include the same money-bearing pending/census payload in both arms.
    let shaped: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/scan_index/real-shaped-v1.json"
    ))
    .unwrap();
    writer.write_all(b"}").unwrap();
    for field in [
        "claude_request_census",
        "claude_account_family_pending",
        "claude_usage_family_pending",
        "accepted_snapshot_fingerprints",
    ] {
        writer.write_all(b",").unwrap();
        serde_json::to_writer(&mut writer, field).unwrap();
        writer.write_all(b":").unwrap();
        serde_json::to_writer(&mut writer, &shaped["logical"][field]).unwrap();
    }
    writer.write_all(b"}").unwrap();
    writer.flush().unwrap();
    drop(writer);
    let mut peaks = Vec::new();
    let mut hashes = Vec::new();
    for mode in ["v1", "v2"] {
        // The v1 save MUST NOT replace the v2 arm's input with normalized bytes.
        let arm = Corpus::new();
        fs::copy(&source.path, &arm.path).unwrap();
        fs::set_permissions(&arm.path, fs::Permissions::from_mode(0o600)).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                NAME,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MODE, mode)
            .env(CORPUS, &arm.path)
            .env(
                "OTTTO_CLAUDE_STATE_V2",
                if mode == "v2" { "1" } else { "0" },
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode} peak child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let metric = |name: &str| {
            stdout
                .lines()
                .find_map(|line| {
                    line.split_once(name)
                        .map(|(_, value)| value.trim().to_owned())
                })
                .unwrap_or_else(|| panic!("child did not reach {name}: {stdout}"))
        };
        hashes.push(metric("S1_IMPORT_CORPUS_SHA256="));
        peaks.push(metric("S1_IMPORT_PEAK_BYTES=").parse::<u64>().unwrap());
        let wal = metric("S1_IMPORT_WAL_PEAK_BYTES=").parse::<u64>().unwrap();
        assert!(wal <= WAL_ALARM_BYTES, "{mode} WAL {wal} exceeds 64 MiB");
    }
    assert_eq!(
        hashes[0], hashes[1],
        "both arms must load byte-identical synthetic corpus"
    );
    assert!(
        peaks[1] <= peaks[0],
        "import peak {} exceeds same-corpus v1 load+save peak {}",
        peaks[1],
        peaks[0]
    );
}

/// Poll both journal-off import and published WAL names, including before the
/// first load and after publication. A peak seen at either edge is retained.
struct ImportWalWatch {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<u64>>,
}
impl ImportWalWatch {
    fn start(index: &Path) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let paths =
            [".v2.sqlite.import-wal", ".v2.sqlite-wal"].map(|suffix| fence::sibling(index, suffix));
        let worker = std::thread::spawn(move || {
            let mut peak = 0;
            loop {
                for path in &paths {
                    match fs::metadata(path) {
                        Ok(meta) => peak = peak.max(meta.len()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => panic!("WAL measurement: {e}"),
                    }
                }
                if done.load(Ordering::Acquire) {
                    return peak;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> u64 {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for ImportWalWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
