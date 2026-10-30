//! Exact retired pins, pre-input caps, carry, and native settlement.
use super::*;

fn old_pin(source: SnapshotSource) -> store::Digest32 {
    store::parse_hex_digest(match source {
        SnapshotSource::ClaudeCode => {
            "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c"
        }
        SnapshotSource::Codex => "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1",
        SnapshotSource::Pi => unreachable!("Pi has no retired registered pin"),
    })
    .unwrap()
}
fn retire_fixture_pin(path: &Path, source: SnapshotSource) {
    let mut bytes = fs::read(path).unwrap();
    bytes[10..42].copy_from_slice(&old_pin(source));
    let end = bytes.len() - 32;
    let trailer = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&trailer);
    fs::write(path, bytes).unwrap();
}

/// Portable store/cache fixture: writes the historical envelope independently
/// of the new decoder. No native heap-layout admission is needed here.
struct Cohort {
    root: crate::test_scratch::ScratchDir,
    source: SnapshotSource,
    index_path: PathBuf,
    cache: SharedCache,
    index: ScanIndex,
    paths: Vec<PathBuf>,
}
impl Cohort {
    fn new(source: SnapshotSource, files: usize) -> Self {
        let root = crate::test_scratch::ScratchDir::new("repin-cohort");
        let index_path = root.join("index.json");
        let cache = SharedCache::default();
        let namespace = Scope("repin-fixture".into());
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        let ds = durable_source(source).unwrap();
        let dir = store::store_dir_for_index(&index_path);
        fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let mut index = ScanIndex::default();
        let paths = (0..files)
            .map(|n| {
                let path = root.join(format!("file-{n}.jsonl"));
                fs::write(&path, b"{}\n").unwrap();
                let key = local_index_key(&path);
                index.files.insert(key.clone(), serde_json::from_value(serde_json::json!({
                "size_bytes":3,"modified_unix_seconds":1,"source_file_fingerprint":"accepted"
            })).unwrap());
                let mut binding = store::tests::binding("account", "old", ("accepted", None));
                binding.source = ds;
                binding.key = store::key_digest(ds, &key);
                binding.context = store::context_digest(&namespace.0, None);
                let mut record = store::tests::pending(binding, certificate(&path, &namespace), 1);
                record.allowlist = old_pin(source);
                let bytes = store::tests::pinned_v1_bytes(&record, 0);
                let record_path = dir.join(format!(
                    "{}.rec",
                    record
                        .binding
                        .key
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ));
                fs::write(&record_path, bytes).unwrap();
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
                path
            })
            .collect();
        Self {
            root,
            source,
            index_path,
            cache,
            index,
            paths,
        }
    }
    fn grow(&self, n: usize) -> File {
        use std::io::Write;
        let path = &self.paths[n];
        fs::OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(b"{}\n")
            .unwrap();
        File::open(path).unwrap()
    }
    fn plan(&self, n: usize, file: &File) -> RepinPlan {
        self.cache.repin_plan(
            self.source,
            &local_index_key(&self.paths[n]),
            file,
            &self.index,
        )
    }
}

#[test]
fn repin_quiet_has_zero_source_input_and_grown_starts_exactly_once_off_and_on() {
    if !crate::test_isolation::run_here() {
        return;
    }
    for on in [false, true] {
        let _policy = if on {
            RestartRestoreForTest::enabled()
        } else {
            RestartRestoreForTest::disabled()
        };
        for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
            let f = Cohort::new(source, 1);
            let file = File::open(&f.paths[0]).unwrap();
            let ((plan, reads), samples) =
                crate::transcript_acquisition::capture_sample_reads(|| {
                    capture_rederive_reads(|| f.plan(0, &file))
                });
            assert!(plan == RepinPlan::Quiet);
            assert_eq!(reads, 0);
            assert!(samples.is_empty());
            assert!(f.cache.durable().unwrap().retail_full_at.is_empty());
            let file = f.grow(0);
            assert!(f.plan(0, &file) == RepinPlan::Ready);
            let key = local_index_key(&f.paths[0]);
            assert!(f.cache.repin_start(source, &key, &file));
            assert!(!f.cache.repin_start(source, &key, &file));
            assert_eq!(f.index.files[&key].size_bytes, 3);
            let stores = f.cache.durable().unwrap();
            assert_eq!(stores.counters.resource_full.get("repin"), Some(&1));
            assert!(owed::key_debt_node_bytes().unwrap() <= 1024);
        }
    }
}

#[test]
fn repin_file_cap_carries_without_spending_and_next_pass_completes_admission() {
    if !crate::test_isolation::run_here() {
        return;
    }
    for on in [false, true] {
        let _policy = if on {
            RestartRestoreForTest::enabled()
        } else {
            RestartRestoreForTest::disabled()
        };
        let f = Cohort::new(SnapshotSource::ClaudeCode, 65);
        for n in 0..64 {
            let file = f.grow(n);
            assert!(f.plan(n, &file) == RepinPlan::Ready);
            assert!(f
                .cache
                .repin_start(f.source, &local_index_key(&f.paths[n]), &file));
        }
        let file = f.grow(64);
        file.set_modified(SystemTime::now() - std::time::Duration::from_secs(86401))
            .unwrap();
        assert!(f.plan(64, &file) == RepinPlan::Ready);
        let key = local_index_key(&f.paths[64]);
        let (started, rows) = crate::local_resource_diagnostics::capture(|| {
            f.cache.repin_start(f.source, &key, &file)
        });
        assert!(!started);
        assert!(rows
            .iter()
            .any(|r| r["counts"]["repin_carry_over_24h"] == 1));
        assert_eq!(
            f.index.files[&key].size_bytes, 3,
            "deferred growth stays discoverable"
        );
        assert!(!f
            .cache
            .durable()
            .unwrap()
            .retail_full_at
            .contains_key(&full_pace_key(f.source, &key)));
        f.cache.durable_begin_pass(
            f.source,
            &f.index_path,
            &Scope("repin-fixture".into()),
            false,
        );
        assert!(f.plan(64, &file) == RepinPlan::Ready);
        assert!(f.cache.repin_start(f.source, &key, &file));
        f.cache.repin_input(f.source, &key, 6, true);
        let (_, rows) =
            crate::local_resource_diagnostics::capture(|| f.cache.repin_report(f.source));
        assert!(rows
            .iter()
            .any(|r| r["counts"]["repin_oldest_carried_age_seconds"] == 0));
        assert!(f.root.exists());
    }
}

#[test]
fn repin_byte_cap_has_no_first_file_escape_and_counts_partial_error_input() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let _policy = RestartRestoreForTest::enabled();
    let f = Cohort::new(SnapshotSource::ClaudeCode, 2);
    let file = f.grow(0);
    fs::OpenOptions::new()
        .write(true)
        .open(&f.paths[0])
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    assert!(f.plan(0, &file) == RepinPlan::Ready);
    assert!(!f
        .cache
        .repin_start(f.source, &local_index_key(&f.paths[0]), &file));
    let file = f.grow(1);
    let key = local_index_key(&f.paths[1]);
    assert!(f.plan(1, &file) == RepinPlan::Ready);
    assert!(f.cache.repin_start(f.source, &key, &file));
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        f.cache.repin_input(f.source, &key, 2, false);
        f.cache.repin_input(f.source, &key, 1, false);
    });
    assert_eq!(
        rows.iter()
            .map(|r| r["counts"]["repin_full_bytes"].as_u64().unwrap_or(0))
            .sum::<u64>(),
        3
    );
    assert!(rows.iter().all(|r| r["counts"]["repin_completed"] == 0));
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn repin_native_full_then_successor_quiet_restart_and_tail_off_and_on() {
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for on in [false, true] {
        let _warm_policy = RestartRestoreForTest::enabled();
        let f = O3Fixture::from_rows(&a1a_row("accepted", 100), false);
        retire_fixture_pin(&f.record_path, SnapshotSource::ClaudeCode);
        let _policy = if on {
            RestartRestoreForTest::enabled()
        } else {
            RestartRestoreForTest::disabled()
        };
        let owner = f.owner();
        let mut prior = f.prior.clone();
        let ((_, quiet, modes), bytes) = observe_consumed(|| f.scan(&owner, &mut prior));
        assert_eq!(bytes, 0);
        assert_eq!(modes, (0, 0, 0));
        assert!(quiet.snapshots.is_empty());
        f.append("growth", 200);
        let ((mut index, mut scan, modes), bytes) = observe_consumed(|| f.scan(&owner, &mut prior));
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(bytes, fs::metadata(&f.path).unwrap().len());
        assert!(!scan.snapshots.is_empty());
        a1a_wire(&f.root, &mut index, &mut scan);
        f.commit(&owner, &mut index, &scan);
        let ds = DurableSource::ClaudeCode;
        let mut disk = DurableTailStore::new(store::store_dir_for_index(&f.index_path), ds);
        let ReadOutcome::Found(record) = disk.read(&store::key_digest(ds, &f.key)) else {
            panic!("durable successor")
        };
        assert_eq!(record.record.allowlist, ds.properties().allowlist());
        let restarted = f.owner();
        let ((_, quiet, modes), bytes) = observe_consumed(|| f.scan(&restarted, &mut index));
        assert_eq!(bytes, 0);
        assert_eq!(modes.0, 0);
        assert!(quiet.snapshots.is_empty());
        f.append("tail", 300);
        let ((_, scan, modes), _) = observe_consumed(|| f.scan(&restarted, &mut index));
        assert_eq!(modes, (0, 1, 0));
        assert!(!scan.snapshots.is_empty());
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn repin_native_over_cap_keeps_extent_and_next_pass_completes() {
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for on in [false, true] {
        let _warm = RestartRestoreForTest::enabled();
        let f = O3Fixture::from_rows(&a1a_row("accepted", 100), false);
        retire_fixture_pin(&f.record_path, SnapshotSource::ClaudeCode);
        f.append("growth", 200);
        let _policy = if on {
            RestartRestoreForTest::enabled()
        } else {
            RestartRestoreForTest::disabled()
        };
        let owner = f.owner();
        owner
            .cache
            .repin_fill_pass_for_test(SnapshotSource::ClaudeCode);
        let mut prior = f.prior.clone();
        let ((held, scan, _), bytes) = observe_consumed(|| f.scan(&owner, &mut prior));
        assert_eq!(bytes, 0);
        assert!(scan.snapshots.is_empty());
        assert_eq!(
            held.files[&f.key].size_bytes,
            f.prior.files[&f.key].size_bytes
        );
        assert!(fs::metadata(&f.path).unwrap().len() > held.files[&f.key].size_bytes);
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            owner.cache.repin_report(SnapshotSource::ClaudeCode)
        });
        assert!(rows
            .iter()
            .any(|r| r["counts"]["repin_carried_files"].as_u64().unwrap_or(0) > 0));
        owner.begin_durable(SnapshotSource::ClaudeCode, &f.root, &f.index_path);
        let mut prior = held;
        let ((mut index, mut scan, modes), bytes) = observe_consumed(|| f.scan(&owner, &mut prior));
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(bytes, fs::metadata(&f.path).unwrap().len());
        a1a_wire(&f.root, &mut index, &mut scan);
        f.commit(&owner, &mut index, &scan);
        assert_eq!(index.files[&f.key].size_bytes, bytes);
        assert!(!owner
            .cache
            .repin_pending(SnapshotSource::ClaudeCode, &f.key));
    }
}

#[test]
fn repin_cold_growth_survives_age_filters_and_partial_retry_uses_shared_pace() {
    if !crate::test_isolation::run_here() {
        return;
    }
    for on in [false, true] {
        let _policy = if on {
            RestartRestoreForTest::enabled()
        } else {
            RestartRestoreForTest::disabled()
        };
        let f = Cohort::new(SnapshotSource::Codex, 1);
        let file = f.grow(0);
        file.set_modified(SystemTime::now() - std::time::Duration::from_secs(40 * 86400))
            .unwrap();
        let key = local_index_key(&f.paths[0]);
        let recovery = DiscoveryRecovery {
            files: &f.index.files,
            cache: Some(&f.cache),
        };
        assert!(
            recovery.requires(f.source, &f.paths[0], 6),
            "cold old-pin growth is discoverable before any admission"
        );
        let now = unix_seconds(SystemTime::now()).unwrap();
        let mut census = ScanCensus::default();
        assert!(candidate_from_traversal_path(
            f.source,
            ScanTraversalPath {
                scan_root: f.root.to_path_buf(),
                path: f.paths[0].clone(),
                census_member: true,
                watcher_hint: false,
            },
            &mut census,
            Some(now),
            1,
            recovery
        )
        .is_some());
        assert!(f.plan(0, &file) == RepinPlan::Ready);
        let at = SystemTime::now();
        f.cache.durable().unwrap().retail_full_now = Some(at);
        assert!(f.cache.repin_start(f.source, &key, &file));
        f.cache.repin_input(f.source, &key, 1, false);
        f.cache.durable_begin_pass(
            f.source,
            &f.index_path,
            &Scope("repin-fixture".into()),
            false,
        );
        assert!(f.plan(0, &file) == RepinPlan::Ready);
        assert!(
            !f.cache.repin_start(f.source, &key, &file),
            "a new pass never refunds spent shared pace"
        );
        assert!(f.cache.owes_discovery(f.source, &key));
        f.cache.durable().unwrap().retail_full_now =
            Some(at + std::time::Duration::from_secs(PACE_SECS));
        assert!(
            f.cache.repin_start(f.source, &key, &file),
            "paced failures have a concrete retry exit"
        );
        assert_eq!(f.index.files[&key].size_bytes, 3);
    }
}

#[test]
fn repin_repaired_mode_refusal_has_a_funded_held_counter_slot() {
    if !crate::test_isolation::run_here() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let _on = RestartRestoreForTest::enabled();
    let mut f = Cohort::new(SnapshotSource::Codex, 1);
    let _lock = test_locks::hold(&f.root);
    let file = f.grow(0);
    let key = local_index_key(&f.paths[0]);
    let digest = store::key_digest(DurableSource::Codex, &key);
    let name = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let disk = store::store_dir_for_index(&f.index_path).join(format!("{name}.rec"));
    fs::set_permissions(&disk, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(f.plan(0, &file) == RepinPlan::Ordinary);
    let held = f
        .cache
        .durable_funded_guard(f.source, &key, |cache| {
            cache.durable_hold(f.source, &key, &f.index, &mut None)
        })
        .unwrap();
    assert_eq!(held, Some(store::Refusal::Repin));
    let mut census = ScanCensus::default();
    let candidate = candidate_from_traversal_path(
        f.source,
        ScanTraversalPath {
            scan_root: f.root.to_path_buf(),
            path: f.paths[0].clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut census,
        None,
        183,
        DiscoveryRecovery::from(&f.index.files),
    )
    .unwrap();
    f.cache.durable_hold_exit(
        f.source,
        held.unwrap(),
        &mut f.index,
        &candidate,
        &mut census,
    );
    assert_eq!(
        f.cache.durable().unwrap().counters.durable_held[store::Refusal::Repin as usize],
        1
    );
    assert!(
        f.plan(0, &file) == RepinPlan::Ready,
        "the repaired mode has a next-pass recovery exit"
    );
}

#[test]
fn repin_ready_members_pass_the_final_group_guard_off_and_on() {
    if !crate::test_isolation::run_here() {
        return;
    }
    for on in [false, true] {
        let _policy = if on {
            RestartRestoreForTest::enabled()
        } else {
            RestartRestoreForTest::disabled()
        };
        let f = Cohort::new(SnapshotSource::Codex, 2);
        for n in 0..2 {
            let file = f.grow(n);
            let key = local_index_key(&f.paths[n]);
            assert_eq!(
                f.cache
                    .durable_member_hold(f.source, &key, &f.index, &mut None)
                    .unwrap(),
                Some(store::Refusal::Repin)
            );
            assert!(f.plan(n, &file) == RepinPlan::Ready);
            assert!(f.cache.repin_start(f.source, &key, &file));
            let mut due = None;
            assert_eq!(
                f.cache
                    .durable_member_hold(f.source, &key, &f.index, &mut due)
                    .unwrap(),
                None
            );
            assert_eq!(due, None);
        }
    }
}

#[test]
fn repin_codex_singleton_applies_a_valid_trailing_record_only_at_unchanged_eof() {
    if !crate::test_isolation::run_here() {
        return;
    }
    use std::io::Write;
    let source = SnapshotSource::Codex;
    for grow in [false, true] {
        let root = crate::test_scratch::ScratchDir::new("repin-trailing-codex");
        let path = root.join("source.jsonl");
        codex_budget_fixture(&path, "019fa111-2222-7333-8444-555555555555", None);
        let mut bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.pop(), Some(b'\n'));
        fs::write(&path, &bytes).unwrap();
        let mut cold = owned_parser(source, &path, File::open(&path).unwrap());
        while !cold.step().unwrap() {}
        let expected = codec::encode(
            &cold.durable_test_reduction_copy(),
            store::BODY_BYTES,
            jsonl_line_cap() as u64,
        )
        .unwrap();
        let mut parser = owned_parser(source, &path, File::open(&path).unwrap());
        parser.reader.set_extent_limit(bytes.len() as u64);
        while !parser.step().unwrap() {}
        assert!(parser.reader.sealed_fragment());
        if grow {
            fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"\n")
                .unwrap();
        }
        parser.apply_repin_eof(bytes.len() as u64);
        assert_eq!(parser.reader.sealed_fragment(), grow);
        let actual = codec::encode(
            &parser.durable_test_reduction_copy(),
            store::BODY_BYTES,
            jsonl_line_cap() as u64,
        )
        .unwrap();
        if grow {
            assert_ne!(
                actual, expected,
                "later appended bytes do not authorize applying the frozen fragment"
            );
        } else {
            assert_eq!(
                actual, expected,
                "native complete totals include the trailing usage row"
            );
        }
    }
}
