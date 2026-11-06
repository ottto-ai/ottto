fn independent_fixture(tag: &str, members: &[u64]) -> (PathBuf, Vec<u64>) {
    let root = temp_root(tag);
    let mut decoded = Vec::new();
    for (i, requests) in members.iter().enumerate() {
        let extra = if i == 0 {
            json!({})
        } else {
            json!({"history_base": {"thread_id": OWNER, "end_ordinal_exclusive": 1, "end_byte_offset": 1}})
        };
        let mut rows = vec![
            meta(OWNER, &format!("2026-10-01T09:0{i}:00Z"), extra),
            turn(&format!("t-{i}")),
        ];
        for n in 1..=*requests {
            // The revert counter starts at an earlier base, while the original
            // has billed turns beyond it. Last usage is each file's own money.
            let base = if i == 0 { 0 } else { 37 };
            rows.push(native(
                OWNER,
                &format!("r-{i}-{n}"),
                100 + i as u64,
                base + n * (100 + i as u64),
            ));
            rows.push(ui(
                100 + i as u64,
                base + n * (100 + i as u64),
                "2026-10-01T10:00:00Z",
            ));
        }
        let bytes = rows
            .iter()
            .map(|row| row.to_string() + "\n")
            .collect::<String>()
            .into_bytes();
        decoded.push(bytes.len() as u64);
        fs::write(
            root.join("sessions").join(format!(
                "rollout-2026-10-01T09-0{i}-00-{OWNER}_00000000-0000-4000-8000-{i:012}.jsonl.zst"
            )),
            zstd::stream::encode_all(bytes.as_slice(), 1).unwrap(),
        )
        .unwrap();
    }
    (root, decoded)
}

fn independent_boot(
    root: &Path,
    order: usize,
    index: &ScanIndex,
    cache: &Arc<SharedCache>,
) -> GroupBoot {
    let paths = fs::read_dir(root.join("sessions"))
        .unwrap()
        .map(|entry| local_index_key(&entry.unwrap().path()))
        .collect();
    let inventory = super::super::super::header_cache_tests::page(root, &paths, cache);
    assert!(inventory.complete);
    let mut group = inventory.groups().into_values().next().unwrap();
    if order % 2 == 1 {
        group.members.reverse();
    }
    let len = group.members.len();
    group.members.rotate_left((order / 2) % len);
    let mut boot = GroupBoot::new(group, index);
    loop {
        match boot.step_with_cache(None, index, Some(cache)) {
            Boot::Pending => {}
            Boot::Ready => return boot,
            _ => panic!("independent group boot held"),
        }
    }
}

fn finish_independent(mut job: Box<OwnedActiveFile>) -> Vec<SnapshotItem> {
    let contributions = std::mem::take(&mut job.group.as_mut().unwrap().contributions);
    let mut parsed = job
        .parser
        .finish_boxed_native(
            FinishRequest {
                expected_opened_object_identity: &job.candidate.opened_object_identity,
                path: &job.candidate.path,
                collected_at: "2026-10-06T23:00:00Z",
                source_file_fingerprint: job.source_file_fingerprint,
                codex_title_metadata: Some(&CodexTitleMetadata::default()),
                claude_title_metadata: None,
                attribution_context: None,
                repository_identity: None,
                money_context: None,
            },
            None,
        )
        .unwrap();
    assert!(parsed.progress_complete());
    fold_independent(&mut parsed.snapshots, contributions).unwrap();
    parsed.snapshots
}

/// [money] Independent compressed reverts retain the original's billed suffix,
/// with one actual decoder pass per member and no publication between members.
#[test]
fn compressed_revert_sums_are_order_independent_and_read_each_member_once() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    for requests in [&[8, 88][..], &[8, 3, 2][..]] {
        let (root, decoded) = independent_fixture("independent-sums", requests);
        let index = ScanIndex::default();
        let mut prior = None;
        for order in 0..2 {
            let cache = Arc::new(SharedCache::default());
            let metadata = CodexTitleMetadata::default();
            let boot = independent_boot(&root, order, &index, &cache);
            let mut job = boot
                .into_job(JobInputs {
                    metadata: &metadata,
                    traces: None,
                    index: &index,
                    cache: Some(&cache),
                })
                .unwrap();
            let no_scope = |_: &CandidateFile| None;
            let inputs = StepInputs {
                metadata: &metadata,
                attribution: None,
                live_scope: &no_scope,
                cache: Some(&cache),
                collected_at: "2026-10-06T23:00:00Z",
                index: &index,
            };
            let ((), bytes) = observe_consumed(|| {
                for _ in 0..100_000 {
                    match step_group(&mut job, &inputs) {
                        GroupStep::Read(Ok(true)) => return,
                        GroupStep::Read(Ok(false)) => {}
                        _ => panic!("independent replay held"),
                    }
                }
                panic!("independent replay did not finish");
            });
            assert_eq!(
                bytes,
                decoded.iter().sum::<u64>(),
                "each member is decoded once"
            );
            assert!(
                index.files.is_empty(),
                "unfinished acquisition commits no index member"
            );
            let items = finish_independent(job);
            assert_eq!(items.len(), 1);
            let item = &items[0];
            assert_eq!(item.request_count, requests.iter().sum::<u64>());
            assert_eq!(
                item.input_tokens,
                requests
                    .iter()
                    .enumerate()
                    .map(|(i, n)| n * (100 + i as u64))
                    .sum::<u64>()
            );
            let money = serde_json::to_value((
                &item.model_usage,
                &item.usage_buckets,
                item.input_tokens,
                item.request_count,
            ))
            .unwrap();
            if let Some(expected) = &prior {
                assert_eq!(&money, expected);
            } else {
                prior = Some(money);
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
}

/// [money] A process loss between members gives no member delivery credit.
/// The next attempt starts from byte zero, counted once again, with no singleton.
#[test]
fn independent_restart_between_members_discards_unfinished_proof() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    let (root, decoded) = independent_fixture("independent-restart", &[8, 88]);
    let index = ScanIndex::default();
    let cache = Arc::new(SharedCache::default());
    let metadata = CodexTitleMetadata::default();
    let boot = independent_boot(&root, 0, &index, &cache);
    let mut job = boot
        .into_job(JobInputs {
            metadata: &metadata,
            traces: None,
            index: &index,
            cache: Some(&cache),
        })
        .unwrap();
    let no_scope = |_: &CandidateFile| None;
    let inputs = StepInputs {
        metadata: &metadata,
        attribution: None,
        live_scope: &no_scope,
        cache: Some(&cache),
        collected_at: "2026-10-06T23:00:00Z",
        index: &index,
    };
    while job.group.as_ref().unwrap().current == 0 {
        assert!(matches!(
            step_group(&mut job, &inputs),
            GroupStep::Read(Ok(false))
        ));
    }
    assert_eq!(job.group.as_ref().unwrap().contributions.len(), 1);
    drop(job);
    drop(cache);
    assert!(index.files.is_empty());
    let cache = Arc::new(SharedCache::default());
    let boot = independent_boot(&root, 0, &index, &cache);
    let mut job = boot
        .into_job(JobInputs {
            metadata: &metadata,
            traces: None,
            index: &index,
            cache: Some(&cache),
        })
        .unwrap();
    let inputs = StepInputs {
        metadata: &metadata,
        attribution: None,
        live_scope: &no_scope,
        cache: Some(&cache),
        collected_at: "2026-10-06T23:00:00Z",
        index: &index,
    };
    let (_, bytes) = observe_consumed(|| loop {
        match step_group(&mut job, &inputs) {
            GroupStep::Read(Ok(true)) => break,
            GroupStep::Read(Ok(false)) => {}
            _ => panic!("restart held"),
        }
    });
    assert_eq!(bytes, decoded.iter().sum::<u64>());
    assert_eq!(finish_independent(job)[0].request_count, 96);
    fs::remove_dir_all(root).unwrap();
}

/// [money] A repeated admitted occurrence or a conflicting session header
/// holds the whole group. A rejected group never publishes a singleton.
#[test]
fn independent_overlap_and_conflict_hold_without_singleton() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    for conflicting in [false, true] {
        let (root, _) = independent_fixture("independent-overlap", &[1, 1]);
        let mut paths = fs::read_dir(root.join("sessions"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        let decode = |p: &Path| zstd::stream::decode_all(File::open(p).unwrap()).unwrap();
        let first = decode(&paths[0]);
        let mut second = decode(&paths[1])
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        let original = first
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        if conflicting {
            second.push(meta(OTHER, "2026-10-01T10:01:00Z", json!({})));
        } else {
            second[3] = original[3].clone();
        }
        let bytes = second
            .iter()
            .map(|r| r.to_string() + "\n")
            .collect::<String>();
        fs::write(
            &paths[1],
            zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap(),
        )
        .unwrap();
        let cache = Arc::new(SharedCache::default());
        let (_, scan) = sampled(&root, ScanIndex::default(), 10, &cache);
        assert!(
            scan.snapshots.is_empty(),
            "held group must not emit either singleton"
        );
        assert!(scan.ownership_incomplete_file_count >= 2);
        fs::remove_dir_all(root).unwrap();
    }
}

/// [money] A partial member is missing proof, not a neutral usage stub.
#[test]
fn independent_partial_member_holds_the_entire_group() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    let (root, _) = independent_fixture("independent-partial", &[8, 88]);
    let path = fs::read_dir(root.join("sessions"))
        .unwrap()
        .last()
        .unwrap()
        .unwrap()
        .path();
    let mut body = zstd::stream::decode_all(File::open(&path).unwrap()).unwrap();
    body.extend_from_slice(b"{broken-json}\n");
    fs::write(path, zstd::stream::encode_all(body.as_slice(), 1).unwrap()).unwrap();
    let cache = Arc::new(SharedCache::default());
    let (_, scan) = sampled(&root, ScanIndex::default(), 10, &cache);
    assert!(scan.snapshots.is_empty());
    assert!(scan.ownership_incomplete_file_count >= 2);
    fs::remove_dir_all(root).unwrap();
}

/// [money] Session features project once from both members' original facts.
#[test]
fn independent_members_keep_tools_distinct_activity_and_artifacts() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    fn facts(acc: &mut SnapshotAccumulator, member: usize) {
        for _ in 0..=member {
            acc.note_activity_tool("exec_command");
        }
        acc.provider_skills.insert(format!("provider-{member}"));
        acc.activity_skills.insert(format!("PROVIDER-{member}"));
        acc.activity_patch_operations += 1;
        acc.activity_lines_added += (member + 1) as u64;
        acc.activity_changed_file_hashes
            .insert("shared-file".into());
        acc.activity_changed_file_hashes
            .insert(format!("own-file-{member}"));
        acc.add_artifacts(vec![
            SessionArtifact {
                kind: "commit".into(),
                value: "1111111111111111111111111111111111111111".into(),
            },
            SessionArtifact {
                kind: "commit".into(),
                value: format!("{:040x}", member + 2),
            },
        ]);
    }
    let (root, _) = independent_fixture("independent-features", &[1, 1]);
    let index = ScanIndex::default();
    let cache = Arc::new(SharedCache::default());
    let metadata = CodexTitleMetadata::default();
    let boot = independent_boot(&root, 0, &index, &cache);
    let mut job = boot
        .into_job(JobInputs {
            metadata: &metadata,
            traces: None,
            index: &index,
            cache: Some(&cache),
        })
        .unwrap();
    let no_scope = |_: &CandidateFile| None;
    let inputs = StepInputs {
        metadata: &metadata,
        attribution: None,
        live_scope: &no_scope,
        cache: Some(&cache),
        collected_at: "2026-10-06T23:00:00Z",
        index: &index,
    };
    let mut seeded = [false; 2];
    loop {
        let member = job.group.as_ref().unwrap().current;
        if !seeded[member] {
            facts(&mut job.parser.accumulator, member);
            seeded[member] = true;
        }
        match step_group(&mut job, &inputs) {
            GroupStep::Read(Ok(true)) => break,
            GroupStep::Read(Ok(false)) => {}
            _ => panic!("feature group held"),
        }
    }
    let items = finish_independent(job);
    assert_eq!(items.len(), 1);
    let mut expected = SnapshotAccumulator::new(SnapshotSource::Codex);
    facts(&mut expected, 0);
    facts(&mut expected, 1);
    let item = &items[0];
    assert_eq!(
        serde_json::to_value(&item.activity_summary).unwrap(),
        serde_json::to_value(expected.activity_summary()).unwrap()
    );
    let (tools, truncated) = codex_tool_usage_rows(
        &expected.activity_tool_counts,
        &expected.activity_mcp_tool_usage_counts,
    );
    assert_eq!(item.tool_usage, Some(tools));
    assert_eq!(item.tool_usage_truncated, truncated);
    expected.artifacts.sort();
    assert_eq!(item.session_artifacts, expected.artifacts);
    assert_eq!(item.activity_summary.as_ref().unwrap().changed_files, 3);
    assert_eq!(item.request_count, 2);
    fs::remove_dir_all(root).unwrap();
}

/// [money] Live revert members hold the entire group before header/decoder IO.
#[test]
fn independent_live_member_holds_zero_bytes_then_seals_and_folds() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    let (root, decoded) = independent_fixture("independent-live", &[8, 88]);
    let mut paths = fs::read_dir(root.join("sessions"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    let archive = paths.last().unwrap();
    let encoded = fs::read(archive).unwrap();
    let plain = archive.with_extension("");
    fs::write(
        &plain,
        zstd::stream::decode_all(encoded.as_slice()).unwrap(),
    )
    .unwrap();
    fs::remove_file(archive).unwrap();
    let cache = Arc::new(SharedCache::default());
    let ((index, held), io) = sampled_scan::transition_fixture::observe_codex_quiet(|| {
        sampled(&root, ScanIndex::default(), 10, &cache)
    });
    assert!(
        held.snapshots.is_empty(),
        "no singleton replaces the accepted body"
    );
    assert!(held.ownership_incomplete_file_count >= 2);
    assert_eq!(io.consumed, 0);
    assert_eq!(
        io.cheap_checks,
        Some(0),
        "no header or decoder read while live"
    );
    fs::write(archive, encoded).unwrap();
    fs::remove_file(plain).unwrap();
    let ((_, folded), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 1));
    assert_eq!(bytes, decoded.iter().sum::<u64>());
    assert_eq!(folded.snapshots.len(), 1);
    assert_eq!(folded.snapshots[0].request_count, 96);
    fs::remove_dir_all(root).unwrap();
}

/// [money] A native-complete but incompatible fold uses existing group refusal
/// custody. An unchanged second generation must not acquire its members again.
#[test]
fn independent_fold_failure_is_memoized_after_one_read_per_member() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    let (root, decoded) = independent_fixture("independent-fold-failure", &[8, 88]);
    let cache = Arc::new(SharedCache::default());
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        ScanIndex::default(),
        "2026-10-06T23:00:00Z",
        7,
        10,
        None,
        &[],
        false,
    )
    .with_sampled_acquisition(Arc::clone(&cache), Scope("group-fixture".into()));
    let mut injected = false;
    let ((index, held), bytes) = observe_consumed(|| {
        for _ in 0..100_000 {
            if let Some(active) = owned.active_file.as_mut() {
                if let Some(group) = active.group.as_mut() {
                    if !injected && !group.contributions.is_empty() {
                        group.contributions[0].model_usage[0]
                            .selector_sources
                            .insert("model".into(), "synthetic-conflicting-provenance".into());
                        injected = true;
                    }
                }
            }
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
            }
        }
        panic!("failed fold never completed");
    });
    assert!(injected);
    assert_eq!(bytes, decoded.iter().sum::<u64>());
    assert!(held.snapshots.is_empty());
    assert!(held.ownership_incomplete_file_count >= 2);
    assert_eq!(counters(&cache).memo_records, 1);
    let ((_, again), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 1));
    assert_eq!(bytes, 0, "memoized failure reads no transcript bytes");
    assert!(again.snapshots.is_empty());
    assert_eq!(counters(&cache).memo_records, 1);
    fs::remove_dir_all(root).unwrap();
}
