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

/// [money] A proof refusal in the last sealed member (a repeated admitted
/// occurrence: `Overlap`) is memoized like a strict end. Unchanged, the group
/// stays held and disclosed at zero transcript bytes in every new discovery
/// generation; a member change, or a restart, reads it again.
#[test]
fn independent_last_member_refusal_is_not_reread_each_generation() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    let (root, _) = independent_fixture("independent-last-refusal", &[1, 1]);
    let mut paths = fs::read_dir(root.join("sessions"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    let rows = |p: &Path| {
        zstd::stream::decode_all(File::open(p).unwrap())
            .unwrap()
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>()
    };
    let write = |p: &Path, rows: &[Value]| {
        let bytes = rows
            .iter()
            .map(|r| r.to_string() + "\n")
            .collect::<String>();
        fs::write(p, zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap()).unwrap();
    };
    let mut last = rows(&paths[1]);
    last[3] = rows(&paths[0])[3].clone();
    write(&paths[1], &last);
    let held = |scan: &SourceScanResult| {
        assert!(scan.snapshots.is_empty(), "no singleton, no fold");
        assert!(scan.ownership_incomplete_file_count >= 2, "still disclosed");
    };
    let cache = Arc::new(SharedCache::default());
    let ((mut index, first), bytes) =
        observe_consumed(|| sampled(&root, ScanIndex::default(), 10, &cache));
    held(&first);
    assert!(bytes > 0, "the first attempt reads the group");
    for n in 1..=3 {
        let ((next, again), bytes) = observe_consumed(|| next_generation(&root, index, &cache, n));
        index = next;
        held(&again);
        assert_eq!(bytes, 0, "generation {n} re-reads no transcript bytes");
    }
    assert_eq!(counters(&cache).memo_records, 1, "the refusal is memoized");
    // A changed last member is read again at once (and refused again).
    last.push(turn("t-appended"));
    write(&paths[1], &last);
    let ((next, grown), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 4));
    index = next;
    held(&grown);
    assert!(bytes > 0, "a changed member is re-read");
    assert_eq!(counters(&cache).memo_records, 2);
    let ((next, again), bytes) = observe_consumed(|| next_generation(&root, index, &cache, 5));
    index = next;
    held(&again);
    assert_eq!(bytes, 0);
    // A restart (empty cache) reads the group once more, as before.
    let restarted = Arc::new(SharedCache::default());
    let ((_, again), bytes) = observe_consumed(|| next_generation(&root, index, &restarted, 6));
    held(&again);
    assert!(bytes > 0, "a restart reads the held group again");
    fs::remove_dir_all(root).unwrap();
}

/// [money] Independent members fold only under one raw creator pair. A revert
/// header with a positive ordinal and no fork id certifies no creator yet names
/// its pair; a missing, partial or different pair holds the group, and a
/// certified creator must name its own raw pair.
#[test]
fn independent_header_gate_compares_raw_creator_pairs() {
    let pair = |user: &str, workspace: &str| {
        json!({"creator_user_id": format!("synthetic-user-{user}"),
            "creator_account_id": format!("synthetic-workspace-{workspace}")})
    };
    let original = meta(OWNER, "2026-10-01T09:00:00Z", pair("a", "a"));
    let revert = |creator: Value| {
        let mut extra = json!({"history_base": {"thread_id": OWNER,
            "end_ordinal_exclusive": 1, "end_byte_offset": 1}});
        extra
            .as_object_mut()
            .unwrap()
            .extend(creator.as_object().unwrap().clone());
        let mut header = meta(OWNER, "2026-10-01T09:01:00Z", extra);
        header["ordinal"] = json!(1);
        header
    };
    let gate = |first: &Value, second: &Value| {
        let mut proof = StreamProof::independent(OWNER.into(), 2);
        for (position, header) in [first, second].into_iter().enumerate() {
            proof.begin_member(position);
            feed(&mut proof, std::slice::from_ref(header), [0]);
            proof.end_member(1);
        }
        proof.refusal()
    };
    let same = revert(pair("a", "a"));
    assert!(codex_creator_header_evidence(&original, &original["payload"]).is_some());
    assert!(
        codex_creator_header_evidence(&same, &same["payload"]).is_none(),
        "the revert header certifies no creator"
    );
    assert_eq!(gate(&original, &same), None, "one raw pair folds");
    let held = Some((JoinRefusal::Overlap, 1));
    assert_eq!(gate(&original, &revert(json!({}))), held, "missing pair");
    let partial = json!({"creator_user_id": "synthetic-user-a"});
    assert_eq!(gate(&original, &revert(partial)), held, "partial pair");
    assert_eq!(gate(&original, &revert(pair("b", "a"))), held, "account");
    assert_eq!(gate(&original, &revert(pair("a", "b"))), held, "workspace");
    // Uncertified members alone: one pair, or no pair on any member as before.
    assert_eq!(gate(&revert(pair("a", "a")), &same), None);
    assert_eq!(gate(&revert(json!({})), &revert(json!({}))), None);
    assert_eq!(gate(&revert(json!({})), &same), held, "pair on one only");
    assert_eq!(
        gate(&revert(pair("b", "b")), &same),
        held,
        "different pairs"
    );
    // A certified member's own raw pair must equal its certified evidence.
    let raw = |user: &str, workspace: &str| codex_raw_creator_pair(&pair(user, workspace));
    assert_eq!(
        independent_member_placement(raw("a", "a"), raw("a", "a")),
        Ok(raw("a", "a"))
    );
    assert_eq!(
        independent_member_placement(None, raw("a", "a")),
        Ok(raw("a", "a"))
    );
    assert_eq!(
        independent_member_placement(raw("a", "a"), raw("b", "a")),
        Err(JoinRefusal::Overlap)
    );
    assert_eq!(
        independent_member_placement(raw("a", "a"), None),
        Err(JoinRefusal::Overlap)
    );
}

/// [money] The folded creator evidence is the original member's own certified
/// evidence, byte-identical. A certified later member under an uncertified
/// original holds instead of leaving the folded body without its creator.
#[test]
fn independent_fold_keeps_the_original_certified_evidence() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    let (root, _) = independent_fixture("independent-evidence", &[8, 88]);
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
    loop {
        match step_group(&mut job, &inputs) {
            GroupStep::Read(Ok(true)) => break,
            GroupStep::Read(Ok(false)) => {}
            _ => panic!("independent replay held"),
        }
    }
    let contributions = std::mem::take(&mut job.group.as_mut().unwrap().contributions);
    let parsed = job
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
    let evidence = SessionAccountEvidence {
        provider: "openai",
        account_identifier_hash: Some("a".repeat(64)),
        provider_workspace_hash: Some("b".repeat(64)),
        identity_hash_scheme: "provider-sha256:v1",
        evidence_source: "codex_creator_header:v1",
        identity_disposition: None,
        source_created_at: Some("2026-10-01T09:00:00Z".into()),
    };
    let fold = |certified_original: bool| {
        let mut last = parsed.snapshots.clone();
        let mut earlier = contributions.clone();
        assert!(last.len() == 1 && earlier.len() == 1);
        assert!(
            earlier[0].session_account_evidence.is_none()
                && last[0].session_account_evidence.is_none()
        );
        // `fold` orders by start; equal starts keep the earlier member first.
        let original_is_last = last[0].source_started_at < earlier[0].source_started_at;
        let (original, later) = if original_is_last {
            (&mut last[0], &mut earlier[0])
        } else {
            (&mut earlier[0], &mut last[0])
        };
        if certified_original {
            original.session_account_evidence = Some(evidence.clone());
        } else {
            later.session_account_evidence = Some(evidence.clone());
        }
        fold_independent(&mut last, earlier).map(|()| last)
    };
    let folded = fold(true).unwrap();
    assert_eq!(folded.len(), 1);
    assert_eq!(folded[0].request_count, 96);
    assert_eq!(
        serde_json::to_value(&folded[0].session_account_evidence).unwrap(),
        serde_json::to_value(Some(&evidence)).unwrap(),
        "byte-identical original creator evidence"
    );
    assert!(fold(false).is_err(), "a later creator never binds the fold");
    // Members whose rows take different binder paths hold: a fold never
    // changes which path tags either member's rows.
    let fold_modes = |first: Option<&'static str>, second: Option<&'static str>| {
        let mut last = parsed.snapshots.clone();
        let mut earlier = contributions.clone();
        for (item, mode) in [(&mut earlier[0], first), (&mut last[0], second)] {
            for row in item.model_usage.iter_mut().chain(
                item.usage_buckets
                    .iter_mut()
                    .flat_map(|bucket| bucket.model_usage.iter_mut()),
            ) {
                row.auth_mode = mode.map(str::to_string);
            }
        }
        fold_independent(&mut last, earlier).map(|()| last)
    };
    assert!(fold_modes(None, None).is_ok());
    assert!(fold_modes(Some("chatgpt"), Some("oauth")).is_ok());
    assert!(
        fold_modes(None, Some("chatgpt")).is_err(),
        "unrecorded vs oauth"
    );
    assert!(
        fold_modes(Some("oauth"), None).is_err(),
        "oauth vs unrecorded"
    );
    assert!(
        fold_modes(Some("apikey"), Some("chatgpt")).is_err(),
        "mixed vs oauth"
    );
    fs::remove_dir_all(root).unwrap();
}
