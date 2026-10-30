// All state and files below are synthetic. No watcher hints or context change.
#[test]
#[serial(source_manifests)]
fn persistent_structural_refusal_serves_due_authority_and_finishes_bounded_admission() {
    if !c1a_layout_supported("persistent_retry_admission") {
        return;
    }
    let started = std::time::Instant::now();
    let _manifests = SourceManifestTestGuard::new();
    let mut fixture = c1a_fixture("persistent-retry-admission");
    // Spend the real 8 MiB cancellation reserve on longer keys rather than
    // excess families/pages. A 900-byte root leaves the nested seed paths
    // below macOS PATH_MAX; each component stays below NAME_MAX.
    let mut long_root = fixture.base.join("long-history");
    while long_root.to_string_lossy().len() < 900 {
        let padding = (900 - long_root.to_string_lossy().len())
            .saturating_sub(1)
            .clamp(1, 200);
        long_root.push("p".repeat(padding));
    }
    std::fs::create_dir_all(long_root.parent().unwrap()).unwrap();
    std::fs::rename(&fixture.root, &long_root).unwrap();
    fixture.root = long_root;
    fixture.native_file_limit = 2048;
    let closing = c1b_generation(&fixture, "seed", (8, 0));
    assert!(closing.census_complete && closing.full_rearm);
    // source_rotation.rs:186-188,293-315 permits an unparkable ordinary active
    // frame to continue serially. Require the real bound to refuse parking;
    // small fixtures and this test's seed retain their original layout gate.
    fixture.serial_active_frame = true;
    // 4608 * 2 * (900 + 1 + 36 + 6) = 8,690,688 > 8 MiB, before
    // counting any container overhead. More than 36 real 128-root groups
    // remain (the seed adds other families), including a partial final group.
    const HEALTHY: usize = 4608;
    let healthy = (0..HEALTHY)
        .map(|number| format!("0{number:07x}-1234-4234-8234-123456789abc"))
        .collect::<BTreeSet<_>>();
    for session in &healthy {
        let path = fixture.root.join(format!("{session}.jsonl"));
        assert!(path.to_string_lossy().len() >= 700);
        std::fs::write(
            path,
            rearm_transcript_line(session, None, &format!("req-{session}"), 0),
        )
        .unwrap();
    }
    // An unrelated loss leaves an exhausted red checkpoint once every
    // healthy body is accepted. Bound due debt is added to that checkpoint.
    RearmFixture::append(&c1b_sibling_path(&fixture), "not-json\n");
    let mut warm_done = false;
    let mut retained = ScanIndex::load(&fixture.index_path).unwrap();
    for tick in 0..80 {
        let page = fixture.scale_page(retained, &admission_clock(1_785_657_600_i64 + 600 + tick));
        let indexed = page
            .index
            .files
            .keys()
            .filter(|key| {
                Path::new(key)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| healthy.contains(s))
            })
            .count();
        let exhausted = page.index.scan_traversal_exhausted_for_test();
        retained = page.index;
        if indexed == HEALTHY && exhausted {
            warm_done = true;
            break;
        }
    }
    assert!(
        warm_done,
        "the real pipeline accepts and exhausts the synthetic history"
    );
    // This regression targets the same-context non-Fix-2 retry. The seed's
    // complete census opened a separate full-rearm window, whose BASE/refusal
    // controls are intentionally unchanged and covered by existing tests.
    drop(scale_checkpoint(&fixture, retained));
    c1b_without_full_rearm_window(&fixture);
    let mut index = ScanIndex::load(&fixture.index_path).unwrap();
    let members = RearmFixture::family_keys(&index)
        .into_iter()
        .map(|(member, key)| (member, index.files[&key].source_file_fingerprint.clone()))
        .collect();
    index.bind_retry_pending_claude_authority_for_test(REARM_ROOT, members);
    let mut saved = serde_json::to_value(&index).unwrap();
    let old_started = saved["traversal"]["census_window_end"].as_str().unwrap();
    let old_started =
        time::OffsetDateTime::parse(old_started, &time::format_description::well_known::Rfc3339)
            .unwrap()
            .unix_timestamp();
    let due = old_started + 60;
    saved["claude_usage_authority_quarantine"][REARM_ROOT]["retry_after_unix_seconds"] =
        serde_json::json!(due);
    saved["traversal"]["unhealthy_retry_not_before_unix_seconds"] = serde_json::json!(due + 3600);
    index = serde_json::from_value(saved).unwrap();
    index.save(&fixture.index_path).unwrap();
    index = ScanIndex::load(&fixture.index_path).unwrap();
    let baseline = serde_json::to_value(&index).unwrap();
    assert!(baseline["claude_full_rearm_progress"]["full_rearm_window"].is_null());
    let healthy_entries = baseline["files"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(key, _)| {
            Path::new(key)
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|s| healthy.contains(s))
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(healthy_entries.len(), HEALTHY);
    assert!(
        healthy_entries
            .keys()
            .map(|key| key.len() * 2)
            .sum::<usize>()
            > crate::source_rotation::PARKED_BUDGET
    );
    assert!(healthy_entries
        .values()
        .all(|entry| entry["last_upload_body_witness"].is_string()));
    let healthy_digest =
        index.healthy_custody_digest_for_test(healthy_entries.keys().map(String::as_str));
    fixture.native_file_limit = 64;
    let mut held_read = false;
    let mut held_settled = false;
    let mut progressed = BTreeSet::new();
    let mut admission_complete = false;
    let mut checkpoints = BTreeSet::new();
    let mut custody_checks = 0;
    let mut page_custody_checks = 0;
    retained = index;
    for tick in 0..160 {
        if tick > 0 {
            fixture.native_file_limit = 10_000;
        }
        // The same real scanner, upload/ACK validator and fold run every page.
        // Durable save/reload and the full custody oracle run at checkpoints.
        let page = fixture.scale_page(retained, &admission_clock(due + 1 + tick));
        assert!(
            page.parsed.is_disjoint(&healthy),
            "no healthy Full reads at tick {tick}: {:?}",
            page.parsed
        );
        assert!(
            !page.scan.census_complete,
            "partial admission never upgrades coverage"
        );
        assert_eq!(
            page.index
                .healthy_custody_digest_for_test(healthy_entries.keys().map(String::as_str)),
            healthy_digest,
            "every-page fingerprints, accepted membership and bindings retained at tick {tick}"
        );
        page_custody_checks += 1;
        held_read |= page.parsed.contains(REARM_ROOT);
        let held_now = page.index.claude_authority_record_for_test(REARM_ROOT);
        if held_settled {
            assert!(
                held_now.is_none(),
                "settled authority must not reappear at tick {tick}"
            );
        }
        if let Some(record) = &held_now {
            assert!(
                !record.terminal
                    && record.bound_to_retained_witness
                    && record.family_pending_retained,
                "bound RetryPending until the real fold settles it, tick {tick}"
            );
        } else {
            assert!(
                held_read,
                "settlement follows an actual held-family read, tick {tick}"
            );
            held_settled = true;
        }
        if tick == 7 {
            assert!(
                held_read,
                "due held work must reach actual selection within eight ticks"
            );
            assert!(held_settled, "the real fold settles the re-proved family");
        }
        assert!(page.index.claude_duplicate_fence_closed_for_test());
        if let Some((after, complete)) = page.index.claude_retry_admission_for_test() {
            if let Some(after) = after {
                progressed.insert(after.to_owned());
            }
            admission_complete = complete;
        }
        // Keep all healthy-entry equality/value checks at the owner-approved
        // checkpoints: first held settlement, midpoint and full completion.
        let first_settlement = held_settled && !checkpoints.contains("held");
        let midpoint = progressed.len() >= HEALTHY.div_ceil(128).div_ceil(2)
            && !checkpoints.contains("midpoint");
        retained = page.index;
        if first_settlement || midpoint || admission_complete {
            retained = scale_checkpoint(&fixture, retained);
            let current = serde_json::to_value(&retained).unwrap();
            for (key, before) in &healthy_entries {
                for field in [
                    "source_file_fingerprint",
                    "last_snapshot_fingerprint",
                    "last_upload_body_witness",
                    "scan_identity_version",
                ] {
                    assert_eq!(
                        current["files"][key][field], before[field],
                        "{key} {field} tick {tick}"
                    );
                }
                assert_eq!(
                    current["file_snapshot_fingerprints"][key],
                    baseline["file_snapshot_fingerprints"][key]
                );
                assert_eq!(
                    current["session_account_bindings"][key],
                    baseline["session_account_bindings"][key]
                );
            }
            assert!(current["claude_duplicate_request_witness_overflowed"]
                .as_bool()
                .unwrap());
            custody_checks += 1;
            if first_settlement {
                checkpoints.insert("held");
            }
            if midpoint {
                checkpoints.insert("midpoint");
            }
            if admission_complete {
                checkpoints.insert("end");
            }
        }
        if admission_complete {
            break;
        }
    }
    assert!(held_read && held_settled);
    assert_eq!(checkpoints, BTreeSet::from(["held", "midpoint", "end"]));
    assert_eq!(custody_checks, 3);
    assert!(
        page_custody_checks >= progressed.len(),
        "every admitted group has an in-memory custody check"
    );
    assert!(
        progressed.len() > 1,
        "admission must progress over saved checkpoints"
    );
    assert!(
        admission_complete,
        "large healthy history must finish bounded admission"
    );
    eprintln!(
        "retry_admission_runtime: elapsed_ms={} healthy={HEALTHY} groups={} custody_checkpoints={custody_checks} page_custody_checks={page_custody_checks}",
        started.elapsed().as_millis(), progressed.len()
    );
}

/// Real durability at the baseline and all three measured checkpoints. This
/// retains save/CAS, manifest publication and the ordinary lenient loader.
fn scale_checkpoint(fixture: &RearmFixture, mut index: ScanIndex) -> ScanIndex {
    let saved = serde_json::to_value(&index).unwrap();
    let at = saved["traversal"]["census_window_end"]
        .as_str()
        .unwrap()
        .to_owned();
    let (start, end) = snapshot_manifest_window(&at, 183).unwrap();
    save_index_and_publish_manifest(
        &mut index,
        &fixture.index_path,
        REARM_DESTINATION,
        SnapshotSource::ClaudeCode,
        false,
        &start,
        &end,
    )
    .expect("real scale checkpoint save and manifest");
    ScanIndex::load(&fixture.index_path).expect("real scale checkpoint reload")
}

fn admission_clock(seconds: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
