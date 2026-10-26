// All state and files below are synthetic. No watcher hints or context change.
#[test]
#[serial(source_manifests)]
fn persistent_structural_refusal_serves_due_authority_and_finishes_bounded_admission() {
    if !c1a_layout_supported("persistent_retry_admission") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let mut fixture = c1a_fixture("persistent-retry-admission");
    let long_root = fixture
        .base
        .join("long-history")
        .join("p".repeat(200))
        .join("q".repeat(200))
        .join("r".repeat(200));
    std::fs::create_dir_all(long_root.parent().unwrap()).unwrap();
    std::fs::rename(&fixture.root, &long_root).unwrap();
    fixture.root = long_root;
    fixture.native_file_limit = 512;
    let closing = c1b_generation(&fixture, "seed", (8, 0));
    assert!(closing.census_complete && closing.full_rearm);
    const HEALTHY: usize = 6356;
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
    for tick in 0..80 {
        let page = fixture.page(
            &admission_clock(1_785_657_600_i64 + 600 + tick),
            RearmUpload::Accept,
        );
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
        let state = serde_json::to_value(&page.index).unwrap();
        let exhausted = state["traversal"]["pending_candidates"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && state["traversal"]["pending_directories"]
                .as_array()
                .is_some_and(Vec::is_empty);
        if indexed == HEALTHY && exhausted {
            warm_done = true;
            break;
        }
    }
    assert!(
        warm_done,
        "the real pipeline accepts and exhausts the synthetic history"
    );
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
    let baseline = c1a_saved(&fixture);
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
    fixture.native_file_limit = 64;
    let mut held_read = false;
    let mut held_settled = false;
    let mut progressed = BTreeSet::new();
    let mut admission_complete = false;
    for tick in 0..160 {
        if tick > 0 {
            fixture.native_file_limit = 10_000;
        }
        // page() uses ordinary ScanIndex::load and saves/reloads after the ACK.
        let page = fixture.page(&admission_clock(due + 1 + tick), RearmUpload::Accept);
        assert!(
            page.parsed.is_disjoint(&healthy),
            "no healthy Full reads at tick {tick}: {:?}",
            page.parsed
        );
        assert!(
            !page.scan.census_complete,
            "partial admission never upgrades coverage"
        );
        held_read |= page.parsed.contains(REARM_ROOT);
        held_settled |= page
            .index
            .claude_authority_record_for_test(REARM_ROOT)
            .is_none();
        if tick == 7 {
            assert!(
                held_read,
                "due held work must reach actual selection within eight ticks"
            );
            assert!(held_settled, "the real fold settles the re-proved family");
        }
        let current = c1a_saved(&fixture);
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
        if let Some(state) = current.pointer("/claude_stale_family_carry/origin/admission") {
            if let Some(after) = state["after_root"].as_str() {
                progressed.insert(after.to_owned());
            }
            admission_complete = state["complete"] == true;
        }
        if admission_complete {
            break;
        }
    }
    assert!(held_read && held_settled);
    assert!(
        progressed.len() > 1,
        "admission must progress over saved checkpoints"
    );
    assert!(
        admission_complete,
        "large healthy history must finish bounded admission"
    );
}

fn admission_clock(seconds: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
