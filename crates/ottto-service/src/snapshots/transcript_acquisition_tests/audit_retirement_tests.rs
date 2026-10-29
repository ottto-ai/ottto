//! Synthetic paired-retirement/cap fixtures through the existing scan helper.
use super::*;

const START: u64 = 1_800_000_000;
struct Clock;
impl Clock {
    fn at(now: u64) -> Self {
        sampled_scan::set_test_now(Some(now));
        Self
    }
}
impl Drop for Clock {
    fn drop(&mut self) {
        sampled_scan::set_test_now(None);
        sampled_scan::test_hooks::clear();
    }
}

#[test]
fn removed_codex_cohorts_cannot_grow_markers_past_cap_or_disable_marked_tails() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    let source = SnapshotSource::Codex;
    let cap = crate::transcript_cache::CACHE_ENTRIES;
    let mut fixture = ScanFixture::new(source);
    fs::remove_file(&fixture.file.0).unwrap();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut index = ScanIndex::default();
    let mut ordinal = 0;
    let mut cap_events = 0;
    let mut alarms = 0;
    let mut control = None;
    // First two cohorts fill the cap; later cohorts would grow without bound
    // before the fix. Removed Codex members keep their actual staged markers.
    for cohort in [cap / 2, cap - cap / 2, 4, 4] {
        for _ in 0..cohort {
            let id = format!("019fa111-2222-7333-8444-{:012}", ordinal + 1);
            fixture.file.0 = fixture
                .root
                .join(format!("rollout-2026-10-07T10-00-00-{id}.jsonl"));
            let mut bytes =
                serde_json::to_vec(&json!({"type":"session_meta", "payload":{"id":id}})).unwrap();
            bytes.push(b'\n');
            fs::write(&fixture.file.0, bytes).unwrap();
            fixture.file.append(&usage(source, 100, 0, "fixture-model"));
            let (next, _, modes) =
                production_scan(&fixture, source, index, Some(cache.clone()), "cohort-cap");
            assert_eq!(modes, (1, 0, 0), "new object seed");
            index = next;
            fixture.file.append(&usage(source, 130, 1, "fixture-model"));
            let ((next, scan, modes), diagnostics) =
                crate::local_resource_diagnostics::capture(|| {
                    production_scan(&fixture, source, index, Some(cache.clone()), "cohort-cap")
                });
            index = next;
            assert!(
                !scan.snapshots.is_empty(),
                "bounded fallback still emits the native Full"
            );
            assert_eq!(modes, if ordinal < cap { (0, 1, 0) } else { (1, 0, 0) });
            let key = local_index_key(&fixture.file.0);
            assert_eq!(index.files[&key].has_unverified_source(), ordinal < cap);
            for record in &diagnostics {
                if record["stage"] == "native_collection_page" {
                    let counts = &record["counts"]["sampled_acquisition"];
                    let n = counts["index_state_at_page_end"]["audit_cap_full"]
                        .as_u64()
                        .unwrap();
                    assert_eq!(n, u64::from(ordinal >= cap));
                    assert!(counts["page_events"]["full_reasons"]
                        .get("audit_due")
                        .is_none());
                    cap_events += n;
                } else if record["stage"] == "sampled_audit_cap_alarm" {
                    assert!(record["counts"]["audit_cap_full"].as_u64().unwrap() > 0);
                    alarms += 1;
                }
            }
            if ordinal + 1 == cap {
                control = Some(fixture.file.0.clone());
            } else {
                fs::remove_file(&fixture.file.0).unwrap();
            }
            ordinal += 1;
        }
        assert_eq!(
            index
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .count(),
            ordinal.min(cap)
        );
    }
    assert_eq!(cap_events, 8);
    assert_eq!(alarms, cap_events);
    assert_eq!(
        index
            .files
            .values()
            .filter(|entry| entry.has_unverified_source())
            .count(),
        cap
    );
    fixture.file.0 = control.unwrap();
    let key = local_index_key(&fixture.file.0);
    assert!(
        cache.retained_checkpoint(&key).is_some(),
        "marked control remains funded"
    );
    let before = cache.retained_checkpoint(&key).unwrap();
    fixture.file.append(&usage(source, 160, 2, "fixture-model"));
    let ((next, scan, modes), diagnostics) = crate::local_resource_diagnostics::capture(|| {
        production_scan(&fixture, source, index, Some(cache.clone()), "cohort-cap")
    });
    assert_eq!(modes, (0, 1, 0), "no global Tail switch at the cap");
    assert!(!scan.snapshots.is_empty());
    assert!(next.files[&key].has_unverified_source());
    let after = cache.retained_checkpoint(&key).unwrap();
    assert!(after.sealed_offset() > before.sealed_offset());
    assert_eq!(after.audit_debt(), before.audit_debt());
    assert_eq!(after.last_full_verified(), before.last_full_verified());
    assert!(!diagnostics
        .iter()
        .any(|record| record["stage"] == "sampled_audit_cap_alarm"));
    // One quiet pass frees precisely one slot, without a Full or verification.
    sampled_scan::set_test_now(Some(
        START + crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS + 1,
    ));
    let ((index, _, modes), diagnostics) = crate::local_resource_diagnostics::capture(|| {
        production_scan(&fixture, source, next, Some(cache.clone()), "cohort-cap")
    });
    assert_eq!(modes, (0, 0, 1));
    assert!(!index.files[&key].has_unverified_source());
    assert_eq!(cache.retained_checkpoint(&key).unwrap().audit_debt(), None);
    assert_eq!(
        cache
            .retained_checkpoint(&key)
            .unwrap()
            .last_full_verified(),
        START
    );
    assert_eq!(
        index
            .files
            .values()
            .filter(|entry| entry.has_unverified_source())
            .count(),
        cap - 1
    );
    let page = diagnostics
        .iter()
        .find(|record| record["stage"] == "native_collection_page")
        .unwrap();
    assert_eq!(
        page["counts"]["sampled_acquisition"]["index_state_at_page_end"]["audit_quiet_retired"],
        1
    );
    assert_eq!(
        page["counts"]["sampled_acquisition"]["page_events"]["audits_completed"],
        0
    );
    // The slot is reusable; existing unavailable obligations were not evicted.
    fs::remove_file(&fixture.file.0).unwrap();
    let id = "019fa111-2222-7333-8444-999999999999";
    fixture.file.0 = fixture
        .root
        .join(format!("rollout-2026-10-07T10-00-00-{id}.jsonl"));
    fs::write(
        &fixture.file.0,
        format!("{}\n", json!({"type":"session_meta", "payload":{"id":id}})),
    )
    .unwrap();
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let (index, _, _) = production_scan(&fixture, source, index, Some(cache.clone()), "cohort-cap");
    fixture.file.append(&usage(source, 130, 1, "fixture-model"));
    let (index, _, modes) = production_scan(&fixture, source, index, Some(cache), "cohort-cap");
    assert_eq!(modes, (0, 1, 0));
    assert_eq!(
        index
            .files
            .values()
            .filter(|entry| entry.has_unverified_source())
            .count(),
        cap
    );
}

#[test]
fn prefix_legacy_partial_lossy_and_growing_reads_keep_the_obligation() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    for source in [SnapshotSource::Codex, SnapshotSource::ClaudeCode] {
        for arm in [
            "prefix",
            "legacy",
            "malformed",
            "partial",
            "lossy",
            "growing",
            "failed_validation",
        ] {
            sampled_scan::set_test_now(Some(START));
            let fixture = ScanFixture::new(source);
            fixture.file.append(&usage(source, 100, 0, "fixture-model"));
            let cache = Arc::new(sampled_scan::SharedCache::default());
            let (index, _, _) = production_scan(
                &fixture,
                source,
                ScanIndex::default(),
                Some(cache.clone()),
                "retirement-negative",
            );
            fixture.file.append(&usage(source, 130, 1, "fixture-model"));
            let (mut index, _, modes) = production_scan(
                &fixture,
                source,
                index,
                Some(cache.clone()),
                "retirement-negative",
            );
            assert_eq!(modes, (0, 1, 0));
            let key = local_index_key(&fixture.file.0);
            let due = index.files[&key].unverified_deadline().unwrap();
            assert!(
                !index.files[&key].has_prefix_provenance(),
                "genuine complete-c seed"
            );
            assert_eq!(
                cache
                    .retained_checkpoint(&key)
                    .unwrap()
                    .audit_debt()
                    .unwrap()
                    .due_unix_seconds,
                due
            );
            match arm {
                "prefix" => {
                    index.files.get_mut(&key).unwrap().scan_identity_version =
                        Some(format!("semantic_sync:v2+sampled_unverified:v2:{due}:p"))
                }
                "legacy" => {
                    index.files.get_mut(&key).unwrap().scan_identity_version =
                        Some(format!("semantic_sync:v2+sampled_unverified:v1:{due}"))
                }
                "malformed" => {
                    index.files.get_mut(&key).unwrap().scan_identity_version =
                        Some("semantic_sync:v2+sampled_unverified:v2:broken:c".into())
                }
                "partial" => {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .open(&fixture.file.0)
                        .unwrap();
                    file.write_all(
                        &serde_json::to_vec(&usage(source, 160, 2, "fixture-model")).unwrap(),
                    )
                    .unwrap();
                }
                "lossy" => OpenOptions::new()
                    .append(true)
                    .open(&fixture.file.0)
                    .unwrap()
                    .write_all(b"not json\n")
                    .unwrap(),
                "growing" => fixture.file.append(&usage(source, 160, 2, "fixture-model")),
                "failed_validation" => {}
                _ => unreachable!(),
            }
            if arm == "failed_validation" {
                let path = fixture.file.0.clone();
                sampled_scan::test_hooks::set(
                    sampled_scan::test_hooks::Point::AfterRetain,
                    move || {
                        OpenOptions::new()
                            .append(true)
                            .open(&path)
                            .unwrap()
                            .write_all(b"{}\n")
                            .unwrap();
                    },
                );
            }
            sampled_scan::set_test_now(Some(due + 1));
            let ((next, _, modes), diagnostics) =
                crate::local_resource_diagnostics::capture(|| {
                    production_scan(
                        &fixture,
                        source,
                        index,
                        Some(cache.clone()),
                        "retirement-negative",
                    )
                });
            assert_eq!(modes.0, 0, "{source:?}/{arm}: no audit Full");
            assert_eq!(
                (modes.1, modes.2),
                if matches!(arm, "partial" | "lossy" | "growing") {
                    (1, 0)
                } else {
                    (0, 1)
                }
            );
            assert!(
                next.files[&key].has_unverified_source(),
                "{source:?}/{arm}: keeps marker"
            );
            if matches!(arm, "partial" | "lossy" | "failed_validation") {
                assert!(
                    cache.retained_checkpoint(&key).is_none(),
                    "uncertified copy cannot retire"
                );
            } else {
                assert!(cache
                    .retained_checkpoint(&key)
                    .unwrap()
                    .audit_debt()
                    .is_some());
            }
            let page = diagnostics
                .iter()
                .find(|record| record["stage"] == "native_collection_page")
                .unwrap();
            assert_eq!(
                page["counts"]["sampled_acquisition"]["index_state_at_page_end"]
                    ["audit_quiet_retired"],
                0
            );
            assert_eq!(
                page["counts"]["sampled_acquisition"]["page_events"]["audits_completed"],
                0
            );
            sampled_scan::test_hooks::clear();
        }
    }
}

#[test]
fn partial_saves_cannot_reuse_quiet_slots_before_retirement_commits() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    let source = SnapshotSource::Codex;
    let mut fixture = ScanFixture::new(source);
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, _, _) = production_scan(
        &fixture,
        source,
        ScanIndex::default(),
        Some(cache.clone()),
        "partial-cap",
    );
    fixture.file.append(&usage(source, 130, 1, "fixture-model"));
    let (mut index, _, _) =
        production_scan(&fixture, source, index, Some(cache.clone()), "partial-cap");
    let quiet_path = fixture.file.0.clone();
    let quiet_key = local_index_key(&quiet_path);
    assert!(index.files[&quiet_key].has_unverified_source());
    let due = index.files[&quiet_key].unverified_deadline().unwrap();
    let id = "019fa111-2222-7333-8444-888888888888";
    fixture.file.0 = fixture
        .root
        .join(format!("rollout-2026-10-07T10-00-00-{id}.jsonl"));
    fs::write(
        &fixture.file.0,
        format!("{}\n", json!({"type":"session_meta", "payload":{"id":id}})),
    )
    .unwrap();
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let (next, _, _) = production_scan(&fixture, source, index, Some(cache.clone()), "partial-cap");
    index = next;
    let growing_key = local_index_key(&fixture.file.0);
    assert!(!index.files[&growing_key].has_unverified_source());
    for n in 1..crate::transcript_cache::CACHE_ENTRIES {
        let key = format!("/synthetic-unavailable/{n}.jsonl");
        let mut entry = index.files[&quiet_key].clone();
        entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        let fingerprint = entry.source_file_fingerprint.clone();
        index.files.insert(key.clone(), entry);
        assert!(index.stage_sampled_audit(
            &key,
            &fingerprint,
            crate::transcript_acquisition::AuditDebt {
                due_unix_seconds: due
            }
        ));
    }
    sampled_scan::set_test_now(Some(due + 1));
    let index_path = fixture.dir.join("partial-index.json");
    for turn in 0..3 {
        let committed = index.clone();
        let order = Arc::new(Mutex::new(Vec::new()));
        let observed_order = order.clone();
        let observed_cache = cache.clone();
        let observed_quiet = quiet_key.clone();
        let observed_growing = growing_key.clone();
        sampled_scan::test_hooks::set(sampled_scan::test_hooks::Point::AfterRetain, move || {
            let who = if observed_cache
                .retained_checkpoint(&observed_quiet)
                .is_none()
            {
                "quiet"
            } else {
                assert!(observed_cache
                    .retained_checkpoint(&observed_growing)
                    .is_none());
                "growing"
            };
            observed_order.lock().unwrap().push(who);
        });
        fixture.file.append(&usage(
            source,
            130 + turn * 30,
            turn as usize + 1,
            "fixture-model",
        ));
        let ((working, _, candidates, modes, _), diagnostics) =
            crate::local_resource_diagnostics::capture(|| {
                production_scan_page_at_with_setup(
                    &fixture,
                    source,
                    index,
                    Some(cache.clone()),
                    "partial-cap",
                    NOW,
                    |_| {},
                )
            });
        assert_eq!(
            *order.lock().unwrap(),
            ["quiet", "growing"],
            "due quiet A must retire before B's admission"
        );
        sampled_scan::test_hooks::clear();
        assert_eq!(
            modes,
            (1, 0, 1),
            "retired slot remains reserved in this scan"
        );
        assert!(!working.files[&quiet_key].has_unverified_source());
        assert!(!working.files[&growing_key].has_unverified_source());
        assert_eq!(
            candidates.snapshots.len(),
            1,
            "quiet A was suppressed before upload"
        );
        assert_eq!(candidates.snapshots[0].source_session_id, id);
        let accepted = candidates
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        // The exact production subset used by shed/error checkpointing. Its
        // accepted set includes emitted B only, never suppressed quiet A.
        let mut selected = working.committable_subset(&committed, &accepted, &BTreeMap::new());
        assert!(
            selected.files[&quiet_key].has_unverified_source(),
            "partial save restored A"
        );
        assert!(
            !selected.files[&growing_key].has_unverified_source(),
            "B used native Full, no fresh debt"
        );
        assert_eq!(
            selected
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .count(),
            crate::transcript_cache::CACHE_ENTRIES
        );
        let page = diagnostics
            .iter()
            .find(|record| record["stage"] == "native_collection_page")
            .unwrap();
        let state = &page["counts"]["sampled_acquisition"]["index_state_at_page_end"];
        assert_eq!(state["audit_quiet_retired"], 1);
        assert_eq!(state["audit_cap_full"], 1);
        selected.save(&index_path).unwrap();
        index = ScanIndex::load(&index_path).unwrap();
    }
    // A healthy retirement save frees capacity for the NEXT scan. No remote
    // ACK, body-witness or census credit is fabricated for that retirement.
    fs::remove_file(&fixture.file.0).unwrap();
    fixture.file.0 = quiet_path;
    let (mut healthy, _, modes) =
        production_scan(&fixture, source, index, Some(cache.clone()), "partial-cap");
    assert_eq!(modes, (0, 0, 1));
    assert!(!healthy.files[&quiet_key].has_unverified_source());
    healthy.save(&index_path).unwrap();
    let loaded = ScanIndex::load(&index_path).unwrap();
    assert_eq!(
        loaded
            .files
            .values()
            .filter(|entry| entry.has_unverified_source())
            .count(),
        crate::transcript_cache::CACHE_ENTRIES - 1
    );
    let (_, _, modes, _) = production_scan_at_with_setup(
        &fixture,
        source,
        loaded,
        Some(cache),
        "partial-cap",
        NOW,
        |scan| {
            assert_eq!(
                scan.sampling.as_ref().unwrap().audit_slots,
                1,
                "committed retirement frees a slot"
            );
        },
    );
    assert_eq!(modes, (0, 0, 0));
}

fn fill_unavailable_audits(index: &mut ScanIndex, template_key: &str, count: usize, due: u64) {
    for n in 0..count {
        let key = format!("/synthetic-held-unavailable/{n}.jsonl");
        let mut entry = index.files[template_key].clone();
        entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        let fingerprint = entry.source_file_fingerprint.clone();
        index.files.insert(key.clone(), entry);
        assert!(index.stage_sampled_audit(
            &key,
            &fingerprint,
            crate::transcript_acquisition::AuditDebt {
                due_unix_seconds: due,
            },
        ));
    }
}

fn assert_held_audit_diagnostics(diagnostics: &[Value], retired: u64) {
    let page = diagnostics
        .iter()
        .find(|record| record["stage"] == "native_collection_page")
        .unwrap();
    let counts = &page["counts"]["sampled_acquisition"];
    let state = &counts["index_state_at_page_end"];
    assert_eq!(state["audit_quiet_retired"], retired);
    assert_eq!(state["audit_cap_full"], 0);
    assert_eq!(counts["page_events"]["audits_completed"], 0);
    assert!(!diagnostics
        .iter()
        .any(|record| record["stage"] == "sampled_audit_cap_alarm"));
}

#[test]
fn held_quiet_audit_retires_only_after_release_and_committed_save() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    let source = SnapshotSource::ClaudeCode;
    let fixture = ScanFixture::new(source);
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, _, _) = production_scan(
        &fixture,
        source,
        ScanIndex::default(),
        Some(cache.clone()),
        "held-quiet",
    );
    fixture.file.append(&usage(source, 130, 1, "fixture-model"));
    let (mut index, _, modes) =
        production_scan(&fixture, source, index, Some(cache.clone()), "held-quiet");
    assert_eq!(modes, (0, 1, 0));
    let key = local_index_key(&fixture.file.0);
    let checkpoint = cache.retained_checkpoint(&key).unwrap();
    let due = checkpoint.audit_debt().unwrap().due_unix_seconds;
    let held = index.file_snapshot_fingerprints[&key].clone();
    assert!(!held.is_empty());
    let fingerprint = index.files[&key].source_file_fingerprint.clone();
    assert!(
        index.record_claude_account_deferred_holds([(key.as_str(), fingerprint.as_str())], &held,)
    );
    assert!(index.claude_account_deferred_holds.contains_key(&key));
    fill_unavailable_audits(
        &mut index,
        &key,
        crate::transcript_cache::CACHE_ENTRIES - 1,
        due,
    );
    sampled_scan::set_test_now(Some(due + 1));
    let index_path = fixture.dir.join("held-index.json");
    for _ in 0..2 {
        let committed = index.clone();
        let ((working, _, modes), diagnostics) = crate::local_resource_diagnostics::capture(|| {
            production_scan(&fixture, source, index, Some(cache.clone()), "held-quiet")
        });
        assert_eq!(modes, (0, 0, 1));
        assert_held_audit_diagnostics(&diagnostics, 0);
        assert!(working.files[&key].has_unverified_source());
        let after = cache.retained_checkpoint(&key).unwrap();
        assert_eq!(after.audit_debt(), checkpoint.audit_debt());
        assert_eq!(after.last_full_verified(), checkpoint.last_full_verified());
        // Exercise the actual partial-save/held-body reconciliation. An
        // unaccepted withheld body must neither retire nor release a slot.
        let mut selected = working.committable_subset_with_local_holds(
            &committed,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &held,
        );
        assert!(selected.claude_account_deferred_holds.contains_key(&key));
        assert_eq!(selected.files[&key].unverified_deadline(), Some(due));
        selected.save(&index_path).unwrap();
        index = ScanIndex::load(&index_path).unwrap();
        assert_eq!(
            index
                .files
                .values()
                .filter(|e| e.has_unverified_source())
                .count(),
            crate::transcript_cache::CACHE_ENTRIES,
        );
    }
    // The ordinary hold API releases the key. Quiet validation may retire it
    // now, but the scan's original slot reservation must remain intact.
    assert!(index.record_claude_account_deferred_holds(
        [(key.as_str(), fingerprint.as_str())],
        &BTreeSet::new(),
    ));
    assert!(!index.claude_account_deferred_holds.contains_key(&key));
    let ((mut retired, _, modes, _), diagnostics) =
        crate::local_resource_diagnostics::capture(|| {
            production_scan_at_with_setup(
                &fixture,
                source,
                index,
                Some(cache.clone()),
                "held-quiet",
                NOW,
                |scan| assert_eq!(scan.sampling.as_ref().unwrap().audit_slots, 0),
            )
        });
    assert_eq!(modes, (0, 0, 1));
    assert_held_audit_diagnostics(&diagnostics, 1);
    assert!(!retired.files[&key].has_unverified_source());
    let after = cache.retained_checkpoint(&key).unwrap();
    assert_eq!(after.audit_debt(), None);
    assert_eq!(after.last_full_verified(), checkpoint.last_full_verified());
    retired.save(&index_path).unwrap();
    let loaded = ScanIndex::load(&index_path).unwrap();
    let (_, _, modes, _) = production_scan_at_with_setup(
        &fixture,
        source,
        loaded,
        Some(cache),
        "held-quiet",
        NOW,
        |scan| assert_eq!(scan.sampling.as_ref().unwrap().audit_slots, 1),
    );
    assert_eq!(modes, (0, 0, 0));
}

#[test]
fn held_fresh_debt_at_cap_is_not_cap_full_or_a_new_marker() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    let source = SnapshotSource::ClaudeCode;
    let fixture = ScanFixture::new(source);
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (mut index, _, _) = production_scan(
        &fixture,
        source,
        ScanIndex::default(),
        Some(cache.clone()),
        "held-cap",
    );
    let key = local_index_key(&fixture.file.0);
    assert!(!index.files[&key].has_unverified_source());
    let held = index.file_snapshot_fingerprints[&key].clone();
    assert!(!held.is_empty());
    let fingerprint = index.files[&key].source_file_fingerprint.clone();
    assert!(
        index.record_claude_account_deferred_holds([(key.as_str(), fingerprint.as_str())], &held,)
    );
    fill_unavailable_audits(
        &mut index,
        &key,
        crate::transcript_cache::CACHE_ENTRIES,
        START + crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS,
    );
    fixture.file.append(&usage(source, 130, 1, "fixture-model"));
    for expected in [(0, 1, 0), (0, 0, 1)] {
        // UnknownOutcome forces the second quiet visit while the account
        // deferral still owns this retry; it confers no audit authority.
        index.files.get_mut(&key).unwrap().last_snapshot_fingerprint = None;
        let ((next, _, modes), diagnostics) = crate::local_resource_diagnostics::capture(|| {
            production_scan(&fixture, source, index, Some(cache.clone()), "held-cap")
        });
        assert_eq!(
            modes, expected,
            "neither cap decision may preempt a held retry"
        );
        assert_held_audit_diagnostics(&diagnostics, 0);
        assert!(next.claude_account_deferred_holds.contains_key(&key));
        assert!(!next.files[&key].has_unverified_source());
        assert!(cache
            .retained_checkpoint(&key)
            .unwrap()
            .audit_debt()
            .is_some());
        assert_eq!(
            cache
                .retained_checkpoint(&key)
                .unwrap()
                .last_full_verified(),
            START,
        );
        assert_eq!(
            next.files
                .values()
                .filter(|e| e.has_unverified_source())
                .count(),
            crate::transcript_cache::CACHE_ENTRIES,
            "central staging still refuses marker257",
        );
        index = next;
    }
}

#[test]
fn held_retry_cannot_stage_against_a_quiet_slot_before_partial_save() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    let source = SnapshotSource::ClaudeCode;
    let mut fixture = ScanFixture::new(source);
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, _, _) = production_scan(
        &fixture,
        source,
        ScanIndex::default(),
        Some(cache.clone()),
        "held-reservation",
    );
    fixture.file.append(&usage(source, 130, 1, "fixture-model"));
    let (mut index, _, _) = production_scan(
        &fixture,
        source,
        index,
        Some(cache.clone()),
        "held-reservation",
    );
    let quiet_key = local_index_key(&fixture.file.0);
    let due = index.files[&quiet_key].unverified_deadline().unwrap();
    fixture.file.0 = fixture.root.join("z-held-tail-fixture.jsonl");
    let held_row = |n, id| {
        let mut row = usage(source, n, id, "fixture-model");
        row["sessionId"] = json!("held-tail-fixture");
        row["requestId"] = json!(format!("held-req-{id}"));
        row["message"]["id"] = json!(format!("held-response-{id}"));
        row
    };
    fixture.file.append(&held_row(100, 0));
    let (next, _, modes) = production_scan(
        &fixture,
        source,
        index,
        Some(cache.clone()),
        "held-reservation",
    );
    assert_eq!(modes, (1, 0, 0));
    index = next;
    let held_key = local_index_key(&fixture.file.0);
    assert!(!index.files[&held_key].has_unverified_source());
    let held = index.file_snapshot_fingerprints[&held_key].clone();
    assert!(!held.is_empty());
    let fingerprint = index.files[&held_key].source_file_fingerprint.clone();
    assert!(index
        .record_claude_account_deferred_holds([(held_key.as_str(), fingerprint.as_str())], &held,));
    fill_unavailable_audits(
        &mut index,
        &quiet_key,
        crate::transcript_cache::CACHE_ENTRIES - 1,
        due,
    );
    sampled_scan::set_test_now(Some(due + 1));
    let index_path = fixture.dir.join("held-reservation-index.json");
    for turn in 0..2 {
        let committed = index.clone();
        let order = Arc::new(Mutex::new(Vec::new()));
        let observed_order = order.clone();
        let observed_cache = cache.clone();
        let observed_quiet = quiet_key.clone();
        let observed_held = held_key.clone();
        sampled_scan::test_hooks::set(sampled_scan::test_hooks::Point::AfterRetain, move || {
            let who = if observed_cache
                .retained_checkpoint(&observed_quiet)
                .is_none()
            {
                "quiet"
            } else {
                assert!(observed_cache.retained_checkpoint(&observed_held).is_none());
                "held"
            };
            observed_order.lock().unwrap().push(who);
        });
        fixture
            .file
            .append(&held_row(130 + turn * 30, turn as usize + 1));
        let ((working, _, modes), diagnostics) = crate::local_resource_diagnostics::capture(|| {
            production_scan(
                &fixture,
                source,
                index,
                Some(cache.clone()),
                "held-reservation",
            )
        });
        assert_eq!(*order.lock().unwrap(), ["quiet", "held"]);
        sampled_scan::test_hooks::clear();
        assert_eq!(modes, (0, 1, 1), "held Tail is never a cap Full");
        assert_held_audit_diagnostics(&diagnostics, 1);
        assert!(!working.files[&quiet_key].has_unverified_source());
        assert!(working
            .claude_account_deferred_holds
            .contains_key(&held_key));
        assert!(cache
            .retained_checkpoint(&held_key)
            .unwrap()
            .audit_debt()
            .is_some());
        assert!(
            !working.files[&held_key].has_unverified_source(),
            "working retirement cannot fund a fresh held marker",
        );
        let reparse_held = working.file_snapshot_fingerprints[&held_key].clone();
        assert!(!reparse_held.is_empty());
        let mut selected = working.committable_subset_with_local_holds(
            &committed,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &reparse_held,
        );
        assert!(selected.files[&quiet_key].has_unverified_source());
        assert!(!selected.files[&held_key].has_unverified_source());
        selected.save(&index_path).unwrap();
        index = ScanIndex::load(&index_path).unwrap();
        assert_eq!(
            index
                .files
                .values()
                .filter(|e| e.has_unverified_source())
                .count(),
            crate::transcript_cache::CACHE_ENTRIES,
            "partial save cannot restore a 257th marker",
        );
    }
}
