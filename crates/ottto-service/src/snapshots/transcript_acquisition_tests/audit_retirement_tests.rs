//! Synthetic paired-retirement/cap fixtures through the existing scan helper.
use super::*;

const START: u64 = 1_700_000_000;
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
fn unavailable_codex_cohorts_cannot_grow_markers_past_cap_or_disable_marked_tails() {
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
    let mut parked_control = None;
    // First two cohorts fill the cap; later cohorts would grow without bound
    // before the fix. ENOTDIR is unavailable, never proven deletion.
    for cohort in [cap / 2, cap - cap / 2, 4, 4] {
        for _ in 0..cohort {
            let id = format!("019fa111-2222-7333-8444-{:012}", ordinal + 1);
            let unavailable_parent = fixture.root.join(format!("cohort-{ordinal}"));
            fs::create_dir(&unavailable_parent).unwrap();
            fixture.file.0 =
                unavailable_parent.join(format!("rollout-2026-10-07T10-00-00-{id}.jsonl"));
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
                // Keep this marked control unavailable during later cohorts,
                // just like their other owed members. Otherwise its due audit
                // legitimately adds an Unchanged visit to each seed page.
                let parked = fixture.dir.join("parked-control");
                fs::rename(&unavailable_parent, &parked).unwrap();
                fs::write(&unavailable_parent, b"unavailable mount placeholder").unwrap();
                parked_control = Some((unavailable_parent.clone(), parked));
            } else {
                fs::remove_file(&fixture.file.0).unwrap();
                fs::remove_dir(&unavailable_parent).unwrap();
                // ENOTDIR is uncertain under E3's hardened proof; a truly
                // missing intermediate beneath a readable root would retire.
                fs::write(&unavailable_parent, b"unavailable mount placeholder").unwrap();
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
    let (original_parent, parked) = parked_control.unwrap();
    fs::remove_file(&original_parent).unwrap();
    fs::rename(parked, original_parent).unwrap();
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
    for turn in 0..4 {
        let offset = if turn == 3 {
            sampled_scan::CAP_PACE_SECONDS
        } else {
            turn * 60
        };
        sampled_scan::set_test_now(Some(due + 1 + offset));
        let reads_full = turn == 0 || turn == 3;
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
            if reads_full {
                vec!["quiet", "growing"]
            } else {
                vec!["quiet"]
            },
            "paced B exits before acquisition and retention"
        );
        sampled_scan::test_hooks::clear();
        assert_eq!(
            modes,
            (usize::from(reads_full), 0, 1),
            "one initial Full, delays, then one Full after six hours"
        );
        assert!(!working.files[&quiet_key].has_unverified_source());
        assert!(!working.files[&growing_key].has_unverified_source());
        assert_eq!(
            candidates.snapshots.len(),
            usize::from(reads_full),
            "delayed B offers no body; quiet A is suppressed"
        );
        if reads_full {
            assert_eq!(candidates.snapshots[0].source_session_id, id);
        } else {
            assert_eq!(
                working.files[&growing_key].size_bytes,
                committed.files[&growing_key].size_bytes
            );
            assert!(working
                .traversal
                .as_ref()
                .unwrap()
                .pending_candidates
                .iter()
                .any(|path| local_index_key(&path.path) == growing_key));
        }
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
        assert_eq!(state["audit_cap_full"], usize::from(reads_full));
        let delays = diagnostics
            .iter()
            .filter(|row| row["stage"] == "sampled_audit_cap_delay")
            .collect::<Vec<_>>();
        assert_eq!(delays.len(), usize::from(!reads_full));
        if !reads_full {
            assert_eq!(delays[0]["counts"]["audit_cap_delay"], 1);
        }
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

#[test]
fn quiet_retirement_selection_and_due_gate_share_the_captured_edge() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        sampled_scan::set_test_now(Some(START));
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (index, _, _) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "due-edge",
        );
        fixture.file.append(&usage(source, 130, 1, "fixture-model"));
        let (mut index, _, modes) =
            production_scan(&fixture, source, index, Some(cache.clone()), "due-edge");
        assert_eq!(modes, (0, 1, 0));
        let key = local_index_key(&fixture.file.0);
        let due = index.files[&key].unverified_deadline().unwrap();
        let verified = cache
            .retained_checkpoint(&key)
            .unwrap()
            .last_full_verified();
        for selected_at in [due - 1, due] {
            sampled_scan::set_test_now(Some(selected_at));
            let ((next, _, modes, _), diagnostics) =
                crate::local_resource_diagnostics::capture(|| {
                    production_scan_at_with_setup(
                        &fixture,
                        source,
                        index,
                        Some(cache.clone()),
                        "due-edge",
                        NOW,
                        |scan| {
                            assert_eq!(scan.audit_now, selected_at);
                            assert_eq!(
                                scan.index.files[&key].audit_requires_full(scan.audit_now),
                                selected_at == due
                            );
                            // Cross the edge after selection, in either direction.
                            // Re-reading the clock in the gate would disagree.
                            sampled_scan::set_test_now(Some(if selected_at == due {
                                due - 1
                            } else {
                                due + 1
                            }));
                        },
                    )
                });
            index = next;
            assert_eq!(modes, (0, 0, usize::from(selected_at == due)));
            assert_eq!(
                index.files[&key].has_unverified_source(),
                selected_at != due
            );
            let checkpoint = cache.retained_checkpoint(&key).unwrap();
            assert_eq!(checkpoint.audit_debt().is_some(), selected_at != due);
            assert_eq!(checkpoint.last_full_verified(), verified);
            let page = diagnostics
                .iter()
                .find(|row| row["stage"] == "native_collection_page")
                .unwrap();
            let counts = &page["counts"]["sampled_acquisition"];
            assert_eq!(
                counts["index_state_at_page_end"]["audit_quiet_retired"],
                usize::from(selected_at == due)
            );
            assert_eq!(counts["page_events"]["audits_completed"], 0);
        }
    }
}

#[test]
fn cap_delayed_growth_survives_age_and_replacement_traversal() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        sampled_scan::set_test_now(Some(START));
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let namespace = "cap-delay-age-reset";
        let (mut index, _, modes) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            namespace,
        );
        assert_eq!(modes, (1, 0, 0));
        let key = local_index_key(&fixture.file.0);
        fill_unavailable_audits(
            &mut index,
            &key,
            crate::transcript_cache::CACHE_ENTRIES,
            START,
        );
        let markers = index
            .files
            .iter()
            .filter(|(_, entry)| entry.has_unverified_source())
            .map(|(key, entry)| (key.clone(), entry.scan_identity_version.clone()))
            .collect::<BTreeMap<_, _>>();
        let assert_cap_counts = |rows: &[Value], full: u64, delay: u64| {
            let page = rows
                .iter()
                .find(|row| row["stage"] == "native_collection_page")
                .unwrap();
            assert_eq!(
                page["counts"]["sampled_acquisition"]["index_state_at_page_end"]["audit_cap_full"],
                full
            );
            let delays = rows
                .iter()
                .filter(|row| row["stage"] == "sampled_audit_cap_delay")
                .collect::<Vec<_>>();
            assert_eq!(delays.len() as u64, delay);
            if delay > 0 {
                assert_eq!(delays[0]["counts"]["audit_cap_delay"], delay);
            }
            assert_eq!(
                rows.iter()
                    .filter(|row| row["stage"] == "sampled_audit_cap_alarm")
                    .count() as u64,
                full
            );
        };
        fixture.file.append(&usage(source, 130, 1, "fixture-model"));
        let ((committed, _, modes), diagnostics) =
            crate::local_resource_diagnostics::capture(|| {
                production_scan(&fixture, source, index, Some(cache.clone()), namespace)
            });
        assert_eq!(modes, (1, 0, 0), "first cap Full enrolls the key");
        assert_cap_counts(&diagnostics, 1, 0);
        assert!(!committed.files[&key].has_unverified_source());
        assert!(!committed.files[&key].source_file_fingerprint.is_empty());
        let committed_size = committed.files[&key].size_bytes;
        fixture.file.append(&usage(source, 160, 2, "fixture-model"));
        let actual_size = fs::metadata(&fixture.file.0).unwrap().len();
        assert!(actual_size > committed_size, "real unpaid growth");
        sampled_scan::set_test_now(Some(START + 60));
        let ((delayed, raw, modes), diagnostics) =
            crate::local_resource_diagnostics::capture(|| {
                production_scan(
                    &fixture,
                    source,
                    committed.clone(),
                    Some(cache.clone()),
                    namespace,
                )
            });
        assert_eq!(modes, (0, 0, 0), "paced delay starts no acquisition");
        assert!(raw.snapshots.is_empty(), "the append has not published");
        assert_cap_counts(&diagnostics, 0, 1);
        assert_eq!(delayed.files[&key].size_bytes, committed_size);
        assert!(delayed.files[&key].source_file_fingerprint.is_empty());
        let old_context = delayed
            .traversal
            .as_ref()
            .unwrap()
            .context_fingerprint
            .clone();
        let mut selected =
            delayed.committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(selected.files[&key].size_bytes, committed_size);
        assert!(selected.files[&key].source_file_fingerprint.is_empty());
        let index_path = fixture.dir.join("cap-delay-index.json");
        selected.save(&index_path).unwrap();
        let loaded = ScanIndex::load(&index_path).unwrap();
        assert!(sampled_audit::path_requires_verification(
            &loaded.files,
            &fixture.file.0
        ));
        let modified =
            unix_seconds(fs::metadata(&fixture.file.0).unwrap().modified().unwrap()).unwrap();
        let future = modified + (BACKFILL_WINDOW_DAYS + 2) * 86_400;
        assert!(!is_recent_enough_at(modified, future, BACKFILL_WINDOW_DAYS));
        let collected = OffsetDateTime::from_unix_timestamp(future as i64)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        sampled_scan::set_test_now(Some(future)); // expired/sanity-bound pace admits
        let extra_root = fixture.dir.join("extra-root");
        fs::create_dir(&extra_root).unwrap();
        let roots = [fixture.root.clone(), extra_root];
        let make_scan = |index| {
            OwnedSourceScan::new(
                source,
                &roots,
                index,
                &collected,
                BACKFILL_WINDOW_DAYS,
                10,
                false,
                None,
                &[],
                false,
                true,
            )
        };
        let scan =
            make_scan(loaded.clone()).with_sampled_acquisition(cache, Scope(namespace.into()));
        let walk = scan.index.traversal.as_ref().unwrap();
        assert_ne!(
            walk.context_fingerprint, old_context,
            "actual context replacement"
        );
        assert_eq!(walk.scan_roots.as_slice(), roots.as_slice());
        assert_eq!(scan.sampling.as_ref().unwrap().audit_slots, 0);
        let ((mut serviced, raw, _, modes, _), diagnostics) =
            crate::local_resource_diagnostics::capture(|| {
                finish_production_scan_page(scan, source)
            });
        assert_eq!(modes, (1, 0, 0), "counted catch-up after the age cutoff");
        assert_cap_counts(&diagnostics, 1, 0);
        let page = diagnostics
            .iter()
            .find(|row| row["stage"] == "native_collection_page")
            .unwrap();
        assert_eq!(
            page["counts"]["sampled_acquisition"]["page_events"]["full_cause"]
                ["rearm_cleared{audit_cap_delay}"],
            json!({"count": 1, "completed_native_bytes": actual_size}),
            "the #897 wrapper retains the cap-delay cause across index reload"
        );
        assert!(
            !raw.snapshots.is_empty(),
            "catch-up emits the unpaid append"
        );
        assert_eq!(raw.disappeared_file_count, 0);
        assert_eq!(serviced.files.len(), loaded.files.len(), "nothing pruned");
        assert_eq!(serviced.files[&key].size_bytes, actual_size);
        assert!(!serviced.files[&key].source_file_fingerprint.is_empty());
        assert!(!serviced.files[&key].has_unverified_source());
        for (marked, version) in &markers {
            assert_eq!(&serviced.files[marked].scan_identity_version, version);
        }
        let (_, cold, _, _, _) = finish_production_scan_page(make_scan(loaded), source);
        assert!(!cold.snapshots.is_empty());
        assert_eq!(production_body(source, raw), production_body(source, cold));
        serviced.save(&index_path).unwrap();
        let loaded = ScanIndex::load(&index_path).unwrap();
        assert_eq!(loaded.files[&key].size_bytes, actual_size);
        assert!(!loaded.files[&key].source_file_fingerprint.is_empty());
    }
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
    let (mut index, held_scan, modes) =
        production_scan(&fixture, source, index, Some(cache.clone()), "held-quiet");
    assert_eq!(modes, (0, 1, 0));
    let key = local_index_key(&fixture.file.0);
    let checkpoint = cache.retained_checkpoint(&key).unwrap();
    let due = checkpoint.audit_debt().unwrap().due_unix_seconds;
    let deferred_tokens = crate::snapshot_sync::withheld_support::deferred_tokens(&held_scan);
    let held = index.file_snapshot_fingerprints[&key].clone();
    assert!(!held.is_empty());
    let fingerprint = index.files[&key].source_file_fingerprint.clone();
    assert!(index.record_claude_account_deferred_holds(
        [(key.as_str(), fingerprint.as_str())],
        &deferred_tokens,
    ));
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
        &BTreeMap::new(),
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
    let (mut index, held_scan, _) = production_scan(
        &fixture,
        source,
        ScanIndex::default(),
        Some(cache.clone()),
        "held-cap",
    );
    let key = local_index_key(&fixture.file.0);
    assert!(!index.files[&key].has_unverified_source());
    let deferred_tokens = crate::snapshot_sync::withheld_support::deferred_tokens(&held_scan);
    let held = index.file_snapshot_fingerprints[&key].clone();
    assert!(!held.is_empty());
    let fingerprint = index.files[&key].source_file_fingerprint.clone();
    assert!(index.record_claude_account_deferred_holds(
        [(key.as_str(), fingerprint.as_str())],
        &deferred_tokens,
    ));
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
    let quiet_path = fixture.file.0.clone();
    let quiet_key = local_index_key(&fixture.file.0);
    assert!(!index.files[&quiet_key].has_unverified_source());
    fixture.file.0 = fixture.root.join("z-held-tail-fixture.jsonl");
    let held_row = |n, id| {
        let mut row = usage(source, n, id, "fixture-model");
        row["sessionId"] = json!("held-tail-fixture");
        row["requestId"] = json!(format!("held-req-{id}"));
        row["message"]["id"] = json!(format!("held-response-{id}"));
        row
    };
    fixture.file.append(&held_row(100, 0));
    let (next, held_scan, modes) = production_scan(
        &fixture,
        source,
        index,
        Some(cache.clone()),
        "held-reservation",
    );
    assert_eq!(modes, (1, 0, 0));
    // Seed B before creating A's audit. Once A is marked, selection may
    // legitimately visit it even on an otherwise B-only seed page.
    let held_path = fixture.file.0.clone();
    fixture.file.0 = quiet_path;
    fixture.file.append(&usage(source, 130, 1, "fixture-model"));
    let (mut index, _, modes) = production_scan(
        &fixture,
        source,
        next,
        Some(cache.clone()),
        "held-reservation",
    );
    assert_eq!(modes, (0, 1, 0));
    let due = index.files[&quiet_key].unverified_deadline().unwrap();
    fixture.file.0 = held_path;
    let held_key = local_index_key(&fixture.file.0);
    assert!(!index.files[&held_key].has_unverified_source());
    let deferred_tokens = crate::snapshot_sync::withheld_support::deferred_tokens(&held_scan);
    let held = index.file_snapshot_fingerprints[&held_key].clone();
    assert!(!held.is_empty());
    let fingerprint = index.files[&held_key].source_file_fingerprint.clone();
    assert!(index.record_claude_account_deferred_holds(
        [(held_key.as_str(), fingerprint.as_str())],
        &deferred_tokens,
    ));
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
        let ((working, mut raw, modes), diagnostics) =
            crate::local_resource_diagnostics::capture(|| {
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
        let working = if turn == 1 {
            let released = crate::snapshot_sync::accept_account_release_for_test(
                working,
                &committed,
                &mut raw,
                &cache,
                std::slice::from_ref(&fixture.root),
                None,
            );
            assert!(!released
                .claude_account_deferred_holds
                .contains_key(&held_key));
            assert!(released.files[&held_key].source_file_fingerprint.is_empty());
            assert!(
                !released.files[&held_key].has_unverified_source(),
                "release cannot spend A's provisional slot"
            );
            released
        } else {
            working
        };
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

#[test]
fn post_scan_account_release_keeps_unfunded_debt_selectable_across_restart() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    let source = SnapshotSource::ClaudeCode;
    for marked in [
        crate::transcript_cache::CACHE_ENTRIES - 1,
        crate::transcript_cache::CACHE_ENTRIES,
    ] {
        sampled_scan::set_test_now(Some(START));
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let namespace = "post-scan-release";
        let (mut index, held_scan, modes) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            namespace,
        );
        assert_eq!(modes, (1, 0, 0));
        let key = local_index_key(&fixture.file.0);
        let fingerprint = index.files[&key].source_file_fingerprint.clone();
        let deferred_tokens = crate::snapshot_sync::withheld_support::deferred_tokens(&held_scan);
        let held = index.file_snapshot_fingerprints[&key].clone();
        assert!(!held.is_empty());
        assert!(index.record_claude_account_deferred_holds(
            [(key.as_str(), fingerprint.as_str())],
            &deferred_tokens
        ));
        let due = START + crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS;
        fill_unavailable_audits(&mut index, &key, marked, due);
        let committed = index.clone();
        fixture.file.append(&usage(source, 130, 1, "fixture-model"));
        let ((scanned, _, mut candidates, modes, _), diagnostics) =
            crate::local_resource_diagnostics::capture(|| {
                production_scan_page_at_with_setup(
                    &fixture,
                    source,
                    index,
                    Some(cache.clone()),
                    namespace,
                    NOW,
                    |_| {},
                )
            });
        assert_eq!(modes, (0, 1, 0), "held release generation is Tail");
        assert_held_audit_diagnostics(&diagnostics, 0);
        assert!(
            !candidates.snapshots.is_empty(),
            "changed accepted generation"
        );
        assert!(scanned.claude_account_deferred_holds.contains_key(&key));
        assert!(cache
            .retained_checkpoint(&key)
            .unwrap()
            .audit_debt()
            .is_some());
        assert_eq!(
            scanned.files[&key].has_unverified_source(),
            marked < crate::transcript_cache::CACHE_ENTRIES
        );
        // Actual post-scan classifier removes the hold, then the production
        // completed-upload selector commits the accepted release generation.
        let (mut accepted, release_diagnostics) =
            crate::local_resource_diagnostics::capture(|| {
                crate::snapshot_sync::accept_account_release_for_test(
                    scanned,
                    &committed,
                    &mut candidates,
                    &cache,
                    std::slice::from_ref(&fixture.root),
                    None,
                )
            });
        assert!(!accepted.claude_account_deferred_holds.contains_key(&key));
        assert_eq!(
            accepted
                .files
                .values()
                .filter(|e| e.has_unverified_source())
                .count(),
            crate::transcript_cache::CACHE_ENTRIES
        );
        if marked == crate::transcript_cache::CACHE_ENTRIES {
            assert!(!accepted.files[&key].has_unverified_source());
            assert!(accepted.files[&key].source_file_fingerprint.is_empty());
            assert!(accepted
                .traversal
                .as_ref()
                .unwrap()
                .pending_candidates
                .iter()
                .any(|candidate| candidate.path == fixture.file.0 && candidate.watcher_hint));
            assert!(release_diagnostics
                .iter()
                .any(|record| record["stage"] == "sampled_audit_account_release"
                    && record["counts"]["retry_queued"] == 1));
        }
        let path = fixture.dir.join("released-index.json");
        accepted.save(&path).unwrap();
        // Make the file quiet far beyond the activity window WITHOUT changing
        // its stamp or either sample. The equal-length file still owes service.
        let modified = fs::metadata(&fixture.file.0).unwrap().modified().unwrap();
        let modified_secs = unix_seconds(modified).unwrap();
        let future = modified_secs + (BACKFILL_WINDOW_DAYS + 2) * 86_400;
        let collected = OffsetDateTime::from_unix_timestamp(future as i64)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        sampled_scan::set_test_now(Some(due + 1));
        let loaded = ScanIndex::load(&path).unwrap();
        // Force a traversal reset too: the durable reparse/marker witness
        // must survive loss of the optional queue's old context.
        let mut loaded = loaded;
        loaded.traversal = None;
        let restart = Arc::new(sampled_scan::SharedCache::default());
        if marked < crate::transcript_cache::CACHE_ENTRIES {
            // A record-backed/retained quiet read can perform counted
            // retirement instead of Full; retain this positive sample control.
            let copy = cache.take(&key).unwrap();
            restart.insert(
                key.clone(),
                sampled_jsonl::CompletedNativeAcquisition {
                    checkpoint: copy.retained.checkpoint,
                    reduction: Some(copy.retained.state),
                    released: None,
                    unsealed: false,
                },
                0,
            );
        }
        drop(cache);
        let ((mut serviced, _, modes, _), diagnostics) =
            crate::local_resource_diagnostics::capture(|| {
                production_scan_at_with_setup(
                    &fixture,
                    source,
                    loaded,
                    Some(restart.clone()),
                    namespace,
                    &collected,
                    |_| {},
                )
            });
        assert_eq!(
            modes,
            if marked == crate::transcript_cache::CACHE_ENTRIES {
                (1, 0, 0)
            } else {
                (0, 0, 1)
            }
        );
        assert!(!serviced.files[&key].has_unverified_source());
        assert!(!serviced.files[&key].source_file_fingerprint.is_empty());
        let page = diagnostics
            .iter()
            .find(|record| record["stage"] == "native_collection_page")
            .unwrap();
        let counts = &page["counts"]["sampled_acquisition"];
        assert_eq!(
            counts["index_state_at_page_end"]["audit_cap_full"],
            usize::from(marked == crate::transcript_cache::CACHE_ENTRIES)
        );
        assert_eq!(
            counts["index_state_at_page_end"]["audit_quiet_retired"],
            usize::from(marked < crate::transcript_cache::CACHE_ENTRIES)
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|record| record["stage"] == "sampled_audit_cap_alarm")
                .count(),
            usize::from(marked == crate::transcript_cache::CACHE_ENTRIES)
        );
        serviced.save(&path).unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        assert!(!loaded.files[&key].has_unverified_source());
        let (_, _, modes, _) = production_scan_at_with_setup(
            &fixture,
            source,
            loaded,
            Some(restart),
            namespace,
            &collected,
            |_| {},
        );
        assert_eq!(modes, (0, 0, 0), "discharge is once, not an hourly Full");
    }
}

#[test]
fn cap_pace_expires_on_six_hours_backwards_or_implausible_clock_and_evicts_oldest() {
    let cache = sampled_scan::SharedCache::default();
    let at = UNIX_EPOCH + std::time::Duration::from_secs(START);
    let six_hours = std::time::Duration::from_secs(sampled_scan::CAP_PACE_SECONDS);
    assert_eq!(cache.cap_pace_for_test("A", at), (true, false, 1));
    assert_eq!(
        cache.cap_pace_for_test("A", at + six_hours - std::time::Duration::from_secs(1)),
        (false, false, 1)
    );
    assert_eq!(
        cache.cap_pace_for_test("A", at + six_hours),
        (true, false, 1)
    );
    assert_eq!(
        cache.cap_pace_for_test("A", at),
        (true, false, 1),
        "backwards expires"
    );
    let implausible = at + std::time::Duration::from_secs(31 * 24 * 60 * 60);
    assert_eq!(
        cache.cap_pace_for_test("A", implausible),
        (true, false, 1),
        "large jump expires"
    );
    // Fresh map: enrollment order and wall time both make A the oldest.
    let cache = sampled_scan::SharedCache::default();
    assert_eq!(cache.cap_pace_for_test("oldest", at), (true, false, 1));
    for n in 1..crate::transcript_cache::CACHE_ENTRIES {
        assert_eq!(
            cache.cap_pace_for_test(
                &format!("pace-{n}"),
                at + std::time::Duration::from_secs(n as u64)
            ),
            (true, false, n + 1)
        );
    }
    assert_eq!(
        cache.cap_pace_for_test("overflow", at + six_hours),
        (true, true, 256)
    );
    assert_eq!(
        cache.cap_pace_for_test("oldest", at + six_hours),
        (true, true, 256),
        "oldest was evicted; fail toward read"
    );
    assert_eq!(
        cache.cap_pace_for_test("overflow", at + six_hours),
        (false, false, 256)
    );
}

#[test]
fn cap_pace_overflow_is_counted_and_alarms_on_the_production_full() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    let source = SnapshotSource::Codex;
    let fixture = ScanFixture::new(source);
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (mut index, _, _) = production_scan(
        &fixture,
        source,
        ScanIndex::default(),
        Some(cache.clone()),
        "pace-overflow",
    );
    let key = local_index_key(&fixture.file.0);
    fill_unavailable_audits(
        &mut index,
        &key,
        crate::transcript_cache::CACHE_ENTRIES,
        START,
    );
    for n in 0..crate::transcript_cache::CACHE_ENTRIES {
        assert_eq!(
            cache.cap_pace_for_test(
                &format!("old-{n}"),
                UNIX_EPOCH + std::time::Duration::from_secs(START)
            ),
            (true, false, n + 1)
        );
    }
    fixture.file.append(&usage(source, 130, 1, "fixture-model"));
    let ((index, _, modes), diagnostics) = crate::local_resource_diagnostics::capture(|| {
        production_scan(&fixture, source, index, Some(cache), "pace-overflow")
    });
    assert_eq!(modes, (1, 0, 0));
    assert!(!index.files[&key].has_unverified_source());
    let page = diagnostics
        .iter()
        .find(|row| row["stage"] == "native_collection_page")
        .unwrap();
    let state = &page["counts"]["sampled_acquisition"]["index_state_at_page_end"];
    assert_eq!(state["audit_cap_full"], 1);
    assert!(
        state.get("pace_evicted").is_none(),
        "pacing has its own bounded carrier"
    );
    assert_eq!(
        diagnostics
            .iter()
            .filter(|row| row["stage"] == "sampled_audit_pace_alarm")
            .count(),
        1
    );
    assert!(diagnostics.iter().any(
        |row| row["stage"] == "sampled_audit_pace_alarm" && row["counts"]["pace_evicted"] == 1
    ));
}

#[test]
fn durable_quiet_retirement_keeps_scheduling_until_writer_and_index_receipts() {
    durable_quiet_retirement_faults(&[
        "crash_before_writer",
        "deferral",
        "writer_error",
        "receipt_before_index",
        "scope_change",
        "legacy_index_clear",
    ]);
}

#[test]
fn durable_debtless_record_index_save_failure_keeps_audit_due_on_restart() {
    durable_quiet_retirement_faults(&["index_save_error"]);
}

fn durable_quiet_retirement_faults(faults: &[&str]) {
    use crate::durable_tail_store as store;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    struct ResetWriter;
    impl Drop for ResetWriter {
        fn drop(&mut self) {
            store::test_hooks::set_before_rename(None);
            sampled_scan::durable_tail::set_test_write_bytes(None);
        }
    }
    let _reset_writer = ResetWriter;
    let _clock = Clock::at(START);
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for &fault in faults {
            sampled_scan::set_test_now(Some(START));
            let fixture = ScanFixture::new(source);
            fixture.file.append(&usage(source, 100, 0, "fixture-model"));
            let scope = Scope(format!("quiet-writer-{fault}"));
            let state = fixture.dir.join("state");
            fs::create_dir_all(&state).unwrap();
            let lock = crate::locked_state_dir::test_locks::hold(&state);
            let index_path = state.join("index.json");
            let key = local_index_key(&fixture.file.0);
            let begin = || {
                let cache = Arc::new(sampled_scan::SharedCache::default());
                cache.durable_begin_pass(source, &index_path, &scope, true);
                cache
            };
            let cache = begin();
            let (mut index, _, _) = production_scan(
                &fixture,
                source,
                ScanIndex::default(),
                Some(cache.clone()),
                &scope.0,
            );
            index.save(&index_path).unwrap();
            assert_eq!(
                cache
                    .durable_write_after_save(lock, source, &index)
                    .unwrap()
                    .written,
                1
            );
            fixture.file.append(&usage(source, 130, 1, "fixture-model"));
            let (mut index, _, modes) =
                production_scan(&fixture, source, index, Some(cache.clone()), &scope.0);
            assert_eq!(modes, (0, 1, 0));
            assert!(index.files[&key].has_unverified_source());
            index.save(&index_path).unwrap();
            assert_eq!(
                cache
                    .durable_write_after_save(lock, source, &index)
                    .unwrap()
                    .written,
                1
            );
            let record_path = fs::read_dir(store::store_dir_for_index(&index_path))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let predecessor = fs::read(&record_path).unwrap();
            assert_eq!(predecessor[311], 1, "#865's envelope carries the debt");
            let full_time = cache
                .retained_checkpoint(&key)
                .unwrap()
                .last_full_verified();
            sampled_scan::set_test_now(Some(START + 2 * 60 * 60));
            let (mut index, _, modes) =
                production_scan(&fixture, source, index, Some(cache.clone()), &scope.0);
            assert_eq!(modes, (0, 0, 1));
            assert!(
                index.files[&key].has_unverified_source(),
                "no pre-writer clear"
            );
            assert_eq!(cache.retained_checkpoint(&key).unwrap().audit_debt(), None);
            assert_eq!(
                cache
                    .retained_checkpoint(&key)
                    .unwrap()
                    .last_full_verified(),
                full_time
            );
            if fault == "legacy_index_clear" {
                // Reproduce the old broken index-saved/old-record window, and
                // force its next actual visit without granting a new revision.
                let fp = index.files[&key].source_file_fingerprint.clone();
                assert!(index.retire_quiet_audit(&key, &fp));
                index.files.get_mut(&key).unwrap().last_snapshot_fingerprint = None;
            }
            index.save(&index_path).unwrap();
            assert_eq!(
                ScanIndex::load(&index_path).unwrap().files[&key].has_unverified_source(),
                fault != "legacy_index_clear"
            );
            let owed_due = index.files[&key].unverified_deadline();
            match fault {
                "deferral" => {
                    sampled_scan::durable_tail::set_test_write_bytes(Some(0));
                    assert_eq!(
                        cache
                            .durable_write_after_save(lock, source, &index)
                            .unwrap()
                            .written,
                        0
                    );
                    sampled_scan::durable_tail::set_test_write_bytes(None);
                    assert!(cache.durable_counters(source).unwrap().0.write_deferred > 0);
                    assert_eq!(
                        cache.durable_reconcile_retirements(lock, source, &mut index, &index_path),
                        0
                    );
                }
                "writer_error" => {
                    let hits = std::rc::Rc::new(std::cell::Cell::new(0));
                    let hook_hits = hits.clone();
                    store::test_hooks::set_before_rename(Some(Box::new(move |_, _| {
                        hook_hits.set(hook_hits.get() + 1);
                        Err(std::io::Error::other("injected quiet writer failure"))
                    })));
                    assert!(cache
                        .durable_write_after_save(lock, source, &index)
                        .is_none());
                    store::test_hooks::set_before_rename(None);
                    assert_eq!(hits.get(), 1, "reached the real writer rename");
                    assert_eq!(
                        cache.durable_reconcile_retirements(lock, source, &mut index, &index_path),
                        0
                    );
                }
                "receipt_before_index" | "scope_change" | "index_save_error" => {
                    assert_eq!(
                        cache
                            .durable_write_after_save(lock, source, &index)
                            .unwrap()
                            .written,
                        1
                    );
                    assert_eq!(fs::read(&record_path).unwrap()[311], 0);
                    if fault == "index_save_error" {
                        assert!(index.files[&key].audit_requires_full(START + 2 * 60 * 60));
                        // Advance the real index CAS without changing its owed
                        // marker. The retirement's second save must now fail.
                        let mut advanced = ScanIndex::load(&index_path).unwrap();
                        advanced.save(&index_path).unwrap();
                        let committed = fs::read(&index_path).unwrap();
                        assert_eq!(
                            index.clone().save(&index_path).unwrap_err().to_string(),
                            "local snapshot scan index changed concurrently"
                        );
                        assert_eq!(
                            cache.durable_reconcile_retirements(
                                lock,
                                source,
                                &mut index,
                                &index_path
                            ),
                            0,
                            "a durable receipt cannot authorize a failed index CAS"
                        );
                        assert_eq!(index.files[&key].unverified_deadline(), owed_due);
                        assert_eq!(fs::read(&index_path).unwrap(), committed);
                    }
                    if fault == "scope_change" {
                        cache.durable_begin_pass(
                            source,
                            &index_path,
                            &Scope("different-account-scope".into()),
                            true,
                        );
                        assert_eq!(
                            cache.durable_reconcile_retirements(
                                lock,
                                source,
                                &mut index,
                                &index_path
                            ),
                            0,
                            "a different scope cannot consume an old durable retirement receipt"
                        );
                    }
                    // Crash after durable success but before marker CAS.
                }
                _ => {}
            }
            if !matches!(
                fault,
                "receipt_before_index" | "scope_change" | "index_save_error"
            ) {
                assert_eq!(fs::read(&record_path).unwrap(), predecessor);
            }
            drop(cache);
            let restart = begin();
            let restart_index = ScanIndex::load(&index_path).unwrap();
            if fault == "index_save_error" {
                assert_eq!(restart_index.files[&key].unverified_deadline(), owed_due);
                assert!(restart_index.files[&key].audit_requires_full(START + 2 * 60 * 60));
            }
            let (mut loaded, _, modes) = production_scan(
                &fixture,
                source,
                restart_index,
                Some(restart.clone()),
                &scope.0,
            );
            assert_eq!(
                modes,
                if fault == "legacy_index_clear" {
                    (1, 0, 0)
                } else {
                    (0, 0, 1)
                }
            );
            if fault != "legacy_index_clear" {
                assert!(loaded.files[&key].has_unverified_source());
                if fault == "index_save_error" {
                    assert_eq!(restart.durable_counters(source).unwrap().0.restored, 1);
                    assert_eq!(loaded.files[&key].unverified_deadline(), owed_due);
                    assert!(loaded.files[&key].audit_requires_full(START + 2 * 60 * 60));
                    // None came from the real record, while the original index
                    // deadline still selected this Unchanged quiet audit. The
                    // successful reconcile below requires that audit to stage
                    // a NEW retirement; restore alone cannot stage or clear it.
                    assert_eq!(
                        restart.retained_checkpoint(&key).unwrap().audit_debt(),
                        None
                    );
                }
                assert_eq!(
                    restart
                        .retained_checkpoint(&key)
                        .unwrap()
                        .last_full_verified(),
                    full_time
                );
            } else {
                assert_eq!(
                    restart
                        .durable_counters(source)
                        .unwrap()
                        .0
                        .ineligible
                        .get("audit_carrier"),
                    Some(&1)
                );
            }
            loaded.save(&index_path).unwrap();
            restart
                .durable_write_after_save(lock, source, &loaded)
                .unwrap();
            let (_, diagnostics) = crate::local_resource_diagnostics::capture(|| {
                assert_eq!(
                    restart.durable_reconcile_retirements(lock, source, &mut loaded, &index_path),
                    usize::from(fault != "legacy_index_clear")
                );
            });
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|row| row["stage"] == "sampled_audit_retirement")
                    .count(),
                usize::from(fault != "legacy_index_clear")
            );
            assert!(!loaded.files[&key].has_unverified_source());
            assert_eq!(
                fs::read(&record_path).unwrap()[311],
                0,
                "same writer rewrote #865's debt carrier"
            );
            drop(restart);
            let (final_index, _, modes) = production_scan(
                &fixture,
                source,
                ScanIndex::load(&index_path).unwrap(),
                Some(begin()),
                &scope.0,
            );
            assert_eq!(
                modes,
                (0, 0, 0),
                "no repeated Full or retirement after restart"
            );
            assert!(!final_index.files[&key].has_unverified_source());
        }
    }
}

/// [behaviour] Secure absence retires audit debt; account holds require a second spaced probe.
#[test]
fn proven_absence_retires_missing_intermediate_but_keeps_unsafe_ancestor_debt() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for ancestor in ["present", "missing", "unsafe"] {
            let mut fixture = ScanFixture::new(source);
            let parent = fixture.root.join("absence-parent");
            fs::create_dir(&parent).unwrap();
            let path = parent.join(fixture.file.0.file_name().unwrap());
            fs::rename(&fixture.file.0, &path).unwrap();
            fixture.file.0 = path;
            fixture.file.append(&usage(source, 100, 0, "fixture-model"));
            let cache = Arc::new(sampled_scan::SharedCache::default());
            let (index, _, _) = production_scan(
                &fixture,
                source,
                ScanIndex::default(),
                Some(cache.clone()),
                "absence-retirement",
            );
            fixture.file.append(&usage(source, 130, 1, "fixture-model"));
            let (mut index, _, modes) = production_scan(
                &fixture,
                source,
                index,
                Some(cache.clone()),
                "absence-retirement",
            );
            let key = local_index_key(&fixture.file.0);
            assert_eq!(modes, (0, 1, 0));
            assert!(index.files[&key].has_unverified_source());
            // Compose E3's account-release carve-out on the Claude path.
            if source == SnapshotSource::ClaudeCode {
                index.claude_account_deferred_holds.insert(
                    key.clone(),
                    index.files[&key].source_file_fingerprint.clone(),
                );
            }
            let contents = fs::read(&fixture.file.0).unwrap();
            fs::remove_file(&fixture.file.0).unwrap();
            if ancestor != "present" {
                fs::remove_dir(&parent).unwrap();
            }
            if ancestor == "unsafe" {
                fs::write(&parent, b"not a readable directory").unwrap();
            }
            let ((mut retired, _, modes), diagnostics) =
                crate::local_resource_diagnostics::capture(|| {
                    production_scan(
                        &fixture,
                        source,
                        index,
                        Some(cache.clone()),
                        "absence-retirement",
                    )
                });
            assert_eq!(modes, (0, 0, 0));
            let mut diagnostics = diagnostics;
            if source == SnapshotSource::ClaudeCode {
                assert!(retired.claude_account_deferred_holds.contains_key(&key));
                assert!(retired.files[&key].has_unverified_source());
                sampled_scan::set_test_now(Some(sampled_scan::now_seconds() + 600));
                crate::snapshots::line_delivery_tests::next_walk(
                    &mut retired,
                    std::slice::from_ref(&fixture.root),
                    NOW,
                    BACKFILL_WINDOW_DAYS,
                );
                let ((next, _, modes), next_diagnostics) =
                    crate::local_resource_diagnostics::capture(|| {
                        production_scan(
                            &fixture,
                            source,
                            retired,
                            Some(cache.clone()),
                            "absence-retirement",
                        )
                    });
                assert_eq!(modes, (0, 0, 0));
                retired = next;
                diagnostics.extend(next_diagnostics);
            }
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|row| row["stage"] == "native_collection_page"
                        && row["counts"]["audit_retired_absent"]["events"] == 1)
                    .count(),
                usize::from(ancestor != "unsafe")
            );
            if ancestor == "unsafe" {
                assert!(retired.files[&key].has_unverified_source());
                if source == SnapshotSource::ClaudeCode {
                    assert!(retired.claude_account_deferred_holds.contains_key(&key));
                }
                continue;
            }
            assert!(!retired.files.contains_key(&key));
            assert_eq!(
                retired
                    .files
                    .values()
                    .filter(|entry| entry.has_unverified_source())
                    .count(),
                0,
                "slot freed by positive absence"
            );
            assert!(!retired.claude_account_deferred_holds.contains_key(&key));
            let index_path = fixture.dir.join("absence-index.json");
            retired.save(&index_path).unwrap();
            drop(cache);
            fs::create_dir_all(&parent).unwrap();
            fs::write(&fixture.file.0, contents).unwrap();
            let cold_owner = Arc::new(sampled_scan::SharedCache::default());
            let ((recreated, _, modes), diagnostics) =
                crate::local_resource_diagnostics::capture(|| {
                    production_scan(
                        &fixture,
                        source,
                        ScanIndex::load(&index_path).unwrap(),
                        Some(cold_owner),
                        "absence-retirement",
                    )
                });
            assert_eq!(modes, (1, 0, 0), "reappearance is A1 FirstRead");
            assert!(!recreated.files[&key].has_unverified_source());
            let page = diagnostics
                .iter()
                .find(|row| row["stage"] == "native_collection_page")
                .unwrap();
            assert_eq!(
                page["counts"]["sampled_acquisition"]["page_events"]["full_reasons"],
                json!({"state_missing":1})
            );
        }
    }
}

/// [behaviour] Protected history keeps custody while its absent audit retires.
#[test]
fn protected_codex_absence_retires_only_the_audit_obligation() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = Clock::at(START);
    let source = SnapshotSource::Codex;
    let fixture = ScanFixture::new(source);
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, _, _) = production_scan(
        &fixture,
        source,
        ScanIndex::default(),
        Some(cache.clone()),
        "protected-absence",
    );
    fixture.file.append(&usage(source, 130, 1, "fixture-model"));
    let (mut index, _, _) =
        production_scan(&fixture, source, index, Some(cache), "protected-absence");
    let key = local_index_key(&fixture.file.0);
    let owner = sha256_hex(&["protected-absence-fixture"]);
    index.files.get_mut(&key).unwrap().codex_protected_owner = Some(owner.clone());
    let fingerprints = index.file_snapshot_fingerprints.clone();
    fs::remove_file(&fixture.file.0).unwrap();
    ensure_bounded_traversal(
        source,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = index.traversal.as_mut().unwrap();
    traversal.observed_index_keys.clear();
    traversal.reconciliation_upper_bound = Some(key.clone());
    let (done, diagnostics) = crate::local_resource_diagnostics::capture(|| {
        let done = reconcile_missing_index_entries_with_side(&mut index, 10, None, source);
        crate::local_resource_diagnostics::Probe::start().collection(
            source.api_slug(),
            crate::local_resource_diagnostics::CollectionCounts {
                scanned_files: 0,
                semantic_noops: 0,
                sampled_acquisition: None,
                full_causes: Default::default(),
            },
        );
        done
    });
    assert!(done);
    assert!(!index.files[&key].has_unverified_source());
    assert_eq!(
        index.files[&key].codex_protected_owner.as_ref(),
        Some(&owner)
    );
    assert_eq!(index.file_snapshot_fingerprints, fingerprints);
    assert_eq!(
        diagnostics
            .iter()
            .filter(|row| row["stage"] == "native_collection_page"
                && row["counts"]["audit_retired_absent"]["events"] == 1)
            .count(),
        1
    );
}

#[test]
fn audit_absence_preserves_legacy_counting_evidence_or_retains_its_entry() {
    use codex_counting_version::{AckEvidence, CountingTombstone};
    let _cutover = codex_counting_version::TestCutover::set(1_790_000_000_000);
    for full_tombstones in [false, true] {
        let fixture = ScanFixture::new(SnapshotSource::Codex);
        let key = local_index_key(&fixture.file.0);
        let id = "019fa111-2222-7333-8444-555555555555";
        let owner = codex_protected_owner(id);
        let entry: ScanIndexEntry = serde_json::from_value(json!({
            "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp",
            "last_snapshot_fingerprint":"legacy-acked", "codex_counting_owner": owner,
            "scan_identity_version": sampled_audit::marker(1)
        }))
        .unwrap();
        assert!(!entry.codex_history_is_protected());
        let mut index = ScanIndex::default();
        index.files.insert(key.clone(), entry);
        ensure_bounded_traversal(
            SnapshotSource::Codex,
            std::slice::from_ref(&fixture.root),
            &mut index,
            NOW,
            BACKFILL_WINDOW_DAYS,
        );
        let traversal = index.traversal.as_mut().unwrap();
        traversal.observed_index_keys.clear();
        traversal.reconciliation_upper_bound = Some(key.clone());
        let generation = traversal.census_window_end.clone();
        if full_tombstones {
            index.codex_counting_tombstones = (0..codex_counting_version::MAX_COUNTING_TOMBSTONES)
                .map(|n| {
                    (
                        format!("{n:064x}"),
                        CountingTombstone {
                            evidence: AckEvidence::LegacyAcked,
                            retired_in: generation.clone(),
                            created_unix_ms: None,
                        },
                    )
                })
                .collect();
        }
        fs::remove_file(&fixture.file.0).unwrap();
        assert!(reconcile_missing_index_entries_with_side(
            &mut index,
            10,
            None,
            SnapshotSource::Codex
        ));
        if full_tombstones {
            assert_eq!(
                index.files[&key].last_snapshot_fingerprint.as_deref(),
                Some("legacy-acked")
            );
            assert!(
                !index.files[&key].has_unverified_source(),
                "only the fulfilled audit ends"
            );
            assert!(!index.codex_counting_tombstones.contains_key(&owner));
        } else {
            assert!(!index.files.contains_key(&key));
            assert_eq!(
                index.codex_counting_tombstones[&owner].evidence,
                AckEvidence::LegacyAcked
            );
        }
    }
}

/// [behaviour] Hold-only removal requires stable rooted absence twice.
#[test]
fn hold_only_inventory_requires_two_secure_absence_observations() {
    use std::os::unix::fs::symlink;
    for ancestor in [
        "present",
        "missing",
        "symlink",
        "dangling",
        "file",
        "root_missing",
    ] {
        let fixture = ScanFixture::new(SnapshotSource::ClaudeCode);
        let parent = fixture.root.join("held-parent");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("held-new.jsonl");
        match ancestor {
            "missing" => fs::remove_dir(&parent).unwrap(),
            "symlink" => {
                fs::remove_dir(&parent).unwrap();
                symlink(&fixture.dir, &parent).unwrap();
            }
            "dangling" => {
                fs::remove_dir(&parent).unwrap();
                symlink("unavailable-target", &parent).unwrap();
            }
            "file" => {
                fs::remove_dir(&parent).unwrap();
                fs::write(&parent, b"not a directory").unwrap();
            }
            "root_missing" => fs::remove_dir_all(&fixture.root).unwrap(),
            _ => {}
        }
        let key = local_index_key(&path);
        let mut index = ScanIndex::default();
        index
            .claude_account_deferred_holds
            .insert(key.clone(), "withheld-new-revision".into());
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&fixture.root),
            &mut index,
            NOW,
            BACKFILL_WINDOW_DAYS,
        );
        crate::snapshots::line_delivery_tests::walk_all(&mut index, BACKFILL_WINDOW_DAYS);
        assert!(index.files.is_empty(), "held-new has no committed entry");
        withheld_account::support::clock(&index.withheld_memo);
        sampled_scan::set_test_now(Some(1_000));
        withheld_account::support::clock(&index.withheld_memo);
        index.probe_absent_claude_account_deferred_holds();
        assert!(
            index.claude_account_deferred_holds.contains_key(&key),
            "one observation keeps custody"
        );
        crate::snapshots::line_delivery_tests::next_walk(
            &mut index,
            std::slice::from_ref(&fixture.root),
            NOW,
            BACKFILL_WINDOW_DAYS,
        );
        sampled_scan::set_test_now(Some(1_600));
        crate::local_resource_diagnostics::withheld_support::take_withheld();
        withheld_account::support::clock(&index.withheld_memo);
        index.probe_absent_claude_account_deferred_holds();
        let removed = matches!(ancestor, "present" | "missing");
        assert_eq!(
            !index.claude_account_deferred_holds.contains_key(&key),
            removed,
            "{ancestor}"
        );
        assert_eq!(
            crate::local_resource_diagnostics::withheld_support::take_withheld()[0],
            if removed {
                BTreeMap::from([("deleted", 1)])
            } else {
                BTreeMap::new()
            }
        );
        assert!(index.files.is_empty(), "no membership invented");
        sampled_scan::set_test_now(None);
    }
}

/// [behaviour] Inventory never probes an imported tail beyond the existing cap.
#[test]
fn hold_only_absence_inventory_never_exceeds_existing_4096_bound() {
    let fixture = ScanFixture::new(SnapshotSource::ClaudeCode);
    let blocked = fixture.root.join("a-unavailable");
    fs::write(&blocked, b"not a directory").unwrap();
    let eligible = local_index_key(&fixture.root.join("z-positively-missing.jsonl"));
    let mut index = ScanIndex::default();
    for n in 0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS {
        index.claude_account_deferred_holds.insert(
            local_index_key(&blocked.join(format!("{n:05}.jsonl"))),
            "held".into(),
        );
    }
    index
        .claude_account_deferred_holds
        .insert(eligible.clone(), "held-new".into());
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    crate::snapshots::line_delivery_tests::walk_all(&mut index, BACKFILL_WINDOW_DAYS);
    withheld_account::support::clock(&index.withheld_memo);
    index.probe_absent_claude_account_deferred_holds();
    assert_eq!(
        index.claude_account_deferred_holds.len(),
        MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS + 1
    );
    assert!(
        index.claude_account_deferred_holds.contains_key(&eligible),
        "over-bound imported tail was not probed or dropped"
    );
    // Indexed/hint callers can name an imported tail too; the central gate
    // must keep it even with memo capacity and two spaced secure absences.
    let members = index.observed_account_members();
    for now in [1_000, 1_600] {
        sampled_scan::set_test_now(Some(now));
        assert!(!index.retire_absent_account_hold(&eligible, &members));
        assert!(index.claude_account_deferred_holds.contains_key(&eligible));
    }
    index
        .claude_account_deferred_holds
        .retain(|key, _| key == &eligible);
    withheld_account::support::clock(&index.withheld_memo);
    index.probe_absent_claude_account_deferred_holds();
    assert_eq!(index.claude_account_deferred_hold_count(), 1);
    crate::snapshots::line_delivery_tests::next_walk(
        &mut index,
        std::slice::from_ref(&fixture.root),
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    sampled_scan::set_test_now(Some(sampled_scan::now_seconds() + 600));
    withheld_account::support::clock(&index.withheld_memo);
    index.probe_absent_claude_account_deferred_holds();
    sampled_scan::set_test_now(None);
    assert!(
        index.claude_account_deferred_holds.is_empty(),
        "the next bounded inventory proves eligible absence"
    );
    // A large missing population must leave some debt unadmitted rather than
    // pin a descriptor for every key; admitted batches must still make progress.
    for n in 0..80 {
        index.claude_account_deferred_holds.insert(
            local_index_key(&fixture.root.join(format!("missing-{n}.jsonl"))),
            "held".into(),
        );
    }
    sampled_scan::set_test_now(Some(1_000));
    withheld_account::support::clock(&index.withheld_memo);
    index.probe_absent_claude_account_deferred_holds();
    crate::snapshots::line_delivery_tests::next_walk(
        &mut index,
        std::slice::from_ref(&fixture.root),
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    sampled_scan::set_test_now(Some(1_600));
    withheld_account::support::clock(&index.withheld_memo);
    index.probe_absent_claude_account_deferred_holds();
    let remaining = index.claude_account_deferred_hold_count();
    assert!(
        remaining > 0 && remaining < 80,
        "descriptor admission keeps debt and makes progress"
    );
    for step in 2..=80 {
        crate::snapshots::line_delivery_tests::next_walk(
            &mut index,
            std::slice::from_ref(&fixture.root),
            NOW,
            BACKFILL_WINDOW_DAYS,
        );
        sampled_scan::set_test_now(Some(1_000 + step * 600));
        withheld_account::support::clock(&index.withheld_memo);
        index.probe_absent_claude_account_deferred_holds();
        if index.claude_account_deferred_hold_count() == 0 {
            break;
        }
    }
    assert_eq!(index.claude_account_deferred_hold_count(), 0);
    sampled_scan::set_test_now(None);
}
