//! Offline exact-body ACK regression fixtures. No installed state or providers.
use super::*;
use crate::snapshot_client::{SnapshotBatchResponse, SnapshotEntityRef, SnapshotEntityRejection};

fn items(count: usize) -> Vec<SnapshotItem> {
    (0..count)
        .map(|i| {
            let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
            item.source_session_id = format!("synthetic-{i}");
            item.cache_observations = None;
            item.cache_observations_state = None;
            item.snapshot_fingerprint =
                crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &item);
            item
        })
        .collect()
}

fn request(items: Vec<SnapshotItem>) -> SnapshotBatchRequest {
    SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "codex".into(),
        machine_id: "synthetic".into(),
        collector_version: None,
        snapshots: items,
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    }
}

fn reference(item: &SnapshotItem) -> SnapshotEntityRef {
    let version = crate::snapshots::snapshot_upload_body_witness_version(item).map(|v| match v {
        9 => 3,
        10 => 4,
        11 => 5,
        12 => 6,
        15 => 13,
        16 => 14,
        19 => 17,
        20 => 18,
        21 | 23 => {
            if item.cache_observations.is_some() {
                13
            } else {
                7
            }
        }
        22 | 24 => {
            if item.cache_observations.is_some() {
                14
            } else {
                8
            }
        }
        other => other,
    });
    SnapshotEntityRef {
        source_session_id: item.source_session_id.clone(),
        snapshot_fingerprint: item.snapshot_fingerprint.clone(),
        occurrence_count: 1,
        body_witness_version: version,
        body_witness_digest: version.map(|_| snapshot_upload_body_witness(item)),
        head_etag: None,
        head_challenge: None,
        unchanged_basis: None,
    }
}

fn response(items: &[SnapshotItem], rejected: usize) -> SnapshotBatchResponse {
    response_with_reason(items, rejected, "usage_accounting_authority_downgrade")
}

fn response_with_reason(
    items: &[SnapshotItem],
    rejected: usize,
    reason: &str,
) -> SnapshotBatchResponse {
    let mut refs = items[..items.len() - rejected]
        .iter()
        .map(reference)
        .collect::<Vec<_>>();
    refs.reverse(); // Response order is independent of request order.
    let unchanged = if refs.is_empty() {
        Vec::new()
    } else {
        vec![refs.remove(0)]
    };
    SnapshotBatchResponse {
        accepted: (items.len() - rejected) as u64,
        sessions_reconciled: 0,
        session_ids: Vec::new(),
        disabled: false,
        disabled_reason: None,
        entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
        accepted_entities: refs,
        unchanged_entities: unchanged,
        conflict_entities: Vec::new(),
        rejected_entities: items[items.len() - rejected..]
            .iter()
            .map(|item| SnapshotEntityRejection {
                source_session_id: item.source_session_id.clone(),
                snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                reason: reason.into(),
                detail: "not logged".into(),
                permanent: true,
                occurrence_count: 1,
            })
            .collect(),
    }
}

fn progress() -> SnapshotUploadProgress {
    SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
}

#[test]
#[serial_test::serial(client_report)]
fn h357_mixed_50_43_exact_ack_restart_holds_only_rejected_bodies() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let items = items(50);
    let mut ledger = progress();
    let mut accepted = 0;
    let outcome = upload_resumable_batches_with_body_witness(
        &items,
        "codex",
        &mut ledger,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let ack = response(&batch, 7);
            ack.validate_entity_ack(&request(batch))?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Rejected { count: 7 });
    assert_eq!(accepted, 43);
    assert_eq!(ledger.accepted_fingerprints.len(), 43);
    assert_eq!(ledger.quarantined_fingerprints.len(), 7);
    // The same serialized ledger used on restart retains exact body identities.
    let mut restarted: SnapshotUploadProgress =
        serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
    restarted.active_quarantine_witness = ledger.active_quarantine_witness.clone();
    assert!(!restarted.prepare_quarantine_retries(&BTreeMap::new()));
    let outcome = upload_resumable_batches_with_body_witness(
        &items,
        "codex",
        &mut restarted,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| panic!("neither accepted siblings nor not-yet-due rejections may resend"),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Rejected { count: 7 });
    assert_eq!(accepted, 43);
    for fp in restarted.quarantined_fingerprints.keys() {
        let i = items
            .iter()
            .find(|i| &i.snapshot_fingerprint == fp)
            .unwrap();
        assert!(restarted.contains_body(fp, &snapshot_upload_body_witness(i)));
        assert!(snapshot_quarantine_deadline_is_bounded(
            &restarted.quarantined_fingerprints[fp]
        ));
    }
}

#[test]
#[serial_test::serial(client_report)]
fn h357_missing_malformed_unknown_or_wrong_body_ack_never_certifies_a_page() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for case in [
        "missing",
        "malformed",
        "unknown",
        "wrong_body",
        "count",
        "overlap",
    ] {
        let items = items(3);
        let mut ledger = progress();
        let mut accepted = 0;
        let error = upload_resumable_batches_with_body_witness(
            &items,
            "codex",
            &mut ledger,
            &mut accepted,
            |i| i.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |batch| {
                let mut ack = response(&batch, 1);
                match case {
                    "missing" => {
                        ack.rejected_entities.clear();
                    }
                    "malformed" => {
                        ack.accepted_entities[0].snapshot_fingerprint = "bad".into();
                    }
                    "unknown" => {
                        ack.entity_ack_contract = Some("future:v9".into());
                    }
                    "wrong_body" => {
                        ack.accepted_entities[0].body_witness_digest = Some("0".repeat(64));
                    }
                    "count" => {
                        ack.accepted = 3;
                    }
                    "overlap" => {
                        ack.conflict_entities = ack.unchanged_entities.clone();
                    }
                    _ => unreachable!(),
                }
                ack.validate_entity_ack(&request(batch))?;
                Ok(ack)
            },
            |_| panic!("invalid ACK must not checkpoint"),
        )
        .unwrap_err();
        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::BackendResponse),
            "{case}"
        );
        assert!(upload_failure_diagnostic(&error).starts_with("kind=backend_response"));
        assert_eq!(accepted, 0);
        assert!(ledger.accepted_body_witnesses.is_empty());
        assert!(ledger.quarantined_fingerprints.is_empty());
    }
}

#[test]
#[serial_test::serial(client_report)]
fn h357_exact_ack_survives_later_timeout_and_changed_body_stays_owed() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut items = items(51);
    let mut ledger = progress();
    let mut accepted = 0;
    let mut pages = 0;
    let error = upload_resumable_batches_with_body_witness(
        &items,
        "codex",
        &mut ledger,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            pages += 1;
            if pages == 2 {
                return Err(anyhow!("synthetic timeout before ACK"));
            }
            let ack = response(&batch, 0);
            ack.validate_entity_ack(&request(batch))?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("synthetic timeout"));
    assert_eq!(accepted, 50);
    assert_eq!(ledger.accepted_body_witnesses.len(), 50);
    let settled = items
        .iter_mut()
        .find(|i| {
            ledger
                .accepted_fingerprints
                .contains(&i.snapshot_fingerprint)
        })
        .unwrap();
    let old = snapshot_upload_body_witness(settled);
    // A hash-neutral body change must not inherit another body's ACK.
    settled
        .context_curve
        .as_mut()
        .expect("curve-bearing fixture")
        .points[0]
        .effective_input_tokens += 1;
    assert_ne!(snapshot_upload_body_witness(settled), old);
    assert!(!ledger.contains_body(
        &settled.snapshot_fingerprint,
        &snapshot_upload_body_witness(settled)
    ));
}

#[test]
#[serial_test::serial(client_report)]
fn h357_reason_vocabulary_never_echoes_response_detail_or_unknown_reason() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let items = items(1);
    let mut ack = response(&items, 1);
    assert_eq!(
        ack.rejected_entities[0].safe_reason(),
        "usage_accounting_authority_downgrade"
    );
    ack.rejected_entities[0].reason = "secret /customer/path".into();
    assert_eq!(ack.rejected_entities[0].safe_reason(), "other");
}

#[test]
#[serial_test::serial(client_report)]
fn h357_terminal_partial_reports_exact_progress_without_a_clean_success_clock() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let counts = SyncCounts {
        uploaded_count: 43,
        ..SyncCounts::default()
    };
    let partial = collector_status_request(
        "h357-synthetic-only",
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "synthetic",
            scan_started_at: "2026-10-12T00:00:00Z",
            counts,
            state: deferred_entity_state(false),
        },
        false,
    )
    .unwrap();
    assert_eq!(partial.last_uploaded_count, 43);
    assert_eq!(partial.last_error_code.as_deref(), Some("server_error"));
    assert!(partial.last_success_at.is_none());
    assert!(partial.last_scan_finished_at.is_some());
    let clean = collector_status_request(
        "h357-synthetic-only",
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "synthetic",
            scan_started_at: "2026-10-12T00:00:00Z",
            counts: SyncCounts {
                census_complete: true,
                ..SyncCounts::default()
            },
            state: CollectorState::Success,
        },
        false,
    )
    .unwrap();
    assert!(clean.last_error_code.is_none());
    assert_eq!(clean.last_success_at, clean.last_scan_finished_at);
}

#[test]
#[serial_test::serial(client_report)]
fn h359_permanent_exact_body_survives_retirement_epoch_restart_and_premature_timer() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let items = items(1);
    let item = &items[0];
    let fp = item.snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(item);
    let mut ledger = progress();
    ledger.quarantine_permanent_body(&fp, &body, "usage_accounting_authority_downgrade");
    assert!(!ledger.accepted_fingerprints.contains(&fp));
    assert_eq!(
        ledger.quarantined_fingerprints[&fp].disposition,
        SnapshotQuarantineDisposition::UnprovenTerminal
    );
    let dir = std::env::temp_dir().join(format!(
        "ottto-h359-{}-{}",
        std::process::id(),
        current_unix_seconds()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("progress.json");
    ledger.save(&path).unwrap();
    ledger.finish_cycle(&path).unwrap();
    let mut witness = snapshot_quarantine_witness(SnapshotSource::Codex);
    witness.collector_version = "synthetic-new-parser-release".into();
    let mut restarted =
        SnapshotUploadProgress::load(&path, &"a".repeat(64), witness.clone()).unwrap();
    assert!(restarted.contains_body(&fp, &body));
    restarted.prepare_historical_replay("synthetic-next-replay");
    let mut stale = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex);
    stale.upload_body_witness = Some(body.clone());
    stale.retry_after_unix_seconds = 0; // Earlier deadline cannot revoke server permanence.
    assert!(!restarted.prepare_quarantine_retries(&BTreeMap::from([(fp.clone(), stale)])));
    // A replay can also have no surviving index quarantine to normalize.
    restarted.quarantined_fingerprints.clear();
    let mut accepted = 0;
    let outcome = upload_resumable_batches_with_body_witness(
        &items,
        "codex",
        &mut restarted,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| panic!("server-permanent exact body cannot resend"),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Rejected { count: 1 });
    assert_eq!(accepted, 0);
    assert_eq!(
        restarted.quarantined_fingerprints[&fp].disposition,
        SnapshotQuarantineDisposition::UnprovenTerminal
    );
    assert_eq!(
        restarted.quarantined_fingerprints[&fp]
            .upload_body_witness
            .as_deref(),
        Some(body.as_str())
    );
    let mut changed = item.clone();
    changed.context_curve.as_mut().unwrap().points[0].effective_input_tokens += 1;
    let outcome = upload_resumable_batches_with_body_witness(
        &[changed],
        "codex",
        &mut restarted,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let ack = response(&batch, 0);
            ack.validate_entity_ack(&request(batch))?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Completed);
    assert_eq!(accepted, 1);
    assert!(restarted.permanent_rejections.is_empty());
    // Same on-disk file cannot suppress another destination/account's candidate.
    let another = SnapshotUploadProgress::load(&path, &"b".repeat(64), witness).unwrap();
    assert!(!another.contains_body(&fp, &body));
    std::fs::remove_dir_all(dir).unwrap();
}

/// Refuse every body of a two-item page with `reason` through the real upload.
fn h359_all_rejected(reason: &str) -> (SnapshotUploadProgress, ResumableUploadResult, u64) {
    let items = items(2);
    let mut ledger = progress();
    let mut accepted = 0;
    let outcome = upload_resumable_batches_with_body_witness(
        &items,
        "codex",
        &mut ledger,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let ack = response_with_reason(&batch, 2, reason);
            ack.validate_entity_ack(&request(batch))?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Rejected { count: 2 });
    assert_eq!(accepted, 0);
    assert!(ledger.accepted_fingerprints.is_empty());
    (ledger, outcome, accepted)
}

/// A non-dominated refusal pins the error path through the production
/// chooser; the dominated twin is below.
#[test]
#[serial_test::serial(client_report)]
fn h359_all_rejected_is_finished_transport_with_incomplete_health_and_no_success_clock() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (ledger, outcome, accepted) = h359_all_rejected("invalid");
    let now = Instant::now();
    let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
    for _ in 0..8 {
        cadence.record_scan_failure(now);
    }
    record_finished_snapshot_cadence(
        &mut cadence,
        now,
        accepted,
        matches!(outcome, ResumableUploadResult::Deferred { .. }),
    );
    assert_eq!(cadence.state(), ottto_protocol::LocalCollectorState::Idle);
    let status = collector_status_request(
        "h359-synthetic",
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "synthetic",
            scan_started_at: "2026-10-12T00:00:00Z",
            counts: SyncCounts::default(),
            state: refused_entity_state(true, PermanentRefusalCounts::of(&ledger), true),
        },
        true,
    )
    .unwrap();
    assert_eq!(status.last_uploaded_count, 0);
    assert!(status.last_success_at.is_none());
    assert_eq!(
        status.last_error_code.as_deref(),
        Some("backend_validation_error")
    );
}

/// Twin of the test above: the same all-refused page with a dominated reason
/// goes through the settled-residue chooser instead of the error path.
#[test]
#[serial_test::serial(client_report)]
fn h359_all_dominated_rejected_reports_the_settled_residue_state() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (ledger, _, _) = h359_all_rejected(DOMINATED_DOWNGRADE);
    let refusals = PermanentRefusalCounts::of(&ledger);
    assert_eq!(
        refusals,
        PermanentRefusalCounts {
            total: 2,
            dominated: 2
        }
    );
    assert_eq!(
        reported_code(refused_entity_state(true, refusals, true)),
        None
    );
    assert_eq!(
        reported_code(refused_entity_state(true, refusals, false)),
        Some("backend_validation_error"),
        "an unsettled cycle keeps the error path"
    );
}

#[test]
#[serial_test::serial(client_report)]
fn h359_unrelated_refusal_never_blocks_a_healthy_exact_probe_page() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let all = items(2);
    let mut ledger = progress();
    ledger.quarantine_permanent_body(
        &all[0].snapshot_fingerprint,
        &snapshot_upload_body_witness(&all[0]),
        "usage_accounting_authority_downgrade",
    );
    let mut accepted = 0;
    let outcome = upload_resumable_batches_with_body_witness(
        &all[1..],
        "codex",
        &mut ledger,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let ack = response(&batch, 0);
            ack.validate_entity_ack(&request(batch))?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Completed);
    assert_eq!(accepted, 1);
    assert_eq!(ledger.permanent_rejections.len(), 1);
}

#[test]
#[serial_test::serial(client_report)]
fn h357_malformed_http200_is_typed_backend_response_not_network_failure() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&bytes[..end]);
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
        }
        let body = br#"{"accepted":"secret /customer/path"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    });
    let client = SnapshotApiClient::new(url);
    let error = client
        .upload_batch("synthetic-only", &request(items(1)), false)
        .unwrap_err();
    server.join().unwrap();
    assert!(!format!("{error:#}").contains("secret"));
    assert!(!format!("{error:?}").contains("/customer/path"));
    assert_eq!(
        snapshot_upload_error_class(&error),
        Some(SnapshotUploadErrorClass::BackendResponse)
    );
    assert_eq!(
        upload_failure_diagnostic(&error),
        "kind=backend_response, detail=snapshot batch response could not be decoded"
    );
}

#[test]
#[serial_test::serial(client_report)]
fn h359_refused_cache_probe_settles_without_head_and_healthy_sibling_continues() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let probes = items(2);
    let mut snapshots = probes.clone();
    for item in &mut snapshots {
        item.cache_observations = Some(crate::snapshots::cache_observations::CacheObservations {
            schema_version: 1,
            operations: Vec::new(),
            coverage: "complete".into(),
            omitted_observation_count: None,
        });
    }
    let mut ledger = progress();
    let rejected_fp = probes[1].snapshot_fingerprint.clone();
    let mut calls = Vec::new();
    bootstrap_cache_heads(
        &probes,
        "h359-probes",
        &mut ledger,
        true,
        |batch, cas| {
            calls.push((batch.len(), cas));
            let rejected = batch
                .iter()
                .filter(|i| i.snapshot_fingerprint == rejected_fp)
                .count();
            // `response` rejects the batch tail; batch order follows the
            // fingerprints, so put the refused probe last explicitly.
            let mut ordered = batch.clone();
            ordered.sort_by_key(|i| i.snapshot_fingerprint == rejected_fp);
            let mut ack = response(&ordered, rejected);
            if cas {
                for reference in ack
                    .accepted_entities
                    .iter_mut()
                    .chain(&mut ack.unchanged_entities)
                {
                    reference.head_etag = Some("e".repeat(64));
                }
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), cas)?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(calls, [(2, false), (1, true)]);
    assert!(!ledger
        .accepted_cache_heads
        .contains_key(&cache_session_key(&probes[1].source_session_id)));
    apply_bootstrapped_cache_heads(&mut snapshots, &ledger).unwrap();
    assert!(snapshots[0].cache_observations.is_some());
    assert_eq!(snapshots[0].cache_base_head_etag, Some("e".repeat(64)));
    assert!(snapshots[1].cache_observations.is_none());
    assert!(snapshots[1].cache_base_head_etag.is_none());
    assert_eq!(
        snapshot_upload_body_witness(&snapshots[1]),
        snapshot_upload_body_witness(&probes[1])
    );
    let mut accepted = 0;
    let outcome = upload_resumable_batches_with_body_witness(
        &snapshots,
        "h359-probes",
        &mut ledger,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            assert_eq!(batch.len(), 1);
            assert_ne!(batch[0].snapshot_fingerprint, rejected_fp);
            let mut ack = response(&batch, 0);
            for reference in ack
                .accepted_entities
                .iter_mut()
                .chain(&mut ack.unchanged_entities)
            {
                reference.head_etag = Some("e".repeat(64));
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), true)?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Rejected { count: 1 });
    assert_eq!(accepted, 1);
    let mut restarted: SnapshotUploadProgress =
        serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
    // Same refused probe completes without a request even after restart.
    bootstrap_cache_heads(
        &probes[1..],
        "h359-probes",
        &mut restarted,
        true,
        |_, _| panic!("unchanged refused probe cannot resend"),
        |_| Ok(()),
    )
    .unwrap();
    let mut changed = probes[1].clone();
    changed.context_curve.as_mut().unwrap().points[0].effective_input_tokens += 1;
    assert!(!restarted.contains_body(&rejected_fp, &snapshot_upload_body_witness(&changed)));
    // Missing proof without an exact refusal still fails closed.
    let mut missing = snapshots[0].clone();
    missing.cache_base_head_etag = None;
    assert!(apply_bootstrapped_cache_heads(&mut [missing], &progress()).is_err());
}

/// The same entity with an additive cache patch that needs a predecessor head.
fn with_cache(item: &SnapshotItem) -> SnapshotItem {
    let mut item = item.clone();
    item.cache_observations = Some(crate::snapshots::cache_observations::CacheObservations {
        schema_version: 1,
        operations: Vec::new(),
        coverage: "complete".into(),
        omitted_observation_count: None,
    });
    item
}

fn index_entry(source_file_fingerprint: &str) -> crate::snapshots::ScanIndexEntry {
    crate::snapshots::ScanIndexEntry {
        size_bytes: 1,
        modified_unix_seconds: 1,
        modified_unix_nanos: Some(1),
        source_file_fingerprint: source_file_fingerprint.into(),
        last_snapshot_fingerprint: Some("3".repeat(64)),
        last_upload_body_witness: None,
        scan_identity_version: None,
        codex_joined_member_set: None,
        codex_captured_joined_member_set: None,
        codex_protected_owner: None,
        codex_applied_tier_receipt: None,
        codex_applied_tier_receipt_required: false,
        codex_captured_tier_receipt: None,
        codex_captured_tier_receipt_required: false,
        codex_captured_uncommitted: false,
        codex_counting_v2: false,
        codex_counting_owner: None,
        effective_upload_body_witness_revision: 0,
        opened_changed_nanos: 0,
        opened_birth_nanos: 0,
    }
}

#[test]
#[serial_test::serial(client_report)]
fn h360_quarantined_probe_carries_exact_held_body_without_request() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for disposition in [
        SnapshotQuarantineDisposition::RetryPending,
        SnapshotQuarantineDisposition::SupersededTerminal,
        SnapshotQuarantineDisposition::UnprovenTerminal,
    ] {
        let probes = items(1);
        let fp = probes[0].snapshot_fingerprint.clone();
        let body = snapshot_upload_body_witness(&probes[0]);
        let mut ledger = progress();
        ledger.quarantine_retryable_body(&fp, &body);
        let record = ledger.quarantined_fingerprints.get_mut(&fp).unwrap();
        record.disposition = disposition;
        if disposition != SnapshotQuarantineDisposition::RetryPending {
            record.retry_after_unix_seconds = 0;
        }
        if disposition == SnapshotQuarantineDisposition::UnprovenTerminal {
            record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
        }
        assert!(snapshot_quarantine_deadline_is_bounded(
            &ledger.quarantined_fingerprints[&fp]
        ));
        assert!(
            cache_head_probe_held(&ledger, &probes[0]),
            "{disposition:?}"
        );
        let deferred = bootstrap_cache_heads(
            &probes,
            "h360-held",
            &mut ledger,
            true,
            |_, _| panic!("an exactly held probe body cannot resend"),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(deferred, 0, "{disposition:?}");
        assert!(ledger.accepted_cache_heads.is_empty());
        let mut snapshots = probes.iter().map(with_cache).collect::<Vec<_>>();
        assert_eq!(
            apply_bootstrapped_cache_heads(&mut snapshots, &ledger).unwrap(),
            1,
            "{disposition:?}"
        );
        assert!(snapshots[0].cache_observations.is_none());
        assert!(snapshots[0].cache_base_head_etag.is_none());
        assert_eq!(snapshot_upload_body_witness(&snapshots[0]), body);
        assert!(ledger.contains_body(&fp, &body));
        // The carried body settles through the ordinary uploader's suppression.
        let mut accepted = 0;
        let outcome = upload_resumable_batches_with_body_witness(
            &snapshots,
            "h360-held",
            &mut ledger,
            &mut accepted,
            |i| i.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |_| panic!("an exactly held body cannot resend"),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(outcome, ResumableUploadResult::Completed, "{disposition:?}");
        assert_eq!(accepted, 0);
        assert_eq!(
            ledger.quarantined_fingerprints[&fp].disposition,
            disposition
        );
        assert_eq!(
            ledger.quarantined_fingerprints[&fp]
                .upload_body_witness
                .as_deref(),
            Some(body.as_str())
        );
    }
    // Server permanence of the exact probe bytes dominates a runtime lease.
    let probes = items(1);
    let mut permanent = progress();
    permanent.quarantine_permanent_body(
        &probes[0].snapshot_fingerprint,
        &snapshot_upload_body_witness(&probes[0]),
        "usage_accounting_authority_downgrade",
    );
    permanent
        .active_quarantine_retries
        .insert(probes[0].snapshot_fingerprint.clone());
    assert!(cache_head_probe_held(&permanent, &probes[0]));
}

#[test]
#[serial_test::serial(client_report)]
fn h360_mixed_siblings_held_probe_does_not_block_healthy_head_or_unrelated_page() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let base = items(2);
    let session = base[0].source_session_id.clone();
    // Same session, a different semantic entity, and different additive bytes.
    let mut held = base[0].clone();
    held.output_tokens += 1;
    held.context_curve.as_mut().unwrap().points[0].effective_input_tokens += 1;
    held.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &held);
    let mut probes = vec![held, base[0].clone(), base[1].clone()];
    probes[0].source_file_fingerprint = Some("1".repeat(64));
    probes[1].source_file_fingerprint = Some("1".repeat(64));
    probes[2].source_file_fingerprint = Some("2".repeat(64));
    let held_fp = probes[0].snapshot_fingerprint.clone();
    let held_body = snapshot_upload_body_witness(&probes[0]);
    assert_eq!(probes[1].source_session_id, session);
    assert_ne!(held_fp, probes[1].snapshot_fingerprint);
    assert_ne!(held_body, snapshot_upload_body_witness(&probes[1]));
    let head_for = |session_id: &str| {
        if session_id == session {
            "1".repeat(64)
        } else {
            "2".repeat(64)
        }
    };
    let dir = std::env::temp_dir().join(format!(
        "ottto-h360-mixed-{}-{}",
        std::process::id(),
        current_unix_seconds()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let progress_path = dir.join("progress.json");
    let mut ledger = progress();
    ledger.quarantine_retryable_body(&held_fp, &held_body);
    let mut calls = Vec::new();
    let deferred = bootstrap_cache_heads(
        &probes,
        "h360-mixed",
        &mut ledger,
        true,
        |batch, cas| {
            assert!(
                batch
                    .iter()
                    .all(|item| item.snapshot_fingerprint != held_fp),
                "held probe bytes never resend"
            );
            calls.push((batch.len(), cas));
            let mut ack = response(&batch, 0);
            if cas {
                for reference in ack
                    .accepted_entities
                    .iter_mut()
                    .chain(&mut ack.unchanged_entities)
                {
                    reference.head_etag = Some(head_for(reference.source_session_id.as_str()));
                }
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), cas)?;
            Ok(ack)
        },
        |state| state.save(&progress_path),
    )
    .unwrap();
    assert_eq!(deferred, 0);
    assert_eq!(calls, [(2, false), (2, true)]);
    assert_eq!(
        ledger
            .accepted_cache_heads
            .get(&cache_session_key(&session)),
        Some(&"1".repeat(64))
    );
    assert_eq!(
        ledger
            .accepted_cache_heads
            .get(&cache_session_key(&probes[2].source_session_id)),
        Some(&"2".repeat(64))
    );
    let mut snapshots = probes.iter().map(with_cache).collect::<Vec<_>>();
    assert_eq!(
        apply_bootstrapped_cache_heads(&mut snapshots, &ledger).unwrap(),
        1
    );
    // The sibling's fresh session head never authorizes the held entity's bytes.
    assert!(snapshots[0].cache_observations.is_none());
    assert!(snapshots[0].cache_base_head_etag.is_none());
    assert_eq!(snapshot_upload_body_witness(&snapshots[0]), held_body);
    assert!(snapshots[1].cache_observations.is_some());
    assert_eq!(snapshots[1].cache_base_head_etag, Some("1".repeat(64)));
    assert!(snapshots[2].cache_observations.is_some());
    assert_eq!(snapshots[2].cache_base_head_etag, Some("2".repeat(64)));
    let mut accepted = 0;
    let outcome = upload_resumable_batches_with_body_witness(
        &snapshots,
        "h360-mixed",
        &mut ledger,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            assert_eq!(batch.len(), 2);
            for item in &batch {
                assert_ne!(item.snapshot_fingerprint, held_fp);
                assert!(item.cache_observations.is_some());
                assert_eq!(
                    item.cache_base_head_etag,
                    Some(head_for(item.source_session_id.as_str()))
                );
            }
            let mut ack = response(&batch, 0);
            for reference in ack
                .accepted_entities
                .iter_mut()
                .chain(&mut ack.unchanged_entities)
            {
                reference.head_etag = Some(head_for(reference.source_session_id.as_str()));
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), true)?;
            Ok(ack)
        },
        |state| state.save(&progress_path),
    )
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Completed);
    assert_eq!(accepted, 2);
    assert!(ledger.contains_body(&held_fp, &held_body));
    // Session one's file owns both siblings; session two's file is unrelated.
    let mut index = ScanIndex::default();
    index
        .files
        .insert("synthetic/s1.jsonl".into(), index_entry(&"1".repeat(64)));
    index
        .files
        .insert("synthetic/s2.jsonl".into(), index_entry(&"2".repeat(64)));
    index.file_snapshot_fingerprints.insert(
        "synthetic/s1.jsonl".into(),
        BTreeSet::from([held_fp.clone(), probes[1].snapshot_fingerprint.clone()]),
    );
    index.file_snapshot_fingerprints.insert(
        "synthetic/s2.jsonl".into(),
        BTreeSet::from([probes[2].snapshot_fingerprint.clone()]),
    );
    let committed = ScanIndex::default();
    let checkpoint = checkpoint_partial_snapshot_index(
        &index,
        &committed,
        &ledger,
        &snapshots,
        None,
        &BTreeSet::new(),
        &dir.join("index.json"),
        &progress_path,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(
        checkpoint.files.keys().cloned().collect::<Vec<_>>(),
        ["synthetic/s1.jsonl", "synthetic/s2.jsonl"]
    );
    assert_eq!(
        checkpoint
            .quarantined_snapshot_fingerprints
            .keys()
            .collect::<Vec<_>>(),
        [&held_fp]
    );
    assert_eq!(
        checkpoint.quarantined_snapshot_fingerprints[&held_fp]
            .upload_body_witness
            .as_deref(),
        Some(held_body.as_str())
    );
    // Without exact carriage only the file owning the unsettled bytes waits.
    let mut uncarried = snapshots.clone();
    uncarried[0] = with_cache(&probes[0]);
    let held_back = checkpoint_partial_snapshot_index(
        &index,
        &committed,
        &ledger,
        &uncarried,
        None,
        &BTreeSet::new(),
        &dir.join("uncarried-index.json"),
        &progress_path,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(
        held_back.files.keys().cloned().collect::<Vec<_>>(),
        ["synthetic/s2.jsonl"]
    );
    assert!(held_back.quarantined_snapshot_fingerprints.is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[serial_test::serial(client_report)]
fn h360_preflight_rejected_probe_self_quarantines_then_settles_as_held() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let probes = items(2);
    let oversize_fp = probes[0].snapshot_fingerprint.clone();
    let oversize_body = snapshot_upload_body_witness(&probes[0]);
    let dir = std::env::temp_dir().join(format!(
        "ottto-h360-preflight-{}-{}",
        std::process::id(),
        current_unix_seconds()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("progress.json");
    let mut ledger = progress();
    let mut calls = Vec::new();
    let deferred = bootstrap_cache_heads(
        &probes,
        "h360-preflight",
        &mut ledger,
        true,
        |batch, cas| {
            calls.push((batch.len(), cas));
            if let Some(position) = batch
                .iter()
                .position(|item| item.snapshot_fingerprint == oversize_fp)
            {
                return Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                    reason: format!("snapshot[{position}] wire body exceeds the item byte limit"),
                }));
            }
            let mut ack = response(&batch, 0);
            if cas {
                for reference in ack
                    .accepted_entities
                    .iter_mut()
                    .chain(&mut ack.unchanged_entities)
                {
                    reference.head_etag = Some("e".repeat(64));
                }
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), cas)?;
            Ok(ack)
        },
        |state| state.save(&path),
    )
    .unwrap();
    assert_eq!(
        deferred, 0,
        "a local preflight hold is not a backend conflict"
    );
    assert_eq!(calls, [(2, false), (1, false), (1, true)]);
    // The self-quarantine is durable before any later cycle relies on it.
    let mut ledger = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert_eq!(
        ledger.quarantined_fingerprints[&oversize_fp]
            .upload_body_witness
            .as_deref(),
        Some(oversize_body.as_str())
    );
    assert!(cache_head_probe_held(&ledger, &probes[0]));
    let mut snapshots = probes.iter().map(with_cache).collect::<Vec<_>>();
    assert_eq!(
        apply_bootstrapped_cache_heads(&mut snapshots, &ledger).unwrap(),
        1
    );
    assert!(snapshots[0].cache_observations.is_none());
    assert_eq!(snapshots[1].cache_base_head_etag, Some("e".repeat(64)));
    // Not yet due: the next cycle spends no request on the held probe.
    let deferred = bootstrap_cache_heads(
        &probes[..1],
        "h360-preflight",
        &mut ledger,
        true,
        |_, _| panic!("a not-yet-due local hold cannot resend"),
        |state| state.save(&path),
    )
    .unwrap();
    assert_eq!(deferred, 0);
    // Due: the lease sends the probe once; a repeat preflight failure re-holds it.
    ledger
        .quarantined_fingerprints
        .get_mut(&oversize_fp)
        .unwrap()
        .retry_after_unix_seconds = 0;
    assert!(ledger.prepare_quarantine_retries(&BTreeMap::new()));
    assert!(!cache_head_probe_held(&ledger, &probes[0]));
    let mut retries = 0;
    let deferred = bootstrap_cache_heads(
        &probes[..1],
        "h360-preflight",
        &mut ledger,
        true,
        |_, _| {
            retries += 1;
            Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                reason: "snapshot[0] wire body exceeds the item byte limit".into(),
            }))
        },
        |state| state.save(&path),
    )
    .unwrap();
    assert_eq!((deferred, retries), (0, 1));
    assert!(cache_head_probe_held(&ledger, &probes[0]));
    let mut snapshots = vec![with_cache(&probes[0])];
    assert_eq!(
        apply_bootstrapped_cache_heads(&mut snapshots, &ledger).unwrap(),
        1
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[serial_test::serial(client_report)]
fn h360_probe_conflict_defers_without_source_abort_and_merges_count() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let probes = items(2);
    let conflict_fp = probes[0].snapshot_fingerprint.clone();
    let mut ledger = progress();
    let mut calls = Vec::new();
    let deferred = bootstrap_cache_heads(
        &probes,
        "h360-conflict",
        &mut ledger,
        true,
        |batch, cas| {
            calls.push((batch.len(), cas));
            let mut ack = response(&batch, 0);
            if cas {
                for reference in ack
                    .accepted_entities
                    .iter_mut()
                    .chain(&mut ack.unchanged_entities)
                {
                    reference.head_etag = Some("e".repeat(64));
                }
                ack.conflict_entities = ack
                    .accepted_entities
                    .iter()
                    .chain(&ack.unchanged_entities)
                    .filter(|reference| reference.snapshot_fingerprint == conflict_fp)
                    .cloned()
                    .collect();
                ack.accepted_entities
                    .retain(|reference| reference.snapshot_fingerprint != conflict_fp);
                ack.unchanged_entities
                    .retain(|reference| reference.snapshot_fingerprint != conflict_fp);
                for reference in &mut ack.conflict_entities {
                    reference.head_etag = None;
                    reference.head_challenge = Some("c".repeat(64));
                }
                ack.accepted -= ack.conflict_entities.len() as u64;
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), cas)?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(deferred, 1);
    assert_eq!(calls, [(2, false), (2, true)]);
    assert_eq!(
        ledger.quarantined_fingerprints[&conflict_fp].disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    assert!(!ledger
        .accepted_cache_heads
        .contains_key(&cache_session_key(&probes[0].source_session_id)));
    let mut snapshots = probes.iter().map(with_cache).collect::<Vec<_>>();
    assert_eq!(
        apply_bootstrapped_cache_heads(&mut snapshots, &ledger).unwrap(),
        1
    );
    assert!(snapshots[0].cache_observations.is_none());
    assert_eq!(snapshots[1].cache_base_head_etag, Some("e".repeat(64)));
    let mut accepted = 0;
    let outcome = upload_resumable_batches_with_body_witness(
        &snapshots,
        "h360-conflict",
        &mut ledger,
        &mut accepted,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            assert_eq!(batch.len(), 1);
            assert_ne!(batch[0].snapshot_fingerprint, conflict_fp);
            let mut ack = response(&batch, 0);
            for reference in ack
                .accepted_entities
                .iter_mut()
                .chain(&mut ack.unchanged_entities)
            {
                reference.head_etag = Some("e".repeat(64));
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), true)?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Completed);
    assert_eq!(accepted, 1);
    assert_eq!(
        with_bootstrap_deferred(outcome, deferred),
        ResumableUploadResult::Deferred { count: 1 }
    );
    // Deferred dominates refusal as in the partitioned uploader.
    assert_eq!(
        with_bootstrap_deferred(ResumableUploadResult::Rejected { count: 2 }, 1),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert_eq!(
        with_bootstrap_deferred(ResumableUploadResult::Deferred { count: 2 }, 1),
        ResumableUploadResult::Deferred { count: 3 }
    );
    assert_eq!(
        with_bootstrap_deferred(ResumableUploadResult::Rejected { count: 2 }, 0),
        ResumableUploadResult::Rejected { count: 2 }
    );
    assert_eq!(
        with_bootstrap_deferred(ResumableUploadResult::Completed, 0),
        ResumableUploadResult::Completed
    );
    assert_eq!(
        with_bootstrap_deferred(
            ResumableUploadResult::Shed {
                retry_after: Some(Duration::from_secs(7))
            },
            1
        ),
        ResumableUploadResult::Shed {
            retry_after: Some(Duration::from_secs(7))
        }
    );
    assert_eq!(
        with_bootstrap_deferred(ResumableUploadResult::Disabled(None), 1),
        ResumableUploadResult::Disabled(None)
    );
    // A shed or disabled probe stage still aborts before any main upload.
    crate::client_report::reset_for_test();
    for case in ["shed", "disabled"] {
        let mut ledger = progress();
        let error = bootstrap_cache_heads(
            &probes,
            "h360-conflict",
            &mut ledger,
            true,
            |_, _| match case {
                "shed" => Err(anyhow::Error::new(UploadShed {
                    status: 429,
                    retry_after: None,
                    code: None,
                })),
                _ => Ok(SnapshotBatchResponse {
                    accepted: 0,
                    sessions_reconciled: 0,
                    session_ids: Vec::new(),
                    disabled: true,
                    disabled_reason: None,
                    entity_ack_contract: None,
                    accepted_entities: Vec::new(),
                    unchanged_entities: Vec::new(),
                    rejected_entities: Vec::new(),
                    conflict_entities: Vec::new(),
                }),
            },
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<SnapshotAckRejected>()
                .map(|rejected| rejected.reason),
            Some("cache head probe did not settle exact predecessor evidence"),
            "{case}"
        );
        assert!(ledger.accepted_cache_heads.is_empty());
    }
    crate::client_report::reset_for_test();
}

#[test]
#[serial_test::serial(client_report)]
fn h360_unexact_leased_or_accepted_probe_refuses_held_fallback() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let probe = items(1).remove(0);
    let fp = probe.snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(&probe);
    let cache_bearing = with_cache(&probe);
    let mut older = probe.clone();
    older.context_curve.as_mut().unwrap().points[0].effective_input_tokens += 1;
    assert_eq!(
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &older),
        fp
    );
    for case in [
        "cache_bearing_body",
        "older_body",
        "witnessless",
        "leased",
        "accepted",
        "never_attempted",
    ] {
        let mut ledger = progress();
        match case {
            "cache_bearing_body" => {
                ledger.quarantine_retryable_body(&fp, &snapshot_upload_body_witness(&cache_bearing))
            }
            "older_body" => {
                ledger.quarantine_retryable_body(&fp, &snapshot_upload_body_witness(&older))
            }
            "witnessless" => {
                ledger.quarantine_retryable_body(&fp, &body);
                ledger
                    .quarantined_fingerprints
                    .get_mut(&fp)
                    .unwrap()
                    .upload_body_witness = None;
            }
            "leased" => {
                ledger.quarantine_retryable_body(&fp, &body);
                ledger
                    .quarantined_fingerprints
                    .get_mut(&fp)
                    .unwrap()
                    .retry_after_unix_seconds = 0;
                assert!(ledger.prepare_quarantine_retries(&BTreeMap::new()));
            }
            "accepted" => ledger.record_body(&fp, &body),
            "never_attempted" => {}
            _ => unreachable!(),
        }
        assert!(!cache_head_probe_held(&ledger, &probe), "{case}");
        let mut snapshots = vec![cache_bearing.clone()];
        let error = apply_bootstrapped_cache_heads(&mut snapshots, &ledger).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<SnapshotAckRejected>()
                .map(|rejected| rejected.reason),
            Some("cache head probe lacks accepted predecessor token"),
            "{case}"
        );
        assert!(snapshots[0].cache_observations.is_some(), "{case}");
        assert!(snapshots[0].cache_base_head_etag.is_none(), "{case}");
    }
}

#[test]
#[serial_test::serial(client_report)]
fn h360_legacy_count_only_cas_ack_still_fails_closed_without_head() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    // A count-only response can acknowledge only evidence-free bodies.
    let mut probe = items(1).remove(0);
    probe.context_curve = None;
    probe.session_account_evidence = None;
    probe.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &probe);
    let mut ledger = progress();
    let mut calls = Vec::new();
    let deferred = bootstrap_cache_heads(
        std::slice::from_ref(&probe),
        "h360-legacy",
        &mut ledger,
        true,
        |batch, cas| {
            calls.push((batch.len(), cas));
            let mut ack = response(&batch, 0);
            if cas {
                ack.entity_ack_contract = None;
                ack.accepted_entities.clear();
                ack.unchanged_entities.clear();
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), cas)?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(deferred, 0);
    assert_eq!(calls, [(1, false), (1, true)]);
    assert!(ledger.accepted_cache_heads.is_empty());
    assert!(!cache_head_probe_held(&ledger, &probe));
    let mut snapshots = vec![with_cache(&probe)];
    let error = apply_bootstrapped_cache_heads(&mut snapshots, &ledger).unwrap_err();
    assert_eq!(
        snapshot_upload_error_class(&error),
        Some(SnapshotUploadErrorClass::BackendResponse)
    );
    assert_eq!(
        upload_failure_diagnostic(&error),
        "kind=backend_response, detail=cache head probe lacks accepted predecessor token"
    );
    assert!(snapshots[0].cache_observations.is_some());
}

#[test]
#[serial_test::serial(client_report)]
fn h360_body_witness_mismatch_in_cas_stage_mints_no_head() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let probes = items(1);
    let mut ledger = progress();
    let saves = std::cell::Cell::new(0usize);
    let saves_before_cas = std::cell::Cell::new(None);
    let error = bootstrap_cache_heads(
        &probes,
        "h360-witness",
        &mut ledger,
        true,
        |batch, cas| {
            let mut ack = response(&batch, 0);
            if cas {
                saves_before_cas.set(Some(saves.get()));
                for reference in ack
                    .accepted_entities
                    .iter_mut()
                    .chain(&mut ack.unchanged_entities)
                {
                    reference.head_etag = Some("e".repeat(64));
                    reference.body_witness_digest = Some("0".repeat(64));
                }
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), cas)?;
            Ok(ack)
        },
        |_| {
            saves.set(saves.get() + 1);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(
        snapshot_upload_error_class(&error),
        Some(SnapshotUploadErrorClass::BackendResponse)
    );
    assert_eq!(
        upload_failure_diagnostic(&error),
        "kind=backend_response, detail=snapshot ACK lacks exact durable context curve body witness proof"
    );
    assert_eq!(saves_before_cas.get(), Some(saves.get()));
    assert!(ledger.accepted_cache_heads.is_empty());
    assert!(!cache_head_probe_held(&ledger, &probes[0]));
}

#[test]
#[serial_test::serial(client_report)]
fn h360_persist_failure_after_cas_ack_certifies_nothing_and_resumes_cas_only() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let probes = items(1);
    let dir = std::env::temp_dir().join(format!(
        "ottto-h360-persist-{}-{}",
        std::process::id(),
        current_unix_seconds()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("progress.json");
    let mut ledger = progress();
    let cas_stage = std::cell::Cell::new(false);
    let error = bootstrap_cache_heads(
        &probes,
        "h360-persist",
        &mut ledger,
        true,
        |batch, cas| {
            cas_stage.set(cas);
            let mut ack = response(&batch, 0);
            if cas {
                for reference in ack
                    .accepted_entities
                    .iter_mut()
                    .chain(&mut ack.unchanged_entities)
                {
                    reference.head_etag = Some("e".repeat(64));
                }
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), cas)?;
            Ok(ack)
        },
        |state| {
            if cas_stage.get() {
                Err(anyhow!("synthetic disk full"))
            } else {
                state.save(&path)
            }
        },
    )
    .unwrap_err();
    assert_eq!(
        snapshot_upload_error_class(&error),
        Some(SnapshotUploadErrorClass::LocalState)
    );
    assert_eq!(
        upload_failure_diagnostic(&error),
        "kind=local_state, operation=save upload checkpoint"
    );
    let mut restarted = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert!(restarted.accepted_cache_heads.is_empty());
    assert!(!cache_head_probe_held(&restarted, &probes[0]));
    assert!(apply_bootstrapped_cache_heads(&mut [with_cache(&probes[0])], &restarted).is_err());
    // The durable ordinary ACK skips stage one; only the CAS repeat is resent.
    let mut calls = Vec::new();
    let deferred = bootstrap_cache_heads(
        &probes,
        "h360-persist",
        &mut restarted,
        true,
        |batch, cas| {
            calls.push((batch.len(), cas));
            let mut ack = response(&batch, 0);
            for reference in ack
                .accepted_entities
                .iter_mut()
                .chain(&mut ack.unchanged_entities)
            {
                reference.head_etag = Some("e".repeat(64));
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), cas)?;
            Ok(ack)
        },
        |state| state.save(&path),
    )
    .unwrap();
    assert_eq!(deferred, 0);
    assert_eq!(calls, [(1, true)]);
    let mut snapshots = vec![with_cache(&probes[0])];
    assert_eq!(
        apply_bootstrapped_cache_heads(&mut snapshots, &restarted).unwrap(),
        0
    );
    assert_eq!(snapshots[0].cache_base_head_etag, Some("e".repeat(64)));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[serial_test::serial(client_report)]
fn h360_head_required_mode_has_no_probe_and_held_body_never_retires_pending_head() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let probe = items(1).remove(0);
    let item = with_cache(&probe);
    let mut index = ScanIndex::default();
    index.files.insert(
        "synthetic/required.jsonl".into(),
        index_entry(item.source_file_fingerprint.as_deref().unwrap()),
    );
    index.file_snapshot_fingerprints.insert(
        "synthetic/required.jsonl".into(),
        BTreeSet::from([item.snapshot_fingerprint.clone()]),
    );
    let mut ledger = progress();
    assert!(ledger
        .record_pending_cache_head(&item, &cache_head_file_groups(&index), true)
        .unwrap());
    // Required CAS strips the patch, so no probe forms and nothing bootstraps.
    let mut projected = item.clone();
    prepare_snapshot_cache_for_upload(&mut projected, &ledger, true, true, &BTreeSet::new());
    assert!(projected.cache_observations.is_none());
    assert_eq!(
        apply_bootstrapped_cache_heads(std::slice::from_mut(&mut projected), &ledger).unwrap(),
        0
    );
    let dir = std::env::temp_dir().join(format!(
        "ottto-h360-required-{}-{}",
        std::process::id(),
        current_unix_seconds()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("progress.json");
    ledger.save(&path).unwrap();
    ledger.finish_cycle(&path).unwrap();
    let mut restarted = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert_eq!(restarted.pending_cache_heads.len(), 1);
    // A sibling-minted session head plus an exactly held probe is not enrichment.
    restarted
        .accepted_cache_heads
        .insert(cache_session_key(&probe.source_session_id), "e".repeat(64));
    restarted.quarantine_retryable_body(
        &probe.snapshot_fingerprint,
        &snapshot_upload_body_witness(&probe),
    );
    let mut carried = vec![item];
    assert_eq!(
        apply_bootstrapped_cache_heads(&mut carried, &restarted).unwrap(),
        1
    );
    assert!(carried[0].cache_base_head_etag.is_none());
    let witnesses = restarted.pending_cache_head_file_witnesses(&index);
    restarted.retire_pending_cache_heads(&index, &carried, &BTreeSet::new(), true, &witnesses);
    assert_eq!(restarted.pending_cache_heads.len(), 1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[serial_test::serial(client_report)]
fn h360_restart_restores_held_probe_quarantine_from_index_and_retries_when_due() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let probes = items(1);
    let fp = probes[0].snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(&probes[0]);
    let dir = std::env::temp_dir().join(format!(
        "ottto-h360-restore-{}-{}",
        std::process::id(),
        current_unix_seconds()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let index_path = dir.join("index.json");
    let progress_path = dir.join("progress.json");
    let mut ledger = progress();
    ledger.quarantine_retryable_body(&fp, &body);
    // Completed-cycle commit: the index keeps the exact record, the ledger retires.
    let mut index = ScanIndex::default();
    index
        .file_snapshot_fingerprints
        .insert("synthetic/held.jsonl".into(), BTreeSet::from([fp.clone()]));
    index.retain_quarantined_fingerprints(&ledger.quarantined_fingerprints);
    index.save(&index_path).unwrap();
    ledger.save(&progress_path).unwrap();
    ledger.finish_cycle(&progress_path).unwrap();
    let loaded = ScanIndex::load(&index_path).unwrap();
    assert_eq!(
        loaded.quarantined_snapshot_fingerprints[&fp]
            .upload_body_witness
            .as_deref(),
        Some(body.as_str())
    );
    let witness = snapshot_quarantine_witness(SnapshotSource::Codex);
    let mut restarted =
        SnapshotUploadProgress::load(&progress_path, &"a".repeat(64), witness.clone()).unwrap();
    assert!(!restarted.contains_body(&fp, &body));
    assert!(!restarted.prepare_quarantine_retries(&loaded.quarantined_snapshot_fingerprints));
    assert!(cache_head_probe_held(&restarted, &probes[0]));
    let deferred = bootstrap_cache_heads(
        &probes,
        "h360-restore",
        &mut restarted,
        true,
        |_, _| panic!("a restored, not-yet-due hold cannot resend"),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(deferred, 0);
    let mut snapshots = probes.iter().map(with_cache).collect::<Vec<_>>();
    assert_eq!(
        apply_bootstrapped_cache_heads(&mut snapshots, &restarted).unwrap(),
        1
    );
    // Once the committed record is due, the lease sends exactly that probe.
    let mut due = loaded.quarantined_snapshot_fingerprints.clone();
    due.get_mut(&fp).unwrap().retry_after_unix_seconds = 0;
    let mut retry = SnapshotUploadProgress::load(&progress_path, &"a".repeat(64), witness).unwrap();
    assert!(retry.prepare_quarantine_retries(&due));
    assert!(!cache_head_probe_held(&retry, &probes[0]));
    let mut calls = Vec::new();
    let deferred = bootstrap_cache_heads(
        &probes,
        "h360-restore",
        &mut retry,
        true,
        |batch, cas| {
            assert_eq!(batch[0].snapshot_fingerprint, fp);
            calls.push((batch.len(), cas));
            let mut ack = response(&batch, 0);
            if cas {
                for reference in ack
                    .accepted_entities
                    .iter_mut()
                    .chain(&mut ack.unchanged_entities)
                {
                    reference.head_etag = Some("e".repeat(64));
                }
            }
            ack.validate_entity_ack_with_head_cas(&request(batch), cas)?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(deferred, 0);
    assert_eq!(calls, [(1, false), (1, true)]);
    let mut snapshots = probes.iter().map(with_cache).collect::<Vec<_>>();
    assert_eq!(
        apply_bootstrapped_cache_heads(&mut snapshots, &retry).unwrap(),
        0
    );
    assert!(snapshots[0].cache_observations.is_some());
    assert_eq!(snapshots[0].cache_base_head_etag, Some("e".repeat(64)));
    std::fs::remove_dir_all(dir).unwrap();
}

const DOMINATED_DOWNGRADE: &str = "usage_accounting_authority_downgrade";
const DOMINATED_STALE: &str = "accepted_log_stale_older_upload";

/// Refuse `count` synthetic bodies with `reason` through the real ledger path.
fn refuse(ledger: &mut SnapshotUploadProgress, reason: &str, count: usize) {
    let start = ledger.permanent_rejections.len();
    for i in start..start + count {
        ledger.quarantine_permanent_body(&format!("{i:064x}"), &format!("body-{i}"), reason);
    }
}

fn reported_code(state: CollectorState<'static>) -> Option<&'static str> {
    match state {
        CollectorState::Success => None,
        CollectorState::Error { code, .. } => Some(code),
        other => panic!("unexpected refused-entity state {other:?}"),
    }
}

/// T1: a retained list of 286 authority downgrades and 23 stale older
/// uploads, no holds. Every refusal is dominated, so the cycle is not a
/// validation error.
#[test]
fn dominated_permanent_refusals_are_not_a_backend_validation_error() {
    let mut ledger = progress();
    refuse(&mut ledger, DOMINATED_DOWNGRADE, 286);
    refuse(&mut ledger, DOMINATED_STALE, 23);
    let refusals = PermanentRefusalCounts::of(&ledger);
    assert_eq!(
        refusals,
        PermanentRefusalCounts {
            total: 309,
            dominated: 309
        }
    );
    assert_eq!(
        reported_code(refused_entity_state(true, refusals, true)),
        None,
        "dominated refusals report the settled-success state"
    );
    assert!(ledger.accepted_fingerprints.is_empty(), "never an ACK");
}

/// T2: one dominated plus one other permanent reason keeps today's code.
#[test]
fn a_non_dominated_permanent_refusal_keeps_backend_validation_error() {
    for other in [
        "divergent_duplicate_logical_session",
        "body_exceeds_max_bytes",
        "occurred_at_beyond_journal_retention",
        "invalid",
    ] {
        let mut ledger = progress();
        refuse(&mut ledger, DOMINATED_DOWNGRADE, 1);
        refuse(&mut ledger, other, 1);
        let refusals = PermanentRefusalCounts::of(&ledger);
        assert_eq!(
            refusals,
            PermanentRefusalCounts {
                total: 2,
                dominated: 1
            },
            "{other}"
        );
        assert_eq!(
            reported_code(refused_entity_state(true, refusals, true)),
            Some("backend_validation_error"),
            "{other}"
        );
    }
    assert_eq!(
        reported_code(refused_entity_state(
            true,
            PermanentRefusalCounts::default(),
            true
        )),
        Some("backend_validation_error"),
        "no retained refusal is no evidence of domination"
    );
}

/// T3: dominated refusals plus a local hold stay unsettled, and the reported
/// code is unchanged.
#[test]
#[serial_test::serial(source_manifests)]
fn dominated_refusals_beside_a_local_hold_keep_unsettled_behavior() {
    let mut ledger = progress();
    refuse(&mut ledger, DOMINATED_DOWNGRADE, 2);
    let holds = LocalHoldSettlement {
        held_entity_count: 1,
        retry_pending_family_count: 0,
        held_fingerprints: BTreeSet::from(["f".repeat(64)]),
        account_deferred_fingerprints: BTreeSet::new(),
        progress_blocking: false,
        held_family_roots: None,
    };
    let settlement = settle_checkpointed_upload(
        ScanIndex::default(),
        &ScanIndex::default(),
        &ledger,
        &holds,
        true,
    );
    assert!(!settlement.fully_settled);
    let refusals = PermanentRefusalCounts::of(&ledger);
    assert_eq!(
        reported_code(refused_entity_state(
            true,
            refusals,
            settlement.fully_settled
        )),
        Some("backend_validation_error")
    );
}

/// T5: a retryable deferral stays `server_error`, whatever the ledger holds.
#[test]
fn retryable_deferrals_stay_server_error_beside_dominated_refusals() {
    let mut ledger = progress();
    refuse(&mut ledger, DOMINATED_STALE, 3);
    let refusals = PermanentRefusalCounts::of(&ledger);
    for settled in [true, false] {
        assert_eq!(
            reported_code(refused_entity_state(false, refusals, settled)),
            Some("server_error")
        );
    }
}

/// F1: a newer body of a refused entity with a retryable conflict owes its own
/// outcome. The older dominated refusal is no longer the entity's terminal
/// record, so it cannot make the cycle a settled success.
#[test]
fn a_pending_newer_body_unbinds_its_dominated_refusal() {
    let mut ledger = progress();
    refuse(&mut ledger, DOMINATED_DOWNGRADE, 2);
    ledger.quarantine_retryable_body(&format!("{:064x}", 0), "newer-body-0");
    let refusals = PermanentRefusalCounts::of(&ledger);
    assert_eq!(
        refusals,
        PermanentRefusalCounts {
            total: 2,
            dominated: 1
        }
    );
    assert_eq!(
        reported_code(refused_entity_state(true, refusals, true)),
        Some("backend_validation_error")
    );
    assert!(ledger.accepted_fingerprints.is_empty(), "never an ACK");

    // A refused body whose entity left the census keeps a terminal record for
    // that same body, so it still counts as dominated.
    let mut ledger = progress();
    refuse(&mut ledger, DOMINATED_DOWNGRADE, 2);
    ledger.retain_current_quarantines(&BTreeSet::new());
    assert_eq!(
        PermanentRefusalCounts::of(&ledger),
        PermanentRefusalCounts {
            total: 2,
            dominated: 2
        }
    );
}

// --- In-place resend budget across the cache-head bootstrap stages ---

fn short_shed() -> anyhow::Error {
    anyhow::Error::new(UploadShed {
        status: 503,
        retry_after: Some(Duration::from_secs(1)),
        code: None,
    })
}

/// An exact ACK for one bootstrap or delivery batch; under head CAS every
/// settled entity carries its held-head etag.
fn stage_ack(batch: Vec<SnapshotItem>, enforce_head_cas: bool) -> Result<SnapshotBatchResponse> {
    let mut ack = response(&batch, 0);
    if enforce_head_cas {
        for reference in ack
            .accepted_entities
            .iter_mut()
            .chain(&mut ack.unchanged_entities)
        {
            reference.head_etag = Some("e".repeat(64));
        }
    }
    ack.validate_entity_ack_with_head_cas(&request(batch), enforce_head_cas)?;
    Ok(ack)
}

/// One source page gets two in-place resends and 10 s of waiting in total,
/// not per bootstrap stage: two short sheds on the ordinary probe spend the
/// budget, so a shed on the CAS repeat stands and the bootstrap keeps its
/// existing unsettled-probe error.
#[test]
#[serial_test::serial(client_report)]
fn inplace_retry_budget_spans_both_bootstrap_stages() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let probes = items(2);
    let mut ledger = progress();
    let mut calls = Vec::new();
    let (result, waits) = with_inplace_retry_test_clock(None, || {
        bootstrap_cache_heads(
            &probes,
            "inplace-bootstrap-budget",
            &mut ledger,
            true,
            |batch, enforce_head_cas| {
                calls.push(enforce_head_cas);
                let stage_attempt = calls.iter().filter(|cas| **cas == enforce_head_cas).count();
                let shed_attempts = if enforce_head_cas { 1 } else { 2 };
                if stage_attempt <= shed_attempts {
                    return Err(short_shed());
                }
                stage_ack(batch, enforce_head_cas)
            },
            |_| Ok(()),
        )
    });
    assert!(
        result.is_err(),
        "the CAS shed stands once the page budget is spent"
    );
    assert_eq!(calls, [false, false, false, true]);
    assert_eq!(waits.len(), 2);
    assert!(waits.iter().sum::<Duration>() <= Duration::from_secs(10));
    assert!(ledger.accepted_cache_heads.is_empty(), "no head is minted");
}

/// The source page's three stages as `finish_sync_source` runs them: ordinary
/// bootstrap, its CAS repeat and the cache-bearing delivery, all drawing on
/// one in-place budget. `sheds` gives the short sheds each stage meets before
/// it succeeds. Returns the calls per stage (0, 1, 2), the waits, the
/// delivery outcome and the ledger.
fn shared_budget_source_page(
    sheds: [usize; 3],
) -> (
    Vec<usize>,
    Vec<Duration>,
    Result<ResumableUploadResult>,
    SnapshotUploadProgress,
) {
    let probes = items(2);
    let mut snapshots = probes.clone();
    for item in &mut snapshots {
        item.cache_observations = Some(crate::snapshots::cache_observations::CacheObservations {
            schema_version: 1,
            operations: Vec::new(),
            coverage: "complete".into(),
            omitted_observation_count: None,
        });
    }
    let mut ledger = progress();
    let mut calls = Vec::new();
    let (delivery, waits) = with_inplace_retry_test_clock(None, || {
        let mut inplace_retry = InplaceRetryBudget::default();
        bootstrap_cache_heads_with_budget(
            &probes,
            "inplace-source-page",
            &mut ledger,
            true,
            &mut inplace_retry,
            |batch, enforce_head_cas| {
                let stage = usize::from(enforce_head_cas);
                calls.push(stage);
                if calls.iter().filter(|seen| **seen == stage).count() <= sheds[stage] {
                    return Err(short_shed());
                }
                stage_ack(batch, enforce_head_cas)
            },
            |_| Ok(()),
        )?;
        apply_bootstrapped_cache_heads(&mut snapshots, &ledger)?;
        let mut accepted = 0;
        upload_resumable_batches_with_body_witness_partitioned(
            &snapshots,
            "inplace-source-page",
            &mut ledger,
            &mut accepted,
            |item| item.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |item| Some(item.source_session_id.as_str()),
            |_| false,
            &mut inplace_retry,
            |batch| {
                calls.push(2);
                if calls.iter().filter(|seen| **seen == 2).count() <= sheds[2] {
                    return Err(short_shed());
                }
                stage_ack(batch, true)
            },
            |_| Ok(()),
        )
    });
    (calls, waits, delivery, ledger)
}

/// Ordinary bootstrap, CAS repeat and cache-bearing delivery of one source
/// page share two resends and 10 s of waiting. With one short shed in each
/// stage, the first two are resent and the delivery's shed stands, so the
/// page waits twice, never three or six times.
#[test]
#[serial_test::serial(client_report)]
fn inplace_retry_budget_spans_bootstrap_and_cache_bearing_delivery() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let (calls, waits, delivery, ledger) = shared_budget_source_page([1, 1, 1]);
    assert_eq!(calls, [0, 0, 1, 1, 2]);
    assert_eq!(waits.len(), 2, "two resends for the whole source page");
    assert!(waits.iter().sum::<Duration>() <= Duration::from_secs(10));
    assert_eq!(
        delivery.unwrap(),
        ResumableUploadResult::Shed {
            retry_after: Some(Duration::from_secs(1))
        },
        "the delivery shed keeps today's backoff"
    );
    assert_eq!(ledger.accepted_cache_heads.len(), 2, "bootstrap settled");

    // Within the budget, sheds spread over the bootstrap and the delivery are
    // all recovered and the page settles as a first-try success would.
    let (calls, waits, delivery, ledger) = shared_budget_source_page([1, 0, 1]);
    assert_eq!(calls, [0, 0, 1, 2, 2]);
    assert_eq!(waits.len(), 2);
    assert!(waits.iter().sum::<Duration>() <= Duration::from_secs(10));
    assert_eq!(delivery.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(ledger.accepted_cache_heads.len(), 2);
}
