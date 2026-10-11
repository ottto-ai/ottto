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
        21 | 23 => 7,
        22 | 24 => 8,
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
    }
}

fn response(items: &[SnapshotItem], rejected: usize) -> SnapshotBatchResponse {
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
                reason: "usage_accounting_authority_downgrade".into(),
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

#[test]
#[serial_test::serial(client_report)]
fn h359_all_rejected_is_finished_transport_with_incomplete_health_and_no_success_clock() {
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
            let ack = response(&batch, 2);
            ack.validate_entity_ack(&request(batch))?;
            Ok(ack)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(outcome, ResumableUploadResult::Rejected { count: 2 });
    assert_eq!(accepted, 0);
    assert!(ledger.accepted_fingerprints.is_empty());
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
            state: deferred_entity_state(true),
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
