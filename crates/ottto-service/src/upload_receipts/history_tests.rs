use super::*;
use crate::snapshots::state_v2::sqlite_sidecar as sidecar;
use crate::snapshots::state_v2::upload_history::{
    CLOUD_QUERIES_FOR_TEST, MMAP_BYTES_FOR_TEST, QUERIES_FOR_TEST, RETENTION_NS,
};
use crate::test_scratch::ScratchDir;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

const DAY_NS: i64 = 24 * 60 * 60 * 1_000_000_000;
const T0: i64 = 1_790_000_000 * 1_000_000_000;

fn temp_dir() -> ScratchDir {
    ScratchDir::canonical("ottto-upload-history")
}

/// A direct store on `dir`; never mixed with the process writer for that dir.
fn open(dir: &Path) -> Store {
    use std::os::unix::fs::DirBuilderExt;
    let snapshots = dir.join("snapshots");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&snapshots)
        .unwrap();
    let store = Store::open(&Store::path(&snapshots)).unwrap();
    let actual: i64 = store
        .conn_for_test()
        .query_row("PRAGMA mmap_size", [], |r| r.get(0))
        .unwrap();
    assert_eq!(actual, MMAP_BYTES_FOR_TEST);
    store
}

fn row(at_ns: i64, source: SourceKind, items: usize) -> Encoded {
    let mut receipt = empty_receipt(
        source,
        items,
        UploadReceiptOutcomeV1::TransportError,
        None,
        None,
        None,
        &UploadReceiptContext::default(),
    );
    receipt.uploaded_at = OffsetDateTime::from_unix_timestamp_nanos(i128::from(at_ns))
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    encode(
        &PersistedReceipt {
            public: receipt,
            validated_evidence: None,
        },
        0,
    )
    .unwrap()
}

/// (seq, source, batch_item_count) of every row, newest first.
fn all(store: &Store) -> Vec<(i64, SourceKind, u64)> {
    let page = store
        .page(&Filter {
            before: None,
            source: None,
            since_ns: None,
            limit: 10_000,
        })
        .unwrap();
    page.rows
        .iter()
        .map(|(seq, json)| {
            let receipt: PersistedReceipt = serde_json::from_slice(json).unwrap();
            (*seq, receipt.public.source, receipt.public.batch_item_count)
        })
        .collect()
}

/// Drop the process writer for `dir`, as a daemon restart would.
fn restart(dir: &Path) {
    let mut history = HISTORY.lock().unwrap_or_else(|p| p.into_inner());
    if history
        .as_ref()
        .is_some_and(|store| store.file_path() == upload_history_path(dir).as_path())
    {
        *history = None;
    }
}

fn ring_row(at: OffsetDateTime, source: SourceKind, items: usize) -> serde_json::Value {
    let mut receipt = empty_receipt(
        source,
        items,
        UploadReceiptOutcomeV1::Shed,
        Some(429),
        Some("ring-request".into()),
        Some(30),
        &UploadReceiptContext::default(),
    );
    receipt.uploaded_at = at.format(&Rfc3339).unwrap();
    serde_json::to_value(receipt).unwrap()
}

fn write_ring(dir: &Path, rows: &[serde_json::Value]) {
    std::fs::write(
        upload_receipts_path(dir),
        serde_json::to_vec(&serde_json::json!({"schema_version":1,"receipts":rows})).unwrap(),
    )
    .unwrap();
}

pub(super) fn entity_counts(dir: &Path) -> Vec<i64> {
    with_history(dir, false, |store| {
        let mut statement = store
            .conn_for_test()
            .prepare("SELECT entity_count FROM upload_history ORDER BY seq")?;
        let counts = statement
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<i64>>>()?;
        Ok(counts)
    })
    .unwrap()
    .unwrap()
}

#[test]
fn expiry_at_30_days_keeps_each_sources_newest_row() {
    let dir = temp_dir();
    let mut store = open(&dir);
    store.append(&row(T0, SourceKind::Codex, 1), T0).unwrap();
    store.append(&row(T0, SourceKind::Pi, 2), T0).unwrap();
    store
        .append(&row(T0 + DAY_NS, SourceKind::Codex, 3), T0 + DAY_NS)
        .unwrap();
    // Exactly 30 days old is kept; older rows go unless newest for a source.
    let now = T0 + RETENTION_NS + DAY_NS;
    store
        .append(&row(now, SourceKind::ClaudeCode, 4), now)
        .unwrap();
    let kept = all(&store);
    assert_eq!(
        kept.iter().map(|r| r.2).collect::<Vec<_>>(),
        vec![4, 3, 2],
        "codex@T0 expired; codex's newest and idle Pi stay"
    );
    // A newer Codex row ends its older one; Pi idle past 30 days still stays.
    let later = now + 10 * DAY_NS;
    store
        .append(&row(later, SourceKind::Codex, 5), later)
        .unwrap();
    assert_eq!(
        all(&store).iter().map(|r| r.2).collect::<Vec<_>>(),
        vec![5, 4, 2]
    );
    // The boundary: a row exactly at the cutoff is kept.
    let at_cutoff = later - RETENTION_NS;
    store
        .append(&row(at_cutoff, SourceKind::ClaudeCode, 6), later)
        .unwrap();
    store
        .append(&row(later, SourceKind::ClaudeCode, 7), later)
        .unwrap();
    assert!(all(&store).iter().any(|r| r.2 == 6));
}

#[test]
fn sequences_are_never_reused_and_cursors_stay_stable_across_expiry() {
    let dir = temp_dir();
    let mut store = open(&dir);
    let mut assigned = Vec::new();
    for n in 0..6 {
        let source = if n % 2 == 0 {
            SourceKind::Codex
        } else {
            SourceKind::Pi
        };
        assigned.push(store.append(&row(T0 + n, source, n as usize), T0).unwrap());
    }
    let first = store
        .page(&Filter {
            before: None,
            source: None,
            since_ns: None,
            limit: 2,
        })
        .unwrap();
    let cursor = first.last_seq;
    // 40 days later every old row but each source's newest expires.
    let now = T0 + 40 * DAY_NS;
    assigned.push(store.append(&row(now, SourceKind::Codex, 9), now).unwrap());
    assert!(
        assigned.windows(2).all(|pair| pair[0] < pair[1]),
        "{assigned:?}"
    );
    let survivors = all(&store);
    assert_eq!(
        survivors.iter().map(|r| r.2).collect::<Vec<_>>(),
        vec![9, 5]
    );
    // The cursor taken before expiry still reads only older survivors.
    let next = store
        .page(&Filter {
            before: cursor,
            source: None,
            since_ns: None,
            limit: 10,
        })
        .unwrap();
    assert!(next.rows.iter().all(|(seq, _)| Some(*seq) < cursor));
    assert!(next.rows.is_empty());
    // Expiring every older row of a source never frees the global maximum.
    drop(store);
    let mut reopened = open(&dir);
    let after = reopened.append(&row(now, SourceKind::Pi, 10), now).unwrap();
    assert!(after > *assigned.last().unwrap());
}

#[test]
fn pages_cover_three_sources_and_an_orphan_namespace_exactly_once() {
    let dir = temp_dir();
    let mut request = super::tests::proof_request("claude_code", false);
    let sources = [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi];
    for n in 0..9 {
        let source = sources[n % 3].clone();
        if n == 4 {
            // A destination this daemon no longer uploads to still pages.
            request.source = "claude_code".into();
            let ack = super::tests::proof_response(&request, false);
            append_success_with_evidence_context(
                &dir,
                source,
                n,
                200,
                None,
                &ack,
                &UploadReceiptContext::default(),
                Some((&request, &"f".repeat(64), &"b".repeat(64), false)),
            )
            .unwrap();
        } else {
            append_transport_error(&dir, source, n).unwrap();
        }
    }
    // A future build's row this build cannot decode is skipped, not fatal.
    with_history(&dir, false, |store| {
        store.append(
            &Encoded::new(T0 + 400 * DAY_NS, "future_source", 0, br#"{"future":1}"#)?,
            T0,
        )
    })
    .unwrap();
    let mut seen = Vec::new();
    let mut before = None;
    loop {
        let page = read_page(&dir, 2, None, None, before).unwrap();
        seen.extend(page.receipts.iter().map(|r| r.batch_item_count));
        assert!(!serde_json::to_string(&page)
            .unwrap()
            .contains("validated_evidence"));
        match page.next_before {
            Some(cursor) => before = Some(cursor),
            None => break,
        }
    }
    assert_eq!(seen, (0..9).rev().collect::<Vec<u64>>());
    for (source, expected) in [
        (SourceKind::Codex, vec![6, 3, 0]),
        (SourceKind::ClaudeCode, vec![7, 4, 1]),
        (SourceKind::Pi, vec![8, 5, 2]),
    ] {
        let mut got = Vec::new();
        let mut before = None;
        loop {
            let page = read_page(&dir, 1, None, Some(source.clone()), before).unwrap();
            got.extend(page.receipts.iter().map(|r| r.batch_item_count));
            match page.next_before {
                Some(cursor) => before = Some(cursor),
                None => break,
            }
        }
        assert_eq!(got, expected, "{source:?}");
    }
    let since = read(&dir, 500, Some("2000-01-01T00:00:00Z"), None).unwrap();
    assert_eq!(since.receipts.len(), 9);
    let none = read(&dir, 500, Some("2999-01-01T00:00:00Z"), None).unwrap();
    assert!(none.receipts.is_empty());
}

#[test]
fn private_evidence_never_enters_any_response() {
    let dir = temp_dir();
    let request = super::tests::proof_request("codex", false);
    let ack = super::tests::proof_response(&request, false);
    append_success_with_evidence_context(
        &dir,
        SourceKind::Codex,
        1,
        200,
        Some("safe-request"),
        &ack,
        &UploadReceiptContext::default(),
        Some((&request, &"a".repeat(64), &"b".repeat(64), false)),
    )
    .unwrap();
    assert!(private_rows_for_test(&dir)[0]["validated_evidence"].is_object());
    for page in [
        read_page(&dir, 500, None, None, None),
        read_page(&dir, 500, None, Some(SourceKind::Codex), None),
        read_page(&dir, 500, Some("2000-01-01T00:00:00Z"), None, None),
        read_page(&dir, 500, None, None, Some(u64::MAX >> 1)),
    ] {
        let json = serde_json::to_string(&page.unwrap()).unwrap();
        for private in [
            "validated_evidence",
            "attempt_identity",
            "destination_namespace_hash",
            &request.snapshots[0].snapshot_fingerprint,
        ] {
            assert!(!json.contains(private), "{private}");
        }
    }
}

#[test]
fn public_response_equals_todays_receipt_contract() {
    let dir = temp_dir();
    let mut ack = super::tests::response("raw-accepted-session");
    ack.accepted = 1;
    ack.conflict_entities = vec![SnapshotEntityRef {
        source_session_id: "raw-conflict-session".into(),
        snapshot_fingerprint: "9876543210abcdef".into(),
        ..ack.accepted_entities[0].clone()
    }];
    append_success_with_context(
        &dir,
        SourceKind::Codex,
        2,
        200,
        Some("req-server-01HX"),
        &ack,
        &UploadReceiptContext {
            device_label: Some("Test Mac".into()),
            account_binding: Some(LocalAccountState::Connected),
        },
    )
    .unwrap();
    let mut actual = serde_json::to_value(read(&dir, 50, None, None).unwrap()).unwrap();
    // The not-written count is process-wide; other tests may have raised it.
    actual
        .as_object_mut()
        .unwrap()
        .remove("history_rows_not_written");
    let uploaded_at = actual["receipts"][0]["uploaded_at"].clone();
    let expected = serde_json::json!({
        "schema": "ottto.upload_receipts.v1",
        "receipts": [{
            "uploaded_at": uploaded_at,
            "outcome": "partial",
            "http_status": 200,
            "server_request_id": "req-server-01HX",
            "retry_after_seconds": null,
            "source": "codex",
            "device_label": "Test Mac",
            "account_binding": "connected",
            "batch_item_count": 2,
            "accepted_count": 1,
            "accepted_entities": [{
                "source_session_id_hash": digest_prefix(
                    b"ottto.upload_receipt.source_session_id:v1", "raw-accepted-session"),
                "snapshot_fingerprint_prefix": "abcdef012345",
                "occurrence_count": 1
            }],
            "unchanged_entities": [],
            "conflict_entities": [{
                "source_session_id_hash": digest_prefix(
                    b"ottto.upload_receipt.source_session_id:v1", "raw-conflict-session"),
                "snapshot_fingerprint_prefix": "9876543210ab",
                "occurrence_count": 1
            }],
            "rejected_entities": []
        }],
        "ring_capacity": 500,
        "state_path_present": true
    });
    assert_eq!(actual, expected);
    // Field for field the shape of the published contract fixture.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/control/receipts-response.json"
    ))
    .unwrap();
    let keys = |value: &serde_json::Value| {
        value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(keys(&actual), keys(&fixture["payload"]));
    assert_eq!(
        keys(&actual["receipts"][0]),
        keys(&fixture["payload"]["receipts"][0])
    );
}

#[test]
fn ring_import_is_lossless_deduped_and_survives_interruption() {
    let dir = temp_dir();
    let now = OffsetDateTime::now_utc();
    // More rows than the old ring kept, with one private-evidence row.
    let mut rows = (0..600)
        .map(|n| ring_row(now, SourceKind::Codex, n))
        .collect::<Vec<_>>();
    let mut with_evidence = rows[10].clone();
    with_evidence["validated_evidence"] = serde_json::json!({
        "schema_version": 1, "destination_namespace_hash": "a".repeat(64),
        "api_destination_hash": "b".repeat(64), "producer_version": null,
        "attempt_identity": "c".repeat(64), "head_cas": false,
        "entity_ack_contract": "snapshot_entity_ack:v1", "requested_occurrences": 0,
        "requested_distinct_entities": 0, "retained_entities": 0, "total_entities": 0,
        "outcome_occurrences": {}, "coverage": "complete", "entities": []
    });
    rows[10] = with_evidence;
    // Before COMMIT: another writer holds the file, so the import cannot
    // start; the ring stays whole and the next open imports it.
    drop(open(&dir));
    write_ring(&dir, &rows);
    let blocker = rusqlite::Connection::open(upload_history_path(&dir)).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(read(&dir, 500, None, None).unwrap().receipts.is_empty());
    assert!(upload_receipts_path(&dir).exists());
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    restart(&dir);
    let private = private_rows_for_test(&dir);
    assert_eq!(private.len(), 600, "every ring row imports");
    assert_eq!(private[0]["batch_item_count"], 0, "oldest first");
    assert!(private[10]["validated_evidence"].is_object());
    assert!(!upload_receipts_path(&dir).exists());
    // After COMMIT but before the unlink: the same ring reappears, and an
    // older daemon appended two rows to it meanwhile.
    rows.push(ring_row(now, SourceKind::Pi, 700));
    rows.push(ring_row(now, SourceKind::Pi, 701));
    write_ring(&dir, &rows);
    restart(&dir);
    let private = private_rows_for_test(&dir);
    assert_eq!(private.len(), 602, "known rows are skipped");
    let newest = read(&dir, 2, None, None).unwrap();
    assert_eq!(
        newest
            .receipts
            .iter()
            .map(|r| r.batch_item_count)
            .collect::<Vec<_>>(),
        vec![701, 700]
    );
    assert!(!upload_receipts_path(&dir).exists());
}

#[test]
fn a_ring_with_one_unreadable_row_is_set_aside_whole() {
    let dir = temp_dir();
    let now = OffsetDateTime::now_utc();
    write_ring(
        &dir,
        &[
            ring_row(now, SourceKind::Codex, 1),
            serde_json::json!({"outcome": "not a receipt"}),
        ],
    );
    assert!(read(&dir, 500, None, None).unwrap().receipts.is_empty());
    assert!(!upload_receipts_path(&dir).exists());
    assert!(std::fs::read_dir(&*dir).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains(".corrupt.")));
}

#[test]
fn ring_import_decodes_rows_without_amplification() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // Under the old 4 MiB ring bound, a generic value tree of this row would
    // take tens of MiB; typed per-row decoding skips the unknown field.
    let dir = temp_dir();
    let mut row = ring_row(OffsetDateTime::now_utc(), SourceKind::Pi, 1).to_string();
    row.pop();
    row.push_str(",\"unrecognized_extension\":[");
    row.push_str(&"\"\",".repeat(900_000));
    row.push_str("\"\"]}");
    let body = format!("{{\"schema_version\":1,\"receipts\":[{row}]}}");
    assert!(body.len() < 4 * 1024 * 1024);
    std::fs::write(upload_receipts_path(&dir), &body).unwrap();
    let (page, allocation) =
        crate::retry_allocation_probe::measure(|| read(&dir, 500, None, None).unwrap());
    eprintln!(
        "ring_import bytes={} requested_peak={} usable_peak={}",
        body.len(),
        allocation.requested_peak,
        allocation.usable_peak
    );
    assert_eq!(page.receipts.len(), 1);
    assert!(
        allocation.requested_peak < body.len() + 1024 * 1024,
        "{allocation:?}"
    );
    assert!(!upload_receipts_path(&dir).exists());
}

#[test]
fn imported_rows_past_30_days_expire_at_the_next_append_except_the_newest() {
    let dir = temp_dir();
    let old = OffsetDateTime::now_utc() - time::Duration::days(40);
    write_ring(
        &dir,
        &[
            ring_row(old, SourceKind::Codex, 1),
            ring_row(old, SourceKind::Codex, 2),
            ring_row(old, SourceKind::Pi, 3),
        ],
    );
    assert_eq!(read(&dir, 500, None, None).unwrap().receipts.len(), 3);
    append_transport_error(&dir, SourceKind::Codex, 4).unwrap();
    let kept = read(&dir, 500, None, None)
        .unwrap()
        .receipts
        .iter()
        .map(|r| r.batch_item_count)
        .collect::<Vec<_>>();
    assert_eq!(kept, vec![4, 3]);
}

#[test]
fn a_locked_or_unwritable_history_never_holds_or_slows_an_upload() {
    // Another holder of the history's owner lock: an append gives up within
    // the busy bound and the upload goes on.
    let dir = temp_dir();
    std::fs::create_dir_all(dir.join("snapshots")).unwrap();
    let owner = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(sidecar(&upload_history_path(&dir), ".owner"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let started = Instant::now();
    assert!(append_transport_error(&dir, SourceKind::Codex, 1).is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    // A deferred page write with the file locked returns normally.
    {
        let _scope = defer();
        append_transport_error(&dir, SourceKind::Codex, 99).unwrap();
    }
    drop(owner);
    restart(&dir);
    append_transport_error(&dir, SourceKind::Codex, 5).unwrap();
    assert_eq!(read(&dir, 500, None, None).unwrap().receipts.len(), 1);
    // An unwritable support directory: appends fail, nothing panics.
    let blocked = temp_dir();
    std::fs::write(blocked.join("snapshots"), b"not a directory").unwrap();
    assert!(append_transport_error(&blocked, SourceKind::Pi, 1).is_err());
    let scope = defer();
    append_transport_error(&blocked, SourceKind::Pi, 1).unwrap();
    drop(scope);
}

#[test]
fn a_held_history_file_counts_every_row_it_could_not_write() {
    let dir = temp_dir();
    // A second handle holds the history's owner lock.
    let held = open(&dir);
    let here = || ROWS_NOT_WRITTEN_HERE.with(std::cell::Cell::get);
    let (mine, process) = (here(), HISTORY_ROWS_NOT_WRITTEN.load(Ordering::Relaxed));
    let started = Instant::now();
    {
        let _page = defer();
        for n in 0..3 {
            // Recording never refuses the upload.
            append_transport_error(&dir, SourceKind::Codex, n).unwrap();
        }
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(here() - mine, 3, "every row not written is counted");
    assert!(HISTORY_ROWS_NOT_WRITTEN.load(Ordering::Relaxed) - process >= 3);
    drop(held);
    let response = read(&dir, 500, None, None).unwrap();
    assert!(response.receipts.is_empty());
    assert!(response.history_rows_not_written >= Some(3));
}

#[test]
fn deferred_rows_are_written_once_the_page_save_returns() {
    let dir = temp_dir();
    let page = defer();
    append_transport_error(&dir, SourceKind::Codex, 1).unwrap();
    append_transport_error(&dir, SourceKind::Codex, 2).unwrap();
    assert!(!upload_history_path(&dir).exists(), "nothing written yet");
    drop(page);
    assert_eq!(read(&dir, 500, None, None).unwrap().receipts.len(), 2);
    // An early return drops the scope too and still writes the attempt.
    let page = defer();
    append_transport_error(&dir, SourceKind::Codex, 3).unwrap();
    assert_eq!(read(&dir, 500, None, None).unwrap().receipts.len(), 2);
    drop(page);
    let kept = read(&dir, 500, None, None).unwrap();
    assert_eq!(
        kept.receipts
            .iter()
            .map(|r| r.batch_item_count)
            .collect::<Vec<_>>(),
        vec![3, 2, 1]
    );
    // Outside any scope a row is written at once.
    append_transport_error(&dir, SourceKind::Codex, 4).unwrap();
    assert_eq!(read(&dir, 500, None, None).unwrap().receipts.len(), 4);
}

#[test]
fn query_plans_use_the_rowid_and_named_indexes() {
    let dir = temp_dir();
    let store = open(&dir);
    let plan = |sql: &str| {
        let mut statement = store
            .conn_for_test()
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        // Plans do not depend on the values; bind every parameter as NULL.
        let nulls = vec![rusqlite::types::Null; statement.parameter_count()];
        statement
            .query_map(rusqlite::params_from_iter(nulls), |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
            .join(" | ")
    };
    for (name, sql) in QUERIES_FOR_TEST {
        let plan = plan(sql);
        eprintln!("upload_history_plan {name}: {plan}");
        assert!(
            !plan.contains("SCAN upload_history"),
            "{name} scans the table: {plan}"
        );
        match name {
            "page" => {
                assert!(plan.contains("INTEGER PRIMARY KEY"), "{plan}");
                assert!(!plan.contains("TEMP B-TREE"), "{plan}");
            }
            "page_source" => {
                assert!(plan.contains("upload_history_src"), "{plan}");
                assert!(!plan.contains("TEMP B-TREE"), "{plan}");
            }
            "page_since" => assert!(plan.contains("upload_history_at"), "{plan}"),
            "expire" => {
                assert!(plan.contains("upload_history_at"), "{plan}");
                assert!(plan.contains("upload_history_src"), "{plan}");
            }
            _ => unreachable!(),
        }
    }
}

/// [regress] A schema-1 history (before the cloud-task ACK cache) upgrades in
/// place: receipt rows stay, the cloud tables appear in the same transaction
/// as the version bump, cloud rows never enter receipt pages, and a newer
/// schema is refused rather than rewritten.
#[test]
fn schema_one_history_upgrades_in_place_and_a_newer_schema_is_refused() {
    let dir = temp_dir();
    {
        let mut store = open(&dir);
        store.append(&row(T0, SourceKind::Codex, 3), T0).unwrap();
        store
            .conn_for_test()
            .execute_batch(
                "DROP TABLE cloud_task_acks; DROP TABLE cloud_collector_state; PRAGMA user_version=1;",
            )
            .unwrap();
    }
    let mut store = open(&dir);
    let version: i64 = store
        .conn_for_test()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 2);
    assert_eq!(all(&store).len(), 1);

    let scope = [7_u8; 32];
    let other_scope = [8_u8; 32];
    let key = format!("hmac-sha256:{}", "ab".repeat(32));
    let etag = "c".repeat(64);
    let now = 1_800_000_000_i64;
    store
        .cloud_commit(
            &scope,
            &[CloudAckWrite {
                entity_key: &key,
                digest: [1; 32],
                head_etag: Some(&etag),
            }],
            Some("2026-07-21"),
            now,
        )
        .unwrap();
    assert_eq!(
        store.cloud_read_acks(&scope, &[key.as_str()], now).unwrap()[&key],
        CloudAck {
            digest: [1; 32],
            head_etag: Some(etag.clone()),
        }
    );
    assert!(store
        .cloud_read_acks(&other_scope, &[key.as_str()], now)
        .unwrap()
        .is_empty());
    // Entries expire 30 days after their ACK.
    assert!(store
        .cloud_read_acks(&scope, &[key.as_str()], now + 30 * 24 * 60 * 60)
        .unwrap()
        .is_empty());
    assert_eq!(
        store.cloud_crawl_completed_date(&scope).unwrap().as_deref(),
        Some("2026-07-21")
    );
    assert_eq!(all(&store).len(), 1);
    store.cloud_erase_all().unwrap();
    assert!(store
        .cloud_read_acks(&scope, &[key.as_str()], now)
        .unwrap()
        .is_empty());
    assert_eq!(store.cloud_crawl_completed_date(&scope).unwrap(), None);
    assert_eq!(all(&store).len(), 1);

    store
        .conn_for_test()
        .execute_batch("PRAGMA user_version=3;")
        .unwrap();
    drop(store);
    assert!(Store::open(&Store::path(&dir.join("snapshots"))).is_err());
}

/// [behaviour] Expired cloud rows are pruned a bounded page per commit.
#[test]
fn expired_cloud_acks_are_pruned_in_bounded_pages() {
    let dir = temp_dir();
    let mut store = open(&dir);
    let scope = [3_u8; 32];
    let keys = (0..450)
        .map(|index| format!("hmac-sha256:{index:064x}"))
        .collect::<Vec<_>>();
    let writes = keys
        .iter()
        .map(|key| CloudAckWrite {
            entity_key: key,
            digest: [2; 32],
            head_etag: None,
        })
        .collect::<Vec<_>>();
    store.cloud_commit(&scope, &writes, None, 0).unwrap();
    let count = |store: &Store| -> i64 {
        store
            .conn_for_test()
            .query_row("SELECT count(*) FROM cloud_task_acks", [], |r| r.get(0))
            .unwrap()
    };
    let later = 31 * 24 * 60 * 60;
    store.cloud_commit(&scope, &[], None, later).unwrap();
    assert_eq!(count(&store), 250);
    store.cloud_commit(&scope, &[], None, later).unwrap();
    store.cloud_commit(&scope, &[], None, later).unwrap();
    assert_eq!(count(&store), 0);
}

#[test]
fn cloud_query_plans_use_the_primary_key_and_expiry_index() {
    let dir = temp_dir();
    let store = open(&dir);
    for (name, sql) in CLOUD_QUERIES_FOR_TEST {
        let mut statement = store
            .conn_for_test()
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        let nulls = vec![rusqlite::types::Null; statement.parameter_count()];
        let plan = statement
            .query_map(rusqlite::params_from_iter(nulls), |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
            .join(" | ");
        eprintln!("cloud_ack_plan {name}: {plan}");
        assert!(!plan.contains("SCAN cloud_"), "{name} scans: {plan}");
        assert!(plan.contains("USING PRIMARY KEY"), "{name}: {plan}");
        if name == "prune" {
            assert!(plan.contains("cloud_task_acks_expiry"), "{plan}");
        }
    }
}
