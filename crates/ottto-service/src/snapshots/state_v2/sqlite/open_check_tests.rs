//! Open-time integrity regression, isolated from shared store/money fixtures.
use super::*;
use std::cell::Cell;

thread_local! {
    static BUDGET: Cell<Option<Duration>> = const { Cell::new(None) };
}
pub(super) fn budget(default: Duration) -> Duration {
    BUDGET.with(|budget| budget.get().unwrap_or(default))
}

/// [regress] quick_check over budget still opens and reports duration/alarm.
#[test]
fn quick_check_over_budget_still_opens() {
    let scratch = crate::test_scratch::ScratchDir::canonical("v2-open-check");
    let path = scratch.join("index.v2.sqlite.import");
    let identity = Identity {
        format: FORMAT,
        db_id: "synthetic-open-check".into(),
        fence_generation: 0,
        binding: crate::snapshots::scan_index_persistence::Binding {
            source: crate::snapshots::scan_index_persistence::Source::Claude,
            namespace_hash: "a".repeat(64),
        },
    };
    let mut db = Sqlite::create_import(&path).unwrap();
    db.control("identity", &identity).unwrap();
    db.control("generation", &0_u64).unwrap();
    // Enough valid rows to cross the former handler's 1,000-op interval.
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for n in 0_u64..256 {
        tx.put(RowInput {
            key: &RowKey::record("raw_hold.files", n.to_be_bytes().to_vec(), 0).unwrap(),
            fixed: &Fixed::None,
            value_version: 1,
            value: b"null",
        })
        .unwrap();
    }
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    drop(tx);
    db.finish_import().unwrap();
    // An opened store remains unclean until an explicit clean checkpoint.
    let db = Sqlite::open(&path, &identity).unwrap();
    assert_eq!(db.read_control::<u8>("phase").unwrap(), Some(1));
    drop(db);

    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            BUDGET.with(|budget| budget.set(None));
        }
    }
    BUDGET.with(|budget| budget.set(Some(Duration::ZERO)));
    let _reset = Reset;
    super::super::telemetry::take_thread_event_for_test("quick_check_ms");
    super::super::telemetry::take_thread_event_for_test("quick_check_slow_alarm");
    super::super::telemetry::event("hold", &Hold::ReloadRequired);
    assert_eq!(
        super::super::telemetry::take_thread_event_for_test("hold"),
        Some(serde_json::json!("reload_required"))
    );
    let db = Sqlite::open(&path, &identity).unwrap();
    assert_eq!(db.stamp().unwrap().0, 1);
    assert_eq!(
        super::super::telemetry::take_thread_event_for_test("hold"),
        Some(serde_json::json!("none"))
    );
    assert!(
        super::super::telemetry::take_thread_event_for_test("quick_check_ms")
            .unwrap()
            .is_u64()
    );
    assert_eq!(
        super::super::telemetry::take_thread_event_for_test("quick_check_slow_alarm"),
        Some(serde_json::json!(true))
    );

    // Health advice uses one exhaustive classification, including through
    // context and storage sanitization. Exercise it in this same regression.
    use crate::snapshots::scan_index_health as health;
    for (hold, code) in [
        (Hold::Future, health::CODE),
        (Hold::UnknownRecordKind, health::CODE),
        (Hold::NewerSchema, health::CODE),
        (Hold::ForeignBinding, health::SHARD_CODE),
        (Hold::FenceLost, health::SHARD_CODE),
        (Hold::ReferenceDrift, health::SHARD_CODE),
        (Hold::DbUnavailable, health::RETRY_CODE),
        (Hold::MigrationFailed, health::RETRY_CODE),
        (Hold::ReloadRequired, health::RETRY_CODE),
        (Hold::SaveCeiling, health::RETRY_CODE),
        (Hold::SaveOversize, health::RETRY_CODE),
        (Hold::SaveFull, health::RETRY_CODE),
        (Hold::AckCustody, health::RETRY_CODE),
    ] {
        let error = anyhow::Error::new(hold).context("opaque context");
        let reason = health::state_v2_reason(&error).unwrap();
        assert_eq!(reason.code(), code);
        let (_, records) = crate::local_resource_diagnostics::capture(|| {
            health::observe(crate::snapshots::SnapshotSource::ClaudeCode, &Err(error));
        });
        for (n, candidate) in health::REASONS.iter().enumerate() {
            assert_eq!(
                health::observations()[n][0].0.is_some(),
                candidate.code() == code
            );
        }
        if code == health::RETRY_CODE {
            assert!(records.iter().all(|row| {
                row["counts"].get("scan_index_repair_required").is_none()
                    && row["counts"].get("index_shard_unavailable_alarm").is_none()
            }));
            assert!(!reason.detail().contains("repair"));
            assert_eq!(reason.action(), "retry_automatically");
        }
    }
    let error = Hold::storage(
        anyhow::anyhow!("state_v2_integrity_requires_explicit_repair").context("opaque context"),
    );
    assert_eq!(
        error.to_string(),
        "state_v2_integrity_requires_explicit_repair"
    );
    assert_eq!(
        health::state_v2_reason(&error).unwrap().code(),
        health::SHARD_CODE
    );
    health::observe(crate::snapshots::SnapshotSource::ClaudeCode, &Err(error));
    assert!(health::observations()[1][0].0.is_some());
    assert!(health::observations()[2][0].0.is_none());
    let stamp =
        crate::snapshots::sampled_scan::codex_cursor::OpenStamp::of(&fs::metadata(&path).unwrap());
    health::observe(
        crate::snapshots::SnapshotSource::ClaudeCode,
        &Ok((
            ScanIndex::default(),
            crate::snapshots::LoadOrigin::Loaded(stamp),
        )),
    );
    assert!(health::observations()
        .iter()
        .all(|reason| reason[0].0.is_none()));
}
