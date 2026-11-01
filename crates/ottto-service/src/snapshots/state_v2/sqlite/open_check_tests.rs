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
    let db = Sqlite::open(&path, &identity).unwrap();
    assert_eq!(db.stamp().unwrap().0, 1);
    assert!(
        super::super::telemetry::take_thread_event_for_test("quick_check_ms")
            .unwrap()
            .is_u64()
    );
    assert_eq!(
        super::super::telemetry::take_thread_event_for_test("quick_check_slow_alarm"),
        Some(serde_json::json!(true))
    );
}
