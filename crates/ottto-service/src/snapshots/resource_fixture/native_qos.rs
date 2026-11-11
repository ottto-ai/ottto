//! Native requested-QoS contract. Explicitly selected by the native PR runner,
//! never ordinary test discovery or a merge-group/scheduled invocation.
use super::*;
use crate::snapshot_sync::resource_schedule as schedule;
type Trace = Vec<(String, String, u32)>;
thread_local! {
    static TRACE: std::cell::RefCell<Option<Trace>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn record_stage(json: &str) {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        let Some(trace) = trace.as_mut() else {
            return;
        };
        let row: Value = serde_json::from_str(json).unwrap();
        let Some(stage) = row["stage"].as_str() else {
            return;
        };
        if ["source_prepare", "native_collection_page", "source_finish"].contains(&stage) {
            trace.push((
                row["source"].as_str().unwrap().into(),
                stage.into(),
                schedule::native_qos().0,
            ));
        }
    });
}
fn observed(driver: &mut Driver<'_>, seconds: u64) -> Trace {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TRACE.with(|trace| {
                trace.borrow_mut().take();
            });
        }
    }
    TRACE.with(|trace| assert!(trace.borrow_mut().replace(Vec::new()).is_none()));
    let _reset = Reset;
    driver.page(seconds);
    TRACE.with(|trace| trace.borrow_mut().take().unwrap())
}
fn matches(trace: &[(String, String, u32)], source: SnapshotSource, class: u32) -> bool {
    for stage in ["source_prepare", "native_collection_page", "source_finish"] {
        let seen: Vec<_> = trace
            .iter()
            .filter(|(s, phase, _)| s == source.api_slug() && phase == stage)
            .collect();
        assert_eq!(seen.len(), 1, "missing/duplicate native QoS stage: {stage}");
    }
    trace.iter().all(|(_, _, qos)| *qos == class)
}

/// [regress] Actual pthread QoS inside native prepare/page/finish. Ordinary
/// stages keep utility; explicitly due resident-paced work is background.
#[test]
#[ignore = "native macOS PR validation only; never merge_group"]
fn resource_native_ordinary_stage_qos() {
    let pr = std::env::var("OTTTO_RESOURCE_QOS_PR")
        .expect("native PR runner must validate PR/head first");
    assert!(pr.parse::<u64>().is_ok_and(|n| n > 0));
    if let Ok(event) = std::env::var("GITHUB_EVENT_NAME") {
        assert_eq!(event, "pull_request");
    }
    schedule::native_worker(|| {
        let initial = schedule::native_qos();
        assert!(
            [0, 0x11, 0x15].contains(&initial.0),
            "fresh worker must inherit utility/default: {initial:?}"
        );
        // Requested UNSPECIFIED inheritance is resolved explicitly to DEFAULT
        // when restored; native APIs do not provide 'clear explicit QoS'.
        let utility = schedule::native_set_qos(0x11);
        let corpus = Corpus::generate([4, 8, 2]);
        let mut drivers: Vec<_> = (0..3).map(|s| Driver::new(&corpus, s)).collect();
        schedule::with_power("ac", || {
            for (s, driver) in drivers.iter_mut().enumerate() {
                let trace = observed(driver, 2000);
                assert!(
                    matches(&trace, SOURCES[s], 0x11),
                    "ordinary stage demoted: {trace:?}"
                );
            }
            with_scan_clock(EPOCH + 3000, || schedule::finished(SOURCES[1], 1, true));
            let paced = observed(&mut drivers[1], 3030);
            assert!(
                matches(&paced, SOURCES[1], 0x09),
                "paced stage kind keeps background"
            );
            assert_eq!(
                schedule::native_qos().0,
                0x11,
                "paced scope restores utility"
            );
            let ordinary = observed(&mut drivers[2], 3030);
            assert!(
                matches(&ordinary, SOURCES[2], 0x11),
                "another source's paced request must not demote ordinary stages"
            );
            // Test-only reintroduction of the former cycle-wide demotion.
            let background = schedule::native_background();
            let replay = observed(&mut drivers[0], 3100);
            assert!(
                !matches(&replay, SOURCES[0], 0x11),
                "cycle-wide replay must trip the ordinary QoS class bound"
            );
            drop(background);
            assert_eq!(schedule::native_qos().0, 0x11);
            let error = (|| -> Result<(), &'static str> {
                let _qos = schedule::native_background();
                Err("synthetic finish error")
            })();
            assert!(error.is_err());
            assert_eq!(schedule::native_qos().0, 0x11, "error restores");
            assert!(std::panic::catch_unwind(|| {
                let _qos = schedule::native_background();
                panic!("synthetic cancellation");
            })
            .is_err());
            assert_eq!(schedule::native_qos().0, 0x11, "unwind restores");
        });
        drop(utility);
        assert_eq!(
            schedule::native_qos().0,
            if initial.0 == 0 { 0x15 } else { initial.0 }
        );
        println!("resource_native_qos ordinary=utility paced=background cycle_replay=tripped restoration=passed");
    });
}
