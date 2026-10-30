//! E1's transport/mapping controls. E5 owns the eight native Pi capture cases.
use super::*;
pub(crate) use sampled_scan::durable_tail::{
    Degraded, DegradedCause, HeldCause, NotPersisted, Unprepared, UnpreparedDisposition,
    WriteOutcome,
};

use sampled_scan::durable_tail::FinishAcquisition;

fn acquisition() -> FinishAcquisition {
    FinishAcquisition::Uncertified(DurableCustody::default())
}

#[test]
fn codex_strict_rebind_keeps_the_existing_publishing_class() {
    let cache = sampled_scan::SharedCache::default();
    let (publication, strict_rebind) = unprepared_disposition(
        &cache,
        &mut acquisition(),
        SnapshotSource::Codex,
        UnpreparedDisposition::PublishStrictRebind,
    );
    assert!(strict_rebind);
    assert_eq!(publication, NativePublication::FailedPublishedWithoutRecord);
    assert!(publication.publishes());
    assert_eq!(
        write_disposition(
            &cache,
            &mut acquisition(),
            SnapshotSource::Codex,
            WriteOutcome::FailedPublishedWithoutRecord(DegradedCause::StrictRebind),
            None,
        ),
        (publication, strict_rebind)
    );
}

#[test]
fn claude_and_pi_strict_rebind_are_held_publication_decisions() {
    let cache = sampled_scan::SharedCache::default();
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Pi] {
        let (publication, strict_rebind) = unprepared_disposition(
            &cache,
            &mut acquisition(),
            source,
            UnpreparedDisposition::PublishStrictRebind,
        );
        // The pre-existing settlement conversion still owns owed/hold effects;
        // the carried value already names its fail-closed result for capture.
        assert!(strict_rebind);
        assert_eq!(publication, NativePublication::Hold);
        assert!(!publication.publishes());
        assert_eq!(
            write_disposition(
                &cache,
                &mut acquisition(),
                source,
                WriteOutcome::FailedPublishedWithoutRecord(DegradedCause::StrictRebind),
                None,
            ),
            (publication, strict_rebind)
        );
    }
}

#[test]
fn native_publication_has_exactly_five_publishing_and_three_held_classes() {
    let cache = sampled_scan::SharedCache::default();
    let source = SnapshotSource::Codex;
    let unprepared =
        |outcome| unprepared_disposition(&cache, &mut acquisition(), source, outcome).0;
    let write = |outcome| write_disposition(&cache, &mut acquisition(), source, outcome, None).0;
    let cause = Unprepared::NotPersisted(NotPersisted::Codec);
    // The receipt policy is a typed value here; real candidate/receipt binding
    // stays in the existing facade fixtures and E5's native outcome tests.
    let publishing = [
        NativePublication::Receipted,
        unprepared(UnpreparedDisposition::PublishWithoutRecord { cause }),
        write(WriteOutcome::FailedPublishedWithoutRecord(
            DegradedCause::StoreUntouched,
        )),
        unprepared(UnpreparedDisposition::PublishRetainingPrior { format: 1, cause }),
        unprepared(UnpreparedDisposition::PublishStoreUntouched {
            cause: Degraded::Disabled,
        }),
    ];
    let held = [
        write(WriteOutcome::FailedHeld(HeldCause::Fence)),
        write(WriteOutcome::ReceiptPending),
        unprepared(UnpreparedDisposition::Hold(HeldCause::Fence)),
    ];
    assert_eq!(
        held,
        [
            NativePublication::FailedHeld,
            NativePublication::ReceiptPending,
            NativePublication::Hold
        ]
    );
    assert!(publishing.into_iter().all(NativePublication::publishes));
    assert!(held.into_iter().all(|class| !class.publishes()));
    // This independent closed list also makes any ninth class a compile error.
    let slot = |class| match class {
        NativePublication::Receipted => 0,
        NativePublication::PublishWithoutRecord => 1,
        NativePublication::FailedPublishedWithoutRecord => 2,
        NativePublication::PublishRetainingPrior => 3,
        NativePublication::PublishStoreUntouched => 4,
        NativePublication::FailedHeld => 5,
        NativePublication::ReceiptPending => 6,
        NativePublication::Hold => 7,
    };
    let mut seen = [false; 8];
    for class in publishing.into_iter().chain(held) {
        assert!(!std::mem::replace(&mut seen[slot(class)], true));
    }
    assert!(seen.into_iter().all(|class| class));
}

#[test]
fn held_decision_survives_later_publishing_siblings_and_empty_page_transport() {
    for held in [
        NativePublication::FailedHeld,
        NativePublication::ReceiptPending,
        NativePublication::Hold,
    ] {
        let root = crate::test_scratch::ScratchDir::new("native-publication-transport");
        let mut frame = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::Codex,
            &[root.to_path_buf()],
            ScanIndex::default(),
            "2026-10-20T12:00:00Z",
            365,
            100,
            false,
            None,
            &[],
            false,
            true,
            false,
        );
        NativePublication::carry(
            &mut frame.native_publication,
            Some(NativePublication::Receipted),
        );
        NativePublication::carry(&mut frame.native_publication, Some(held));
        NativePublication::carry(&mut frame.native_publication, None);
        NativePublication::carry(
            &mut frame.native_publication,
            Some(NativePublication::PublishStoreUntouched),
        );
        let mut completed = false;
        for _ in 0..1000 {
            match frame.step(None) {
                OwnedSourceScanStep::Pending(next) => {
                    assert_eq!(next.native_publication, Some(held));
                    frame = next;
                }
                OwnedSourceScanStep::Complete { scan, .. } => {
                    // No body or page shape is needed to preserve the held value.
                    assert!(scan.snapshots.is_empty());
                    assert_eq!(scan.native_publication, Some(held));
                    completed = true;
                    break;
                }
            }
        }
        assert!(
            completed,
            "publication transport must reach a completed page"
        );
    }
}

// Typed e4 inputs at the native consumer boundary. Receipt cases use the real
// store; injected non-receipt outcomes discard the actual private stage and
// run the same production disposition/custody mapping before any body effect.
pub(crate) enum E4Outcome {
    Write(WriteOutcome),
    Unprepared(UnpreparedDisposition),
}
thread_local! {
    static SETTLEMENT: std::cell::RefCell<Option<(String, E4Outcome)>> = const { std::cell::RefCell::new(None) };
}
pub(crate) struct SettlementGuard;
impl Drop for SettlementGuard {
    fn drop(&mut self) {
        SETTLEMENT.with(|slot| *slot.borrow_mut() = None);
    }
}
pub(crate) fn inject_settlement(key: String, outcome: E4Outcome) -> SettlementGuard {
    SETTLEMENT.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some((key, outcome));
    });
    SettlementGuard
}
pub(super) fn take_outcome(key: &str) -> Option<E4Outcome> {
    SETTLEMENT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(target, _)| target == key) {
            slot.take().map(|(_, outcome)| outcome)
        } else {
            None
        }
    })
}
pub(super) fn map_settlement(
    cache: &sampled_scan::SharedCache,
    acquisition: &mut FinishAcquisition,
    source: SnapshotSource,
    candidate: Option<&sampled_scan::durable_tail::RecordIdentity>,
    outcome: E4Outcome,
) -> (NativePublication, bool) {
    match outcome {
        E4Outcome::Write(outcome) => {
            write_disposition(cache, acquisition, source, outcome, candidate)
        }
        E4Outcome::Unprepared(outcome) => {
            unprepared_disposition(cache, acquisition, source, outcome)
        }
    }
}
pub(crate) fn assert_settlement_consumed() {
    SETTLEMENT.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "actual native settlement must be reached"
        )
    });
}
