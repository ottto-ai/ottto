//! Transport and disposition mapper controls, including typed WriteOutcome inputs.
//! These do not prove real store failures. Injected Pi rows additionally check
//! downstream HTTP/ACK behaviour in retry_live_native_tests.rs. Real-path proof:
//! durable_transition_pi_tests::pi_stale_survivor_holds_then_resolves_with_a_counted_tail
//! and retry_live_native_tests::pi_e4_receipted_captures_and_posts (uninjected).
use super::*;
pub(crate) use sampled_scan::durable_tail::{
    Degraded, DegradedCause, HeldCause, NotPersisted, Unprepared, UnpreparedDisposition,
    WriteOutcome,
};

use sampled_scan::durable_tail::FinishAcquisition;

fn acquisition() -> FinishAcquisition {
    FinishAcquisition::Uncertified(DurableCustody::default())
}

/// [money] Mapper: Codex strict rebind keeps the existing publishing class.
/// Typed outcomes exercise disposition conversion, not a real store failure.
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

/// [money] Mapper: Claude and Pi strict rebind are held publication decisions.
/// Typed outcomes exercise disposition conversion, not a real store failure.
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

/// [money] Mapper: native publication has five publishing and three held classes.
/// Typed outcomes exercise disposition conversion, not a real store failure.
#[test]
fn native_publication_has_exactly_five_publishing_and_three_held_classes() {
    let cache = sampled_scan::SharedCache::default();
    let source = SnapshotSource::Codex;
    let unprepared =
        |outcome| unprepared_disposition(&cache, &mut acquisition(), source, outcome).0;
    let write = |outcome| write_disposition(&cache, &mut acquisition(), source, outcome, None).0;
    let cause = Unprepared::NotPersisted(NotPersisted::Codec);
    // The receipt policy is a typed value here; real candidate/receipt binding
    // stays in the existing facade fixtures and the uninjected Pi receipt test.
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

/// [money] held decision survives later publishing siblings and empty page transport.
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

/// Typed mapper inputs at the native consumer boundary, not real store failures.
/// Injected outcomes discard the actual private stage and run production
/// disposition/custody mapping before downstream HTTP/ACK effects. The uninjected
/// receipt and stale-survivor tests named above provide real-path evidence.
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
/// Inject a mapper input; this seam does not fail a store operation.
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
/// Map the supplied WriteOutcome/UnpreparedDisposition through production policy.
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
/// Confirm the mapper input was consumed, not that a real store failure occurred.
pub(crate) fn assert_settlement_consumed() {
    SETTLEMENT.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "actual native settlement must be reached"
        )
    });
}
