//! D3 per-key hold and G3 owed-marker regression controls (RAM state only).
use super::super::owed::OwedMark;
use super::*;
use crate::durable_tail_store::DurableSource;

const A: store::Digest32 = [1; 32];
const B: store::Digest32 = [2; 32];
const OBJECT: (u64, u64, u64) = (7, 11, 13);

/// [money] owed hold is not downgraded and source clear is scoped.
#[test]
fn owed_hold_is_not_downgraded_and_source_clear_is_scoped() {
    let mut stores = Stores::default();
    stores.set_owed(A, OwedMark::Hold(DurableSource::ClaudeCode));
    stores.set_owed(A, OwedMark::Owed(DurableSource::ClaudeCode));
    assert_eq!(
        stores.owed_mark(&A),
        OwedMark::Hold(DurableSource::ClaudeCode)
    );
    stores.set_owed(B, OwedMark::Owed(DurableSource::Codex));
    stores.clear_source_owed(DurableSource::ClaudeCode);
    assert_eq!(stores.owed_mark(&A), OwedMark::None);
    assert_eq!(stores.owed_mark(&B), OwedMark::Owed(DurableSource::Codex));
    stores.clear_owed(B);
    assert_eq!(stores.owed_mark(&B), OwedMark::None);
}

/// [money] d3 edit proof survives subsequent failed settlement and not discovery.
#[test]
fn d3_edit_proof_survives_subsequent_failed_settlement_and_not_discovery() {
    let mut stores = Stores::default();
    stores.hold_key(A, Some((OBJECT, 100)));
    stores.release_hold(A, HoldRelease::Content);
    assert!(stores.hold_content_changed(A));
    assert!(stores.hold(&A).is_none());
    assert!(!stores.observe_hold(A, Some((OBJECT, 200))));
    stores.hold_key(A, Some((OBJECT, 200)));
    assert!(stores.hold_content_changed(A));
    assert_eq!(stores.claude_holds(), [0, 0]);
}
