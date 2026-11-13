//! Pi usage ledger tests.

#[cfg(test)]
mod ledger;

#[test]
fn session_header_preserves_check_session_id() {
    use crate::snapshots::{SnapshotAccumulator, SnapshotSource};
    let id = "ottto-check-3726e33d-c085-444e-8c83-b9be1b492a80";
    let header = serde_json::json!({"type": "session", "id": id});
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Pi);
    super::apply_pi_line(&header, &mut accumulator);
    assert_eq!(accumulator.source_session_id.as_deref(), Some(id));
}
