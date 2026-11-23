use super::*;

/// [money] The new-destination latch path preserves the multi-account,
/// switch, side-call and gap oracle, including exact ACK and quiet restart.
#[test]
fn first_read_latch_multi_account_transition_oracle() {
    crate::snapshots::with_claude_reemission_stop_restored_for_test(|| {
        crate::snapshots::restart_claude_reemission_stop_for_test();
        first_request_own_login_transition_oracle_with_marker(true);
    });
}
