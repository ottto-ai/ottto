// Original bodies/assertions are called unchanged. This is disabled/base-exit
// mode, NOT evidence for eligible envelope reuse.
use super::*;

#[test]
fn p12_experimental_base_exit_account_deferred_hold_lets_a_bounded_claude_traversal_converge() {
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    account_deferred_hold_lets_a_bounded_claude_traversal_converge();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=account_deferred_hold_lets_a_bounded_claude_traversal_converge mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
#[ignore = "terminal-off ON-readiness: NBF/C6"]
fn terminal_off_on_p12_experimental_base_exit_account_deferred_hold_lets_a_bounded_claude_traversal_converge() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    terminal_off_on_account_deferred_hold_lets_a_bounded_claude_traversal_converge();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=account_deferred_hold_lets_a_bounded_claude_traversal_converge mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
fn p12_experimental_base_exit_terminal_family_member_controls_keep_blocking_pruning_and_rebinding() {
    // Terminal-authority hold/rearm policy; E2 literal bodies bypass legacy demotion.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    terminal_family_member_controls_keep_blocking_pruning_and_rebinding();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=terminal_family_member_controls_keep_blocking_pruning_and_rebinding mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
#[ignore = "terminal-off ON-readiness: NBF/C6"]
fn terminal_off_on_p12_experimental_base_exit_terminal_family_member_controls_keep_blocking_pruning_and_rebinding() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // Terminal-authority hold/rearm policy; E2 literal bodies bypass legacy demotion.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    terminal_off_on_terminal_family_member_controls_keep_blocking_pruning_and_rebinding();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=terminal_family_member_controls_keep_blocking_pruning_and_rebinding mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
fn p12_experimental_base_exit_terminal_family_never_committed_members_let_the_claude_census_complete() {
    // Terminal-authority hold/rearm policy; E2 literal bodies bypass legacy demotion.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    terminal_family_never_committed_members_let_the_claude_census_complete();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=terminal_family_never_committed_members_let_the_claude_census_complete mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
#[ignore = "terminal-off ON-readiness: NBF/C6"]
fn terminal_off_on_p12_experimental_base_exit_terminal_family_never_committed_members_let_the_claude_census_complete() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // Terminal-authority hold/rearm policy; E2 literal bodies bypass legacy demotion.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    terminal_off_on_terminal_family_never_committed_members_let_the_claude_census_complete();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=terminal_family_never_committed_members_let_the_claude_census_complete mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}
