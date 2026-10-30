// Original bodies/assertions are called unchanged. This is disabled/base-exit
// mode, NOT evidence for eligible envelope reuse.
use super::*;

#[test]
fn p12_experimental_base_exit_claude_duplicate_across_pages_stays_refused_without_reparse_loop() {
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    claude_duplicate_across_pages_stays_refused_without_reparse_loop();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_duplicate_across_pages_stays_refused_without_reparse_loop mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
#[ignore = "terminal-off ON-readiness: C1-X"]
fn terminal_off_on_p12_experimental_base_exit_claude_duplicate_across_pages_stays_refused_without_reparse_loop() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    claude_duplicate_across_pages_stays_refused_without_reparse_loop();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_duplicate_across_pages_stays_refused_without_reparse_loop mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
fn p12_experimental_base_exit_claude_explicit_fork_duplicate_owned_request_fails_posture_closed() {
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    claude_explicit_fork_duplicate_owned_request_fails_posture_closed();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_explicit_fork_duplicate_owned_request_fails_posture_closed mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
fn terminal_off_on_p12_experimental_base_exit_claude_explicit_fork_duplicate_owned_request_fails_posture_closed() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let _completion_paths = crate::snapshots::ClaudeCompletionPathsForTest::enable();
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    terminal_off_on_claude_explicit_fork_duplicate_owned_request_fails_posture_closed();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_explicit_fork_duplicate_owned_request_fails_posture_closed mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
fn p12_experimental_base_exit_claude_future_quarantine_preserves_cross_page_duplicate_refusal() {
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    claude_future_quarantine_preserves_cross_page_duplicate_refusal();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_future_quarantine_preserves_cross_page_duplicate_refusal mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
#[ignore = "terminal-off ON-readiness: C1-X"]
fn terminal_off_on_p12_experimental_base_exit_claude_future_quarantine_preserves_cross_page_duplicate_refusal() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    claude_future_quarantine_preserves_cross_page_duplicate_refusal();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_future_quarantine_preserves_cross_page_duplicate_refusal mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
fn p12_experimental_base_exit_claude_pending_census_recovers_without_releasing_future_quarantine() {
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    claude_pending_census_recovers_without_releasing_future_quarantine();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_pending_census_recovers_without_releasing_future_quarantine mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
#[ignore = "terminal-off ON-readiness: C1-X"]
fn terminal_off_on_p12_experimental_base_exit_claude_pending_census_recovers_without_releasing_future_quarantine() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    claude_pending_census_recovers_without_releasing_future_quarantine();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_pending_census_recovers_without_releasing_future_quarantine mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
fn p12_experimental_base_exit_claude_stable_owned_start_recovers_after_partial_conflict() {
    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    claude_stable_owned_start_recovers_after_partial_conflict();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_stable_owned_start_recovers_after_partial_conflict mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}

#[test]
#[ignore = "terminal-off ON-readiness: C1-X"]
fn terminal_off_on_p12_experimental_base_exit_claude_stable_owned_start_recovers_after_partial_conflict() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let scope = crate::snapshots::envelope_selection_experiment::Scope::restart();
    claude_stable_owned_start_recovers_after_partial_conflict();
    assert_eq!(scope.counts().rearm_suppressed, 0);
    writeln!(std::io::stderr().lock(), "p12_oracle: name=claude_stable_owned_start_recovers_after_partial_conflict mode=experimental_base_exit_no_reuse status=PASS original_assertions_unchanged=true eligible_reuse_proved=false").unwrap();
}
