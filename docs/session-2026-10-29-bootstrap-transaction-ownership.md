# Bootstrap transaction ownership

Agent: Codex. Session: `01a1892d-458c-7001-8500-fb04c42804e5`.
Task/review identity: `codex/bootstrap-transaction-ownership`.
Base: `2c560a8c9ea3fd681f027933f56890371ea6f499`.

A terminated service-bootstrap helper could leave a mutating launchctl child
alive while another caller replaced the same per-user job. CLI autostart also
mutated that label without coordinating with bootstrap.

`ottto-core::service_lifecycle` now owns one fixed home/label lock path, its
safety checks, explicit descriptor inheritance, and bounded command cleanup.
Both helper bootstrap/plist writes and default CLI autostart participate.
The file is never unlinked or explicitly unlocked: a surviving child retains
the same flock after helper termination. The parent keeps CLOEXEC set; only the
intended child's copy is cleared before exec.

Bootstrap waits up to five seconds for the transaction. CLI autostart tries
once and, if busy, issues no launchctl commands and returns to the CLI's
existing bounded socket retry. Participating launchctl commands use a fixed
executable path, a ten-second polling deadline, a one MiB output cap, and
kill/wait cleanup. CLI command work also has a thirty-second budget. Its
existing finite loaded-job reconciliation is retained; indeterminate command
errors stop recovery. A failed bootout cannot proceed to bootstrap unless its
status specifically means that the job is already absent.

The helper's ownership probe runs under the lock and refuses unknown results.
It reuses the existing ownership decision and shared refusal-message builder,
including the current owner and owner-specific repair hint. Explicit owner
migration remains available. Failed stages abort the remaining helper plan.
Successful command exit does not assert daemon readiness.

The service error envelope and nonzero exit status are preserved. JSON error
classification is corrected:

| Condition | Code | Retryable |
| --- | --- | --- |
| Existing owner refusal | `launch_agent_owner_conflict` | false |
| Transaction busy before cleanup, writes or current-job commands | `launch_agent_transaction_busy` | true |
| Unknown probe, filesystem/command failure or indeterminate mutation | `launch_agent_lifecycle_failed` | false |

A typed lifecycle failure overrides nested preflight markers, so a failed
mutation never becomes retryable merely because an underlying error is busy.

An independent source review of `b19b46f33` returned NO-GO: CLI autostart bypassed
the lock, all errors were mislabeled as owner conflicts, and refusal messages
lost the current owner and repair hint. All three findings were accepted and
addressed here. That initial verdict is preserved; no subsequent Claude GO is
claimed. Final verification uses the same task identity and one focused,
sensitive AutoReview pass after relevant CI.

Regression tests use temporary files, injected command results and synthetic
subprocesses, never live launchd. They cover timeout kill/reap, inheritance
after owner close and Rust helper death, competing acquisition, CLI contention
without mutation, indeterminate CLI recovery refusal, conclusive recovery,
failed-stage short-circuiting, actual JSON decision mapping, owner hints,
explicit migration, external plist preservation and symlink-lock refusal.

Validation is CI-only for this task. No local Cargo/tests, live launchctl,
installer action or daemon restart is performed. Exact-head results and the
focused review outcome are linked from the PR. Native macOS compilation and
flock behavior remain required before integration; Linux success alone does
not establish either. No manual macOS dispatch is requested.

Limits: external launchctl, older binaries and installer scripts bypassing the
shared implementation remain outside this lock. Requests already accepted by
launchd cannot be revoked by killing a child. Callers must reconcile ownership
and runtime identity/readiness after failure or cancellation. A wedged child
left by helper SIGKILL can hold the lock indefinitely, causing later attempts
to fail closed. Legacy-label cleanup remains separate behavior and runs after
lock acquisition, before current-label inspection/writes; its own process and
SMAppService timing is unchanged. No persistent transaction journal, atomic
plist replacement or rollback protocol is introduced.
