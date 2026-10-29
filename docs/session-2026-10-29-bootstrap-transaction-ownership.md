# Bootstrap transaction ownership

Agent: Codex. Session: `01a1892d-458c-7001-8500-fb04c42804e5`.
Task/review identity: `codex/bootstrap-transaction-ownership`.
Base: `2c560a8c9ea3fd681f027933f56890371ea6f499`.

`service bootstrap` previously waited indefinitely for launchctl and had no
cross-process transaction ownership. Terminating its direct helper could leave
a mutating child alive while another helper replaced the same job.

Both `write-launch-agent` and `bootstrap` now take a fixed per-user, per-label
file lock before inspecting ownership or writing the plist. The lock is never
unlinked or explicitly unlocked. Only explicitly spawned lifecycle children
inherit its descriptor, keeping the same flock alive after helper exit or
abrupt termination. A competing helper waits up to five seconds and refuses
changes if the lock is still held. Execution uses `/bin/launchctl`; generated
plan strings and CLI flags remain unchanged.

The current-label ownership probe and each lifecycle command have a ten-second
polling deadline and a one MiB output cap. Normal timeout/error cleanup kills
and waits for the direct child before returning. An unparseable successful
probe or a query failure other than exact service absence refuses mutation.
A failed stage aborts the remaining sequence and reports a possible partial
installation. Successful command exit still does not assert daemon readiness.

Regression coverage uses temporary files, injected command/ownership seams and
shell builtins. It covers bounded command kill/reap, inherited lock retention,
helper death while a child owns the transaction, competing lock acquisition,
nonzero stage short-circuiting, unknown probe refusal, external-owner
noninterference and symlink-lock refusal. Tests never contact launchd.

Validation is CI-only for this task. No local Cargo command, test execution,
live launchctl operation, installer action or daemon restart is authorized.
The PR links exact-head Linux CI and the required local strict AutoReview
receipt. Native macOS compilation and flock behavior remain required before
integration; Linux success alone does not prove either. No manual macOS
workflow dispatch is requested.

Limits: the lock coordinates callers using this implementation. It cannot
serialize external launchctl invocations, old helper binaries, or shell
installers that bypass it. A request already accepted by launchd cannot be
revoked by killing a child. After failure or helper cancellation, the caller
must reconcile actual ownership and daemon identity/readiness; it must not
interpret helper completion as successful installation. A wedged child left
by helper SIGKILL can retain the lock indefinitely, causing later attempts to
fail closed. Legacy-label cleanup is unchanged and precedes this transaction;
its separate process/SMAppService behavior is outside this change.
