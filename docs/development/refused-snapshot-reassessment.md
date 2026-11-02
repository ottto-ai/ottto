# Refused snapshot reassessment

An older activity timestamp does not prove that accepted usage covers a refused
snapshot. `accepted_log_stale_older_upload` and
`accepted_log_stale_older_mixed` remain owed. The mixed reply may be non-permanent;
it is recognized for Claude, Codex and Pi independently of request-owned usage
contracts. Refusals and body witnesses remain in the destination's upload ledger.
An identical refused body is suppressed. Input changes can produce a new body
and one new offer. Parser labels, elapsed time and exhausted retries grant no
permission to resend refused bytes.

Existing terminal records retain their disposition until explicitly reassessed.
For a one-time reassessment, the local data owner creates a regular file beside
that source's destination-scoped upload-progress JSON, replacing its `.json`
extension with `.stale-older-reopen-once`. Symlinks and non-files grant nothing.
The marker is an operator action, not a persistent feature switch. Removing it
does not cancel already saved work. Leaving it present or recreating it cannot
renew the action. No daemon restart is required.

On the next ordinary source cycle, the upload ledger atomically records the
action as consumed and marks retained stale refusals non-terminal and pending
one reconstruction. Each pending record uses the existing paced retry budget.
Before source acquisition, its claim is saved; a failed save prevents reading.
Unchanged bytes remain suppressed even during this acquisition. Source holds
and interrupted claims remain owed and visible; they do not gain timer-based
renewal. This action clears no ACK, proof, identity or refusal evidence and
changes no server acceptance rule. A changed-body ACK alone does not erase an
older refused revision without coverage evidence.

`owed_exposure` page diagnostics and a daily summary on the next source cycle
report distinct entities by source, refusal reason and age bucket. Snapshot
mirrors and resolvable authority member aliases are combined before counting.
Unresolved body revisions stay separate; an identical mirror counts once.
Known request and token counts are reported separately from unknown counts.
Token totals respect the body's declared cached-input scope.
Legacy age remains unknown; observation time is never substituted for it.
A rising entity count or oldest known age emits a local alarm. These diagnostics
do not gate, cap, wake, settle or retire work.

Older stale revisions retain their own body witnesses and exposure when a later
body is refused. Only exact acknowledgement clears that revision's debt.

The state extensions are optional, default absent, and omitted when absent.
Existing disposition and reason enum values are unchanged. No schema or parser
version changes are required.
