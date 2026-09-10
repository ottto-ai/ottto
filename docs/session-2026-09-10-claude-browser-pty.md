# Claude browser launch under supervised authentication

**Date:** 2026-09-10
**Scope:** Public Claude provider supervisor

Installed stable `0.1.127` proved that the new in-app authorization-code state
machine removed the Terminal fallback, preserved the existing Claude account,
and exposed a safe browser retry. It also exposed a provider-launch regression:
Claude Code 2.1.263 treats ordinary piped standard streams as non-interactive,
so the supervisor's private output scanner caused the official CLI to skip its
automatic browser launch and exit.

The supervisor now attaches the exact `claude auth login --claudeai` process to
a private pseudo-terminal. All three provider standard streams remain
interactive, while Ottto continues to drain the output privately and emits
only the existing typed authorization-code events. Terminal echo is disabled
before process launch so a submitted one-time code cannot be reflected into
the scanner. The PTY descriptors are close-on-exec; only the intended slave
standard streams and the existing provider-lifetime lock cross the exec
boundary.

Focused acceptance covers PTY-backed stdin/stdout/stderr, parent-EOF process
termination, no-echo terminal attributes, authorization-code state and input
validation, exact event scanning, root pinning, cancellation, recovery, and
provider lifetime evidence. No public protocol or UI contract changed.
