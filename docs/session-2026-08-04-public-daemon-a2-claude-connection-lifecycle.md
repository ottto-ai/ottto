# Public daemon Claude connection lifecycle

**Date:** 2026-08-04
**Scope:** W3 A2 public daemon connection-lifecycle contract

The authenticated local daemon can now prepare, observe, stop, resume, and
remove a managed Claude Code account registration. It creates one owner-only
directory under the daemon support root, persists intent before filesystem
creation, and returns an exact `CLAUDE_CONFIG_DIR=... claude` command. The
customer performs official Claude Code `/login`; Ottto never enters credentials,
refreshes OAuth, writes Keychain, invokes a model, or kills the customer process.

Prepare is idempotent by operation id and survives crashes before directory
creation or registration. Settings mutations use process and filesystem locks,
atomic owner-only writes, no-follow opens, and mode-at-create directory checks.
Stop Waiting is terminal to ordinary checks; only explicit prepare replay resumes
the same operation and path. Empty crash-window directories may be removed, but
non-empty directories and credentials are preserved. Removing a registration
also preserves its directory.

One check holds an operation-specific nonblocking lock across exact-slot
identity and usage collection. All collection paths also share an account-level
nonblocking lock across cache admission, provider request, and persistence, so
scheduled collection and setup checks cannot duplicate the same account request.
Contention serves only an exact cache within the existing 24-hour bound or
returns typed in-progress state.

Completion requires fresh canonical session and weekly account windows plus at
least one scoped/model limit for the exact strong account. Credits are optional.
Provider outages preserve prior same-account full-read proof without fabricating
new identity. Account rotation produces typed mismatch. The network off-switch
returns `collection_paused`, makes no provider call, and retains caches,
registrations, and consent with honest timestamps.

Unresolved-account status is derived only from high-confidence Claude Desktop
session evidence, using the evidence activity timestamp and the existing
90-day detected-use retention. Accounts with current or retained same-slot full
proof are subtracted; partial, weak, hashless, expired, removed-slot, and orphan
state cannot suppress a warning. Raw paths, launch commands, and operation state
remain authenticated local-control data and never enter backend snapshots.
