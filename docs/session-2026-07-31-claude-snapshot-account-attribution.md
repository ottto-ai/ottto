# Session: Attribute Claude Snapshot Usage to Desktop Accounts

Date: 2026-07-31

## Problem

Claude Code snapshot rows carried provider routing but no account identity. On
a machine with more than one Claude subscription, the backend therefore could
not connect a top-level session to the correct source-plan profile. Subagents
can inherit a proven parent profile, but root sessions need their own evidence.

## Resolution

The existing Claude Desktop session-store scan now derives an account hash from
the first path component below
`claude-code-sessions/<accountUuid>/...` and joins it to the transcript by the
provider-native `cliSessionId`. It uses the same
`billing_identity_hash("anthropic", "account", ...)` function as quota and plan
observations.

Only the hash is retained or uploaded. Raw account UUIDs, emails, credentials,
and file paths never enter the snapshot. The hash is copied to every top-level
and hourly `model_usage` row and survives local OTLP effort-row splitting.

The per-session sidecar fingerprint includes the selected hash. A Desktop-store
mapping that arrives after the transcript was first scanned therefore reselects
that one session. The hash also participates in the policy-scoped attribution
component so semantic no-op suppression cannot discard the reparsed snapshot.
It remains outside released hash-epoch-1 content identity, avoiding a fleet-wide
content remint.

## Fail-closed rules

- A session id found under exactly one account gets that account hash.
- Repeated files under the same account remain one exact match.
- The same session id found under different accounts is ambiguous and emits no
  account hash.
- Subagent transcripts never borrow the root's Desktop-store identity; the
  backend's parent/root profile inheritance remains their evidence path.
- A session absent from the Desktop store remains explicitly unattributed.

## Remaining provider gap

Headless Claude Agent SDK sessions are not written to Claude Desktop's session
store, and their transcript metadata carries no account or parent identity.
Anthropic's SDK documentation also says SessionStart hooks are unavailable in
the Python SDK. Assigning those roots from the machine's current login during a
later scan would be time-of-check guesswork after an account switch, so this
change deliberately leaves them unknown. Complete SDK-root attribution requires
an SDK/caller launch-time binding that supplies the session id and account
identity together.

## Verification

- Exact Desktop-store match stamps top-level and hourly rows.
- Raw account-directory values do not appear on the wire.
- Cross-account duplicate session ids stay unattributed; removing the conflict
  changes both the sidecar fingerprint and selected identity (negative control).
- A mapping discovered after an unattributed scan emits a second snapshot
  instead of being discarded as a semantic no-op.
- Claude effort enrichment preserves the exact account hash while splitting
  model rows.
- The snapshot test suite and cross-language semantic-envelope golden retain
  released hash-epoch-1 semantics with or without the optional field.
