# Session: Attribute Claude Snapshot Usage to Desktop Accounts

Date: 2026-07-31

## Problem

Claude Code snapshot rows carried provider routing but no account identity. On
a machine with more than one Claude subscription, the backend therefore could
not connect a top-level session to the correct source-plan profile. Subagents
can inherit a proven parent profile, but root sessions need their own evidence.

## Resolution

The existing Claude Desktop session-store scan derives an account hash from the
first path component below
`claude-code-sessions/<accountUuid>/...` and joins it to the transcript by the
provider-native `cliSessionId`. It uses the same
`billing_identity_hash("anthropic", "account", ...)` function as quota and plan
observations.

Only the hash is retained or uploaded. Raw account UUIDs, emails, credentials,
and file paths never enter the snapshot. The hash is copied to every top-level
and hourly `model_usage` row and survives local OTLP effort-row splitting.

Headless Agent SDK sessions use a second provider-native path. Claude Code emits
`session.id` plus `user.account_uuid` on its official `claude_code.api_request`
OTLP log for Claude-account authentication. The loopback relay already reduces
that log locally for effort evidence even when organization live telemetry is
disabled. It now validates the canonical UUID, reduces it immediately to the
same account hash, discards the UUID, and stores only the hash in the owner-only
per-session sidecar. Snapshot enrichment requires every locally observed API
request to carry the same exact hash and clears a conflict or partial identity
instead of choosing between accounts. Account capture does not depend on the
optional `effort` attribute; unsupported-effort models still retain identity,
while only valid effort values participate in effort-row splitting. Legacy
effort-only sidecar rows are explicitly neutral rather than being mistaken for
current missing-account evidence during upgrade. A session spanning that
upgrade remains unknown unless independent Desktop-store identity matches the
new exact hash. For an SDK-only session, checked events must exactly cover the
snapshot's request count and all token totals; one post-upgrade request cannot
claim older usage by itself.

The per-session sidecar fingerprint includes the selected hash. A Desktop-store
mapping that arrives after the transcript was first scanned therefore reselects
that one session. The hash also participates in the policy-scoped attribution
component so semantic no-op suppression cannot discard the reparsed snapshot.
It remains outside released hash-epoch-1 content identity, avoiding a fleet-wide
content remint. The local OTLP sidecar's stat fingerprint also participates in
candidate selection, so identity arriving after a transcript's final write
reselects that session without reopening unrelated transcripts.

## Fail-closed rules

- A session id found under exactly one account gets that account hash.
- Repeated files under the same account remain one exact match.
- The same session id found under different accounts is ambiguous and emits no
  account hash.
- Subagent transcripts never borrow the root's Desktop-store identity; the
  backend's parent/root profile inheritance remains their evidence path.
- Direct API/cloud sessions, missing/malformed UUIDs, partially identified
  sessions, and sessions with multiple locally observed account hashes remain
  explicitly unattributed.
- A Desktop-store hash and locally reduced OTLP hash must agree; disagreement
  clears the snapshot identity.

## Agent SDK boundary

Headless SDK sessions are absent from the Desktop store, but they do not require
a caller-owned launch-time guess: the Claude Code child process emits the
session/account pair itself. Users who disable Claude telemetry or account UUID
inclusion remain honestly unknown. Direct API, Bedrock, Vertex, and Foundry
sessions intentionally carry no Claude account UUID and also remain unknown.

## Verification

- Exact Desktop-store match stamps top-level and hourly rows.
- Raw account-directory values do not appear on the wire.
- Cross-account duplicate session ids stay unattributed; removing the conflict
  changes both the sidecar fingerprint and selected identity (negative control).
- A mapping discovered after an unattributed scan emits a second snapshot
  instead of being discarded as a semantic no-op.
- Claude effort enrichment preserves the exact account hash while splitting
  model rows.
- The local reducer persists the hash but never the raw provider UUID; equivalent
  canonical UUID casing produces the same daemon/backend identity.
- One consistently observed SDK account stamps every usage row; a second
  account or any request without a valid hash clears the identity (negative
  control proves the conflict guard is load-bearing).
- The snapshot test suite and cross-language semantic-envelope golden retain
  released hash-epoch-1 semantics with or without the optional field.
