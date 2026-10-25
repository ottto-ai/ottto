# Recent Desktop request activity and cached agent status

`ottto agent-status --app claude-code --cached --json` reads only the running
status owner's process memory. It neither starts the daemon nor schedules or
waits for collection, loads a disk cache, reconciles settings, builds general
status, or refreshes provider quota. Success prints the existing snapshot JSON
array; `[]` means no in-memory collection. The separate local-control command is
`{"command":"agent_status_cached","source":"claude_code"}` (protocol 15).
Older daemons reject the unknown command; callers must not retry with refresh.
Transport/authentication errors retain the usual CLI JSON error and exit codes.

The existing health snapshot supplies config-selected account evidence even
when a registered slot shadows the default upload. Existing exact
`plan_observations` can optionally contain
`"desktop_recent_at":"2026-10-25T10:00:00Z"`. This is the latest qualifying
request event time for that exact account hash and organization hash, restricted
to the Desktop account already selected by `lastKnownAccountUuid`. Account
selection, billing attribution, plan labels, and current-login flags are
unchanged. Both organizations can qualify. The response omits timestamps older
than 15 minutes or in the future; fractional event time is preserved. Clients
holding a response must apply the same expiry against their current clock.

The existing request fold contributes activity only when the request's own
usage records say `entrypoint: claude-desktop`, its event clock is complete,
and an existing line-ordered credential-org marker governs the request. Every
physical usage record of a progressive response must qualify; missing or mixed
entrypoints fail closed. Resuming a Desktop session in a terminal cannot extend
Desktop activity, and starting on CLI does not hide subsequent Desktop requests.
Native, unimported, unambiguous Desktop session evidence supplies the account;
organization membership alone never supplies it. This uses the native original
already saved before request enrichment, since the existing billing veto may
mark an old native org conflicted after a valid same-account org switch. Stronger
per-request ownership/account/org mismatches still veto activity; the existing
billing veto and classifier are unchanged. The existing capture/permit
and successful request-fold gates still apply. Incomplete or unmatched evidence
stays absent; this signal is opportunistic, not proof of the current UI selection.

No acquisition path was added: the parser retains one boolean on each existing
response/occurrence; the existing request sink stages at most 64 hashed pairs
and successful folding publishes a process-local aggregate of at most 64 pairs.
The overlay touches only response copies. No additional file read, scan, watcher,
poll, replay, census, cache invalidation, disk persistence, or startup hydration
is introduced. Restart begins without activity until ordinary processing
supplies it. Source inspection follows the new cached command through direct
in-memory token authorization and status-lane `cached`, never `collection`.

`AgentStatusSnapshot::redacted_for_backend` removes `desktop_recent_at`.
The signal is never installed into daemon health, diagnostics sections, snapshot
wire data or their semantic hashes. Only account/org hashes and event times are
retained by the new aggregate; no credential, prompt, raw identifier or path is
added. Existing Desktop-config acquisition remains unchanged.

Synthetic unit coverage includes window/future/expiry boundaries, both orgs,
shared-org account isolation, Desktop-to-CLI and CLI-to-Desktop transitions,
missing entrypoint, ambiguous native ownership, serialization/redaction, distinct
CLI/control wire form, and cached reads during failed or in-flight collection
without scheduling or disk fallback. Full Rust/native/export checks run in CI.

This source change ships in the next stable runtime release containing its
merged commit. It does not cut a release or change a consumer runtime pin.
