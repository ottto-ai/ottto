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
to the accounts selected by `lastKnownAccountUuid` in each discovered Desktop
app's config. Both accounts and both organizations can qualify. Billing
attribution, plan labels, and current-login flags retain their existing rules
within each app. The response omits timestamps older
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

No transcript acquisition path was added: the parser retains one boolean on each existing
response/occurrence; the existing request sink stages at most 64 hashed pairs
and successful folding publishes a process-local aggregate of at most 64 pairs.
The overlay touches only response copies. No additional watcher, poll, replay,
census, cache invalidation, disk persistence, or startup hydration is introduced.
Restart begins without activity until ordinary processing
supplies it. Source inspection follows the new cached command through direct
in-memory token authorization and status-lane `cached`, never `collection`.

`AgentStatusSnapshot::redacted_for_backend` removes `desktop_recent_at`.
The signal is never installed into daemon health, diagnostics sections, snapshot
wire data or their semantic hashes. Only account/org hashes and event times are
retained by the new aggregate; no credential, prompt, raw identifier or path is
added.

Desktop root discovery includes `Library/Application Support/Claude` and
immediate sibling `Claude-*` directories containing `config.json`. It examines
at most 4,096 directory entries and keeps at most 64 roots, default first and
then sorted siblings. It neither recurses nor follows sibling directory
symlinks; helper folders without config are skipped. Each root uses the existing
config, `claude-code-sessions`, and `local-agent-mode-sessions` metadata readers.
Session ownership and labels are resolved separately inside each root before
combining observations, so buckets from different apps cannot lend each other
identity. Primary pairs are consolidated by strong account/org binding before
global upload and connect-target limits. The newest root-local pair supplies
the primary reading; other distinct session witnesses remain duplicate evidence.
Unresolved connect-target IDs are deduplicated before their limit.
The snapshot fold's existing native-identity/title sidecar reader uses the same
roots and retains its global file/entry budgets. Native witnesses still fail
closed when copies of a transcript disagree on account or organization.
Desktop-local parent IDs resolve within their own app; copies of a child across
apps must agree on the resolved parent. The existing path-keyed session entries
keep the app scope. An additive, optional inventory digest binds the saved census
cursor, frozen ceiling and completeness to the configured stores. Changed or
unknown inventory clears those claims and restarts the bounded sweep under the
existing retry backoff. Older indexes rebuild that census before asserting it
complete; session-entry formats are unchanged.
Installation detection uses the same roots. The existing account-switch probe
includes every root's config identity, waking the existing wait loop on a sibling
account switch or profile addition/removal. The single-app fingerprint is
unchanged. No session metadata is read by that probe.

Synthetic unit coverage includes window/future/expiry boundaries, both orgs,
shared-org account isolation, Desktop-to-CLI and CLI-to-Desktop transitions,
missing entrypoint, ambiguous native ownership, serialization/redaction, distinct
CLI/control wire form, and cached reads during failed or in-flight collection
without scheduling or disk fallback. Full Rust/native/export checks run in CI.

This source change ships in the next stable runtime release containing its
merged commit. It does not cut a release or change a consumer runtime pin.
