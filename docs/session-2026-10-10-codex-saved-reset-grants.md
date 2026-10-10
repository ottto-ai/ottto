# Codex saved-reset grants, detail cadence and pool evidence

Codex already reported how many saved rate-limit resets an account holds
(`reset_bank`), and every 5-minute poll already fetched the list of those
resets. The list was reduced to a counts-only diagnostic and dropped. This
change sends it, through the shared daemon credit model, as the grant section
of the existing `reset_bank` balance, and makes the list read cheaper.

## Grants

`agent_status::codex_credit_grants` is the only place that reads Codex
reset-credit field names. Each `rateLimitResetCredits.credits[]` row becomes a
model `GrantInput`: `id`, `resetType`, `status`, `grantedAt` and `expiresAt`
(unix seconds), and `title`. `description` is never read. The model owns the
grant key, the status table, field refusals, ordering, the 20-grant cap and
`grants_state`; the adapter re-implements none of it.

- `availableCount` is the provider count and stays the balance `remaining`.
  The list is `complete` only when every counted grant came back; fewer rows
  is `capped`; an invalid row makes it `partial`.
- `credits: null` (a count-only answer, or a failed detail call that Codex
  silently replaces with the count) is `unavailable` with the count kept. It is
  never an empty list.
- Every app-server Codex balance now carries the read completion clock
  (`observed_at`), as quota windows already did. Credit balances carry no
  `updated_at`; consumers use the snapshot capture time.
- Every Codex balance now carries `kind`: `credits` → `plan_credits`,
  `reset_bank` → `saved_resets`, `workspace_monthly_credits` →
  `workspace_allowance`. A pool other than `codex` keeps its existing
  `<limit_id>_` name prefix and the same kind. Names do not change.

## Detail cadence

A detailed `account/rateLimits/read` makes Codex call its backend twice. Every
poll now first sends the routine read, `{"excludeResetCreditDetails": true}`,
which still returns usage and the count. The detailed request is unchanged (no
params) and follows in the same app-server session when:

- the account binding has had no successful detailed read for an hour (a
  one-minute slack keeps a 5-minute poll on the hour); this includes the first
  poll after the daemon starts;
- the routine count has no cached list for that count: a count change or a
  different account in the same Codex home.

Because the routine answer comes first, a detailed read that errors, times out
or cannot be sent never costs the poll's usage and count; only the list is
missing, and the cached list is re-sent while the count matches. The detailed
read gets its own time budget (at least 10 seconds, at most 20) after the
routine answer. A routine answer that already carries the list (a server that
ignores the parameter) counts as the detailed read, with no second request.

Only a JSON-RPC "invalid params" or "invalid request" answer (-32602, -32600)
to the routine read makes the collector send the plain request instead (older
servers). Any other error fails the reading as before, without a costlier
retry.

At most one detailed read is sent per session. A failed detailed read is
retried after 15 minutes, not on every poll; a count with no cached list is
still read at once. A detailed read that never answered (error, timeout, output
bound, unsent) is a failure even for an account whose answers carry no reset
section at all; only an answered one without a reset section counts as done. A whole session that fails before any reading (spawn error,
JSON-RPC error, timeout) counts as a failed detailed read for the account last
validated at that Codex home: the next 5-minute routine read still runs, but the
hourly detailed read waits 15 minutes. A home that was never validated records
nothing, so no identity or count is invented.

Cost per account and hour, assuming one backend call per routine read and two
per detailed read (inferred from the upstream client, not measured):

- stable count: 11 routine polls plus 1 routine-and-detailed poll, about 14
  calls instead of the historical 24;
- two count changes: 9 routine polls plus 3 routine-and-detailed polls, about
  18;
- detail endpoint failing throughout: one detailed retry every 15 minutes,
  about 20.

An escalated poll costs 3 calls, more than the old 2. A count that keeps
changing, a persistent routine/detail count disagreement or a server rejecting
the parameter can therefore cost more than before in that hour.

The decisions are pure functions of a per-binding state and the clock
(`DetailCadence`, `CodexCreditTracker::routine_needs_details`), unit-tested over
a simulated hour.

## Sender stability

Between detailed reads the last observed list is re-sent from the model's
`SectionCache` unchanged, with its original `grants_observed_at`. It is re-sent
only while the routine count equals the count the list was read with. Cadence
never changes balance presence, `grants`, `grants_state` or `status`. The cache
key is the credential identity (account and workspace hashes), so switching a
home from account A to B and back keeps A's list, and two homes signed into the
same account share one list and one hourly read. An unbound reading neither
uses nor fills the cache.

## Pool evidence (counts only)

A new `codex_rate_limit_pools_observed` diagnostic describes the
`rateLimitsByLimitId` map without emitting any pool: the number of pools other
than `codex` and their ids (ids outside `^[a-z0-9_.-]{1,64}$` are only
counted), how many have a window whose reset equals read time plus window
length (an idle, sliding window), a used-percent bucket per pool, and whether
`ordinaryUsageAllowed` and `accountId` are present, null or absent. No values,
labels or account ids are copied.

The `codex_reset_credit_details_observed` diagnostic keeps its detailed-read
wording. A routine read reports `list not requested on this routine read`, and
model refusals are appended as field-path counts.

## Desktop bundle resolver

Newer ChatGPT and Codex desktop apps keep the CLI under
`Contents/Resources/codex-cli/`, as a `bin/codex` launcher and the
`CodexCLI.app/Contents/MacOS/codex` binary it runs. The resolver now probes, for
each bundle and applications root, the old `Contents/Resources` first, then the
launcher, then the inner binary, before falling back to `PATH`.

## Tests

- Canonical fixtures: every Codex `provider/*.json` body of
  `fixtures/agent-status/quota-contract-v2.2/`, read through the adapter,
  equals its `expected/*.wire.json` (complete, provider-capped, 21 rows capped
  by the sender, count-only as `unavailable`), and the re-send sequence
  matches step for step.
- Adapter fixtures: provider JSON → expected wire for complete two- and
  three-grant lists, count-only and `credits: null`, provider-capped, invalid
  rows (partial, with field-path diagnostics), empty list with zero count.
- Cadence: a simulated hour with two count changes is exactly three detailed
  reads and twelve routine reads; the next hourly read lands one hour after the
  last detailed read.
- Stability: the list is byte-identical across four routine polls; after a
  daemon restart the first poll reads details eagerly, so the first upload
  already carries the list; A→B→A keeps A's list; a failed hourly read re-sends
  the matching list; a failed read after a count change is `unavailable` and is
  retried on the next count change or after the retry wait.
- Session: a scripted app-server confirms the routine request carries the
  parameter and the escalation sends the plain request in the same session. An
  escalated read that errors, never answers, exceeds the output bound or cannot
  be sent keeps the
  routine reading. A rejected parameter falls back to the plain read, and fails
  the reading if that read fails too. Any other routine error is not retried.
- Whole-session failures: a failed session charges the detail back-off to the
  binding last validated at that home (unit and end-to-end with a scripted
  app-server that dies), a count change still escalates, and a never-validated
  home records nothing.
- Resolver: executable scratch bundles with the old and new layouts, through
  the same lookup the resolver uses.

No live provider calls were made; all fixtures are synthetic.

## Limits

- If Codex's routine count and detail count ever disagreed persistently, every
  poll would send the routine and the detailed read: 3 calls per poll instead
  of the old 2.
- The cost figures are inferred from the upstream client's request pattern,
  not measured provider calls.
- The legacy OAuth fallback path (opt-in, default home only) gains `kind` but
  no grants; it never read the reset list.
- Emitting pools as meters, an exact-decimal credit balance and an
  `ordinaryUsageAllowed` passthrough remain out of scope.
