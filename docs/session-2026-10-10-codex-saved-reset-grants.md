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
- Every Codex balance now carries `kind`: `credits` → `plan_credits`,
  `reset_bank` → `saved_resets`, `workspace_monthly_credits` →
  `workspace_allowance`. A pool other than `codex` keeps its existing
  `<limit_id>_` name prefix and the same kind. Names do not change.

## Detail cadence

A detailed `account/rateLimits/read` makes Codex call its backend twice. Routine
polls now send `{"excludeResetCreditDetails": true}`, which still returns the
count. The detailed request is unchanged (no params) and is sent when:

- the account binding has had no successful detailed read for an hour (a
  one-minute slack keeps a 5-minute poll on the hour);
- a routine answer reports a count with no cached list for that count: a count
  change, a cold cache after restart or sleep, or a different account in the
  same Codex home. The detailed read follows in the same app-server session;
- the app-server rejects the routine parameter (older servers).

A failed detailed read is retried after 15 minutes, or at once if the count
changes again, never on every poll. A failing detail endpoint therefore never
costs more than the old every-poll detailed read did. If the detailed read in
the same session does not answer before the existing 20-second session bound,
the routine answer is used.

The decisions are pure functions of a per-binding state and the clock
(`DetailCadence`, `CodexCreditTracker::plan_read` and
`routine_needs_details`), unit-tested over a simulated hour.

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

- Adapter fixtures: provider JSON → expected wire for complete two- and
  three-grant lists, count-only and `credits: null`, provider-capped, invalid
  rows (partial, with field-path diagnostics), empty list with zero count.
- Cadence: a simulated hour with two count changes is exactly three detailed
  reads and eleven routine reads; the next hourly read lands one hour after the
  last detailed read.
- Stability: the list is byte-identical across four routine polls; a cold
  cache reads details first; A→B→A keeps A's list; a failed hourly read re-sends
  the matching list; a failed read after a count change is `unavailable` and is
  retried on the next count change or after the retry wait.
- Session: a scripted app-server confirms the routine request carries the
  parameter, the escalation sends the plain request in the same session, the
  detailed plan sends exactly the historical request, and a server that rejects
  the parameter falls back to the plain read.
- Resolver: scratch bundles with the old and new layouts.

No live provider calls were made; all fixtures are synthetic.

## Limits

- If Codex's routine count and detail count ever disagreed persistently, every
  routine poll would read details again: the old cost, not more.
- The legacy OAuth fallback path (opt-in, default home only) gains `kind` but
  no grants; it never read the reset list.
- Emitting pools as meters, an exact-decimal credit balance and an
  `ordinaryUsageAllowed` passthrough remain out of scope.
