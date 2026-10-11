# Claude one-time credits, saved resets and read cadence

The Claude usage reader now maps three credit kinds through the shared daemon
credit model (`quota_credit_model`), with the provider field names kept in one
adapter module, `agent_status/claude_credit_pools.rs`.

## Credits

- **Usage credits** keep their name (`Usage credits`) and gain
  `kind: usage_credits`, set by the adapter. When credits are off, the
  provider's `spend.disabled_reason` (or `extra_usage.disabled_reason`) is
  sent as `disabled_reason` through the model's disabled shape
  (`apply_disabled`) when it is a reason code (`^[a-z0-9_.-]{1,64}$`), such as
  `out_of_credits`; any other text is refused and logged as a field refusal.
  The `extra_usage` fallback still reads bare numbers as dollars. Real bodies
  show those numbers are minor units, but every observed plain body carries
  `spend`, which wins, so the fallback is latent and left unchanged with a code
  comment.
- **One-time dollar pools.** Every top-level object of a full usage body with a
  numeric `limit_dollars` (window keys excluded) becomes a
  `one_time_credit` balance: `limit_id` = the provider codename, amounts in
  cents from `*_dollars`, `expires_at` = the pool's `resets_at` (an expiry, not
  a cycle), `title` = `label` when present, `enabled` absent. Null pools, pools
  whose expiry passed before the read, and the percent-only `cinder_cove` are
  skipped; a pool whose codename is not a code-shaped, privacy-safe
  `limit_id` is refused by the model (`one_time_credit`) and skipped with its
  `field_refused:limit_id` refusal.
- **Saved resets.** `cedar_ember` maps to one `reset_bank` balance
  (`unit: resets`, `kind: saved_resets`) whose grants, `grants_state`,
  `grant_count`, `remaining`, `status` and expiry summary come from the model.
  Readiness is passed through by the model (`apply_readiness`) as the
  provider states it: `eligible`, `ineligible_reason`, `at_limit`,
  `cooldown_until`, and grant `usable_now`. Invalid values are refused field
  by field and never change the list state. A `cedar_ember` with readiness but
  no `grants` array keeps the last observed complete list (through the model's
  `GrantListSection`, with its original read time, count and status).

`cedar_ember` is only populated by the saved-reset read variant
(`?cedar_ember=1&skip_spend=1`), which is enabled and self-checks every
response. A `cedar_ember` object with a `grants` array or a boolean `eligible`
status is used normally. When the variant gives nothing usable (a 200 without
a recognizable `cedar_ember`, a 200 without windows, or a 4xx rejection other
than 401/403/429), the read adds the code-only diagnostic
`claude_saved_reset_variant_unrecognized` (fixed message, allowlisted for
registered-slot status, so it reaches the upload), sends no saved-reset balance
of its own (the last observed section is re-sent; never an `unknown`
stand-in), and pauses the variant for that binding for 24 h, so every slot
reads plain. A body without windows or a rejection serves the stored reading
unchanged and moves the binding's next read out by one slot: no second call in
that slot and no retry on every pass. The pause is separate variant state,
never a strike on the endpoint breaker. After 24 h the variant is read and
checked again. A variant 200 without windows but with a recognizable
`cedar_ember` is not a shape failure either: its saved-reset section is kept,
the stored windows and other sections are served unchanged, and the next read
moves out by one slot. With no stored reading at all, an unusable or
windowless variant still holds the binding until its next slot (a
"not before" time in the read schedule), so it never leads to a plain call in
the same slot. During that hold a servable stored reading (with windows) is
served, with the hold's own reason. A cedar-only reading with no stored
windows keeps its saved-reset section in the stored reading for the next
reading; until windows return, the snapshot shows no OAuth quota for that
binding (both callers drop a reading without windows), exactly as before the
read. A "not before" time further ahead than the longest slot any binding can
have (the idle slot's 3 h maximum) can only come from the clock stepping back
after it was written, so it is ignored and cleared; bounding by the longest
slot, not the current one, keeps the hold when the account turns active and
its slot shrinks. The stored reading's `next_refresh_after` is not bounded the same
way, because it also carries a provider Retry-After, which may be longer than
a slot. Other variant HTTP errors (401/403, 429, 5xx) follow the
existing backoff; a variant 429 counts toward the shared rate-limit breaker,
as it is the same endpoint.

## Read cadence

One OAuth usage read per account binding per slot; no new endpoint and no
extra calls:

- the slot is 15 min while the account had Claude session activity (from the
  daemon's active-session scan, exact account and organization) in the last
  30 min, the existing 55-65 min gate by default, and 2-3 h once the account
  has been idle more than 6 h (also spread deterministically per account);
- a slot is admitted at its elapsed boundary: readings are taken inside a
  collection pass (every ~5 min), so a 60 s slack lets the pass one slot later
  read instead of the pass after it. A 15 min slot is 15 min, not 20. The
  default and idle slots are served by the first pass at or after their
  boundary (up to one pass late); a pass that is late (sleep) reads once, with
  no catch-up;
- due slots alternate the plain and saved-reset reads. While usage credits are
  off, the plain read is due about every 6 h (measured from the usage-credit
  section's own read time and serviced at the next eligible slot) and the
  other slots take the variant. A section missing from the stored reading is
  filled first: with plain data but no saved-reset section (an older cache, a
  lost schedule) the next due slot reads the variant; the reverse reads plain;
- if Claude Code's own `.claude.json` `cachedUsageUtilization` for the same
  account (its `accountUuid` and the config's `oauthAccount` account and
  organization match the binding) is newer than the stored reading and inside
  the slot, it stands in for a **plain** slot without a call, parsed by the
  same plain-body parser. It never displaces a saved-reset slot, so an account
  in constant use still gets its variant read every other slot. A body without
  the credit keys (`spend`/`extra_usage`) updates windows only: it neither
  replaces the stored credit sections nor resets the credits-off plain clock;
- the cached body has no organization, so it is adopted only when it was
  fetched inside a continuous run of collection passes (every ~5 min, gaps up
  to 15 min) that all reached the collector with that caller signed in to
  exactly this account and organization. Another binding, a longer gap, a
  restart or a clock going backwards starts a new run, and a run never adopts a
  body fetched before it began. At the end of every full collection pass, every
  caller that did not reach the collector loses its run, whatever made it skip
  (an identity gate, upkeep, a failed resolution or settings load, capacity, a
  missing binary, a browser re-sign-in). The single-slot path, which is not a
  full pass, ends the run explicitly on each of its skip returns. Overlapping
  full passes share one reached set (their union) and sweep when the last one
  ends, so a caller reached by one of them keeps its run there; the skipping
  pass's explicit run-end and the 15 min run gap still apply. Accepted
  residual: a switch to another organization and back by the same login inside
  one pass interval, combined with a Claude Code usage fetch in flight across
  the switch, cannot be told apart from local evidence;
- the existing 5-minute post-success spacing, Retry-After handling, breaker and
  per-caller auth backoff are unchanged; one active binding never shortens
  another binding's slot;
- `CLAUDE_ACTIVITY_CADENCE_ENABLED` is a kill switch (default on): off, every
  binding uses today's 55-65 min gate with no active boost or idle slowdown.

Cadence state (`read-schedule.json`: last plain and variant reads, last
activity, first reading, variant pause) lives next to each binding's usage
cache and is written the same owner-only, atomic way. The active-session scan
lists a session only while its activity advances, so each sighting is saved
when seen, even on passes that serve the stored reading.

### Per-section ages

A 15 min slot is not a promise that every credit section is newly observed
every 15 min; usage windows are fresh on either read. Each credit balance is
labelled Fresh or Stale from its own read time (never from a newer windows or
passive read of the same binding), with these bounds for a binding whose slot
gate is G (G = the larger of the default gate and the binding's slot):

| Section | Read by | Fresh while its own read is at most |
|---|---|---|
| Saved resets | the variant, every other slot | 2 G (~2 h default, 4-6 h idle) |
| Usage credits, credits on | the plain read, every other slot | 2 G |
| Usage credits, credits off | the plain read, due every ~6 h | 6 h + G |
| One-time pools | every full usage body | 2 G |

While active, the variant still runs every other 15 min slot (~30 min), well
inside the 2 G bound. A 24 h variant pause, an open breaker or an auth hold
therefore shows the affected section as Stale, with its original read time
kept. Window freshness and the slot snapshot's state follow the windows only. A
retained slot snapshot reused as fresh has its credit sections relabelled from
their own read times at reuse.

## Section stability

A read that does not carry a section re-sends the binding's last stored section
unchanged through the model's `SectionCache`, with its original `observed_at`
and `grants_observed_at`: the plain read owns usage credits, the variant owns
saved resets, and one-time pools are fresh from every full usage body (both
readings report them). Presence, `grants`, `grants_state` and `status`
therefore do not flip across alternation, a restart (the stored reading is on
disk per binding), or switching between accounts. A section never read is not
sent. Credit balances carry no `updated_at`.

The saved-reset and one-time sections are persisted with the stored reading.
A restart therefore never drops the saved-reset balance before the next
variant read (each disappearance and return would be stored by the backend):
it is re-sent with its original `observed_at`/`grants_observed_at`. The
canonical v2.2 sequence fixture models an in-memory cache that starts cold
after a restart. This adapter's stored reading is on disk per binding, so after
a restart the last observed saved-reset section is still re-sent; every other
step matches the fixture.

## Tests

`claude_credit_pools::tests` covers the $250 pool, expired, percent-only and
refused-codename pools, usage credits off with a reason (and a refused one),
the saved-reset Team, Max, ineligible and readiness-only shapes, field
refusals, section stability, the canonical v2.2 Claude fixtures and sequence,
per-section freshness (directly and through the cache serve path), retained
snapshot freshness during an idle slot, the variant self-check end to end
through the collector (valid; unrecognized; 400/404/422 and windowless 200
keeping the stored reading with no second call; a cedar-only windowless 200
kept over repeated passes with the breaker closed; no stored reading; 24 h
plain-only; no breaker strike; recovery), restart re-send and missing-section fill,
`read-schedule.json` permissions and restart, passive identity matching, and
24 h scheduler days on real 5-min passes (15/60 min slots on the pass grid,
alternation, plain every ~6 h while off, active and idle slots, sleep without
catch-up, continuous passive input never starving saved resets, kill switch).

End-to-end `agent_status` tests drive real collection passes through each way
a pass can skip a caller (identity gates before and after resolution,
resolution failures from conflicting files or a missing credential, an
unresolved default-login identity, a failed settings load, a browser
re-sign-in, a provisional browser target, an unregistered slot, an upkeep-blocked pass
whose refresh grant expired), in the slot
loop and the single-slot path, and prove a body fetched during that pass is
never adopted. Another proves a passive body never displaces a saved-reset
slot, and another that the variant diagnostic reaches the upload, with and
without windows.
