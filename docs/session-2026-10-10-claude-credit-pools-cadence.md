# Claude one-time credits, saved resets and read cadence

The Claude usage reader now maps three credit kinds through the shared daemon
credit model (`quota_credit_model`), with the provider field names kept in one
adapter module, `agent_status/claude_credit_pools.rs`.

## Credits

- **Usage credits** keep their name (`Usage credits`) and gain
  `kind: usage_credits`. When credits are off, the provider's
  `spend.disabled_reason` (or `extra_usage.disabled_reason`) is sent as
  `disabled_reason` when it is a reason code (`^[a-z0-9_.-]{1,64}$`), such as
  `out_of_credits`; any other text is dropped. The `extra_usage` fallback still
  reads bare numbers as dollars. Real bodies show those numbers are minor
  units, but every observed plain body carries `spend`, which wins, so the
  fallback is latent and left unchanged with a code comment.
- **One-time dollar pools.** Every top-level object of the plain body with a
  numeric `limit_dollars` (window keys excluded) becomes a
  `one_time_credit` balance: `limit_id` = the provider codename, amounts in
  cents from `*_dollars`, `expires_at` = the pool's `resets_at` (an expiry, not
  a cycle), `title` = `label` when present, `enabled` absent. Null pools, pools
  whose expiry passed before the read, and the percent-only `cinder_cove` are
  skipped.
- **Saved resets.** `cedar_ember` maps to one `reset_bank` balance
  (`unit: resets`, `kind: saved_resets`) whose grants, `grants_state`,
  `grant_count`, `remaining` and expiry summary come from the model. Readiness
  is passed through as the provider states it: `eligible`,
  `ineligible_reason`, `at_limit`, `cooldown_until`, and grant `usable_now`.
  Invalid values are refused field by field and never change the list state.

`cedar_ember` is only populated by the saved-reset read variant
(`?cedar_ember=1&skip_spend=1`), which is enabled and self-checks every
response. A `cedar_ember` object with a `grants` array or a boolean `eligible`
status is used normally. Anything else on a 200 response (missing, null,
another shape, or a body with no windows at all) adds the code-only diagnostic
`claude_saved_reset_variant_unrecognized`, sends no saved-reset balance from
that read (the last observed section is re-sent; never an `unknown` stand-in),
and pauses the variant for that binding for 24 h, so every slot reads plain.
The pause is separate variant state, never a strike on the endpoint breaker.
After 24 h the variant is read and checked again. Variant HTTP errors follow
the existing backoff; a variant 429 counts toward the shared rate-limit
breaker, as it is the same endpoint.

## Read cadence

One OAuth usage read per account binding per slot; no new endpoint and no
extra calls:

- the slot is 15 min while the account had Claude session activity (from the
  daemon's active-session scan, exact account and organization) in the last
  30 min, the existing 55-65 min gate by default, and 2-3 h once the account
  has been idle more than 6 h (also spread deterministically per account);
- with the variant enabled, due slots alternate the plain and saved-reset
  reads; while usage credits are off, the plain read runs about every 6 h and
  the other slots take the variant;
- if Claude Code's own `.claude.json` `cachedUsageUtilization` for the same
  account (its `accountUuid` and the config's `oauthAccount` account and
  organization match the binding) is newer than the stored reading and inside
  the slot, it is parsed by the same plain-body parser and used without a
  call. The cached body has no organization, so it is adopted only when it
  was fetched inside a continuous run of collection passes (every ~5 min,
  gaps up to 15 min) that all found that caller signed in to exactly this
  account and organization. Another binding, a longer gap, a restart, a clock
  going backwards, or a registered slot's identity gate refusing the slot
  (another account or organization signed in) ends the run, and a run never
  adopts a body fetched before it began;
- the existing 5-minute post-success spacing, Retry-After handling, breaker and
  per-caller auth backoff are unchanged;
- `CLAUDE_ACTIVITY_CADENCE_ENABLED` is a kill switch (default on): off, every
  binding uses today's 55-65 min gate with no active boost or idle slowdown.

Cadence state (`read-schedule.json`: last plain and variant reads, last
activity, first reading, variant pause) lives next to each binding's usage
cache and is written the same owner-only, atomic way.
The active-session scan lists a session only while its activity advances, so
each sighting is saved when seen, even on passes that serve the stored
reading.
A stored reading is labelled stale only after the larger of the default gate
and the binding's slot.

## Section stability

A read that does not carry a section re-sends the binding's last stored section
unchanged through the model's `SectionCache`, with its original `observed_at`
and `grants_observed_at`: the plain read owns usage credits and one-time pools,
and the variant owns saved resets. Presence, `grants`, `grants_state` and
`status` therefore do not flip across alternation, a restart (the stored
reading is on disk per binding), or switching between accounts. A section never
read is not sent. Claude balances still carry no `updated_at`.

The canonical v2.2 sequence fixture models an in-memory cache that starts cold
after a restart. This adapter's stored reading is on disk per binding, so after
a restart the last observed saved-reset section is still re-sent; every other
step matches the fixture.

## Tests

`claude_credit_pools::tests` covers the $250 pool, expired and percent-only
pools, usage credits off with a reason, the saved-reset Team, Max and
ineligible shapes, field refusals, section stability, the canonical v2.2
Claude fixtures and sequence, the variant self-check (valid, unrecognized,
24 h plain-only, no breaker strike, recovery) end to end through the
collector, `read-schedule.json` permissions and restart, passive identity
matching, and a simulated 24 h day for the scheduler (slot spacing,
alternation, plain every ~6 h while off, active and idle slots, passive input,
kill switch). `agent_status::tests::failed_slot_gate_never_lets_a_passive_reading_through`
drives a registered slot through a refused identity gate and proves a body
fetched meanwhile is never adopted.
