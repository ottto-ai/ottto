# A transient Claude read failure is not a connection that needs attention

2026-09-14, observed on stable `0.1.132`.

Sibling of
[session-2026-09-13-duplicate-claude-slot-is-not-attention.md](session-2026-09-13-duplicate-claude-slot-is-not-attention.md).
Same predicate, same symptom, a different family of state.

## What it looked like

One registered Claude slot was `fresh` and serving a full live meter bundle,
every credential was valid with background upkeep up to date, and the macOS
Apps pane still said:

- header: **"Some sources need attention"**, 2 sources
- the Claude Code card: **needs attention**, with a **Verify Claude** button
- source problem: `secret_expired`, "Claude Code durable connections need
  attention - The current login remains available. One or more saved account
  connections need attention; their last verified identities remain separate."

Nothing was expired, mismatched, or waiting on a login. Anthropic's usage
endpoint was temporarily unable to serve one account's slot, which the accounts
panel already reported honestly and without alarm: state `Unavailable`, "Ottto
could not read current limits. No old reading is shown as live usage." The last
reading was kept as history rather than shown as a live meter.

Clicking Verify could not change any of it.

## Cause

`claude_custom_slot_needs_attention` in `collect_claude_status_snapshots`
treated every state except `Fresh`, `Unverified` and `DuplicateAccount` as
something the operator has to act on. That set includes the transient
read-failure states, so a provider-side outage raised a durable-connection
repair warning.

The default slot reached the same warning through a second branch that compared
against `Fresh` directly:

```rust
let default_full_meter_needs_attention = default_has_full_meter_evidence
    && default_state.state != ClaudeConfigSlotCollectionStateV1::Fresh;
```

Both fired here, so correcting only one would have left the warning standing.

## Rule

"Needs attention" is reserved for a repair the operator can actually make in
Ottto. A state qualifies as benign when two independent classifications already
in this crate agree that it is a read failure rather than a repair:

1. `projected_claude_quota_access_state` maps it to `TemporarilyUnavailable`,
   and
2. the approved operator copy for it names no user action.

That intersection is `ProviderUnavailable`, `ProbeFailed`,
`CollectionInProgress` and `RefreshDue` - "Ottto could not read current limits"
and "Staged". The credential is untouched, background upkeep keeps running, and
the failed-verification re-verify backoff clears them unattended.

`ConcurrentMutation`, `StaleAccessToken` and `ReloginApproaching` are also
`TemporarilyUnavailable` but stay actionable: their copy tells the operator to
sign in again, which is a repair. `CapacityExceeded` stays actionable and
unexamined here - it did not occur in this repro and its copy is ambiguous
about whether an operator action exists.

## Fix

Both branches now ask the same named question, and the benign set covers the
duplicate case plus the four transient read failures.

## Tests

`a_transient_claude_read_failure_does_not_need_attention` pins every one of the
seventeen protocol states through an exhaustive `match` with no wildcard, so a
new state fails to compile until someone decides which side it belongs on
rather than silently defaulting to "the operator must act".
`default_slot_transient_read_failure_does_not_need_attention` pins the second
branch, including that it stays silent without full-meter evidence and still
fires for an expired default sign-in.
`a_duplicate_claude_registration_does_not_need_attention` is narrowed to its own
claim; the exhaustive list now lives in one place instead of two that drift.

All three fail on the parent commit.
