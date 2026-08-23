# W3 multi-anchor Claude account continuity

Date: 2026-08-23

## Outcome

The daemon now treats every strongly identified Claude subscription as the
composite of its account and organization hashes. Any number of personal or
team subscriptions, up to the existing ten-slot machine limit, can retain a
separate registered anchor while the replaceable default Claude Code login
switches between them.

Meter authority is independent from anchor durability and health. The best
coherent bundle wins by freshness and completeness, while a registered anchor
continues to report whether it is healthy, paused, temporarily unavailable, or
requires official Claude Code login. Default-slot shadowing is an additive
relationship field and does not change the legacy collection-state enum.

## Compatibility and setup

- Existing Claude account status and legacy mutations remain protocol v18.
- Daemon-selected, opaque-target prepare and reconnect mutations use
  command-scoped protocol v19.
- Internal settings migrate explicitly from schema v1 to v2 and reject an
  unsafe downgrade or multiple nonterminal setup/reconnect operations.
- Target-bound operations persist and verify both account and organization;
  replay remains idempotent after the target becomes anchored.
- Legacy v18 setup with an expected account derives exactly one current strong
  organization binding and rejects missing or ambiguous identity.
- Capacity and ambiguous identity are separate setup blockers.

## Collection and upkeep

OAuth usage cache files, locks, attempt admission, circuit breakers, and
cadence jitter are keyed by the same composite strong binding. Account-only
evidence is attached only when exactly one organization is possible.

Registered-slot upkeep is queued and coalesced outside snapshot and settings
locks. Collection reads persisted safe deadlines, while the background worker
owns credential metadata reads and the official non-inference `claude doctor`
command. Each successful slot schedules normal collection/upload immediately.
The last exact coherent bundle can remain visible as stale for at most 24
hours, without overwriting a newer current read.

## Guardrails

No raw OAuth refresh, Keychain write, automated `/login`, inference prompt,
Desktop-state decryption, token output, or secret-bearing transition record was
added. The bounded local transition ledger contains only opaque slot ids,
timestamps, and typed events.

## Validation

- `cargo check --workspace`
- `cargo test -p ottto-protocol` (51 passed, 1 ignored)
- `cargo test -p ottto-core` (109 passed)
- `cargo test -p ottto-cli` (80 passed)
- `cargo test -p ottto-service` (1,464 passed across library and binary, 2
  ignored)
- Focused regressions cover five accounts with default switching, two
  organizations under one account, cache/breaker/admission isolation,
  same-account wrong-organization setup rejection, default meter authority
  with broken-anchor health, bounded secret-free transitions, setup replay,
  migration invariants, stale continuity, and five due anchors without blocking
  collection or settings.
