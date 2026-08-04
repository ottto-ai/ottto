# Claude registered-slot reconnect and local meters

## Scope

This follow-up completes two machine-local W3 contracts without changing the
backend agent-status wire or OAuth posture:

- `claude_account_reconnect` begins or replays a persisted observation for one
  explicitly registered custom slot. The operation is immutably bound to the
  opaque slot id, exact stored config-dir string, and last strong account hash.
- Authenticated `claude_accounts_status` returns the full quota values already
  collected for each exact slot: session and weekly windows, model-scoped
  limits, and usage-credit balances, plus captured/observed time and typed
  `fresh`, `stale`, `partial`, or `unavailable` state.
- A live statusLine context sample augments, but no longer downgrades, the
  `cli_json` provenance of full OAuth quota. StatusLine-only quota remains
  explicitly `status_line` and partial.

Both additions remain on command-scoped local-control protocol 18. They are
additive to the existing W3 command family; ordinary local control remains on
protocol 15.

## Reconnect boundary

Reconnect reuses the exact descriptor already in the daemon registry. It never
creates a path, adds a duplicate registration, chooses the default slot, or
accepts an arbitrary command. The response uses the existing single-quoted
daemon-authored launch command. Adversarial tests cover spaces, a single quote,
shell substitutions/metacharacters, a trailing slash, and composed/decomposed
Unicode spellings; executing the returned string through a test shell preserves
the value byte-for-value and cannot run injected text.

After a reconnect reaches a terminal state, the same slot may start another
reconnect while the previous operation id moves into a fixed-size fail-closed
retirement filter. Slot removal does the same. This permits repeated reconnects
without unbounded tombstone growth; an old id cannot be rebound, and a filter
false positive only refuses a new id. The fixed-size owner-only sidecar survives
an older daemon rewriting the additive settings shape. Only one reconnect per
slot can be active.

The customer opens official Claude Code and types `/login`. Ottto does not run
`/login`, enter credentials, start or refresh OAuth, write Keychain, decrypt
Desktop state, or make an inference call. Check and Stop Waiting reuse the
existing single-flight persisted lifecycle. Removal, weak/missing account
bindings, default/unknown slots, account rotation, and registration races fail
closed.

## Local meter boundary

The local values are copied from the exact account-isolated
`AgentStatusSnapshot` that the existing collector already builds. No second
provider read is introduced. Provider/cache `observed_at` stays distinct from
the later local `captured_at`; the wrapper uses the oldest represented
observation so it cannot overstate freshness.

Last-known values may be retained as stale only within the same opaque slot and
only when both strong account and organization hashes still match. Each retained
window and credit balance is marked stale. Identity mismatch, organization
change, sibling slots, and values older than 24 hours never inherit the values.
Malformed or future-dated represented-observation times also fail closed.
Serialized local fixtures
exclude tokens, refresh material, credential blobs, config paths, and Keychain
service names.

## Validation

Focused tests cover protocol-version routing and backwards-compatible decoding,
exact reconnect/no duplicate, stop/restart/replay, removed/default/weak/mismatch
failures, immutable operation-id replay, cross-kind operation ordering, shell
quoting, managed first/repeated reconnects, bounded retirement across repeated
register/remove cycles, parsed observation ordering and poisoned-state recovery,
meter account/org isolation and 24-hour expiry, fresh/stale/partial state,
quota-provenance preservation with live statusLine context, and privacy.
Full workspace, strict clippy, public export/manifest/secret gates, and
autoreview are required before review.
