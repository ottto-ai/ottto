# Consented Claude upkeep could never pass its own registration check

2026-09-12. Durable Claude Code connections on a healthy Mac stopped reporting
limits roughly a day after each slot's access token expired, while every
refresh grant behind them stayed valid for another month. The accounts panel
said "one background upkeep attempt in progress" and never moved.

## What was wrong

`ProductionFinalSpawnGate::start_if_allowed` answered "is this slot still
registered?" by comparing whole `ClaudeConfigSlotDescriptorV1` values:

```rust
.any(|current| current == descriptor)
```

The descriptor carries `collection`, which is collector-owned. The settings
registry builds its descriptors straight from the persisted registration
(`slot_id`, `ownership`, `config_dir`, `service_name`) and leaves `collection`
default, while the caller's copy has been through
`annotate_claude_accounts_status` and carries live expiry, quota, and upkeep
state. The two are never equal for a slot that has ever collected, so the gate
returned `NeedsLogin` for every registered account, every time.

That answer is treated as a concurrent removal, so the attempt's own witness is
pruned. The next status request finds no witness, reports `InProgress`, and
enqueues another attempt that fails the same way. `NeedsLogin` is a neutral
result, so `consecutive_failures` stays at `0` and the backoff never grows.
The loop is stable and silent: `claude-background-upkeep-state.json` holds
`{"slots": {}}` and is rewritten every pass.

Downstream, the access token stays expired, the usage read collects 401s, and
the OAuth usage breaker opens for its full 24-hour cool-down.

The production gate had no test. `FixedFinalSpawnGate`, the double every
existing upkeep test uses, has no registration check at all, so the predicate
that decided every refresh was never exercised.

## The change

- `slot_is_still_registered` compares registration identity only, at both the
  spawn gate and the pre-claim publication path.
- A `Refreshed` upkeep result clears an **auth-class** open breaker for that
  account. The breaker's own rule is that a changed call configuration resets
  it; a replaced credential is exactly that. A response-shape change or a
  sustained 429 is a statement about the endpoint and keeps its cool-down.
- `collector_annotated_descriptor_is_still_a_registered_slot` drives the real
  `ProductionFinalSpawnGate` against a real registry in a temp support dir. It
  fails on `origin/main` at `d7280ad2` with "a registered slot carrying
  collector annotations must reach the doctor spawn", and carries two negative
  controls: an unregistered slot id and a slot id pointing at a different
  config dir both still fail closed.
- `refreshed_credential_clears_only_the_auth_breaker` proves the rate-limited
  breaker survives the same call.

## Scope

Registration identity is what the settings registry owns. Consent, browser-auth
suppression, the network sentinel, and the disabled-upkeep file are unchanged
and still gate every spawn. No credential material, provider login, or MFA
behaviour is touched.
