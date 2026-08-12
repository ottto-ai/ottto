# Claude quota access witness

Date: 2026-08-12

## Outcome

The agent-status account contract now carries an optional, backend-safe
`claude_quota_access_state` for exact Claude Code slots. The compact enum reports
`full`, `partial`, `temporarily_unavailable`, `reconnect_required`, `paused`, or
`attention_required`. Claude snapshots also advertise the
`claude_quota_access_state_v1` capability so consumers can distinguish an old
producer from an upgraded producer that intentionally omitted state.

When an exact default or registered custom slot cannot return meters but its
previously verified account and organization hashes remain available,
collection emits one meterless degraded snapshot for that identity. A healthy
snapshot for the same account suppresses the degraded duplicate; multiple
failed slots for one account collapse deterministically to the most actionable
state. Recovery replaces the degraded current row with the normal full or
partial snapshot.

## Safety properties

- The wire carries no config path, slot id, Keychain service, credential
  deadline, token, token fingerprint, or local slot diagnostic payload.
- A degraded witness requires both the exact account hash and organization
  hash. Missing or weak identity remains absent rather than guessed.
- `concurrent_mutation` is temporary because the collector retries from stable
  state. `reconnect_required` is emitted only for conclusive `needs_login`
  evidence with retained strong identity. Credential-unreadable and other
  ambiguous credential failures remain `attention_required`.
- Degraded witnesses contain no quota windows, credit balances, or plan
  observations. Slot health therefore cannot become subscription-plan evidence.
- The field is additive and omitted by older producers. Backend schema support
  must land before a public daemon release carries this contract.

## Validation

Targeted protocol and service tests cover serialization/redaction, full and
partial projection, fail-closed identity matching, temporary/reconnect mapping,
meterless degraded output, plan-observation isolation, duplicate suppression,
and the capability marker. The public export and formatting gates remain part
of PR validation.
