# Health and Claude quota integrity

## Problem

A historical workspace-policy verification could keep a currently reachable source
and the whole Mac yellow. Claude quota responses also lack provider-owned account
identity, so a stale default-slot binding could attribute another account's complete
meter snapshot to the wrong row.

## Runtime behavior

- `telemetry_disabled_by_admin` remains source history but does not degrade machine
  health.
- A current agent snapshot supersedes policy verification evidence older than 24
  hours.
- Complete Claude meter payloads are compared without Ottto-stamped identity fields.
- An exact payload collision across different strong identities is hidden from the
  mutable default slot when a durable registered slot has the same reading.
- Ambiguous registered-to-registered collisions hide every conflicting reading.
- The affected slot reports identity mismatch and asks the user to reconnect.

This is fail-closed. Ottto does not show a meter under an identity it cannot prove.
