# Claude retained-meter collision and Pi policy log cleanup

## Problem

Same-cycle Claude quota collision protection did not compare a current complete
provider reading with an older retained snapshot. An exact copied meter bundle
could therefore survive under a different strong account and organization
binding as stale history.

Pi verification also wrote an expected workspace-policy rejection to the
daemon error log before converting it to the typed
`telemetry_disabled_by_admin` result.

## Change

- Normalize Claude meter payloads independently of account labels, identity
  hashes, observation timestamps, and fresh/stale markers.
- Compare current complete readings with retained stale slot snapshots.
- Quarantine an exact cross-binding match as `identity_mismatch`; remove its
  quota snapshot and completeness flags.
- Keep distinct retained values as legitimate account history.
- Do not emit the expected Pi workspace-policy rejection as an error-log
  failure. The typed verification result remains unchanged.

## Validation

- `cargo fmt --all -- --check`
- focused cross-binding collision regression
- focused Pi admin-disabled verification regression
- `cargo check -p ottto-service`
- full `cargo test -p ottto-service` (`1,786` tests passed, `4` ignored)

No release was cut from this session.
