# Codex Cloud Sessions Collector

> Historical foundation note. Daily complete-snapshot semantics and the newer
> 200-observation/five-minute bounds are documented in
> `session-2026-07-22-cloud-session-complete-snapshots.md`.

Implemented the supported public-runtime slice for Cloud Sessions Observability.

- Added the explicit-setup `codex:cloud_sessions` connector. It uses only the
  official `codex cloud list --json` surface as the effective user; no auth-file,
  Keychain, WHAM, browser, or private-endpoint access is present.
- Added a separate five-minute, bounded-jitter service job outside snapshot sync.
  It caps work at three pages, 60 items, 45 seconds, and 12 seconds per CLI
  process; pagination cursors remain memory-only. The job uses a runtime kill
  switch, semantic no-op digest, persistent local checkpoint, exponential
  backoff, and circuit breaker.
- Added local versioned grant storage with immediate pause/revoke APIs. Raw
  installation scope is discarded after deriving an HMAC installation
  fingerprint and immutable grant-scope id; no provider credentials are read or
  stored. State uses a private 0700 directory and randomized, exclusive 0600
  atomic writes. Earlier v1 files migrate on first read without losing
  pause/revoke control. Revocation is rechecked before transport.
- Grant creation now persists a privacy-safe exact-scope tombstone and returns
  the same idempotent request after timeout or restart until the grant UUID is
  bound. A single backend-list absence cannot clear the tombstone. Every
  provider cycle also requires a fresh bounded backend grant-list response with
  strict server policy approval before the Codex process can start.
- Added the initial content-free `cloud_session_observations.v1` boundary and
  typed deferred transport interface. A follow-up alignment supplies the exact
  server-owned grant epoch, nested health, strict observation fields, and relay
  adapter; public startup remains deferred until its separate activation gates.
- Added the operator/UI-safe `ottto-service cloud-sessions-status --json`
  contract. It reports `transport_deferred` and
  `provider_cli_invocation_permitted: false` without constructing or invoking a
  Codex runner, so setup cannot be mistaken for active provider collection.
- The Codex subprocess receives a restricted allowlisted environment and null
  stdin. Provider API keys are neither inherited nor recovered from an
  interactive shell.

Validation: `cargo test -p ottto-service cloud_sessions --lib` passes 29
focused tests covering content leak prevention, idempotency/no-op, ambiguous
create/restart/late-response races, strict policy parsing and transitions,
backend-error fail-closed behavior, invalid required provider identity/status
rows, strict coarse backend health mapping,
disabled/revoked grants, the revoke-before-send race, deferred-transport
no-call behavior, pagination/cursor persistence, and circuit breaking. Local
load evidence is an in-memory 60-task, three-page fixture under the hard
item/page caps; it completes below one second and never stores its cursors. A
repeated semantic digest writes no second payload.
