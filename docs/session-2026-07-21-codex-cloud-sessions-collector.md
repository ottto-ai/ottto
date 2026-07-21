# Codex Cloud Sessions Collector

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
- Added the content-free `cloud_session_observations.v1` wire and typed deferred
  transport interface. The backend endpoint is intentionally not guessed; this
  public build does not register a poller or construct a Codex runner until a
  future private transport implementation attaches without changing parsing,
  grants, checkpoints, or privacy boundaries.
- Added the operator/UI-safe `ottto-service cloud-sessions-status --json`
  contract. It reports `transport_deferred` and
  `provider_cli_invocation_permitted: false` without constructing or invoking a
  Codex runner, so setup cannot be mistaken for active provider collection.
- The Codex subprocess receives a restricted allowlisted environment and null
  stdin. Provider API keys are neither inherited nor recovered from an
  interactive shell.

Validation: `cargo test -p ottto-service cloud_sessions --lib` exercises twelve
focused tests covering content leak prevention, idempotency/no-op,
disabled/revoked grants, the revoke-before-send race, deferred-transport
no-call behavior, pagination/cursor persistence, and circuit breaking. Local
load evidence is an in-memory 60-task, three-page fixture under the hard
item/page caps; it completes below one second and never stores its cursors. A
repeated semantic digest writes no second payload.
