# Cloud-session relay runtime composition

Implemented the final public daemon composition boundary for the experimental
Codex Cloud Sessions collector. This change does not publish a release or
change a release version. Default-off means no local grant and no matching
server approval, rather than a process environment gate.

## Activation boundary

The daemon starts exactly one collector supervisor normally. The independent
`OTTTO_CODEX_CLOUD_SESSIONS_DISABLED=1` emergency switch wins on every cycle.
Without a locally eligible grant, each five-minute cycle performs one local
grant-file existence/read check and no account, device, connection, Keychain,
provider, relay, or checkpoint work. It writes no state. Adding consent and
server approval activates the same supervisor on its next cycle without daemon
restart or environment surgery.

An enabled process still needs all of the following before a relay transport is
retained:

- a locally enabled or policy-disabled grant bound to the compiled collector
  version and a reconciled backend UUID/version;
- HMAC-exact matches for the current relay device, connected organization, and
  connected user;
- a Codex-enabled relay device whose machine binding exactly matches the local
  backend connection;
- a trusted production destination, or an exact process-owned loopback
  developer override;
- the same device binding when relay credentials are reloaded from Keychain.

Only then is a candidate relay built. It must pass a bounded exact backend grant
UUID/version authority read before the daemon retains it as the active runtime
transport. The device secret is never logged or persisted by this collector.
Browser JWTs remain confined to the local control flow and never enter transport
composition. Authority revalidation still runs before the first provider call
and before every later provider page, chunk, finalize, or heartbeat boundary.

## Load and rollback behavior

The established five-minute supervisor cycle plus at most 20 seconds of jitter
is unchanged. The active transport and relay token are reused while the exact
runtime binding and an in-memory digest of the Keychain secret remain unchanged.
A missing, disabled, paused, revoked, mismatched, or malformed local binding
drops the transport and performs no provider or backend call. The no-grant
default-off path writes no grant or checkpoint state. Existing 12-second
command, 45-second cycle, 2,000-entity,
100-page, ten-chunk, daily full-scan, hourly heartbeat, semantic no-op, and
circuit-breaker limits remain unchanged.

The extra activation authority read occurs only when a transport is first
created or its exact identity/credential key changes; it is not added to steady
state polling. A failed activation participates in the existing bounded circuit
backoff. Failure count, deadline, and circuit-owned error category are scoped to
the exact backend grant epoch, so later consent never inherits an older grant's
delay or elevated failure count. Resetting that circuit preserves the separate
`scan_incomplete` health marker.

Disabling, pausing, revoking, or replacing an active transport clears the
process-memory scan and its receipt state before a later resume. Status commands
derive readiness from the same exact local bindings and credential availability
instead of relying on process-local activation state, so standalone CLI and
daemon control responses agree without adding a status heartbeat or database
write.

Pause and revoke close the process-shared collector-I/O admission fence, wait
boundedly for every already admitted Codex subprocess or relay write, and only
then return the exact backend deletion target. Failed composition or authority
validation does not rewrite grant identity, advance a scan, or authorize
absence.

## Validation

- `cargo test -p ottto-service cloud_sessions --lib`: 71 passed.
- `cargo test -p ottto-protocol`: 36 passed, one pre-existing ignored.
- `cargo test -p ottto-service`: 850 passed across library and binary, one
  pre-existing ignored.
- `cargo clippy -p ottto-service --all-targets -- -D warnings`: passed.
- Public export and manifest integrity checks: passed with zero rewrites.
- First-party connector package contract test: passed.
- Focused additions cover no-grant zero-touch/no-write behavior, activation of
  the same dormant supervisor after later consent, fresh circuit ownership for
  new grant epochs, preservation of incomplete-scan health, exact local identity
  binding, paused scan cleanup, untrusted destination rejection, and immutable
  grant rollback on composition failure. A concurrent startup test proves only
  one process-local supervisor can own the polling loop.
- Existing coverage continues to prove authority-before-provider ordering,
  bounded scan/chunk/finalize behavior, response-loss retries, no-op cadence,
  concurrent stop fencing, and revoke-before-delete behavior.
- Strict local AutoReview and its focused correction passes found seven
  actionable lifecycle, status, documentation, and grant-epoch circuit issues.
  All were fixed; the final focused verification rerun reported no
  accepted/actionable findings with 0.96 confidence.
