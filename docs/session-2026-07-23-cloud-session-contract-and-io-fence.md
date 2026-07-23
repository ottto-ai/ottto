# Cloud-session official contract and collector-I/O fence

Release-blocker remediation for the experimental Codex Cloud Sessions relay.
This change does not invoke Codex, access credentials, publish a release, or
change a release version.

## Official upstream contract

`cloud_sessions_control` alone requires local-control protocol v16. Base
status, update, socket/XPC, release-manifest, and backend protocol reporting
remain v15, preserving mixed-owner upgrade compatibility while making a new
web client fail closed against an old daemon.

The collector now consumes the exact JSON shape emitted by the officially
documented, upstream-experimental `codex cloud list --json` command:

- top-level pagination uses `cursor`;
- tasks use `attempt_total`;
- `ready` and `applied` normalize to `completed`;
- `error` normalizes to `failed`;
- `pending` normalizes to `unknown`, because the upstream CLI combines backend
  pending and in-progress states and cannot distinguish queued from running.

Legacy `next_cursor` and `nextCursor` aliases remain parseable for compatibility,
but a response containing aliases with different values is rejected. Only an
explicit official `cursor: null` proves terminal enumeration. Fieldless
objects, alias-only nulls, and root arrays may retain valid nonempty positive
facts but cannot finalize or authorize absence; empty ambiguous pages fail
closed. Cursor values remain process-memory-only and bounded to 4,096 bytes.
Exact official-shaped tests prove two-page traversal, the 20-item page bound,
truthful status/attempt normalization, content redaction, and that a multi-page
terminal scan is never labeled `single_response` or granted absence authority.

## Shared admission and stop ordering

The former provider-only activity fence is now one process-shared collector-I/O
fence. It admits:

- bounded provider subprocess calls;
- v2 observation chunk writes;
- v2 scan finalization writes;
- v1 empty heartbeats;
- v1 empty failure-health writes.

Every relay write first completes exact backend authority revalidation, then
rechecks the persisted local grant while entering the shared fence. A local
pause or revoke persists stopped state before waiting for the fence. Therefore:

1. a write whose revalidation completed before the stop but which has not been
   admitted observes the stopped grant and cannot start;
2. a write already admitted may finish, but pause/revoke waits for it and cannot
   return while it is active;
3. no provider or relay write can begin after the completed control action.

The fence is process-memory-only, adds one uncontended mutex admission per real
provider or relay operation, and is not touched by the default-off five-minute
path. Admitted relay requests are capped at 12 seconds, strictly below the
15-second local stop wait, while the overall collector cycle remains capped at
45 seconds. No database, checkpoint, or ingestion work was added.

Cloud-session HTTP agents also reject redirects instead of replaying the
long-lived device secret or relay bearer token to a redirect target. Every
response is required to be 2xx before its typed body is parsed. A loopback
regression proves a relay-token 302 with a valid-looking token body is rejected,
reaches only the configured backend listener, and never reaches the redirect
listener.

Deterministic barriers cover revoke after revalidation but before chunk,
finalize, heartbeat, and failure-health admission. A separate blocking transport
test proves revoke waits for an already admitted relay chunk, complementing the
existing provider-subprocess wait coverage.

## Validation

- `cargo test -p ottto-service cloud_sessions --lib`: 85 passed.
- `cargo test -p ottto-service`: 861 library tests passed with one pre-existing
  ignored test; three binary tests passed.
- `cargo test -p ottto-protocol`: 36 passed with one pre-existing ignored test.
- `cargo clippy -p ottto-service --all-targets -- -D warnings`: passed.
- Public manifest, export/no-rewrite, contract, and secret gates: passed.
- Strict local AutoReview found the stale manifest and a relay/stop timeout
  mismatch. Both were accepted and corrected; the final focused verification
  result is recorded in the implementation handoff.
- A final strict branch review found that the new relay-token request could
  inherit ureq's redirect behavior and replay its device-secret header. The
  cloud-session agent now rejects redirects, with targeted regression coverage.

The authenticated status repair also makes ambiguous activation and cleanup
states explicit without provider or pipeline work. Pending create reconciliation
returns the exact persisted create request; locally revoked but backend-active
bindings report `backend_revocation_confirmation_required` until exact delete
confirmation, after which status reports ordinary `revoked`.

The private backend still requires the next immutable collector release version
to be explicitly approved and deployed before demo enrollment. This public
change intentionally does not alter that cross-repository rollout gate.

The connector manifest and generated registry now expose `cloud_sessions`
maturity as `experimental`, matching its disclosure, default-off setup, and the
upstream CLI's own maturity.
