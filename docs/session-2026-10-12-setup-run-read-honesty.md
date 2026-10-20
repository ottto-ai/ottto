# Honest agent reads after a rejected setup run

Agent reads (`ottto costs`, `sessions`, `context`, `recommendations`,
`provider-impact`, `cloud`) use the short-lived setup-run token. On a `401`
the daemon refreshes that token once with the relay device secret and retries
once. When Ottto no longer accepts the setup run, the refresh is refused too,
but local status kept reporting `setup_run_state: complete` and
`setup_token_state: valid` because both came only from the local connected
flag.

Revised 2026-10-20 on top of the expired-run login and refresh backoff work:
the timezone refusal and expired-run messages are already on `main`, so this
change only adds the status writer and the refresh commit.

## Behavior

- Each read still makes at most one refresh and one retry.
- Only an authoritative terminal refresh answer counts: a `401` from
  `/local-client/refresh` with one of the exact backend details that
  `terminal_refresh_rejection` already recognizes. Every read path returns
  that refresh error unchanged, so it is the read's final error.
- A read `401` alone, a `401` on the retry after a successful refresh, a
  refresh `401` with any other detail, and network, timeout or other backend
  failures are not proof. They record nothing and do not clear a recorded
  rejection. A successful read records `SetupRunReadRecovered`.
- Events are recorded only on transition, so repeated failing reads do not
  grow the event log. A different kind of terminal answer is a new transition.
- While the rejection is current and the account is connected, canonical
  health reports:
  - **Ended run** (`Setup run expired` / `Setup run cancelled`):
    `setup_run_state: rejected`, `setup_token_state: expired`, Warning blocker
    `setup_run_rejected`. Account state and source trust are unchanged,
    because uploads use the device credential and keep working.
  - **Refused device credential** (`Telemetry device is not active` / `... secret
    is invalid` / `... not found`): `setup_run_state: unknown`,
    `setup_token_state: refresh_required`, `device_state: inactive`, Warning
    blocker `device_credential_rejected`. The run is not known to be ended, so
    this is never reported as expired. An inactive device untrusts sources the
    same way a rejected upload does.
- The rejection belongs to the binding the read started with. Replacing or
  removing the binding (a new claim, account switch, logout or terminal scan
  clear) closes it. A late outcome from a replaced binding, or one that
  finishes after logout, is dropped. The state is in memory and resets on
  daemon restart until the next read.

## Refresh persistence

A device-secret refresh commits its new setup-run token and connection only if
the persisted binding still belongs to that refresh. The commit runs under the
setup-run binding lock that every other writer of the pair (claim, account
switch, setup attach, terminal clear, logout reset) already holds, so a
reconnect or logout cannot interleave with it.

- The persisted binding may name the refresh's own run or the run the backend
  just rebound to. Only the run id and token expiry change; the persisted
  record keeps its other fields.
- Anything else means the binding was replaced or removed while the refresh
  was in flight. The minted token is dropped, nothing is written, and the
  read fails with the existing mismatch or missing-connection error instead
  of retrying. A refresh that finishes after logout therefore never recreates
  the connection or token.
- If the connection write fails after the token write, the prior token is put
  back (or the new one removed when none could be read), so the stores keep
  the prior binding. The two stores are not written atomically: if that
  rollback also fails, the new token stays beside the prior connection until
  the next refresh.
- The lock is process-wide; only the daemon writes these stores.

## Compatibility

No protocol, schema or persisted-format change. The canonical health values
used here already exist in the local health contract, and blocker codes are
free-form strings.

## Validation

CI runs the tests. Focused tests cover:

- The status projection for both kinds, transition-only recording, recovery,
  and the binding-replacement sites.
- Against a scripted backend: an unrecognized refresh `401`, a `401` retried
  after a successful refresh, and a refresh transport failure record nothing;
  an ended run reports rejected with one read and one refresh per command; a
  refused device credential is not expired; a successful read clears it.
- A concurrency regression drives `ottto costs` on worker threads against a
  backend whose responses the test releases, so ordering comes from messages,
  not timing. A late rejection or success of a replaced run cannot mark or
  clear the new run, and logout mid-read records nothing.
- Refresh persistence: a refresh of run A that finishes after a reconnect to
  run B leaves B untouched and makes no retry; one that finishes after logout
  restores nothing; a same-binding refresh persists the new pair and retries
  with the new token. Commit-step tests with in-memory stores cover a backend
  rebind, a different API base, and token or connection write failures.
