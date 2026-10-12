# Honest agent reads after a rejected setup run

Agent reads (`ottto costs`, `sessions`, `context`, `recommendations`,
`provider-impact`, `cloud`) use the short-lived setup-run token. On a `401`
the daemon refreshes that token once with the relay device secret and retries
once. When Ottto no longer accepts the setup run itself, the refresh is rejected
too, but local status kept reporting `setup_run_state: complete` and
`setup_token_state: valid` because both came only from the local connected
flag. Uploads use the separate relay device credential and kept working.

## Behavior

- Each read still makes at most one refresh and one retry. A read that ends in
  a `401` from a local-client endpoint records `SetupRunReadRejected`; the next
  successful read records `SetupRunReadRecovered`. Events are recorded only on
  transition, so repeated failing reads do not grow the event log. Network,
  timeout and other backend failures leave the recorded state unchanged.
- While the rejection is current and the account is connected, canonical health
  reports `setup_run_state: rejected`, `setup_token_state: expired`, and a
  Warning blocker `setup_run_rejected`. Account state and source trust are
  unchanged because uploads still work. Replacing or removing the setup-run
  binding (a new claim, account switch, logout or terminal scan clear) closes
  the rejection, because it described the old run. A read records its outcome
  only if the binding it started with is still current, so a late response
  from a replaced run cannot re-reject the new one. The state is in memory and
  resets on daemon restart until the next read.
- An expired or cancelled setup run maps to one message: uploads continue,
  agent reads stop until the Mac is reconnected from the Ottto Apps page or with
  `ottto setup --claim-code <code>`.
- `--timezone` is hidden from `ottto costs`, `sessions` and `context` help.
  Ottto rejects an explicit `timezone=` query because calendar windows use the
  timezone saved in account settings, so the daemon now refuses a non-blank
  value with `invalid_request` before any network call and never forwards
  `timezone=`. The protocol field stays for wire compatibility.

## Compatibility

No protocol, schema or persisted-format change. The canonical health values used
here already exist in the local health contract. Backend refusal to mint a token
for an expired run is a separate server change; this runtime change does not
depend on it, and with it the rejected refresh is reported the same way.

## Validation

Focused tests cover the status projection, transition-only recording,
recovery, the one-refresh-per-read bound against a backend that rejects both
the read and the refresh, the shared message, timezone refusal for all three
commands, URL builders without `timezone=`, and the frozen CLI help contract.

A concurrency regression drives `ottto costs` on worker threads against a test
backend whose responses are released by the test thread, so ordering comes from
messages, not timing. A late rejection or success of a replaced run cannot mark
or clear the new run; same-binding rejection and recovery still apply; logout
mid-read records nothing; each read makes one request and at most one refresh,
and an in-flight refresh keeps the binding the read started with.
