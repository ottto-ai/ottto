# Claude valid-access continuity — 2026-10-01

An upkeep worker can find already-valid local OAuth metadata after a login or
refresh while foreground collection still gates on the older saved access
deadline. The worker's `NotRequired`/`ReloginApproaching` outcome previously had
no collection-state handoff, so ordinary collection could repeatedly queue the
same expired saved descriptor. A mocked installed-head reproducer established
this independent defect; it does not establish the cause of any live account's
missing windows.

The correction reuses the exact-root local identity verifier, existing
registration/consent/suppression fence, and locked collection merge/write owner.
Only the same registered account/organization and old deadline fence can accept
matching future access metadata. Removal, rebind, changed root/deadline, missing
identity, paused collection, invalid/future clocks, or a changed proof refuses
the handoff. No provider quota check or credential mutation is added.

The accepted write retains unavailable state, saved meters, full-read clocks,
provider-check diagnostics, and account profile. Its new observation clock is a
real local identity completion, not a provider read or upkeep command attempt.
Only a changed durable write requests the existing ordinary collection refresh;
collection retains ownership of subsequent quota success/failure.

Validation: four new synchronous mocked reconciliation fixtures, thirteen
existing upkeep identity/consent/preclaim/backoff guards, and the existing
timestamp/collection merge fixture pass. Targeted service clippy uses CI's
`--all-targets --locked -- -D warnings`; format and diff checks pass. Tests do not
invoke the detached production queue or provider/auth processes. Held support-
directory fence work remains separate and is not adopted here.
