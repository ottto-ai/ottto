# Setup-claim credential continuity

**Date:** 2026-08-01 · **Change:** `crates/ottto-core/src/account_store.rs`
and `crates/ottto-service/src/control.rs`

## Problem

An existing local installation included its relay-device identifier and sources
when completing a setup claim, but did not present the established relay-device
secret. The backend therefore could not prove that the claimant controlled the
predecessor credential before preparing a replacement generation.

## Authority boundary

Setup-claim completion now loads the active device binding and relay-device
secret from their established file and Keychain authorities. When both exist,
the request sends the device identifier, sources, prior-device secret, and
`prior_device_credential_v1` capability as one continuity proof. A first-device
claim omits all prior-credential proof fields.

An existing device without a readable, non-empty Keychain secret fails closed
before network I/O. Backend rejection leaves the active device and secret
unchanged and leaves the setup claim resumable. Request payloads are never
logged; backend excerpts continue through the shared recursive secret
redactor.

The identity-mutation reservation remains held across the HTTP operation, but
the filesystem/Keychain lifecycle mutex does not. The client snapshots local
authority under the mutex before the request and revalidates the account,
device binding, sources, and a constant-work secret commitment immediately
after the response. Normal local writers are blocked by the reservation;
out-of-band Keychain changes fail before journaling.

## Crash and retry binding

The existing v2 pending-credential journal now records an additive non-secret
request-authority object. It binds the preparation to:

- flow and deterministic idempotency key;
- machine, installation, hardware, and account scope;
- identity-continuity capability;
- prior device identifier and sources;
- SHA-256 commitment of the prior Keychain secret.

The candidate secret remains in its dedicated pending Keychain account, with
only its existing SHA-256 commitment in the journal. Same-preparation retries
must reproduce the entire immutable journal, including request authority,
candidate generation, target binding, and claim commit. Confirmation receipts
for newly authority-bound rotations must name the exact journaled predecessor.
Older v2 journals without the additive request-authority object remain
recoverable.

## Validation

- Existing-device request contract and exact retry body: passed.
- First-device omission, missing proof, backend rejection, and in-flight
  Keychain mutation tests: passed.
- Same-preparation request-authority and candidate-rebinding tests: passed.
- Confirmation predecessor and generation tests: passed.
- Restart promotion, pending-status, and pruned-404 recovery tests: passed.
- Runtime workspace tests: 1,372 passed, 3 ignored, 0 failed.
- Connector workspace tests: 19 passed, 0 failed; the 14-test connector
  package gate also passed independently.
- Root and connector formatting and clippy gates: passed.
