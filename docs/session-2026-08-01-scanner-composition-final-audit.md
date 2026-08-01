# Scanner composition final audit

Date: 2026-08-01

## Scope

Independent adversarial review of the composed local snapshot scanner and
credential-continuity changes. Review covered bounded discovery and exact
opens, semantic identity and deduplication, durable progress and audit state,
resumable acknowledgement handling, manifests and cache withdrawal, restart
and concurrent-daemon behavior, title-less Claude account sidecars, Pi current
transcripts, terminal/incomplete/disabled results, and file-only test secrets.

Only synthetic repository fixtures were exercised. No live daemon, Keychain,
local transcript tree, or production progress state was read or mutated.

## Repairs

- Compact JSON redaction now applies inline secret detection inside
  non-sensitive string fields after key-based redaction.
- Restart recovery retains an expired, pruned credential candidate after a
  generic forbidden probe; only an unambiguous unauthorized response retires
  that fallback candidate.
- Pi compatibility deduplication rejects unmatched divergent cross-shape reuse
  after exact pairs while retaining repeated identical same-shape billable
  occurrences.
- Offline snapshot audit runs now finalize post-policy semantic fingerprints
  and activity witnesses before persisting their dedicated scan index.

Each repair has a focused regression test.

## Independent post-fix review

An independent strict review rechecked exact clean source HEAD
`7d155edb5c947610097df65c8e8023bb93055609` against base
`36c44c9dc71f4b6c4834a358c03d68640afce31a`. It found and repaired three
additional state-machine gaps:

- A due quarantined snapshot retry could be reparsed and then suppressed as a
  semantic no-op, preventing the required retry upload. Due quarantine entries
  now bypass semantic no-op suppression.
- An abandoned, unconfirmed account-switch preparation could survive claim
  cancellation or restart and block a distinct new claim. Starting a fresh
  claim now invalidates only a current-schema claim-backed preparation that has
  neither confirmation authority nor passed preconfirmation guards; active or
  ambiguous recovery states still fail closed.
- Logout ignored failure to invalidate the pending credential recovery journal
  before clearing the active identity. Journal invalidation is now required
  inside the identity lifecycle lock before active account and device files are
  reset.

Each gap has a direct regression test. The single focused verification pass
accepted all three findings and reported no accepted or actionable findings.

## Validation

- Full service: 1,208 library tests and 10 binary tests passed; two explicitly
  real-local-data tests remained ignored.
- Full core: 83 tests passed.
- Scanner module: 257 passed; one explicitly real-local-data test remained
  ignored. Snapshot-audit module: 8 passed.
- Workspace all-target Clippy with warnings denied and `cargo fmt --check`
  passed.
- Every service test and Clippy invocation used a fresh explicit file-only
  secret directory and proved it remained empty.
- Public export, manifest, contract, and secret-history gates passed after the
  generated export manifest was refreshed.

The strict discovery review found four actionable issues. Its single focused
verification pass accepted three repairs and caught one over-broad Pi edge;
the narrowed implementation and its direct regression were then verified by
the focused and full test suites.
