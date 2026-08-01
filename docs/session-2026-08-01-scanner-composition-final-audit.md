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

## Validation

- Full service: 1,205 library tests and 10 binary tests passed; two explicitly
  real-local-data tests remained ignored.
- Full core: 83 tests passed.
- Scanner module: 256 passed; one explicitly real-local-data test remained
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
