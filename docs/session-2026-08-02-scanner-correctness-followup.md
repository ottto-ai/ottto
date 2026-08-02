# Scanner correctness follow-up

Date: 2026-08-02

## Outcome

A second end-to-end review of the composed local snapshot scanner found and
repaired five independent correctness, liveness, or trust-boundary defects:

- A non-monotonic Codex cumulative counter reset cleared the replacement usage
  buckets but retained the pre-reset session-wide totals. The resulting item
  failed the daemon's exact totals/buckets preflight. The reset now clears both
  representations before accepting the replacement cumulative value.
- A bounded traversal that durably committed only an accepted subset after
  backend shedding could finish its already-advanced cursor and claim a
  complete census. Such a generation now requires one fresh clean traversal
  before completeness or policy-epoch advancement.
- RFC3339 lifecycle and bucket extrema used lexical ordering outside the Pi
  compatibility helper. Fractional seconds and offsets could therefore invert
  first/last activity. All scanner timestamp extrema now use parsed instant
  ordering with the existing deterministic invalid-value fallback.
- The resumable uploader quarantined byte-different items that shared a valid
  semantic fingerprint. That contradicted the identity contract: collection
  time, source-file witness, and parser observation metadata deliberately do
  not mint a new remote entity. Duplicate semantic identities now upload one
  representative; exact daemon preflight still recomputes every representative
  fingerprint before network I/O.
- Setup-run token refresh consulted the pending credential-promotion journal
  before rejecting an attacker-controlled API base, contrary to its documented
  trust order. The untrusted destination is now rejected before any credential
  or journal state is read; a trusted destination remains fenced by an
  incomplete promotion.

## Reproduction and regression coverage

The cumulative-reset regression was reproduced on the pristine pre-fix branch:
the emitted top-level input total remained 120 while the replacement bucket
contained 20, and preflight rejected the item. The new regression proves 20/8/1
replacement totals and successful preflight.

Additional direct tests prove that a partially settled final page cannot publish
completeness until a clean follow-up generation, fractional RFC3339 values retain
chronological lifecycle/bucket extrema, and observation-only duplicate bodies
coalesce without quarantine or poison-loss accounting.

The full parallel service suite exposed the refresh ordering defect because a
concurrent credential test temporarily made a promotion journal visible. The
existing untrusted-base regression now exercises the corrected fail-closed
ordering independently of that local state.

## Independent review boundary

The follow-up review covered scanner discovery/census state, parser accumulation,
semantic fingerprints, upload packing and ACK settlement, partial-shed commits,
manifest authority, restart persistence, credential-promotion admission fencing,
and privacy-sensitive serialization. The composed branch includes public change
`36c44c9dc71f4b6c4834a358c03d68640afce31a`, so every test uses an explicit fresh
file-only `OTTTO_SERVICE_SECRET_FALLBACK_DIR`; no Keychain, daemon, transcript
tree, or production state is read or mutated.

## Validation

- Five focused scanner regressions and the untrusted-refresh regression passed.
- Full service library: 1,218 passed; two explicitly real-local-data tests were
  ignored. Service binaries: 10 passed. Core library: 83 passed.
- Workspace all-target Clippy passed with warnings denied. Formatting and diff
  whitespace checks passed.
- A strict local AutoReview closeout found no accepted or actionable findings
  and classified the patch as correct with 0.93 confidence.
- Every Rust invocation used a fresh explicit file-only secret directory and
  proved it remained empty. Full-suite reruns also used a fresh support directory.

The public export, generated-manifest, repository-skeleton, public-contract, and
current-plus-history secret-scan gates passed after the manifest refresh.
