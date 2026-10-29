# Large-record restore review repairs — 2026-10-29

A successful exact replacement receipt now clears the corruption-rebuild latch
at delayed reconciliation as well as immediate write success. A negative or
unresolved outcome keeps custody and cannot grant a second rebuild. Store
regressions cover ambiguous rename, delayed receipt, a clean offer and the next
changed offer, preserving the one actual rebuild count. The old write-failure
fixture now distinguishes pending custody from terminal non-replacement and
asserts the exact offered digest/generation, surviving bytes and bounded actual
reconciliation failures before disabled-store recovery.

Every retained member-start, read-only settlement and final Full classifier
probe reserves active input credit before taking the store lock. A preflight
lease that already ended is insufficient. Missing settlement credit aborts the
unaccepted collection with a retryable local refusal; it cannot silently discard
a recovered deadline and publish. Settlement does not reconcile pending state,
grant a corruption rebuild or count a Full start merely to obtain funding.

The existing certificate metadata edits and bounded head/boundary checks now
precede typed decode and deterministic unfunded rederive refusals. A strict
record bound to the accepted entry can establish a real equal-size edit or
shrink before the accepted extent floor hides it. Future accepted revisions and
unproven originals retain the floor. These are existing native edit checks,
not a new resource or mtime-only replay allowance. Native production-scanner
controls use a content-bearing v1 record, RAM loss and no seeded sampled debt,
then check one changed body and quiet behavior through retirement and restart.

Resource growth Full and exhausted-retail recovery share the same source/key
wall-clock map, with six-hour expiry, backwards/implausible-time expiry toward
reading and oldest eviction with a separate capacity alarm. The spend map is
never evicted or refunded. Independent native Full planning before consulting
the retail allowance remains a prerequisite integration with the Claude restore
component; this repair does not implement another planner or pace map.

Generic growth discovery, including bounded index-driven rescue from old
directories, remains owned by the separate discovery change and must join via
main. The partial copied growth age exemption is removed here; the local
shorter-extent/future-revision correctness-floor rescue remains. The isolated
retail fixture now keeps growth inside the window and does not claim to prove
the old-directory dependency. Oversize and census-retirement qualifications
remain separate owner gates; no source cap or persisted format changes.

Validation uses package-scoped Clippy with Rust 1.95.0, all targets, locked
inputs and warnings as errors. Test targets compile; tests remain CI-only.
No PR, CI dispatch, release or production action belongs to this repair.
