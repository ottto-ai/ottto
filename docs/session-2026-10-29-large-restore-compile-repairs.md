# Large-record restore compile repairs — 2026-10-29

This follow-up checks the folded integration based on 4d0bb20f0 using Rust
1.95.0 Clippy for ottto-service, all targets, locked dependencies and warnings
as errors. Test targets are compiled; no tests are run locally. No CI workflow,
pull request or release is dispatched by this source repair.

The hold diagnostics retain seven coordinates. The removed UpgradeMissing hold
stays removed: its old coordinate 5 is reserved at zero, and ReceiptPending is
explicitly coordinate 6. Full-array zero assertions retain every old condition
and include the receipt coordinate; held-group/census controls explicitly assert
zero pending receipts, while the pending-receipt fixture asserts one in slot 6
and zero in the retired coordinate. This corrects the integration's compressed
six-coordinate layout without changing acquisition or preservation decisions.

Test-only repairs adapt the existing assertions to the folded APIs: resolve
codex_cursor through its actual module, make the saved index mutable, use funded
receipt guarding and the current carrier-aware hold interface, remove obsolete
private restore/GC allowlist arguments, and inspect all four current pending
obligation fields with the failure counter at tuple index 3. The Q11 writer
fixture already supplied index_length=0 at the folded base; no extra change is
needed there. No fixture outcome or money assertion is weakened.

Production caller repair uses the existing Slot directory for the held writer
lookup instead of a test-only store accessor. Both designate the same store
directory assigned when the Slot is built. Removing an unused import and an
empty line between a doc comment and its method has no runtime effect. The
prior integration's predecessor verification, receipt reconciliation, stored
representation/debt hashing, active funding, N=3 original return bound and
large-Codex refusal semantics remain the contract.

MSRV fixes replace Option::is_none_or with equivalent map_or(true, ...) rather
than raising the declared Rust 1.80 minimum. SessionStart rederive helpers and
the retail pread helper are test-only because their remaining callers are
retained legacy/direct test oracles; funded production rederive integration
must enable helpers it actually calls. Test-style repairs retain refusal checks,
original-box identity, empty-custody and money assertions.

A narrow result_large_err allowance documents the existing lossless inline
refusal carrier. It avoids adding a Box allocation to a path whose funding and
custody semantics must remain unchanged; no warning is globally disabled.

Clippy results and exact frozen-head receipts are recorded in the integration
handoff. Successful Clippy is compile/lint evidence, not executed tests or a
replacement for Linux/native runtime, money, owner or shared-transition gates.
P2, funded rederive and shared transition integration remain separate work.
