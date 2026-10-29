# Claude restore: landed core merge and shared fixture repairs

P2 merges main at `688fdb8939a3d5ae00ee867bcd2c8f8075bbb1ff`, including the
landed v1 durable core (#865), without rebasing or merging P3. Merge resolutions
retain the original-binding mapper, typed stale attribution, shared wall-clock
pace, strict mutation witnesses, clean-generation receipts, and O3 replay state.
The exhaustive index field inventory includes both upstream account-window
retention and O3 replay. Native fixtures retain explicit platform gates;
upstream capture-binding and appended-body restart assertions are preserved.

Two Linux failures from `f60b80da5` have the same fixture causes repaired on P3
at `a807f44a2`. Attribution toggle directions now use independent stores, with
an additional assertion that each seed was written. Binding inequality,
unchanged context/entry/key, Codex independence, zero restores, one read, and
P2's finite `old_binding_no_match` refusal remain required. P3's generic `scope`
label belongs to its classifier; importing that expectation would discard P2's
original-binding contract.

The completed-audit branch of the dropped-envelope-debt fixture authorizes its
loaded predecessor on the same store before replacing it, using the loaded
committed generation. It still requires one actual write, no residual envelope
debt, and an index-matching audit carrier. The prior clean-save branch retains
its exact stored-generation bytes and clean receipt assertions. Neither fix
changes production behavior or relaxes mutation authority.

Validation: pinned local Clippy is required before the frozen push. Tests remain
CI-only; the owner dispatches the next Linux run. Local compilation and review
do not establish runtime or native-platform qualification.
