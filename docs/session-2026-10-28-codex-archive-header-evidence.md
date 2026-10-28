# Codex archive header evidence

Archive inventory shares a stamp-bound first-record projection with acquisition:
owner, logical rollout id, SHA256 digest, header timestamp and optional client
version (at most 64 printable ASCII bytes). A distinct `HeaderValidated`
disposition grants no acquisition, money, checkpoint, census or ACK authority.

Inventory performs one paid header decode per unchanged stamp with an 8 KiB
output buffer. The retained first record is capped at 64 KiB, physical input at
128 KiB including read-ahead. Decoding may pass the newline; actual decoded
bytes and thread CPU are measured.
It closes the singleton decoder before returning. The projection survives full
acquisition deferral or failure and ordinary failure checkpoints. Full acquisition
still takes its own paid decoder through the existing stateful main parser.

Dependency witnesses and membership checks reuse metadata before decoding.
Compressed group/proof/physical-offset readers retain their explicit refusals;
the projection never invents group ordinal, history-base or fork evidence.
The public compatibility parser remains plain-only with the permanent counted
`CompressedCompatibilityUnsupported` refusal. Repository searches found only
test callers of that API; the main scan uses `new_source_parser`.

The inventory counters use S2's partial inventory purpose. Physical input is
reported separately from decoded bytes and belongs outside Full/body totals.
Inventory emits no Full/encoding row. Physical bytes charge the inventory
bound, decoded bytes charge E2-4, and HeaderWork exposes CPU and a fail-closed
AC/utility permission seam for 11b-1's shared catch-up pacing.

A rejected archive is a counted held member without globally holding other
owners. The full read captures first lines through the JSONL line cap, including
headers larger than the inventory bound. Effects are validation/selection effects;
there is no money formula change. Identity requires payload.id and a filename
candidate; double-UUID archives outside that set remain named OwnerUnproven holds.
This is not universal archive coverage.

Validation for this prerequisite slice is explicit-file formatting, whitespace
checks and strict code review. CI waits for the predecessor slice to merge;
Linux then precedes macOS contracts and money-equivalence at the exact head.

Failed archive filename owners also block paused singleton and group cursor revalidation. A paused reader cannot publish a partial owner body while an excluded archive leaves that owner's membership unresolved; unrelated owners retain a complete inventory.
