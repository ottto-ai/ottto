# Codex archive header evidence

Archive inventory shares a stamp-bound first-record projection with acquisition:
owner, logical rollout id, SHA256 digest, header timestamp and optional client
version (at most 64 printable ASCII bytes). A distinct `HeaderValidated`
disposition grants no acquisition, money, checkpoint, census or ACK authority.

Inventory performs one paid header decode per unchanged stamp, limited to the
first newline, 64 KiB decoded and 128 KiB physical input including read-ahead.
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
The encoding totals describe the same input; the two views must not be summed.

Validation for this prerequisite slice is explicit-file formatting, whitespace
checks and strict code review. CI waits for the predecessor slice to merge;
Linux then precedes macOS contracts and money-equivalence at the exact head.
