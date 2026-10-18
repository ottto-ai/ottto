# Codex compressed rollout input seam

Codex can store a finished rollout as `.jsonl.zst`. This change adds the
bounded decoder and the single opened-input type the native JSONL parser reads
from. Discovery still enumerates only `.jsonl`, so production behavior is
unchanged: no compressed file is opened, decoded or uploaded yet.

Every parser input is now one `OpenedInput`. The plain variant is exactly the
previous `BufReader::new(file)`, with the same buffer capacity and heap charge.
`OwnedJsonlParser::new(file, ..)` keeps its signature and wraps the file as
plain input; `new_opened` is the one constructor for either kind. The type keeps
the `get_ref`/`get_mut`/`buffer`/`capacity` calls that existing callers make on
`BufReader<File>`. `get_ref`/`get_mut` return the original opened `File`, so
identity revalidation never reopens a path.

The compressed variant streams through zstd and feeds the same
`BoundedJsonlReader` line parser. It is bounded and fails closed:

- A caller must prepay `compressed_input_credit()` before construction: decoder
  heap (twice zstd's streaming bound for an 8 MiB window, plus the input
  buffer), the boxed reader and its decoded buffer. The heap charge is that
  full credit, not the decoder's current size. A decoder that grows past its
  credit fails the read.
- Frames that need a window over 8 MiB, corrupt or legacy frames, trailing
  bytes, a truncated last frame and an empty file all fail. Concatenated frames
  are supported. EOF succeeds only at a frame end.
- `decoded_limit` is a sticky per-file cap on decoded bytes. Content beyond it
  fails the read instead of ending as a shorter complete body.
- Any failure is sticky, so the reader records a failure and the parser cannot
  finalize. No whole file is buffered in memory.
- Checkpoints, samples and resume offsets are physical-file bytes. A compressed
  stream has none, so `prepare_acquisition` refuses compressed input. Callers
  must not seek its `File` before the decoder reaches EOF.

Not in this change, and needed before any compressed rollout is collected:
`.jsonl.zst` discovery, header decoding for the join inventory, plain and
compressed twin identity (logical identity is kept only after a complete decode
proves the full decoded bytes equal the earlier plain extent), compressed
handling of protected-missing join members, and paying the decoder credit at
each open site. Until then, no `.zst` group is recovered.

Tests cover exact-limit and multi-frame decoding, every refusal above, the
prepaid credit, parse parity against the plain parser for the same synthetic
Codex rollout, refusal of acquisition, and that an over-limit stream never
finalizes.
