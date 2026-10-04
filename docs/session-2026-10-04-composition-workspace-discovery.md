# Composition workspace discovery

Composition now reads a transcript only until the first cwd that names an
existing directory. It preserves the previous field precedence: top-level
`cwd`, then `payload.cwd`, then `turn_context.payload.cwd`. A missing path,
regular file, or invalid cwd does not prevent checking subsequent records.
Malformed JSON is ignored; a valid final record without a newline is accepted.
The footprint collector still enumerates every cwd candidate.

The composition cycle budget starts before workspace discovery. The reader
checks that deadline while framing records and applies the existing 16-MiB
JSONL record bound. A read error, invalid UTF-8 before resolution, oversized
record, expired budget, or observed source mutation makes discovery incomplete.
Incomplete discovery aborts before composition uploads or cache replacement.
An expired report budget also prevents replacing last-good workspace data.
No new durable state or upload format is introduced.

Opened-file and path metadata are compared after scanning, including length,
modification time and, on Unix, device, inode and change time. This detects
observed append, rewrite, truncation and replacement. It does not lock provider
files or guarantee a snapshot against changes after the final check. Records
past the first existing cwd are intentionally unread; their JSON shape does not
affect discovery. Full composition parsing retains its existing behavior and
50-MiB transcript limit.

Focused native tests cover provider field variants and precedence, vanished
paths and regular files, malformed and unterminated input, bounds, read errors,
metadata mutation, early stopping and incomplete discovery. The opt-in native
measurement test emits only byte counts, timings, peak RSS and parity booleans;
it does not emit transcript text or workspace paths. Release and installed
performance acceptance remain separate from source validation.
