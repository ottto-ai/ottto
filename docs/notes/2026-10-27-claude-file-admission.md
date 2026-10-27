# Claude file admission limit

Claude Code JSONL discovery now admits files up to and including 1,024 MiB.
Pi remains at 256 MiB, Codex at 2 GiB, and the physical line limit remains
16 MiB. Larger files retain the existing oversized/incomplete disclosure.
A shrink below the relevant source threshold requires a successful native read
before new read authority can be recorded.

This interim admission change preserves all Full audits, reproof, rearm,
cache admission and retry behavior. A selected Claude file without a retained
native reduction can still require another Full read. The file limit does not
bound native reduction memory or promise tail-only processing.

The `large_claude_native_memory_and_append` regression creates synthetic
200 MiB and 400 MiB transcripts containing unique usage-bearing responses,
text and tool output. Fresh child processes run native discovery, parsing and
finalization and report lifetime peak RSS and, on macOS, physical footprint.
Fixture generation runs in the parent. The larger case checks cumulative
usage after append and zero native reads after a ctime-only metadata change.
Artifacts are disabled, context curves and default identity capture remain
as configured by the scanner. The receipt does not measure production telemetry
joins, resident cache pressure, uploads or the full daemon baseline, and it
does not establish a resource budget.
