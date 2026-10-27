# Claude file admission limit

Claude Code JSONL discovery now admits files up to and including 1,024 MiB.
Pi remains at 256 MiB, Codex at 2 GiB, and the physical line limit remains
16 MiB. Larger files retain the existing oversized/incomplete disclosure.
A shrink below the relevant source threshold requires a successful native read
before new read authority can be recorded.

This interim admission change preserves all Full audits, reproof, rearm,
cache admission and retry semantics. A selected Claude file without a retained
native reduction can still require another Full read. The file limit does not
bound native reduction memory or promise tail-only processing.

Each Claude pass admits at most one large-Full scheduling unit, including
first admission, audits and recovery reads. An ordinary file above 256 MiB is
one unit. All live path twins of a session may share one unit only when the
whole group fits the existing 1 GiB history page reservation; all contributions
still need native reading and E2 complete-twin proof in that pass. An over-budget
group stays visible deferred debt, with no partial money or new proof. Other large Full candidates stay pending
census debt and receive priority in oldest-deferral order on subsequent passes,
including after restart. They contribute no read count or new source proof;
pending debt remains visible through existing scan-cap/skipped-file counters
and withholds census completeness. Scheduling priority is capped at 256 unique
absolute-path keys and 64 KiB, including conservative container/wire charges,
with a 4 KiB key limit. Both production readers bound the raw leaf before string
decoding; malformed or oversized state clears priority, logs a decode-drop counter
and uses the independent pending census FIFO. Overflow also uses that queue,
so losing cached priority never drops a read. Priority is collected when files
shrink, disappear, exceed admission, or the scan/account scope changes. Tail reads and files at or below 256 MiB
keep their existing admission. The oversized path still runs before this gate.

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
