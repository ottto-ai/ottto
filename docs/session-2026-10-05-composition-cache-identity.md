# Composition cache invalidation

Composition's local preparse cache previously stored whole-second modification
times. A same-second edit could change the report without triggering a rescan;
the active UTC window and parser identity were also absent from admission.

The existing discovery metadata witness now also identifies cached files: full
modification time, length, and Unix device/inode and change time. Admission
includes both ends of the existing 92-day UTC window, a local parser revision,
the existing methodology hash, and label policy. Old cache entries rebuild once.
The wire schema, collector version, content hash and scheduling cadence remain
unchanged. Parser changes must advance the local parser revision when they do
not change the methodology or collector version.

An unchanged same-day workspace still avoids transcript parsing. The first scan
on a new UTC day rebuilds the window once. When that rebuild produces an
unchanged payload, the cache retains the last successful upload timestamp so
the existing seven-day refresh remains effective. Metadata checks before and after
parsing, plus a final metadata pass, reject changed or unreadable sources before
upload or cache replacement. An incomplete workspace retains its last good
cache and allows other workspaces to continue; only deadline exhaustion aborts
the source loop. No transcript-body hash or extra body read is added;
normal rebuilds retain one existing whole-file read per admitted file. Existing
50 MiB per-file and source-deadline bounds continue to apply. Unix ctime/inode
provide the replacement witness; other platforms retain size and full mtime.

Synthetic native regressions cover nanosecond edits, growth with restored mtime,
same-size rewrites, inode replacement, day rollover, parser/methodology/label
identity, destination/source changes, seven-day staleness, legacy-cache rebuild,
unchanged suppression, and preservation of the last good cache on incomplete
reads. A three-cycle loopback harvest verifies unchanged rollover suppression
preserves the previous post time, then an overdue upload refreshes successfully
while the damaged workspace retains its cache. Normal malformed-line handling and report values remain unchanged.

Validation: 25 composition tests and 20 shared footprint/discovery tests passed
(two composition measurements and one discovery measurement remain opt-in).
An actual native debug harness measured 100 synthetic files per source over
three samples per phase. Unchanged passes parsed zero body bytes. UTC rollover
parsed 128,090 Claude bytes and 135,490 Codex bytes once; subsequent unchanged
passes again parsed zero. Median collector-loop wall times were 9.511/9.295 ms
unchanged and 19.899/21.901 ms rollover for Claude/Codex. Process CPU, including
sandbox and test-harness startup, was 21.264/21.011 ms unchanged and
31.751/34.040 ms rollover. These are bounded synthetic phase costs, not a
before/after daemon CPU claim. Cache signature work adds one metadata stat per
file on an unchanged pass; signature plus pre/post/final witnesses total four
per rebuilt file. Cold and rollover serialized report hashes matched per source.

Installed acceptance belongs to the next containing release: confirm unchanged
same-day suppression, a same-second update on a disposable fixture, rollover,
and refusal of an unreadable or concurrently changing source while retaining
its last good report. Local synthetic tests do not prove installed behavior or
production persistence. This fix adds no selective parser.
