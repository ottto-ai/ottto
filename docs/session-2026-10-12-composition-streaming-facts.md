# Context composition: retain facts instead of whole transcripts

The daily composition parser previously held a complete transcript string and
all decoded JSON records through both attribution passes. It now decodes one
JSONL row, measures returned content, retains call/measurement/residency facts,
and releases the row before reading the next. Facts are applied only after
successful EOF. Later call definitions and duplicate IDs retain their existing
behavior; I/O or UTF-8 failure leaves the report unchanged.

This representation change preserves supported JSON decoding, category and
token estimates, image handling, subagent/session identity, timestamps, modeled
residency, wire fields, privacy labels, acquisition and cache semantics. No
parser-identity bump or historical replay is needed for equal semantics. Cache
metadata fences, last-good retention and successful-upload refresh timestamps
remain unchanged.

The simpler implementation decodes each row once using the existing serde_json
Value policy. It removes file-wide retention without adding the research
prototype's second validation pass. It still retains a raw row buffer, one
decoded row, compact facts and report aggregates. Peak memory depends on the
largest row and event/call cardinality; it is not constant memory or a promise
of fewer source reads, smaller uploads, or improved whole-daemon CPU.

Tests compare every normalized request field and error outcome with a frozen
test-only whole-file oracle on fifteen synthetic fixtures. New failure tests
cover valid facts followed by invalid UTF-8 or an I/O error. Existing cache and
loopback tests cover source changes, expired budgets, daily rollover and overdue
unchanged-payload refresh. Normal parity is capped at 32 MiB of logical input
reads; isolated resource samples at 64 MiB. Both fit a 128 MiB focused-proof
budget. Baseline reads use a full-file logical upper bound; successful candidate
reads are counted at the Read boundary. These are not physical disk counters.

The existing public Rust CI job, limited to two build jobs, runs the isolated
receipt after ordinary tests on explicit workflow dispatch only; PR and main
checks retain ordinary parity without repeating the benchmark. It compares complete payloads, serialized sizes,
source bytes, requested/usable heap, CPU and wall time, using the existing
test-only allocation probe and one test subprocess per sample. No live input or
provider call is needed. Allocation instrumentation affects timing; comparisons
use the same binary/profile/probe. Source parity and measured resource results
must be reviewed before accepting the candidate for shipping, particularly any
CPU increase. A green test receipt alone is not installed-runtime acceptance.
