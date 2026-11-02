# Copied-corpus reduction measurements

Adds test-only instrumentation to the ignored restart/restore corpus harness.
The recorder emits aggregate sizes, histograms, equality counts and refusal
classes. File keys, provider identities, field values and comparison digests
stay in memory. The recorder is inert until explicitly enabled by the harness.

Measurements cover accumulator fields before finalization, suffix response-book
touches, completion counts, missing-record history, policy flags, re-arm
provenance and partial-settlement observations. Existing codec refusals remain
unknown measurements. Head sums include known fields only. Process footprint
is an instrumented pass upper bound rather than a per-file isolated peak.

Validation: changed-file formatting and whitespace checks passed. The release
test build passed after correcting a proxy macro identifier error. The three
serialized copied-corpus arms completed with no harness failures; their oracle
differences and measurement limits are retained in the private aggregate report.
All three hybrid resume experiments selected Tail. This records a completed
measurement, not oracle equivalence for every arm. No production behavior,
persistence format or policy is changed.

The expanded measurement plan also records collection element counts,
finish-only and empty-field checks, candidate stable page geometries, estimated
unsaved staging bytes, Codex cursor state and copied-database header scans.
The header scan uses an immutable, read-only main-file copy; WAL tails are
excluded. Cold-Tail comparisons use a hybrid codec/resume proxy: encodable
fields round-trip through the existing codec, while content and live/empty
classes move unchanged. Proxy coverage and limitations are emitted with counts.
Actual Tail transactions, WAL/checkpoint costs and commit timings await the
store implementation. An explicit measurement-only heap scope traverses owned
collections without using their optional cache charge; admission is unchanged.
