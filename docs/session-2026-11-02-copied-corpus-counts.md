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

Validation: changed-file formatting and whitespace checks passed. Compilation
and copied-corpus execution are pending the serialized harness measurement slot.
No production behavior, persistence format or policy is changed.
