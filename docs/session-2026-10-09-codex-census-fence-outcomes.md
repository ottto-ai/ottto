# Local Codex census fence outcomes

An old fenced-census cache does not identify why it was not renewed. A scan may
still be running, preparation may have returned before completion, authority
may have changed at a fence, or a diagnostic write and its invalidation may have
failed. A ten-minute observation floor is a reader's acceptance criterion; the
collector does not promise a completed scan or a cache replacement every ten
minutes. This change adds causal evidence without changing that floor, scheduling
or any collection decision. It does not establish an installed writer fault or
healthy ingestion.

The existing local `ottto-service: local_resources` JSON carrier gains the
`codex_census_fence` stage under schema version 2. Existing stages stay unchanged.
The envelope retains process ID and `observation.observed_unix_ms`; `counts`
contains exactly three closed string enums:

- `phase`: `outer` or `inner`.
- `outcome`: `passed`, `rejected`, `published`, `projection_unavailable`,
  `clock_unavailable`, `encoding_failed` or `private_write_failed`.
- `invalidation`: `not_attempted`, `removed`, `already_missing` or `failed`.

The outer event observes the existing account/source and destination validation
pair after an owned scan page completes. Both checks keep their order and run
once at their existing site. An outer rejection retains the prior cache, as
before, and prevents entering the inner path. The inner event observes the
existing first fence in source finishing, then the existing fixed-buffer
projection, secure non-durable atomic write and best-effort invalidation. The
original authority error is returned unchanged. A failed diagnostic write still
cannot fail collection. There are at most two events per completed Codex page;
outer rejection emits one, and other sources emit none.

`published` means the cache write returned successfully at that boundary. It
certifies neither continuing account authority nor later upload, checkpoint,
ACK or healthy census. An incomplete or red census page can still publish.
`private_write_failed` with `failed` invalidation explains why an older target
could remain after this attempt; no filesystem error text is exposed. Missing
preparation/scan-completion events are not diagnosed by this narrow stage. A
reconciliation-disabled source returns before these boundaries and emits none;
no new enable switch, watcher or scan trigger is added.

These are point outcomes, not measured resource windows: elapsed microseconds
are zero, and CPU/RSS fields are null. Encoding has a fixed shape of bounded
numeric fields and enums, tested below 1 KiB per event. The new stage takes no
CPU/RSS probes, visits no index entries, copies no index, and uses the existing
best-effort stderr sink with no new file, fsync or durable state. Sink failure or
panic can leave no event; absence does not prove no fence. Readers must filter
known stage/schema and bind PID/time to a signed process image externally. Event
clocks and the cache's observation clock describe separate boundaries, and
neither replaces the reader's predeclared freshness floor.

No namespace/account/path/digest/credential/arbitrary error enters the event.
Public status, CLI and upload DTOs, cache record schema, writer permissions,
authority reads, retry/cadence, checkpoint and receipt semantics stay unchanged.

Native controls use synthetic temporary files and typed errors. The original
code fails the write-plus-invalidation outcome test. Candidate controls check
outer/inner ordering and error identity, rejection before publish, private atomic
write failure with failed invalidation, encoding overflow, fixed publication
failure categories, removed/missing targets, other-source suppression, bounded
carrier encoding, and the existing private-cache/status-wire contract. These
are source proofs; a containing release and separately bounded installed
observation remain necessary to attribute an actual runtime outcome.

A synthetic native debug measurement emitted 256 inner outcome records through
the actual existing stderr sink in 3,463 microseconds. The test-thread allocator
measured a 768-byte peak including realloc overlap, three allocation events per
record and zero retained bytes after the loop. Encoding/privacy controls cover
all fixed enum spellings. These fixture measurements do not predict installed
daemon latency or guarantee stderr sink availability.

Local validation passed the 36 census controls (three ignored), workspace Clippy
with warnings denied, and formatting. The full native workspace run reached
2,340 passing service tests and one failure in the unchanged
`claude_code_config_state_detects_settings_shape_without_env_fence_dependency`
fixture; that test passed alone. Its wrapper expectation depends on process
environment shared with other tests, but the cause of the full-run failure was
not established. This local run is not a green whole-workspace receipt. Required
hosted CI must pass on the submitted head before merge.
