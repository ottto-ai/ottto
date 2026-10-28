# Composition worker memory lifetime

The changed-days composition reader runs each hourly wake in a short-lived
service process. The daemon keeps only the folder map and file witnesses needed
by the next hourly wake. Pin reloads, checkpoint shards, interned names, Git-root
lookups, read buffers, upload payloads and clients belong to the worker. Waiting
for its exit releases the system allocator's retained pages; thread teardown and
allocator pressure relief alone can leave free pages resident.

The worker uses the same once-per-UTC-day gate, saves the date before scanning,
and applies utility QoS. Its hidden entry point also checks the changed-days
release switch. Checkpoint formats, upload bytes, scope attribution and retry
rules remain unchanged. Folder metadata travels over local pipes, preserving
the cached witnesses that avoid redundant pin reads. The parent makes one
allocator-relief call after the worker exits and temporary pipe buffers and
superseded folder metadata have dropped.

Tests cover successful and unsuccessful worker exits and the hourly cache round
trip. The explicit real-scale harness runs one phase per process. Its peak bound
includes both parent and worker high-water marks, and its total CPU includes
process startup, scan, serialization and teardown. Optional heap diagnostics
separate live Rust allocations from native allocator retention.
