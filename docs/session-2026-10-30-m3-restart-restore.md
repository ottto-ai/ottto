# Restart restore

The durable-tail store uses v3 write-ahead records prepared at native settlement,
before publication effects and index save. Restore validates the record against
its source, scope, file certificate and committed index evidence, then replays
bounded content and reads the appended suffix. Local receipts never substitute
for exact upload acknowledgement. Byte budgets defer work without dropping usage.

Restart restore defaults OFF. The `restart_restore_enabled` support-directory
marker also requires `DISCOVERY_DEPENDENCY_READY`, which is false in this build.
Enabling it requires implementing the discovery dependency and flipping that
constant; the marker alone cannot enable this build. OFF disables ordinary store
reads, writes, repair and GC. Consent/source erasure and counted deletion of
outgrown v1 records remain active, with failed deletions retried. The former v1
warm-restore route is removed; growth can require a paced Full read.

Erasure leaves no deleted data readable in the database, WAL or SHM. Record files
are unlinked and their directory synced under the existing writer lock. This does
not promise physical block overwrite. `rec_orphans_erased` counts verified
private-label records erased after a save because their digest is absent from
the committed JSON index. It does not establish a complete erasure sweep across
all triggers or formats.

Store diagnostics contain counts only. `disk_bytes` measures per-source store
bytes; `store_bytes_alarm` fires above 512 MiB without refusing writes for capacity.
See [diagnostics.md](diagnostics.md) for units and reset semantics, and the service
[architecture](../crates/ottto-service/ARCHITECTURE.md) for the read path and stores.
