# M3 write-ahead assembly checkpoint

The assembly contains the format-3 reader and the three original work lanes.
Native write-ahead publication remains incomplete; format-3 reading does not
establish receipt-before-publication ordering.

The atomic writer now preserves a structured error when the write and both
existing temporary-file cleanup boundaries fail. A transient explicit cleanup
failure followed by a successful fallback remains an ordinary write failure.
The existing resource diagnostics receive `store_write_cleanup_failed`; no
persisted field or separate diagnostics emitter is added. The cleanup still
runs at most twice, and neither attempt removes the canonical predecessor.

The D3 policy is **not yet activated**: its process-wide disable/degraded
publication disposition needs an index-floor save before the native ACK. The
current M1 writer runs after upload and selected-state settlement, so adding a
floor save there would not establish that ordering. Existing receipt-pending
handling is retained until the native preparation and publication boundary is
integrated. This checkpoint must not be qualified as D3 complete.

Validation: package-scoped all-target Clippy with warnings denied passed. The
new I/O regression controls compile but were not executed; no cargo test ran.
