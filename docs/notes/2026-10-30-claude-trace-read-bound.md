# Strict Claude trace reads stop at the opened length

The strict trace-ownership reader used to stream an opened sidecar to EOF
after its size check. A concurrent writer could therefore extend the read past
the stat'd length, even past the 64 MiB per-file cap, and a file replaced while
open could still yield complete ownership evidence.

The reader now opens without blocking, re-checks the opened file (regular file
below the cap), and reads at most the opened length plus one sentinel byte.
It drops the decoded rows for that session when:

- **cap**: the sentinel byte was read, so the file grew while it was read;
- **generation**: the opened file's or the path's device, inode, length,
  mtime or ctime changed while it was read (replacement, truncation, rewrite).

A dropped read also counts as an oversized file, so the report is never
complete. Downstream, an incomplete trace makes that root identity-unhealthy:
its requests are refused as incomplete evidence and carry no login. They are
never bound to another account, and a later clean read restores them. Stable
input keeps the previous rows, dedupe and health counters exactly.

Counters: the trace report carries `rows_discarded` (`cap`, `generation`,
`cap_rows`, `generation_rows`), summed into the Claude local evidence counts
line as `trace_rows_discarded`. The key is absent while empty, so ordinary
counts lines and snapshot-audit output are unchanged.

No persisted field, upload body, ACK, fingerprint or checkpoint changes. The
pre-paid bounded reader is unchanged.
