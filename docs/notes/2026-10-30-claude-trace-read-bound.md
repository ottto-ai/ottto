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

The generation-change guarantee is Unix-only (macOS/Linux daemons). On
non-Unix the generation witness is absent; only the byte bound applies.

A dropped read also counts as an oversized file, so the report is never
complete. Downstream, an incomplete trace makes that root identity-unhealthy:
its requests are refused as incomplete evidence. For cap/generation discards,
E2 places every family share at None for this page: no own account, retained
start/binding fallback, root-to-child inheritance, or markerless-account
shortcut can supply a login. Final grouping and identity_parts keep None.
Durable creator bindings remain untouched and owed history stays held. Account
attribution is delayed to a later clean pass, never a retained or other account.
Other unhealthy reads retain their existing fallback behavior. Stable
input keeps the previous rows, dedupe and health counters exactly.

Counters: the trace report carries `rows_discarded` (`cap`, `generation`,
`cap_rows`, `generation_rows`), summed into the Claude local evidence counts
line as `trace_rows_discarded`. The key is absent while empty, so ordinary
counts lines and snapshot-audit output are unchanged. The same counts line
also carries `trace_discard_no_fallback_requests`, the number of requests placed
at None by this rule, omitted while zero.

No persisted field, upload body, ACK, fingerprint or checkpoint changes. The
pre-paid bounded reader is unchanged.

The real scanner/evidence regressions are
`e2_pipeline_bound_a_own_b_cap_discard_has_no_fallback_then_recovers` and
`e2_pipeline_bound_a_own_b_generation_discard_has_no_fallback_then_recovers`
(Unix-only). Both retain binding A while clean own evidence tags B, discard
tags None, and the next clean page tags B again. They check root/child shares,
identity_parts, unchanged per-session request/token/cost totals, history custody
and the request counter. `e2_pipeline_bound_a_malformed_trace_keeps_main_fallback`
controls the existing non-discard fallback to A.
