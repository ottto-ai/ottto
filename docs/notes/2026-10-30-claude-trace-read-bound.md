# Strict Claude trace reads stop at the opened length

The strict trace-ownership reader used to stream an opened sidecar to EOF
after its size check. A concurrent writer could therefore extend the read past
the stat'd length, even past the 64 MiB per-file cap, and a file replaced while
open could still yield complete ownership evidence.

The reader now opens without blocking, re-checks that the opened file is regular,
and reads at most the opened length plus one sentinel byte. As of the October 31
sidecar fix, 64 MiB is a size warning rather than a capture or read limit.
It drops the decoded rows for that session when:

- **cap**: the sentinel byte was read, so the file grew while it was read;
- **generation**: the opened file's or the path's device, inode, length,
  mtime or ctime changed while it was read (replacement, truncation, rewrite).

The generation-change guarantee is Unix-only (macOS/Linux daemons). On
non-Unix the generation witness is absent; only the byte bound applies.

A dropped read retains its existing `oversized_files` diagnostic count, but the
`rows_discarded` witness independently makes the report incomplete. Size warnings
alone do not make an otherwise complete read unhealthy. Downstream, an incomplete trace makes that root identity-unhealthy:
its requests are refused as incomplete evidence. For cap/generation discards,
E2 places every family share at None for this page: no own account, retained
start/binding fallback, root-to-child inheritance, or markerless-account
shortcut can supply a login. Final grouping and identity_parts keep None.
Durable creator bindings remain untouched and owed history stays held.

The page then defers the family's upload. Root and child items are withheld
through E2's existing withhold (`entity.held`, as for an undecided copy), so
`finish_page` emits no body and `hold_request_owned` holds them. Nothing of
the family is posted and no ACK is recorded. Each held key keeps its committed
revision, so the next page reads it again. Owed history keeps its custody
through the existing unhealthy-telemetry hold. A bucket the server already
accepted with a tag is therefore never replaced by an untagged revision. Such
a revision could let a backend fallback move that hour to another account.
Attribution and usage for a session whose trace read was discarded are delayed
one pass. They are never untagged and never another account. A page that
discards again defers again. Each discard event costs one re-read, the same
as any other E2 withhold. The None placement and the wire-account clear stay
as defence in depth: they act only on items the page now withholds.
Other unhealthy reads retain their existing fallback behavior. Stable
input keeps the previous rows, dedupe and health counters exactly.

Counters: the trace report carries `rows_discarded` (`cap`, `generation`,
`cap_rows`, `generation_rows`), summed into the Claude local evidence counts
line as `trace_rows_discarded`. The key is absent while empty, so ordinary
counts lines and snapshot-audit output are unchanged. The same counts line
also carries `trace_discard_no_fallback_requests`, the number of requests placed
at None by this rule, and `trace_discard_deferred_items`, the number of items
whose upload the page deferred. Both are omitted while zero.

No persisted field, upload body format, ACK or checkpoint format changes. The
pre-paid bounded reader is unchanged.

The real scanner/evidence regressions are
`e2_pipeline_bound_a_own_b_cap_discard_has_no_fallback_then_recovers` and
`e2_pipeline_bound_a_own_b_generation_discard_has_no_fallback_then_recovers`
(Unix-only). Both retain binding A while clean own evidence tags B. The discard
page defers root and child, so the production upload filter sends nothing of
the family. The next clean page tags B again with unchanged per-session
request/token/cost totals. They check root/child shares, identity_parts,
history custody and both counters. `e2_pipeline_bound_a_malformed_trace_keeps_main_fallback`
controls main's uniform-login case: an unhealthy, non-discard trace keeps the
uniform own login B already set on the wire. The split-login family (root B,
child C, binding A) shows the retained-account hazard:
`e2_pipeline_bound_a_split_logins_malformed_trace_matches_main_a` keeps main's
non-discard fallback to A, while
`e2_pipeline_bound_a_split_logins_cap_discard_blocks_retained_a` and
`e2_pipeline_bound_a_split_logins_generation_discard_blocks_retained_a`
(Unix-only) defer the family on discard and tag B/C again on the next clean
page. `e2_pipeline_accepted_b_cap_discard_defers_upload_then_recovers` and
`e2_pipeline_accepted_b_generation_discard_defers_upload_then_recovers`
(Unix-only) first record the clean B/C bodies in the accepted-identity ledger,
with the write a stored ACK makes, and read that ledger on every later page.
The discard page uploads nothing for the family. The next clean page uploads
B/C with unchanged totals.
