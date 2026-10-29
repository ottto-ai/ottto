# M1 writer reservation and exact encoding

The existing post-save durable writer now counts the original borrowed reduction
fields before allocating an exactly sized body. Field order, re-derivation
digests, allowlists and persisted bytes are unchanged. The count pass allocates
no body and produces no provider-id span observations.

One process-wide owner reserves 40 MiB before the writer takes cache or store
locks. This covers the existing 8 MiB pass bodies, overlapping envelope and
verification buffers, and bounded writer metadata. Its independent ceiling is
64 MiB; the retained cache keeps its existing limits. A fixed FIFO of 64 waiter
slots uses a 20-second deadline. Busy or over-budget requests defer the existing
writer; they authorize no transcript read or census change. The writer releases
ownership explicitly on success and error, with a counted Drop fallback.

The existing local resource diagnostic carrier reports `active_wait_us`,
`active_wait_busy`, `active_budget_refused`, `active_current_bytes`,
`active_peak_bytes` and `active_drop_release`. These are per-attempt/per-lease
observations: byte values describe reserved credit, and the peak is that lease's
maximum reservation. Drop release is 1 only when explicit release was omitted.
No paths, ids or transcript values enter these observations.

Disk admission, batch/pass limits, cache-transit restore, directory durability
and post-save publication ordering remain unchanged. This change does not add
active-only restore, pending-receipt reconciliation or a live-finish writer.
It does not change parser or scan-identity versions.

Regression fixtures cover zero-allocation count/refusal, exact byte identity for
populated Claude and Codex records (including absent/Legacy/V2 counting state),
FIFO timeout cleanup, checked credit and explicit/Drop release. A native fixture
uses the real M1 writer on both sources and injects a rename failure to verify
release and body bytes. Static branch validation is formatting and diff checks;
runtime results must be attached from authorized CI before landing.
