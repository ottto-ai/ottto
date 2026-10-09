# Fenced local Codex census aggregates

The existing terminal journal is scoped to a destination directory. A consumer
that retained its redacted counters without the selected directory cannot safely
choose the corresponding index later. A new producer-side diagnostic avoids
that file join: the runtime projects its completed Codex scan and already-owned
working index immediately after the existing source/account/destination fence.
The fence still runs exactly once at that site and returns its original error.

One latest record is written at `snapshots/codex-fenced-census-v1.json` under the
local support root. Its `local_fenced_codex_census:v1` schema contains producer
PID/version, a fresh RFC3339 observation clock, scan-input generation, native
scan gates/loss counts, and index aggregate counters. The scope is
`last_completed_scan_at_destination_fence`; `working_before_delivery` means the
working index before later account filtering, upload policy/finalization,
delivery and checkpointing. Scan-input and working-index generations are
separate. This is neither ongoing current-account authority nor a certificate
of a later terminal report, durable checkpoint, backend materialization or ACK.

Index evidence includes schema/generation/file count, traversal presence,
pending directory/candidate counts, directory-census presence/stability/count,
reconciliation-start/watcher flags, retry attempt/deadline, protected-history
count, protected entries absent from the observed rollout set, and that absent
set's valid-owner share. An incomplete observed rollout set can still grow;
absence alone does not prove source retirement. Missing traversal/directory
evidence is null, not zero or healthy. Directory stability does not prove an
ephemeral header inventory completed successfully.

The projection visits at most 32,768 index entries, uses borrowed membership
lookups, and rejects protected aggregation when either population exceeds that
limit. It then reports incomplete aggregation with null protected counts. It
does not clone the index, read transcripts/provider state/credentials, enumerate
destinations, or mutate scan/index/receipt state. It omits destination hashes,
locators, account/device/session identifiers, paths, fingerprints, root/body
digests, lineage samples and arbitrary error text. No public DTO, CLI JSON,
status HTTP body, upload body or account attribution contract changes.

Encoding uses an 8 KiB fixed buffer. The disposable record reuses the secure
owner-only create-new temporary file and atomic rename path with mode 0600 and
an owner-only parent, but does not request fsync. Durable credential writes
retain their existing fsync behavior. Diagnostic write/size failures and fence
rejections invalidate the prior local record best-effort without changing the
scan result or rejection error. Unsupported non-Unix private-cache writes are
unavailable rather than falling back to an unsafe write. The cache can disappear
after a crash; it is not a ledger or collection prerequisite.

A future reader needs one bounded read of this known file, process PID/start/
image continuity, matching producer PID, the expected schema/scope, and an
observation clock after both process start and an explicit fresh-observation
floor. The logical census start can survive restarts and is not that floor.
Process changes, old records after an account/authority change, missing/invalid/
oversize records or unsupported scope mean unavailable. A failed deletion can
leave an old file, so freshness checks remain mandatory. This change adds no
runtime reader, retry, scan trigger, repair, restart or installed acceptance.

Native tests cover fence count/order/original errors, stale-record invalidation,
private bounded latest-only writing, nonfatal failures, source suppression,
all eight protected-history predicates, unknown/capped aggregates, separate
generations, immutable index/snapshot output and unchanged mock HTTP status
bodies. Existing credential writer tests still pass. On synthetic native debug
fixtures, 32,768 protected entries took 17,853 microseconds with zero heap
allocations; 100 private atomic writes of a 1,128-byte record took 19,635
microseconds total without fsync. These are bounded fixture measurements,
not installed-daemon performance or census-completion evidence.
