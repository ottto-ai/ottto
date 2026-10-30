# Terminal-off discovery and debt service

Claude terminal authority remains off. Ordinary page upload, exact ACK and
selected-save rules are unchanged. Scheduling state below exists only in RAM.

Owed work enqueues individual keys, bounded by the page allowance and deduplicated
against the retained candidate queue. A RAM cursor also bounds inspected keys
and stat operations per page, including turns that admit no work. Actual selected
scan-root custody survives targeted requeues. New targeted entries are non-census; an
existing entry keeps its census role. Targeted service never marks observed
census keys. Existing selector, privacy/history, byte budget, numeric audit debt
and failed-open throttle remain authoritative. Diagnostics count existing causes:
cleared fingerprint, identity version, receipt-mintable context/body-witness
adoption, due audit, leased quarantine retry and watcher stat changes. No new
body-read cause or receipt/adoption shortcut is introduced.

Root changes, watcher overflow and the existing 300-second cadence request a
metadata walk. Both pending queues must drain; otherwise the request coalesces.
`TERMINAL_OFF_FRESHNESS_WALK_CEILING_SECONDS` is 1800. At the ceiling a suppressing
root probe starts even with queued work, preserving older directory work. It
skips queued paths and paths observed in the current RAM round whose length,
mtime, device/inode and birth still match. Unknown identity is never a reason to
suppress. Watcher hints bypass this suppression and still obey the existing
same-stat park. Rename-over, shrink and stat changes reach ordinary validation.
The observed census-key set resets at each ordinary round start.

Context and revision work has its independent targeted route, including during a
suppressing walk. A served unchanged blocking hold or oversized path keeps its
existing six-hour floor; changed stat or revision can wake it earlier. Failed
opens retain their original debt and use their own throttle before retrying.
Vanished paths enter the existing NotFound flow; no absence/retirement shortcut.

`terminal_off_freshness` reports `rediscovery_coalesced`,
`root_walk_forced_by_freshness_cap`, walk interval and oldest-unscanned age.
The age is diagnostic, never a scheduling predicate. Discovery reports zero body
bytes; ordinary candidate identity samples remain separately counted. Scratch
queue positions replace the directory walk's repeated linear search. RAM
observations have layout accounting and bounded scope/aggregate capacity;
evictions are counted and allow extra conservative work, never proof or ACK.

Controls cover saturated drain using the existing service-round end predicate,
unhinted create and same-length/mtime rename-over by the ceiling, page-bounded
non-census adoption, parked hints followed by stat recovery, and two held keys
at the six-hour floor. Existing unhinted-append cadence and oversized pipeline
floor assertions are unchanged. Compilation is not a native-runtime receipt.
