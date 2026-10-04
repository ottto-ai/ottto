# Agent status freshness independent of transcript scans

The daemon previously collected/uploaded each source status inside the sequential
session scan cycle, then waited five minutes after all work. Startup/wake Claude
refresh also waited on that cycle's lock. Long scans and an absent/busy Companion
therefore delayed quota/status uploads beyond their freshness windows.

One daemon owner now has three independent source workers. Each ordinary
collection starts at most 300 seconds after the previous start while work fits
that period. A late tick runs once, and work exceeding the period leaves a
60-second recovery wait. Backend transport retries wait at least 60 seconds and
reuse the collected body until the next ordinary acquisition. Existing provider
adapters retain their account/cache/cooldown/consent ownership and observation
clocks. Source grants are checked on each pass. Provider calls are never forced.

Manual/Companion refresh shares collection and upload with its source worker.
Concurrent collection calls coalesce; results are available before upload completes. Idle
manual calls within one second reuse the same collection; older calls queue one
fresh acquisition after an in-flight upload. Startup cold-CLI reconfirmation uses
this same fresh acquisition request. Claude registry,
upkeep and auth events coalesce into one pending pass with a 60-second minimum
between event-driven acquisitions. Network/wake signals only expedite genuinely
overdue collections, including when macOS monotonic time paused during sleep.

The scan reads the same complete collection (all account snapshots and Codex
home/binding witnesses) from the owner. Immediately before session binding, the
scan revalidates each Codex auth-file modification witness and withholds changed
or missing home ownership and stale current-login fallback. Persisted session
ownership remains with ScanIndex. The replaced automatic in-cycle upload
and scan-locked Claude hook thread/claim are removed. A standalone one-shot sync
and a one-request control server retain their original explicit upload behavior
when no periodic daemon owner exists. Startup reconfirmation retains its
conservative seeded-verifying health rule. Collector check-in remains a separate
liveness signal, not a fabricated provider observation.

Worker count is three, one flight and at most one pending event per source. Stop
wakes blocked readers and prevents future passes; already admitted adapter/HTTP
operations finish under existing deadlines. No new durable queue, provider cache,
backend store or wire contract is added. Logs expose source, duration, outcome
and snapshot count without credentials or payloads.

Native tests use a fake clock and real ownership boundary, hold the actual scan
lock for a simulated twenty-minute scan, and cover source isolation, concurrent
manual/timer calls, unchanged cached observations and account batches, retry/lost
response bounds, sleep with paused monotonic time, disabled grants, and shutdown.
No live daemon or provider proof call is required.

A five-minute acquisition interval does not guarantee continuous backend
300-second Claude coverage once acquisition/upload latency or cached provider
observations are included. Backend freshness meaning is unchanged; QUOTA/SOURCE
owns any decision about that boundary. Source completion must be distinguished
from the signed containing release and ordinary installed acceptance. Ron owns
the morning M1 release, installation and lifecycle actions.
