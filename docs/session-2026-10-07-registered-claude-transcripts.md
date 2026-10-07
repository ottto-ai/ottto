# Collect sessions from registered Claude folders

The macOS app can register several Claude Code configuration folders through
Add Claude account. Session collection now includes each registered folder's
`projects/` directory alongside the default `~/.claude/projects` directory.
Previously the collector scanned and watched only the default Claude directory.

The existing slot registry supplies paths through a bounded, regular-file,
no-follow read. Discovery does not require upkeep consent or read the retired
reconnect sidecar. It neither loads credentials nor starts a login or quota
request. Invalid or oversized registry data fails the Claude scan explicitly.

Scanning and filesystem watching share one root composer. Duplicate configured
paths are included once, and registry order does not change the selected root
set. The watcher refreshes when registration or available watch targets change.
A missing `projects/` directory is watched nonrecursively through its existing
config parent;
if both are missing, periodic collection discovers them when they appear.
The debouncer uses its no-cache mode: watching is a cadence hint and does not
need a synchronous, symlink-following file-ID census of directory contents.
Periodic scanning remains the correctness fallback when watching is unavailable.

Existing upload and checkpoint authority checks recheck the selected Claude
roots. A registration add, removal, or repoint invalidates that in-flight
selection. The next preparation uses the current registry. Unreadable transcript
roots retain the scanner's incomplete-census behavior while readable roots still
yield sessions.

The native parser, persisted scan index, logical session identity, wire payload,
retry and acknowledgement contracts are unchanged. A registered path does not
establish which account paid for historical requests. Manually copied or moved
conversation reconciliation and per-request subscription attribution remain
separate work.

Synthetic native fixtures cover default and registered roots, import and persisted
restart, changed transcripts, registration lifecycle and order, invalid registry
data, unreadable roots, exact duplicate roots, existing same-ID wire behavior, and
watch-target creation/removal. Tests use temporary directories and deny network
and sensitive local stores. Validation results are recorded in the source PR;
source checks do not establish containing-release or installed acceptance.

Public CI exposed a pre-existing parallel Codex creator-fixture race: clock-only
scratch directory names can collide, letting one test overwrite or remove another
test's same-session file. Focused native tests reproduced the parser's existing
opened-object identity refusal. The shared creator fixture now uses the existing
unique, owner-only scratch-directory helper; a parallel regression checks each
synthetic creator retains its own identity. Production parser and identity guards
remain unchanged.

A later hosted run passed the creator controls but exposed another existing
fixture timing defect: the cloud-cleanup test's mock backend stopped after
750 milliseconds, potentially before the operation reached it. A controlled
one-second setup delay reproduced the assertion with connection refusal. The
mock now observes until the operation finishes; its watchdog fails rather than
certifying absence. A delayed synthetic request verifies late registration
remains observable. Production cloud-cleanup and identity-reservation guards
are unchanged.
