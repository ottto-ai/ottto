# Shared sampled transcript acquisition

Claude Code JSONL and eligible single-file Codex rollouts use one private
acquisition kernel and one generic bounded reduction cache. Full and suffix
reads feed the existing native line reader, reducer and finalizer. The kernel
owns byte acquisition only: it knows no provider row schema, usage calculation,
account attribution, upload policy, scheduler or acknowledgement contract.
A future plain record-file adapter can reuse it by supplying its native reducer,
interpretation dependencies and existing durable index authority. Databases,
compressed files and journals are not automatically eligible.

First acquisition is full. Warm appends compare 4 KiB at the beginning and
4 KiB immediately before the previous newline-sealed byte pointer, then parse
the suffix. Shrink, replacement, same-size mutation, sample/scope changes,
invalid checkpoints and due audits choose a full acquisition. Source/dependency
races and lossy parsing cannot certify a checkpoint. Samples come from native
reader chunks already consumed, without a second record decoder. A valid
unterminated EOF keeps the native output but declines state retention, so a
future append cannot count that row twice.

Matching samples do not prove the entire historical prefix unchanged. An
in-place middle edit followed by growth can preserve both samples and leave
historical usage, detail or money temporarily stale. A full audit is due one
hour after the last successful full verification of a generation subsequently
changed under sampling. Appends, uploads and cache eviction cannot extend that
deadline. Offline operation, unreadable files, failed upload or scheduling
backlog can delay actual server correction beyond an hour.

The smallest durable obligation uses the existing ScanIndexEntry version string:
`semantic_sync:v2+sampled_unverified:v1:<deadline>`. Ordinary verified entries
keep `semantic_sync:v2`. There is no second ledger, cursor database, persisted
accumulator or raw sample. The marker is checked before unchanged-file and age
suppression, prioritized in the existing bounded candidate page, retained during
replay/missing-file cleanup and merged through the existing partial-ACK/index-CAS
path. Malformed markers conservatively require full verification. Successful
native full parsing clears it; delivery/ACK authority remains independent.
Native settlement of a disclosed oversized row retains the prepared audit
deadline even when parsing cannot issue a completion/retention certificate.
This preserves first-tail debt and failed-audit debt without claiming verified
bytes. Once native loss is repaired, a valid full acquisition can clear it.
Acquisition-bypass full parsing uses the same loss-free report predicate and
requires complete interpretation dependencies before clearing existing debt.

Known original-owner, relevant sidecar and policy inputs still control reuse.
Codex binds the existing bounded whole owning header, including headers longer
than the head sample, and refreshes current decoration and projected EOF.
Prior consumed turn-priority decisions must match current trace evidence.
Only cache-enabled acquisition records these decisions, with at most 256
identifiers of at most 128 bytes. Excess or nonstandard identifiers decline
retention while preserving native output and source-verification certificates.
The ordinary full reader keeps no additional priority map. A missing durable
index entry requires full acquisition even when a warm RAM entry still exists.
Joined groups, fork/parent-proof cases, Claude family authority reconstruction
and protected pricing receipts retain their full proof path. A newly discovered
Codex priority contribution forces actual full replay before creating a receipt.
Source capture, common/exact ACK, pending recovery and checkpoint fences remain
in their existing owners.

The optimization allowance is incremental, not a daemon RSS limit. Background
and manual acquisition share the cache under the existing full-cycle sync lock.
Of 64 MiB,
32 MiB remains reserved for the existing aggregate parked/optional-send owner;
31 MiB bounds tail cache, active native state and finalization/retention copies;
1 MiB reserves incremental audit markers and fixed scope/header/path scratch.
Entries are limited to 8 MiB and 256 cache entries. At most 256 unverified
markers per supported source can be introduced; bounded 64-byte strings replace
an existing version string, avoiding a new field in every baseline index entry.
The unchanged ordinary serial index/metadata remains baseline and is reported
separately. The existing source-rotation owner bounds its parked frame queue
and frames to 8 MiB; the remaining existing overlap reservation covers the
independently admitted complete-body send owner. That owner is currently
inactive and retains its own envelope validation. Parked frames include their
referenced shared cache in the existing layout bound, conservatively refusing
parking when it cannot be charged. The marker reserve covers the bounded
increment in working, committed, settlement/CAS and serialized index copies;
those remain the existing serial index owners rather than a new cache ledger.
This allowance is not a proof for arbitrary HTTP/TLS allocations or process RSS.

All retained native containers, private strings, spare capacities, samples and
live copies use the existing fail-closed heap-layout helper. Unknown/opaque
state, unsupported platforms/toolchains, arithmetic overflow or traversal
exhaustion decline retention. A narrow helper correction skips recursive
per-element visits only for proven heap-free scalar types while charging all
allocated Vec/VecDeque capacity. The 4096-visit limit remains unchanged; this also
changes optional rotation/retry admission for valid scalar buffers.

Local content-free diagnostics report full/tail counts, fallback causes,
parser/sample bytes, priority replay, pending/overdue audit age and audit
start/completion age. Audit effective-body changes use the existing post-policy
body witness; changes can include legitimate new suffix or policy output and
are not a count of proven sampling misses. Body/header/sidecar/discovery and
independent identity I/O are distinct. The 8 KiB sampling guard is not total
warm I/O. Existing Claude 256 MiB, Codex 2 GiB and 16 MiB row caps remain.

Validation used synthetic native fixtures on macOS with Rust 1.88. Workspace
formatting, Clippy with warnings denied, release compilation and doctest
discovery passed. The final bulk workspace run passed 2,547 ordinary tests with
zero failures. Two existing native process/context tests ran separately outside
the bulk sandbox and passed, for 2,549 ordinary tests exercised successfully.
Fifteen tests were ignored by default; the two acquisition measurement tests
were explicitly run and passed. External network and actual provider,
credential and support stores were denied to bulk/measurement processes;
localhost fixture servers and sockets remained available. Earlier unrelated
browser-auth teardown, cloud-CLI child-start timing and sandboxed context-probe
failures passed separately; the first two also passed in the final bulk run.

Strict source discovery and subsequent sensitive focused verification used
fresh-context Codex with requested model `gpt-6.1-sol` at high effort. Review
identified two audit-debt defects: first-tail native terminal loss could lose
its prepared obligation, and ordinary acquisition-bypass full parsing could
clear debt after loss or incomplete dependencies. Both were fixed with native
regressions; final focused review was clean. Resolved model identity was not
exposed by the CLI; this is same-provider review, not cross-model review.

The actual production-scan fixture used a 32 MiB transcript and three append
scans per provider, matching complete output against native full acquisition.
Repeated full scans took 16.1–16.2 ms for Claude and 85.5–87.5 ms for Codex;
warm tail scans took 0.5–0.7 ms and 0.7–0.8 ms respectively. Native tail bytes
were 242/293 plus 8,192 sampled bytes. Retained requested-layout charges ranged
from 109–150 KiB; isolated process RSS peaked at 19.8 MiB for timing and 21.2 MiB
for allocation. These are warm-filesystem fixtures, not fleet averages.

The allocator probe measures all-thread requested allocations born during each
isolated scan. Baseline full peaks were about 3.0 MiB; cold sampled peaks were
about 8.4 KiB higher; warm scan peaks were 72–74 KiB. Pre-existing index/cache
allocations are excluded from these scope counts and reported separately by
layout/RSS. Adding 5,000 ordinary index entries grew measured live baseline
state by 5.5 MiB for either provider, while actual small warm acquisition still
used the tail path. Near-budget cache/active-copy, native rotation/retry,
refusal/eviction, idle/restart audit, hidden-edit reconciliation, partial EOF,
dependency, missing-index, partial-ACK and stale-CAS checks passed.

Public export, manifest, skeleton, secret and contract checks passed. No
connector workspace, dependency, wire or release inputs changed.
No transcript-generating provider run, observer, installed daemon or release
configuration was started or changed by this implementation. Local source
review is a separate model invocation and uses public source only.
