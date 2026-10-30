# Diagnostics

Diagnostics help support understand local runtime state without exposing raw
local content.

## Local Collection

Collect a redacted diagnostics bundle locally:

```bash
ottto diagnostics collect --json
```

The response includes sectioned runtime, install, account, source, repair,
update, and security facts plus a redaction report.

`versions.app_version` comes only from the Ottto app's own `Info.plist`, and
only when its bundle identifier is the Ottto app's. When the service runs
from inside the app, it is that app's version. When Homebrew or the installer
owns the service, it is the version of the app in `~/Applications` or
`/Applications`, but only if every copy found there reports the same version.
In every other case it is `unknown`. It is never taken from the service or CLI
version, because the app and a Homebrew install can be at different versions.

## Account-bound terminal launch

Session launch blocks travel over authenticated local control. Reasons include
`slot_not_found`, `slot_needs_login`, `slot_not_verified`, `account_mismatch`,
`cli_not_found`, `cli_version_unsupported`, `cloud_provider_route`, `api_key_route`,
`settings_env_override`, `settings_unreadable`, `settings_malformed`,
`config_unsupported`, `forced_login_method`, `forced_org_mismatch`,
`codex_provider_not_openai`, `codex_api_key_login`, `folder_missing`,
`folder_not_directory`, `folder_not_local`, `folder_invalid`, `folder_changed`,
`launcher_dir_unsafe`, `launch_expired`, `launch_already_used`, `launch_unknown`,
`launch_cancelled`, `launch_limit`, `chdir_failed`, and `exec_failed`.
The block can name a typed settings layer, never its values or paths. Launch
status is `pending`, `starting`, `blocked` or `expired`; no successful exec or
running agent is inferred. These features add no path or nickname diagnostics.
See [the local handoff contract](session-launch.md).

## Claude Local Evidence Health

Local collection includes a `claude_local_evidence` section with separate API
and trace counters for available canonical rows, duplicate/conflicting requests,
malformed or unframed rows, oversized files/lines, unavailable or changed files,
and limited selection/reads. The inspection is on demand: at most four files per
store, 64 directory entries per store, 64 KiB read per file (512 KiB total),
16 KiB per line and 128 physical rows per file. Selection can be partial and is
not a complete census or a retained-history replay. Symlinks and non-files are
refused; no file is rewritten.

These are support facts, not new session totals or account evidence. The section
always reports `complete_capture_authority: false`. Available rows in a capped
file remain incomplete; a partial line or JSON object missing its final newline
is not counted as a validated framed row. Strict upload/account readers retain
their existing refusal behavior. Counts do not detect every zero-byte capture
failure, establish power-loss durability or solve capped-file growth. No request
ids, paths, fingerprints, identity observations, token/cost values or row content
appear in this section. Approved upload uses the existing disclosure and consent.

## Local Resource Measurements

The existing service error log contains content-free JSON lines prefixed
`ottto-service: local_resources`. The macOS app/dev LaunchAgent writes
`~/Library/Logs/Ottto/ottto-service.err.log`; Homebrew writes
`~/Library/Logs/Ottto/ottto-service.error.log`. These records add no remote
telemetry endpoint or CLI command. They contain counts, byte lengths, timing,
process id and a fixed source label; no paths, account/session identifiers,
payloads, credentials or backend response bodies.

Records use `schema_version: 2`. Within a version, fields and stage values may
only be added; readers must ignore unknown keys and stages. Removing a field
or line, or changing its meaning, increments the version. Version 2 removes
the `sampled acquisition` text line: full-read reasons now come from
`counts.sampled_acquisition.page_events.full_reasons` in `local_resources` JSON.
Version 1 readers that need reasons must retain their text fallback while
accepting version 1 binaries; there is no version negotiation.

Each completed `native_collection_page` records existing scanned-file and
semantic-no-op counts. `sampled_acquisition` is `null` when unavailable. Its
full/tail/unchanged selection counts describe acquisition decisions, including
repeated or subsequently failed plans; they are not distinct file counts.
`completed_native_bytes` counts completed sampled JSONL read plans.
`completed_guard_bytes` also includes actual returned head/boundary bytes from
quiet-retirement validation attempts, including attempts that keep their debt.
Other failed reads, joined-file replay, discovery, headers, sidecars and
independent identity reads are excluded. Zero here does not prove
zero filesystem work. Collection timing covers native initialization and steps,
including time parked between steps, and ends before post-policy finalization
and upload. A capped/partial page is still a completed page.

When sampling is present, `page_events` records existing full-read reasons as a
sparse map of closed snake_case keys (`state_missing`, `audit_due`,
`clock_changed`, `scope_changed`, `invalid_checkpoint`, `replaced`, `shrunk`,
`same_size_edit`, `head_changed`, `boundary_changed`, `unsupported_identity`).
Their sum equals `full_selections`. It also records `priority_full_replays`,
`audits_started`, `audits_completed`, `max_start_overdue_seconds` and
`max_completion_overdue_seconds`. Separate `index_state_at_page_end` gauges
record `pending_audits`, `overdue_audits` and `oldest_due_age_seconds` using the
existing index calculations. These three fields are state gauges. The same
object adds page-event counts `audit_quiet_retired` and `audit_cap_full`.
To keep the existing native page under its 4 KiB budget, `audit_cap_delay`
emits a separate nonzero-only `sampled_audit_cap_delay` record on this carrier;
`pace_evicted` is emitted by `sampled_audit_pace_alarm`. Values remain exact.
Full counts actual per-file cap fallbacks; refused prefix/lossy completions and
paced candidates count as delays. The RAM
pace is six hours per key, 256 fixed slots, oldest-evicted on overflow. Its
SystemTime clock expires on backwards time or jumps beyond 30 days. A restart
allows at most one extra cap Full per key. Existing marked Tails stay enabled.
A positive Full count emits `sampled_audit_cap_alarm` immediately (`> 0`);
positive `pace_evicted` emits its own `sampled_audit_pace_alarm` immediately.
Delayed paths keep their committed size and clear the existing source
fingerprint as a durable reparse witness. It remains age-exempt across partial
saves, restarts and context-changing traversal replacements; the watcher queue
alone is not its custody.
The clear uses the process-local rearm wrapper: a later Full reports
`rearm_cleared{audit_cap_delay}` with its count and completed native bytes.
That tag survives an index reload in the same process; a process restart loses
the diagnostic tag while retaining the persisted retry witness.

Due complete-c quiet retirement requires both samples, stable EOF/stamp and native
completion/RAM admission. With an active durable store the scheduling marker
remains until the same writer durably stores no debt and a second index CAS
clears the marker. The existing diagnostics carrier then emits
`sampled_audit_retirement` with `audit_quiet_retired` and `pending_audits`.
The page's retirement count is zero while that receipt remains outstanding.
Writer errors, skipped records and deferrals keep the obligation scheduled.
Freed slots become usable on the next committed scan; the current page reserves
them because partial-save reconciliation can restore an unacknowledged marker.
Quiet retirement keeps the old Full verification time and grants no
`audits_completed`, source, census or ACK credit.
Before the deadline, incidental telemetry-only Unchanged reuse keeps the exact
index and checkpoint debt. A cap Full keeps its frozen acquisition extent even
though it cannot sample; independent grown-prefix/marker refusals still apply.

`audit_retired_absent{events}` counts an obligation retired on positively proven absence:
ENOENT on a no-follow descriptor chain from a readable configured root.
A missing intermediate directory counts only beneath the nearest securely
opened readable ancestor; all pinned directories are revalidated. Symlinks,
dangling links, unreadable/missing roots and other errors keep it owed. Codex-protected history
remains retained; this counter grants no Full or source/census credit. Account
removal also emits `withheld_hold_released{deleted}`. Ordinary unavailable audit
markers are never evicted.
The absence predicate is shared with the hardened account-hold proof. The
`audit_retired_absent` and deleted-hold counts currently use temporary traversal
point carriers; integration must replace them with the shared account/absence
diagnostics, preserving both retirement paths without double counting.
Both keys and their count meanings are shared with the integrated diagnostics.
Deleted-hold tokens aren't reported until the shared withheld-account
bookkeeping lands. Whichever change integrates second must use one emitter for
each count; the deletion fixture pins one emission per key, then none on retry.
The sampled acquisition objects are absent when sampling is null.

Additive version 2 Claude counts on the existing page/check-in carrier classify
refused census-member NotFounds by the **existing immediate-parent metadata
probe**: `claude_absence_parent_missing`, `claude_absence_parent_symlink`,
`claude_absence_parent_not_directory`, `claude_absence_parent_metadata_error`.
Missing includes a NotFound parent or no parent component; metadata_error means
any other probe error. The same four suffixes under
`claude_absence_parent_subagent_` count the subset whose path has an exact
`subagents` component. Fields are omitted at zero, saturate on overflow, and
count refusals, not distinct files. CandidateWalk, CandidateForcedIndex and Open
share these totals; there is no site split. Counts follow the existing scoped
page/check-in accumulation, including cooperative steps, and reset with that
scope. A live non-symlink parent still authorizes removal and adds no refusal
count. Codex/Pi, watcher hints and nonmember candidate losses add none. No new
filesystem probe, event stream, path/key/name output or authority decision is
introduced; diagnostics only, no behaviour change.

The `codex_continuation` stage uses the same version 2 `local_resources`
point carrier, with source `codex` and no CPU/RSS measurement. Each admission
record has `continuation_pages_run` (1 when a prepared page enters the scan
step loop, otherwise 0) and a sparse `continuation_held` object whose single
nonzero count is 1. Its closed reason keys are `roster_changed`,
`context_changed`, `policy_changed`, `group_job`, and `other`. Sum these point
counts over the desired window; they are not persisted process totals.

Roster/context/policy holds occur before prepare or transcript reads. Context
wins if both context and policy changed; missing carried evidence, prepare
errors/refusals and step-admission refusals use `other`. Group refusals are
counted at resume or when a group would otherwise mint (exhausted cursor
budget and accelerated), before taking the job. Ordinary ineligible group
pauses add no continuation hold. A stepped page can
later produce an additional hold record; the two counters are not exclusive.
Timer wakes without a ready page and platform/QoS skips are outside these scan
admission counts. No path, session id, digest, error text or transcript content
is included, and the counts grant no authority.

The `codex_continuation_mint` stage uses the same point carrier and source,
with one sparse `continuation_mint` count: `minted`, `inventory_incomplete`,
`groups_completed`, `no_remaining`, or `over_bound`. Each record counts one
mint decision for a paused, accelerated ticket candidate. Completed joins take
precedence over incomplete/missing inventory. With valid evidence, missing
rotation allowance is `no_remaining`; unknown/over-limit retained layout is
`over_bound`; `minted` means inputs were admitted, before ordinary finish,
contention and cadence may still discard the candidate. These counters grant
no authority and do not imply a continuation page ran. No raw ticket means no
mint decision; authority/lifetime refusals remain outside these five outcomes.

The inventory check performs at most one `lstat` per carried rollout path
(up to 32,768), stopping on the first mismatch. It includes ledger parents and
the held file. Any changed rollout holds continuation, so active Codex sessions
usually leave it idle. Additions wait for the ordinary census; an EOF park that
cannot fit becomes strict StateBound debt for the ordinary pass to disclose,
keeping the prior body rather than emitting a zero replacement.

A `source_finish` record wraps rotation finish, including its validation,
post-policy finalization and upload work. It exists exactly when finish was
called and returned normally, including an error return. It has `counts: {}`
and no result field; outcome reporting and transport receipts remain the
existing outcome owners. Prepare failures, prepare returning no frame,
rotation validation failures before finish, panics, aborts and hard kills
produce no finish record.

Each `snapshot_batch_call` records the actual serialized body length and the
encoded/decoded body lengths across attempts passed to HTTP. Gzip refusal adds
both the compressed attempt and its identity fallback. A refusal before send
adds no attempt; serialization failure leaves the body length `null`. These
are **attempted body bytes**, excluding headers, TLS, responses and library-level
transport activity; they do not prove successful delivery or ACK settlement.
Encoding settings, packing and delivery semantics are unchanged. Upload timing
covers serialization, compression, request/response handling and existing local
receipt processing, including failures.

`shared_process_cpu_delta_us` samples self-process CPU across the observation
window, including concurrent stages; it excludes child processes. It must not
be attributed to one provider. `process_lifetime_max_rss_bytes` is the process's
lifetime memory high-water mark, not a collection/cycle peak or current RSS.
`process_lifetime_max_rss_before_bytes` preserves the start sample when both
samples are available and non-regressing; otherwise it is `null`. A rise
correlates only with a process-wide time window, not allocation ownership.
Unavailable measurements and regressing CPU deltas are `null`. Unix observation
time and process id support comparison with an independently measured matching
process. Never subtract or sum overlapping windows or infer per-stage memory
use: the finish window contains its batch-call windows.

There is one bounded observation per completed page, batch call and normally
returned finish, with two OS resource samples per observation, no per-row
sampling, extra transcript reads or new diagnostic store. Version 2 adds one
record per finish and removes one text line per sampled page; total log writes
are not unchanged. Output is a synchronous best-effort write on the calling
thread under std's stderr lock; errors are ignored, with no retry, queue or
thread. It may block for the duration of a regular-file write, like existing
service stderr lines. Log output uses existing service retention and may be
unavailable; diagnostic write errors do not fail collection or upload.
Status/quota refresh, OTLP reception and independent metadata/discovery work are
outside this measurement slice. Installed comparisons must use the same
source/encoding settings and distinguish idle, ordinary changes, import and
recovery. A containing release and matching installation are required before
calling these measurements installed evidence.

### Durable Store Alarm

A `durable_tail_alarm` record (schema 2 additive) follows a post-save pass
whose durable-store counts for that source changed. Each count is
`[since the last alarm, process total]`: `held_keys` (unknown, newer,
undecodable or unbindable records), `t14_rebuild` (known corrupt records
read Full once and replaced after the save) and `mode_repaired` (store
directory or records restored to owner-only). `store_disabled` appears once,
with `foreign_owner`, `not_directory`, `mode_unrepairable` or `t14_breaker`
(more than max(20, 2%) corrupt records in one pass), when the store becomes
memory-only for the process. While a key is held, its source's census stays
retryable (red) for the whole hold, so census close, retirement and
account-family proof wait for that source; a held key is not yet terminal
disclosed residue.

The `durable_tail` line also carries `store_write_after_save_failed[files]`
(records offered to a post-save batch that returned an error; the store keeps
their predecessors) and **`store_write_failed_restart_full[files,bytes]`
(upper bound)**: Fulls whose restore refused the record as
`ineligible.entry_changed`, with the completed native bytes those Fulls read.
It is not an exact count of write failures. It reuses the existing
`entry_changed` refusal, and no persisted marker records that a write failed,
so it also counts a record that was never offered (deferred or evicted before
the write) and any RAM-miss restore of such a record. Both are process totals.
On the first counted file in a process, a `durable_tail_restart_full_alarm`
record (`store_write_failed_restart_full` `[files, bytes]` and the
write-failure total) is emitted at once, then at most once per 24 h in that
process; a restarted process alarms again on its own first file. The counter
remains the persistent signal. The mark and the alarm time are RAM-only;
nothing is persisted.

An absent record is a restore `missing` outcome and keeps the existing Full
admission; it is not a held key. For Claude, `upgrade_state_missing` counts the
first native read of a previously indexed key that grew while it had no record
(observation only: no hold and no claim ledger); it is zero for Codex.

Claude restore adds R2 transitional counts, each `[since, total]` and each an
alarm when nonzero: `old_binding_no_match` (an unprovable original binding),
`context`, `restore_semantics` and `revision_adoption_required` (stale holds),
`retail_exhausted` (the Tail re-read allowance is spent or its accounting was
lost). Each is one counted Full, taken only on growth past the accepted end and
paced to one per key per six hours through one shared RAM map;
`retail_exhausted_paced` counts growth skipped by that pace. On map overflow the
oldest key is evicted and the read allowed; `pace_evicted` counts it and alarms
separately from the growth counts. `t14_rebuild_full_started` is the process
total of admitted rebuild Fulls. Audit deadlines remain owned by the index,
and the v1 writer takes compatibility debt from the current committed index at
write time, including after a restore dropped the envelope field. Unknown debt
tags, absent-with-nonzero deadlines and present-with-zero deadlines are
`unbindable` holds, preserved byte for byte. A debt-bearing record whose index
entry is absent is a miss counted once by the common acquisition guard as
`ineligible.audit_carrier`, including when sampling admission skips restore.
It does not increment `durable_held` or the held-key alarm. The guard uses the
already classified store header and adds no read. The old reduction is never
restored as audit-clean: normal acquisition reads Full. The validated envelope
deadline travels with that acquisition independently of sampling admission.
Import requires the record's binding context to equal the live namespace/account
digest and clamps the deadline once to min(envelope due, recovery time). Foreign
contexts and malformed/unknown records supply no deadline. A direct restore
carrier check likewise cannot import a foreign context's scheduling authority.
Native parsing creates the index entry; only source-verified Full completion
satisfies the audit and supplies the post-save replacement. Terminal row loss
may publish without verification: the native-created entry then receives the
existing unverified-source marker with the recovered deadline. That marker
survives save/restart and keeps discovery eligible beyond the age window until
a verified Full retires the obligation. No index membership is inferred from a
record, and no persisted field or acquisition cause is introduced.
The production `durable_tail` pass summary emits `ineligible={...}` with static
class names and process-total counts, including
`audit_carrier_staged_unverified:1` after the first staged transition.
`ineligible.audit_carrier_staged_unverified` counts only the successful transition
to the native-created entry's unverified marker; the earlier
`ineligible.audit_carrier` counts recovery misses. A verified-first Full has zero
staged transitions and uses the existing `audits_completed` counter. Later retries
and later deadline offers cannot renew the recovered obligation.
Grouped Codex members, aliases included, take the same live-context, once-clamped
deadline at group job start (not at the preflight hold check); a paused paged job
carries it, while a deferred group recaptures at its later start. At settlement
each member's native-created entry stages the existing marker when the group
publishes unverified; a verified group Full retires each recovered or marked
member through `audits_completed`. Group retirements have no `audits_started`
counterpart (groups never plan a sampled mode), so `audits_completed` may exceed
`audits_started`. A paged group member or singleton that captured no deadline but
has no index entry at settlement (a fresh index loaded while the job was parked)
re-probes the same handoff before recording; the job is not invalidated. The
re-probe only reads the record header: it applies the live-context gate and the
once clamp, but takes no hold, T14 rebuild authorization, breaker accounting or
RAM-corrupt count. A re-probed singleton retired by a verified Full counts
`audits_completed` once, like a captured deadline. Both
carrier counters advance once per settled member, never on preflight or pause.
Post-save GC preserves same-context debt-bearing records whose key is absent
from the index; fresh-index cleanup without a trusted context preserves their
debt evidence too, until acquisition establishes custody. These preservation
decisions keep counting `format_hold.unbindable`. Once the real entry carries
unverified-source debt, GC keeps its same-context predecessor regardless of a
decided scope change until verification permits ordinary replacement/collection.
Proven foreign-context records remain ordinary GC candidates. An existing entry with reset/postponed
debt instead re-arms an immediate index audit and plans Full(`audit_due`), also
recovering an index-new/record-old crash after a successful audit. Direct restore
misses also count `ineligible.audit_carrier`, without becoming held exits.
Re-arming changes no accepted body, witness or ACK; native completion alone can
clear the obligation. No record means ordinary Full-on-miss admission.
The `format_hold` and `durable_held` arrays keep eight slots:
`newer,unknown,undecodable,unbindable,known_corrupt,retired_upgrade_missing,receipt_pending,behind_accepted`.
The retired coordinate (slot 5) stays zero; the removed hold is not restored.
ReceiptPending remains slot 6.

Store header reads for GC (including representation lookup for a decided key)
are counted in `gc_records_read` / `gc_bytes_read`, using actual bytes read;
GC trailer/body verification uses `delete_verify_bytes`. They do not inflate
`guard_header_bytes` / `guard_verify_bytes`. A decided key currently needs two
bounded header reads (each at most 324 bytes); the verification memo avoids a
second full verification. Representation lookup opens only the durable record,
never a transcript. A direct fixture removes the synthetic transcript, rejects
body reads after verification, observes both header accesses and asserts exactly
648 additional GC bytes, no guard/verification bytes and an unchanged record.
These are store bytes, separate from transcript re-derivation bytes. Counters
on the durable pass summary are process totals; `take_pass` store receipts reset
their flows while retaining disk levels. Alarm counts retain the delta/total
contract above.

## Credential File Cap Refusals

Schema 2 adds `credential_file_cap_refusal` point records on the same
`ottto-service: local_resources` stderr carrier. Snapshot device-authority,
destination, promotion-guard and connection loaders count typed device-binding,
file-backed-secret, pending-credential-journal and connection-binding cap errors through the service's existing diagnostic emitter before error detail
is replaced. Both ordinary snapshot sync and retained retry use those loaders.
Core returns typed errors and never emits or keeps counters itself. Metadata rejection before body
allocation and growth past the cap during the bounded read both count once;
oversize invalid UTF-8 counts as a cap refusal before decoding. Other I/O,
JSON, UTF-8 and missing-file failures do not increment this counter.

`counts.file_kind` is `device_binding`, `file_secret`, `connection_binding` or
`pending_device_credential`;
`credential_file_cap_refused` is 1 for this event and
`credential_file_cap_refused_total` is a saturating process-lifetime total for
that kind. Count attempts, not distinct files. Totals include only those observed
snapshot authority/destination loads (including continuation authority), so
`source` is `unknown`; other core
callers are not counted. Never attribute totals to Pi alone or sum cumulative
totals. The observation is a point with
zero elapsed time and null CPU/RSS samples. These records contain no path,
account, secret or content, add no probes or reads, and use the same ignored
stderr-write errors as other local resource records. They remain local and
may be unavailable if logging fails. Native Keychain loads are outside this
file cap and remain in the shared ordinary-path resource domain. A connection
binding read, parse or cap failure now stops endpoint resolution and propagates
before creating a credential-bearing client. Environment/default endpoint
fallback applies only when the binding is absent, never after a failed load.
This applies to every source and composition/footprint/inventory harvest.

## Unreadable Connection Binding

Endpoint resolution also emits a schema-2 `connection_binding_read` point on
the existing `local_resources` carrier with
`counts.connection_binding_unreadable: 1` for each failed binding load (I/O,
parse, UTF-8 or cap refusal). Absent and valid bindings do not count. Cap
refusals also retain the distinct cap event above; these are two causes for
one attempt, not two refused uploads. There is no cumulative total for this
cause. No path, endpoint, account or error text is emitted.

The existing canonical health blocker registry, used by `ottto doctor` and
status, checks endpoint resolution too. An unreadable binding adds the blocking
`connection_binding_unreadable` finding: get a fresh claim code from Ottto Apps,
then run `ottto login --claim-code <code>` to reconnect this Mac and resume uploads.
Plain `ottto login` may reuse a cached connected state and leave the corrupt file
unrepaired; an explicit claim attaches and persists the fresh binding. Human doctor/status output shows the first blocker's
guidance; `--json` retains all findings. The finding clears on the next health projection after
the binding is repaired or removed. Each failed diagnostic check counts as a
load attempt too. This uses the existing health and diagnostic channels; it
adds no background subsystem or upload fallback.
The safe diagnostic names the connection binding and asks to reconnect; it
contains no path or endpoint URL. During owned-scan authority revalidation,
an endpoint load failure remains a local-state rejection.

Claude's supported old-binding migration reports `counts.migration` as four
`[delta, process total]` pairs in this order: held classification, awaiting
reservation save, claimed A5, durably replaced. These are events, not unique
file gauges. `upgrade_state_missing` counts actual first native read attempts
under A5; claiming or saving a reservation alone does not increment it. The
saved release/key spend survives restart. A witness's captured floor remains
immutable for that permission. Completed native output, exact saved selection
and the current-target directory-sync receipt are required to count replacement.

O3 adds a termination path to the existing option (i). Other migration refusals
on real growth use the counted, shared paced `old_binding_no_match` Full, with
no migration/replacement authority and no A5 refund. This includes spent grants,
a shorter current extent, obsolete certificate length, generation-ahead records,
object changes and resource failures. Genuine idle and correctness barriers
(future revision, owed replay, context/namespace or downgrade) stay held.
Fallback counts and pacing are separate from A5 reads and durable replacements.
Generic growth eligibility past the activity window remains an integration
dependency; this migration path does not add a Claude-only discovery exception.
Idle migration files take no body read. A changed object or mtime can require
existing bounded certificate samples before a stale/no-match hold; samples are
counted separately from body I/O and mtime alone grants no real-edit acquisition.

Only O3's negative release/key spends use the existing `reread_guard` wire slot,
under `replayed[upgrade_state_missing:<release>]`. They survive production decode,
partial checkpoints and restart; live grants never survive serialization or an
index copy. Ambiguous or malformed spend evidence refuses migration authority.
The retired generic reread budgets and selection holds remain absent.

Unregistered replay rejected by a Claude binding is still Stale policy. The
existing restore carrier includes its typed `stale_attribution`; this is neither
a generic Miss nor an ACK. `pace_anomaly` reports implausible wall-clock stamps
separately from capacity `pace_evicted`; both are delta/process-total pairs.
Clock anomalies expire the Full pace toward reading without refunding Tail
allowance already spent.

## Line Delivery Counters

Schema 2's `native_collection_page` can add two sparse, counts-only objects.
They add no wire fields, persisted state or transcript reads, and contain no
paths, identifiers, hashes or line content. Missing keys mean zero in that
observation; an absent object also means zero, or a page line that was not
written. Counts saturate at `u64::MAX`.

`counts.line_delivery` is keyed by the fixed name of the page's one registered
line observer, for example `{"footprint": {...}}`. The observer receives the
physical lines the page's primary reads already consumed; proof, parent, side,
group, native-comparison and one-shot reads deliver nothing. All values are
page events, not gauges, and are never summed across observers:

- `lines`: newline-complete physical lines delivered, including blank,
  malformed, invalid UTF-8 and overlong lines. An unterminated final record is
  not a line until its newline arrives in a later read.
- `bytes`: physical bytes of those lines, newline and skipped overlong bytes
  included. These are bytes the read already consumed, never extra reads.
- `incomplete`: files whose delivery ended before their read completed: removed
  unfinished by a hold or refusal, a read failure, a paged job pausing, or the
  page ending or being dropped mid-file. A file the observer skipped is not
  counted. A later page can count the same file again.

`counts.line_delivery_unselected` counts discovery skip decisions for the
page's source: `age` (outside the backfill window and not held for
verification) and `size` (over the source's file-size cap). They are recorded
after the existing decision, are drained by that source's next completed page,
and count repeated decisions, not distinct files or bytes. They are recorded
whether or not an observer is registered.

## Context Footprint Discovery

Context footprint opens no transcript. Its workspaces come from the cwds of
the Claude lines snapshot sync's primary reads already delivered to the
`footprint` line observer, kept in RAM only (no transcript path, nothing
persisted). Coverage follows that read:

- After a daemon restart, only files read since then are known; a workspace
  idle since the restart is not proposed until it is used again.
- An org backfill window of 1-13 days narrows footprint's 14 days to that
  window; 0 days leaves almost no history.
- While reconciliation is off, Claude is disabled for the source or snapshot
  sync is down, nothing new is delivered; files already known stay usable
  until they age out of the 14 days or are evicted.
- Claude files over 256 MiB are never delivered, and a cwd only on a line
  over 16 MiB is not seen.

Each footprint cycle's `context_footprint_harvest_metrics` line adds these
counts, with no paths or values:

- `discovery_path_scopes` (this cycle): workspaces scoped by their own path
  (no repository, or a repository probe that failed).
- `footprint_observer_files`, `footprint_observer_bytes` (now): files held and
  their charged RAM (cwd allocations plus a fixed per-file slot), capped at
  4 MiB with at most 8 cwds per file.
- Since daemon start:
  - `footprint_observer_passes`: snapshot-sync Claude passes that registered
    the observer. 0 means no delivery reached footprint.
  - `footprint_observer_evicted_files`: files dropped at the cap, oldest
    modification time first.
  - `footprint_observer_cwd_dropped`: cwd values over 4 KiB, not kept.
  - `footprint_observer_incomplete_files`: each delivery that ended before
    its read completed, plus the first appended or unchanged read of a file
    whose earlier lines this process never saw (restart, durable restore or
    eviction). That second count repeats only after the file stops being held
    (evicted, aged out or without a modification time). What was delivered is
    kept.

## Private Codex Census Outcomes

The support-root `snapshots/codex-fenced-census-v1.json` file now uses schema
`local_fenced_codex_census:v3`: bounded completed-page scan/index aggregates plus
producer PID/version, optional kernel start seconds/microseconds, attempt sequence
and observation UTC. A separate `snapshots/codex-fenced-census-outcome-v1.json`
file records only the last non-success outer/inner outcome and actual invalidation.
Census v3 adds a fixed eight-category unreadable-event histogram, an explicit
unattributed remainder for old traversals, and existing terminal-loss shares.
Categories identify the original failing branch, not an OS diagnosis or distinct
files; see [branch attribution](session-2026-10-12-codex-unreadable-causes.md).
The census remains limited to 8 KiB; the sidecar to 1 KiB. Healthy attempts add
no sidecar write or unlink. Both are owner-only disposable atomic caches without
fsync, excluded from public status, upload DTOs and diagnostics bundles.

These files are structural diagnostic evidence, not health, current account,
delivery, checkpoint or ACK proof. A separately scoped reader needs matching exact
PID/start tuples before and after, image continuity, freshness and attempt ordering.
Unavailable identity, equal-attempt contradiction or foreign-current writer evidence
gives UNKNOWN; files show last persisted, never latest executed. See the
[carrier contract](session-2026-10-11-codex-census-outcome-carrier.md) before interpreting
either file. This adds no reader, runtime repair or installed acceptance.

## Approved Upload

Upload only when the user approves the upload and accepts the retention
disclosure. An active login or support claim is required:

```bash
ottto diagnostics collect --upload \
  --approve-upload \
  --accept-retention-disclosure \
  --support-claim <claim> \
  --json
```

If the user is already logged in, a support claim may not be needed. Follow the
JSON `upload_report` and next-action fields.

Support claims are authorization material. They are sent only on the upload
request and must not appear in the returned JSON payload or uploaded bundle
content; the JSON report exposes only whether a support claim was provided.
Stable local identifiers, including machine ids, must appear only as redacted
placeholders such as `[machine_id]` in diagnostics output. Account, user,
organization, device, and installation identifiers must follow the same
redacted-placeholder rule.

## What To Share

Share:

- command family;
- exit code;
- high-level status;
- support bundle id or uploaded state;
- next user action.

Do not share raw local paths, prompts, account ids, machine ids, credential
material, cookies, or command output. Also keep raw user, organization, device,
and installation ids out of diagnostics summaries and support handoffs.

## Upload Receipts

An upload receipt is a local, bounded record of one snapshot batch attempt and
the backend acknowledgement, when one was returned. Use receipts to confirm
when a source uploaded, how many entities the backend accepted, and whether the
backend shed, rejected, or partially accepted a batch:

```bash
ottto receipts --limit 20
ottto receipts --json --since 2026-09-10T00:00:00Z --source codex
```

The daemon keeps at most 500 receipts. Public receipt output replaces source
session ids with a 12-hex SHA-256 prefix and limits snapshot fingerprints to
12 hex characters. Raw source session ids are never stored in receipts.
Request bodies, authorization headers, tokens,
and raw backend rejection details are not included. `device_label` and
`account_binding` use only the user-facing label and binding state already
shown by `ottto status`; raw device, account, user, and organization ids are
never stored. If `server_request_id` is present, provide it to support so the
local attempt can be correlated with the server request. Older backends may
omit the optional `X-Request-ID` header, in which case the field is `null`.

```json
{
  "schema": "ottto.upload_receipts.v1",
  "receipts": [
    {
      "uploaded_at": "2026-09-10T02:54:21Z",
      "outcome": "accepted",
      "http_status": 200,
      "server_request_id": "req-server-01HX",
      "retry_after_seconds": null,
      "source": "codex",
      "device_label": "Test Mac",
      "account_binding": "connected",
      "batch_item_count": 1,
      "accepted_count": 1,
      "accepted_entities": [
        {
          "source_session_id_hash": "7d96706e12ab",
          "snapshot_fingerprint_prefix": "abcdef012345",
          "occurrence_count": 1
        }
      ],
      "unchanged_entities": [],
      "conflict_entities": [],
      "rejected_entities": []
    }
  ],
  "ring_capacity": 500,
  "state_path_present": true
}
```

The private, owner-only receipt file may additionally retain content-free
request-specific ACK evidence after the existing validator succeeds. This
annotation contains full semantic fingerprints and body-witness hashes,
one-way session/destination identifiers, hashed head references, occurrence
counts, uploaded cache-patch presence, two numeric usage scalars and explicit
retained-coverage limits. It shares the existing ring's 500-receipt and 4 MiB limits and retains at most 50 entity records per receipt.
It is excluded from public receipt output, local-control responses and
diagnostics bundles. Raw head tokens, session ids, request bodies and
credentials are not retained.

An HTTP success receipt alone does not prove that a request-specific ACK
validated. Even a validated ACK does not prove that local checkpoint saving,
backend publication or customer-page freshness completed. Legacy count-only
responses and missing or truncated proof remain explicitly unproved; private
evidence is diagnostic and never authorizes delivery or a retry.

## Provider Requests

The daemon keeps a local log of every call it makes to OpenAI and Anthropic:
quota reads, sign-in and login-refresh runs of the provider CLIs, Codex cloud
task listing, Codex daily usage totals, and Verify smoke prompts. Use it to
count those calls per day and see why they ran:

```bash
ottto provider-requests
ottto provider-requests --json --since 24h
```

Each call is one JSON line in `provider-calls/YYYY-MM-DD.jsonl` (UTC day) in
the Ottto support directory, readable only by the user:

```json
{"v":1,"at":"2026-10-15T12:00:00Z","provider":"openai","kind":"codex_app_server_quota","trigger":"schedule","account":"01234567","result":"ok","duration_ms":1250,"basis":"subprocess_lower_bound","requests_at_least":2}
```

- `provider` is `openai`, `anthropic`, or `unknown` for a model request whose
  provider the daemon cannot tell (the Pi smoke prompt on Pi's default route).
- `trigger` is `schedule`, `explicit_refresh`, `older_app_compat`, `setup`,
  `startup` or `other`. A person's Verify is `setup`; the first status pass
  after the daemon starts is `startup`, and the first pass after the Mac wakes
  is `schedule`.
- `account` is the first 8 hex characters of the account identifier hash, or
  `unknown`.
- `result` is `ok`, `http_<status>`, `timeout`, `exit_<code>` or a short
  error class.
- `basis` is `observed` for an HTTP request the daemon made itself (one
  request), or `subprocess_lower_bound` for a provider CLI run, which makes at
  least `requests_at_least` requests the daemon cannot see. Requests count
  when sent, answered or not; `result` shows how the call ended. A Codex quota
  read through `codex app-server` that started counts two (a token refresh and
  a rate-limits read), or three with the detailed read, even when it fails or
  times out. A sign-in counts one once a code was submitted.

Lines never contain tokens, URLs, prompts, emails or provider responses. Days
older than 7 are deleted. A day holds at most 30,000 lines and 8 MiB, and the
directory at most 32 MiB; a day that reaches its bound ends with one
`log_full` line and the summary marks it. Logging is best effort: it never
fails a provider call, and a line it cannot write promptly is dropped.

## Claude Relay Endpoint Mismatch

When the relay is connected but approved Claude telemetry settings name a
different loopback port, `ottto doctor` reports both ports. `ottto status --json`
and `ottto doctor --json` expose `relay.last_error.code` as
`claude_relay_endpoint_mismatch`; `relay.state` remains `connected`. The
`claude_local_evidence` diagnostics section includes the same finding.
Canonical local health carries it as a `Warning` blocker with the same code
(owner `source`), so the machine reads `degraded` and the existing machine-health
upload reports it to Ottto the same day. Its uploaded text carries no ports.
To avoid flapping on a restart or rebind, the finding and blocker appear only
once the same mismatch is seen again at least 60 seconds after first sight; the
first agreeing check clears both. The support diagnostics item is not delayed.

This compares current approved settings with the daemon's listener state; it
does not probe exporters or prove that a running Claude process reloaded its
settings. It clears when ports agree or Claude telemetry approval is absent
or disabled. It does not rewrite settings or change account identity.

After a listener failure, the relay re-reads approved settings on each retry
and tries an approved candidate port up to three times using its existing
capped backoff. If all three attempts fail, recovery immediately uses the
old-port, default-port and per-user fallback order so control, health and all
OTLP sources can serve again. A busy approved port can then produce the mismatch
finding above. Without an approved candidate, the fallback chain applies immediately.
Startup retains its existing behavior of falling back if the approved port is
busy.

## Common Diagnostics Flow

```bash
ottto status --json
ottto receipts --json --limit 20
ottto doctor --json
ottto diagnostics collect --json
```

If support requests an upload, rerun with the upload flags after the user has
approved the disclosure.

## Checkpointed Hold Settlement Total

The checkpointed-upload log includes a process-lifetime count of settlement
decisions for Rejected pages with non-progressing, restorable local holds.
Recorded Claude account holds are included. It increments before the index
save, so it does not count durable-save successes or unique pages; restarts
reset it. See [counter scope and hold semantics](session-2026-10-22-terminal-bound-hold-settlement.md).

## Prior Held Family Observation

A `bounded_traversal_transition` row with `event: starting` includes
`prior_held_family_roots` and `prior_held_family_set_digest`. For Claude, a
known valid persisted `claude_full_rearm_progress.held_family_roots` scope
reports its count and the first 16 lowercase hex characters of SHA-256 over
its sorted, concatenated, fixed-width canonical root digests. Only those
already-persisted digests are hashed; no raw root, identifier or path is read
or emitted. Equal observations suggest the same held-family set, subject to
truncated-hash collisions; they do not prove the same individual entity.
Unknown, empty, malformed or over-cap scopes, and other sources, report count
zero and a null digest. Null does not prove the absence of holds.

This local diagnostic observation adds O(held roots) work per start, constant
scratch space and no persisted state. Hold-reason observation below uses the
existing classification/commit branches, without another index scan. Both
observations stay local and never enter wire payloads or uploads. The reason
counters are counts-only; the set digest is a content-free aggregate of
canonical digests, not collected content.

## Claude Re-read Attribution Counters

Schema 2's existing `native_collection_page` and `native_comparison_decision`
records can include two sparse, counts-only objects for `source: claude_code`:
`counts.claude_reread` and `counts.retained_cache_page_events`. Missing keys
mean zero events in that observation. Counters saturate at `u64::MAX`. They
add no wire fields, collected data kinds, persisted state or transcript reads.
No paths, identifiers, fingerprints, bodies or content are emitted.

Collection counters cover initialization and all cooperative steps of one page,
including steps before a pause or a move to another worker thread. Comparison
counters cover preparation (including load normalization) and post-collection
finalization/save. These are disjoint event intervals: sum their events for the
page; neither object is a gauge or a count of distinct files across pages.
Nested operations, other sources and other threads cannot contribute to the
active interval. Abandoned collection pages have no completed collection line.
With comparison disabled, the existing `disabled_before_lease` decision still
reports the gate; additional rows on that same decision stage report nonzero
preparation/save events after work, without creating a comparison permit.

A due terminal that skips whole-index re-arm can additionally emit
`counts.rearm_veto_ignored`, a sparse object with the closed keys
`withheld_account`, `evidence_gap`, `requests_refused`, `identity_refusals`,
`invalid_rows`, `duplicate_rows`, `client_mismatch`, `multi_root_claims`,
`proof_failure`, `reconstruction_failure`, `missing_inputs`, `rebuild_failure`.
Each observed reason increments once per skipped terminal, including reasons
accumulated on earlier pages of that census window. This is the canonical
selected refusal, not every hypothetical failure in malformed evidence.
Nonterminal, non-due and re-arming passes do not increment these counters.
`counts.rearm_fingerprints_preserved` counts nonempty Claude file fingerprints
that survive every independent clearing condition on those skipped terminals;
already-empty or independently cleared entries are excluded. It is not a count
of distinct files across terminals. Window changes reset the process-local
reason mask; the existing page scope/merge carries published counts.

These are scheduling diagnostics, never proof or attribution. Request refusal,
identity refusal, proof, input-consistency and rebuild classes can read native
facts as well as telemetry. Native transcript duplicates retain a structural
veto even under an unrelated invalid family. A stable native copy keeps vetoing every due terminal by design.
`counts.rearm_structural_native_duplicate` counts due closed-fence terminals
where this native-duplicate veto is present (other vetoes may coexist). It is
sparse, saturating and count-only. Unique appends, unique new sessions/members
and routine census retirement do not enter a scheduling projection: no such
projection is added. Telemetry duplicate rows/multi-root claims alone do not
activate this native veto. Strict loader/read-health failures remain retryable even when their malformed rows would also fail a
semantic reducer. No extra reader, output stream or persisted diagnostic state
is introduced.

The three terminal scheduling fields (`rearm_veto_ignored`,
`rearm_fingerprints_preserved`, `rearm_structural_native_duplicate`) are emitted
only on the existing `native_collection_page` carrier. The fold follows scan
collection, so a terminal with nonzero scheduling counts emits an additional
row with `scanned_files: 0` and `semantic_noops: 0`. This row reports only the
terminal delta; it does not drain identity, money or record-cap observations.
The comparison carrier omits these fields to avoid counting them twice. Sum
counters rather than treating diagnostic row count as a page/file count.

`claude_reread` contains these closed keys:

- `restored_empty_held`, `restored_nonempty_held`, `restored_empty_sibling`,
  `restored_nonempty_sibling`: `committable_subset` replaced a working entry
  with a nonempty parsed source fingerprint by its previous entry. Empty versus
  nonempty describes the **previous** fingerprint. Held means a decode hold or
  an entity/head in the caller's local hold set; sibling means neither. Existing
  empty working debt and keys without a previous entry are excluded. A restored
  previous nonempty fingerprint can equal the working fingerprint.
- `held_reason`: sparse counts under the closed labels
  `authority_unbound_revision`, `authority_correction_pending`,
  `account_hold_unrecorded`, `not_restorable`. The first three count held
  snapshots in the existing progress-blocking classification: missing or
  mismatched revision/witness evidence or an invalid/unbounded authority record
  (including failed contract, fingerprint-shape, failure-count or deadline
  checks); a RetryPending record with a correction grant; or an account deferral
  without its durable disclosure. The correction
  label wins when that branch rejects the record before checking its witness or
  member revision. Missing revision or record/witness pair is unbound.
  `not_restorable` counts completed commit attempts whose non-progress-blocking
  holds fail the existing restore check, once per attempt, not per file.
  Bound authority holds and recorded account deferrals add no reason. These
  counts sit beside the restore counters but are not a partition of them:
  snapshots, file keys and commit attempts have different units. They change
  no hold, selection, money, census, checkpoint or upload decision.
- `sibling_exact_incidence_only`: subset of sibling restorations rejected by
  the early exact-entity incidence branch whose legacy head/equality fallback
  would have admitted them. This records the branch, not proof of settled body
  equivalence, acceptance or permission to advance the checkpoint.
- `owned_start_calls`, `owned_start_cleared`: corrective owned-start reparse
  clear calls and actual nonempty-to-empty transitions.
- `account_reproof_calls`, `account_reproof_cleared`: invalid account witness
  reproof clear calls and actual nonempty-to-empty transitions.
- `retry_admission_offered`, `retry_admission_cleared`: existing indexed members
  in the actually offered oversized-family contiguous prefix, and actual
  nonempty-to-empty clears.
  This family reserve is distinct from the transcript file byte cap.
- `authority_normalization_cleared`: nonempty-to-empty transitions while dropping
  unbound authority records on working load/save. Discarded CAS probes are
  excluded, matching the existing authority-drop totals.
- `history_permitted_not_stamped_not_accepted`, `_telemetry_unread`, `_held`,
  `_other`: upgrades the history gate permitted on this page that did not stamp
  the active revision. `not_accepted` stamped but a partial save kept the
  committed entry; `telemetry_unread` and `held` were held after the permit
  (unread telemetry; the stop latch); `other` finalized below the active
  revision for any other reason (incomplete parse, decode or local hold).
  These concern the history-upgrade gate, not request identity.
- Removed with the identity permit (contract 5 always on): the gauge
  `stamped_without_permit`. The local money mark it counted
  (`STAMPED_WITHOUT_PERMIT`, 64) is no longer set or cleared; stores that carry
  it keep decoding it, and nothing reads or replays it. Files stamped while the
  permit was off are not re-read for identity: they gain identity tags on their
  next real content change. User effect: such sessions may show no
  subscription until then.

`retained_cache_page_events` reuses the existing cache lifecycle event keys and
sites: `take_*`, `insert_*`, `cursor_reservation_entries_evicted`,
`copy_refusal_*`, `clear_*`, `retention_*`, `prefix_excluded_bodies`, and
`prefix_tag_clears`. Unlike `process_retained_cache_lifecycle_totals` (which stays
cumulative, cross-source and labelled `unknown`), these are exact deltas from
operations executed by the Claude page. Eviction/clear counts describe the
causing page, **not** the source of each victim in the shared cache. No victim
identity/history is retained. Existing refusal causes include entry/key/frozen
charge, layout/disabled, live reservation, missing/invalid plan, incomplete or
lossy reduction, unsealed EOF, clone/finalization bounds and poisoned locks.

Three additional page-only keys refine those existing sites:

- `insert_count_entries_evicted` and `insert_byte_entries_evicted` partition
  `insert_entries_evicted`: each victim counts as count pressure when the count
  cap is exceeded before removal, otherwise byte/layout-bound pressure. Entry
  bound refusals remain `insert_entry_bound_refused`; they are not evictions.
- `reinsert_failed`: one destructive cache hit whose acquisition ends without a
  successful reinsertion, including eligibility/prepare/parse/retention failure
  and refused insertion. A fixed boolean follows the active read across steps;
  it stores no identity and disarms only after admission. Events are recorded
  when that attempt ends, potentially on a later cooperative step. Process
  termination cannot report an unfinished attempt.

All diagnostics are best-effort local stderr observations. Their counters never
feed collection, proof, save, memory admission, account attribution or upload
decisions. Scopes and counters use fixed integers and inline storage, with no
new locks, heap allocations, event history, lookups or background work.

### Stale-start carry rejection histogram

By design, `stale_carry_rejection_counts` rides the plain census re-arm stderr
line, separate from the `local_resources` records.

The existing local text line beginning `local snapshot census re-armed stale
Claude request evidence:` appends `stale_carry_rejection_counts={...}`. This is
**a text-line suffix**, not a new `local_resources` field or a wire field. The
JSON object has eleven fixed `u64` keys, including explicit zeros:

- `provenance_or_context`: retained provenance rewind or missing same-context
  admission prevents this carry route. Valid legacy full-rearm-window carry
  remains eligible through its existing separate route.
- `contract`: missing identity contract or its changed latch.
- `accepted_ledger`: accepted ledger version/reconciliation is not current.
- `upload_context`: retained and active upload context differ.
- `window_scratch`: active full-rearm window's combined Fix 2/C1b scratch price
  refused, selecting the existing empty-carry fallback.
- `ordinary_scratch`: selected ordinary carry scratch or streaming structural
  admission refused.
- `member_evidence`: membership, body/ACK, pending, legacy/fence or evidence
  qualification refused after earlier route admission.
- `cancellation_funding`: the selected cancellation price refused.
- `reserve_allocation`: an actual member/replay vector reservation failed.
- `eligible_before_funding`: roots that passed member/evidence qualification
  before the selected route's cancellation reservation. Streaming pre-prices
  cancellation before member qualification, so an early refusal can have zero
  observed eligible roots; this is not a claim that no root could qualify.
- `final_carried`: final carried roots after both cancellation funding passes.

Counts are captured immediately before the existing stale-start fingerprint
clear and appended where the existing re-arm text line is emitted. A resumed
page, cadence wait, or start that emits no such line adds no log write or JSON
serialization. These fixed counters add no retained graph, root history or
extra source walks. Structured traversal-transition rows and their size budgets
are unchanged. Integers saturate; no tokens, paths, sessions, hashes or content
are included.

Each stale root has one first rejection on its selected route or a final carry:
the nine rejection buckets plus `final_carried` sum to the line's pending-family
count. Window scratch is checked before entering ordinary carry; within an
ordinary start-admission refusal, precedence is context, contract, ledger,
upload context, then remaining legacy/member admission. A successful streaming
alternate rescues ordinary scratch refusal. Failed whole-set/batch probes are
discarded when a smaller batch succeeds; uncovered/deferred roots retain the
first whole-set capacity refusal, while selected roots use their actual outcome.
An existing admission cursor's whole-set deferral counts as structural scratch
refusal. This describes carry admission, not unique families over multiple
starts, proof completeness, actual rereads, or permission to change checkpoints.
Capped roots retain their earlier carry rejection and cannot be counted again
if the final combined cancellation funding refuses them.

### Claude Contract Debt Counters (schema 2 additive)

The existing `native_collection_page` / `native_comparison_decision` carrier
also includes sparse, counts-only `identity_contract_transition`
(`from_empty`, `to_empty`, `collector_e2_grouping`, `mid_traversal_placeholder`)
and `identity_contract_latch` (`set`, `cleared`). The existing synchronous
preparation, collection and finish scopes own these deltas: merge disjoint
scopes, never sum a repeated scope twice. Relay-token and activity-hint errors
retain the last contract and reach the existing early decision/unwind carrier,
including when no page is collected. There is no new event stream or wire
check-in payload.

Contract 5 is always on for Claude Code: every Claude cycle captures markers
and builds identity evidence, and the activity hint's
`session_request_identity_contract` token is decoded but never read. The
per-cycle `request_identity_permit` counters (`permitted`, `denied`,
`fetch_failed`, `hint_failed`) are removed with the permit. A Claude cycle
always records the full contract, so `to_empty` no longer occurs; `from_empty`
counts the one transition of an install that ran without the permit. That
transition sets the latch but re-owes no history. Its latch re-arms at one
complete census terminal only (the first one under the recorded contract
behind a fence that stays closed; persisted as the full-rearm progress's
`contract_cutover` state; census, evidence-gap or restart flips never repeat
it), and that terminal's structural record carries over to the new contract,
so the cutover forces no whole-index re-arm. `contract_cutover_rearm` (`runs`,
`files`, `bytes`) counts that terminal and every family file it re-armed (an
upper bound: the count includes files that other rules re-arm at the same
terminal).

Transitions count observed state changes, not repeated observations of the same
placeholder. `mid_traversal_placeholder` counts entry into and exit from a
placeholder, including recording the actual contract at a genuine start.
`set` / `cleared` count in-memory false-to-true / true-to-false observations;
a partial save can retain the durable latch through its existing OR rule.
Decode containment setting the latch is outside these observation counters.
`deferred_by_contract_debt` counts finally funded families once per traversal
start, summed only when multiple starts occur in one page. Deferral keeps
correction debt and the old census window; it grants no current projection,
identity, ownership or duplicate-fence proof. Unknown or sweep-wide settlement
debt refuses deferral. The upload-context mismatch veto remains unchanged.

`traversal_context_change` counts comparisons with the process-observed retained
traversal's start: `backfill_changed`, `active_upload_context_changed`,
`policy_changed`, `attribution_available_changed`, `attribution_epoch_changed`,
`cache_capability_changed`, `replay_changed`, `roots_changed`. Each comparison
may increment multiple components. The first observation in a process, an
unobserved retained traversal and an unavailable component are unknown and
increment no change counter. Epoch differences require both epochs available;
availability has its own counter. Ordered roots are compared through a
domain-separated SHA-256 digest with length-prefixed normalized path bytes, so a same-count
replacement or reorder counts. Diagnostics retain no root paths.
`root_count` is the most recent comparison's gauge, including zero. These process-local observations do not
persist or affect decisions; no roots, paths, keys, namespaces, hashes, token
values or body contents are emitted.

The deferral count includes newly classified storage-only singleton deferrals;
those retain custody without granting carry or proof. Under contract debt the
existing stale-carry `contract` rejection bucket also includes member-evidence
refusals. While a placeholder is stored, a contract change cannot be
classified into `from_empty`, `to_empty` or `collector_e2_grouping` from that
unknown prior contract.

Retained Pi retry authority also binds the original client's API endpoint digest.
An endpoint-only transition refuses before relay-token acquisition and batch
submission, even if device credentials and the account witness stay unchanged.
The digest is RAM-only authority and is never emitted in diagnostic records.

### Restore Provenance (schema 2 additive)

Completed `native_collection_page` records can include
`counts.full_causes.restore_outcome`. Counts are saturating u64 values,
scoped to that page's attempted durable restores. A resumed scan keeps its
counts until the page completes. This is separate from process-lifetime
store/write/GC totals, which remain on the existing `durable_tail` line;
restore-class totals on that text line are retired.

| Field under `restore_outcome` | Unit / meaning |
|---|---|
| `restored` | Restore returned a charged, retained reduction. |
| `held` | Restore's existing integrity guard returned Held. |
| `pending` | Restore yielded for active funding or a quiet resource refusal; no successful restore or read permission. |
| `miss.<class>` | Restore returned no retained reduction, with the class below. |
| `stale.<reason>` | Claude restore kept the accepted body stale: a typed, content-free reason from the original-binding proof or restore semantics (for example `old_binding_no_match`, `context`, `restore_semantics`, `revision_adoption_required`, `descriptor`, `accepted_floor_missing`). Growth past the accepted end may take the paced counted Full on the `durable_tail` alarm. |

Zero fields and an empty `full_causes` block are omitted. An absent miss
class means zero attempts of that class, not a disabled store.
`sampled_acquisition: null` retains its existing unavailable meaning.
A pre-acquisition guard hold is not a restore attempt and adds no count here.
Retries count again; a cooperative yield does not recount a completed decision.

Miss keys are fixed, content-free class labels. Dots below are part of the
JSON class key, not extra nested objects:

- `unavailable`, `no_entry`, `missing`;
- `resource_full.{decode,cache_transit,stores_unavailable,input,cache_key,certificate_scope,rederive_unfunded}` records a growing-file resource refusal returning an ordinary Full miss; it grants no independent read permission;
- `ineligible.{selection_cleared,history_owed,source,key,context,scope,generation_ahead,entry_changed}`;
- `refused_record.{newer,unknown,undecodable,unbindable,corrupt,receipt_pending}`, `corrupt_body`;
- `certificate_refused.{replaced,shrunk,same_size_edit,head_changed,boundary_changed,invalid_checkpoint,read_error}`;
- `not_rederived.<field>` preserves the existing codec's static field/class
  labels, including `SnapshotAccumulator.title` and `compressed`; these are
  code field names or representation classes,
  never filesystem paths or transcript values;
- `unregistered_replay.{body_witness,money_rule}` attributes a scope miss
  only when the current replay lever has no registry row and replacing that
  lever with a registered value reproduces the record's scope. Unattributed
  changes remain `ineligible.scope`. Registered audit rows cover body witness
  r3 and money rules v1/v2; they grant no new replay.

A disabled store reports `unavailable`, while an absent record in a usable
store reports `missing`. Sample reads cut short by concurrent truncation report
`certificate_refused.shrunk`. Other sample I/O errors are
`certificate_refused.read_error`, never evidence of a real edit. This precursor
changes diagnostics only: it adds no Full-admission policy, new body reads, persisted fields, record grants, or integrity holds.
Capacity/availability retain their existing degraded behavior. Full-cause
admission and its other counter projections arrive in subsequent slices.


## Compressed Codex reader refusals

The existing `local_resources` carrier emits stage `codex_zst_refused` with
`counts.codex_zst_refused{cause}`: a sparse map containing the incremented,
saturating process-lifetime counter for that cause. These count refused attempts,
not distinct sessions, decoded bytes or money. No path or session id is included.

| Cause | Unsupported boundary |
| --- | --- |
| `CompressedReplayNotAuthorized` | Tail/protected-tier replay reopen |
| `CompressedProofParentUnsupported` | Proof parent reader |
| `CompressedProofChildUnsupported` | Proof child reader |
| `CompressedParentSideUnsupported` | Parent side acquisition |
| `CompressedDurableTailUnsupported` | Durable certificate restore and rederive |
| `CompressedGroupProbeUnsupported` | Group ordering probe |
| `CompressedGroupReadUnsupported` | Initial member, member swap and legacy tee |
| `CompressedParentLedgerUnbound` | Parent identity without archive ledger binding |
| `CompressedPhysicalOffsetUnsupported` | Physical acquisition, cursor and memo offsets |
| `CompressedHeaderUnfunded` | Temporary header inventory/dependency refusal |
| `CompressedCompatibilityUnfunded` | Temporary compatibility/plain-parser refusal |
| `CompressedAdmissionRefused` | Transient decoder reservation or singleton yield |

These refusals authorize neither discovery nor a decoder. A refusal publishes no
empty or zero-cost replacement body: previous accepted output remains stale, or
usage remains unknown. Raw bounded samples of compressed physical objects remain
legal identity observations; they establish no decoded-offset certificate.

A paid compressed-input decoder reserves the existing SharedCache credit under
retained → cursor before taking the durable Stores leaf lock. It keeps an
fixed admission floor (one 8 MiB primary entry plus side-ledger bytes) free
for primary Tail reads; admission never evicts or charges retained bytes twice.
Only one paid decoder is live per process, with the existing 2 GiB decoded cap.
A short reservation or busy singleton yields `None`, counts
`CompressedAdmissionRefused` on `codex_zst_refused`, and changes no acquisition
evidence. Callers disclose the yielded file in the unreadable census.

On close, `codex_zst_input` on the #799 carrier reports consumed
`codex_zst_compressed_bytes`, produced `codex_zst_decoded_bytes` and decoder thread
`codex_zst_cpu_micros`, including failures. There is no content or path in these
counts. Callers close the decoder and explicitly release after Stores drops.
Fallback Drop release counts `codex_zst_owner.counts.leaked_release`; it is a
cancellation/unwind safety net. Stores-held debug assertions guard admission and
explicit release, including real durable I/O paths.

Pi joins the shared sampled RAM reader. Its `native_collection_page` acquisition
counts report Full, Tail and Unchanged decisions with the actual planner reasons.
Pi inherits the accepted sampled residual: an interior same-length rewrite plus
growth can Tail a stale prefix until the next Full; Pi's writer is append-only,
and its header rewrite reads Full.
Age and clock changes do not invalidate checkpoints. Admission of a new sampled
obligation follows the shared audit cap: with no slot left, an unmarked change
reads a counted cap Full (or waits); already-marked files keep Tailing.
Until Pi durable records are enabled, an already-indexed file that changes
without a RAM reduction still reads Full: the transitional `pi` leaf in
`retained_cache_page_events` counts that attempt once at read start, alongside
`state_missing`. A newly discovered file's first Full read does not increment
that leaf. A no-RAM-copy cap Full on a changed indexed file can increment both
`pi` and `audit_cap_full` for one read. Audit, upload-context and other non-content
reparse reasons do not increment `pi`; a change that an earlier gate (such as a
due audit) selects first is counted under that reason, not `pi`. After a restart or eviction, an idle Pi
file whose 1 h verification marker falls due is read once (audit); Pi-b2's durable
record removes this. The verified Full retires the marker without re-staging it.
This is a staged exception; it does not turn a cache miss into a first-read
authorization.

The same #799 page line (source `pi`) reports cache-only
`retention_bound_refused_pi` events and `retention_bound_refused_pi_bytes`:
the completed reduction's measured allocation charge, summed across refusals.
`retention_bound_refused_pi_bytes_unavailable` counts refusals whose charge could
not be measured; zero bytes with that count is unavailable, not a zero-sized
copy. These counters do not mean a durable write was attempted or refused.
`cache_evicted_by_pi_claude_code` and `cache_evicted_by_pi_codex` count respective
insert-time capacity victims (excludes `Release::CopyAdmission` releases).
They also appear on the existing
`process_retained_cache_lifecycle_totals` line (source `unknown`): cumulative,
saturating process totals since startup, shared across namespaces. They are
counts and bytes only, with no file names, response ids or content.

The tag-1 audit-safe bootstrap core is a hard release pair with the grouped
custody and stored-representation binding completion. The first part preserves
main's narrower current-representation binding formula. Grouped Codex members
still have main's index-reset recovery gap there; the paired completion closes
it for every member/alias. Both parts must ship in the same release, in order;
the first is not a standalone recovery-complete release.

## Codex ownership-incomplete causes

The existing `snapshot terminal_census source=codex` line appends nonzero,
count-only `ownership_incomplete_contributions{bucket="<name>"}=<count>` fields.
The labels are closed: the six causes below and `unattributed`, emitted last.
Omitted new fields mean zero in their stated scope. Existing fields keep their
order; no paths, ids, tokens, membership, distinct counts or cap flags are emitted.

Contributions reset at the generation-start marker (`ownership_incomplete_generation_start`).

**Buckets count CONTRIBUTIONS, not distinct files.** Contributions are
generation-cumulative, restart-retained, the same unit as scanner S in
`ownership_incomplete_files`. Both the scalar and buckets are generation-cumulative;
repeated selections, memo replays and holds contribute again. Compare totals across
generation starts: growth means new work, stable means the same work recurring.
This is a contribution comparison, not proof that particular paths are identical.
`unproven_terminal` (U) and any existing account-deferred term added to the public
scalar remain separate from S and the bucket partition.

**First-match precedence: exactly one bucket for each existing scalar addition:**

| Order / bucket | Matching site and contribution unit |
| --- | --- |
| 1. `inventory_hold` | Compound A1/group-preparation refusal: group member count. Incomplete-inventory remaining-singleton clear: remaining candidate count. |
| 2. `other_group_receipt_legacy` | Strict group member count; one per terminal member disclosure or failed tier replay candidate; receipt-cap alias members (minimum one); incomplete joined-replacement alias members; distinct affected keys per legacy-hold invocation. |
| 3. `parent_unresolvable` | One per held parsed rollout with an exact parent cause, including Absent, DeferredRef and DeferredRestart. |
| 4. `created_thread_proof` | One per held parsed rollout in the native-created-thread-only path, including failed parentless A2 conjuncts, after parent precedence. |
| 5. `protected_absent` | Newly missing protected path index keys excluded by the existing traversal residue set. |
| 6. `other_parser` | One per remaining ownership-incomplete parsed rollout. |
| 7. `unattributed` | Last-resort remainder of scanner S without a recorded cause, never U. |

Precedence matches the site/outcome of the individual addition, not every fact
that might apply to its path. Inventory and group exits do not also merge a
parsed-rollout contribution. Held memo replays retain their original cause.
Post-parse legacy holds are separate contributions, not reassignment. No path
membership is retained or consulted. Round 4 removes input-encoding counters too:
the only cause observations retained are contributions; no Absent-parent origin
is inferred. Two original input slots remain decode-compatible but are never
incremented or emitted.

The six classified buckets plus `unattributed` equal S exactly in the terminal
projection. `unattributed` is expected approximately zero by construction:
**nonzero = chase this**. Pre-upgrade checkpoints and an older object-form save
can legitimately lose the split until the next fresh traversal. Otherwise
investigate a missing hook or the invalid/reset disclosure below.

`ownership_incomplete_generation_start` is the existing traversal's frozen census
window boundary, expressed as Unix seconds: a numeric generation-start marker.
It is derived from the already-persisted `census_window_end` each page, so routine
save/load/resume and process restart preserve it. Fresh traversals use their new
window boundary. It has second resolution: separate traversals started within the
same second can share a marker; compare across timestamped generation starts,
not as a globally unique id. Invalid/nonpositive timestamps omit the zero marker.
No new generation field is persisted or used for admission.

Checked additions and checked aggregate/subtraction arithmetic protect the new
counters. Per-slot addition/merge overflow clears the diagnostic split, counts a
reset, and later contributions may be classified again. At terminal projection,
an unrepresentable sum or classified sum greater than S instead clears the
projected split and reports all S as `unattributed`. It does not rewrite S or
repair the stored record. `ownership_incomplete_invalid_resets` counts arithmetic
resets observed by the in-memory traversal owner, plus one when the current
projection is invalid. Repeated invalid projections each disclose that condition;
they do not accumulate repeated reads as additional stored reset events. The
reset count saturates at `usize::MAX` and resets on checkpoint reload (including restart) or a fresh generation; lost
attribution remains visible in the restart-retained unattributed remainder.
This explicitly discloses lost attribution; silent clamping is forbidden. A
legacy S overflow is detected if it leaves classification greater than the
observed scalar; the pre-existing scalar arithmetic itself is unchanged.

Persistence uses the existing traversal counts: `causes` is a trailing defaulted
slot after retired positional slots. Its eight numeric contribution slots keep
the prior order (six causes, two retired input counters). Empty `causes` is omitted
from object-form checkpoints and #799 JSON rows, including Claude/Pi defaults;
fixed positional arrays retain zero elements because position is their schema.
SOURCE approved class N counts and these absence/re-upgrade semantics on
2026-10-29. Object form is the only supported downgrade representation;
positional array form is never emitted. An older object reader ignores `causes`
and drops the split on save; re-upgrade preserves S as all-unattributed, without
backfill. Existing old-object/old-array decoding stays supported. No format,
parser or scan-identity bump, new reader, hold, selection, admission or upload
behavior is introduced.

The shared six-hour Full pace also owns structural active-budget fallback.
`degraded_no_record.active_bound` and `active_bound_delay.active_bound` are
`[event delta, source process total]` on the same alarm carrier. The source
leaf is `claude_code`, `codex`, or `pi`; missing means zero events, never a
successful restore. `pace_evicted` has one immediate alarm owner and a per-source
process total; post-save alarms never emit its delta again:
at capacity the oldest stamp is evicted, the new key is enrolled and the read
is allowed. A busy FIFO lease remains `active_wait_busy`, a transient delay.
These are RAM-only counters and stamps; restart can admit one extra growth
Full. Structural Full publishes without a replacement retained/durable record.
The pace uses `SystemTime`: backwards time or an elapsed interval beyond the
seven-day sanity maximum expires toward reading. Codex page/cursor deferral
consumes no structural allowance; the stamp is enrolled at acquisition start.
Growth at 90% or more of the source file cap bypasses pacing immediately, under
the same cause with a `near_cap` annotation. Source caps predate this path:
512 MiB Claude, 256 MiB Pi, 2 GiB Codex. Above the cap the existing oversized-file
rejection/disclosure still applies; near-cap admission does not expand it.

Workspace re-derivation captures at most 4096 bytes per selected field and
requires the original digest. Unsupported first-prompt, title, agent-label
and session-start obligations remain `rederive_unfunded`. Capture/hash/read
refusals are counted as `not_rederived`; no altered value is published.
`rederive_input_bytes` counts each actual physical read, including bytes read
before a later capture/hash refusal. Success receipts count successful restores
separately; do not add the two byte counters together.

## Codex state-only identity coverage

Prior coverage retains both the uniquely resolved filename identity and the
existing committed header/counting or protected owner hash, including a header
outside both filename candidates. Accepted-owner coverage requires nonempty
exact file incidence whose entities are accepted, not quarantined or decode-held;
a permanent refusal or local wire-size rejection grants no new coverage.

Checkpoint retention and expiry follow the existing rules; local retention
changes are deferred. The backend downgrade fence
(`usage_accounting_authority_downgrade`) protects attributed usage floors against
an uncontracted state-only successor. Local coverage reduces redundant emission;
it does not replace that backend money protection.

With a prior snapshot fingerprint, exactly two evidence-supported filename
identities, and no committed owner coverage, both candidates are withheld from
state-only output. No fingerprint preserves ordinary fallback; zero supported
candidates are not counted. The existing `local_resources` carrier emits at most
one `codex_state_only_ambiguous_identity` line per state-only pass, whose
`counts.codex_state_only_ambiguous_identity` is the number of ambiguous entry
observations in that pass. Repeated passes observe the same entries again: this
is NOT a distinct-entry/file/session count, and sums must not be reported as
files. Alongside the count, `counts.codex_state_only_ambiguous_identity_tokens`
is the saturating sum of the supported state threads' `tokens_used` per observed
ambiguous entry in that pass (units: tokens). The token sum is an UPPER BOUND on
possibly withheld state-only usage: repeated candidates and already-covered
usage can contribute again. A zero-token observation reports zero tokens. Only
aggregate counts and token sums are logged, with no paths, ids or per-session
values.

A later complete native parse still emits its exclusive body for a session with
an earlier state-only row. An emitted total alone does not prove a server-side
overwrite; backend authority rules independently govern successor acceptance.
