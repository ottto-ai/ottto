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

| Stage | Local fields | Meaning |
| --- | --- | --- |
| `claude_request_identity_over_cap` | `counts.claude_request_identity_over_cap`: `evidence_entries`, `authority_keys`, `parts_per_row`, `parts_per_item`, `rows`, `bytes`; `counts.claude_request_identity_last_over_cap_item_bytes` | Cumulative, saturating process counters per cap reason, plus the attempted tagged item's last budgeted compact wire byte size, including semantic framing. One attempt can increment several reasons; retries count separately. Recorded before budget recovery or full-strip fallback. Labels are append-only. No row content or identity is logged or uploaded. |

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
`source_prepare` wraps synchronous source preparation (including index load
and baseline construction); it emits an empty counts object on normal return,
including errors or no-frame returns. Like `source_finish`, it emits no record
on panic. Both stages, for Claude Code, Codex and Pi, include
`stage_peak_footprint_bytes`, `stage_start_footprint_bytes`,
`stage_end_footprint_bytes` and `footprint_samples` when available. One shared
background thread samples current process footprint every 50 ms while stages
are open and parks when idle. Start and end reads also contribute to the peak
and successful sample count. macOS uses `TASK_VM_INFO.phys_footprint`, falling
back to resident size; Linux uses resident pages from `/proc/self/statm`.
These are sampled process-wide peaks during a stage, including concurrent work;
shorter spikes can be missed. They do not establish allocation ownership.
Up to 16 overlapping stages have independent bounded counters; overflow or
thread-start failure leaves the measurements absent. `footprint_sample_failures`
counts unavailable reads (or one refused sampler/slot attempt). Failed endpoints
and wholly unavailable measurements are absent, as are all footprint fields
on unsampled stages. Other unavailable measurements and regressing CPU deltas
are `null`. Unix observation time and process id support comparison with an
independently measured matching process. Never subtract or sum overlapping
windows or infer allocation ownership: the finish window contains its batch-call
windows.

There is one bounded observation per completed page, batch call and normally
returned prepare or finish, with two CPU/lifetime-RSS samples per observation,
plus the bounded prepare/finish footprint sampler. There is no per-row sampling,
extra transcript read or new diagnostic store. Version 2 adds one record per
finish and removes one text line per sampled page; the footprint gauge adds one
record per prepare. Output is a synchronous best-effort write on the calling
thread under std's stderr lock; errors are ignored, with no retry or queue for
log output. It may block for the duration of a regular-file write, like existing
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
admission; it is not a held key. There is no `upgrade_state_missing` counter or
alarm in this format-1 bootstrap. Audit deadlines remain owned by the index,
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
The `format_hold` and `durable_held` arrays keep five slots:
`newer,unknown,undecodable,unbindable,known_corrupt`.

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

### Claude Census Retirement Overlap

A complete Claude terminal retires transcript census records whose file was
last modified more than 35 days before the census window. An aged record that
shares a request id with another unretired census record is kept instead, so a
resumed copy keeps its cross-session copy proof while both files stay indexed.
The terminal then emits `claude_census_retire_kept_overlap` with
`census_retire_kept_overlap_records`, `census_retire_kept_overlap_hashes`,
`census_retire_kept_overflow` and its two reasons,
`census_retire_kept_overflow_occupancy` and
`census_retire_kept_overflow_admission`, each with a `_total` process total,
and `census_missing_over_budget`: the same terminal's census-full tombstone
count (the shadow's `missing_over_budget`), so both read together.
Kept records stay while the census, after the other aged records retire, is
at most 90% full by both its hash budget and its serialized budget. Above
that, the oldest kept records (equal ages in path order) retire until it is
back at 90%, counted as occupancy overflow, so one index always yields one
kept set. Kept records never cost another record its admission: a transcript
record that does not fit whole first retires, oldest first, the records the
age rule would retire at that window but that still hold their hashes, only
as many as it needs; if retiring all of them would still not admit it, none
retires and the record is tombstoned as before. Each such insert emits a row with zero kept counts, no
`census_missing_over_budget`, and the records it retired as admission
overflow. The census holds at most 65,536 records, live as on load: a new
transcript key past that gets no record (read as missing) and emits a row
with `census_record_limit_refused` = 1 and no `census_missing_over_budget`.
Every row carries `census_record_limit_refused` and its `_total`. A positive
overflow, by either reason, or a positive refusal also emits
`claude_census_retire_kept_overlap_alarm` with the same counts. Each terminal
decides again, so a kept record retires once its partner is pruned or
retired. Counts only; no path, id or wire event.

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

**Owed-key discovery retention.** `DiscoveryRetention` (`snapshots.rs`) is the
one shared exemption from the discovery window, used by every age gate: the
Claude/Pi walk, candidate revalidation and open, the Codex roster and
`codex_parent_outside_window`. A key owed by a registered source stays
discoverable and observed whatever its age while it is owed, so reconciliation
never prunes it. Its growth goes through the counted Tail path. Only a validated
catch-up or a proven, counted removal releases it, and it is never a Full cause.
File-size caps still apply. Registered sources today are the unverified
sampled-generation marker (any source) and Claude withheld-account holds. A new
owed source (a Codex owed-residue set, a compressed hold) registers as one field
plus its lines in `discovery_retention!`, `unverified` and `owes`; it adds no
separate exemption.

`counts.line_delivery_unselected` counts discovery skip decisions for the page's
source: `age` (outside the backfill window, not held for verification and not
withheld for an unresolved Claude account) and `size` (over the source's
file-size cap). `withheld_oversized` counts the decisions, at the walk,
candidate revalidation or open, that keep an over-cap key observed without a
full parse while its parsed revision is withheld for an unresolved account: the
entry and hold stay, and growth past the cap is not read. They are recorded
after the existing decision, are drained by that source's next completed page,
and count repeated decisions, not distinct files or bytes. They are recorded
whether or not an observer is registered.

`DiscoveryRetention::owes_with_len` also retains a file whose current length
exceeds its committed indexed `size_bytes`, using metadata already available at
the age gate. Grown since committed: retention ends when the growth is committed
(`size_bytes` catches up). Untouched and truncated files gain no exemption. This
covers the walk, candidate/open rechecks, Codex roster and opened parent.
`counts.discovery_retained.grown` counts aged growth-retention decisions by
source on the #799 page line, drained per page and omitted at zero. It counts
one event per gate check, even if another retention source also matches; a file
may pass several gates. Oversized growth stays observed for reconciliation
without a full parse under the existing size cap. Retention grants no new
Full-read cause. Directory traversal does not prune old directories by age. This
arm performs only an indexed committed-size lookup and reuses current metadata,
adding zero stat calls and zero directory walks; all discovery remains inside
the existing per-pass walk budget. Tail starts at the committed extent where the
RAM layout is supported. Unsupported layout, restart or eviction takes the
existing counted Full fallback; shrink retains A2.

After a successful index save, the existing `local_resources` schema also emits
`stage: discovery_growth_fate` for any page that observed indexed growth. The
same `DiscoveryRetention` collects metadata already available to the walk,
roster, candidate and open gates, including size refusals, for **all sources**
(Claude, Codex and Pi). `counts.discovery_retained_grown_fate` gives one outcome
per observed key: `committed` when the saved index extent catches up to the
observed length, `still_retained` when it remains behind, and `unindexed` when
no saved entry remains. This is evaluated after held-key restoration and index
save, including partial checkpoints; a completed parse alone cannot count as a
commit. It is an extent comparison, not an upload ACK or verification grant.
The row is a snapshot of that saved page, not an additive lifetime total. The
older `discovery_retained.grown` remains the separate per-age-gate flow counter.

`counts.discovery_retained_grown_age` counts only the still-retained keys in
that snapshot: `le_30d`, `d31_90`, `gt_90d`, and `unknown`. Age is a **wall-clock
estimate since the last available file mtime**, recomputed at save time, not a
persisted growth/hold start time or a retry deadline. Touches can reset this
estimate; missing or future mtimes are unknown. A page includes recent growth
as well as age-exempt growth. It does not estimate undiscovered keys, unparsed
usage or bytes appended after its last metadata observation. Repeated gates
for a key update one observation instead of multiplying its population count.

This is page scratch in the existing resource probe and then scan result,
charged by the scan owner's existing heap accounting. It is discarded with the
page, adds no persisted field or cross-page ledger, and performs no additional
stat, transcript read or directory walk. Scratch admits at most 4,096 observations per page, below the existing
10,000-entry discovery-tick bound. `counts.observation_overflow` reports refused
diagnostic observations (possibly repeated), making coverage explicitly partial
when roster/selection observations plus walking exceed it. This diagnostic cap
never caps growth retention. A failed save emits no committed outcome; a page
that never reaches a save has no fate row. Population/age rows describe bounded
page observations, not a whole-index census.

Retention changes no refusal/backoff or acquisition decision. Unchanged account
refusals keep the existing content memo skip; oversized growth remains observed
without parsing each pass. The dedicated `discovery_growth_tests` fixtures cover
real account-hold classification, Completed restoration and two unchanged passes
with zero extra body bytes, saved catch-up, and oversized aging in all three
sources. Existing identity/anchor controls remain in
`reread_trigger_content_tests::truncate_regrow_with_unchanged_samples_is_reread_by_mtime`,
`transcript_acquisition::tests::head_and_old_boundary_edits_growing_file_reset_to_full`,
`transcript_acquisition::tests::shrink_and_replacement_reset_even_with_identical_samples`,
`fe_claude_sp5a_truncate_then_regrow_after_short_eof_keeps_main_failure`,
`fe_claude_sp5b_regrow_after_reader_passes_frozen_with_new_head_refuses`,
and `sampled_scan::durable_tail_tests::certificate_sample_truncation_is_shrunk_for_both_windows`.
They retain counted rebuilds for observed rewrites/shrink/sample mismatches;
length-only retention grants no Tail authority. Existing sampled acquisition's
accepted unsampled-interior-edit limitations still apply.

Oversized retention costs count attempts, not unique files. An
over-cap grown file cannot commit the unread suffix: it stays observed and is
counted in both grown retention and size refusal on every eligible pass,
indefinitely until its state changes. Counting has no once-per-process cap.
Codex's already-known unterminated EOF fragment is excluded from grown retention
and its fate/age population when a validated cursor certificate and retained
prefix reduction bind the entire residual to the unchanged object. This RAM-only
binding reuses discovery metadata (no additional stat), requires known birth,
and grants no audit completion or custody release. The selector also requires
the existing sampled fingerprint to match, after independent audit/context gates.
Real extra bytes, termination, replacement or missing binding use the ordinary
counted catch-up path; a length difference alone never proves a known fragment.

The fragment-only Codex exclusion holds within a source preparation; the witness
isn't retained across index reloads yet, so an aged, unchanged unterminated-fragment
Codex file may be counted grown and Tail-read once per preparation past the window
(bounded; never Full). Follow-up: cache-retained witness.

The retained-cache residual is **at most one Tail per unchanged unterminated
fragment per source preparation; never Full; fail-open; fragment bytes only
(from the committed fragment offset to EOF)**. A preparation is a fresh source
scan frame: the ordinary rotation offers each due source once per sync cycle
(`snapshot_sync.rs:4569`, index reload `:6051`), after its negotiated cadence and
backend-backoff gates. Resuming a parked frame's `step` does not reload it.
Each admitted Codex continuation worker page also prepares and reloads its own
frame (`snapshot_sync/continuation.rs:1078`, `snapshot_sync.rs:6528,6594`); it is
not limited to once per outer sync cycle. Thus the bound is per preparation,
not per process or per day.

On the #799 Codex `native_collection_page` line,
`counts.codex_fragment_tail_repeat{files, bytes}` counts this residual using the
approved fallback: actual aged Tail completions with no RAM fragment witness,
an unchanged sampled source fingerprint, a start equal to the committed prefix,
an end at the observed EOF and no newly terminated record. `files` counts read
attempts, not unique paths; `bytes` is the native fragment range, excluding
identity/guard samples. It is recorded after reading, never used to select or
pace a read, and drained per emitted page. It does not count Full reads, real
appends/completed records, or in-preparation Skips with a retained witness.
The literal never-Full bound describes the retained, valid prefix-cache case;
true cache loss, unsupported layouts and due audits retain their separately
named existing Full causes and are outside this Tail-repeat counter.


Withheld ownership debt is a **correctness hold**: it stays Unknown, remains
discoverable while recorded, and publishes or settles nothing until resolution
or eligible absence. The approved interim Full exception is the named, counted
`withheld_reparse{start,evidence,growth}` path; it is unpaced because it publishes
nothing and matches main's recovery. This is not a Full cause for arbitrary
ownership holds. At the 4,096-hold cap new unrecorded debt stays withheld/Unknown
without an invented age exemption; unknown identity cannot grant a memo Skip.

On Claude pages, `counts.withheld_reparse` counts re-parses of keys withheld for
an unresolved account: `start` (first in this process), `evidence` (same size,
but the sampled content, the file object, its api/trace sidecar stamps or the
request identity contract changed) and `growth` (the size changed). A withheld
key whose content and evidence are unchanged is skipped and not counted; an
mtime, ctime or xattr change alone causes no parse or line delivery; existing
bounded identity samples still read the opened file. A validated completed parse
records its content witness immediately. Equal committed fingerprints never
grant an ordinary Skip to a recorded hold without that CONTENT witness. Missing,
refused or poisoned advisory state recovers through the existing counted parse;
genuine authority/correction/rearm constraints retain priority. Unknown object
generation (including missing birth identity) fails closed to that same path. A
past-due sampled audit on such a key is deferred to its next counted re-parse
(it cannot settle while held). Restored upload-context, body-witness adoption
and missing-activity repair debt likewise cannot settle an account hold on
unchanged content. The completed CONTENT witness is scoped to the active body
revision and upload context: within that authority it defers repeated local
adoption/activity repair, including after one counted restart/discard recovery.
A newly activated revision/context, actual quarantine retry, family correction
or genuine external rearm still selects independently. W2 token/age disclosure
remains available while the memo is admitted. The memo behind that skip is RAM only.
`counts.withheld_birth_clamp_accepted.events` counts an accepted backwards
birth/mtime clamp, emitted on the Claude page and drained per page (numeric
only, not unique keys). A completed RAM CONTENT memo may continue only with the
same device/inode, length, bounded samples and account/output evidence, a
strictly earlier known birth, and birth exactly equal to mtime in the platform's
normalized nanoseconds. Acceptance updates the memo birth to that clamp once;
identical later passes neither re-parse nor recount it. This is platform-neutral
code: Linux normally retains birth unchanged. Forward birth, unequal birth and
mtime, changed identity/content/evidence or unavailable identity keep the
existing fences and counted acquisition paths. This avoids parse/line delivery;
existing bounded identity samples remain. No new persisted state or read occurs.

Known gap: APFS birth-clamp continuation accepts an object with an identical [device,inode], length, bounded samples and evidence whose birth moved down to its mtime. A reused-inode replacement crafted to match all of these (unsampled interior differing) would inherit the withheld memo until binding or real change. APFS does not reuse inode numbers in normal operation; Linux cannot produce the signature. Counted by withheld_birth_clamp_accepted.
The effect is a withheld memo Skip until binding or a real change, never a wrong upload; no unprivileged continuity witness is available (`st_gen` needs root). No ACK, census or money credit is granted.

The virtual N1 audit delay is a **bounded/transient scheduling hold**, ending at
its existing due time. Unknown identity or resource refusal grants no new Skip
or completion credit. It applies only to an aged grown key admitted solely by the
grown-since-committed retention arm. A recent grown key keeps main's immediate
TranscriptChanged selection. At its retained due time, the aged key takes the
existing Audit cause. Main's #903 fixes virtual-deadline to sampled-marker
conversion: restoration carries the minimum owed due time, and only a successful
secure open marks the slot attempted. Failed opens preserve the owed due time;
stat-aware backoff and parking pace retries. The RAM backoff map admits 256 keys;
longest-quiet eviction is counted and transfers the evicted owed deadline into
the next slot, failing toward reading rather than dropping the obligation.

`counts.withheld_hold_released` counts released holds: `deleted` (the held file
was proved absent), `deleted_tokens` (its last-known withheld tokens, when
available), and `resolved` (a parse bound the account). A held audit obligation
is retired only after two consecutive rooted NotFound observations at least
600 seconds apart under the same validated parent. Elapsed witness time uses
RAM-only monotonic `Instant`, independently of wall-clock corrections; an earlier
monotonic observation resets the sequence. Each observation uses
`sampled_audit::proven_absent`: ENOENT of the file or a missing intermediate
directory beneath a readable configured root. Descriptor-relative nofollow
opens revalidate the chain before accepting absence. The existing capped memo
pins the nearest existing parent's descriptor and missing-component depth
between probes; inode reuse cannot substitute a different parent. Presence,
symlink/non-directory ancestors, permission errors, parent replacement,
missing/unreadable roots or unavailable memo state reset the sequence and keep
debt. Restart loses the witness and requires two new observations. Descriptor
open failures also fail closed. The memo admits at most 32 retained parent
descriptors and at most one eighth of the process soft descriptor limit; failure
to query the limit refuses admission. Unadmitted keys keep their debt and retry
on later inventory passes as admitted keys retire.
The inventory probes at most 4,096 recorded holds at each Claude page end,
including held-new keys, outside aggregate terminal authority. These are metadata-
only rooted openat walks, never transcript reads. A pinned parent on a removable
root can delay eject for at least 600 seconds. Each discovered held-file presence
check resets its witness using one key construction and memo lookup. Indexed reconciliation and removal hints
share this eligibility gate; generic file removal preserves account holds.
Retirement preserves audited fingerprint incidence and existing ACK custody,
and counts `counts.audit_retired_absent.events` when it removes audit debt and
`Vanished::RequestCensusRemoved` when it removes a request-census record. It
provides no Full, source, census, manifest, ACK or money completion credit.
Codex-protected entries keep their separate protected history.
`counts.withheld_hold_unrecorded` counts refused admission attempts past the
4,096-hold cap (`events`) and their withheld `tokens`; these are attempts, never
unique keys. Admission follows the completed-parse order; existing holds remain
updateable. Such an unrecorded key has no hold age exemption and remains
Unknown; no $0 is invented. All three are drained like
`line_delivery_unselected`. `counts.withheld_memo` is a gauge of that memo:
`entries` (at most 4,096) and `retained_bytes`, the bytes charged to the sync
owner's process-retained bound using a conservative layout-independent allowance
(1,536 bytes per entry for a possible B-tree node, boxed content witness and
pinned absence witness, plus a
root and state header).
Codex-version, native-comparison and continuation graphs are admitted first;
this memo is charged only from the remainder. Its own refusal drops only the
memo details and cannot discard those admitted sibling graphs or BASE-exit
native comparison. An unsupported sibling alone does not discard a memo that
fits the available allowance. Persistently refused memo details remain unknown
and require the existing counted recovery path until they can be retained.
An empty memo releases its B-tree root and optional heap charge. The existing
transcript-cache owner shares the memo with its working index handles in all
builds; rotation prices its optional state once. The completed content witness
is a fixed 64-byte value boxed in the memo. A compact map entry and its box fit the same
existing per-entry allowance; pending completion owns its value inline. `counts.withheld_held_tokens` is a gauge of the withheld
tokens across recorded holds (each key's tokens at its last parse), and
`counts.withheld_held_age` counts those held keys by wall-clock estimates since
this process first recorded them held: `le_30d`, `31_90d` and `gt_90d`. Both are
counts only and RAM only, and omitted while nothing is held.
`counts.withheld_held_count` discloses the durable population;
`withheld_memo_unavailable: true` explicitly discloses missing/refused advisory
details, omitting unknown tokens/ages instead of reporting zero. First-seen
resets on restart or refused retained charge, so these wall-clock age estimates
are a lower bound; after a restart each held key re-enters on its one `start`
re-parse. A released key (resolved, deleted, or dropped from the hold map)
leaves both. The map is charged with the memo.

Known limitations: a renamed held file whose mtime is older than the window can
lose its withheld usage; removal events and last-known tokens are counted.
Same-size middle-only rewrites remain Ron's accepted interior-edit residual.
Evidence outside stamped inputs (including API/trace metadata tokens and
reader-health recovery) wakes only after restart: a delay while a recorded hold
keeps the file discoverable, not an age-based drop. A never-binding account
keeps usage off the server; token/age disclosure is implemented, and
bounded-lifetime release remains a SOURCE follow-up.

`counts.source_rotation_serial_fallback` counts failed parking decisions while
sibling sources wait, drained by that source's next completed page. Closed
causes are `unsupported_layout` and `bound_refused`. A refused bound (`None`)
covers both opaque ownership and over-limit frames; it does not distinguish
their causes. Unavailable shared allowance also uses `bound_refused`.
Each decision continues the same owned frame serially and counts once; ordinary
serial turns with no waiting sibling do not count.

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

## Claude Stale Exporter Port

Claude Code keeps its telemetry endpoint for the life of a session. Ottto can
serve up to two older approved candidate ports on loopback, accepting only
`POST /v1/logs`, `/v1/metrics` and `/v1/traces` through the same local export
handler. Control and health routes return 404 on these listeners. A private,
versioned port record retains the newest two previous approvals. On first
approval it seeds once from retained Ottto-owned Claude settings backups,
reading at most the newest ten JSON backups with the existing size and
no-symlink checks. Ports must be in the current user's relay candidate list;
seed discovery does not guess ports or connect to them. Busy ports are skipped
and retried every 60 seconds. Legacy binds first probe IPv4 and dual-stack
IPv6 wildcard addresses, then bind IPv4 loopback. Successful wildcard probes
stay bound through the loopback bind and listen, closing that acquisition gap.
All three binds use `SO_REUSEADDR`: live wildcard or IPv4 loopback listeners veto
the port, while our connected sockets and TIME_WAIT allow immediate replacement.
IPv4 remains available when the probe reports that IPv6 is unavailable.
A port observed as the current approval is removed from legacy ingress; primary
recovery releases that legacy socket before attempting its bind.

Every legacy export rechecks Claude endpoint approval and the listener's live
approval generation immediately before capture. Refused exports return 403 and
store no evidence or successful-request activity. Claude telemetry disable,
default-approval removal and setup opt-out operations invalidate that generation
synchronously and wait up to two seconds for the supervisor to persist
retirement and close sockets. Secondary-account removal
and browser-login cleanup preserve legacy listeners and default approval;
acknowledgement waits never hold the Claude settings lock. Each tick captures
its generation before reading approval, so a concurrent revoke also fences
sockets created later in that tick. A pending revoke also blocks exports and
new/refreshed listener activity until retirement is persisted and sockets close.
Periodic checks retire ports only after two consecutive definite non-approval
reads. I/O errors, missing
settings and truncated or unparsable JSON are unknown: that export is refused,
but listeners/history are preserved and the consecutive-revocation streak resets.
Idle expiry also retires a port. Retirement survives restarts and prevents
re-seeding or reopening until that port is explicitly approved again and then
superseded. The primary listener continues its existing behavior for all sources.
The optional record is separate from existing daemon formats: older daemons
ignore it, and missing fields or unknown extra fields decode without error.
Retirement is persisted before socket closure, with a separate owner-only
`legacy-relay-retired.json` tombstone protecting against replay of a stale main
record after a failed write. A write failure closes legacy listeners and attempts
to remove the stale main record. If both state and tombstone writes fail,
compatibility supervision stops and logs the failure; retirement may be unknown
after restart. Existing atomic-file durability guarantees apply.

A legacy entry retires after 24 hours without a successful OTLP request, starting
when it enters the persisted record even if a busy port never binds. Entry time
and request activity persist across daemon restarts; activity writes are
limited to once per 10 minutes, so a crash can lose up to that much recent
activity and shorten retention. No request content or identity is in the port
record. The primary relay's `/healthz` response includes process-local counts
under `legacy_relay`: `otlp_legacy_listener_bound` (current gauge),
`otlp_legacy_listener_requests`, `otlp_legacy_listener_busy` and
`otlp_legacy_listener_closed` (cumulative counts since process start). Busy means
bind attempts skipped. Closed counts only actually open sockets released,
including on supervisor exit; retiring a never-bound entry adds no close.
With no open sockets the supervisor waits until its next tick or a command.
Live sockets drain up to 16 pending connections per turn. Resource-related
accept failures back off; unusable sockets release for later tick rebind, keeping
recent request activity. Release checks descriptor ownership before closing. Accept
error logs are limited to one line per minute per socket.

Canonical health reports `claude_stale_exporter_port` as a `Warning` owned by
`source`, with runtime authority, while a legacy listener has accepted OTLP
within the last hour in this process. Restart those Claude Code sessions to
reload the current telemetry endpoint. The uploaded warning contains no port
number. It follows blocking account and source findings in the blocker list.
This restores future local evidence; it cannot recover dropped batches
and does not change consent, account attribution or money calculations.

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
| `miss.<class>` | Restore returned no retained reduction, with the class below. |

Zero fields and an empty `full_causes` block are omitted. An absent miss
class means zero attempts of that class, not a disabled store.
`sampled_acquisition: null` retains its existing unavailable meaning.
A pre-acquisition guard hold is not a restore attempt and adds no count here.
Retries count again; a cooperative yield does not recount a completed decision.

Miss keys are fixed, content-free class labels. Dots below are part of the
JSON class key, not extra nested objects:

- `unavailable`, `no_entry`, `missing`, `budget_refused`, `restore_take_lost`;
- `ineligible.{selection_cleared,history_owed,source,key,context,scope,generation_ahead,entry_changed}`;
- `refused_record.{newer,unknown,undecodable,unbindable,corrupt}`, `corrupt_body`;
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


## Claude Family Census Shadow (schema 2 additive)

Each Claude Code scan page emits one `local_resources` record with stage
`claude_family_census_shadow`, under `counts`. It estimates, per session family
(a root transcript and its subagents), whether the family would be complete in
the current census window. It is shadow-only: the record changes no read,
census bit, manifest, upload, retirement or other decision. Other sources emit
no such record. The row holds counts, ages, fixed reason names and one order-free
digest; no paths, ids, account hashes or request hashes.

**Units.** A page evaluates the families its selection touched
(`touched_families`, with `touched_families_over_cap` beyond the bound of 1,024),
the families its previous page parsed (`followup_families`), and up to 64 others
from a rotating cursor (`rotation_families`). Family counts are evaluations on
this page: a family can repeat across pages, so they are neither distinct
families nor a stock, and rows must not be summed into one.

**Strict partition.** Every evaluated family (`families_evaluated`) is exactly
one of `family_census_complete`, `family_complete_deferred.quantum` (complete past
the limit of 64 per page), or one first-match reason in
`family_census_incomplete`, tried in this order: `membership_unknown`, `queued`,
`refused_read`, `refused_read_unattributed`, `held`, `quarantine`, `residue`,
`evidence`, `evidence/presence_only`, `not_current_window`, `path_not_unique`.
`singleton_families_evaluated` is included in `families_evaluated`.
`families_unevaluated_member_budget` counts families left for a later page, which
are not in `families_evaluated`.

**Freshness.** `pending_census_members` describes the skipped set: `count`
(queue plus replay entries), `replay`, `replay_repeat`, `oldest_age_s`,
`over_24h`, `tracked`, `unqueued_unresolved`, `pace_evicted` and `stamped_for_s`.
`skipped_set` holds `digest` and `retained`, the entries the previous page also
skipped. `sticky_vetoes` holds `namespace_loss_age_s` and `unattributed_age_s`,
null when the veto is not latched. These are process-local, and restart, a scope
change or an eviction (`pace_evicted`) resets them, so every age is a LOWER BOUND
across a restart and `stamped_for_s` caps it. Attestations reset the same way, so
after a restart members count `evidence/presence_only` until ordinary work attests
them again. Attestations and vetoes also reset with each new traversal generation.

**Work counters.** These are approximate units, not exact operations.
`member_keys_visited` is range advances of the member lookups, at most 16,384.
Under `cost`: `root_index_keys_processed` is keys the uniqueness pass consumed,
at most 8,192, plus one check per parse; the merged loop may also peek up to 2
keys it does not count. `rotation_keys_visited`, `queue_entries_visited` (two
passes over the queue, not bounded by a constant) and `history_gates_visited`
count entries. `predicate_cpu_us` is thread CPU, and excludes mutex wait.
`families_evaluated`, `attested_keys`, `attestations_evicted` and
`runtime_heap_bytes` (retained shadow state after the page, excluding page
transients) are gauges. `root_index_restarted`, `root_index_complete`,
`root_index_overflowed`, `queued_roots_overflowed` and `history_gates_overflowed`
are flags. At the top level, `shadow_decision_calls`
and `shadow_attest_micros` measure this page's equality attestation, and
`attest_capped` counts Skips past the limit of 4,096 per page, not attested.

**Zero and unavailable.** A zero count is a real zero for that page. An absent
record means the page had no traversal state or was not Claude. Uniqueness is
unavailable while `cost.root_index_complete` is false, and families then count
`path_not_unique`.

## Pi reported-cost parsing

Pi cost fields use checked decimal arithmetic and an inclusive $100,000 ceiling
per field per source record. Negative values, including numeric or string `-0`,
and malformed fields remain Unknown. Arithmetic overflow or a value above the
ceiling also remains Unknown, preserving valid sibling fields. Strings retain
their original decimal lexeme; JSON floating numbers use serde_json's shortest
round-trip f64 representation because their original lexeme is unavailable.
Integers remain exact.

More than twelve fractional decimal places after applying the exponent rounds
half-to-even to picos. `pi_cost_precision_rounded` counts each accepted field with
that precision, including trailing zeros and values rounded to zero. It measures
lexical source precision, not an anomaly: Pi computes costs with floating point,
so their decimal representations often carry more than twelve fractional digits.
`pi_cost_refused_overflow` counts each field refused for arithmetic overflow or
the ceiling, including a sub-pico excess above it. A string lexeme whose digits
overflow checked `u128` arithmetic also counts, even when its mathematical value
is in range; that field safely remains Unknown. Other invalid fields do not increment
these counters.

Both counters are cumulative saturating process totals in the lifecycle registry,
reported through `process_retained_cache_lifecycle_totals`. There is no labelled
log line or per-line diagnostic emission. Counts are per observed usage line,
before response deduplication, timestamp drops and token-field validation;
rereads count again. Shape probes do not count. These are observations rather
than retention failures. The replay harness classifies both as `Observation`.


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

## Claude request-identity cap priority

`native_collection_page.counts.identity_cap` contains sparse page observations
for `retained_buckets`, `refused_new_buckets`, `accepted_state_unknown`, and
`accepted_overflow.{same_as_parent,differs}`, `accepted_share_changed`,
`unpriced_part_untagged`, `accepted_row_vanished` and
`accepted_state_unknown_cause.{no_key,epoch_changed,untracked_session,incomplete}`.
Labels are append-only.
`accepted_share_changed` counts bucket observations where a previously accepted
row gains a different authority or loses a tagged share/presence. Unchanged
shares stay tagged; changed/missing shares become untagged with one refusal
per affected row. Such a bucket is not counted as retained.
`accepted_state_unknown_cause` splits each `accepted_state_unknown` attempt
into exactly one cause: `no_key` (no usable attribution key, so share
protection is off while shares are still tagged), `epoch_changed` (this pass
discarded hints of a different key epoch), `untracked_session` (no hints for
the session: never stored-body ACKed, evicted or invalid) or `incomplete`
(whole buckets evicted at the share limit). `accepted_row_vanished` counts
frozen tagged rows absent from their still-present accepted bucket, such as
usage moved to a new row key by late effort or billing resolution; it is
counts-only and changes no tag or money.

The final derived rows mirror the receiver's identity-part money presence
rule: a row carrying a cost field needs it on every part. A share whose
contributing buckets all lack a cost its priced row carries has no exact
value, and no zero or guessed identity stands in. That whole model row (top
row and every bucket row) goes out untagged with unchanged money and one
refusal per newly untagged bucket row; orphaned evidence is pruned and the
wire is reconciled again. `unpriced_part_untagged` counts such model rows; a
stripped row with frozen accepted shares also counts in
`accepted_overflow.differs`.

The default classifier always uses `differs`: a local starting login, creator
hint or display cannot prove the backend's parent binding. Zero
`same_as_parent` is explicit when this object is present. Counts describe tagging
attempts, including retries, rather than distinct sessions.

Within the existing item caps, acknowledged tagged buckets have priority over
never-acknowledged buckets. If those accepted buckets overflow, a fitting open
current-hour accepted bucket has priority; settled buckets are considered newest first, preferring to drop the oldest
within the classifier's priority. One unencodable bucket does not erase
independent accepted proof; the complete accepted set is checked first. Dropped usage goes out untagged with a
row refusal; there is no upload hold. Top-level shares are refolded from exactly
the kept bucket shares and the untagged remainder, as required by receiver
reconciliation. Evidence is pruned and references remapped. Display names only
accounts still proved by emitted bucket rows.

Accepted overflow removes buckets from the collective set in that drop order,
using reversible per-share sums and money-presence counts. A bucket need not
fit alone: multiple buckets can collapse a temporary top-level parts row. Only an unavoidable representation
lower bound can exclude an impossible bucket before the collective check.
Row byte deltas and reference widths are updated incrementally; allocation
does not serialize the growing item for each candidate or removal.

Money follows the receiver's presence arithmetic independently for all five
cost fields: add present values, ignore absent contributions, and leave the
sum absent only if none was present. All eight counters sum exactly. There
is no unpriced-witness rule: an absent contribution cannot erase known money.
Re-admission can complete a shared top row when this collapses Parts to Single;
failed row completions are cached until selection changes. The byte budget
includes the existing semantic envelope, the largest policy flag encoding and
a possible cache predecessor. The upload owner reserves any cache reconciliation
growth once before selection, without changing the local cache patch. Full
wire size is checked again after allocation; 640 KiB is unchanged.
Individual shared-row completions are tried before their union, so unrelated
new buckets sharing another row cannot prevent a fitting accepted completion.

The destination-scoped upload progress stores class L hints: hashed session
keys, sorted bucket starts, and SHA-256 row/authority fingerprints of each
row's first accepted share set, including whether an untagged share was present.
It never stores or reconstructs identities. Only stored-body ACKs update it;
a later stripped/refused ACK cannot bless a new authority or missing presence.
Restoration still requires current held proof. An always-missing sibling row
has no accepted tagged fingerprint and is not spuriously refused.

Limits are 16 sessions, 5,000 starts and 1,536 share-presence records per session.
Each share record occupies 80 inline bytes on the requested 64-bit layout;
the maximum requested-layout fixture is 2,628,072 bytes (below 3 MiB). Whole buckets are
evicted from the hint ledger at the share limit, never partial share sets;
`accepted_state_unknown` counts attempts using incomplete or missing state.
Eviction, timestamp-only migration and older-decoder loss degrade to currently
proved buckets that fit. The append-only progress field still defaults empty;
invalid L hints do not invalidate neighbouring billing ACKs. No wire cap or
backend rule changes.

The pure `measure_identity_cap(item, accepted_state)` hook returns
`tagged_recent_buckets`, `refused_recent_buckets`, `accepted_retained`,
`accepted_overflow` and `item_bytes` without reading evidence, logging or
uploading. Here recent means the currently proved, never-accepted candidate
buckets; already stripped proof cannot be recovered from the hint ledger.

Upstream authority-key allocation loss remains fail-closed: inherited partitions
are not reclassified as request proof by budget recovery or a uniform starting-account
retry. Only an intact current grouping can enter the cap allocator.

### Option (ii): `identity_retained` bucket rows

Off unless the activity hint carries exactly
`session_request_identity_retained_contract: "session_request_identity_retained:v1"`;
any other value keeps the bodies above byte-identical. When on, the backend
retains per-row proof, so the accepted priority is not used: fresh tags take
the plain newest-first order within the unchanged caps.

A bucket row enters the local proved-row ledger only when a stored-body entity
ACK (no `unchanged_basis`) covers a body where that row carried a positive tag,
only while the capability is on, and only when that ACK declares a body witness
version and its digest equals the local body witness of a body that has a
public witness version (context curve, session account evidence or cache
observations), so the ACK validator also checked the exact version. The
ledger keeps truncated keyed digests of the row key and of that proof
(authorities plus the eight counts and five costs); later positive proof
replaces it. Per revision, a proved row whose current proof equals the ACKed
proof in a closed hour, or whose transcript no longer proves it, is sent
untagged with full amounts and `identity_retained: true`; it is not a refusal.
Different proof, the open hour and never-proved rows get fresh tags. A row is
never both tagged and marked; top-level rows are never marked. If the
untagged fallback cannot fit every marker beside the stripped body, it keeps
the newest that fit and counts each dropped proved row as a refusal.

Before any upload, a proved row that the outgoing body freshly tags with a
different proof becomes a proof-free tombstone, and progress is saved before
the request, so a lost reply cannot leave a stale proof that a later marker
would honour. While that tombstone stands, a row the transcript no longer
proves is a counted refusal; the replacement's ACK replaces it.
A stored-body ACK's optional `retained_proof_missing` bucket starts remove that
body's marked rows, so a later revision re-tags them through the same
allocator. A destination namespace or historical replay generation change
clears all proved rows, as do key rotation and session eviction (the class L
last-ACK LRU above). Limits: 1,024 proved rows per session, persisted as
versioned base64 of 73-byte records, and 64 pending missing buckets (diagnostic
only). Each proved record also stores the proving revision's optional row-level
account hash (class H, bounded and erased with the session). Login markers resend
that ACK-bound hash for grain only; parts markers have no hash. Old records without
hash provenance fail closed to fresh tags. Markers require contract 6
(`claude_request_owned_usage:v1`); contract-5-only bodies send fresh tags.
Rows evicted at the proof cap also send fresh tags through the usual caps. At every cap the progress JSON stays below 8 MiB and the
requested-layout maximum below 4 MiB.

Sparse `identity_cap` counters, omitted while zero: `retained_marker_rows`,
`retained_proof_missing_received`, `retained_set_cleared`, `proved_rows_capped`
(rows not retained at the proof cap), and
`retained_missing_unfit` (a missing-proof bucket whose fresh proof did not fit
and kept today's untagged/refused rule). `accepted_share_changed` also counts
proved rows sent with different proof.

### Money freshness (Claude queue and replay)

The default-ON Claude shadow and freshness gauges share one
`claude_family_census_shadow` emission. Gauges are flattened into
`counts.pending_census_members`: the existing `oldest_age_s`, `over_24h`, `tracked`
and `unqueued_unresolved` describe the bounded pending stamps; no duplicate
oldest-skipped or skipped-tracked fields or second queue traversal is added.
`count` includes queue/replay occurrences, while age thresholds count retained
unique queued files. `tracked` also includes unresolved files no longer queued.
All ages are process-local LOWER BOUNDS, never inputs to decisions.

A regular file `money_freshness_disabled` in the normal support directory turns
BOTH the shadow and gauges OFF. Missing marker, directories and symlinks leave
them ON. Policy is read once per process; restart after adding/removing the
marker. OFF skips Touched allocation, equality attestation, page observation and
metadata observation before any tracker mutex, clone or candidate decision. It
emits neither shadow nor freshness data. The ordinary scan and skipped-file audit
count continue unchanged. Fixtures use thread-local guards and never consult the
host marker.

`discovered_unread_tracked_files`, `oldest_discovered_unread_age_seconds` and
`discovered_unread_over_24h_tracked_files` cover unindexed, non-replay queued work.
Indexed or replay work is counted separately. No retained index is not proof a
physical file has never been read. Queue/replay overlaps are deduplicated among
retained stamps. `skipped_untracked_entries` and
`discovered_unread_untracked_entries` disclose lost coverage at the existing
16,384-stamp bound; they are occurrences, not invented distinct-file counts.
Directories not yet enumerated and files outside the skipped view are uncovered.

`changed_since_scan_files` and `unchanged_since_scan_files` compare metadata
already observed on the opened candidate with indexed size and second/nanosecond
mtime. No transcript read or extra candidate stat is added. Missing or stale
samples and files without an indexed scan count as
`changed_since_scan_unknown_files`; `changed_since_scan_complete_count` is null
when coverage is incomplete. The first page may have only unknown coverage.
These counters are folded into the existing FirstPending traversal and bounded
stamp work, with no third queue pass or second map.

`changed_over_6h_alarm` is true after observed changed positives on consecutive
passes span **more than 21,600 seconds**; the same row includes unread count and
age. There is no second alarm emission. Zero/unknown-only observations, scope
reset, restart or clock rollback break the episode. Inter-pass continuity is a
sampled condition, not proof of continuous filesystem state.

The restart proxy is DERIVED server/log-side from this same emission:
`tracker_initialized && changed_since_scan_files > 0`, correlated with its
`process_id` and source. `tracker_initialized` is claimed by an independent
process-wide atomic at completed emission, so it is true AT MOST ONCE per process.
Tracker resets, index reloads, scope/path changes and kill-switch toggles never
re-arm it. No per-scope ledger, restart_* payload field or persisted evidence is
needed. This counts starts with an observed positive condition; it does not prove
a prior episode. A positive condition cleared before the first completed pass,
or hidden by unknown initial metadata, is not counted. A disabled process emits
nothing and does not claim a first observation.

Memory remains bounded by the existing 16,384 stamps (48 bytes each, +512 KiB
versus the original shadow), accounted by runtime_heap_bytes and its retained
bound. Classification is transient in the existing bounded heap/vector; there
is no separate gauge dedup allocation or scope ledger. Enlarged stamp transients
are conservatively bounded by an additional 4 MiB. No child-finalize eligibility
measurement, dormant family-consumer API or money/read/census decision is added.
