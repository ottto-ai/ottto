# A completed census with settled residue is a success, and says so on the wire

## Problem

Since ottto#399 a source census completes even when some of its loss cannot
be changed by any retry - a Codex rollout whose exclusive-usage boundary
cannot be determined, a file with usage evidence the parser turns into no
entity, and the usage records those files drop. The generation settles that
residue as terminal, names it in the local index, and reports
`last_census_complete: true`.

The terminal collector receipt did not follow. `collector_status_request`
still mapped any nonzero loss counter on a successful cycle to the shape it
has always used for loss: `last_error_code: parse_error`, a generic message,
`consecutive_failures: 1`, and - the part that matters most - no
`last_success_at`, because the cycle was recorded as not having succeeded.
Every backend predicate that decides whether a source witness is terminal
binds the manifest to `last_success_at == last_scan_finished_at`, so a
machine whose only problem is one unresolvable archived rollout stayed
non-terminal forever, exactly as if its scan had failed.

Nor could a backend tell the two apart. The public loss counters travelled,
but nothing said which part of that loss the daemon had settled and which
part it was still going to retry. "Treat `parse_error` with a complete census
as residue" would have been inference from a string.

## Change

### The settled share of every loss class travels

`SourceScanResult`, `SyncCounts` and `SnapshotStatusRequest` gain the
generation's settled counterpart of each public loss counter
(`ScanTraversalCounts::terminal_*`), five fields named
`last_terminal_<class>`: ownership-incomplete files, zero-snapshot usage
evidence files, recognized usage drops, dropped usage records, and
over-line-cap lines. Each is a decomposition of the public counter it is named
after, never an addend, so `terminal <= public` always holds. Snapshot
families the bounded reconstruction ladder gave up on
(`last_snapshot_unproven_terminal_count`) are terminal by disposition and are
folded into the terminal ownership share the same way they are already folded
into the public one, so that class stays matched.

Three more fields carry the residue witness as cardinalities only:
`last_census_residue_index_key_count`,
`last_census_residue_archived_rollout_count`, and
`last_census_residue_blocked_session_count`. The witness's index keys and
Codex session ids stay in the local index; the wire-shape fixture test pins
the exact member set so neither can be added without a test failing.

`last_census_residue_settled` is the census verdict itself: true exactly when
the census completed, no retryable problem remains, and every loss class
equals its terminal counterpart. It is a function of the counts alone, so a
backend can check the same equality and agree or disagree with it.

All nine are sent on every terminal receipt whatever error code it carries,
and are zero or false on a liveness beat. A backend that predates them ignores
them; a backend that declares them journals the disclosure.

### A settled residue census reports success

The residue arm of `collector_status_request` is split on
`SyncCounts::disclosed_loss`:

| Disclosed loss | Receipt |
| --- | --- |
| none | unchanged: no code, no message, `last_success_at` bound |
| terminal - census complete, no retryable class, every class equal to its terminal share | `last_error_code: census_residue`, a message naming the settled classes and counts, `consecutive_failures: 0`, `last_success_at == last_scan_finished_at` |
| unsettled - incomplete census, a retryable class beside the residue, or a class above its terminal share | unchanged: `parse_error`, `consecutive_failures: 1`, no `last_success_at` |

The retryable classes are the ones `ScanTraversalCounts::has_retryable_problems`
names - symlink rejected, unreadable, oversized, disappeared, malformed JSON,
invalid UTF-8, and over-line-cap loss beyond its terminal share - so a walk
that could not enter or read something still reports the retryable shape even
when the residue beside it is settled.

`census_residue` is a named disclosure, not a failure: a consumer that needs a
fully clean receipt still sees a non-null code, while every clock binding
holds without being relaxed.

### The new code is gated on the backend admitting it

The backend's collector error-code set is a closed list, and its forward
tolerance covers unknown fields, never unknown values. A daemon emitting
`census_residue` against a backend that does not admit it would have its
entire terminal receipt rejected - no journal append, no census counters, no
manifest - which is strictly worse than today's red.

So the code is emitted only when the activity hint the daemon fetches
immediately before building the receipt carries
`"census_residue_status_contract": "census_residue_status:v1"`
(`CENSUS_RESIDUE_STATUS_CONTRACT`). This is the same fail-closed contract
shape the context-curve capability uses: absent, `null`, and any other token
all read as "not admitted", and the receipt keeps the legacy `parse_error`
shape while still carrying the additive counters. The backend therefore
decides when its fleet flips, and no install ordering between the two sides
can produce a rejected receipt. The width and the admission are read from
the same hint, so one server answer decides both.

Until a backend advertises the token, an upgraded daemon changes exactly one
thing on the wire: nine additive fields.

## Compatibility

- `SnapshotStatusRequest`: nine additive fields, each `#[serde(default)]` so
  a terminal-status journal written by an older daemon reloads with them
  absent. The liveness beat carries them as zero/false and the egress
  falsifier refuses a `checkin` that claims any of them.
- `ActivityHintResponse`: one additive optional field,
  `census_residue_status_contract`.
- No existing wire field changed shape or meaning. The legacy residue receipt
  is byte-identical to a released daemon's apart from the additive fields.
- Local index: unchanged. `SourceScanResult` is in-process only.

## Tests

`crates/ottto-service/src/snapshot_sync.rs`:

- `a_settled_residue_census_reports_census_residue_once_the_backend_admits_it`
  - the M1 witness under an admitting hint: `census_residue`, zero failures,
  `last_success_at == last_scan_finished_at`, every terminal share equal to
  its public counterpart, the witness counts, the exact message.
- `a_settled_residue_census_keeps_the_legacy_shape_until_the_backend_admits_the_code`
  - absent, `null`, a different version, and a different token all keep
  `parse_error` / `consecutive_failures: 1` / no `last_success_at`, with the
  additive counters still present.
- `a_retryable_problem_beside_settled_residue_still_reports_parse_error` -
  each of the seven retryable classes vetoes the settled verdict under an
  admitting hint.
- `unsettled_residue_and_an_incomplete_census_still_report_parse_error` -
  one class below its terminal share, one above, and an incomplete census all
  keep the retryable shape; a clean census is untouched by the admission.
- `the_census_residue_receipt_matches_the_backend_admitted_wire_fixture` -
  exact equality against `fixtures/collector-status/census-residue-scan-status-v1.json`,
  the body the backend's residue admission accepts; doubles as the privacy
  fence.
- `the_journaled_census_residue_receipt_reloads_byte_for_byte`.
- `unchanged_conflict_is_unproven_terminal_on_fourth_failure_and_body_change_recovers`
  additionally asserts the terminal ownership share follows the unproven
  fold.

`crates/ottto-service/src/snapshot_client.rs`:

- `census_residue_status_admission_defaults_off_and_requires_exact_contract`.
- `a_journaled_receipt_without_residue_fields_reloads_with_them_absent`.
- `a_checkin_may_not_disclose_scan_evidence` covers the nine new fields.

`crates/ottto-service/src/snapshots.rs`:

- `residue_rollouts_under_archived_and_active_roots_stay_blocked_while_the_fallback_resumes`
  and `retryable_problem_keeps_the_census_red_and_the_latch_bounded`
  additionally assert the terminal shares and witness counts the scan result
  exposes: matched and `2 / 1 / 2` on the settled generation, all zero beside
  a retryable problem and on a clean generation.
