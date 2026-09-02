# Collector status receipts declare their own kind

## Problem

Every collector-status receipt the daemon posts to
`/api/v1/agent-session-snapshots/status` carries one of two very different
meanings:

- a **liveness beat** — the independent check-in heartbeat and the cycle-start
  in-progress marker — which asserts only "this collector is alive"; and
- a **scan-result report** — a completed traversal, a scan or upload failure, a
  changed loss census, a cap-hit change, or an enabled/disabled transition.

Until now the daemon never said which it was sending. The backend answered the
question by looking at the wire SHAPE: `last_scan_finished_at` absent, no error
code or message, no retry clock, zero consecutive failures. That inference is a
shape coincidence, not a statement of intent. It re-classifies silently the
moment the collector's liveness shape changes — a beat that started carrying a
durable terminal clock would stop being a beat, with no test on either side
failing, and the source manifest disposition would flip from `preserve` to
`invalidate` on every heartbeat.

## Change

`SnapshotStatusRequest` gains one additive field, `report_kind`, with two
values: `checkin` and `scan_status`.

The value is a constant at each of the two construction sites, chosen from what
the daemon knows it is sending, never computed from the fields it is about to
send:

| Emission site | Callers | Declared kind |
| --- | --- | --- |
| `snapshot_sync.rs` `collector_status_request` | every terminal outcome: success, derived `parse_error`, scan/upload error, policy tombstone, disabled transition | `scan_status` |
| `snapshot_sync.rs` `report_checkin_status` | `collector_checkin_once` heartbeat; `sync_once` cycle-start marker | `checkin` |

A `checkin` must never disclose evidence the backend has not already accepted.
That is closed by construction rather than by convention:

- `report_checkin_status` has no access to any scan outcome. It receives a
  source, a machine id, an optional cycle-start clock, and the server's own
  width hint; every scan-result field it writes is a literal absence or zero.
  `last_census_complete` is the one field where zero-shaped honesty is not
  enough — see "Census completeness is absence, not `false`" below — so it is
  an `Option<bool>` the beat leaves `None`. A durable terminal status journal
  does exist (ottto#393 writes the
  exact typed receipt to disk before the POST), but no beat can reach it:
  `report_checkin_status` takes no support directory and has no reader for it,
  and its doc comment records why replaying one there would be wrong. So a beat
  replays nothing at all. The only evidence it forwards is the cached source
  manifest — a witness the backend already accepted from the last completed
  terminal report.
- `SnapshotStatusRequest::validate_declared_report_kind` runs on the single
  egress, `SnapshotApiClient::report_status`. It is a falsifier, not a
  classifier: it never picks the kind, it only refuses to send a `checkin`
  whose own payload contradicts it. The check exhaustively destructures the
  request, so a new wire field cannot be added without deciding, at compile
  time, whether a liveness beat may carry it.

`checkin` plus a disabled collector is unreachable here for the same reason: a
disabled state report is durable state, and only the terminal path can express
it. (The backend rejects that combination with a 400.)

## Census completeness is absence, not `false`

Declaring the kind exposed a bug that the shape inference had been hiding, and
this change fixes it rather than shipping on top of it.

The backend merges a check-in's census into what it has already accepted
(`_merge_retained_checkin_census`). For the counters that merge is a `max`, and
a beat's honest `0` is the identity, so an unmeasured zero is harmless.
`last_census_complete` has no such identity. It merges as a conjunction resolved
through pydantic's `model_fields_set`: an OMITTED value retains the accepted
one, and an explicitly declared `false` asserts incompleteness and LOWERS it,
because only a real census can claim a corpus was not fully seen.

`report_checkin_status` hardcoded `last_census_complete: false`, and the field
was a plain `bool` that always serialized. So every heartbeat declared an
incomplete census it had never measured, and — against a backend that reads the
declaration — would retract a complete census on every beat.

The fix is on the daemon, where the honesty belongs: a beat has run no census,
so it must state nothing.

- `SnapshotStatusRequest.last_census_complete` is now
  `Option<bool>` with `#[serde(skip_serializing_if = "Option::is_none")]`, so
  `None` means the key is ABSENT on the wire — not `null`, not `false`.
- `report_checkin_status` sends `None`. `collector_status_request` still sends
  the measured `Some(bool)` in both directions.
- `checkin_contradicting_evidence` refuses ANY present value on a declared
  `checkin`, `true` and `false` alike. That is parity with the backend's rule:
  it reads presence, not truth.

Verified against the deployed backend model (private `origin/master`, which
carries #5225): the real emitted beat bodies validate with
`last_census_complete` outside `model_fields_set` and merge to
`census_complete=True` against a retained-`True` head, while the same body with
an explicit `false` merges to `False`. The legacy shape inference
(`_inferred_checkin_receipt`) does not read the field, so a backend predating
`report_kind` classifies the beat exactly as before.

Building the receipt is already split from sending it: `collector_status_request`
is pure, and `report_status_with_fresh_relay_token` journals and posts what it
returns. Tests therefore assert against the exact payload the daemon would put
on the wire, including the declared kind, and the journal round trip has to
preserve that declaration — which is why `SnapshotStatusReportKind` derives
`Deserialize` alongside `Serialize`.

## Wire compatibility

One additive optional field; nothing else about the receipt changed. The
liveness shape in particular is byte-identical to before — `last_scan_finished_at`
stays absent on a beat — so a backend that predates the field still infers
exactly the same classification from the shape.

A backend that predates the field ignores it: the status request model is
forward-tolerant (`extra="ignore"`), `report_kind` is not a retired wire field
for that model and is not a content-, path-, or credential-forbidden name, so it
is accepted and counted as an unknown additive field rather than rejected. The
status ACK the daemon reads back (`accepted`, `source`, `machine_id`,
`disabled`, `disabled_reason`) is unchanged, so the check-in and terminal ACK
handling paths behave identically against old and new backends.

## Verification

- `cargo test --workspace -- --test-threads=1`
- `cargo fmt --all --check`; `cargo clippy --workspace --all-targets --locked
  -- -D warnings` on both 1.88.0 and 1.97.0
- New coverage: heartbeat and cycle-start marker both declare `checkin`; a beat
  discloses nothing (every scan-result field absent or zero, and
  `last_census_complete` absent from the serialized body entirely, asserted on
  the JSON keys rather than the struct); the guard refuses a declared `checkin`
  carrying `last_census_complete` in either direction; the terminal path still
  emits the measured bool for both a complete and an incomplete census; fresh
  terminal report, new or changed error, derived `parse_error` with a changed
  loss census, cap-hit change, disabled transition, zero-width tombstone, and
  the first report after a reinstall all declare `scan_status`; the guard names
  every field a beat may not disclose while the same payload declared
  `scan_status` always travels.
- Mutation proof: the real receipt built for a fresh `scan_error` is sent
  successfully as `scan_status`, then re-declared `checkin` with nothing else
  changed — the egress guard refuses it and exactly one receipt reaches the
  server.
