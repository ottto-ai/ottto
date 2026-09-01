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
  width hint; every scan-result field it writes is a literal absence, zero, or
  `false`. A durable terminal status journal does exist (ottto#393 writes the
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
  discloses nothing (every scan-result field absent, zero, or false); fresh
  terminal report, new or changed error, derived `parse_error` with a changed
  loss census, cap-hit change, disabled transition, zero-width tombstone, and
  the first report after a reinstall all declare `scan_status`; the guard names
  every field a beat may not disclose while the same payload declared
  `scan_status` always travels.
- Mutation proof: the real receipt built for a fresh `scan_error` is sent
  successfully as `scan_status`, then re-declared `checkin` with nothing else
  changed — the egress guard refuses it and exactly one receipt reaches the
  server.
