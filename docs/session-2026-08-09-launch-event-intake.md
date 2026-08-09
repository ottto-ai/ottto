# 2026-08-09 — Launch-event intake (`launcher_event:v1`)

## Outcome

`ottto-service` can now read content-free launch events written by an
instrumented launcher and turn them into ordinary session attribution facts on
the worker session. This is the first capture path that can state "the session
that ordered this work is *that* session in another app" — the one relationship
providers cannot supply, because no provider owns both halves of it.

Nothing is inferred. If the event is absent, ambiguous, or malformed in any way,
no relationship is produced.

## The problem this solves

Claude → Claude and Codex → Codex family trees already work, because each
provider records its own subagents. The economically interesting edge is the
other one: a controller in one app starting a worker in another. There is no
universal, symmetric cross-app contract for that, and the signals that look
tempting — start time, repository, worktree, model, process ancestry, matching
titles — are all wrong often enough to be worthless as a positive claim. An
absent edge is recoverable; a wrong edge is not.

The only acceptable source is a launcher that knows both sides and says so in a
typed event. This change is the reader for such events.

## The event

One JSON file per launch, dropped into `~/.ottto/launch-events/pending/`:

```json
{
  "schema": "agent_launch.v1",
  "controller_session_ref": "<uuid>",
  "worker_session_ref": "<uuid>",
  "relationship_kind": "launched",
  "workflow_ref": "<uuid>",
  "pr_ref": 1653,
  "launch_ts": "2026-08-09T15:17:21Z",
  "capture_source": "launcher_event:landing_repair",
  "evidence": "direct"
}
```

Nine keys, and every one of them is an identifier, a fixed enum, or a timestamp.
There is no field that can hold free text, which is what makes the channel
content-free by construction rather than by convention.

The filename is `sha256(controller \n worker \n attempt).json`. Identity lives in
the name, so re-emitting the same launch resolves to the same path and cannot
produce a second edge.

## Validation, in both directions

Membership is checked both ways: every allowlisted key must be present, and no
key outside the allowlist may be. An unknown key rejects the whole **file**
rather than being ignored — "ignore what you do not understand" is exactly how a
content-free channel quietly stops being content-free.

| Refused | Why |
| --- | --- |
| unknown key | an unreviewed field could carry anything |
| missing key | a partial event is not evidence |
| schema other than `agent_launch.v1` | a v2 writer and a v1 reader disagreeing is how a wrong edge gets minted |
| reference that is not a UUID | the privacy chokepoint: a path, branch, or prompt fragment dies here |
| composite subagent ref (`<uuid>_agent-<id>`) | that family belongs to the provider |
| `relationship_kind` ≠ `launched`, `evidence` ≠ `direct` | fixed vocabulary |
| `pr_ref` not a positive integer | broken emitter |
| `launch_ts` not `YYYY-MM-DDTHH:MM:SSZ` | this is the observation time of Direct evidence |
| capture source outside the allowlist | an uninstrumented launcher cannot claim Direct |
| controller equals worker | a session cannot launch itself |
| filename not the triple's digest | the name is the identity; a mismatch breaks replay safety |
| file larger than 4 KiB | refused by `stat`, before it is read |
| two events, one worker, different controllers | both are withheld; picking one would be a guess |

## Facts

An accepted event produces up to four facts on the **worker** session:

| Field | Value |
| --- | --- |
| `parent_session_ref` | the controller session |
| `origin_kind` | `agent_spawn` |
| `workflow_ref` | the launcher's attempt id |
| `agent_kind` | the worker role, chosen from the capture-source allowlist |

Ordered most- to least-load-bearing, because `enforce_fact_limits` trims from
the tail. They ride immediately behind the provider-native facts and ahead of
the derived grouping ids, and any field the provider already answered is dropped
before they are appended: a launcher may add an edge the provider never knew
about, never overwrite one the provider owns.

`pr_ref` is validated and then discarded. There is no allowlisted attribution
field for a pull-request number, and a value with nowhere honest to go does not
belong in daemon memory.

## Evidence kind

Facts carry `evidence.kind = "launcher_event"` and
`evidence.source_version = "launcher_event:v1"`.

`launcher_event` is a **new** vocabulary token, and that is deliberate. None of
the kinds the backend lists today is honest here: this is not provider-native,
not a provider-owned artifact, not a scheduler-definition match, and not a live
process check. The ingest path tolerates an unknown evidence kind by dropping
that one fact, counting it, and storing the session, so the truthful token costs
nothing today and starts working the moment the backend enum lists it — with no
backfill, because these facts re-emit on every scan of the worker session.

The launcher family rides as `agent_kind`, not in `source_version`: the backend
hard-validates `source_version` against a bounded parser-version shape and
rejects the whole batch on a miss, which is a much worse failure than one
dropped fact.

## Lifecycle

`pending/` is an inbox and drains on every refresh. Accepted events move to
`processed/` and stay joinable for thirty days; rejected ones move to
`rejected/` for seven, with a reason **code** in the log and never the file's
contents.

The inventory is built from `processed/`, not from `pending/`, and that ordering
is the whole trick. The event is written at spawn — before the worker has
written its first transcript line — so an intake that consumed the file on first
read would routinely discard the edge before the transcript it belongs to was
ever parsed. Keeping the accepted event readable for the retention window also
covers a stalled upload, a checkpoint reset, an explicit replay, and a machine
that was simply off.

Every mutation is a rename or an expiry delete, so repeating a refresh — from
another source's context in the same cycle, from the audit tool, or after a
crash mid-drain — converges on the same state.

## Gating

Launch-event intake rides the **same** gate as every other attribution fact:
`SessionAttributionContext::from_activity_hint` builds the inventory, and that
constructor already requires `session_attribution_enabled` plus a current
backend-issued key epoch. With attribution off, the drop directory is not even
listed. There is no separate switch and no way to reach this path around the
existing consent.

Scan identity is deliberately untouched. Launch events are semantic input for
sessions parsed after they arrive, exactly like the scheduler inventory, and an
unrelated launch must not invalidate every transcript checkpoint and replay
local history. No parser-version bump is warranted: the transcript parsers'
file-to-session mapping is unchanged.

## Cross-user safety

The daemon is per-user and the drop root is inside the user's own home, so both
sessions belong to the same user by construction. The plausibility check the
code can actually make is the reference shape, and it makes it strictly: plain
UUIDs only, which is what both worker paths produce (Claude workers get their id
pre-assigned by the launcher; Codex workers' ids are parsed from the run header).

## Validation

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` — all clean; 1,365 `ottto-service` tests pass.
- 11 intake tests cover every fail-closed row above, atomic lifecycle, replay
  idempotence, ambiguity refusal, the oversize cap, the filename check, and the
  redacted log label.
- 2 attribution tests pin the fact shape, ordering, evidence vocabulary, and
  wire-budget compliance.
- 2 end-to-end tests drive a real dropped file through the scan: one asserts the
  controller edge on a worker transcript and the `pending/` → `processed/`
  transition, the other asserts that a Codex subagent's provider-native parent
  wins while the rest of the launch event still lands.

## Not in this change

- **The emitter.** It lives beside its launcher, outside this repository. The
  two ship independently and both are inert alone: events accumulate with no
  reader until this lands, and this reads an empty directory until the emitter
  does.
- **The backend evidence-kind widening.** Until `launcher_event` joins the
  enum, these facts are dropped and counted at ingest. That is the designed
  ordering, not a gap.
- **A second launcher family.** Adding one is a one-line widening of
  `CAPTURE_SOURCES` on both sides.
