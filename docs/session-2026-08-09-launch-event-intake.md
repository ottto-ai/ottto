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

This token identifies a local launcher assertion. Provider-native and
provider-artifact evidence keep precedence. Consumers must explicitly support
this evidence kind; an unsupported consumer may drop the facts while accepting
the session. A launcher event never authenticates the provider, account or payer.

The launcher family rides as `agent_kind`, not in `source_version`: the backend
hard-validates `source_version` against a bounded parser-version shape and
rejects the whole batch on a miss, which is a much worse failure than one
dropped fact.

## Lifecycle

`pending/` is an inbox. Lookup advances through bounded intake and read-only
claim passes, moving valid events to `processed/`. Accepted events stay joinable
for thirty days by file modification time; rejected files are retained for seven.
Only fixed reason codes and bounded hash prefixes appear in rejection logs.

There is no hash-prefix admission limit on the retained launch store. Each
transcript page demands up to 512 worker references; later pages demand the
remaining workers through the same path. A continuation visits at most 256
directory entries and reads at most 4 KiB plus one oversize-detection byte per
event. The complete pending and processed claim sweep must finish before any
edge in that demand batch becomes available. Different claims for one worker
withhold its edge even when separated across pages. Negative hits are retained
only for the current demand batch. Directory I/O loss or a changed directory
fence discloses incomplete work and leaves the native file uncheckpointed.

Intake renames and uniqueness checks are separate passes. This prevents a
platform directory iterator from skipping a conflicting pending file while
other files move. Queries retain no whole-directory path list or full event
inventory. Total work is linear in retained directory entries per demand batch;
this is not constant CPU for an arbitrarily large store. Expiry cleanup is also
streamed. An opaque directory iterator conservatively declines optional source
parking under the existing heap validator; the same native frame continues
serially rather than restarting. No new scheduling queue or persistent cache
is introduced.

A fresh source context validates same-name edits, removal and expiry. A completed
batch may be reused within that context for at most sixty seconds. The lookup
is a bounded local observation, not an atomic filesystem transaction; events
must be emitted atomically and retained while ordinary collection/import uses
them. Continuous mutation or unreadable evidence is disclosed as incomplete
work rather than a unique controller claim.

`launcher_event:opus_cli_agent` derives `opus-cli-agent`. Its controller and
worker must be UUIDs, workflow may be a UUID or null, and PR may be a positive
integer or null. The exact nine-key schema, timestamp, filename hash and
self-launch checks remain required. The two legacy families retain their exact
labels and required/null fields; composite controllers remain relay-only.
Arbitrary and reserved-looking capture-source slugs are refused. A strict slug
syntax alone would not authenticate the launcher that wrote it.

## Gating

Launch-event intake rides the **same** gate as every other attribution fact:
`SessionAttributionContext::from_activity_hint` builds the inventory, and that
constructor already requires `session_attribution_enabled` plus a current
backend-issued key epoch. With attribution off, the drop directory is not even
listed. There is no separate switch and no way to reach this path around the
existing consent.

The checkpoint namespace and parser mapping stay unchanged. A path-scoped
launcher witness selects its worker transcript when an edge arrives, changes,
conflicts or disappears, even if transcript bytes are unchanged. An unrelated
launch does not invalidate every transcript checkpoint. The same forward path
handles ordinary collection and a new user's first historical import; it adds
no account-specific rescue or backfill operation.

## Cross-user safety

The drop root belongs to the local user. A writable launch event is that user's
assertion of exact references; UUID shape does not prove session ownership,
launcher authentication, provider authority, organization or account/payer
identity. Provider-native fields keep precedence. Launch facts never supply
account evidence. Workers remain UUID-only; the reviewed relay family alone
may name a composite Claude controller reference.

## Original intake validation

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
- **Backend contract changes.** Facts retain the existing evidence kind,
  source version and fields. The additional launcher role uses `agent_kind`.
- **Arbitrary launcher families.** Additional capture sources require their own
  explicit contract and reviewed mapping.
