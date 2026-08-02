# Claude reasoning effort: attribute per request, not per hour

2026-08-02. Ottto's Optimize "session economics" view reported `Unknown`
reasoning effort for most Claude Code sessions. The evidence was being
collected correctly; it was being routed to the wrong sessions.

## Symptom

On one machine over a 14-day window, effort coverage by model:

| Model      | sessions with a tier | sessions reported `Unknown` |
| ---------- | -------------------- | --------------------------- |
| Sonnet 5   | 176                  | 199                         |
| Opus 5     | 20                   | 243                         |
| Opus 4.8   | 33                   | 102                         |
| Fable 5    | 36                   | 82                          |

The local sidecars were not thin: the same window held 12,858 observed
`claude-opus-5` xhigh requests. Almost none of them reached a session.

## Root cause

Claude transcripts never carry the effort tier, so the daemon learns it from
Claude Code's `claude_code.api_request` OTLP log, reduced into a content-free
sidecar keyed by `sha256(session_id)`.

**Claude Code stamps the top-level `session.id` on subagent requests too.** A
Task or Workflow subagent's requests are logged under the parent human session,
discriminated only by `query_source` (`agent:builtin:Explore`) and `agent.name`.
The daemon, correctly, files each subagent transcript as its own session
(`<parentSessionId>_agent-<agentId>`). Keying evidence by session id alone
therefore broke in two directions:

1. **Sidechain sessions could never match.** Their `source_session_id` is not
   the id the sidecar is filed under. Measured: **294 of 294** subagent sessions
   with real usage had zero effort evidence. They could only report `Unknown`.
2. **Parent sessions lost effort as well.** The subagent requests stayed pooled
   in the parent's evidence, so the parent's observed totals exceeded what its
   own transcript recorded for that (hour, model). `usage_totals_fit` then
   failed and `apply_claude_effort_evidence` skipped the split wholesale rather
   than risk inventing usage. Measured: **159 of ~760** (bucket, model) groups,
   e.g. a Fable 5 hour with `request_count` 193 observed against 77 recorded.

Top-level sessions that hit neither path were fine (298 of 332 had evidence),
which is why a model rarely used as an orchestrator, like Sonnet 5, looked
healthy while Opus 5 did not.

## Fix

The `claude_code.api_request` log already carries `request_id`, Anthropic's own
per-call identifier, and every transcript repeats it as `requestId` on each
record of that response. That is an exact join, and it is indifferent to which
transcript a request landed in.

- `claude_effort.rs` records `request_id` on each evidence row and adds
  `load_claude_effort_by_request`, which reduces a scan's sidecars to
  `request id -> tier`. Request ids are globally unique, so one flat map serves
  every transcript in the scan.
- The scan builds that map once per cycle, collecting the *owning* session id
  per candidate: `claude_subagent_identity(path).root_session_id` for a subagent
  transcript, the file stem otherwise. It is shared read-only via `Arc`, the
  same shape as the Codex turn-trace map.
- The Claude line parser sets each usage row's tier from its own `requestId`, so
  the existing `RowKey` machinery splits rows by effort with no hourly
  reconciliation, no fit gate, and no residual row.
- `apply_claude_effort_evidence` still serves evidence captured before
  `request_id` existed, and now skips any row the parse already attributed.

A turn whose request was never captured stays effort-unknown. That is the honest
answer, and it is covered by a test.

`CLAUDE_CODE_SNAPSHOT_PARSER_VERSION` moves to `claude_code_jsonl:v26`. Scan
identity does **not** move: which session a file maps to is unchanged, and
`claude_effort_sidecar_fingerprint` already re-selects a transcript whose
evidence grew after its final write.

## Verification

- Live capture of `claude_code.api_request` from a headless run that spawned one
  Explore subagent: all 6 records joined exactly, the 4 `query_source=sdk`
  requests to the parent transcript and the 2 `agent:builtin:Explore` requests
  to the sidechain transcript. Zero ambiguity, zero misses.
- `cargo test --workspace`: 1470 tests pass, including six new ones covering
  per-request splitting, subagent routing, uncaptured turns staying unknown, the
  legacy aggregate path being left alone, index construction across a parent and
  its subagent, and legacy rows being excluded from the index.
- `cargo clippy --all-targets` and `cargo fmt --check` clean.
- The semantic-envelope golden moves only `parser_version` and its two derived
  revision hashes for the 20 Claude cases. `content_hash` is unchanged, which is
  the invariant: a provenance bump must not change semantic identity.

## Scope

This applies to evidence captured from this version onward. Historical rows have
no request id, so past `Unknown` sessions do not backfill: the tier for a request
that was never recorded with its id is not recoverable.
