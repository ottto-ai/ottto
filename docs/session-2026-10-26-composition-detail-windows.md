# Composition detail windows and session tool attribution

The v2 composition upload can send seven UTC calendar days of tools, files
and heavy sessions, and the largest tool by estimated tokens entered in a
session. This uses the existing incremental reader, with no additional
transcript or file reads. Existing 30-day and retained-history lists remain.
The repair-byte budget and start-verdict size cap remain unchanged.

## Admission and privacy

The existing activity hint must advertise
`context_composition_details_contract: "context_composition_details:v1"`.
Missing, null, unknown, or a failed hint fetch keeps the old upload shape.
The backend must admit and persist the entire contract before advertising it.
This capability is separate from consent. Existing harvest opt-out applies;
tools and nested session tool labels also require `workspace_labels_enabled`.
All tool labels use the existing safety check, normalization and 64-character
limit. The optional MCP `server_label` uses the same server check as `tools[].server`.
Files retain existing relative-name safety and privacy behavior.

## Additive wire

All additions below are v2 only. Counters use the existing unsigned-integer
encoding and server BIGINT admission range (0–9,223,372,036,854,775,807).
The new top-level fields and nested tool
objects are omitted entirely unless the capability is present.

- `sessions[].top_tool`: optional object with `label` (string, 1–64 characters),
  optional `server_label` (string, 1–64 characters), `kind` (existing v2 kind),
  and `tokens_entered_est` (nonnegative integer). MCP labels start with
  `<server_label>/`. A tie chooses the lexical tool name. The winning tool is
  measured by tokens, not calls; unsafe winners are omitted.
- `tools[]`: up to 20 additional rows with `window: "7d"`; existing row shape
  and uniqueness rules apply. The total tools cap therefore becomes 60.
  Parts continue to contain only `30d` and `all` (cap 96).
- `top_files_7d`: array, up to 100 rows, ordered by window tokens descending,
  then name ascending. Each row has `relative_path_or_name` (1–512 characters),
  `category` (`files_read`), `part` (existing files-read part), `events`,
  `tokens_entered_est`, `session_count` (nonnegative integers), and optional
  `last_accessed_at` (RFC3339 string). Counts and last access cover this window.
- `sessions_7d`: array, up to 50 rows, same shape as `sessions[]`, including
  optional `top_tool`. Total tokens, top kind, top-kind tokens and top-tool
  tokens are calculated inside this window. `in_30d` is true (a 7-day subset).
  Session identity/hash and optional start time keep existing semantics.
- `session_count_7d`: nonnegative integer counting all sessions with positive
  v2 entered tokens in this window, including sessions outside the top 50.

The window is `[max(retention_floor, window_end - 6 days), window_end]`,
inclusive, in UTC. It is anchored to this scope's scan day, not rolling 168
hours. Existing `sessions[]` still carries retained-history totals and
`in_30d` membership; seven-day totals must be read from `sessions_7d`.

Example additive fields (alongside all required existing fields):

```json
{
  "tools": [{"label":"docs/read","server":"docs","kind":"other_tools","window":"7d","calls":2,"distinct_sessions":1,"tokens_entered_est":120}],
  "top_files_7d": [{"relative_path_or_name":"src/lib.rs","category":"files_read","part":"file_tool","events":2,"tokens_entered_est":80,"session_count":1}],
  "sessions_7d": [{"session_id_hash":"sha256:example","source_session_id":"session-example","total_tokens_entered_est":200,"top_kind":"other_tools","top_kind_tokens_entered_est":120,"in_30d":true,"top_tool":{"label":"docs/read","server_label":"docs","kind":"other_tools","tokens_entered_est":120}}],
  "session_count_7d":1
}
```

## Bounded forward-only attribution

Older local totals deserialize without session tool history and omit
`top_tool`; they are never backfilled by rereading transcripts. Normal reads
accumulate day/tool tokens for complete new sessions. State is capped at 256
tracked sessions, 128 day/tool pairs per session, and 8,192 pairs per scope.
Exceeding a bound withholds that session's attribution instead of claiming
an approximate winner. Existing session token totals remain available.
Rewrite subtraction, pruning, failed reads and checkpoint commits follow the
existing aggregate ownership. The stored layout adds optional
`session_tools` with no schema/version reset.

Extra reader work is a bounded map update per already counted result. Added
state is at most roughly 2.75 MiB per scope for 8,192 map entries with
64-character UTF-8 names (96-byte row estimate plus up to 256 name bytes),
plus session containers and a bounded temporary read delta. Seven-day upload
assembly traverses existing in-memory daily maps/memberships, with no extra
transcript pass. Added wire is at most 20 tools, 100 files, 50 sessions and
150 optional session-tool objects across the existing and seven-day lists;
conservatively under 512 KiB for maximum-length Unicode labels/names. Typical
payloads are much smaller. These are estimates, not measured benchmarks.
