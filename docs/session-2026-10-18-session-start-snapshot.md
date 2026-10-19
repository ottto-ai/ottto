# Session-start facts on snapshots

Each Claude Code and Codex snapshot item may carry an optional `session_start`
object. It records what a fresh session sent in its first model request and what
it read in its opening window, requests 1-3. The snapshot parser computes it
inline from transcript lines it already decodes. There are no extra file reads,
jobs, timers or caches. The window freezes at request 3; after that each line
costs one branch. The value is a pure function of the transcript, the device salt
and the tenant attribution key. It is computed for any session the daemon parses,
and no parser bump forces a republish. It is not part of the content hash, the
snapshot fingerprint or the upload-body witness.

Fields:
- Request 1 usage: uncached input, cache read, and cache writes split 5m/1h
  (Claude only; Codex logs no cache writes). Sent only when the parts add up
  exactly to request 1's context and that is the item's first-turn context.
- Opening request count, and context for requests 2 and 3.
- Output tokens, tool calls and client-truncated outputs over the opening
  responses.
- Up to 64 opening files.
- Request-1 character counts per part. `cc_wire_v1` derives them from Claude
  Code's logged request shape and blobs. `codex_items_v1` derives them from
  Codex's labelled prelude items through the one Codex prelude parser
  (`codex_prelude.rs`, shared with the Codex prelude footprint); it needs
  `world_state` (Codex 0.159+), and the Codex tools part is present only when
  `additional_tools` is logged.
- A 16-hex configuration fingerprint.
- `client_version`.

All character counts are UTF-16 code units. A field that was not observed is
omitted. The object is omitted when nothing was measured. Everything
request-indexed (files, request 2/3 context, outputs, tool calls, truncations)
covers only the contiguous requests the transcript reached, so a partly written
session never reports a file for a request it has not made.

An opening file is one the injected instructions name (trailing path segments
found verbatim, counted in `instruction_segments`) or one the client loaded
itself (`client_loaded`). Claude matches against its request-1 instructions;
Codex against the AGENTS.md body in `world_state`. Paths are matched lexically
and nothing is `stat`ed. A plain `repo_path` is sent only with workspace-label
consent, only for paths inside the session's working directory, and only when
backend admission accepts it unchanged (no forbidden fragment such as
`/users/`, no backslash or drive form). A relative path needs a proven base:
the session directory is known and, for Claude, the shell has not changed
directory (`cd`, `-C`/`-Cdir`, `--chdir`, ...); for Codex, the command record
states the session directory as its `cwd`. Any other path is sent as the tenant
attribution HMAC (`path_hash`, plus `ext`), and only with attribution consent.
An entry with neither identity is counted in `opening_file_overflow`. If the
instruction text outgrew its matching budget, file facts are unknown: no
opening file and no overflow are sent. Tool labels outside admission's
`[A-Za-z0-9_.:-]{1,64}` travel as `unknown`. Forks and
transcripts that start with copied records keep only `client_version`; for
Codex that includes the shared prelude parser's verdict (another session's
`session_meta` before the first usage). MCP tool
names collapse to `mcp`. No text leaves the Mac.

The in-window state is held to 256 KiB under the daemon heap model: up to
128 KiB of instruction text for matching, and the rest for tracked files, calls
and request blobs. It is freed at the freeze. Once the upload policy picks
each file's identity, the local candidates are released; a later application
can only withhold more. The configuration fingerprint is
the device-salted SHA-256 of a stable running digest over the configuration
parts (instructions, memory, skills, agents, MCP names and MCP instructions).

Backend admission must deploy before this field merges, and the runtime release
must follow it.
