//! Parser and scan-identity versions: per-source parser provenance, the
//! scan identity folded into each candidate's file fingerprint, and the
//! local scan-index, opened-object and terminal-disposition identities.

use crate::snapshots::*;

// Parser versions describe parser provenance only. They MUST NOT be reused as
// incremental-scan identity or historical replay policy: a parser build bump
// is not proof that every historical session changed semantically.
// v16: the Codex state-only fallback now treats a session whose rollout was
// parsed in ANY prior scan run (tracked in the persisted scan index) as
// covered, instead of only sessions parsed in the current run. The version
// bump re-walks every rollout once so the backend supersedes the stale
// unattributed "Other" totals that the previous (run-scoped) check produced
// on every incremental scan.
// claude_code v8: every Claude Code usage row now carries a derived
// `context_bucket` (long/short) selector so turns that ran on the "(1M
// context)" window are attributed separately (see
// CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS). The per-row selector shape
// changed, so the bump re-walks every Claude session once to re-emit at v8.
// v17: Codex per-model usage now carries per-turn reasoning_effort
// claude_code v9: each Claude Code session origin now carries
// `used_workflow_orchestration` (true when the local
// `<session>/workflows/wf_*.json` footprint is present, i.e. the Workflow tool
// / dynamic multi-agent orchestration ran). The bump re-walks every Claude
// session once so already-scanned sessions re-emit with the new origin field.
// claude_code v10: Claude Code `type=ai-title` rows now feed
// `session_display_name_source=ai_title`, which the private API normalizes to
// `local_transcript_title`. The bump re-walks existing project JSONL files so
// sessions that previously only had first-prompt/fallback names can be
// superseded by Claude's generated title.
// claude_code v11: captured Claude Code work-attribution keys now ride inside
// selector_context so already-scanned sessions re-emit with subagent, skill,
// plugin, and MCP server selector rows. `attribution_mcp_tool` stayed stripped
// from that first contract because of its higher cardinality.
// claude_code v12: each Claude Code session now carries session-level latency
// aggregates (`avg_duration_ms` / `max_duration_ms`) derived from per-turn
// wall-clock durations — each assistant API response's first content-block
// timestamp minus the preceding `type=user` record (prompt or tool_result).
// Claude Code transcripts carry ms-precision RFC3339 timestamps on every record
// but no first-token marker, so TTFT stays absent (unlike Codex `task_complete`,
// which supplies both). The bump re-walks existing Claude sessions once so
// already-scanned sessions re-emit with the duration aggregates populated.
// claude_code v13: Task-tool subagent transcripts (`<sessionId>/subagents/
// agent-<agentId>.jsonl`) carry the parent's `sessionId` on every line, so they
// used to collapse onto the human parent session. They now re-key to a distinct
// `<parentSessionId>_<agentFileStem>` id (see `claude_subagent_source_session_id`)
// and stand up as their own `isSidechain=true` -> ai_agent sessions. The bump
// re-walks existing project JSONL once so already-scanned subagent files re-emit
// under the new id instead of remaining folded into their parent.
// claude_code v14: Claude Code session titles now also come from the Claude
// desktop app's per-session store (`~/Library/Application Support/Claude/
// claude-code-sessions/<accountCtx>/<workspace>/*.json`, `cliSessionId` ->
// `title`), emitted as `session_display_name_source=desktop_title`, plus a
// Codex-style first-user-prompt fallback (`first_prompt`) for pure-CLI
// sessions. Transcripts almost never carry `ai-title`/`summary` records, so
// most Claude sessions previously uploaded with no title at all. The store is
// folded into the scan fingerprint (see `ClaudeTitleMetadata`) so a title
// arriving after the transcript was scanned still re-emits, and the bump
// re-walks every Claude session once so existing sessions pick up titles.
// claude_code v15: local OTLP reasoning-effort enrichment no longer treats
// Claude's aggregate cache-creation count as a 5-minute TTL. The one-shot
// backfill re-enriches transcripts indexed by v0.1.77 from their existing
// content-free effort sidecars after upgrade.
// claude_code v16: derive per-session first-turn/peak context and compaction
// watermarks. The bump is required in addition to fingerprinting the new
// fields: the incremental scanner must revisit already-indexed transcripts
// before their new fingerprint can trigger a one-time backend re-upload and
// seed the machine-local posture cache.
// codex v19: extend those same context-posture watermarks to Codex rollouts
// (first-turn/peak context from `last_token_usage`, compactions from the
// `compacted` records). Same one-shot rationale as claude_code v16 — the
// incremental scanner must revisit already-indexed rollouts before their new
// fingerprint can trigger the one-time backend re-upload.
// v20/v17/v9: attach privacy-safe git repository identity locally. Raw paths
// and remotes never enter the snapshot payload.
// v21/v18: retain timestamped compaction events for the machine-local active
// session status and the additive backend snapshot contract.
// v22/v19/v10: activate the backend-gated session-attribution wire contract.
// Facts join the fingerprint only when present, and all three versions advance
// atomically so already-indexed history is revisited once.
// claude_code v20: complete the v13 subagent re-key. v13 only recognized a
// subagent transcript whose IMMEDIATE parent directory is `subagents`, which is
// true for a Task-tool agent (`<sessionId>/subagents/agent-<id>.jsonl`) but NOT
// for a Workflow-tool agent, whose transcript sits one or two levels deeper at
// `<sessionId>/subagents/workflows/<wfId>/agent-<id>.jsonl`. Those files carry
// the PARENT's `sessionId` on every line just like the Task-tool ones, so they
// kept collapsing onto the human parent session: an arbitrary workflow agent's
// slice (its model, its totals, `isSidechain=true` -> ai_agent, its context
// watermark) overwrote the real orchestrator session under last-writer-wins
// promotion. The subagent test is now "ANY ancestor directory is `subagents`",
// the parent session id is read from the PATH (the directory whose child is
// `subagents`) rather than from the in-file `sessionId`, and the workflow
// journal (`.../subagents/workflows/<wfId>/journal.jsonl`) is excluded from
// snapshot emission outright: it carries no `message.usage` and no `sessionId`,
// and its `journal` file stem is not unique across the workflow directories of
// one parent session. The bump re-walks every Claude transcript once so already
// scanned workflow-agent files re-emit under their own
// `<parentSessionId>_agent-<agentId>` id instead of over their parent.
// claude_code v21: subagent sessions get real display names. A re-keyed
// `<parentSessionId>_agent-<agentId>` session now emits
// `session_display_name_source=agent_label` built from the best available
// durable label material — Workflow run-manifest `label`
// (`workflows/wf_*.json` -> `workflowProgress[].label`, e.g.
// `probe:data-model`) > Task sidecar `description` (`agent-<id>.meta.json`,
// e.g. "Fix flaky backend tests") > sidecar `agentType`. Parent provenance is
// emitted separately, so it is not duplicated inside the child title. The
// first-prompt TITLE fallback is suppressed for subagent transcripts (their
// "first prompt" is the injected Task prompt body; the operator decision is
// short titles yes, prompt content no), while first-prompt MATERIAL still
// feeds attribution grouping. Naming sidecars (meta.json, workflow manifest,
// parent desktop title) join the subagent scan fingerprint so late-arriving
// labels re-select unchanged transcripts, and the scan-identity bump below
// re-walks already-indexed subagent files once so EXISTING agent sessions
// re-emit with names instead of staying on their generic fallbacks.
// claude_code v22: consume Claude Code's transcript-native `custom-title`
// records, including the PR-fixer slug emitted by automated repair sessions;
// reject continuation boilerplate as a first-prompt title; and keep subagent
// task labels independent from their parent relationship. The bump revisits
// existing transcripts so corrected titles replace already-uploaded fallbacks.
// v23/v23/v11: injected AGENTS/environment envelopes are not human prompts.
// Skip them before selecting first-prompt title and attribution material, then
// continue to the first real task message. All scan identities move so already
// indexed sessions are revisited and stale shared-envelope template groups are
// removed or replaced by task-specific opaque groups.
// codex v24: constrained "You are the <role> agent/worker/orchestrator" startup
// prompts expose the role as a safe title instead of falling back to the model
// or repository. The full prompt remains private and is never used as a title.
// codex v25: Codex response-item user messages carry injected prompt scaffolds
// as separate content elements. Strip each full element before title/template
// normalization; the shared 255-character normalizer used to truncate the
// recommended-plugins element before its closing tag, making it look human.
// claude_code v25: current Claude transcripts write one compaction twice: a
// `compact_boundary` system record and a legacy `isCompactSummary` user record
// a few milliseconds apart. Pair those provider records into one event while
// retaining support for transcripts that carry only one of the two shapes.
// codex v26: Codex Desktop persists the authoritative parent -> child graph in
// `state_5.sqlite.thread_spawn_edges`, while many rollout headers expose only
// `thread_source=subagent` and omit the parent object. Join that bounded local
// sidecar so existing Codex child sessions emit exact parent/root/depth facts.
// Codex v27 / Claude Code v26 add privacy-safe hourly Browser, Chrome, and
// Computer Use activity to the existing content-free activity summary.
// claude_code v27: attribute reasoning effort per API request instead of
// reconciling hourly aggregates. Claude Code stamps the top-level `session.id`
// on subagent OTLP records, so evidence keyed by session id alone never reached
// a sidechain transcript -- every subagent session reported effort-unknown --
// and the pooled subagent requests also overflowed the parent's fit check,
// dropping the parent's effort for that hour too. The sidecar now carries the
// API request id and the transcript repeats it as `requestId`, so each turn
// takes its own observed tier. Scan identity does NOT move: which session a file
// maps to is unchanged, and the effort sidecar fingerprint already re-selects a
// transcript whose evidence grew after its final write.
// codex v28: forked subagent rollouts may contain a physical copy of their
// parent's history. Bound all session-derived telemetry to the child's own
// rollout suffix, using Codex's native ordinal when present and the legacy
// inter-agent trigger marker otherwise. Usage is accounted from the exact
// per-response `last_token_usage`; cumulative totals remain a reset-safe
// fallback/checkpoint. Existing indexed rollouts must be revisited once.
// codex v30: resolve `execution_mode` through the provider surface instead of
// reading `source` alone. This changes the attribution derived from unchanged
// session headers in both directions -- `codex_exec`-only rollouts gain the
// headless fact, and desktop-originator rollouts that merely carry
// `source: "exec"` correctly lose it -- so the derivation must not keep
// claiming v29 provenance. Existing indexed rollouts must be revisited once.
// codex v31: turn a spawned agent's content-free `agent_path` leaf into the
// existing consented `agent_label` attribution label. Parent provenance stays
// in its own graph facts and no prompt material enters the label. Existing
// indexed subagent rollouts must be revisited once.
// codex v32: Codex Desktop's create-thread path records the parent only in the
// trusted `threads` row: `thread_source=agent_created_thread` plus a
// machine-generated `<codex_delegation>` wrapper in `first_user_message`.
// Import that content-free source-thread id into the existing family graph.
// The per-session sidecar fingerprint already includes family position, so
// affected immutable rollouts are selected without a global scan-identity
// bump; unrelated sessions stay untouched.
// codex v33 adds the bounded, content-free context-curve derivation and its
// owned-request indexing. This must remain a distinct parser revision from
// v32's created-thread lineage import so both derivation changes replay once.
// codex v34 attempted to admit provider-created child rollouts from cumulative
// usage equality plus representation-level absence from the parent ledger.
// That predicate repeats at counter resets and optional-field variation can
// manufacture absence, so it is not an ownership proof. v35 removes it. A
// fresh physical child is admitted only from Codex's native creation layout:
// the trusted sidecar edge and creation time, an identity-bound paginated
// session_meta at ordinal zero, the child's task_started preamble, and one
// complete gap-free/non-retrograde ordinal+timestamp stream. Legacy copied
// prefixes may diverge only before a later observed parent signature; parent
// ledger EOF is never treated as provider-final extent.
// codex v36 removes the created-thread history_base/ordinal authorization
// shortcuts and requires the native witness for every such paginated shape.
// It also binds the first record to the sidecar creation time within five
// seconds and, when Codex exposes them, corroborates the opened file against
// its state-row rollout path/times and thread-history byte/ordinal extent.
// codex v37 promotes allowlisted SKILL.md reads from the existing activity
// summary into canonical opaque skill attribution facts. This makes the
// Sessions skill facet work for Codex without uploading paths or prompt text.
// codex v39 finds SKILL.md references with the shared path extractor (any
// skills root, nested `.system`/synced layouts, relative paths, filename
// boundaries) and emits capability marker v2 when every reference was named.
// codex v40 pairs `model_context_window` with each context watermark (first,
// peak, last turn), read from the same owned token_count record. Scan identity
// is unchanged: an unchanged rollout is not selected. A changed rollout
// re-reads Full once, because retained Tail reductions and group receipts are
// scoped by this version. The windows stay outside every hash.
pub const CODEX_SNAPSHOT_PARSER_VERSION: &str = "codex_jsonl:v40";
pub(in crate::snapshots) const CODEX_CREATED_THREAD_TIME_TOLERANCE_NANOS: i128 = 5_000_000_000;
// claude_code v30: retain the exact response ids for counted transcript usage
// in local memory. Account attribution can then prove that every billed request
// appears in one-account local OTLP evidence while safely tolerating auxiliary
// requests (such as prompt suggestions) that Claude records only in OTLP under
// the same root session. Raw request ids are never uploaded except where the
// upload contract already carries them; persisted only in the local
// durable-tail store (class L).
// v31 resolves Claude assistant content-block records as one complete provider
// response before admitting usage. Claude Code sidechains progressively update
// `output_tokens` across repeated (`message.id`, `requestId`) rows; taking the
// first row undercounts the response. Explicit `forkedFrom` rows are copied
// branch history and are excluded from every child-session metric.
// v32 retains the exact resolved occurrence in local memory and joins it to
// current api_request + enhanced llm_request evidence. Only a healthy complete
// family census can replace usage with the reported occurrence union. The
// same census may exclude a legacy top-level fork's duplicated leading
// response prefix, but only when exact current API/trace evidence assigns each
// excluded request to another root; provider graph facts remain untouched.
// v34 emits Claude Code's `attributionMcpTool` as `attribution_mcp_tool` beside
// the four existing attribution selectors. Tool labels are normalized to the
// backend's selector identity before applying its 128-character and 100-row
// admission bounds.
// v35 resolves progressive records for one Claude/Fable provider response in
// provider-timestamp order rather than physical append order. Fable can append
// an earlier partial observation after its later terminal observation; the
// canonical fold accepts monotonic population of every usage counter while
// retaining fail-closed handling for chronological regressions and incomparable
// states at the same provider instant.
// v38 qualifies original usage-event clocks and complete mixed-root delivery.
// Ordinary parser invalidation retains scan identity and accounting authority.
// v39 records skill evidence from the tool walk: `Skill` tool input as an
// invocation, SKILL.md paths read by `Read`/`Bash` as references (shared
// extractor with Codex), and capability marker v2 when every reference was named.
// v40 reads `output_tokens_details.thinking_tokens` into `reasoning_output_tokens`
// (clamped to `output_tokens`). Scan identity is unchanged: only changed
// transcripts re-parse, so a 0 under v39 means "not read", not "no thinking".
pub const CLAUDE_CODE_SNAPSHOT_PARSER_VERSION: &str = "claude_code_jsonl:v40";
// v13 makes the provider response timestamp authoritative for both Pi usage
// record shapes and reconciles every exact cross-shape occurrence for a reused
// response id. This prevents envelope write time from moving current records
// into a different hour or turning a valid transitional pair into loss.
pub const PI_SNAPSHOT_PARSER_VERSION: &str = "pi_jsonl:v13";

// Frozen scan-identity versions. They intentionally begin at the versions used
// by the 0.1.91 baseline so upgrading to semantic sync does not itself select
// every indexed transcript. Advance only for a reviewed scan-index derivation
// change, never for ordinary parser implementation work.
//
// claude_code v20 IS such a change and is the reason this constant moves with
// the parser version here: the scan index skips a transcript whose bytes and
// mtime are unchanged, so a parser-version bump alone (which no longer feeds
// `scan_file_fingerprint_with_context`) would leave every already-indexed
// workflow-agent file permanently skipped and the fix inert on existing
// installs. The derivation that changed is which SESSION a file maps to, which
// is scan identity, not parser provenance. Cost of the one-time revisit stays
// bounded: an unchanged session re-parses to the same semantic fingerprint and
// is suppressed as a semantic no-op instead of being re-uploaded.
// claude_code v21 also moves scan identity, for the same reason v20 did: the
// scan index skips a transcript whose bytes and mtime are unchanged, and the
// new naming-sidecar fingerprint components only guard FUTURE label/title
// changes — they are computed against entries indexed under the old identity,
// which recorded no sidecar contribution at all, so without the bump every
// already-indexed subagent transcript would keep its generic fallback name
// forever. The one-time revisit stays bounded: an unchanged session re-parses
// to a new title but is otherwise a semantic no-op-sized re-upload of
// already-known usage.
// Capability activity changes transcript-derived session semantics. Advance
// scan identity so already-indexed local history is revisited once; unchanged
// files still converge through the semantic no-op path after the new summary
// has been uploaded.
// codex v30 moves scan identity for the same reason: the execution-mode
// derivation changed for headers that are already on disk and will never be
// rewritten, so without the bump the scan index would skip every one of them
// and the corrected attribution would only ever reach sessions created after
// the upgrade. The one-time revisit stays bounded - a rollout whose derived
// facts did not actually change re-parses to the same semantic fingerprint and
// is suppressed as a no-op instead of being re-uploaded.
// codex v31 also moves scan identity: historical rollout headers already carry
// `agent_path`, but those immutable files would otherwise stay indexed under
// the version that emitted no label.
// codex v32 revisits existing rollouts once so activity-derived skill facts
// backfill naturally instead of appearing only on sessions touched later.
// codex v34 revisits retained rollouts once for the v39 skill extractor and the
// v2 capability marker; unchanged sessions then converge as semantic no-ops.
pub const CODEX_SCAN_IDENTITY_VERSION: &str = "codex_jsonl:v34";
pub(in crate::snapshots) const CODEX_CONTEXT_BUCKET_REVISIT_FROM_UNIX_NANOS: u64 =
    PROVIDER_PRICE_LINE_EFFECTIVE_FROM_UNIX_SECONDS * 1_000_000_000;

/// Scan identity folded into one candidate's file fingerprint: the source's
/// identity plus the bounded Codex price-bucket revisit for recent rollouts.
pub(in crate::snapshots) fn candidate_scan_identity(
    source: SnapshotSource,
    modified_unix_nanos: u64,
) -> String {
    if source == SnapshotSource::Codex
        && modified_unix_nanos >= CODEX_CONTEXT_BUCKET_REVISIT_FROM_UNIX_NANOS
    {
        format!(
            "{};{CODEX_CONTEXT_BUCKET_REVISIT}",
            source.scan_identity_version()
        )
    } else {
        source.scan_identity_version().to_string()
    }
}
// v28 revisits Claude history once because the v34 MCP-tool selector changes
// transcript-derived session semantics for operators who enabled attribution
// capture. Sessions parsed with capture off remain semantic no-ops.
// v27 adds claude_code_effective_input_context() reconciliation against
// usage.iterations[] to fix resumed-session first-turn baseline (all-zero
// top-level fields while iterations carry real prompt), and multi-iteration
// responses where the largest prompt is an iteration not the top level.
// Every snapshot rescans to apply the watermark fix retroactively.
// v26 deliberately revisits Claude history so every snapshot clears the old
// safety state and future-captured, trace-owned occurrence unions can mint the
// reported-usage contract. Historical v31 sidecars remain unproven.
// v28 binds context-posture scalars to that same owned-occurrence proof. Legacy
// Fable/takeover transcripts can copy an unmarked predecessor prefix; v32 usage
// reconciliation and v33 curves excluded it, but first/peak/last context and
// compactions still came from the raw transcript. Revisit Claude history once
// so proven successors replace those scalars and unresolved predecessors omit
// them instead of publishing inherited context as child-owned.
// v30 revisits Claude history once for the v39 skill evidence and the v2
// capability marker, so stored empty skill lists are corrected, not only new ones.
pub const CLAUDE_CODE_SCAN_IDENTITY_VERSION: &str = "claude_code_jsonl:v30";
pub const PI_SCAN_IDENTITY_VERSION: &str = "pi_jsonl:v13";
pub(in crate::snapshots) const LOCAL_SCAN_INDEX_IDENTITY_VERSION: &str = "semantic_sync:v2";
pub(in crate::snapshots) const OPENED_OBJECT_IDENTITY_VERSION: &str = "opened_object:v2";
// Legacy compatibility identity, retained byte-for-byte. The reader has no
// active line limit; consumed record loss must never advance this generation.
pub(in crate::snapshots) const JSONL_TERMINAL_DISPOSITION_GENERATION: &str =
    "bounded_jsonl_terminal:v1:max_line_bytes=16777216";
