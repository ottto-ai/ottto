# 2026-08-15 — headless session role

## Outcome

A locally observed session that ran without an interactive terminal now carries
the role `headless`, so the Companion can title it honestly instead of showing
one undifferentiated "Codex session" row.

Measured on 737 local Codex sessions: 598 (81.1%) carry `originator: codex_exec`
and `source: exec` in their rollout `session_meta` and previously received no
role at all. The only non-interactive role that fired,
`thread_source == "automation"`, matched 6 of 737.

## What the role means

`headless` says exactly one thing: the provider recorded a non-interactive entry
point for this run. It is an attribute of a single session.

It does **not** say who or what started the session. A person typing
`codex exec` and a script calling `codex exec` write the identical header, so the
role can never be read as a parent, an agent, a controller, or a finished run.
It never enters the family graph and never produces an edge. Parent edges come
only from `parent_session_ref`, which is unchanged by this work.

Consumer wording must follow the same limit — "ran headlessly" or
"non-interactive", never "started by an automation".

## Changes

- `session_attribution::execution_mode(source, origin)` is now the single
  definition of how a run was driven. Codex resolves through the existing
  `codex_provider_surface`: headless exactly when the surface resolves to
  `codex_exec`. Claude Code keeps its existing mapping: `session_kind == "bg"`
  is `background`, `entrypoint == "sdk-cli"` is `headless`. Pi reports none.
- `direct_provider_facts` calls it for both sources instead of carrying two
  local copies of the rule. Fact order is unchanged.
- `active_sessions::active_session_kind` takes the snapshot source and returns
  `headless` after the subagent and automation checks. Most specific role wins:
  a subagent spawned through `codex exec` stays `subagent`.
- `ActiveSession.session_kind` documents the new value, the wording limit, and
  the rule that values are additive — an app that does not know a role must fall
  back to a plain title, not fail.

## Why `codex_provider_surface`, and the two shifts it causes

The two Codex signals disagree in real data, so reading `source` alone is not
safe. Deferring to the surface rule puts `originator` — the client that actually
ran the session — ahead of `source`, matching how the provider surface is
already resolved everywhere else. Two changes fall out, both toward saying less:

- **Wider, correctly.** Only `source == "exec"` used to produce the
  `execution_mode: headless` fact. Codex subagent rollouts put a spawn object in
  `source` instead of a string, so their `codex_exec` originator was the only
  remaining signal and was dropped. Those sessions now report the execution mode
  as well. Their `origin_kind: subagent` fact is unchanged and still separate.
- **Narrower, also correctly.** ChatGPT Work desktop rollouts write
  `source: "exec"` under `originator: "codex_work_desktop"` — 17 such sessions in
  the local corpus. They used to receive `execution_mode: headless`; they no
  longer do. Calling a desktop session "no interactive terminal" is exactly the
  overreach this attribute exists to avoid, and the same rollout is already
  reported as `provider_surface: codex_desktop`, so the two would have
  contradicted each other on the same row.

A table test pins every observed `originator`/`source` combination so the two
readers of this rule can never drift apart.

## Existing rollouts are revisited once

`CODEX_SNAPSHOT_PARSER_VERSION` and `CODEX_SCAN_IDENTITY_VERSION` both move to
`codex_jsonl:v30`. Without the scan-identity bump the incremental scanner skips
any rollout whose bytes and mtime are unchanged, so the corrected attribution
would have reached only sessions created after the upgrade — leaving the exact
corpus this work exists to fix permanently stale. The parser version moves too
because the derivation changed and must not keep claiming v29 provenance.

The one-time revisit is bounded, and the golden proves it: regenerating
`fixtures/snapshot-audit/semantic-envelope-golden.json` moved only
`parser_version`, `scan_identity_version`, `revision_hash`, and
`revision_v2_hash` across the 20 Codex cases. `content_hash`,
`snapshot_fingerprint`, and the component hashes are byte-identical, so a
rollout whose derived facts did not actually change is still suppressed as a
semantic no-op rather than re-uploaded.

## Not changed: provider-native parent ids

`source.subagent.thread_spawn.parent_thread_id` was checked and is already
consumed: `apply_codex_line` parses it into `SnapshotOrigin.parent_session_ref`,
and `direct_provider_facts` emits it as a `parent_session_ref` fact with kind
`provider_native` and strength `direct`. The backend already turns that fact
into a `parent` edge. No change was needed.

## Validation

- `scripts/public_repo_manifest_check.sh` — 327 file hash records, clean.
  `PUBLIC_EXPORT_MANIFEST.json` was regenerated from the git inventory for the
  three edited sources and this new note. `source_commit` is left untouched
  because this change did not come from a private export run.
- `scripts/public_repo_export_check.sh` — 326 tracked files, 0 rewrite-required
  references.
- `cargo test -p ottto-service -p ottto-protocol` — 1,441 + 50 + 10 tests,
  0 failures.
- `cargo clippy -p ottto-service -p ottto-protocol --all-targets -- -D warnings`
  — clean.
- `cargo fmt --check` — clean.

New tests cover the headless rollout shape, an interactive run staying
unlabelled, subagent precedence over headless, the originator-only proof, a
desktop originator overriding an `exec` source, a table over every observed
`originator`/`source` pair, and an assertion that the role produces no lineage
fact.
