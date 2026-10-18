# Codex harness-injected user messages in context composition

Codex puts the AGENTS.md chain (`agents_md.instructions`) and the environment block (`environments.environment_context`) into user-role messages. The composition parser entered the user-role branch but recorded only developer-role text, so these blocks were in no category. A read-only count over 906 local Codex rollouts (2026-10-11 to 10-18, chars/4, before residency) found 7.28 M developer tokens counted, 3.38 M injected user-role tokens dropped (AGENTS.md 3.26 M) and 0.91 M typed prompt tokens skipped on purpose.

A user-role block now counts as `harness_attachments` when its `content_item_kinds` label is not `user.*`. Rollouts without labels fall back to the injected prefixes `# AGENTS.md instructions`, `<environment_context>` and `<user_instructions>`. Typed prompts stay skipped, matching the Claude parser. `COMPOSITION_PARSER_VERSION` moves to v2, so cached workspaces rescan once.

Unchanged: wire fields, cadence, cache layout, Claude parsing. Focused `context_composition` tests pass locally (27 passed); full validation runs in Public CI.
