# Claude Code Fast default reported as off

Claude Code keeps Fast off until `/fast` saves `fastMode` in a settings file.
The daemon used to report `fast_mode_enabled` as unknown when no file in the
settings chain had that key, so the first switch to Fast looked like a value
becoming known rather than a change from off.

When at least one settings file in the chain is read and parsed, and none of
them sets `fastMode` or `fastModePerSessionOptIn`, the Claude Code runtime
defaults now report `fast_mode_enabled = false` with the source
`claude_code.default.fastMode`. The source names the default, not a key in a
file. Explicit `fastMode` values and the rule that `fastModePerSessionOptIn`
makes the durable default off are unchanged, as are their sources.

A missing, unreadable, oversized or unparseable chain still reports nothing,
with the `claude_runtime_defaults_unreadable` diagnostic. Because Fast is now
always known once a file is read, a readable chain always carries runtime
defaults. The `claude_runtime_defaults_not_configured` diagnostic and its
unsupported capability are gone; the other fields stay unset when their keys
are absent.

Codex is unchanged. Codex can default to Fast on some plans, which is why
`fast_default_opt_out` exists, so a `config.toml` without `service_tier`,
`[features].fast_mode` or an opt-out still leaves Fast unknown.

No new file is read, no field is added, and polling is unchanged. A reporting
stream whose chain has no Fast key changes from unknown to `false` once after
upgrade, so its runtime-defaults content changes once.

Validation:

- readable settings without a Fast key report off with the default source,
  while other fields stay unset;
- explicit `fastMode: false` keeps its key as the source;
- missing and unparseable settings still report nothing;
- `fastModePerSessionOptIn` and explicit `fastMode: true` cases unchanged;
- Codex config without Fast keys still reports Fast as unknown, and explicit
  `[features].fast_mode` values are reported as set.
