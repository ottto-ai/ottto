# Plugin MCP inventory declarations

Configured MCP inventory includes servers declared by installed plugins when
that app explicitly enables the plugin. Explicitly disabled installations retain
rows with `disabled: true`; cached files without matching app configuration do
not create rows. Existing manually configured servers take precedence.

Claude Code discovery joins `plugins/installed_plugins.json` installation paths
with `enabledPlugins` settings from the same user or registered account directory.
`settings.local.json` overrides `settings.json` within that directory. Runtime
names use `plugin_<plugin>_<server>`. Account roots use the existing registered-slot
decoder, including customer-owned paths outside the managed folder. Stale or
unregistered folders are not inspected; an unreadable registry grants no account
roots. A plugin enabled in any registered account keeps the machine/app inventory
row active.

Codex discovery joins explicit `[plugins."name@marketplace"]` enablement with
that plugin's version directory in `plugins/cache/marketplace/name`. No active
version index was established, so discovery uses a documented fallback: a
single version is unambiguous; multiple versions are considered only for an
explicitly enabled plugin. All-numeric dotted versions sort numerically; opaque
versions sort by directory modification time, with a stable path tie break.
An explicitly disabled plugin with several cached versions is omitted until its
active version can be established. Missing enablement or missing installation
files never create a row.

Both apps read `.mcp.json` declarations and their app's plugin manifest
`mcpServers` (inline names or relative declaration files). Referenced files must
resolve inside the installation. Only server names are retained; launch
commands, environment, endpoints and tool definitions are discarded. Plugin
rows use the existing wire shape, with no transport, no tools, and
`reachable: false`. They are never executed or probed by inventory collection.
Reachability and footprint remain unmeasured for these declaration-only rows.

Codex emits declared server keys, including `cua_repl` when its installed plugin
is configured. Existing computer-use capability rows are unchanged. The possible
overlap between the MCP row and capability row requires product semantics review;
this change does not combine or remove either category.

Validation covers installed/enabled, installed/disabled, cache-only and missing
cases, registered-account isolation/aggregation, stale folders and unreadable registries,
version selection, inline
and referenced manifests, wire state, and explicit MCP configuration precedence.
No backend or wire schema change, runtime installation, or release is included.
