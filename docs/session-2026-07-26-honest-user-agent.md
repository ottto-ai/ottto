# Session: honest User-Agent on the Claude OAuth usage read

**Date:** 2026-07-26 · **Change:** `crates/ottto-service/src/agent_status.rs`

The daemon's `GET api.anthropic.com/api/oauth/usage` call presented itself as
`claude-code/<cli-version>` - an (incorrect) imitation of the Claude Code CLI,
whose real User-Agent is `claude-cli/<version> (external, cli)`. Anthropic's
support policy names tools that "misrepresent their identity to Anthropic's
servers" as an enforceable category, and the recorded provider-endpoints
posture (product repo,
`docs/efforts/cloud-sessions-provider-endpoints-implementation-handoff.md`)
is: be trivially identifiable and trivially benign - never spoof.

The call now sends
`ottto/<daemon-version> (subscription-usage-reader; +https://ottto.net)`.
`claude_code_user_agent(version)` became `ottto_user_agent()` (daemon version
via `compiled_release_version()` - the crate manifest is a 0.1.0 placeholder
and real release versions arrive through `OTTTO_RELEASE_VERSION` at package
time), and `collect_claude_oauth_usage` dropped its now unused `version`
parameter. A unit test pins the posture: the UA must start
with `ottto/` and must never contain `claude`.

Deliberately unchanged: the Claude Desktop cookie collector's browser UA
(sentinel-gated off, slated for removal under the multi-slot config-dir work)
and polling cadence (separate change).
