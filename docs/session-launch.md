# Account-bound terminal sessions

The authenticated local-control commands `session_launch_prepare`,
`session_launch_consume`, `session_launch_report`, `session_launch_status`,
`session_launch_cancel`, `session_launch_recent_folders`, `account_nicknames`
and `account_nickname_set` use command-scoped protocol **28**. Every older
command retains its existing version. Responses are optional-field DTOs with
inert unknown enums. An unknown command/version on an older daemon means the
feature is unavailable; it must not trigger an alternative launch or write.

## Handoff

Prepare accepts a provider (`claude_code` or `codex`), slot id, expected account
and organization/workspace hashes, and exactly one of `folder.path` and
`folder.recent_id`. A recent id is an opaque, process-keyed HMAC that resolves
only through the last 30-second local projection.

The daemon compares current local identity claims with the last verified
collection and, for a registered slot, its accepted binding. Claims never adopt
or move a binding. Missing, mismatched, duplicate, or unverified logins refuse
the launch. Prepare and consume perform this check independently. Retry,
cancel, account mutation and restart invalidate pending handoffs.

Claude also needs a current exact-slot OAuth login, classified locally without
refresh or provider commands. An expired access token with a live refresh token
can open an interactive session, where the provider CLI owns renewal. A reported
background refresh in progress blocks until it finishes. Missing, cleared or unreadable
credentials cannot fall back to a stored Console key. Codex reads only the
existing saved provider-verified collection and current credential claims; this
projection performs no login/model probes, provider reads or scheduler wakeup.

The folder must be absolute, canonical, a directory on a local filesystem,
and outside the Ottto support directory. Filesystem root and the effective
user's home root are refused. The handoff records the folder's device and inode.
macOS uses `MNT_LOCAL`; portable Linux tests refuse known network/FUSE types.

Launchers live in the owner-checked `session-launch/` support subdirectory at
0700. The daemon opens the directory without following its final symlink and
creates each 0700 launcher with `openat(O_EXCL|O_NOFOLLOW)`. Its entire content
is a shebang, `rm -f -- "$0"`, and an `exec` of the quoted, pinned Ottto CLI
path with `launch-check --exec`, the opaque launch id and its one-time secret.
No folder or provider account configuration is written into the launcher.
Startup removes stale launcher files after acquiring the daemon state lock.

Consume is token-authenticated and CLI-only. The registry claims the first
attempt atomically, even on failure. It rechecks the secret, monotonic
120-second deadline (also bounded by wall time across system sleep), local binding, effective-auth settings, folder identity
and the pinned CLI. A successful consume returns an optional typed exec plan
and an attempt secret. Status becomes `starting`; the UI must never call it
`started`. `SessionLaunchReport` accepts only the exact attempt secret and a
typed chdir/folder/exec failure. The other states are `pending`, `blocked` and
`expired`; unknown states are inert.

`ottto launch-check --exec` is hidden from ordinary help. It reads existing
control state and contacts the running daemon directly, with no state creation
or daemon autostart. It opens the folder, compares descriptor metadata,
`fchdir`s, applies the environment plan, and replaces itself with the provider
CLI. No launcher shell runs after the environment scrub. Directory and exec
failures are reported before exit. Launch blocks use exit 60, malformed plans
use 2, and an unavailable daemon uses 10. It never runs provider doctor, auth
or login commands. The daemon runs only a bounded, three-second `--version`
probe at prepare; supported ranges are Claude Code >=2.0 and <3, and Codex
>=0.150 and <1. Unknown versions refuse with `cli_version_unsupported`.
The daemon records the version and executable path, dev/ino, size and mtime.
Any executable change before consume refuses with `cli_changed`.
Lookup searches the inherited daemon PATH first, then known per-user install
prefixes; Codex app bundles come last, and Claude Desktop's private binary is
excluded. The version probe includes the selected install's bin directory in
PATH so npm/nvm shebang interpreters work under launchd. That exact PATH is also
applied at exec, with the same selected folder and account environment as the probe.

## Effective environment and settings

Both providers inherit the terminal environment minus the daemon-owned scrub
list in `session_launch/preflight.rs`. `HOME`, `USER`, and `LOGNAME` are forced
from `getpwuid_r(geteuid())`, including in the version probe. Claude's default
slot leaves `CLAUDE_CONFIG_DIR` unset. Registered Claude slots preserve the
exact stored string, including trailing slash and Unicode spelling. Codex
sets both `CODEX_HOME` and `CODEX_SQLITE_HOME` to its absolute selected home.
`OTTTO_CONTROL_TOKEN` is always removed before exec.

The Claude scrub list includes account/config selectors, API/auth/OAuth tokens,
gateway URL/header overrides, Bedrock/Vertex/Foundry/Anthropic-AWS route selectors
and credentials, and inherited Claude session entrypoint variables. The Codex
list includes home selectors, API keys, ambient access tokens, OAuth refresh/revoke URL
and client overrides, OpenAI/Azure endpoint and organization overrides, and
inherited profile selection. The source constants are the
authoritative complete lists; the CLI applies the returned lists unchanged.

The evaluators support Claude Code **2.x** and Codex **0.x**. Claude checks the
selected home settings, project and project-local settings in cwd and its
ancestors, the main checkout settings for a linked worktree, and the platform
managed JSON. It reuses the existing alternative-auth precedence evaluator.
Any auth-routing scrub key in settings `env`, API helper, forced non-Claude.ai
login, or different forced organization refuses. Unreadable/malformed relevant
files also refuse. Managed preference files, drop-ins, cached remote policy
files and policy helpers that cannot be evaluated statically refuse as
`config_unsupported`; helpers are never executed.

Codex checks its selected `config.toml` and active profile. Non-OpenAI providers,
redefined OpenAI providers, endpoint overrides, API login, a different forced
workspace, or a credential store other than file are refused. System
`/etc/codex/config.toml`, project `.codex/config.toml` and
managed policy that this evaluator cannot evaluate are presence-refused.
Reasons identify a typed settings layer, never a settings value or path.
This conservative evaluator can reject a configuration the provider would
accept. It does not fetch remote organization policy.

Vendor references: [Claude settings and precedence](https://code.claude.com/docs/en/settings),
[managed sources](https://code.claude.com/docs/en/managed-settings),
[environment variables](https://code.claude.com/docs/en/env-vars), and
[Codex configuration reference](https://developers.openai.com/codex/config-reference/).

## Recent folders and privacy

The local worker reads at most ten roots per provider, sixteen bounded live
Claude registrations per root, 200 non-archived Codex thread rows per home, and
two composition v2 indexes. SQLite is read-only with a 100 ms busy timeout and
a deadline progress callback. Composition projection reads no transcripts;
pins attribute main-checkout folders by the transcript's login root. Index
projections cache by file modification time. Paths are canonicalized and
deduplicated, with this-login items first and other Mac folders second.

The worker has a one-second caller deadline, a 30-second memory cache and a
100-item output cap. Partial results carry a reason code. Missing files or an
unsupported SQLite schema do not trigger new scans. Paths cross authenticated
local control only: no uploads, diagnostics, analytics or disk history are added.

## Nicknames

`account_nicknames` reads the 0600 local cache only. The optional
`account_nicknames` field in existing status-upload responses carries
`[{pair:{source,account_identifier_hash,organization_identifier_hash},nickname,revision}]`.
The no-organization component is an explicit empty string backed by positive
provider evidence. A missing organization hash remains unknown and cannot
become a nickname target. The daemon applies
only strictly newer revisions, keeps null tombstones, and admits only pairs
present in that upload request. Missing fields preserve the cache. Lookup
errors or malformed optional metadata never fail ingest.

Requests are tagged before relay-token issuance with device/org credential
generation and a local lifecycle epoch. Old-generation responses are dropped.
Reclaim/logout invalidates cache state; a different device/org generation
cannot read an earlier cache. The upload cadence remains unchanged.

`account_nickname_set` requires a current verified local login and writes once
with the existing relay-token client to
`PUT /api/v1/agent-status/account-nickname`, with `machine_id`, the exact pair,
`nickname` or null, and optional `base_revision`. Backend principal checks own
organization/user authority and uploaded-pair eligibility. Requests follow no
redirects, parse success bodies only after 2xx, and never log body/error text.
Nickname validation matches the write endpoint: NFC, trimming, 40 characters,
no email-shaped text or controls, formatting characters (except emoji ZWJ),
private-use, unassigned or line/paragraph separators (Unicode 15.1 baseline).
401/403 makes editing not connected; no retry, offline queue or registration
is attempted. An older backend's absent upload field is a no-op.
Authorization rejection is persisted for the device/org generation and survives
daemon restart. Successful ordinary uploads do not clear that rejection;
reconnecting or reclaiming establishes new authority. Repeated unchanged
uploads update in-memory freshness and persist it at most every fifteen minutes;
changed revisions persist immediately.

Values are trimmed, at most forty Unicode codepoints, with empty meaning
delete. Controls, bidi override/isolate characters and email-shaped text are
refused. Nicknames are display data only, with redacted debug wrappers. They
never enter account matching, tags, billing, logs, diagnostics or analytics.
Folder paths stay on this Mac. Nicknames sync to your Ottto account.
