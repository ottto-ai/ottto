# Privacy

Ottto separates local enriched data, live telemetry, integration connectors,
cloud billing connectors, and calculated estimates. The local platform keeps
local state and secret material on the Mac unless a user-approved setup or
diagnostics flow sends a redacted payload.

## Local Ownership

`ottto-service` owns:

- account binding metadata;
- setup-run binding metadata;
- source/app health;
- local control token storage;
- repair planning and backups;
- diagnostics redaction;
- update and uninstall state.

Agents, the CLI, the macOS app, and the web app are clients. They should not
duplicate local setup or repair logic.

## What Stays Local

The local platform must not upload raw prompts, raw responses, tool output,
command output, browser cookies, OAuth credentials, API keys, passwords,
absolute local paths, or raw provider account ids.

Local usage snapshots use derived and redacted fields such as session ids,
timestamps, usage totals, model usage, hashed workspace identity, and
display-safe account or plan evidence.

## Live Telemetry

Live telemetry is source-level opt-in. Setup can mint scoped setup keys and
write local source config through `ottto-service`. Opt-out must remove fenced
local config or Keychain state before backend setup-key revocation completes.

## Repair Boundaries

`ottto fix --json` returns repair authority metadata. Terminal repair is allowed
only for setup-safe actions tied to an active setup-run binding. Credential,
auth-adjacent, stale-account, or disconnected cases require browser approval.

## Diagnostics Redaction

Diagnostics collection is local-only by default. Uploads require explicit
approval, retention disclosure acceptance, and either an active login or a
support claim. Redaction covers local paths, secret tokens, account identifiers,
machine identifiers, raw prompts, and command output before display or upload.

## Reporting Guidance

Support and agents should summarize status and next actions. Do not paste full
diagnostics payloads or raw JSON containing local identifiers unless the user
explicitly asks and the payload has been reviewed for redaction.
