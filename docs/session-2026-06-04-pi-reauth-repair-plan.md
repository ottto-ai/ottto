# Session note — Pi repair: actionable provider re-auth plan (2026-06-04)

## Problem (0.1.12 P0, repair half)

`ottto verify --app pi` fails (the `openai-codex` subscription-OAuth route smoke can't
authenticate — the rotating provider OAuth token is expired/consumed), and
`ottto fix --app pi` then returns `status=blocked`,
`config_repair_not_supported` ("Pi does not support local config repair"),
`actions=[]` — a dead end. The customer sees a critical Pi source with **no actionable
recovery**.

## Root cause

`repair_source` retains only `WriteConfig` actions and, for any source where
`source_requires_config_patch` is false (Pi), sets `Blocked` /
`config_repair_not_supported` and clears all actions. The repair planner conflates
local-config repair with credential/auth repair, and `RepairActionKind` had no
re-auth variant, so a Pi route whose failure is an expired provider OAuth credential
(which only a provider re-sign-in can fix — the daemon can't re-mint a rotating token)
had no recovery path.

## Fix

- Add `RepairActionKind::ReauthProvider` (protocol) — an advisory action guiding the
  user to re-authenticate a failing provider the daemon cannot repair itself.
  Additive; the macOS app decodes `RepairAction.action` as a `String`, so no break.
- `repair_source`: for `SourceKind::Pi`, return `build_pi_reauth_repair_plan(...)`
  **before** the WriteConfig-only retain, producing `RepairPlanStatus::Proposed` with
  `message.code = "pi_provider_reauth_required"` and two actions — `ReauthProvider`
  ("Run `pi` and re-authenticate the failing provider, then retry Verify") +
  `VerifyTelemetry` ("Re-run Pi verification") — reusing the authority already
  computed by `propose_repair_plan`. Non-Pi no-config sources keep the existing
  blocked behavior.

`cargo build/fmt/clippy` clean; `cargo test -p ottto-service --lib` 318 passing (+1
new: `pi_reauth_repair_plan_is_actionable_not_blocked`).

## Follow-up (separate — the verify half)

Stop the Pi verify from **burning the rotating token** in the first place: never live-
smoke a subscription-OAuth route (`openai-codex`/`anthropic`/`github-copilot`) — verify
it passively from telemetry the local_sessions collector already uploaded, and surface
a `pi_oauth_reauth_required` **Warning** (not a hard smoke `Failed`) when none is fresh,
with the aggregate + standalone-action status updated to treat reauth-pending as
Warning. This change (`run_one_pi_route_verification` + `pi_route_aggregate_result` +
`run_pi_verify_source_action`) is planned but not in this commit.
