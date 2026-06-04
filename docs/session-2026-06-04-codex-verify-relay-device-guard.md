# Session note — Codex/Claude verify: relay-device provisioning guard (2026-06-04)

## Problem (0.1.12 P0)

On a freshly-claimed Mac, `ottto fix --app codex` reports success but
`ottto verify --app codex` returns `no_fresh_telemetry` / `verified=false` /
`records_seen=0` — even after a real `codex exec` smoke session. On a machine with
prior `ottto setup` it verifies fine.

## Root cause

`verify_source` proves Codex/Claude telemetry by polling the backend for records that
the **local OTLP relay** forwards. That forward requires the relay device binding
(`FileDeviceStore`) + the relay-device-secret (`OTTTO_RELAY_DEVICE_SECRET_ACCOUNT`)
(`otlp_relay.rs` → `issue_relay_token` → `snapshot_client::load_snapshot_device_credentials`).
Those are provisioned only by `run_install_source_action` (the setup-run install
action) — **not** by claim completion (`auth_complete`) and **not** by `ottto fix`
(which only patches the agent's OTLP config). So on a fresh claim there is a window
where the device/secret are absent: the relay rejects every export with a 502 and the
telemetry is dropped, the backend poll returns 0, and `verify` reports the generic
`no_fresh_telemetry` — masking the real cause and racing the async provisioning.

## Fix

Add a provisioning guard to `verify_source` (codex/claude only — Pi uses a different
route-smoke path that returns earlier): before running the smoke, check
`relay_device_is_provisioned()` (mirrors `load_snapshot_device_credentials`: both the
`FileDeviceStore` binding and the relay-device-secret must exist). When they are
missing, return an accurate, actionable status —
`SourceVerificationStatus::ReconnectRequired` with `message.code =
"relay_device_not_provisioned"` and guidance to finish setup / retry — instead of
running a doomed smoke and reporting `no_fresh_telemetry`. `message.code` is a free
`StableMessage` string, so this is additive (no enum/contract break for the macOS app).

`cargo build`, `cargo fmt`, `cargo clippy` clean; `cargo test -p ottto-service --lib`
317 passing.

## Follow-ups (not in this change)
- Stronger fix: provision the relay device eagerly (at claim, or self-heal in
  fix/verify by driving the install flow / a token-only backend register endpoint) so
  a fresh-claim `fix`→`verify` *passes* rather than guiding. Infeasible to self-heal
  without a backend endpoint (the existing companion install-session requires a
  claimed `install_source` action), so it's scoped separately.
- Surface `relay_device_not_provisioned` in the macOS app as a "still setting up"
  state and in the `ottto-telemetry-doctor` skill (treat as retry/guide, not a hard
  failure).
- Pi subscription-OAuth verify (token burn) + `ottto fix --app pi` actionable re-auth
  plan — separate change.
