# Codex Source Policy

Review tier: `official`

## Default Posture

- `local_sessions` defaults on for official pilot installs because it reads local transcript files and uploads aggregate session usage only.
- `otel_config` requires setup and user/org telemetry controls before live telemetry is enabled.
- `quota_status` requires setup because the current implementation reads the local Codex OAuth credential and calls an undocumented ChatGPT usage endpoint. It must redact local paths, account secrets, and token material from all uploads.

## Documented Surfaces

- Codex local transcript JSONL files may be read by `ottto-locald` for aggregate local usage snapshots.
- Codex `[otel]` settings may be inspected or managed only through the explicit live telemetry setup path.
- Local quota/status observations may be captured from safe agent status snapshots when they are available from documented local CLI/status surfaces.

## Undocumented Surfaces

- Do not scrape browser sessions, cookies, private web UI state, or account pages.
- Do not default-enable quota/status probes that read `auth.json` token material or call private ChatGPT endpoints.
- Do not infer undocumented selector fields from model names or provider identity.
- Do not add static platform fields to the manifest. Runtime operation state reports unsupported or degraded local availability.

## Local-Only Behavior

- Local transcript reads stay on the user's machine until transformed into aggregate usage or collector-health records.
- Local OAuth credential reads for quota/status must stay in `ottto-locald`; only redacted quota windows, credit state, plan evidence, and collector health may leave the machine after setup.
- Local status collection must hash or omit workspace, path, account, and machine-specific details before upload.

## Upload Boundaries

- Do not upload raw Codex prompt, response, command output, tool output, or local file paths.
- Do not upload OAuth access tokens, ID tokens, refresh tokens, cookies, account pages, or raw provider responses.
- Preserve selector context v1 names such as `service_tier`, `batch_mode`, `billing_channel`, `auth_mode`, and `gateway_provider`.
