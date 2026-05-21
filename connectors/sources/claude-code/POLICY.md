# Claude Code Source Policy

Review tier: `official`

## Default Posture

- `local_sessions` defaults on for official pilot installs because it uploads aggregate usage and metadata only.
- `otel_config` requires setup and user/org telemetry controls before live telemetry is enabled.
- `quota_status` may use the documented status-line JSON `rate_limits` payload through the opt-in Ottto wrapper.

## Documented Surfaces

- Claude Code project JSONL files may be read locally for aggregate usage snapshots.
- Managed telemetry environment/settings may be inspected or written only through the live telemetry setup path.
- The documented status-line `rate_limits` payload may be used for quota evidence when the Ottto wrapper is enabled.

## Undocumented Surfaces

- Do not scrape `/status`, `/usage`, browser sessions, cookies, or private credentials.
- Do not proxy Claude traffic.
- Do not infer plan, speed, or billing selectors from undocumented UI state.

## Local-Only Behavior

- Project files and local paths stay on the machine; uploads use aggregate usage, hashed workspace/session identifiers, and collector-health metadata.
- Wrapper status collection must keep status-line evidence bounded to documented JSON fields.

## Upload Boundaries

- Do not upload raw Claude Code prompts, responses, command output, tool output, or local file paths.
- Keep Claude selector context names stable, especially `speed`, `speed_mode`, `service_tier`, `batch_mode`, and residency selectors.
