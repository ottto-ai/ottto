# Claude Code Source Package

Claude Code remains an official Ottto app in product and CLI surfaces. This package describes the internal source and collector capabilities that back local enriched usage, live telemetry setup, and documented status-line quota evidence.

Collectors:

- `local_sessions`: reads local Claude Code project JSONL files through `ottto-locald` and uploads aggregate local usage snapshots.
- `otel_config`: describes the managed live telemetry environment/settings capability.
- `quota_status`: describes the documented status-line `rate_limits` evidence captured by Ottto's local wrapper.

Raw prompts, responses, tool output, command output, local paths, cookies, and provider credentials must not be uploaded by these collectors.
