# Codex Source Package

Codex remains an official Ottto app in product and CLI surfaces. This package describes the internal source and collector capabilities that back that app.

Collectors:

- `local_sessions`: reads local Codex session JSONL files through `ottto-locald` and uploads aggregate local usage snapshots.
- `otel_config`: describes the managed live telemetry config capability for Codex `[otel]` settings.
- `quota_status`: requires setup because the current quota path reads the local Codex OAuth credential and calls an undocumented ChatGPT usage endpoint before emitting redacted quota/status metadata.

Raw prompts, responses, tool output, local paths, tokens, and credentials must not be uploaded by these collectors. Local enriched uploads stay aggregate and metadata-only unless a later manifest version explicitly declares a different upload boundary.
