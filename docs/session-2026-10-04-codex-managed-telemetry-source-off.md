# Codex managed telemetry source-off

Ottto no longer enables its Codex logs, metrics or traces exporters. Codex usage
continues through local session files; quotas, plans and source check-ins remain
independent. Claude Code local evidence and relay forwarding are unchanged.

The service reconciles older managed Codex exporters at ordinary startup,
installation and explicit repair. Ownership requires both an Ottto source header
and a loopback signal endpoint; external destinations and unrelated settings are
preserved. Invalid TOML or ambiguous fences refuse cleanup. Configuration backups
remain available. `OTTTO_PATCH_CODEX_DISABLED` retains its no-touch meaning,
including startup cleanup; it does not stop exporters already loaded by a client.

Restart existing Codex processes after cleanup. Ottto does not forcibly stop
clients. Configuration cleanup is not evidence that an already-running process
has stopped exporting.

Manual and setup Codex verification no longer run a provider smoke or wait for
raw OTLP. The existing protocol reports local-import readiness with a warning,
`verified: false`, and zero observed records. It creates no end-to-end verification
success witness. Readiness avoids an endless telemetry repair/verify loop while
actual configuration, account and collection failures remain visible.

No implemented local Codex OTLP consumer is removed. This does not claim all
provider calls have rollout records: background calls without local session
representation remain outside currently supported usage capture.
