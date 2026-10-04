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

Local-import readiness requires this Mac's Codex device registration and usable
source credentials, detected Codex local files or executable, clean configuration,
and no no-touch override. Missing registration follows the existing install path.
Setup summaries carry optional `local_import_ready` and
`live_telemetry_required` flags; older summaries remain decodable. Configuration
checks report no record identifiers or receive/smoke timestamps, and cannot mint
an upload verification witness. Actual setup execution failures retain their
error codes and report local-import readiness false.

The containing release requires compatible setup admission and companion UI.
Companion checks must say **Local import configured** and **Upload not checked**;
first-data onboarding still requires accepted data. Source tests are separate from
installed acceptance: a signed containing release and ordinary client restart
are needed before claiming the managed exporter has stopped in live processes.

Independent AutoReview found and prompted fixes for legacy-fence TOML scope and
recovery from resolved source absence. Cleanup retains the table header when
settings after the fence depend on it. Current local readiness clears a prior
source-not-installed problem; unrelated auth, collector and upload failures stay
actionable. The registration-readiness fixture stages local configuration and
isolates executable detection, including hosts without the Codex CLI.
