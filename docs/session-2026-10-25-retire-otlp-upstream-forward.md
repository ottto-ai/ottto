# Retire the local relay's upstream OTLP forward (2026-10-25)

## Why

Ottto's server permanently retired OTLP ingest: every authenticated
`/v1/logs|metrics|traces` request is answered with a non-error "disabled" body
and nothing is read or stored. The local relay still forwarded every raw
Claude Code (and legacy Codex) export upstream, synchronously, after first
obtaining a relay token. That cost a relay-token exchange, up to 3 s connect
plus 10 s read/write per request on a daemon worker thread, and outbound raw
telemetry with no consumer.

## What changed

- `otlp_relay::handle_client` no longer forwards. `local_otlp_export_response`
  runs the unchanged Claude local reducers and answers the exporter itself.
  Removed: `forward_otlp_request`, `send_otlp_request`, the relay-token cache,
  the relay's own token request, the pooled upstream agent and its timeouts.
- Responses:
  - accepted (Claude evidence stored, or a signal/source with no local
    consumer): `200` with an empty OTLP export response in the request's
    encoding (`{}` JSON, or an empty `application/x-protobuf` body);
  - Claude body the reducer cannot decode, or an unsupported content
    encoding: `400` (non-retryable). Gzip bodies are inflated locally under
    the same 25 MiB cap; before, a gzip body failed local reduction silently;
  - decoded Claude evidence that could not be stored (I/O, evidence cap):
    `500` (non-retryable). Before, both failures were hidden behind the
    server's `200`.
- `claude_local_otel` marks decode failures (`is_undecodable_body`) so the
  relay can tell them apart from storage failures; the relay maps both into a
  typed `LocalCaptureFailure`. Evidence format, location,
  caps and readers are unchanged.
- `net_resilience`: the OTLP agent rebuild flag is gone with the agent. The
  sync-stall watchdog keeps its remaining truthful evidence: agent-status
  upload success and the fresh out-of-process TCP probe.
- Credential-promotion fence tests now call
  `snapshot_client::ensure_no_incomplete_device_credential_promotion` directly;
  the fence still guards every remaining credential use. Local capture was
  never behind that fence and still is not.

## Kept on purpose

- Claude Code exporter configuration, the relay listener, `/healthz`,
  `/control`, `/whoami`, `/local-health`.
- Relay-token issuance for snapshot uploads and other upload paths.
- Setup verification markers in `control.rs` (synthetic markers, not raw
  agent forwarding). They still post to the retired route and report success
  on its disabled answer; that is a separate follow-up.

## Validation

Focused synthetic tests in `otlp_relay.rs`: relayed Claude log and trace
evidence equals direct capture; gzip exports are inflated and captured; exports without a local consumer store nothing
and get an empty success; malformed bodies get `400`; storage failure gets
`500`. Package Clippy compiled the changed files cleanly; tests run in CI.
