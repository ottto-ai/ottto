# Bounded legacy relay listeners

Claude Code sessions retain the telemetry endpoint they read at startup.
The relay now keeps at most two older candidate ports available for OTLP
exports, using the primary listener's export handler, connection cap and I/O
timeouts. Legacy sockets accept only the three OTLP POST paths; control,
identity and health routes remain available through the primary listener.

A versioned owner-only atomic record remembers the newest two prior approved
ports and seeds the first per-user fallback once. A single compatibility
supervisor owns both nonblocking sockets and dispatches existing connection
workers. Busy ports are skipped and retried on a 60-second tick. A port observed
as currently approved is removed immediately during reconciliation; primary
recovery also requests a synchronous socket release before binding it.
Compatibility startup or persistence failure closes only compatibility sockets.

Idle listeners close after 24 hours. First-open time is durable before serving;
last-request time is flushed at most once per ten minutes and survives restart.
A crash can lose that final activity interval, shortening retention rather than
renewing it. Process-local counts appear in the existing relay health response.
A recent legacy request adds the canonical health warning
`claude_stale_exporter_port` for one hour, with fixed text containing no ports.
The existing health projection computes the warning in its normal pass.

Synthetic fixtures cover path restrictions and shared export responses,
seed-once and candidate filtering, approval history and deduplication, busy
ports, primary handoff, persisted idle clocks, activity write throttling and
warning expiry. Tests are authored for CI; no local tests, daemon restart or
live-port probes were run. Only the authorized serialized service clippy check
and rustfmt are used for local validation. Consent, identity and money handling
are unchanged; dropped historical exports remain unrecoverable.
