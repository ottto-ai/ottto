# Bounded legacy relay listeners

Claude Code sessions retain the telemetry endpoint they read at startup.
The relay now keeps at most two older candidate ports available for OTLP
exports, using the primary listener's export handler, connection cap and I/O
timeouts. Legacy sockets accept only the three OTLP POST paths; control,
identity and health routes remain available through the primary listener.

A versioned owner-only atomic record remembers the newest two prior approved
ports and seeds once from retained Ottto-owned Claude settings backups. It
reads at most ten recent JSON backups through the existing owner-controlled,
size-bounded no-symlink reader and accepts only complete managed relay settings
on eligible candidate ports. No uid-derived port is used as seed authority.
Missing or unknown extra fields have defaults; older daemons ignore this separate
optional record. A single compatibility
supervisor owns both nonblocking sockets and dispatches existing connection
workers. Busy ports are skipped and retried on a 60-second tick. A port observed
as currently approved is removed immediately during reconciliation; primary
recovery also requests a synchronous socket release before binding it.
Compatibility startup or persistence failure closes only compatibility sockets.
Legacy requests recheck current approval and their live listener generation
before capture; refused requests return 403 without evidence or request activity.
Claude disable/removal hooks invalidate workers synchronously and request
persisted retirement/socket closure with a two-second acknowledgement bound.
Previously accepted connections are fenced, and already-admitted exports drain
before a successful acknowledgement. Periodic revocation remains a fallback. Idle expiry also
retires ports. Retirement persists across restarts and re-seeding; only a fresh
approval followed by supersession permits reopening. Primary listener behavior
for all sources is unchanged. No process enumeration is used for early closure.
Retirement precommits a separate private tombstone and updates the main record
before dropping sockets. Write failure still closes sockets and attempts to
unlink stale state; loading the tombstone masks replayed old allowlists.
If both state and tombstone persistence fail, supervision exits and logs the
residual risk of losing retirement across restart.

Idle listeners close after 24 hours. First-open time is durable before serving;
last-request time is flushed at most once per ten minutes and survives restart.
A crash can lose that final activity interval, shortening retention rather than
renewing it. Process-local `otlp_legacy_listener_bound`, `_busy`, `_requests`
and `_closed` counts appear in the existing relay health response.
A recent legacy request adds the canonical health warning
`claude_stale_exporter_port` for one hour, with fixed text containing no ports.
The existing health projection computes the warning in its normal pass.

Synthetic fixtures cover path restrictions and shared export responses,
backup provenance, newest-two selection, seed-once and candidate filtering,
approval history and deduplication, busy ports, primary handoff, revocation,
persisted retirement and idle clocks, tolerant optional record decoding,
activity write throttling and warning expiry. Tests are authored for CI; no local tests, daemon restart or
live-port probes were run. Only the authorized serialized service clippy check
and rustfmt are used for local validation. Consent, identity and money handling
are unchanged; dropped historical exports remain unrecoverable.
