# Relay authorization backoff and isolated unit-test networking

Relay-token authorization rejections now share an in-memory gate across snapshot,
bounded retry and credential-recovery requests. The binding includes the device,
credential generation, a digest of its secret, API destination, source and setup-run
binding. New credentials or a reattach admit an immediate attempt. HTTP 401/403
starts an equal-jitter exponential wait: initially 2.5–5 minutes, eventually
3–6 hours. One probe runs per rejected binding at a time. Successful exchanges
clear rejection state; no tokens are cached beyond their existing lifetime.

The local-health path keeps its existing terminal setup-run refresh hold. Each
rejected probe grants one setup refresh opportunity, including when another
caller observed the rejection first. A successful refresh admits one retry
without resetting the device rejection streak or granting another refresh,
including when that refresh replaces the setup-run id.
Each source shares its gate across callers; a source-specific 401 never pauses
another source.
Concurrent initial rejections count as one wave. Local scans, quota/account
checks and their scheduling keep running. The existing reconnect-required health classification remains typed.

Unit-test builds reject every non-loopback HTTP destination before DNS or TLS.
This includes default production URLs used by background threads after a test
fixture ends. Test agents also disable redirects, because the HTTP library only
runs middleware on the initial request. Production routing and redirect policy
are unchanged. Tests must provide loopback backend fixtures.

Regression coverage exercises shared suppression across callers for one source,
isolation between sources,
probe admission, changed credential keys, success reset, transient 429/503
classification, setup refresh and test-only egress rejection. Broad workspace
checks remain CI's responsibility.

Round 2 corrects refresh handover ownership: a new setup-run key starts with no
in-flight probe marker, while an existing destination key keeps its own marker.
An authorized connect, doctor or non-dry-run repair clears auth retry state,
including the terminal setup-refresh hold, even for unchanged credentials.
Doctor sends the additive optional status flag `retry_relay_authorization: true`;
ordinary status omits its default false value and never resets backoff. Existing
clients and polling retain their request shape and behavior.

The loopback gate fixture retains response sockets until teardown and switches
accepted sockets to blocking mode. This avoids response-close/read-timeout races
on macOS without retries or relaxed assertions in the regressions.

Round 3 incorporates the upstream retirement of raw OTLP forwarding and the
install-time synthetic OTLP POST. Local OTel capture and its exporter responses
stay on the local-only implementation. No relay-token acquisition, cached-token
grant check or forwarding admission gate remains in the OTLP listener.

Backoff still covers snapshot uploads and status/check-in reporting, agent status
and local-health uploads, bounded snapshot retries, context footprint/composition
and health uploads, MCP activity hints, Codex prelude footprint, cloud-session
polling, provider daily reference, and the pruned-credential authority probe.
These callers share the snapshot token exchange or the same authorization gate;
local-health setup-run refresh remains limited to one opportunity per probe.
The pruned probe preserves the distinction between a cached rejection and fresh
evidence that an expired candidate is inactive.

Shared suppression and setup-refresh regressions now exercise snapshot callers.
Tests confined to the removed OTLP token cache, token acquisition and forwarding
grant checks are retired with that code. Credential-promotion fence tests call
the surviving snapshot credential fence directly. Source isolation, recovery
handover, explicit reset and the unit-test egress guard remain covered.
