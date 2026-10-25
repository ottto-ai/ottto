# Relay authorization backoff and isolated unit-test networking

Relay-token authorization rejections now share an in-memory gate across snapshot,
bounded retry, OTLP relay and control requests. The binding includes the device,
credential generation, a digest of its secret, API destination and setup-run
binding. New credentials or a reattach admit an immediate attempt. HTTP 401/403
starts an equal-jitter exponential wait: initially 2.5–5 minutes, eventually
3–6 hours. One probe runs per rejected binding at a time. Successful exchanges
clear rejection state; no tokens are cached beyond their existing lifetime.

The local-health path keeps its existing terminal setup-run refresh hold. A
suppressed relay request does not refresh setup credentials. A real rejected
probe may refresh once and, on success, retry once without resetting the device
rejection streak. Local scans, quota/account checks and their scheduling keep
running. The existing reconnect-required health classification remains typed.

Unit-test builds reject every non-loopback HTTP destination before DNS or TLS.
This includes default production URLs used by background threads after a test
fixture ends. Test agents also disable redirects, because the HTTP library only
runs middleware on the initial request. Production routing and redirect policy
are unchanged. Tests must provide loopback backend fixtures.

Regression coverage exercises shared suppression across callers and sources,
probe admission, changed credential keys, success reset, transient 429/503
classification, setup refresh and test-only egress rejection. Broad workspace
checks remain CI's responsibility.
