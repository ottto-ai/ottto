# TLS root and WebPKI advisory repair

`cargo audit --deny warnings` reported RUSTSEC-2026-0382 for rustls-webpki
0.103.15 and RUSTSEC-2026-0381 for webpki-roots 0.26.11 and 1.0.7. Both concern
distrusted emSign intermediates. The patched releases are rustls-webpki 0.103.16
and webpki-roots 1.0.10. No webpki-roots 0.26 release is patched, and every ureq
2.x release pulls webpki-roots 0.26 through its default `tls` feature.

ureq now keeps only its `gzip` and `json` features. The service depends on
rustls directly, with the same `ring`, `logging`, `std` and `tls12` features
ureq enabled and no default features, so aws-lc stays out. webpki-roots is a
direct 1.0.10 dependency. The lockfile drops the 0.26.11 shim and moves to
webpki-roots 1.0.10 and rustls-webpki 0.103.16. No other package changes.

`retry_tls` owns the one rustls connector. It is a port of ureq 2.12.1's built-in
connector, with attribution in the file and in NOTICE. It keeps the ring
provider, TLS 1.2 and 1.3, WebPKI chain and name verification against the
patched root set, SNI, bracketed-IPv6 handling, no client auth and no ALPN. It
uses one process-wide config, as ureq's lazy default did, and the stream still
forwards the TCP socket that ureq's timeouts use. Every production agent comes
from `retry_tls::agent()` or `retry_tls::agent_builder()`. The bounded snapshot
agent keeps its deadline connector, which now uses the same connect step.
Timeouts, retries, redirects and pooling are unchanged.

ureq builds errors from outside the crate only through `io::Error`, so connector
failures carry a typed `TlsSetupError` inside an `io::Error` that keeps the
underlying kind. Provider-call results recover ureq's former DNS, connect and
I/O categories from that type, and timeout detection still sees the original
I/O kind. One delta is visible: transport messages for TLS setup failures now
start with `Network Error:` instead of `Connection Failed:` or `Dns Failed:`.
The step message and its cause are unchanged.

With ureq's `tls` feature off, `AgentBuilder::new()` first installs ureq's
no-TLS placeholder, then `tls_connector` replaces it. Each agent construction
therefore makes one extra transient 16-byte allocation. Agents built per call
(the former shortcuts and the per-request deadline agents) pay it once per
request. Pooled agents pay it once. The connect path allocates as before.

CI covers the change with synthetic loopback certificates only:
- the default agent and the deadline connector, each with its production trust
  config, refuse an unknown issuer through the shared connect step;
- a trusted host succeeds by name, by IPv4 address and by bracketed IPv6
  literal;
- wrong-host and untrusted certificates are refused;
- the deadline agent succeeds, and bounds a stalled handshake as a timeout;
- the category mapping holds for every connector step.

A source inventory test pins every guarded line by file, exact text, scope and
count:
- each `ureq` shortcut and constructor, including the connector argument of
  each connected builder chain;
- `ureq` imports and re-exports at any visibility;
- rustls policy overrides: custom verifiers, native or platform roots, ALPN,
  SNI, resumption, early data, client certificates, key logs and root-store
  sources.

Any new occurrence fails it. A lockfile test pins the resolved TLS graph of
both workspaces; CI's `--locked` builds and the advisory audit check the
lockfiles themselves. The native TLS retry allocation audits remain
`#[ignore]`, as before this change, so CI compiles them but does not run them.
