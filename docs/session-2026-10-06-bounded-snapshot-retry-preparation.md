# Bounded snapshot retry preparation

This source preparation follows the owned-source rotation change. Production
still uses ordinary snapshot delivery. No production caller captures or sends
retained pages, no setting enables them, and no release is requested here.

The compiled preparation combines a retained native page with the existing
entity ACK, durable progress, partial-index checkpoint and index CAS. A bounded
transport variant shares one absolute network turn across fresh relay tokens,
gzip refusal fallback and one authentication replay. An optional-only TLS I/O
wrapper enforces that exact deadline inside pinned ureq's handshake, using the
same ring, TLS 1.2/1.3 and WebPKI trust policy; no new network worker is added.
The already locked WebPKI roots crate becomes a direct dependency without a
package-version change. It limits successful token
and batch response bodies before JSON decoding. The ordinary transport and
checkpoint callers retain their existing behavior.

Optional production retries require an HTTPS destination before token or batch
I/O. Pinned ureq's plaintext request writes do not pass through the absolute
TLS wrapper, so HTTP destinations decline retention delivery and recover through
the ordinary path. Synthetic loopback HTTP cases use an explicit test-only
opt-in restricted to a literal loopback socket address; it is absent from
production builds. Default-client regression checks prove zero token/batch
connections and unchanged POST allowance for a plaintext destination.

The body allowance is three additional physical batch POSTs across all turns;
fallbacks and replay consume it before sending. Retention lasts 300 seconds from
first shed, each network turn ends within the remaining lifetime or 60 seconds,
and another shed preserves the original expiry and remaining POST allowance.
Server backoff remains in the existing source deadline/streak state when a
retained body is discarded. Fresh tokens and client-report leases exist only
inside a turn. No raw transcript or persisted retry payload is introduced.

`source_rotation::Owner::boundary` offers at most one optional turn after all due
siblings have received a collection turn. Its busy-source iterator includes
every parked parser; the native retry owner refuses same-source publication at
that boundary. The fixed three-source queue shares a 4 MiB requested-layout
allowance for copied items, proof, complete native index/progress context and
queue storage. This sits beside the existing 8 MiB parked reservation and a
20 MiB send/checkpoint reservation inside the 32 MiB overlap budget. Admission
uses the existing pinned layout walker; unsupported layouts and opaque cache
state decline retention. These reservations are not a universal physical-memory
bound, nor a hard deadline on filesystem/lock operations.

Generated native tests run the real loopback token/batch client through the
native ACK/checkpoint path and ordinary restart preparation. They cover gzip
fallback plus authentication replay, a second shed, stale authority/body/device
and competing or oversized durable state before any token, response overflow,
cancellation after a durable ACK, stalled tokens, trickling ACK bodies and
incomplete trickling TLS handshake records on token and batch connections.
An owned-parser driver exercises the actual collection boundary, complete scan
and index parity, same-source blocking, sibling fairness and recovery. Network
clock deadlines use real monotonic time; simulated parser time remains a
separate deterministic adapter. Positive retained-layout tests require the
pinned Rust 1.88/macOS layout and decline on unsupported toolchains.

## Activation review boundary

This is preparation for review, not completed production Retry-After delivery.
Activation must wire initial shed capture, retained state and delivery-only
wakeups into the existing long-lived owner. Wakeups must preserve the ordinary
absolute cycle deadline and must not launch a scan per retry. The live authority
hook must revalidate complete file, parent, sidecar and provider/account
relationships, current device/destination and stop state, current activity-hint
policy and attribution-key epoch before every network phase and publication.
Current tests supply controlled authority and current native bodies; they do
not establish that live dependency/policy closure. The 20 MiB send/checkpoint
reservation also needs an activation-level allocation audit including transport,
receipts and bounded competing-state reads. Production wiring and that review
must be one explicit change; editing a marker cannot activate this preparation.
