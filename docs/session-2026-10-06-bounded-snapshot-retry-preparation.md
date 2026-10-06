# Bounded snapshot retry preparation

This source preparation follows the owned-source rotation change. Production
still uses ordinary snapshot delivery. The long-lived daemon owns gated capture and delivery-only wake plumbing, but
its production constructor declines retention. No setting enables it and no
release is requested here.

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

## Gated live owner integration

The existing snapshot thread owns the retry queue across collection cycles and
waits. Native shed handling captures only after the canonical partial checkpoint
returns successfully, adopting that exact generation. Collection boundaries
exclude all parked sources. Delivery-only wakes take the same cycle mutex,
retain the original absolute ordinary deadline, and do not start a provider scan.
Manual one-shot collection keeps a closed, disposable owner.

The initial live admission is deliberately narrow: Pi with attribution disabled,
no workspace or repository identity derived from external Git metadata, and no
required head CAS. Other graphs remain ordinary collection. Legacy-settlement
migration and leased legacy reconciliation also decline
retention; their native CAS partition and exact entity ACK requirements remain
in ordinary delivery. Before the native
scan, a bounded input closure freezes the whole Pi transcript tree: at most 128
paths, 32 KiB of path bytes and 8 MiB of source file lengths. It refuses symlinks,
special objects and non-JSONL leaves. Native opened-file fingerprints and directory
mutation stamps are rechecked before capture and each network/publication guard;
retry turns inspect known paths without enumeration or provider parsing. Every
retained item must be covered by that exact pre-scan native file evidence.

The owner freshly loads device credentials for a turn and checks device/source
permission, machine/account binding, endpoint, secret-bound destination and daemon
stop state. A hash of the bounded backfill state fences cutoff changes. A fresh
activity-hint GET follows each new relay token within the same absolute network
turn and checks enabled policy, evidence window, titles, workspace/artifact privacy,
attribution-off and CAS admission. Fresh key material is zeroized and dropped in
the turn. The GET establishes current policy at that request; the server still
owns authorization for subsequent physical POSTs. No instantaneous remote policy
change fence is claimed. Local input/authority guards remain at each network phase
and publication. Exact ACK persistence precedes post-response authority checks.

Live native context is admitted within 1 MiB of the shared retained reservation.
Allocation-free JSON counting refuses escaped item bodies over 128 KiB before a
retained copy, and index/progress inputs over 128 KiB. Full wire encoding, including
native semantic envelopes, is checked before token acquisition and capped at
256 KiB during serialization. Token/policy responses are capped at 16 KiB and
batch/competing-state reads at 128 KiB before decoding. These byte caps complement
the typed requested-layout accounting; they do not equate encoded size with
allocated size.

Native synthetic cases exercise the real capture helper, frozen input guards,
wait body, gzip batch serializer, token/policy client, exact ACK/progress writer,
partial checkpoint and ordinary restart. They cover file rewrites/replacements,
new paths, cutoff, account, stop and privacy changes, unsupported dependencies,
JSON escaping and legal response allocation amplification. Account-switch reads
and credentials use isolated adapters; no live provider account is inspected.

## Activation review boundary

Production activation remains closed. Codex/Claude parent/sidecar/account and
attribution/key/scheduler graphs, and Pi external workspace identity, need their
own complete live dependency closures before admission. Source body limits and
finite native allocation measurements strengthen the send audit; they do not
prove a universal 20 MiB allocator/RSS envelope for opaque HTTP/TLS/DNS graphs,
receipts and every competing persisted shape. That activation-level audit and
explicit activation review remain required. Filesystem reads and locks retain
their native blocking semantics. There is no new timer, worker, persisted body,
scheduler setting, census/replay/backfill completion receipt or release here.
