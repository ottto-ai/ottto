# Optional Pi retry: allocation limits and readiness

Production activation remains false. The existing supported domain is a native Pi
page with no workspace enrichment, session attribution, required head CAS or
legacy settlement migration. The page retains its native body and dependency
witness; Codex joining and other providers are outside this optional live path.

The native receipt loader exposed a counterexample to the reserved 20 MiB send
allowance: a synthetic 2,700,354-byte receipt file caused 36,256,067 requested and
36,259,104 usable peak heap bytes while decoding an unknown extension. Wire bytes
alone do not bound decoded container storage.

The optional path now applies additional guards:

- Receipt input and output use the existing 128 KiB auxiliary-state limit.
  Oversized or invalid existing receipt state is preserved. Best-effort receipt
  recording may skip; remote exact ACK and native progress remain authoritative.
  Node pressure evicts oldest rows so admitted rings continue recording.
  Ordinary receipt recording retains its existing 4 MiB/500-row contract.
- Optional cutoff capture, progress, index and receipt readers preflight at most 8,192 JSON
  key/value/container nodes and 64 nesting levels before typed decoding.
  Ordinary readers and persisted schemas are unchanged. Legal response arrays
  continue using their separate decoded-body byte limit.
- After normal authenticated TLS, aggregate status/header bytes are limited to
  16 KiB before ureq retains headers. The pinned transport previously limited
  individual lines without an aggregate limit. Body decoding keeps its existing
  limits and the absolute TLS I/O deadline. Header termination matches the
  pinned parser, including malformed CR sequences.
- Total encoded status/header/body/framing bytes are capped at 272 KiB beneath
  HTTP chunk decoding and gzip. A long chunk-size line can otherwise allocate
  without producing any decoded bytes. Unusually excessive HTTP framing is
  refused by this optional turn; ordinary transport remains available.

## Native evidence

On 64-bit macOS with Rust 1.88.0, 20 selected bounded-path checks and four fast
header/framing regressions passed, followed by three isolated process allocation
audits. Each toolchain uses separate task-local Cargo outputs; actual source and
binary hashes were frozen during the owned build/test slot. The maximum fixture used the native
Pi parser, 100 model rows and escaped model labels: 317 label bytes were admitted,
318 refused, and the admitted item JSON was 130,910 bytes. This is the boundary of
one finite fixture family, not a maximum over every legal admitted shape.

The completed synthetic trusted TLS path used real localhost DNS, a 15,800-byte
token, gzip request serialization, a 129,334-byte ACK with 43,000 empty session
strings, native receipt recording, exact progress/index settlement and restart.
Its replay case used three physical batch POSTs, gzip fallback, two token
acquisitions and two policy GETs. Existing response, post-ACK cancellation,
checkpoint race, authority, legacy refusal and absolute deadline tests also pass.

| Fixture | Requested heap peak | Usable heap peak |
| --- | ---: | ---: |
| Original receipt counterexample | 36,256,067 B | 36,259,104 B |
| Refused 72,355-byte amplified receipt | 131,440 B | 131,488 B |
| Refused 2,700,355-byte receipt | 262,470 B | 262,512 B |
| Completed TLS with accepted large headers | 111,961 B | 117,680 B |
| Refused aggregate headers | 78,122 B | 79,744 B |
| Refused malformed-CR headers | 78,113 B | 79,200 B |
| Refused 1 MiB leading-zero chunk-size line | 928,705 B | 945,888 B |
| Refused decoded gzip token body | 130,294 B | 136,480 B |
| Maximum-family native ACK and restart | 4,932,723 B | 5,004,496 B |
| Same family with gzip/auth replay | 5,420,102 B | 5,486,784 B |

The all-thread audit forwards unchanged allocations to System and uses a fixed
65,536-entry pointer table. It tracks pointers allocated within the measured
scope, including child-thread allocations; freeing older pointers cannot cancel
its charge. Reallocation conservatively charges old/new overlap, including
in-place growth. Table overflow fails the audit. Fixture certificate/trust setup
is outside the scope; native parser/capture, client, production default trust
configuration, server connections, fixture responses and native restart
allocations created inside the scope are charged.

Whole-test-process maximum RSS for the maximum-family case was 44,351,488 bytes.
RSS includes the harness, static audit table, fixture setup, allocator arenas,
thread stacks and native libraries. It is neither incremental requested heap nor
a daemon physical-memory bound. The shared 8 MiB parked +4 MiB retained +20 MiB
send reservation remains requested-layout accounting.

## Lifetimes included in the transport audit

| Stage | Simultaneous or temporary owned allocations |
| --- | --- |
| Capture/checkpoint validation | Retained page/context, body proofs, capped state buffers, decoded competing progress/index, canonical comparison buffers |
| Native request preflight | Pending item clone, report lease and report clone, validation clones, semantic Values and canonical hash buffers |
| Wire/send | Raw request buffer, gzip encoder state and output, token/header copies, fresh agent/resolver/TLS connection and plaintext headers |
| Response/ACK | Decompression state, capped decoded bytes, native response containers, ACK partition maps and body witness temporaries |
| Receipt/progress | Bounded old receipt ring and new evidence, serialization/eviction buffers, full temporary item Value used by native progress recording |
| Partial publication/restart | Native progress reload, index copies and generation CAS, atomic file writes, recovered index and native no-op scan |

These are lifetime inclusions in a whole-scope peak, not independently measured
stage peaks. No client-side clone is excluded by measuring only the retained page.

## Activation blockers

The complete production fresh-context envelope is not proved. Fresh device,
pending credential, connection and file-secret loaders read unbounded local files.
The native Keychain loader copies the complete secret into Rust storage and its
eight-second timeout can leave the worker alive after the caller returns. A
post-load size check cannot establish a preallocation bound. Security framework
and resolver allocations/thread lifetimes also require an explicit production
resource domain. This change does not alter credential ownership or recovery.

A separate correction to inline scalar Vec/VecDeque accounting can change the
admission domain. Retry and rotation budget checks must run against its containing
normal merge before an activation decision relies on that new domain. Prior
scalar-collection refusal is not a bound.

Retention remains 300 seconds and the allowance remains three additional batch
POSTs. Each entered turn has one absolute network deadline of at most 60 seconds,
shared by token, policy, TLS, body, fallback and replay work. Initial credential
loading, synchronous local validation, locks, serialization and filesystem
checkpointing do not gain a preemptive wall-clock deadline. Activation requires
bounded fresh context and a supported resource envelope; finite synthetic heap
and RSS receipts alone cannot establish a universal 32 MiB physical guarantee.

The expensive process-wide audits are explicitly isolated:

```sh
cargo +1.88.0 test -p ottto-service --lib bounded_retry_envelope_native_ \
  -- --include-ignored --test-threads=1 --nocapture
cargo +1.88.0 test -p ottto-service --lib bounded_retry_envelope_probe_ \
  -- --include-ignored --test-threads=1
```

For cold-process receipts, invoke each exact unit-test name in a fresh test binary
process. The synthetic TLS fixture creates ephemeral local certificates with the
system OpenSSL executable and never accesses a provider account or user secret.
