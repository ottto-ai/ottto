# Advisory replay harness

This synthetic development tool is advisory only, never a release gate. It is
absent from default and installed builds. Build it explicitly with
`--features replay-harness`; release packaging must never enable that feature.
The feature gates the command, root and status overrides, diagnostic capture,
emitted-body observer, and synthetic loopback backend. Existing unit-test
status/diagnostic overrides and benchmark backend access remain available under
`cfg(test)` only, preserving benchmark discovery without enabling a runtime feature.

It runs real snapshot pages and the entity ACK/recovery pipeline against an
in-process IPv4 loopback sink. It never starts serve, relays, MCP, provider
status workers, login recovery or launchd.

```
ottto-service replay-harness --support-dir <scratch> --roots-manifest <manifest> \
  --pass <P0|P1|P2|P3|COLD> --out <scratch/output.jsonl> \
  --blinding-key-file <private-key> --collected-at <frozen-RFC3339> \
  [--hold-back <inventory>] [--kill-after-pages N]
```

The key input is an existing owner-only regular file of exactly 32 bytes. It is
read-only and shared between the chain and COLD; the tool never generates a
substitute key. Symlinked, hard-linked, missing, public and oversized key files
are refused before output or scratch mutation. Keep the key outside the clone
and scratch directories so separate invocations can share it.

The driver must create two physically independent copies of the same frozen
corpus before running the chain and COLD. The manifest's private containing
directory is each copy's boundary. COLD starts in a separate process with a fresh
empty private scratch directory (or an empty private secrets child). It refuses
a scratch marker from any earlier pass. No index, durable store, process RAM or
provider collection is shared. File hard links, symlinks and roots outside the
clone are refused. Independence and identical frozen input bytes are driver
preconditions; the command cannot attest the copying history of an input tree.

Set `OTTTO_LOCAL_PLATFORM_SUPPORT_DIR` to exactly scratch and
`OTTTO_SERVICE_SECRET_FALLBACK_DIR` to scratch or a private child. Leave
`OTTTO_API_BASE_URL` unset: the command binds an ephemeral loopback listener and
installs that address. Any inherited API value must match its own listener
exactly. Real support/provider directories and saved connections are refused.
Scratch HOME/provider homes and file secrets prevent access to live provider
slots or Keychain; proxy variables are removed. The real state-directory lock
is held for process lifetime. Never edit the private clone during a pass.

The roots manifest is `{"claude": [paths], "codex": [paths], "pi": [paths]}`,
with absolute paths or paths relative to its containing directory. The optional
hold-back inventory is `{"files": [clone-relative paths]}`; the driver owns
truncation and appending. `--kill-after-pages` accepts a positive page count only
for P3 and kills after a successfully completed real source page, with records
already synced. A count beyond the final page does not cause a kill.

All passes emit the same session record, including `token_totals`,
`entity_count`, `emitted_body_digest`, and `money_oracle`. The last session record
for each blinded session is the latest emitted body; quiet pages emit no fake
zero or empty replacement. Consumers fold records in emission order, including
completed records before a P3 kill. Counts and unavailable values in page
diagnostics retain their existing meanings.

Pass totals are sampled acquisition selections and completed native plus guard
bytes, excluding discovery, joins, sidecars and failed acquisitions. They are
not total filesystem I/O. Unavailable values remain null. `local_resources`
carries the existing schema unchanged. Exit codes are 0 completed, 2 isolation
refused, 3 failed; deliberate termination is SIGKILL.

`money_oracle_encoding` is `keyed-field-digests-v1`. `money_oracle` contains
exactly these 15 named fields, each a domain-separated HMAC-SHA256 of the
canonical `[present, value]` pair from the actual emitted entity:

- `input_tokens`, `output_tokens`, `cache_read_tokens`
- `cache_creation_5m_tokens`, `cache_creation_1h_tokens`
- `reasoning_output_tokens`, `unattributed_total_tokens`, `request_count`
- `cost`, `usage_buckets`, `model_usage`
- `removed_usage`, `removed_request_count`
- `usage_accounting_contract`, `telemetry_owned_complete`

The domain is `replay-money-field-v1\0<field>\0`. This compares every field
independently, including absence versus null, without exporting labels,
selectors, identifiers or arbitrary object keys. The seven numeric token totals
remain available for aggregate comparisons. Field commitments detect monetary
inequality; a commitment alone does not reveal the direction of a cost change.

The body digest uses the exact emitted item, checked against the typed request.
The driver supplies the same frozen RFC3339 `--collected-at` input to the real
scan on every chain/COLD invocation. Collection timestamp bytes remain in the
digest. Only the existing money-equivalence sentinel is normalized:
`source_file_fingerprint = "physical-identity:excluded"`, with revision hashes
recomputed by the production semantic-envelope function. Normalization fails
closed if any other envelope field changes. No money field is normalized. The
session and body domains remain `replay-session-v1\0` and
`replay-emitted-body-v1\0`. All commitments use the same supplied key.

The feature-enabled synthetic integration target declares `required-features`.
The separate, path-filtered `Replay harness (feature)` Linux job runs it and the
oracle unit tests explicitly, in parallel with default tests. This advisory job
is non-required and pending the CI-speed owner's OK. It uses the existing Linux
cache scheme and enables the feature only for these targets. Both commands run
even if one fails, and either failure fails the step:

```
cargo test -p ottto-service --test replay_harness --features replay-harness --locked -- --nocapture
cargo test -p ottto-service --lib --features replay-harness --locked snapshot_sync::replay_harness::oracle_tests -- --nocapture
```

Default CI runs `replay_harness_disabled`, which checks the command is absent.
The ignored reference benchmark retains its implementation, assertions and
default unit-test discovery; its backend compiles under `cfg(test)`. Existing
reference benchmark workflows need no feature change.

P1 asserts zero Full/Tail/native+guard bytes, a positive `index_reuse_skips`
count from the actual candidate-skip branch, and zero `durable_store_io`.
The latter reuses the existing store's restore attempts, record/GC read counts,
and body/header/verification/GC byte counts. Missing telemetry stays null.

P2 asserts at most one Full plus a positive Tail count. Every Full must have an
actual diagnostic cause in the test's pinned transitional set with its named
retiring slice; missing, unknown or unaccounted causes fail. Restore misses are
never translated into allowed causes. Every P2 prints the exact `full_causes`,
`restore_outcome` and aggregate page record. A panicking synthetic fixture retains
its directory and prints aggregate JSONL to the test log.
