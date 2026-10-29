# Isolated replay harness

`ottto-service replay-harness` is a hidden, advisory debugging command. It is
never a release gate. It runs production snapshot pages and their real entity
ACK/recovery pipeline against an in-process IPv4 loopback sink. It does not start
the service, provider status workers, relays, MCP, login recovery or launchd.

```text
ottto-service replay-harness --support-dir <scratch> --roots-manifest <json> \
  --pass <P0|P1|P2|P3> --out <scratch/output.jsonl> \
  [--hold-back <json>] [--kill-after-pages N]
```

The driver must prepare separate user-owned 0700 clone and scratch directories.
The roots manifest's containing directory defines the clone boundary. Its shape
is `{"claude": [paths], "codex": [paths], "pi": [paths]}`; paths can be absolute
or relative to that boundary. Every effective transcript root comes exclusively
from this in-memory registry. Default provider roots and registered real slots
are excluded. Symlinks, hard links, special files and paths outside the clone
are refused. The driver must not modify the private clone during a pass.

Set `OTTTO_LOCAL_PLATFORM_SUPPORT_DIR` to exactly the scratch directory and
`OTTTO_SERVICE_SECRET_FALLBACK_DIR` to scratch or a private child directory.
Leave `OTTTO_API_BASE_URL` unset: the command binds its own ephemeral loopback
listener and installs that exact address. An inherited API value must match
that listener exactly; unrelated loopback addresses also fail. Saved connection
bindings are refused. The scratch directory must initially be empty (or contain
only the empty secret directory); subsequent passes require the harness marker.
Real support/provider directories are refused. A scratch HOME and provider-home
variables are installed before daemon construction; proxy variables are removed.
File secrets are mandatory, so the harness cannot fall back to Keychain.

The command acquires the real state-directory lock and holds it until process
exit. P0, P1 and P2 label cold, quiet restart and growth respectively; they do not
change scanner policy or suppress unexpected reads. The driver owns truncation
and appending. `--hold-back` accepts `{"files": [clone-relative paths]}` and
validates the inventory, reporting only its count. `--kill-after-pages N` is
valid only for P3 with positive N and sends SIGKILL after the Nth successfully
finished source page. The page marker and emitted aggregates are synced first.
If N is greater than the completed pass's pages, the pass finishes normally;
a driver expecting a crash must reject that run.

JSONL contains `pass_started`, `local_resources`, `session`, `page_finished` and
one final `pass_totals` record. Interrupted passes have no totals. Session rows
record each actual emitted entity, including retries; they are cumulative
session revisions, so a consumer carries the latest revision across quiet
passes rather than summing tokens. Rows include source, seven numeric token
totals, entity count, a blinded session ID and a blinded canonical emitted-body
digest. Only the top-level collection timestamp is excluded from that digest.
No raw paths, identities or content are written. The random 0600 blinding key in
scratch is stable across restarts, and emission records are synced before ACK.
The caller must preserve the interrupted pass's output when restarting.

Pass totals reuse existing diagnostics: full/tail counts are sampled acquisition
selections and bytes are completed native plus guard bytes. These exclude
failed acquisitions, discovery, joins and sidecars; they are not total file I/O.
Unavailable acquisition counters are null, never invented zeroes. Restore counts
are successful durable restore outcomes. `local_resources` records carry the
existing schema unchanged for an external extractor.

Exit codes are 0 (completed), 2 (isolation refused), and 3 (failed). Deliberate
P3 termination is SIGKILL. Synthetic integration tests run in CI only. Equality
with the independent `snapshot-audit` oracle requires a shared key, identity,
policy and digest contract; this command alone does not establish that oracle.
