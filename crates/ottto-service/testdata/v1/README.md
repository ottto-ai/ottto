# Historical v1 records

The historical production writer generated these four synthetic v1 records
using Rust 1.95.0 on Linux x86-64. The generator checked all 16 persisted facts
against the historical reader. Both Codex records carry selector context
`model_provider=openai` with source `derived_from_codex_source`.

Do not regenerate these bytes with the current writer or update their headers,
certificates or trailers to make a restore pass.

| Case | Historical input/decision |
| --- | --- |
| claude-three-request | Three requests, populated start window, API evidence and accepted body witness |
| claude-selector-unequal | Same input plus explicit context `priority` and source `derived_from_logs_2` |
| codex-legacy-acked | Dated Codex session, real prior Legacy ACK, populated usage/counting state |
| codex-v2-24b | V2 counting, dated header with CLI version `0.148.9`, accepted body witness |

The manifest pins lengths and SHA-256 for records and synthetic sidecars.
Expected JSON distinguishes decoded facts from generation-time API evidence,
index/ACK bindings and live TierReplay settlement; those external facts are
not all serialized into the reduction. The selector case also names exact
record-relative field/map spans. There is no shipped Pi v1 durable record.

These are **record/field format** fixtures. Their device, inode, timestamps,
path-dependent bindings and filesystem certificates belong to the generation
run. Copying them next to a fresh transcript does not prove a native restore.
The current reader's representation dispatch and field codec are the format
authority; native money/restart/receipt tests keep their existing live fixtures
and money oracle. A reader that retires these pins must assert its actual
Repin/rebuild outcome rather than relabeling the records or resurrecting an old
decoder.
