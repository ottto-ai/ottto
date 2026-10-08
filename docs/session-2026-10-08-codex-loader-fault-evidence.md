# Attribute local Codex loader faults without retaining error text

A failed owning-state SQLite census deliberately keeps Codex ownership incomplete. The local diagnostic previously retained only an aggregate `sqlite_open_or_query` reason and root counts. If a concurrent database fault naturally clears, that receipt cannot identify which root failed, which operation failed, or SQLite's native error code. A later successful schema probe cannot reconstruct the earlier failure.

Retain the first failed root's domain-separated digest, a fixed operation stage (`open`, `prepare`, `query`, or `row`), and the native SQLite extended error code alongside the existing counts and reason. All three facts refer to the same first failure. Later roots continue contributing counts without replacing that witness. Successful subsequent loader invocations start with empty fault fields.

Operation stages are typed error contexts, not classifications inferred from arbitrary error text. The schema contains no raw root path, provider row, SQL error message, credential, or new variable-length collection. The existing 32 KiB local diagnostic bound and exhaustive heap inventory cover the added fixed fields. The evidence remains local and is excluded from status/upload DTOs.

Read-only SQLite flags, query semantics, secure acquisition, required shape and identity guards, census refusal, retry/backoff, persisted scan/checkpoint formats, ACK settlement and historical/no-op behavior stay unchanged. This repairs missing fault attribution; it does not repair or bypass an unknown database failure or establish upload recovery.

Validation uses synthetic databases. The released code fails a native regression because the SQLite code is absent; the candidate records code 26 and the prepare stage for all three owning-state loaders, associates the failing root among a healthy root, remains fail closed, and clears fault evidence after natural fixture recovery. Schema tests preserve the first witness across different later native errors and forbid private error text or root strings in serialized evidence; the fully populated schema stays under the existing byte ceiling.

Installed acceptance still requires an ordinary containing-release observation: either attributable root/stage/code evidence for the actual fault, or a naturally healthy complete census followed by positive exact entity ACK and durable checkpoint/history proof. Successful source tests alone establish neither outcome.
