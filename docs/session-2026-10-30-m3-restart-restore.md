# M3 restart restore

M3 restores a committed transcript reduction from the existing durable-tail
store, then feeds only the appended suffix to the native parser. It preserves
account attribution, complete-body money semantics and exact upload ACK rules.
Quiet files consume no transcript input. An unavailable or incompatible record
uses the existing growth recovery and Full pacing paths; unknown formats remain
protected. Parser versions, pins and wire contracts are unchanged by this cut.

The `restart_restore_enabled` sentinel requests the feature. The discovery
readiness gate must also be open; otherwise `restart_restore_on_refused` reports
the refusal and the native M1 route remains active. M3 is intended to land with
its discovery dependencies. This simplification does not change those gates.

Claude native completions use write-ahead preparation on the existing source
owner and active lease. Commit fences check the held object, scope, generation
and accepted evidence before the existing writer can publish a replacement.
Receipt debt keeps uncertain completions discoverable. Neither parsing nor a
local durable receipt manufactures an upload ACK. Failed/ambiguous writes retain
custody for reconciliation; unknown survivors cannot be deleted by a stale proof.

Bounded content replay uses the saved marks, certificate samples and content
hash fences. It reads at most a 1 MiB head plus a 1 MiB title line and meters
Value allocations on the active lease. Content moves only after every fence
passes. Replays cannot publish money rows. Claude's accepted floor remains held;
Codex/Pi publication follows each adapter's existing complete-body acceptance.

Diagnostics use the existing `durable_tail_alarm` carrier. `disk_bytes` is the
per-source store-bytes gauge; `store_bytes_alarm` is true above 512 MiB. There is
no r26 quota, persisted capacity debt or capacity refusal. Live counters include
restore outcomes and physical input, `resource_full` causes, write/receipt faults,
rederive input and fences, `restored_behind_accepted`, exact retirement outcomes
and the existing process proxies. See [diagnostics.md](diagnostics.md) for units
and reset semantics. Counters never contain transcript content or file paths.

Known limits: native layout proofs require macOS; Linux does not execute those
fixtures. RAM-only six-hour pacing resets at process restart. Exact retired-pin
records now follow missing-record recovery: a quiet file reads zero bytes,
and growth takes a counted repin Full through the shared six-hour pace and
history-upgrade page (2,000 files / 1 GiB, 512 MiB per file). Replacements use
the normal write-ahead/receipt path; only an exact upload ACK settles the body.
No post-ACK GC gate or second-generation store is introduced. The per-key state
consolidation and switch decision remain separate follow-ups.
