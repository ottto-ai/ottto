# M3 restart restore

M3 restores a committed transcript reduction from the existing durable-tail
store, then feeds only the appended suffix to the native parser. It preserves
account attribution, complete-body money semantics and exact upload ACK rules.
Quiet files consume no transcript input. An unavailable or incompatible record
uses the existing growth recovery and Full pacing paths; unknown formats remain
protected. Parser versions and upload wire contracts are unchanged. The retained
private-label schema uses new allowlist pins; retired pre-label pins are not read.

The `restart_restore_enabled` sentinel requests the feature. The discovery
readiness gate must also be open; otherwise the store remains OFF.
OFF fully disables ordinary store reads, writes, repair and GC;
files use main's no-record acquisition path. Consent/source erasure remains
bounded, counted and fail-closed. Owned sibling recognition and counted deletion
of outgrown v1 records also remain active while OFF. A failed deletion retries at
the next publication; a downgrade during that window may re-count that file.

The adopted erasure contract is: "Nothing deleted is readable in S1's db, WAL or SHM. For .rec files, unlink plus dir-sync under the existing writer custody (my 10-30 retire_exact ruling item 4)."
S1 owns database, WAL and SHM erasure; M3 owns record unlink and directory sync.
This does not promise physical block overwrite. `rec_orphans_erased` counts only
verified private-label records erased after a save because their digest is absent
from the committed JSON index. Consent erasure and ordinary GC do not contribute.
This incremental counter does not establish the complete C′ owner sweep: an
authoritative sweep independent of label inventory and body decoding, all erasure
triggers and whole-source fallback still need integration before adapter-free ON.

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

Known limits: Linux exercises supported heap-layout paths; macOS APIs and
macOS-only fixtures still require macOS evidence. RAM-only six-hour pacing resets at process restart. With ON, exact retired-pin
records follow missing-record recovery: a quiet file reads zero bytes,
and growth takes a counted repin Full through the shared six-hour pace and
history-upgrade page (2,000 files / 1 GiB, 512 MiB per file). Replacements use
the normal write-ahead/receipt path; only an exact upload ACK settles the body.
No post-ACK GC gate or second-generation store is introduced. The per-key state
consolidation and switch decision remain separate follow-ups.

M3 off: files that older builds could warm-restore are read once in full on their
next growth (paced, cost only). Main's normal per-page Full read-mode counters
are the cost signal. M3 custody debt is not yet covered by the 6 h freshness alarm.

Cargo-invoked process default thread stack becomes 8 MiB; installed runtime
stack configuration unchanged.
