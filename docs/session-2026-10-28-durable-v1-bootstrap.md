# Durable v1 bootstrap and missing-state admission

The first format-v2 preparation slice keeps writing format v1. Restore and GC
bind each known record using its stored format and source allowlist, preserving
the original scope formula. Decoded Codex counting state must agree with the
configured cutover; its interpretation/evidence remain the reduction's decision.
V1 audit-debt bytes are checked and dropped on decode. Ordinary replacement
failure or budget refusal retains the valid v1 authority.

Indexed cold misses hold while idle. Changed content uses an existing saved,
once-per-file/per-release reread reservation before acquisition. A counter and
alarm expose `upgrade_state_missing`. Group preflight waits for every sibling's
saved reservation before consuming any, so requeues cannot strand a member.
Completed joined Codex members intentionally have no per-file reduction and
use their existing group admission, while durable-record holds still apply.
The existing replay ledger keeps one hash per indexed file and release, avoiding
a fixed file grant cap. Release history survives rollback/re-upgrade, preserving
the once-per-release limit.

The next slice enables v2 layout, metadata and recovery-marker preservation.
No feature flags or new source tags are introduced here.
