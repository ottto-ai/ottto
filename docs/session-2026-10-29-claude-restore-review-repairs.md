# Claude restore review repairs and O3 integration

Merged the reviewed O3 migration implementation into the folded restore branch.
The core binding/carrier/T14 behavior, source table, strict receipts and shared
wall-clock Full pacing remain. The retired generic reread budget stays absent.
O3 alone uses the existing index compatibility slot and hashed
upgrade_state_missing:<release> negative keys. Its reservation becomes usable
only after saving that negative evidence on the committed index; working bodies,
ACKs, census and traversal are not published at that boundary. Restart and index
copies retain negative evidence and cannot copy a positive grant. Map capacity
falls back to the existing paced no-match Full without mutation permission.

Unregistered replay is classified before an early Claude scope rejection. The
outcome retains both its typed obligation and Stale policy. The existing resource
carrier reports stale_attribution separately; it is not a Miss or a replay grant.

Stale/no-match cannot hide an independent real edit. The existing bounded
certificate checks can prove replacement, shrink or changed sample bytes first.
Mtime alone cannot grant this bypass. Accepted-prefix and future-revision floors
remain, and acquisition does not authorize rewriting the old record. New native
fixtures compare the updated body to cold acquisition, check no manufactured ACK,
perform an explicit exact-body ACK, retain an unproved predecessor through save,
and check a quiet restart past the activity window.

Clock anomalies expire Full pace toward reading and have a pace_anomaly alarm
separate from pace_evicted. The spent Tail grant is never refunded.

Generic growth discovery is a separate integration dependency. The overlapping
Claude-only age exception from the migration branch was excluded; the generic
rule must come from its owning main change. Its paced, marker-free downtime and
restart fixture is explicitly ignored until that dependency lands. No claim of
complete no-drop or native qualification follows from compilation. Local checks
use the authorized pinned clippy wrapper only; no tests run locally.
