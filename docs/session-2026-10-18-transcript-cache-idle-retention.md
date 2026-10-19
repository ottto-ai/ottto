# Transcript reduction cache keeps idle entries

The sampled transcript reduction cache dropped every entry admitted more than
one audit interval (1 h) earlier, each time a new entry was admitted. After a
2 h or 5 h idle gap, a changed or re-selected transcript therefore found no
retained reduction and was read in full with `StateMissing`, even when the
cache had room.

Idle age no longer removes entries. An entry now leaves the cache only when it
is taken for a scan, evicted by the existing count/byte caps, cleared by the
existing copy-refusal path, or lost on restart.

Unchanged:

- Caps: 256 entries, 8 MiB per entry, and the shared byte limit (64 MiB minus
  the 32 MiB overlap budget and the 1 MiB audit/scratch reserve, 31 MiB for the
  production cache). All layout, frozen-charge, live-reservation and overlap
  checks run as before.
- Victim order: oldest clipped source modification time, then oldest
  admission. Future modification times are still clipped to admission time.
- Audit: the audit deadline comes from the checkpoint's last full verification
  and from the file index's durable audit debt, not from cache age. A retained
  checkpoint older than the audit interval still yields `AuditDue` for a
  changed file. Cache presence grants no body or ownership authority; every
  reuse is revalidated by the read plan (stamp, scope, samples, debt).

Trade-offs:

- Actual resident memory can stay near the cap for longer. Before, an idle
  cache shrank at the next admission after 1 h; now it keeps its entries until
  pressure or a scan takes them. The configured cap is the same, so this is a
  duration change, not a higher bound. Each entry is 8 bytes smaller.
- Under pressure, work whose source modification time is older than every
  resident entry is refused admission instead of displacing newer idle state.
  The timer used to let such backdated work regain space after 1 h. Refusal
  only means a later full read; it never suppresses one.

Scope: this does not change audit policy and does not by itself remove
`AuditDue` full reads. An appended file whose last full verification is older
than the audit interval is still read in full.

Validation: the existing cache test now covers 2 h and 5 h idle admissions
(state kept and reusable), refusal of backdated work at the count cap, and
eviction of the oldest resident by newer work. Tests run in CI only. Layout-gated
tests return early on compilers without validated layouts; only a run on a
supported compiler counts as coverage.
