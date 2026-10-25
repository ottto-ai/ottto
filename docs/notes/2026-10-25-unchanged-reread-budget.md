# Unchanged transcript reread admission

Claude and Codex read selection now applies one shared per-file admission
budget after Parse selection, including forced families, comparison targets and
Codex joined members. Same size, nanosecond mtime and opened device/inode mean
unchanged bytes, independent of parser versions, privacy policy and sidecars.
Legacy entries without an object witness are budgeted conservatively.

An unchanged file receives at most two attempts per rolling seven days. New
files and changed transcript bytes remain outside this budget. Full reads caused
by growth are counted and alarmed at the 25th read in a 24-hour observation
window, without refusing new bytes. A selected attempt is charged before
acquisition; failure or a later reusable cache hit can conservatively spend it.

The traversal tripwire refuses unchanged work after more than
`max(indexed_files / 20, 300)` admissions. Its plan check runs before traversal
start clears and again after rearming; an oversized plan keeps fingerprints
and debt instead of starting a whole-history read. A large plan remains
withheld until an explicit approved replay grant changes that decision.

A refusal keeps the current file entry, empty fingerprint debt, bindings and
ACKs. The census remains incomplete with `withheld: reread budget`, and its
existing local census line includes `unchanged_reread_refused{cause}` counters.
`REREAD_BUDGET_EXHAUSTED` and `REREAD_TRIPWIRE` are local coded alarms.

The sparse persisted budget uses a 16-byte key digest and two 32-bit hour
stamps, pruned on load. The wall high-water never moves backward. Transient
single-use tickets expire after twelve wall-clock hours or suspend-inclusive
monotonic hours; restart cannot reuse a ticket. An additional hour in the
retention window covers hour rounding. Ordinary page reservations are saved
together through the committed index before reads resume. The save publishes
negative scheduling evidence, never uncommitted scan output or authority.
A production reader without that committed-index save handoff refuses unchanged
rereads; volatile in-memory tickets are test-only.

Replay still removes its ordinary delivery entries. A separate hash-keyed
negative physical witness keeps those old files subject to selection admission;
recording a replacement retires that detached witness. No ACK or binding is
carried in this scheduling metadata. The root budget field is appended to the
persisted field registry to preserve older positional encodings, and omitted
when empty.

The compiled `ReplayGrant { revision }` list is empty. An explicitly approved
revision can grant one persisted additional read per file, including through a
tripwire hold. No implicit grant accompanies a parser or contract bump.
Duplicate-request census rebuild admission should become a sub-budget of this
selection budget when that separate mechanism is composed; neither may add
reads on top of the other.

Synthetic contracts cover clock rollback, suspend, restart, failed saves,
physical replacement, tripwires, grant reuse, and held/healthy families over
seven days with retry, context, policy, fence, contract, version and cache events.
Test builds assert that unchanged indexed Full reads have an Admit ticket.
