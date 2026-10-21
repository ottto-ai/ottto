# Claude prior-index lifetime at final save

A non-current Claude native comparison already revokes its local lease before
finalization. After all selected-state restoration and correction settlement,
that path no longer needs the old committed scan index. It now drops that owner
before the final save decodes the on-disk index for compare-and-swap validation.
Other sources and every potentially current native-comparison path retain the
prior index conservatively. The live authorization, exact body ACK and durable
save checks still run at their original post-save boundary. An authorized
receipt without its retained prior index fails closed.

No schema, CAS validation, partial checkpoint, held/debt rule, wire contract or
resource cap changes. This does not remove earlier evidence-fold or partial-save
copy peaks. Source ownership proves a narrower live graph; it does not establish
an installed memory saving, leak fix or cause of a measured RSS peak.

The real-finish regression compares the same completed native input with the
old retention lifetime and the new retirement lifetime. A caller-thread
born-pointer allocator audit charges the actual prior-index clone and observes
its release before the final save. Exact serialized selected index, progress
ledger and offered bodies are compared, with acceptance, permanent refusal,
retryable conflict and a real concurrent-generation CAS failure. An earned
predecessor lease control retains its prior index through the receipt path.
The test-only counter getter reads the existing audit table without allocating;
no allocator, table, cap, production diagnostic or CAS hook is added. Runtime
resource observations and positive native receipt regressions remain separate
from this synthetic requested-allocation evidence.
