# Census safety retention admission pressure

A test-only resource reproduction shows why retained transcript-safety hashes
need an explicit admission policy before they share D1's existing budget.
No production code, persisted format, selector or activation gate changes.

At the 2,097,152-hash limit, use two transcript records of 1,048,576 hashes
each. The existing retirement drops the first record's hashes. A new active
transcript with one hash then stores successfully. Reserving the same retired
hash slots for safety instead leaves zero headroom: the existing insert path
stores the new active record as an OverBudget tombstone. The existing MONEY
scope reader consequently changes that active family's completeness from
true to false. Metadata and serialized-size growth are not needed to trigger
this case.

The regression deliberately models only hash-slot reservation with ordinary
synthetic records. It does not implement safety accessors, retirement buffers,
shadow counters, or a new admission policy. Its passing assertions establish
the pressure difference; they do not establish parity for a future retention
implementation. Existing pipeline parity tests continue to cover unchanged
production behavior.

Before implementing retention, define and validate how a later active parse
reclaims safety capacity while retaining the retired MONEY state, marking the
safety refusal, charging metadata exactly, and bounding reclamation work and
memory. Simply retaining hashes at retirement or making the new active record
OverBudget changes MONEY's existing result. Giving active and safety hashes
independent budgets would exceed the combined bound.

Validation is CI-only. The draft PR records the exact tested head and results.
