# Scan index record decoding

The persistence reader isolates record typing from JSON syntax. Activity and
accepted-identity damage drops only unusable positive evidence. Undecodable
file, entity-refusal and Claude family records retain opaque holds at their
original JSON field and key. Intact sibling correction/exclusion records for a
held family are frozen with it. Clones and partial commits share held payloads.

Holds grant no acceptance, proof, retry or mismatch bypass. Candidate, group,
publication, manifest and removal gates preserve their scope. This first slice
keeps holds until a compatible implementation understands the original slot;
it introduces no automatic release. A held file without exact incidence keeps
its prior membership UNKNOWN. Both acceptance pruners retain existing ACKs while
that uncertainty exists, and legacy reconciliation neither reopens ACKs nor seals
until incidence is known. This creates no acceptance or manifest membership;
an explicit exact empty set remains known empty. An opaque Codex file with unknown ownership
also fences state-only publication, since its lost owner cannot safely be named.

Hold admission checks lexically delimited keys before String allocation and
charges their original wire bytes, values and per-slot bookkeeping before
retention: at most 8 MiB, one eighth of the input, and 4,096 slots per read.
File holds also reserve an owner copy up to the raw value length. Repairs release
the complete charge; output restart admission uses that same charge. Oversized
keys take the counted budget path without allocating a large key buffer.
Excess damage uses the existing load quarantine or CAS error. The load diagnostic
names the prior-history gated rebuild, which requires #712 to land first; the
existing whole-index alarm and lenient_hold_budget_exceeded counter remain. Syntax/truncation still quarantines on load.
Malformed schema, generation, ledger or monotone controls refuse with the source
file unchanged. Ambiguous duplicate fields also refuse. Bounded selected CAS
keeps its existing byte cap and 8,192-node/depth-64 admission. A save also checks
that its output will admit the same holds after restart; if dropping optional
input would violate that fraction, it refuses with the original file unchanged.

Both CAS readers use the same record policies as load. New opaque debt or an
incompatible negative-state repair found only at CAS requires reload before a
write. Matching holds permit unrelated commits and retain their exact raw slots.

This slice covers files, activity, accepted identities, settlement cursor,
native refusal records, Claude authority refusals, family pending/witness maps,
and the existing census codec. Other collections retain strict typing and
non-quarantining refusal until their domain gates are integrated. The canonical
Codex key-collision behavior remains unchanged.

The independent money-selection codec must drop/count only a bad file selection,
leave that file due for census, and retain other selection records. A money
ledger version or decode failure must return an error without moving or replacing
the ledger file. Adding claude_money_files requires coordinated updates to the
ScanIndex serializer, field registry and decoder dispatch; the census registry
assertion rejects incomplete integration. This contract does not add money fields
or change their owner.

The original-input lexical gate keeps scalar depth, quote/escape and number
state, with no container stack. Main-document nesting above 256 refuses in
place. Optional census evidence beyond that depth or its existing raw byte cap
is drained and becomes unknown/null as a resource outcome. Only admitted input
reaches bounded grammar checks; syntax damage within admitted data retains the
quarantine rule. The syntax-only census pass neither buffers nor interprets it.

Negative repair provenance is one fixed-size digest and count, independent of
the corpus. The digest sums truncated SHA-256 commitments to field, key and
original record hash. Domain edits after load keep that commitment, so ordinary
transitions can save against the same damaged disk input. Changed nonempty CAS
provenance requires reload. Canonical saves remove the repaired input; an empty
current commitment contains no new damage and permits later partial/final saves.
