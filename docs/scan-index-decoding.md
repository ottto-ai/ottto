# Scan index record decoding

The persistence reader isolates record typing from JSON syntax. Activity and
accepted-identity damage drops only unusable positive evidence. Undecodable
file, entity-refusal and Claude family records retain opaque holds at their
original JSON field and key. Intact sibling correction/exclusion records for a
held family are frozen with it. Clones and partial commits share held payloads.

Holds grant no acceptance, proof, retry or mismatch bypass. Candidate, group,
publication, manifest and removal gates preserve their scope. This first slice
keeps holds until a compatible implementation understands the original slot;
it introduces no automatic release. An opaque Codex file with unknown ownership
also fences state-only publication, since its lost owner cannot safely be named.

Hold admission checks lexical lengths before retaining bytes: at most 8 MiB,
one eighth of the input, and 4,096 slots per read. Excess damage uses the existing
load quarantine or CAS error. Syntax/truncation still quarantines on load.
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
the ledger file. This contract does not add money fields or change their owner.
