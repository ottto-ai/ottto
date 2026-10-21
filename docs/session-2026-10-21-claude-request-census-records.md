# Claude request-census records (shadow only)

Each Claude transcript index key now has one durable request-census record in
`ScanIndex::claude_request_census`. The record has these fields:

- `fp`: the candidate source fingerprint of the parse that wrote it.
- `v`: `CLAUDE_REQUEST_CENSUS_DERIVATION`.
- `w`: the census window end, in unix seconds.
- `s`: the shape, one of `exact`, `empty`, `identity_incomplete`, `lossy` or
  `over_budget`.
- `tw` (optional): a twin flag, set when the parsed (root, member) differs from
  the path-derived pair.
- `u` (optional): set when the parse is not source-verified.
- `h`: the sorted 8-byte SHA-256 prefixes of the request ids the parse saw.

Records are local-only and content-free. They are never proof, usage or upload
input. No fence, coverage, rearm, posture, ACK or upload decision reads them.

**Production.** Every Claude family-member parse that reaches `parser.finish`
replaces the key's record:

- A complete, loss-free parse is classified by shape.
- A parse with no positive usage yields no item, but the request ids of its
  buffered responses (zero-usage API errors) are hashed before `finish`
  consumes the parser. They are kept as `identity_incomplete`.
- Any loss, an incomplete or residue parse, or more than one item is `lossy`,
  and keeps the ids it saw.
- A failed finish and a native comparison target remove the record. An older
  revision's record never survives a newer parse.

**Ownership.** Records follow the working index through `committable_subset`
and the held-key reverts, never `previous`. A held key therefore keeps the
record of the revision this window parsed while its entry reverts.

**Removal.** The #588 selected restore and `remove_file_entry` remove the key's
record.

**Prune.** At a complete Claude terminal, before any fold, records are pruned to
keys that are indexed or were walked in this generation.

## Shadow

The scan then measures the shadow predicate and carries it on
`SourceScanResult`. The usage fold copies it into
`ClaudeDuplicateCensusCounts::request_census`, which is logged with the
existing census counters.

`would_open` is true when all of these hold:

- the census is complete;
- every indexed family-member key that is not confirmed empty has a record of
  the current derivation, matching its entry fingerprint or parsed in this
  census window;
- the hash total fits the budget;
- duplicate owners fit the existing owner bound.

Uncovered keys are counted once each, under the first matching cause:
over budget, account hold, residue, placeholder, empty fingerprint,
fingerprint mismatch, then migrate. The shadow also counts:

- quarantine roots without a record;
- shapes, unverified records, twins and census-unknown roots;
- records, hashes, duplicate hashes, duplicate owners and shared keys;
- `would_open` flips between terminals;
- a derivation-drift tripwire: a verified, complete re-parse at the same
  fingerprint and derivation that yields other ids;
- JSON and heap bytes.

`ClaudeRequestCensusShadowState` persists only the last `would_open`, the flip
count and the drift count.

## Decoder

The decoder streams per entry and is tolerant and bounded. Each of these drops
only that record or field, and the index is never quarantined:

- a wrong type, a duplicate or unknown field, or an over-long key or scalar;
- hex that is not lowercase, not ascending or not a multiple of 16;
- a shape that does not admit its hashes;
- a record beyond the record cap or the hash budget (checked before decoding).

A wrong type for the whole field gives an empty census. An older binary skips
the field.

## Bounds and pins

- `MAX_CLAUDE_REQUEST_CENSUS_HASHES = 1_048_576` (8 MiB of hashes). A
  production record past it becomes an inert `over_budget` tombstone.
- Both new fields are charged through `fields!(ScanIndex)`. `ScanIndexEntry` is
  unchanged, so #588 per-entry restore pricing is unchanged.
- The derivation canary pins the shape and hash table of a fixed synthetic
  corpus to `CLAUDE_REQUEST_CENSUS_CANARY`. A test shows the canary fails for
  each named extraction change made without a bump.

## Not changed

- No cap, wire field, schema version, body witness, scan identity or parser
  output.
- No existing test assertion was edited.

## Verification

A real-pipeline parity test runs one corpus with records on and with records
off. Every per-page decision and the persisted decision state are equal; only
the record map and the shadow differ.

No local builds or tests were run. CI on the PR is the verification.

## Review corrections

Persisted load and CAS reads cap each optional raw census field at 32 MiB
before Serde buffers its tokens. Oversized evidence is drained in constant
space and discarded. Fully escaped field names and Serde's positional struct
form use the same bound; positional slots come from Serde field metadata.
Input draining remains linear in the file bytes. Raw
sub-parses isolate numeric overflow and wrong tokens from the enclosing index;
individual records are limited to 16 MiB plus 1 KiB, 65,536 attempted entries,
and 32 MiB of interpreted entry bytes, including rejected entries. Known-field
duplicates use a fixed bitset. The `raw_value` Serde feature enables isolated
sub-parses without a field-wide `Value`.

The shadow reports integer hash-budget utilization and a warning beginning at
80% (838,861 hashes). Unproven-family age buckets are a D2 obligation: the
persisted authority record has a retry deadline, but no creation timestamp from
which a family's age can be recovered without inventing one.

Construction buffers retain at most 1,048,577 hashes before becoming an inert
budget tombstone. Vector growth is bounded by 16 MiB per construction buffer;
shrink/conversion can overlap two such buffers. The terminal join bounds inventory and key sizes and checks a conservative
requested-layout estimate of at most 128 MiB before allocating workspace, reports `transient_limited` on refusal, and measures its
peak requested layout separately as `transient_peak_bytes`. Ordinary scans
have no transient admission budget; these shadow limits and measurements do
not consume the cache-retention `copy_budget` or change its decisions. Native
comparison targets continue to invalidate records.

Parity compares semantic fingerprints plus additive-body witnesses for every
offered item, full retained proof witnesses and correction grants/owed members.
A live, nonempty correction is explicitly checked across historical replay
reset, and the corpus also traverses the reset pipeline. An old-shape decoder
control actually ignores the added fields.

The maximal shadow row uses `false`, the longest boolean spelling. Including
all added cost fields, its compact encoding is bounded by 1,238 bytes on the
64-bit scalar domain; the assertion pins equality at that maximum.
