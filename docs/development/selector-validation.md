# Selector capture validation

Newly captured selector candidates pass one shared key and value validator before
entering context or provenance maps. Claude, Codex, Pi custom selectors and Codex
quota windows use the existing normalizer and insertion seam. Valid values retain
their original normalized spelling and source label. Alias order and nested merge
order are unchanged. Validation does not activate previously unrecognized aliases
or bypass attribution consent.

`SELECTOR_KEY_RULES` in `crates/ottto-service/src/snapshots.rs` enumerates the 29
known keys and their validators. Token fields require JSON strings normalized to
1–128 ASCII letters, digits, underscore, dot or colon. Batch mode keeps its existing
boolean aliases; mode keeps fast/standard/priority/flex normalization. Context
bucket accepts short/long/standard/unknown. Cache TTL accepts unsigned decimal seconds or an
unsigned decimal duration followed by s/m/h/d. Plan-window day bucket and quota
window minutes/reset timestamps require decimal u64 strings. Quota percentages
and balance require finite nonnegative numeric values; percentages may exceed
100. Credit flags accept normalized true/false. Accepted numeric spellings are
not parsed and reserialized. Recognized null candidates mean absence.

Unknown fields in explicit selector containers and malformed captured values are
dropped. Ordinary event-envelope fields are outside the selector vocabulary.
The existing native collection page diagnostics carrier reports process-wide cumulative
`selector_key_rejected` counts with only `unknown` and `format` classes; repeated
capture attempts are counted, not unique lines. These counters contain no raw
key, value or source text. `format` counts only candidates the base normalizer
accepted and the new validator rejects; nulls, empty strings and other values
already dropped by normalization remain uncounted. Diagnostics do not affect parsing or recovery.

Current selector persistence, record framing, allowlist hashes, tier receipt keys
and detected-use plan grouping remain unchanged for valid inputs. Validation is
forward-only: existing record decode and restore do not scrub legacy values.
There is no cleanup scan, forced re-read or compatibility revision. Local selector
fields remain clear in mode-0600 records. An identifier grammar limits shape; it
cannot establish that every identifier-shaped value is non-private.

Synthetic tests exercise real producer aliases and quota shapes, zero valid-input
rejections, rejected-value record canaries, Pi occurrence inputs, and Claude/Codex
restore followed by Tail versus cold Full. The money-equivalence dispatch also
overlays only the valid-input test on its comparison ref and compares exact
serialized emitted bodies, record bodies, row identity, tier keys and detected
plan fingerprints. Both comparison arms read the same physical synthetic files,
so birth timestamps and file identity cannot create false byte differences.
Invalid-input tests stay outside that equal-output comparison.
