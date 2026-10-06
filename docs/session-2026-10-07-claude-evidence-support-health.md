# Bounded Claude local evidence support health

`ottto diagnostics collect` now has a real on-demand consumer of bounded typed
API-request/trace evidence inspection. Available prior canonical rows and explicit
incomplete health are kept separate; only aggregate counters leave the reader.
A capped file can contribute available row counts while remaining oversized and
non-authoritative. No source bytes are changed, and strict accounting/account
loaders, scanner selection, ScanIndex, accepted facts and forwarding are unchanged.

The reader retains duplicate/conflict state across small pages on one opened
object. It reuses API identity-upgrade replay decisions, validates canonical row
fingerprints, file/session binding, request ids, capture revision and event time.
Unframed or oversized lines are refused, and every exhausted file/directory/row
bound remains explicit. Child files are opened relative to pinned directories
without following symlinks; object/size/mtime changes disclose incomplete reads.

The consumer reads at most eight files and 512 KiB, with 16 KiB lines and 128
physical rows per file. There is no background scan, new screen, wire DTO, durable
metadata, journal, cap increase, TTL, deletion, growth scheme, account authority or
reported-money promotion. Existing diagnostics upload approval still applies.
`complete_capture_authority` is always false; parse-valid observed prefixes cannot
certify missing requests. Persistent zero-byte loss health and growth remain
separate unresolved store-owner contracts.

Synthetic native checks cover exact prior bytes, cap/malformed/unframed tails,
line/read/row/file bounds, continuation conflicts, duplicate and identity-negative
rows, symlink refusal, strict cap withholding and actual diagnostics integration.
Public source review/CI and normal containing signed-release acceptance remain
separate; this change does not trigger a release or a provider request.
