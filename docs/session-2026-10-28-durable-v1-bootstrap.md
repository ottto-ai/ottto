# Durable v1 bootstrap

Restore and GC bind each known record using its stored format and source
allowlist, preserving the original scope formula. The writer remains format 1.
Formats 2 and 3 remain newer-format holds: this change allocates no new tag.
Decoded Codex counting state must agree with the configured cutover; its
interpretation and evidence remain the reduction's decision. V1 audit-debt
bytes are checked and dropped on decode without changing their wire offsets.
The v1 writer still emits that field. The index-owned audit obligation remains
the deadline authority: restore and later offers cannot postpone its deadline.
Ordinary replacement failure or budget refusal retains valid v1 authority.

No migration occurs in this slice: tag 1 and its scope formula are unchanged.
An absent record keeps the existing Full-on-miss behavior, including absence
caused by capacity, inventory overflow, write deferral, failed persistence or GC.
There is no missing-state hold, counter, alarm or special Codex exemption.
O3 upgrade recovery belongs to 5b-Claude-A1 (SOURCE SRC-1b): idle hold, then one
counted A5 on real new content, excluding keys with no record by design. That
later slice must supply its durable cause binding; this change grants none.
GD's retired reservation ledger and positional fields remain retired.

Fixed v1 scope/replay digests and header bytes pin the two historical writers
and both sources independently of current helpers. Native restart fixtures
cover old restore, Tail, ordinary save/GC and a second restore with zero Fulls;
existing bounded class-X re-derivation still prevents a zero-byte claim.
No flags, parser/scan-identity bump, Pi source or tag reinterpretation.
