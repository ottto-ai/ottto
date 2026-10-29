# Durable v1 bootstrap

Restore and GC bind each known record using its stored format and source
allowlist, preserving the original scope formula. The writer remains format 1.
Formats 2 and 3 remain newer-format holds: this change allocates no new tag.
Decoded Codex counting state must agree with the configured cutover; its
interpretation and evidence remain the reduction's decision. V1 audit-debt
bytes are checked and dropped on decode without changing their wire offsets.
The v1 writer takes that field from the current committed index obligation,
so a decoded checkpoint cannot erase debt needed by downgrade readers. Invalid
debt tags or inconsistent flag/deadline pairs are preserved as Unbindable holds.
A debt-bearing record with an absent index entry is a counted acquisition miss
before sampling admission can skip restore. The existing classified header adds
no read; the old reduction is never restored as audit-clean. Normal Full creates
real index membership on completion, satisfies the audit and supplies the
post-save replacement. Post-save GC preserves same-context missing-carrier debt
records; fresh-index cleanup retains evidence without a trusted context until
that acquisition. Both-source production tests require one-pass census
completion and publication with exactly one `ineligible.audit_carrier` miss.
Supported native layouts additionally verify replacement, append/Tail, idle
beyond the discovery window and a quiet restart with zero transcript bytes.
An existing entry with a reset/postponed carrier re-arms an immediate
index audit, recovering the normal completed-audit/index-saved/record-old crash
window through Full(AuditDue). The envelope never restores checkpoint debt;
the index remains deadline authority and later offers cannot postpone it.
Dirty detection hashes validated stored header/body bytes, normalizing only
the generation; dropping decoded debt cannot falsely skip its clean replacement.
Ordinary replacement failure or budget refusal retains valid v1 authority.

No migration occurs in this slice: tag 1 and its scope formula are unchanged.
An absent record keeps the existing Full-on-miss behavior, including absence
caused by capacity, inventory overflow, write deferral, failed persistence or GC.
There is no missing-state hold, counter, alarm or special Codex exemption.
O3 upgrade recovery belongs to 5b-A1a/A1b2d (SOURCE SRC-1b): idle hold, then one
counted A5 on real new content, excluding keys with no record by design. That
later slice must supply its durable cause binding; this change grants none.
GD's retired reservation ledger and positional fields remain retired.

Fixed v1 scope/replay digests, headers and complete writer-output literals
(nonzero and zero audit debt, both sources) pin the historical serializers.
The full writer goldens use an opaque fixed body; production body decoding and
restoration are covered separately. A two-reload debt fixture rewrites from the
current index, checks downgrade-visible bytes, misses absent entries and re-arms
reset carriers. A native crash-window fixture audits, saves without replacing,
restarts, completes the re-armed audit and proves replacement permits Tail.
GC representation lookup is bounded to store-header bytes, charged to GC, and
has a direct header-only fixture with the synthetic transcript unavailable. Native restart fixtures
cover old restore, Tail, ordinary save/GC and a second restore with zero Fulls;
existing bounded class-X re-derivation still prevents a zero-byte claim.
No flags, parser/scan-identity bump, Pi source or tag reinterpretation.
