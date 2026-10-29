# Durable v1 audit-safe bootstrap core

This core and the grouped-custody/stored-representation binding completion are
a **hard release pair**. The core lands first, the completion immediately after,
and both ship in the same release. The core never ships alone. Grouped Codex
member/alias recovery remains main-equivalent in the core and is completed by
the paired slice; this is not a claim of complete grouped recovery here.

The core uses main's narrower current-representation scope-binding formula.
Parameterized old-representation scope construction is deferred with its runtime
record-format plumbing. Header dispatch still checks stored format/source/pin;
tags 2/3 remain newer-format holds and tag 3 is reserved. No allowlist repin,
parser/scan identity bump, Pi section or new persisted field is introduced.
The existing Codex stored-cutover compatibility guard stays enabled.

V1 compatibility debt is canonical-validated before it is removed from checkpoint
authority. Invalid debt pairs remain byte-preserving Unbindable holds. The writer
uses the CURRENT committed index obligation and the unchanged v1 encoding.
Dirty detection hashes validated stored bytes with generation normalized, so
removed decoded debt cannot falsely skip a clean replacement. Four complete
zero/nonzero debt writer literals remain byte-identical.

A surviving debt record with absent index membership is a counted miss into
normal native Full, never a permanent hold or a clean restore. Only a canonical
validated SAME-context record supplies recovery debt: the live digest includes
the namespace and active upload-context fingerprint. Its deadline clamps once
to min(envelope due, now), independently of sampling admission. The acquisition's
runtime custody survives paging and missing preparation; no entry is created
from the envelope. Native parsing creates membership. Source-verified Full
completion retires its obligation through the existing completion counter and
post-save writer. Terminal-loss publication stages the existing unverified-source
marker/deadline instead, preserving save/restart and age-independent discovery.
`ineligible.audit_carrier_staged_unverified` counts only successful initial
staging, while `ineligible.audit_carrier` counts the miss. Verified-first recovery
stages nothing. Existing retry/backoff owns the next audit; no new schedule.

GC preserves missing-key debt evidence before Full, and the same-context
predecessor while the real entry remains unverified, even if its decided scope
changed. A verified Full supplies the ordinary replacement. Reset/postponed debt
on an existing entry still rearms an immediate index audit. A foreign record
cannot supply that scheduling authority before ordinary binding checks.

An absent record retains main's Full-on-miss behaviour, including capacity,
deferral and failed persistence. There is no UpgradeMissing hold/counter/alarm.
O3 belongs to 5b-A1a/A1b2d: idle hold then one counted A5 on real content,
excluding by-design no-record keys. This core grants no such replay permission.

Both-source singleton fixtures cover verified-first Full, terminal-loss marker
custody, actual save/GC/restart and later verified retirement; future-deadline
and foreign-account controls distinguish import/clamp/counting. Native layouts
also check replacement, next-append Tail, idle and quiet restart with zero
transcript bytes. Independent native/money and exact-head CI qualification remain
required. Original bounded class-X rederivation still prevents a blanket
zero-transcript-byte restore claim. Grouped members and complete old-binding
bootstrap are explicit hard-pair completion work.
