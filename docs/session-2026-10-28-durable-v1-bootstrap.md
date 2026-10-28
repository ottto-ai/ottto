# Durable v1 bootstrap

Restore and GC bind each known record using its stored format and source
allowlist, preserving the original scope formula. The writer remains format 1.
Formats 2 and 3 remain newer-format holds: this change allocates no new tag.
Decoded Codex counting state must agree with the configured cutover; its
interpretation and evidence remain the reduction's decision. V1 audit-debt
bytes are checked and dropped on decode without changing their wire offsets.
Ordinary replacement failure or budget refusal retains valid v1 authority.

GD removed the old reread reservation ledger. This change does not restore it
or use its retired positional fields. Indexed cold misses hold conservatively,
including changed content, until the approved cause gate can durably bind the
one permitted A5 recovery. Held misses are observable as `durable_held` class
`upgrade_missing`; `upgrade_state_missing` counts admitted A5 reads and remains
zero while that admission is unavailable. Completed joined Codex jobs retain no
per-file reduction by design and use their existing group admission. Durable
record holds still precede this exemption.

No feature flags, new source tags or representation reinterpretation. Broader
restart admission and R2 format 3 remain separate changes.
