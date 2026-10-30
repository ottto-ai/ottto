# Claude resumed-file copied-prefix accounting

Resumed main transcripts written by older Claude Code versions now use the
existing earlier-file request census to decide their copied prefix. Their own
turns stay outside the removal range. Certified 2.1.309/2.1.310 transcripts keep
their existing timestamp/twin decision.

A newly proven removal is saved on the resumed file as local request hashes
grouped by the earlier holder. While that holder remains indexed, retirement of
its census hashes does not restore an already removed request. A current holder
that no longer lists the request invalidates that saved removal.

The store has a 4 MiB charged bound: 40 bytes per resumed file, 32 per holder
group, and 8 per request hash. Existing decisions are never evicted for capacity.
New proven removals that cannot fit hold the session, counted by
`held_copy_removal_capacity` and `copy_removal_store_overflow`. This exceptional
hold can delay the session's own turns. It is distinct from absent or expired
proof: a copied prefix without proof or a saved removal emits unchanged and is
counted by `copy_prefix_unproven_requests` and `copy_prefix_unproven_files`.
A parent link alone does not prove an older-writer resumed prefix.

Flags remain diagnostic. Reported dollars cover only flagged requests matched
to priced local telemetry; `copy_prefix_unproven_priced_requests` states that
coverage. No wire field, server counting rule, automatic re-read, or release
change is included.

Synthetic pipeline fixtures cover an older-writer resume chain, expired and
missing proof, saved decisions after expiry, a rewritten holder, certified
writers, no prefix, and capacity refusal. Tests run in Linux CI, never locally.

Integration remains pending: the census proof interface currently accepts Lossy
records, while the resumed-prefix policy requires those records to be unproven.
A read-only census shape accessor is needed before this patch is ready to ship.
The persisted-state decoder also currently discards damaged removal metadata;
that disclosed recovery limit needs review before release.
