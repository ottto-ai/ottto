# Retired unchanged transcript reread guard

The observe-only structural reread guard and dormant enforcement were removed.
Read selection, cache behavior, durable restore, money folds and joins keep their
existing policy. This removes bookkeeping, not transcript reads.

The local census text keys `unchanged_reread_over_budget{cause|override}`,
`reread_mode`, `reread_observed`, `reread_tracking_dropped{attempts|physical|growth}`,
`reread_planned`, `reread_indexed`, `reread_tripwire_would_fire`, and `growth_full`,
and the guard's stderr alarms, are retired. Existing physical-read `full_reasons`,
Claude reread diagnostics, durable-head bytes and carried-ACK age remain. These
text fields were outside versioned `local_resources` JSON; its schema is unchanged.

Legacy `reread_guard` and traversal counter slots `unchanged_reread_admitted` and
`reread_budget_refused` decode and drop through zero-sized placeholders with the
original wire names and positions. Writers omit them. Earlier readers default
these absent fields. Index schema, generation, entry layout and certificates do
not change; retired counters cannot trigger a reset or a reread.
