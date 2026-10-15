# Claude slot state follows the windows, not credit sections

Quota contract v2.2 gave each Claude credit section its own freshness, read
from its own read time, and made the slot snapshot's state follow the windows
only (see `session-2026-10-10-claude-credit-pools-cadence.md`). Two paths still
derived the slot's collection state from every credit section as well:

- a registered slot's reading (`custom_claude_snapshot_from_usage`), and
- the default login's reading (`claude_default_slot_collection_status`).

A single Stale section therefore turned a slot with fresh windows into
`provider_unavailable`. The app shows that as "Connection temporarily
unavailable", or as "Limits not updating" with the fresh meters hidden as
stale history, although no read failed.

This happens regularly on an unused account with usage credits off. Its plain
read runs about every 6 h and refreshes the windows but not the saved-reset
section, which keeps the previous slot's read time. The next read waits one
full gate after the plain read. When that read is late (passes land after the
gate, and long collection passes delay it further), the saved-reset section
crosses its two-gate bound first. The slot then reads as temporarily
unavailable until the next read, even though the windows are minutes old. An
off-cadence plain read, a 24 h variant pause or an open breaker widens that
gap the same way.

Both paths now take the state from the windows only, as the snapshot already
did. Each credit section keeps its own Stale label and original read time, so
an old saved-reset or usage-credit section still shows as stale on its own.
Stale windows still produce `provider_unavailable`. Identity checks on credit
sections are unchanged, and so are read cadence, scheduling, provider calls,
breakers, upkeep, wire values and persisted formats.

A regression test builds a reading with fresh windows and a Stale saved-reset
section. It checks that the registered-slot path and the default-login path
both report `fresh`, that the snapshot is not Stale, and that the section keeps
its Stale label. The same reading with stale windows still reports
`provider_unavailable` on both paths.

The snapshot candidate ranking (`claude_snapshot_candidate_rank`) still ranks a
reading lower when a credit section is stale. That ranking picks between
readings of the same account and does not set a state, so it is unchanged.
