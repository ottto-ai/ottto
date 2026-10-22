# Composition recovery without history replay

The reader persists its initial discovery cutoff and starting offsets before
committing any scope. An interrupted installation resumes that discovery; a
restart never substitutes a newer cutoff for files still waiting to be read.

Scope commits retain the previous manifest, totals, and checkpoint shards until
a replacement is verified. Unusable state falls back to that generation and
charges only its missing delta to the repair allowance. Without usable prior
state, the scope or damaged shard's files are quarantined and counted. No scope
is rebuilt from transcripts. Sibling checkpoints keep their identities and open
residency. Unknown kind or part identifiers in any checkpoint field restart only
that checkpoint at its end, preserving its aggregated history.

Exceptional pins are saved with the scope manifest: pending fallback offsets,
repair boundaries, and file quarantine decisions survive a crash before the
single index write. Ordinary checkpoints recover their committed offsets without
inferring repair debt from a decrease: a shorter offset can be a successful
rewrite. Temporarily absent files retain pending fallback work. Reads beyond a
full-read reservation remain for the next run. New state directories are flushed
into their parents before committing children.

The metrics line includes `state_fallbacks`, `scopes_quarantined`,
`files_quarantined`, and `checkpoint_restarts`. Daily run-health transport will
need to carry these counters separately from workspace uploads. This change does
not modify the server or enable the reader's release switch.

Regressions cover interrupted two-scope installation, invalid scope state,
unknown checkpoint identifiers, missing and truncated active shards, pending
fallback reads after failed reads or exhausted budgets, lost index writes,
complete index loss, shorter rewrites, discovery-to-open growth, and directory
sync ordering. Full workspace validation also runs in public CI.
