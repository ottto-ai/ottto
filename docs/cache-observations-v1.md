# Cache observations v1

The local Codex and Claude collectors derive numeric cache evidence from owned
requests while parsing existing transcripts. Upload requires the existing
activity hint to advertise `session_cache_observations:v1` through
`session_cache_observations_contract`. Missing, null, or unknown capability
suppresses cache patches and cache witnesses; local evidence remains available.
Capability changes reuse existing file upload-context invalidation.

Each affected request has a stable identity, actual previous and immediate-next
request slots, and separate baseline and episode-anchor references. Codex uses
canonical `token_usage_record` reports; legacy accounting echoes are excluded.
Claude uses resolved completed response reports after existing ownership proof.
Copied prefixes and uncertain ownership cannot create cache evidence.

Prompt tokens include cache reads, cache creation, and uncached input. Counters
retain null when unavailable, and known zero remains zero. Claude's input count
is normalized by adding reported reads and creation; Codex's input count already
includes reads. Uncached input is calculated only when all required counters are
known. Output counters retain the provider's reported value. Timestamps preserve
source spelling and precision; durations floor to nonnegative whole seconds.

The detector distinguishes unexpected loss, known rebuild boundaries, cold
starts, and ambiguity. Model/configuration changes and compaction are recorded
as competing conditions. `likely_expiry` requires comparable warm evidence,
measured Codex task-complete to task-start idle, and an observed stable
configuration. Claude completion-report gaps remain report gaps, with idle
unknown. These explanations are hypotheses; they establish no billing or
provider cache lifetime guarantee. Missing predecessors, uncertain order, and
unknown counters cannot supply an unexpected-loss baseline.

The optional `cache_observations` patch uses bounded upsert/retract operations.
Gate materializes the cumulative current set, so corrections and retractions
produce self-contained downstream evidence. V1 permits 64 operations and
128 KiB per patch; cumulative state permits 128 rows and 128 KiB. Overflow
reports partial coverage and omitted counts while preserving accepted evidence;
it does not silently evict rows or introduce another uploader.

Every cache patch declares `snapshot_head_etag:v1` and uses the accepted
predecessor etag for existing entities. A collector without that token first
settles grown ordinary usage with cache omitted through the existing optional
ordinary write authority, then probes that same frozen body through the existing
CAS contract. Server-mandated CAS and legacy reconciliation skip ordinary
bootstrap; an existing changed head without a saved token then requires the
existing authorized reconciliation path. Conflicts fail closed, and conflict
challenges never authorize a cache correction. Exact head ACKs and numeric cache state persist in the
existing destination-scoped atomic upload ledger across completed cycles and
restarts. Legacy count-only responses cannot acknowledge cache evidence.

The body witness hashes canonical cumulative cache state plus declared existing
curve/tool fields. Modern cache-only versions 15/16 normalize to public ACK
versions 13/14; cache-plus-curve versions 19/20 normalize to 17/18. Cache remains
neutral to semantic revision v2 and content-hash epoch 1. Existing accounting,
pricing, and usage authority remain unchanged.

A deployment that mandates head CAS must coordinate the existing producer
release floor and reconciliation support before rollout. Cache capability does
not grant missing-head or stale-head authority; pre-feature changed entities
without a token cannot bootstrap through a mandatory-CAS route.
