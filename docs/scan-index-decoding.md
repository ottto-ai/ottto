# Scan index record decoding

The persistence reader isolates record typing from JSON syntax. Activity and
accepted-identity damage drops only unusable positive evidence. Undecodable
file, entity-refusal and Claude family records retain opaque holds at their
original JSON field and key. Intact sibling correction/exclusion records for a
held family are frozen with it. Clones and partial commits share held payloads.

Holds grant no acceptance, proof, retry or mismatch bypass. Candidate, group,
publication, manifest and removal gates preserve their scope. This first slice
keeps holds until a compatible implementation understands the original slot;
it introduces no automatic release. A held file without exact incidence keeps
its prior membership UNKNOWN. Acceptance pruning, including partial commits, retains existing ACKs while
that uncertainty exists, and legacy reconciliation neither reopens ACKs nor seals
until incidence is known. This creates no acceptance or manifest membership;
an explicit exact empty set remains known empty. An opaque Codex file with unknown ownership
also fences state-only publication, since its lost owner cannot safely be named.

Hold admission checks lexically delimited keys before String allocation and
charges their original wire bytes, values and per-slot bookkeeping before
retention: `min(8 MiB, max(input_bytes / 8, 1 MiB))` and 4,096 slots per read.
Intact file owners use inline ranges into the shared raw slot, without a second
payload allocation. Repairs release the complete charge; output restart admission
uses that same charge. Oversized
keys take the counted budget path without allocating a large key buffer.
Excess damage uses the existing load quarantine or CAS error. The load diagnostic
names the prior-history gated rebuild, which requires #712 to land first; the
existing whole-index alarm and lenient_hold_budget_exceeded counter remain.
If this same checkpoint has a `.corrupt` sibling timestamped within seven days,
the next over-budget load refuses in place instead of rebuilding again. The
existing backup name supplies the rename timestamp (mtime survives rename);
no new durable state is added. Future timestamps also block a rebuild, covering
clock rollback. All same-checkpoint corruption backups conservatively count,
including syntax and identity-collision quarantines. Syntax/truncation still quarantines on load.
A paused source reports `scan_index_rebuild_loop` with its automatic retry time
(`auto_retry_at=`, the newest backup stamp plus seven days) in the health
`clear_condition`. One interactive user Repair from the signed companion
(token-less `repair`, not dry run) may pass the guard once: the next source load
strictly decodes the session-identity fields (bindings, deferred holds,
contract token, owned-start census, stale-family carry, duplicate owners and
fence flag, current-ledger accepted fingerprints and their per-file incidence,
plus completed replay and curve generations) from the damaged bytes and
durably replaces the index with a generation-0 gated rebuild that carries them
(contract latch set; carried acknowledgements retained per file until that
file is completely reconstructed through the emission policy, including
history-held files that never re-parse during a full census; a vanished file
releases only when pruned at a healthy effective complete terminal), keeps the damaged bytes as `.corrupt.override.`, counts
`scan_index_rebuild_manual_override` and logs one line. If any of those fields
cannot be strictly recovered (syntax damage included), the override refuses:
the source stays paused, the index is untouched, and the successful-override
cooldown is not spent. A later press returns the same clear refusal without arming or incrementing the
attempt counter. A compatible load clears that refusal.
`scan_index_rebuild_override_identity_unrecoverable` is counted, alarmed and
named in the health `clear_condition`. Syntax damage waits for the seven-day
automatic retry: sessions arrive late, not lost.

Carried ACK debt is separate from ordinary ACKs: only the original identities
are retained, so superseded healthy-sibling revisions still prune. Entry and
byte admission charge file keys, ACK strings, duplicate ledger storage and
bookkeeping before retention: at most 4,096 combined file/identity slots and
8 MiB. Admission exhaustion refuses before writing the index or cooldown;
`scan_index_rebuild_override_carried_ack_budget_exhausted` counts that code
separately from identity, persistence and cooldown refusals. Content-free
`scan_index_rebuild_carried_ack_debt_entries` and
`scan_index_rebuild_carried_ack_debt_bytes` disclose the admitted debt size.
Each census line reports `retained_carried_entries` and
`history_held_carried_entries` after finalization. Unknown original incidence stays bounded and retained rather than guessing a
file or granting new ACKs blanket retention. Releasing a file suppresses its
already accepted entities and transfers its reconstructed membership to the
ordinary ACK ledger; a partial commit retires debt only for committed files.
 The witness re-arms the seven-day guard;
the 24-hour cooldown is durable per checkpoint and source-wide
(`<support>/snapshots/<source>-scan-index-rebuild-override.json`, outside every
destination namespace, so a re-pair does not reset it; future or malformed
stamps cool). A second press inside it returns
`scan_index_rebuild_override_cooldown`. Verify, automatic retries,
unattributed loads and token (CLI or agent) Repairs never override. Transcripts
stay on disk, so a paused source's sessions arrive late, not lost.
Malformed schema, generation, ledger or monotone controls refuse with the source
file unchanged. Ambiguous duplicate fields also refuse. Each refused decode
emits one content-free fixed-category containment line; the future-ledger path
keeps its existing once-per-source alarm. Recovery requires a compatible decoder
or reviewed repair that preserves custody. Do not delete the index: that is a
Missing origin, and forfeits its acceptance and history evidence. Bounded selected CAS
keeps its existing byte cap and 8,192-node/depth-64 admission. A save also checks
that its output will admit the same holds after restart; if dropping optional
input would violate that fraction, it refuses with the original file unchanged.

Both CAS readers use the same record policies as load. New opaque debt or an
incompatible negative-state repair found only at CAS requires reload before a
write. Matching holds permit unrelated commits and retain their exact raw slots.

This slice covers files, activity, accepted identities, settlement cursor,
native refusal records, Claude authority refusals, family pending/witness maps,
and the existing census codec. Other collections retain strict typing and
non-quarantining refusal until their domain gates are integrated. The canonical
Codex key-collision behavior remains unchanged.

The independent money-selection codec must drop/count only a bad file selection,
leave that file due for census, and retain other selection records. A money
ledger version or decode failure must return an error without moving or replacing
the ledger file. Adding claude_money_files requires coordinated updates to the
ScanIndex serializer, field registry and decoder dispatch; the census registry
assertion rejects incomplete integration. This contract does not add money fields
or change their owner.

The original-input lexical gate keeps scalar depth, quote/escape and number
state, with no container stack. Main-document nesting above 256 refuses in
place. Optional census evidence beyond that depth or its existing raw byte cap
is drained and becomes unknown/null as a resource outcome. Only admitted input
reaches bounded grammar checks; syntax damage within admitted data retains the
quarantine rule. The syntax-only census pass neither buffers nor interprets it.

Negative repair provenance is one fixed-size digest and count, independent of
the corpus. The digest sums truncated SHA-256 commitments to field, key and
original record hash. Domain edits after load keep that commitment, so ordinary
transitions can save against the same damaged disk input. Changed nonempty CAS
provenance requires reload. Canonical saves remove the repaired input; an empty
current commitment contains no new damage and permits later partial/final saves.

The manual serializer, FIELDS registry and dispatch must change together.
An all-persisted-fields, non-default fixture asserts exact registry coverage and
an unchanged round trip through the shared decoder. An unhandled dispatch field
refuses in place rather than panicking.

The ClaudeScope shadow reader still treats held native files as absent. Before
money-ledger decisions become live, its walk must include held file keys as lost
debt. This is a prerequisite for enabling the independent money implementation.
