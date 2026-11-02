# Refused snapshot custody

`accepted_log_stale_older_upload` keeps new refusals owed in `RetryPending`.
A timestamp refusal alone proves neither coverage nor dominance. Existing
records retain their dispositions and count as owed in refusal diagnostics.

The existing refusal owner retains exact body witnesses, including older
refused revisions. Identical refused stale bytes are never sent again. Changed
input may produce a different body through ordinary Tail or Full acquisition;
that body gets its ordinary offer and exact acknowledgement handling.
`accepted_log_stale_older_mixed` uses ordinary non-permanent retry custody.

A retry resends a stored body; transcripts are read again only for new bytes.
The retained retry driver uses its frozen items and existing authority checks.
A body witness is not a stored body. Missing body custody never authorizes a
transcript reconstruction. Stale entities never ride automatic quarantine,
reason re-offer, audit or revision-triggered reconstruction paths. Their existing
cooldown view holds unchanged physical input independently of retry deadlines,
parser versions and upload contexts. Changed input remains discoverable.

Diagnostics extend the existing refusal records, native collection page and
StageWindow with scalar owed/held counts, known requests/tokens, unknown counts
and oldest known age. Overlapping revisions contribute one observed revision
per entity. Missing legacy observations stay unknown. One alarm line discloses
a rising owed count or oldest age through the existing refusal observation.
There are no age buckets, additional observation windows, history structures,
retention limits or diagnostic gates. Counters do not grant read authority.

Claude, Codex and Pi share refusal custody, suppression, acquisition and
diagnostics. The timestamp refusal has currently been observed in Claude only.
Exact acknowledgements, proofs, identity, account attribution and server
acceptance authority keep their existing contracts. No schema or parser
version changes; optional observations decode independently per record.
