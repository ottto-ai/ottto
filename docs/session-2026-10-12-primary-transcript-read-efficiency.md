# Primary transcript read-efficiency diagnostics

The existing local resource record counted full/tail/unchanged selections and
aggregate input bytes. Selections occur before native completion, and one tail
can be followed by a full priority replay. These totals had no paired full-read
byte denominator, so they could not establish ordinary read savings.

An additive `counts.sampled_acquisition.acquisition_efficiency` namespace,
version 1, reports qualified completed primary operations for both Claude Code
and Codex. The enclosing local resource schema remains version 2. Legacy counts,
source output, wire data, index/ACK boundaries, guards, audits and byte caps are
unchanged. No new read, stat, hash, per-line log or clock query is required.

The page owns one noncloneable operation slot, following its one active primary
parser through moves, resumptions and protected-tier replay. Constant-time
snapshots retain native framing progress; each superseded attempt is charged
once. Existing EOF, source/dependency and native-finish validation qualify the
final operation. Cache-admission refusal does not invalidate qualified reads.
Failed preparations preserve actual guard progress; unsuccessful and unknown
operations are disclosed separately.

Each completed full/tail operation has one `full_equivalent_bytes` denominator:
the file length already captured and revalidated for that final read. Native
bytes include all attempts in that operation; guard bytes are separate. A tail
followed by full replay has one final full denominator and both attempts' cost.
Unchanged operations use a zero denominator, preserving unchanged skipping in
the modeled baseline. Repeated operations in later cycles are repeated work.

For a qualified set, net logical byte avoidance is the sum of full-equivalent
bytes minus native bytes minus guards. Compute this with signed arithmetic;
small tails and replays can produce negative avoidance. Do not add audit subsets
a second time. Native bytes represent input consumed by framing, including
unterminated input consumed at EOF, not just the retained sealed pointer.
Joins, parent traces, sidecars, header/discovery/account reads and physical disk
I/O remain outside this primary-acquisition scope.

`paired_totals_valid=false` makes arithmetic totals unavailable. Checked
arithmetic does not silently wrap or saturate into apparently complete savings.
`page_coverage_complete=false` discloses unpaired/unknown/unsampled work or a
concurrent abandoned-page gap. Unpaired observed bytes are known portions,
never a claim that missing work was zero.

Page abandonment performs no logging, allocation, syscall or log-lock access.
It only updates a checked, process-image-lifetime counter for the source. The
existing normal collection event reports `abandoned_pages_at_start` and
`abandoned_pages_at_emit`; no page drains that counter. Overflow makes its
value unavailable. A previous nonzero gap is not recovered byte evidence;
a changed marker during the interval signals unobserved abandonment. If no
later normal event exists, absence of the marker is not evidence of no work.
Counters reset with the process image. Analysis must bind PID, exact start,
mapped executable and counter version; reset, ambiguous ordering or incomplete
window coverage cannot become a zero-gap claim.

Existing CPU spans include concurrent process work and may overlap other stage
windows. They measure observed cost, not exclusive parser CPU or CPU savings.
Kernel I/O counters are physical I/O. Exact CPU savings still require a matched
experiment. This namespace makes a primary-read byte comparison available; it
does not by itself prove an installed performance outcome.

Focused controls cover completed modes, replay overhead, preparation failure,
unfinished/unknown progress, move/drop ownership, cumulative abandonment,
overflow, inline requested-layout accounting, bounded event serialization and
both providers' real scanner path against independent full-reader output.
A future ordinary observation requires an equipped signed daemon and current
process binding. Source validation does not authorize a live capture or change
normal collection cadence.

Native Rust 1.95 measurements on the initial candidate: the page counter/ledger
retains 296 inline bytes and the process-wide abandonment counters occupy
64 static bytes. A read-progress snapshot is 56 stack bytes (24 more than the
previous snapshot). The worst-case resource record is 2,528 bytes; its namespace
is 1,014 bytes, below a 4 KiB complete-record ceiling, while the unchanged legacy
projection remains below its prior 2 KiB ceiling. Emission frequency is unchanged.
An isolated 100,000-update native progress loop took 184 microseconds; this is a
small scalar-operation measurement, not an end-to-end or installed CPU result.
All runtime progress work is constant-size arithmetic/copying. No syscall,
allocation, file lookup, clock sample or record serialization is added per line.
