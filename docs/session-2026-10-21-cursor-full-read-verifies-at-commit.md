# A complete cursor Full read of an unchanged file verifies at commit (AD-1)

A cursor job certifies its sealed prefix with
`ReadPlan::commit_sealed_prefix`. Its Full arm recorded the read's start as
the verification time, and staged audit debt when the read outlived the audit
interval `I`. That is right for a file that grew during the read: a slow read
must not reset its deadline. For a quiescent file it was a loop. A large
unchanged file whose read took longer than `I` committed already due, staged
a due marker, and was read in full again every census generation.

The Full arm now has one guarded case in front of the old one. A Full read
verifies at commit (`now`, no debt) only when all of these hold:
- the held FD's full stamp at commit equals the plan's opening stamp (device,
  inode, length, mtime and ctime with nanoseconds; for a resumed read, the
  stamp `unpark` restored);
- the sealed prefix is the whole opened length;
- every byte of the opened length was consumed;
- the clock did not step back during the read (`now >= started`).

This is the trust the in-page Full commit (`commit_after_native_completion`)
and `Unchanged` already use: no write the stamp can see reached the object
while it was read. Every refusal still returns before the match (replacement,
shrink, same-size edit, samples, scope, a tail past its deadline, and a lossy
read), so lossy, uncertified and refused reads keep their obligations. A grown
file, a partial read (an unterminated last record, withheld or applied at
end of file) and a regressed clock keep the old case: verified at the start,
debt staged when outlived. Tail and Unchanged plans are unchanged. No other
file changes: the host's staging, the minimum-deadline rule, the withheld
fragment debt and every counter are as before.

What converges: a quiescent, loss-free, complete singleton under a trusted
census needs at most one more stable read after its last change, then the
marker clears and the scheduler skips the file. Not every unchanged file is
zero-cost. These still re-read, as before:
- a lossy file with a marker: one full read per generation, any size;
- a withheld final fragment, and a final record applied at end of file whose
  read outlived `I`;
- a singleton under an untrusted census, and lossy or census-incomplete group
  jobs;
- refused or deferred reads while their cause persists.

The forward-clock exposure is unchanged in kind but stated here: after a
forward clock jump that is later corrected, the retained checkpoint's
`ClockChanged` check forces a re-read only while that checkpoint survives.
After a restart or an eviction the marker is already cleared and the unchanged
file is skipped, exactly as after an in-page Full read today. This change adds
no detection guarantee. Timestamp granularity (coarse mtime/ctime clocks,
network attribute caches, writes to dirty shared mappings) is the same
exposure `Unchanged` already accepts.

Diagnostics: `audit_overdue` now counts only grown overdue completions.
A slow audit stays visible in `completion_overdue_seconds`, which is measured
against the deadline that selected the file. `audits_completed` and the audit
comparison now include stable outlived audits.

Tests (synthetic times and scaled page budgets only):
- `ta` units: a stable outlived read verifies at commit and its horizon runs
  from the commit; an in-time stable read likewise; a regressed clock keeps
  the start and the next read is `ClockChanged`; a partial read (`s < L`) and
  a short `consumed` keep the start and the debt; a lossy outlived stable
  read still refuses as `Lossy`.
- Three existing tests that committed a stable outlived read now append
  before the commit, so they keep pinning the grown case with unchanged
  assertions; U-T30 adds the stable seal (no debt, not outlived, admitted as
  `Unchanged` with or without the publication flag), and the park round trip
  adds its stable twin, which verifies at commit like an uninterrupted read.
- A scan-level test runs a cursor job that outlives `I` on an unchanged file
  (with no marker, and with a seeded past-due marker): it certifies at commit,
  clears the marker and records no overdue audit. With an append mid-read the
  grown case stays overdue with a due marker, and the next generation's
  stable audit converges. In later generations past `commit + I` the scheduler
  decision is `Skip` and no acquisition is selected (no `Unchanged`, no read).
  The next change after `commit + I` is a full `AuditDue` read, not a tail.
- The lossy cursor test gains a `stable` case: the unchanged lossy file
  publishes uncertified, keeps its deadline, and is re-read in full in each of
  three later generations.
- A sparse-file unit test seals a checkpoint past 2^32 bytes and checks that
  `prepare` tails from that exact offset with two sample windows read, and
  that one edited boundary byte below it refuses as `BoundaryChanged`.
