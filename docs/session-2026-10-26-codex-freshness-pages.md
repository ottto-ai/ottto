# Codex freshness during census revalidation

An open Codex census accepts new rollout paths. Its timestamp bounds the
lookback cutoff, rather than excluding later files. Previously, retained-roster
refresh appended new members behind old revalidation work and discarded a
watcher hint when that path was already queued. The singleton byte budget could
then delay new uploads until thousands of old members drained.

When fresh work exists and queued work could exhaust a page, an ordinary scan
can select a freshness-only page up to
the existing watcher/file cap. A hinted new path or an indexed file whose byte
length changed qualifies for priority. The same candidate, ownership, parse,
pricing, identity, post-policy body and acknowledgement gates still decide
whether anything uploads. Metadata-only changes do not create this priority.
Same-size edits continue through ordinary scheduling.

A persisted `codex_freshness_yield` checkpoint bit reserves the following
ordinary scan page for census work ahead of new hinted members. That page
selects unchanged census debt first; if all remaining members have changed
bytes, it selects census members in FIFO order. Missing bits default false;
continuation pages never consume or create this turn. File and byte budgets,
generation membership, large-file fences and next-generation carry keep their
existing meanings. Under continuous fresh traffic, a finite original census
receives at least one full-budget ordinary page out of every two ordinary scan
pages. This can double its singleton drain page count.

After directory discovery completes, an eligible fresh singleton batch fitting
one page's byte and file allowances reaches the normal upload set within two
ordinary scan pages, independently of the old revalidation population. This is
not a network or wall-clock promise. Cursor slot waits, grouped ownership,
identity holds and larger fresh batches retain their existing bounds.

Regression coverage uses 2,800 owed unchanged-output revalidations, a new rollout
found without a watcher hint, growth of an already processed rollout, and a
checkpoint round trip between fresh and ordinary service. A separate scheduling
check covers permission-only changes and identical-content inode replacement.
Existing carry tests retain their explicit ordinary-page premise.

Pages whose queued population fits the file allowance and the singleton byte
estimate keep ordinary scheduling. As in the page budget plan, a file larger
than the singleton allowance is cursor work with its own budget and is not
counted; an indexed file also counts one sample pair for its memo check. A small repair
or projection-adoption page therefore continues to service its fitting sibling
in the same page. This estimate changes scheduling only, never read admission
or the actual byte accounting.

Codex stores rollouts in day directories, so a new day usually means a new
directory. A directory that retained-roster refresh finds after the walk
carries the same freshness provenance as a rollout that appeared directly. The
bounded walk passes it to every subdirectory and file beneath. The initial
history walk starts unmarked, so cold history keeps FIFO census order. This
provenance is scheduling only. It adds no re-read trigger, and a hint alone
never authorizes a read. As with any hinted path, a marked file that vanishes
before its read settles as a removal. Coverage: a new day directory found
without a watcher hint behind 2,800 owed revalidations reaches the upload set
within two ordinary pages. A portable check confirms that the initial walk
leaves old nested days unmarked while a later new month is marked through its
subtree.
