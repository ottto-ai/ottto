# Authority binding repair: rejected record-only prototypes

These synthetic tests characterize existing candidate and durable-load behavior.
They change no production code and are not a repair or landing candidate.

A complete healthy family census can replace its witness while an earlier-page
hold retains the prior witness binding. The loader correctly rejects this pair.
Preserving that validation and keeping exact held-body/ACK state are required.

The tests model three possible existing-record transitions, using a different
synthetic witness digest and the real candidate/save/load methods:

| Transition | Count | Disposition | Deadline | Candidate result |
| --- | --- | --- | --- | --- |
| Rebind digest only | 4 | UnprovenTerminal | unchanged | Skip despite cleared correction debt |
| Rebind and make due | 1 | RetryPending | 0 | Parse remains due across unacknowledged reloads |
| Rebind and claim future retry | 1 | RetryPending | current time plus existing retry interval | Both unfinished members skip after reload |

The new digest can record which proof is consumed, but these record-only
transitions cannot simultaneously carry a one-attempt claim and unfinished
bounded correction pages. The existing candidate quarantine gate precedes the
entry's cleared source fingerprint. Merely honoring that fingerprint would also
reopen generic retry debt, which is not certified as a new proof correction.
Existing traversal state does not bind an authorized correction attempt to a
particular new witness. This is a gap in these prototypes, not a proof that no
more complete existing-state protocol is possible.

No counter/deadline reset on unchanged proof, changed files, unhealthy reports,
or partial proof is implemented. New state/schema, load-validation weakening,
removing held disclosure, and treating a held body as accepted are excluded.
Domain review must qualify a protocol before a production change. Natural
multi-page correction through exact ACK, same-proof restart and shed controls
remain required and are not established by these characterization tests.
