# Provider-envelope boundary experiment

This test-only, nonshipping experiment characterizes three boundaries needed
before an incremental Claude owner-comparison optimization can be implemented.
Production scanning, wire bodies, account attribution, ACKs, index formats,
selection budgets and cache limits are unchanged.

- A real parsed transcript grows while a complete provider proof is replaced.
  The retained pre-mutation proof cannot certify the new native set; using the
  newly inserted proof as the prior would hide the new request.
- Actual partial/terminal owner folds and locked checkpoint saves exercise an
  ephemeral bootstrap receipt. A narrowly qualified negative candidate retains
  one earlier-page source fingerprint; after reload the permit is absent and
  the base native fold compares a new legacy fork before its first reported
  body. Exact owner outcomes and bodies are compared to the base history.
  Concurrent checkpoint failure revokes the permit.
- Real selected checkpoint restoration keeps a deferred replacement's old entry
  and a new candidate uncommitted. Target fingerprint rearm and unsettled-sweep
  state survive a locked save/reload. The real scanner queue shows that rearm
  alone does not imply priority; moving the existing target queue entry first
  can preserve next-pass priority without adding a persisted field.

This is boundary scaffolding, not a complete two-phase scanner: the test drives
fold/selection seams directly and uses synthetic accepted-state fixtures. It
has no network upload, performance measurement or installed acceptance. The
second case compares a candidate fingerprint-retention boundary; it does not
prove all eligibility, same-census target acquisition or per-class net savings.
The deferral case does not prove a full body-withholding upload lifecycle.

No existing timestamp dates a comparison deferral. Census time may predate it;
retry deadlines concern other failure domains; file activity/stat time concerns
content; generation is only checkpoint CAS. None proves age across restart.
Scheduling priority while running with available reads, consecutive eligible
attempts, and elapsed completion time including downtime are distinct claims.
A daemon that cannot run or read cannot guarantee completion within 15 minutes.
The wall-time/age limit remains unproved; no clock is reset to manufacture it.

Validation belongs to the existing hosted CI. No local Cargo build or test is
part of this experiment. It is not release or merge readiness for the related
optimization.
