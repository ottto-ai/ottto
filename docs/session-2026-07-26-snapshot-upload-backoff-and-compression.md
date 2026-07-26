# 2026-07-26 — Snapshot upload backoff, partial progress, and compression

## Outcome

A shed snapshot upload no longer produces an identical re-upload every five
minutes forever. The daemon now recognises 429/503, honours `Retry-After` with
jitter, commits the progress it actually made, and defers that source until the
backoff expires. Cycle phase is spread deterministically across the fleet, and
batch bodies can be gzip-encoded once the backend route decompresses them.

## What was wrong

Three behaviours compounded into one failure mode:

1. **No shed handling.** Every non-auth, non-validation upload error was a
   "network error". A 503 therefore looked identical to an offline laptop, and the
   next tick re-sent the same bytes.
2. **All-or-nothing scan checkpointing.** `index.save()` ran only after the whole
   scan was accepted, so a shed page meant the entire cycle — scan, derive,
   upload — replayed from the start.
3. **A fleet synchronised by construction.** Cycle phase is set by install or
   restart time, so any fleet-wide event (a deploy, a shed, a partition healing)
   re-aligned every machine onto the same tick and kept them there. Obeying a
   shared `Retry-After` exactly makes that worse, not better.

## Shed handling

`upload_batch` maps 429 and 503 to a typed `UploadShed { status, retry_after }`.
`Retry-After` is parsed in both spec forms — delta-seconds and HTTP-date — and
capped at 30 minutes: a server asking for a day off is still asking for freshness
the product promises in minutes.

The wait is then jittered:

* **With** a server-supplied value: `Retry-After × uniform(0.8, 1.2)`. The whole
  fleet was told the same number; obeying it exactly re-synchronises every
  machine onto the same instant, which is how a shed becomes a thundering herd.
* **Without** one: full jitter over an exponential ladder,
  `random(0, min(cap, base·2ⁿ))` with a 30 s base. Full jitter — not
  "exponential plus a little noise" — is the form that actually decorrelates
  retries.

A shed sets a per-source deadline. While it is outstanding the sync loop skips
that source entirely rather than re-scanning and re-deriving pages the server
just refused. No status receipt is posted for a skipped source: the previous one
still describes reality, and the check-in heartbeat keeps freshness alive on its
own clock. The backoff is per source, so one shed source does not silence the
others.

The receipt for the shed cycle itself uses the `server_error` collector code —
the closest value the receipt contract carries — and the `ratelimit_backoff` row
of the client report is where the shed is named precisely.

## Partial progress

`ScanIndex::committable_subset` answers "what is safe to commit when the upload
did not finish". An entry is safe when the server demonstrably holds its content:

* it produced no snapshot at all (nothing to lose), or
* its snapshot was accepted in this pass, or
* its fingerprint is unchanged from the committed index — which is what "semantic
  no-op" means: the server already has exactly that content.

Anything else keeps its previously committed entry, so the next scan re-parses and
re-uploads it. Both failure directions are real and both are avoided: committing
everything drops every entity the server never received (the next scan skips an
unchanged transcript, so its snapshot is never re-derived), and committing
nothing replays the whole cycle forever.

The same rule applies to Codex state-only entities.

## Cadence phase offset

`hash(machine_id) mod interval`, applied once before the first cycle of the sync
loop and the check-in heartbeat. Derived from the durable machine id so it is
stable across restarts — a random offset would re-scatter on every launch, which
is worse for the freshness promise than being predictable. A machine that has not
been claimed yet has no stable id and simply starts on time.

## gzip — shipped, default off, and why

Bodies repeat identical selector maps per hour bucket, so deflate has a lot to
work with; the encoder measurably shrinks a representative body by more than 4×.

It is **off by default** because nothing decompresses a *request* body unless a
route opts in, and the batch route does not yet — the OTLP route is the only one
in the estate with a request-decompression path. Shipping this enabled would 4xx
every upload from an upgraded daemon against today's server.

So the encoder ships now, behind `OTTTO_SNAPSHOT_UPLOAD_GZIP=1`, and the default
flips in the release **after** the batch route decompresses. Two safeguards make
a premature flip harmless:

* On a 400 or 415 the client disables gzip for the process and immediately retries
  the same batch with identity encoding.
* 422 is deliberately **not** a fallback trigger: a 422 means the server parsed
  the body and disliked its contents, so the encoding worked, and falling back
  would hide a real validation failure.

## Client report

`ratelimit_backoff` now has a live writer for the shed path (HTTP 429 and 503).
The poison ledger is also keyed per source: a Codex pass must not prune Claude's
ledger, or the next Claude cycle would count its already-counted poison a second
time.

## Follow-ups

* Flip the gzip default once the batch route decompresses request bodies.
* The receipt has no "deferred" collector state; `server_error` is the closest
  fit. A `deferred` outcome belongs with the per-entity ACK vocabulary.
