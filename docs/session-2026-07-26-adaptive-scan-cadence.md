# 2026-07-26 — Adaptive scan cadence and the filesystem watcher

## Outcome

The filesystem watcher and the adaptive cadence tiers were implemented, declared,
and called by nothing. The server's `recommended_scan_after` was parsed and never
read. All three are now wired, with the cost tiers first: a machine nobody is
coding on today re-reads its transcripts every 30 minutes instead of every 5,
while file activity brings a source back to the existing five-minute floor.

## What is expensive, and what is not

The cycle cadence is **unchanged at five minutes**. Quota and agent-status
freshness, the reconciliation policy cache, and the active-session projection all
keep the cadence they have — they are cheap and product-visible.

What the tiers gate is the expensive part: the local transcript scan and its
upload. One active 105 MB Codex rollout is fully re-read every five minutes today,
which is ~30 GB/day of local reads for a single session.

## Four constraints, and how each is met

**1. Never per-event uploads.** An event *promotes a tier*; it never triggers a
scan. `CadenceConfig::cost_first` pins both `hot_min_interval` and `warm_interval`
to the five-minute floor, so the hot 10-second tier is deliberately not enabled
and a promoted source becomes due at the floor. Fifty events in a second cannot
buy fifty scans — that is a test, not an intention.

**2. The cadence tier is outside every identity.** The tier and the scan trigger
are implementation state. If either entered an identity, every session on a
machine would re-mint its content hash the moment the machine went idle. Nothing
carries them: not the snapshot envelope, not the receipt (asserted), and not the
scan index.

**3. The sweep is never gated on the watcher.** The negotiated wait is capped at
30 minutes, which is *stricter* than the 6-hour full sweep, so a full scan of the
window happens at least every 30 minutes whatever the watcher does. A machine that
cannot watch its transcripts at all — no permission, exhausted descriptors, a root
that does not exist yet — collects on exactly the schedule it does today, and says
so in one log line. A watcher that silently stopped delivering events would
otherwise stop collection with every health signal green.

**4. The floor is respected.** It wins over every other input, always.

## The negotiated cadence

`clamp(directive, floor, ceiling)`, with three inputs in this order of authority:

1. **The local floor (5 min)** — a hard guarantee. No tier, no server directive,
   and no filesystem event can produce more than one scan per interval.
2. **`recommended_scan_after`** — a minimum interval **between scans**, anchored
   to the last scan, and it may only ask for *less* frequent scanning than the
   local tier decided. It is a cost directive, not a freshness lever; a server that
   could shorten it would be asking the fleet to pay for the server's own load.
   Unparsable values leave the previous directive alone rather than inventing one.

   The anchoring is load-bearing, not stylistic. Treated as a *countdown* instead,
   a directive re-read at the top of every cycle would push its own deadline
   forward on every tick: a server that always says "come back in five minutes"
   would stop the scan permanently, on a healthy machine, with nothing looking
   wrong. Anchored to the last scan, the same repeated directive simply means "one
   scan per five minutes" — and the wait strictly decreases as time passes, which
   is a test.
3. **The ceiling (30 min)** — bounds everything, including a server directive that
   would otherwise silence a source for a day.

Tier transitions come from real cycle outcomes: uploads keep a source warm, quiet
cycles let it fall to idle and then cold, failures back it off, and the backend
activity hint warms a source the server has seen data for.

## Interaction with the shed backoff

An outstanding shed backoff still skips the whole source cycle, including its
agent-status upload. A 429/503 from the batch route is a server-wide signal, so
backing everything off is the conservative reading; the cost is up to 30 minutes of
quota staleness on a shedding server.
