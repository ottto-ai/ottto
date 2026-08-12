# Claude subagent active-account attribution

Date: 2026-08-12

## Problem

The local collector could already prove one Claude account for a complete
parent/subagent request family and stamp that privacy-safe hash onto every
snapshot model-usage row. Subagents also carried direct parent/root lineage
facts. The active-session reconciler ignored both forms and only looked for an
exact per-session plan observation, so recently changed children appeared in
the macOS app under **Account not identified** while their parent was correctly
account-owned.

## Resolution

Active-session account attribution now consumes the strongest evidence already
present in the local read model:

- exact session plan observation;
- one exact snapshot account hash;
- one high/medium-confidence account shared by directly evidenced parent/root
  plan observations;
- compatible current login as the final fallback.

Conflicts remain fail-closed. An exact observation that disagrees with the
snapshot hash, missing or conflicting hashes across aggregate and bucket usage
rows, conflicting parent/root observations, weak lineage, or missing direct
lineage facts produces no attribution. Once conflict is detected, weaker
fallbacks are not considered. No repository, title, time, token, or
provider-only correlation is used.

This is a read-time correction over deterministic local evidence. It adds no
wire fields, raw identifiers, persistence mechanism, scheduler, or backend
write path. Existing active-session cache replacement remains idempotent and
bounded.

## Verification

Focused tests cover exact snapshot identity, direct root inheritance, lineage
conflict, and exact observation/snapshot conflict. Existing current-login and
provider-surface tests remain green.
