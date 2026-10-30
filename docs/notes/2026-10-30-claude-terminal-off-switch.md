# Claude terminal containment: local opt-in, default OFF

`claude_terminal_off_enabled` defaults to **false**. With OFF, the ordinary main
completion, discovery, retry, upload and absence paths run. This is a staged
release of containment code, not a fleet rollout of containment policy.

The existing machine-local sentinel pattern (`mcp_inventory/disabled`,
`context_footprint/disabled`) supplies the setting. A regular, non-symlink file
named `claude_terminal_off_enabled` in Ottto's support directory opts in. The
owner changes it manually; there is no remote control or new settings/index
serialization format. The daemon pins the setting for its lifetime, across
workers and cooperative yields. Restart after a change. Unit tests ignore the
host file and explicitly opt in with a scoped test guard.

Only Ron can authorize ON on his M4 with a typed go, and only Ron flips that
machine's setting. No agent changed the installed setting in this work.
The owner procedure, **after** that authorization and the ON blockers below:

```sh
support="${OTTTO_LOCAL_PLATFORM_SUPPORT_DIR:-$HOME/Library/Application Support/Ottto}"
# ON, owner only; then restart the installed Ottto service normally.
touch "$support/claude_terminal_off_enabled"
# OFF, owner only; then restart the installed Ottto service normally.
rm "$support/claude_terminal_off_enabled"
```

The existing traversal-context digest includes an ON-only domain tag. A saved
ON traversal therefore cannot resume in OFF, including after restart: main
starts a fresh traversal before reconciliation. No new persisted field is
needed. OFF-to-ON similarly starts a new policy-scoped traversal. A transition
can pay main's ordinary reconstruction/re-read cost; it never adopts a receipt,
ACK, source context, family proof or absence in a shortcut.

ON withholds all Claude terminal effects before raw removals/reconciliation,
retirement and tombstone drain, while ordinary page upload, exact ACK and
selected save continue. New cohorts remain unproven; strict posture/cache/curve
outputs pause. Small-cohort completion/corrections wait for paged reconstruction,
delayed rather than erased. Stale unchanged pending custody remains unproven;
admission advances in its retained window. Root discovery coalesces through a
backlog, with a suppressing 1800-second probe. Targeted service retains ordinary
privacy, byte/page, audit deadline, failed-open park and six-hour hold gates.
Each real held serve renews its own RAM six-hour floor. Presence is recorded
before enqueue suppression, including stat-confirmed hints. Read the
[discovery design](2026-10-30-terminal-off-discovery.md) and
[OFF-path hunk audit](2026-10-30-claude-terminal-off-static-audit.md).

## Readiness and known ON residuals

OFF merge still requires R6/R12, the empty-context B1 control, missing-ACK B-P2,
re-arm-loop B-P5, OFF identity, Linux and branch Mac. B-P2/B-P5 are the next
separate fix round; this switch does not waive them.

ON is **not ready anywhere**, including the M4. Lead B's pending labels remain:

- **BLOCKS-RELEASE before ON:** R2 (correction settlement against wrong revision),
  R10 (unproven money-harness coverage), R7/R8/R9 (held-page custody, manifest
  membership and accepted-body differences), R5/R11 (repeating re-reads), and R1
  if still red after B1. None is relabelled fixture-only without evidence.
- **SHIP-WITH-DISCLOSURE for M4 ON, fix before fleet default-ON:** R3's bounded,
  counted page-0 correction drain; R4's counted one-time history-upgrade burst
  above one file/page, which still needs an M4 measurement.
- **R13:** repair the fixture phase (START before RESUME) and obtain a green
  production-path result. This is still pending, not an asserted pass.

Additional accepted containment disclosures, S3–S8:

- S3: at most 10,000 RAM observations per scope, 40,000 aggregate and 64 scopes.
  Counted evictions permit conservative extra metadata/read work; measure M4's
  cohort. Restart or eviction loses a key's RAM floor and permits a cold offer.
- S4: without known identity/birth, unchanged held reuse/floor is unavailable.
- S5: a cold overlapping-root key can pay one ScopeChanged Full after restart.
- S6: the 30-minute ceiling bounds **discovery**, not FIFO body-read latency.
  Walk interval and oldest-unscanned age are diagnostics; ordinary read budgets
  and backoff still apply. Discovery itself consumes zero transcript body bytes.
- S7: prior review estimated about 14 MB worst-case observation RAM, plus at
  most 640 KB for the new optional served-at values. This is a planning estimate,
  not measured RSS; runtime heap accounting includes every scheduling field.
- S8: the directory walk's scratch pending map clones paths each page. It now
  keeps the **first** duplicate, matching main's previous `.find()` semantics;
  it is not persisted or carried across pages.

Existing per-class retention gauges/alarms remain ON-only. Ron accepted
2026-10-29: ships with per-class gauges/alarms; per-family completion,
usage-proof retirement and the CAS peak are next-release top priorities.
Ordinary held-history total remains a post-release gauge gap. F4 and #876 remain
paired next-release work; no new absence shortcut is introduced here.
