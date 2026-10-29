# Claude restore shared Full pacing

Merged main's continuation activation while preserving both native-read test
observers. The shared bounded Full map now uses SystemTime: backwards changes,
six-hour expiry (including sleep), and forward changes beyond seven days expire
toward reading. Growth at 90% of Claude's source cap bypasses the cooldown and
increments the separate near_cap alarm. Spent Tail authority remains unchanged.

Absent-upgrade growth uses this same map and a separate upgrade_missing_full
admission counter; upgrade_state_missing still counts actual native starts.
Already-admitted stale/no-match/retail Fulls carry a local grant to avoid being
charged twice. Paced known absence preserves census and accepted size without
an unreadable count. Cancellation may consume admission, so retries wait for
expiry. A restart permits one extra Full per key under the transitional policy.

The #865 counted Missing outcome and process-lifetime T14 rebuild limit survived
the fold. D-U recovery remains a dependency on #879 and must be reconciled onto
this shared map at integration. A1b2d remains separate. Historical
upgrade_state_missing:<release> replay keys belonged to the removed reread guard;
this tree does not create them or treat them as acceptance or reuse evidence.

Regression fixtures cover wall-clock jumps, the exact 90% sparse-file boundary,
shared absent-upgrade pacing, and native zero-read holds followed by byte-equal
recovery. Native-only continuation/bootstrap fixtures explicitly ignore other
platforms and assert layout support when executed. No tests run locally; pinned
clippy compiles all targets. Exact-head Linux/native and money qualification are
separate release obligations, not supplied by compilation.
