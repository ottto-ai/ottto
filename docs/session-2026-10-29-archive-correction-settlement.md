# Archive correction and settlement contracts

Archives retain per-setting correction generations, committed decode attempts,
and terminal upload failures in the existing scan-index evidence. User policy
changes request A3 correction; internal cache metadata does not. Code-driven
historical replay and body revision changes remain held until replay approval.
Existing HeaderWork permission remains fail-closed; discovery stays plain-only
until the activation slice supplies real power/QoS and shared CPU pacing.

The sixth committed attempt caps transient recovery; the third terminal failure
caps terminal settlement recovery. Exact current-body ACK can revive Stuck.
Reservation persistence precedes decode and retry accounting. Terminal archive
and prolonged admission debt becomes disclosed per-session residue, preserving
other sessions' census progress and protecting affected sessions from state-only
substitution, retirement and departed-owner release. Admission streaks remain
RAM-only, per archive, bounded to 256 keys; restart/eviction limits remain explicit.

Synthetic fixtures cover correction/no-change, revision hold, settlement,
reservation crashes/save refusal, residue scopes, rotating starvation and
plain-only discovery. Only explicit-file rustfmt and diff whitespace checks were
run during static branch preparation; compiler, tests and CI remain unexecuted.
